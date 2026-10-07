//! Three screens over the scan, the review inventory, and one usage tree.
//!
//! Each screen leads with a bar. Volumes show used and free. Reclaim shows
//! how the measured bytes split across safe, caution, and review, then one
//! line per row under its tier. Usage shows each child as a share of its
//! parent. [`Palette::Plain`] draws those bars with block characters and no
//! color, and is what `NO_COLOR` selects.
//!
//! [`Model::handle`] is a pure function of a key. Tests drive it without a
//! terminal. The only mutation it can ask for is [`Effect::ConfirmApply`],
//! and the caller fulfills that by [`crate::trash::apply_typed_total`].
//! Space changes a caution row that is staged or held only for its age. It
//! does not change a safe row, a review row, or a caution row held for any
//! other reason. The usage screen has no stage key.
//!
//! The scan, the review inventory, a usage walk, and an apply each run on
//! their own thread and report over one channel. The UI thread does not
//! walk or rename anything, so it can always paint and always quit. Quitting during an
//! apply stops it between entries and waits for its report.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, SystemTime};

use crate::config::Loaded;
use crate::plan::{Entry, Plan};
use crate::report::format_bytes;
use crate::review::Item;
use crate::rules::{Skip, Tier};
use crate::scan::Finding;
use crate::time::unix_nanos;
use crate::trash::ApplyReport;
use crate::usage::UsageNode;
use crate::volumes::Volume;
use crate::walk::Fs;

/// Which screen is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Mounts from `getmntinfo`.
    Volumes,
    /// Safe, caution, and review rows.
    Reclaim,
    /// One volume, drilled down.
    Usage,
}

/// How tier words are colored. [`Palette::Plain`] emits no escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Palette {
    /// `COLORTERM=truecolor`.
    True,
    /// `COLORTERM` set to something else.
    Ansi256,
    /// No `COLORTERM`.
    Ansi16,
    /// `NO_COLOR`, or a test that must not emit escapes.
    Plain,
}

/// One key, after escape sequences are decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable character, including the command keys.
    Char(char),
    /// Enter.
    Enter,
    /// Backspace.
    Backspace,
    /// Escape, with no following bracket sequence.
    Escape,
    /// Tab.
    Tab,
    /// Arrow up.
    Up,
    /// Arrow down.
    Down,
    /// Arrow left.
    Left,
    /// Arrow right.
    Right,
    /// Page up.
    PageUp,
    /// Page down.
    PageDown,
    /// Home.
    Home,
    /// End.
    End,
}

/// What the caller should do after a key.
///
/// Quit writes nothing. Confirm is the only effect that leads to a rename,
/// and only through the typed byte total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Stay on the current screen.
    None,
    /// Leave without writing a plan or moving a file.
    Quit,
    /// The typed total matched [`format_bytes`] of the staged rows.
    ConfirmApply {
        /// The exact string the operator typed.
        typed: String,
    },
    /// The operator asked to walk one volume. The model does not walk it.
    WalkUsage {
        /// Mount point.
        mount: PathBuf,
    },
    /// Quit was pressed while an apply is running. The caller stops the
    /// apply after its current entry and leaves once it has reported.
    Interrupt,
}

/// Reclaim filter. `f` cycles it. The footer names the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Filter {
    /// Every row.
    #[default]
    All,
    /// Safe rows.
    Safe,
    /// Caution rows.
    Caution,
    /// Review rows.
    Review,
}

/// How a finished scan went, for the title and the status line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ScanSummary {
    /// Entries the scan could not read.
    unreadable: u64,
    /// Project roots that do not exist.
    roots_missing: usize,
    /// Project roots on the denylist or on another volume.
    roots_denied: usize,
    /// Why the scan stopped early, when it did.
    failed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScanState {
    Running,
    Done,
    /// Stopped early. The title keeps saying so after the message is gone.
    Failed,
}

/// Order of the reclaim groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RowKind {
    Safe,
    Caution,
    Review,
}

/// What keys mean right now. One at a time, so a help screen cannot sit on
/// top of a half-typed total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Keys move and act on the current screen.
    Browse,
    /// Keys are typed into the confirm prompt.
    Confirm,
    /// The key list is showing. Any key closes it.
    Help,
}

/// Order of the children on the usage screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    Size,
    Name,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Motion {
    Up,
    Down,
    PageUp,
    PageDown,
    Top,
    Bottom,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    kind: RowKind,
    rule: String,
    path: PathBuf,
    bytes: u64,
    age: Option<Duration>,
    staged: bool,
    /// Why the last apply left this row in place.
    skipped: Option<String>,
    detail: String,
    finding: Option<Finding>,
}

/// The UI state. Rendering reads it. Keys go through [`Self::handle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    screen: Screen,
    palette: Palette,
    columns: usize,
    /// Terminal height. The list scrolls inside what this leaves after the
    /// title and the footer.
    term_rows: usize,
    /// Shown as `~` in paths, when known.
    home: Option<PathBuf>,
    now: SystemTime,

    volumes: Vec<Volume>,
    volume_cursor: usize,
    /// Whether mounts that cannot be walked are listed.
    all_volumes: bool,

    rows: Vec<Row>,
    /// Rules whose findings are loose files. Their rows are shown as one
    /// line per directory.
    grouped_rules: Vec<String>,
    cursor: usize,
    filter: Filter,
    detail: bool,
    typed: String,
    scan: ScanState,
    scan_dirs: u64,

    usage: Option<UsageNode>,
    usage_cursor: usize,
    usage_path: Vec<usize>,
    order: Order,
    walk_dirs: u64,

    /// Mount a usage walk is reading, on another thread.
    walking: Option<PathBuf>,
    /// An apply is running on another thread. Separate from the walk: the
    /// two can overlap, and neither may forget the other.
    applying: bool,
    /// What the last apply did. Printed again after the UI leaves.
    applied: Option<String>,
    mode: Mode,
    message: String,
    /// Bumped on every change the screen shows. The driver skips a paint
    /// when this still matches the frame it drew.
    revision: u64,
}

impl Model {
    /// Volumes, findings, and review rows already known.
    ///
    /// Safe rows keep the staged bit the scan computed. Caution starts at
    /// that bit too, and space can flip it. Review rows are not staged.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::ui::{Model, Palette};
    /// use std::time::UNIX_EPOCH;
    ///
    /// let model = Model::new(Vec::new(), Vec::new(), Vec::new(), Palette::Plain, UNIX_EPOCH);
    /// assert!(!model.is_staged(std::path::Path::new("/missing")));
    /// ```
    #[must_use]
    pub fn new(
        volumes: Vec<Volume>,
        findings: Vec<Finding>,
        review: Vec<Item>,
        palette: Palette,
        now: SystemTime,
    ) -> Self {
        let mut rows = findings
            .into_iter()
            .map(|finding| row_from_finding(finding, now))
            .collect::<Vec<_>>();
        rows.extend(review.into_iter().map(row_from_review));
        Self {
            screen: Screen::Volumes,
            palette,
            columns: 80,
            term_rows: 40,
            home: None,
            now,
            volumes,
            volume_cursor: 0,
            all_volumes: false,
            rows,
            grouped_rules: Vec::new(),
            cursor: 0,
            filter: Filter::All,
            detail: false,
            typed: String::new(),
            scan: ScanState::Running,
            scan_dirs: 0,
            usage: None,
            usage_cursor: 0,
            usage_path: Vec::new(),
            order: Order::Size,
            walk_dirs: 0,
            walking: None,
            applying: false,
            applied: None,
            mode: Mode::Browse,
            message: String::new(),
            revision: 1,
        }
    }

    fn say(&mut self, text: &str) {
        self.message.clear();
        self.message.push_str(text);
    }

    fn bump(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    /// Applies one key.
    ///
    /// `q` quits while a total is being typed. Every other key is a
    /// character during confirm: the printed total contains `1`, `2`, and
    /// `3`, and treating them as screen changes would drop the prompt.
    /// While an apply is running the only key is `q`, which asks it to stop.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::ui::{Effect, Key, Model, Palette};
    /// use std::time::UNIX_EPOCH;
    ///
    /// let mut model = Model::new(Vec::new(), Vec::new(), Vec::new(), Palette::Plain, UNIX_EPOCH);
    /// assert_eq!(model.handle(Key::Char('q')), Effect::Quit);
    /// ```
    pub fn handle(&mut self, key: Key) -> Effect {
        self.bump();
        if self.applying() {
            return self.handle_applying(key);
        }
        // A status line answers the key before it. The next key starts clean.
        self.message.clear();
        if key == Key::Char('q') {
            return Effect::Quit;
        }
        match self.mode {
            Mode::Help => {
                self.mode = Mode::Browse;
                return Effect::None;
            }
            Mode::Confirm => return self.handle_confirm(key),
            Mode::Browse => {}
        }
        if key == Key::Char('?') {
            self.mode = Mode::Help;
            return Effect::None;
        }
        if self.switch_screen(key) {
            return Effect::None;
        }
        if let Some(motion) = motion(key) {
            self.move_cursor(motion);
            return Effect::None;
        }

        match self.screen {
            Screen::Volumes => self.handle_volumes(key),
            Screen::Reclaim => self.handle_reclaim(key),
            Screen::Usage => self.handle_usage(key),
        }
    }

    /// Appends a finding that arrived while the screen was up.
    ///
    /// A second finding with the same rule and path replaces the first.
    pub fn push_finding(&mut self, finding: Finding) {
        self.push_findings(vec![finding]);
    }

    /// Appends a batch of findings and restores the cursor once.
    ///
    /// If a total is being typed and the batch changes what is staged, the
    /// prompt is cancelled. The total on screen when typing began would no
    /// longer be the total of what Enter moves, and to one decimal place a
    /// new row can hide inside it.
    fn push_findings(&mut self, findings: Vec<Finding>) {
        let anchor = self.anchor();
        let staged = self.staged_mark();

        for finding in findings {
            let existing = self
                .rows
                .iter_mut()
                .find(|row| row.rule == finding.rule && row.path == finding.path);
            match existing {
                Some(row) => *row = row_from_finding(finding, self.now),
                None => self.rows.push(row_from_finding(finding, self.now)),
            }
        }

        self.restore_anchor(anchor);
        if self.mode == Mode::Confirm && self.staged_mark() != staged {
            self.mode = Mode::Browse;
            self.typed.clear();
            self.say("the staged rows changed; press t again");
        }
        self.bump();
    }

    /// How many rows are staged and their exact bytes.
    fn staged_mark(&self) -> (usize, u64) {
        let count = self.rows.iter().filter(|row| row.staged).count();
        (count, self.staged_bytes())
    }

    /// Replaces review rows. Finding rows stay, including their staged bits.
    pub fn set_review(&mut self, items: Vec<Item>) {
        let anchor = self.anchor();
        self.rows.retain(|row| row.finding.is_some());
        self.rows.extend(items.into_iter().map(row_from_review));
        self.restore_anchor(anchor);
        self.bump();
    }

    /// Records how far the scan's project walk has come.
    fn set_scan_progress(&mut self, dirs: u64) {
        if self.scan_dirs != dirs {
            self.scan_dirs = dirs;
            self.bump();
        }
    }

    /// Marks the scan finished and reports what it could not do.
    fn finish_scan(&mut self, summary: &ScanSummary) {
        self.scan = if summary.failed.is_some() {
            ScanState::Failed
        } else {
            ScanState::Done
        };
        if let Some(note) = scan_note(summary) {
            self.message = note;
        }
        self.bump();
    }

    /// Notes that a usage walk of `mount` is running elsewhere.
    fn begin_walk(&mut self, mount: PathBuf) {
        self.message.clear();
        self.walking = Some(mount);
        self.walk_dirs = 0;
        self.bump();
    }

    /// Records how many directories the usage walk has expanded.
    fn set_walk_progress(&mut self, dirs: u64) {
        if self.walk_dirs != dirs && self.walking.is_some() {
            self.walk_dirs = dirs;
            self.bump();
        }
    }

    /// Stores a usage tree, and shows it if the operator is still waiting
    /// on the volumes screen.
    pub fn set_usage(&mut self, node: UsageNode) {
        self.end_walk();
        self.usage = Some(node);
        self.usage_path.clear();
        self.usage_cursor = 0;
        self.sort_current();
        // The walk can take minutes. Whoever started it may be typing a
        // total by now, and the screen must not change under that.
        if self.mode == Mode::Browse && self.screen == Screen::Volumes {
            self.screen = Screen::Usage;
        } else {
            self.say("the usage walk finished; press 3 to see it");
        }
        self.bump();
    }

    /// Reports a usage walk that did not produce a tree.
    fn fail_walk(&mut self, message: impl Into<String>) {
        self.end_walk();
        self.set_message(message);
    }

    fn end_walk(&mut self) {
        self.walking = None;
    }

    /// Notes that an apply is running elsewhere. Keys other than `q` wait.
    fn begin_apply(&mut self) {
        self.applying = true;
        self.message.clear();
        self.mode = Mode::Browse;
        self.typed.clear();
        self.bump();
    }

    /// Whether an apply is running. The caller must not quit while it is.
    fn applying(&self) -> bool {
        self.applying
    }

    /// Takes moved rows off the list and marks the ones that stayed.
    ///
    /// A row that was skipped is no longer staged, so the total in the title
    /// is again what a confirm would move.
    fn finish_apply(&mut self, report: &ApplyReport) {
        let anchor = self.anchor();
        let mut bytes: u64 = 0;
        self.rows.retain(|row| {
            let moved =
                row.finding.is_some() && report.moved.iter().any(|item| item.from == row.path);
            if moved {
                bytes = bytes.saturating_add(row.bytes);
            }
            !moved
        });
        for skipped in &report.skipped {
            for row in &mut self.rows {
                if row.finding.is_some() && row.path == skipped.path {
                    row.staged = false;
                    row.skipped = Some(skipped.reason.to_string());
                }
            }
        }

        self.applying = false;
        self.restore_anchor(anchor);
        self.message = apply_note(report, bytes);
        self.applied = Some(self.message.clone());
        self.bump();
    }

    /// Reports an apply that returned an error. Nothing was renamed.
    fn fail_apply(&mut self, message: impl Into<String>) {
        self.applying = false;
        self.set_message(message);
        self.applied = Some(self.message.clone());
    }

    /// Sets the render width. A resize redraws from this snapshot.
    pub fn set_columns(&mut self, columns: usize) {
        self.columns = columns.max(1);
        self.bump();
    }

    /// Sets the render height. A resize redraws from this snapshot.
    pub fn set_rows(&mut self, rows: usize) {
        self.term_rows = rows.max(1);
        self.bump();
    }

    /// Names the rules whose findings are single files in one directory.
    ///
    /// A log directory can hold dozens of them, a few KiB each. They are
    /// drawn as one line. Each file keeps its own row underneath, so the
    /// plan still names every file and its own staged bit.
    fn set_grouped_rules(&mut self, rules: Vec<String>) {
        self.grouped_rules = rules;
        self.bump();
    }

    /// Sets the directory shown as `~` in paths.
    fn set_home(&mut self, home: &Path) {
        self.home = Some(home.to_path_buf());
        self.bump();
    }

    /// Replaces the status line.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = message.into();
        self.bump();
    }

    /// Whether the row at `path` is staged. Review paths are never staged.
    #[must_use]
    pub fn is_staged(&self, path: &Path) -> bool {
        self.rows
            .iter()
            .find(|row| row.path == path)
            .is_some_and(|row| row.staged)
    }

    /// Plan covering the finding rows, with the caution bits the operator set.
    ///
    /// Review rows are absent. They have no [`Entry`].
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::ui::{Model, Palette};
    /// use std::time::UNIX_EPOCH;
    ///
    /// let model = Model::new(Vec::new(), Vec::new(), Vec::new(), Palette::Plain, UNIX_EPOCH);
    /// assert!(model.plan("host").entries.is_empty());
    /// ```
    pub fn plan(&self, host: &str) -> Plan {
        let entries = self.rows.iter().filter_map(entry_of).collect();
        Plan::from_entries(entries, host, self.now)
    }

    /// Apparent bytes the confirm prompt asks for.
    #[must_use]
    pub fn staged_bytes(&self) -> u64 {
        self.rows
            .iter()
            .filter(|row| row.staged)
            .fold(0, |sum, row| sum.saturating_add(row.bytes))
    }

    fn handle_applying(&mut self, key: Key) -> Effect {
        if key == Key::Char('q') {
            self.say("stopping after the current entry");
            return Effect::Interrupt;
        }
        Effect::None
    }

    fn switch_screen(&mut self, key: Key) -> bool {
        let screen = match key {
            Key::Char('1') => Screen::Volumes,
            Key::Char('2') => Screen::Reclaim,
            Key::Char('3') => Screen::Usage,
            Key::Tab => self.screen.next(),
            _ => return false,
        };
        self.screen = screen;
        true
    }

    fn move_cursor(&mut self, motion: Motion) {
        match self.screen {
            Screen::Volumes => {
                self.volume_cursor = moved(self.volume_cursor, motion, self.shown_volumes().len());
            }
            Screen::Reclaim => self.cursor = moved(self.cursor, motion, self.visible().len()),
            Screen::Usage => {
                self.usage_cursor = moved(self.usage_cursor, motion, self.child_count());
            }
        }
    }

    fn handle_volumes(&mut self, key: Key) -> Effect {
        match key {
            Key::Char('u') | Key::Enter => self.walk_selected(),
            Key::Char('a') => {
                self.toggle_all_volumes();
                Effect::None
            }
            _ => Effect::None,
        }
    }

    fn toggle_all_volumes(&mut self) {
        let selected = self.shown_volumes().get(self.volume_cursor).copied();
        self.all_volumes = !self.all_volumes;
        let shown = self.shown_volumes();
        self.volume_cursor = selected
            .and_then(|index| shown.iter().position(|shown| *shown == index))
            .unwrap_or(0);
    }

    /// Indexes of the mounts on screen. A mount that cannot be walked is
    /// noise until someone asks for all of them.
    fn shown_volumes(&self) -> Vec<usize> {
        self.volumes
            .iter()
            .enumerate()
            .filter(|(_, volume)| self.all_volumes || volume.walkable)
            .map(|(index, _)| index)
            .collect()
    }

    fn walk_selected(&mut self) -> Effect {
        let shown = self.shown_volumes();
        let Some(volume) = shown
            .get(self.volume_cursor)
            .map(|index| &self.volumes[*index])
        else {
            return Effect::None;
        };
        if !volume.walkable {
            self.message = format!("not walkable: {}", volume.mount.display());
            return Effect::None;
        }
        if let Some(mount) = &self.walking {
            self.message = format!("still walking {}", mount.display());
            return Effect::None;
        }
        Effect::WalkUsage {
            mount: volume.mount.clone(),
        }
    }

    fn handle_reclaim(&mut self, key: Key) -> Effect {
        match key {
            Key::Char(' ') => self.toggle_selected(),
            Key::Char('d') => self.detail = !self.detail,
            Key::Char('t') => self.begin_confirm(),
            Key::Char('f') => {
                let anchor = self.anchor();
                self.filter = self.filter.next();
                self.restore_anchor(anchor);
            }
            _ => {}
        }
        Effect::None
    }

    fn toggle_selected(&mut self) {
        let Some(index) = self.selected_row() else {
            return;
        };
        if let Some(refusal) = toggle_refusal(&self.rows[index]) {
            self.message = refusal;
            return;
        }
        let row = &mut self.rows[index];
        row.staged = !row.staged;
        row.skipped = None;
    }

    fn begin_confirm(&mut self) {
        if !self.rows.iter().any(|row| row.staged) {
            self.say("nothing is staged");
            return;
        }
        self.mode = Mode::Confirm;
        self.typed.clear();
    }

    fn handle_confirm(&mut self, key: Key) -> Effect {
        match key {
            Key::Enter => return self.finish_confirm(),
            Key::Backspace => {
                self.typed.pop();
            }
            Key::Escape => {
                self.mode = Mode::Browse;
                self.typed.clear();
            }
            Key::Char(ch) => self.typed.push(ch),
            _ => {}
        }
        Effect::None
    }

    fn finish_confirm(&mut self) -> Effect {
        let expected = format_bytes(self.staged_bytes());
        if self.typed == expected {
            self.mode = Mode::Browse;
            Effect::ConfirmApply { typed: expected }
        } else {
            self.say("does not match; type the total, or esc to cancel");
            Effect::None
        }
    }

    fn handle_usage(&mut self, key: Key) -> Effect {
        match key {
            Key::Char('s') => {
                self.order = match self.order {
                    Order::Size => Order::Name,
                    Order::Name => Order::Size,
                };
                self.sort_current();
            }
            Key::Enter | Key::Right | Key::Char('l') => self.descend(),
            Key::Backspace | Key::Left | Key::Char('h') | Key::Escape => self.ascend(),
            _ => {}
        }
        Effect::None
    }

    fn descend(&mut self) {
        let Some(child) = node_at(self.usage.as_ref(), &self.usage_path)
            .and_then(|node| node.children.get(self.usage_cursor))
        else {
            return;
        };
        // A file, an empty directory, or a directory below the depth the
        // walk expanded. Entering it would show an empty screen.
        if child.children.is_empty() {
            self.message = format!("nothing listed below {}", file_label(&child.path));
            return;
        }
        self.usage_path.push(self.usage_cursor);
        self.usage_cursor = 0;
        self.sort_current();
    }

    fn ascend(&mut self) {
        let left = node_at(self.usage.as_ref(), &self.usage_path).map(|node| node.path.clone());
        if self.usage_path.pop().is_none() {
            return;
        }
        // `s` only sorts the directory on screen, so the parent may still
        // be in the other order. Sort it, then find the child by name.
        self.sort_current();
        let siblings = node_at(self.usage.as_ref(), &self.usage_path);
        self.usage_cursor = siblings
            .and_then(|node| {
                node.children
                    .iter()
                    .position(|child| Some(&child.path) == left.as_ref())
            })
            .unwrap_or(0);
    }

    fn sort_current(&mut self) {
        let order = self.order;
        let path = self.usage_path.clone();
        let Some(node) = node_at_mut(self.usage.as_mut(), &path) else {
            return;
        };
        sort_children(node, order);
    }

    fn child_count(&self) -> usize {
        node_at(self.usage.as_ref(), &self.usage_path).map_or(0, |node| node.children.len())
    }

    /// Lines of the reclaim list in screen order: by tier, then largest
    /// first. A line is one row, or every loose-file row of one rule in
    /// one directory.
    fn visible(&self) -> Vec<Vec<usize>> {
        let mut lines: Vec<Vec<usize>> = Vec::new();
        let mut grouped: Vec<(&str, &Path, usize)> = Vec::new();
        for (index, row) in self.rows.iter().enumerate() {
            if !self.filter.matches(row.kind) {
                continue;
            }
            let Some(directory) = self.group_directory(row) else {
                lines.push(vec![index]);
                continue;
            };
            let known = grouped
                .iter()
                .find(|(rule, path, _)| *rule == row.rule && *path == directory);
            if let Some((_, _, line)) = known {
                lines[*line].push(index);
            } else {
                grouped.push((row.rule.as_str(), directory, lines.len()));
                lines.push(vec![index]);
            }
        }

        lines.sort_by(|left, right| {
            let (first_left, first_right) = (&self.rows[left[0]], &self.rows[right[0]]);
            first_left
                .kind
                .cmp(&first_right.kind)
                .then(self.line_bytes(right).cmp(&self.line_bytes(left)))
                .then(self.line_path(left).cmp(self.line_path(right)))
                .then(first_left.rule.cmp(&first_right.rule))
        });
        lines
    }

    /// The directory a loose-file row is grouped under, if its rule groups.
    fn group_directory<'a>(&self, row: &'a Row) -> Option<&'a Path> {
        if row.kind != RowKind::Safe || !self.grouped_rules.contains(&row.rule) {
            return None;
        }
        row.path.parent()
    }

    fn line_bytes(&self, line: &[usize]) -> u64 {
        line.iter()
            .fold(0, |sum, index| sum.saturating_add(self.rows[*index].bytes))
    }

    /// What a line is called: the row's path, or the directory of a group.
    fn line_path(&self, line: &[usize]) -> &Path {
        let first = &self.rows[line[0]];
        self.group_directory(first).unwrap_or(&first.path)
    }

    fn anchor(&self) -> Option<PathBuf> {
        let visible = self.visible();
        let line = visible.get(self.cursor)?;
        Some(self.line_path(line).to_path_buf())
    }

    fn restore_anchor(&mut self, path: Option<PathBuf>) {
        let Some(path) = path else {
            self.clamp_reclaim();
            return;
        };
        let visible = self.visible();
        if let Some(pos) = visible.iter().position(|line| self.line_path(line) == path) {
            self.cursor = pos;
        } else {
            self.clamp_reclaim();
        }
    }

    /// The row space acts on. A group is safe rows, which space leaves alone.
    fn selected_row(&self) -> Option<usize> {
        self.visible().get(self.cursor).map(|line| line[0])
    }

    fn clamp_reclaim(&mut self) {
        let len = self.visible().len();
        if len == 0 {
            self.cursor = 0;
        } else if self.cursor >= len {
            self.cursor = len - 1;
        }
    }
}

impl Screen {
    const fn next(self) -> Self {
        match self {
            Self::Volumes => Self::Reclaim,
            Self::Reclaim => Self::Usage,
            Self::Usage => Self::Volumes,
        }
    }
}
impl Filter {
    fn next(self) -> Self {
        match self {
            Self::All => Self::Safe,
            Self::Safe => Self::Caution,
            Self::Caution => Self::Review,
            Self::Review => Self::All,
        }
    }

    fn matches(self, kind: RowKind) -> bool {
        match self {
            Self::All => true,
            Self::Safe => kind == RowKind::Safe,
            Self::Caution => kind == RowKind::Caution,
            Self::Review => kind == RowKind::Review,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Safe => "safe",
            Self::Caution => "caution",
            Self::Review => "review",
        }
    }
}

/// Why the TUI should not start.
///
/// `TERM=dumb` and a captured stdout both name `scan --format text`.
/// `NO_COLOR` is not a reason: it selects [`Palette::Plain`].
///
/// # Examples
///
/// ```
/// use disk_health::ui::refuse;
///
/// let message = refuse(false, Some("dumb")).unwrap();
/// assert!(message.contains("scan --format text"));
/// assert!(refuse(true, Some("xterm-256color")).is_none());
/// ```
#[must_use]
pub fn refuse(tty: bool, term: Option<&str>) -> Option<&'static str> {
    if !tty || term == Some("dumb") {
        Some("the terminal cannot draw the tui; run scan --format text")
    } else {
        None
    }
}

/// Picks a palette from `NO_COLOR`, then `COLORTERM`, then `TERM`.
///
/// # Examples
///
/// ```
/// use disk_health::ui::{Palette, palette_from};
///
/// assert_eq!(palette_from(Some("truecolor"), None, false), Palette::True);
/// assert_eq!(palette_from(None, None, false), Palette::Ansi16);
/// assert_eq!(palette_from(Some("256"), None, false), Palette::Ansi256);
/// assert_eq!(palette_from(None, Some("xterm-256color"), false), Palette::Ansi256);
/// assert_eq!(palette_from(Some("truecolor"), None, true), Palette::Plain);
/// ```
#[must_use]
pub fn palette_from(colorterm: Option<&str>, term: Option<&str>, no_color: bool) -> Palette {
    if no_color {
        return Palette::Plain;
    }
    if matches!(colorterm, Some("truecolor" | "24bit")) {
        return Palette::True;
    }

    // Terminal.app sets TERM and leaves COLORTERM empty. 256 colors are
    // what makes a meter readable there.
    if colorterm.is_some() || term.is_some_and(term_has_256) {
        Palette::Ansi256
    } else {
        Palette::Ansi16
    }
}

fn term_has_256(term: &str) -> bool {
    term.contains("256color") || term.contains("truecolor")
}

/// Decodes one read burst into the keys it holds, in order.
///
/// A held key or a pasted total arrives as several keys in one read. An
/// escape sequence this does not know is dropped whole, so its tail is not
/// typed into the confirm prompt.
///
/// # Examples
///
/// ```
/// use disk_health::ui::{Key, decode};
///
/// assert_eq!(decode(b"q"), [Key::Char('q')]);
/// assert_eq!(decode(b"jj\x1b[B\r"), [Key::Char('j'), Key::Char('j'), Key::Down, Key::Enter]);
/// assert_eq!(decode(&[0x1b]), [Key::Escape]);
/// ```
#[must_use]
pub fn decode(bytes: &[u8]) -> Vec<Key> {
    let mut keys = Vec::new();
    let mut rest = bytes;
    while let Some((&first, tail)) = rest.split_first() {
        rest = tail;
        let key = match first {
            0x1b if matches!(rest.first(), Some(b'[' | b'O')) => {
                let (key, after) = escape_sequence(&rest[1..]);
                rest = after;
                key
            }
            0x1b => Some(Key::Escape),
            0x7f | 0x08 => Some(Key::Backspace),
            b'\r' | b'\n' => Some(Key::Enter),
            b'\t' => Some(Key::Tab),
            byte if byte.is_ascii() && !byte.is_ascii_control() => {
                Some(Key::Char(char::from(byte)))
            }
            _ => None,
        };
        keys.extend(key);
    }
    keys
}

/// Reads the parameters and final byte after `ESC [` or `ESC O`.
fn escape_sequence(bytes: &[u8]) -> (Option<Key>, &[u8]) {
    // ECMA-48: parameter and intermediate bytes are 0x20..=0x3f, and one
    // final byte in 0x40..=0x7e ends the sequence.
    let params = bytes
        .iter()
        .take_while(|byte| (0x20..=0x3f).contains(*byte))
        .count();
    let Some(last) = bytes.get(params) else {
        return (None, &[]);
    };
    // Not a final byte, so this was not a sequence. Drop what was read of it
    // and let the byte be decoded as itself.
    if !(0x40..=0x7e).contains(last) {
        return (None, &bytes[params..]);
    }

    let key = match (&bytes[..params], *last) {
        (b"", b'A') => Some(Key::Up),
        (b"", b'B') => Some(Key::Down),
        (b"", b'C') => Some(Key::Right),
        (b"", b'D') => Some(Key::Left),
        (b"", b'H') | (b"1" | b"7", b'~') => Some(Key::Home),
        (b"", b'F') | (b"4" | b"8", b'~') => Some(Key::End),
        (b"5", b'~') => Some(Key::PageUp),
        (b"6", b'~') => Some(Key::PageDown),
        _ => None,
    };
    (key, &bytes[params + 1..])
}

/// Renders `model` to a string, at most as many lines as the terminal has.
///
/// [`Palette::Plain`] has tier words, block bars, and no escapes.
///
/// # Examples
///
/// ```
/// use disk_health::ui::{Model, Palette, render};
/// use std::time::UNIX_EPOCH;
///
/// let model = Model::new(Vec::new(), Vec::new(), Vec::new(), Palette::Plain, UNIX_EPOCH);
/// let frame = render(&model);
/// assert!(frame.contains("? help"));
/// assert!(frame.contains('─'));
/// assert!(!frame.contains('\u{1b}'));
/// ```
#[must_use]
pub fn render(model: &Model) -> String {
    let mut head = vec![title_line(model), rule_line(model)];
    head.extend(scan_line(model));
    let (body, focus) = if model.mode == Mode::Help {
        (help_body(model), 0)
    } else {
        head.extend(allocation_lines(model));
        match model.screen {
            Screen::Volumes => volume_body(model),
            Screen::Reclaim => reclaim_body(model),
            Screen::Usage => usage_body(model),
        }
    };
    let mut foot = vec![String::new(), footer_line(model)];
    foot.extend(message_line(model));

    // The bottom lines win on a short terminal. The confirm prompt is
    // there, and a prompt that takes keys without being drawn is worse than
    // a list that is cut. The meter above the list goes first.
    let foot = foot.split_off(foot.len().saturating_sub(model.term_rows));
    let above = model.term_rows - foot.len();
    if head.len() >= above {
        head.truncate(2.min(above));
    }

    let mut lines = head;
    let budget = above - lines.len();
    if budget > 0 {
        lines.extend(viewport(body, focus, budget));
    }
    lines.extend(foot);
    lines.join("\n")
}

/// Starts the UI, or refuses when the terminal cannot draw it.
///
/// A refused call does not scan and does not change the terminal.
///
/// # Errors
///
/// Returns [`crate::Error::Usage`] when stdout is not a terminal or `TERM`
/// is `dumb`. Later errors are a failed mount table, config file, or
/// terminal mode.
///
/// # Examples
///
/// ```
/// use disk_health::ui::{Session, run};
/// use std::path::Path;
///
/// let err = run(&Session {
///     tty: false,
///     term: None,
///     no_color: false,
///     colorterm: None,
///     home: Path::new("/home"),
/// })
/// .unwrap_err();
/// assert!(err.to_string().contains("scan --format text"));
/// ```
pub fn run(session: &Session<'_>) -> crate::Result<i32> {
    if let Some(message) = refuse(session.tty, session.term) {
        return Err(crate::Error::Usage {
            message: message.to_owned(),
        });
    }
    if let Some(note) = drive(session)? {
        print_note(&note);
    }
    Ok(0)
}

/// Repeats what the last apply did, once the terminal is the shell's again.
///
/// Leaving the alternate screen takes the UI's last frame with it. A stopped
/// apply reports in that frame and nowhere else, and "not logged, restore by
/// hand" has to outlive it.
#[allow(
    clippy::print_stdout,
    reason = "the apply result is the command's output"
)]
fn print_note(note: &str) {
    println!("{note}");
}

/// Inputs for [`run`]. The terminal flags are explicit so tests do not read
/// the process environment.
#[derive(Debug, Clone, Copy)]
pub struct Session<'a> {
    /// Whether stdout is a terminal.
    pub tty: bool,
    /// `TERM`, when set.
    pub term: Option<&'a str>,
    /// `NO_COLOR` was present. The UI draws without color.
    pub no_color: bool,
    /// `COLORTERM`, when set.
    pub colorterm: Option<&'a str>,
    /// Home directory passed to the scan.
    pub home: &'a Path,
}

/// Events taken off the channel between two reads of the keyboard.
const MAX_EVENTS_PER_TICK: usize = 512;

/// What a background thread hands back to the UI thread.
enum Event {
    Finding(Finding),
    ScanDone(ScanSummary),
    Review(Vec<Item>),
    Usage(std::result::Result<UsageNode, String>),
    Applied(std::result::Result<ApplyReport, String>),
}

/// Everything slow runs on a thread started here. The UI thread only reads
/// keys, takes events, and paints, so `q` always answers.
struct Background {
    home: PathBuf,
    /// Recorded in a plan. Looked up once, off the key path.
    host: String,
    loaded: Arc<Loaded>,
    events: mpsc::Sender<Event>,
    scan_dirs: Arc<AtomicU64>,
    walk_dirs: Arc<AtomicU64>,
    /// The one thread that renames. Joined before the driver returns.
    apply: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Background {
    /// Waits for a running apply on every way out of the driver, including
    /// an error from the terminal. The process exiting between a rename and
    /// its log line would leave a move that `restore` cannot find.
    fn drop(&mut self) {
        let Some(apply) = self.apply.take() else {
            return;
        };
        // `Release`: pairs with the `Acquire` load the apply loop makes
        // between entries. The flag guards no other data.
        crate::tty::interrupt_flag().store(true, Ordering::Release);
        // A panic in the apply thread has already been reported by the hook.
        let _ = apply.join();
    }
}

fn drive(session: &Session<'_>) -> crate::Result<Option<String>> {
    let loaded = crate::config::load(session.home)?;
    let (roots, denied) = crate::config::prepare_roots(&loaded.roots, &loaded.deny)?;
    let home_dev = crate::walk::RealFs.meta(session.home)?.dev;
    let volumes = crate::volumes::confine_to(crate::volumes::list_mounts()?, home_dev);
    let palette = palette_from(session.colorterm, session.term, session.no_color);
    let mut model = Model::new(volumes, Vec::new(), Vec::new(), palette, SystemTime::now());
    model.set_home(session.home);
    // Open on what the tool is for. The volumes screen has one line of
    // news, and the scan's results would be a keypress away from sight.
    model.screen = Screen::Reclaim;
    model.set_grouped_rules(
        loaded
            .safe_rules
            .iter()
            .filter(|rule| matches!(rule.anchor, crate::rules::SafeAnchor::Files(_)))
            .map(|rule| rule.id.to_owned())
            .collect(),
    );
    resize(&mut model);

    let raw = crate::tty::RawMode::enter(0, 1)
        .map_err(|source| crate::Error::io("set terminal mode", "/dev/tty", source))?;
    let _panic = crate::tty::PanicGuard::install(0, 1, raw.previous());
    let _signals = crate::tty::Signals::install_with_resize()
        .map_err(|source| crate::Error::io("install signals", "/dev/tty", source))?;

    let (events, inbox) = mpsc::channel();
    let mut background = Background {
        home: session.home.to_path_buf(),
        host: hostname(),
        loaded: Arc::new(loaded),
        events,
        scan_dirs: Arc::new(AtomicU64::new(0)),
        walk_dirs: Arc::new(AtomicU64::new(0)),
        apply: None,
    };
    // Detached on purpose. They only read, and quitting must not wait for a
    // walk of a large volume.
    background.spawn_scan(roots, denied.len());
    background.spawn_review();

    // `read_input` times out ten times a second. Painting an unchanged
    // frame at that rate flickers, so the revision has to move first.
    let mut drawn = 0;
    let mut pending = Pending::default();
    loop {
        // An apply is told to stop by the same flag and reports back. Leaving
        // before it does would drop the rows it skipped.
        if crate::tty::interrupted() && !model.applying() {
            return Ok(model.applied.take());
        }
        background.deliver(&mut model, &inbox);
        if crate::tty::take_resized() {
            resize(&mut model);
        }
        if model.revision != drawn {
            paint_frame(&model)?;
            drawn = model.revision;
        }

        let bytes = crate::tty::read_input(0)
            .map_err(|source| crate::Error::io("read key", "/dev/tty", source))?;
        for key in pending.take(bytes.as_deref()) {
            if background.act(&mut model, key) {
                return Ok(model.applied.take());
            }
        }
    }
}

/// Bytes read from the terminal that do not yet make a whole key.
///
/// A read can end in the middle of an escape sequence. Decoding it there
/// turns an arrow key into Escape followed by two letters, and Escape
/// cancels a prompt.
#[derive(Default)]
struct Pending(Vec<u8>);

impl Pending {
    /// Adds a read and returns the keys that are complete. `None` is a read
    /// that timed out: nothing more is coming, so what is held is the key.
    fn take(&mut self, read: Option<&[u8]>) -> Vec<Key> {
        let whole = match read {
            Some(bytes) => {
                self.0.extend_from_slice(bytes);
                whole_prefix(&self.0)
            }
            None => self.0.len(),
        };
        let keys = decode(&self.0[..whole]);
        self.0.drain(..whole);
        keys
    }
}

/// Length of the part of `bytes` that does not end inside an escape sequence.
fn whole_prefix(bytes: &[u8]) -> usize {
    let Some(start) = bytes.iter().rposition(|byte| *byte == 0x1b) else {
        return bytes.len();
    };
    let unfinished = match &bytes[start + 1..] {
        // A lone ESC is the Escape key, or the start of a sequence whose
        // rest is in the next read. A timed-out read settles which.
        [] => true,
        [b'[' | b'O', rest @ ..] => rest.iter().all(|byte| (0x20..=0x3f).contains(byte)),
        _ => false,
    };
    if unfinished { start } else { bytes.len() }
}

/// Takes the window size, when the terminal has one.
///
/// A pseudo-terminal nobody sized reports 0 by 0. That is "unknown", not a
/// window with no cells, and the model keeps the size it has.
fn resize(model: &mut Model) {
    if let Ok((rows, cols)) = crate::tty::window_size(0)
        && rows > 0
        && cols > 0
    {
        model.set_columns(usize::from(cols));
        model.set_rows(usize::from(rows));
    }
}

fn paint_frame(model: &Model) -> crate::Result<()> {
    crate::tty::write_frame(1, &frame_bytes(model))
        .map_err(|source| crate::Error::io("draw", "/dev/tty", source))
}

/// The frame as terminal output, after the cursor is homed.
///
/// Each line is erased before it is written, so nothing of a longer line
/// from the previous frame is left. Erasing after the text would start from
/// the pending-wrap position of a full-width line, and some terminals erase
/// the last cell there. Lines are joined, not terminated: a newline after
/// the last row of a full screen scrolls it and the title is gone.
fn frame_bytes(model: &Model) -> String {
    let frame = render(model);
    let mut painted = String::new();
    let mut lines = 0;
    for line in frame.split('\n') {
        if lines > 0 {
            painted.push_str("\r\n");
        }
        painted.push_str("\u{1b}[K");
        painted.push_str(line);
        lines += 1;
    }
    // Only when there are rows below the frame. On a full screen the erase
    // would begin at that same pending-wrap position.
    if lines < model.term_rows {
        painted.push_str("\r\n\u{1b}[J");
    }
    painted
}

impl Background {
    fn deliver(&self, model: &mut Model, inbox: &mpsc::Receiver<Event>) {
        // Bounded, so a scan that finds thousands of rows cannot keep the
        // loop from reading a key. The rest waits a tenth of a second.
        let mut found = Vec::new();
        for event in inbox.try_iter().take(MAX_EVENTS_PER_TICK) {
            match event {
                Event::Finding(finding) => found.push(finding),
                Event::ScanDone(summary) => model.finish_scan(&summary),
                Event::Review(items) => model.set_review(items),
                Event::Usage(Ok(tree)) => model.set_usage(tree),
                Event::Usage(Err(message)) => model.fail_walk(message),
                Event::Applied(Ok(report)) => model.finish_apply(&report),
                Event::Applied(Err(message)) => model.fail_apply(message),
            }
        }
        if !found.is_empty() {
            model.push_findings(found);
        }
        // `Relaxed`: these are counters for the status line and publish nothing else.
        model.set_scan_progress(self.scan_dirs.load(Ordering::Relaxed));
        model.set_walk_progress(self.walk_dirs.load(Ordering::Relaxed));
    }

    /// Applies one key. `true` means leave.
    fn act(&mut self, model: &mut Model, key: Key) -> bool {
        match model.handle(key) {
            Effect::Quit => return true,
            Effect::None => {}
            Effect::Interrupt => {
                // `Release`: pairs with the `Acquire` load the apply loop
                // makes between entries. The flag guards no other data.
                crate::tty::interrupt_flag().store(true, Ordering::Release);
            }
            Effect::WalkUsage { mount } => {
                model.begin_walk(mount.clone());
                self.spawn_walk(mount);
            }
            Effect::ConfirmApply { typed } => {
                // Typed size, not the plan id. `apply` would reject this path.
                let plan = model.plan(&self.host);
                model.begin_apply();
                self.spawn_apply(plan, typed);
            }
        }
        false
    }

    fn spawn_scan(&self, roots: Vec<PathBuf>, denied: usize) {
        let home = self.home.clone();
        let loaded = Arc::clone(&self.loaded);
        let events = self.events.clone();
        let dirs = Arc::clone(&self.scan_dirs);
        std::thread::spawn(move || {
            let found = events.clone();
            let notify = move |finding: &Finding| {
                let _ = found.send(Event::Finding(finding.clone()));
            };
            let progress = move |visited: u64| dirs.store(visited, Ordering::Relaxed);
            let report = crate::scan::scan(&crate::scan::ScanOptions {
                home: &home,
                roots: &roots,
                safe_rules: &loaded.safe_rules,
                project_rules: &loaded.project_rules,
                deny: &loaded.deny,
                now: SystemTime::now(),
                git: &crate::git::SystemGit,
                fs: &crate::walk::RealFs,
                progress: Some(&progress),
                on_finding: Some(&notify),
            });
            let summary = match report {
                Ok(report) => ScanSummary {
                    unreadable: report.unreadable,
                    roots_missing: report.roots_missing.len(),
                    roots_denied: report.roots_denied.len() + denied,
                    failed: None,
                },
                Err(err) => ScanSummary {
                    failed: Some(err.to_string()),
                    ..ScanSummary::default()
                },
            };
            let _ = events.send(Event::ScanDone(summary));
        });
    }

    fn spawn_review(&self) {
        let home = self.home.clone();
        let events = self.events.clone();
        std::thread::spawn(move || {
            let settings_path = home.join(".rustup/settings.toml");
            let settings = std::fs::read_to_string(settings_path).ok();
            let rows = crate::review::inventory(
                &crate::walk::RealFs,
                &home,
                SystemTime::now(),
                &crate::git::SystemWorktree,
                settings.as_deref(),
            );
            let _ = events.send(Event::Review(rows));
        });
    }

    fn spawn_walk(&self, mount: PathBuf) {
        let events = self.events.clone();
        let dirs = Arc::clone(&self.walk_dirs);
        dirs.store(0, Ordering::Relaxed);
        std::thread::spawn(move || {
            let progress = move |expanded: u64| dirs.store(expanded, Ordering::Relaxed);
            let tree = crate::usage::walk(
                &crate::walk::RealFs,
                &mount,
                crate::usage::DEFAULT_DEPTH,
                Some(&progress),
            );
            let _ = events.send(Event::Usage(tree.map_err(|err| err.to_string())));
        });
    }

    fn spawn_apply(&mut self, plan: Plan, typed: String) {
        let home = self.home.clone();
        let loaded = Arc::clone(&self.loaded);
        let events = self.events.clone();
        // The model takes no key but `q` while an apply runs, so the handle
        // this replaces belongs to an apply that already reported.
        self.apply = Some(std::thread::spawn(move || {
            let mut reply = Reply(Some(events));
            let report = apply_plan(&home, &loaded, &plan, &typed);
            reply.send(report.map_err(|err| err.to_string()));
        }));
    }
}

/// The apply thread's one message. The UI takes no key but `q` until it
/// arrives, so a thread that dies without sending it must still send it.
struct Reply(Option<mpsc::Sender<Event>>);

impl Reply {
    fn send(&mut self, result: std::result::Result<ApplyReport, String>) {
        if let Some(events) = self.0.take() {
            let _ = events.send(Event::Applied(result));
        }
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        self.send(Err(
            "the apply stopped without a report; check the action log".to_owned(),
        ));
    }
}

fn apply_plan(
    home: &Path,
    loaded: &Loaded,
    plan: &Plan,
    typed: &str,
) -> crate::Result<ApplyReport> {
    let filesystem = crate::walk::RealFs;
    let home_meta = filesystem.meta(home)?;
    let mut log = crate::log::FileLog::new(action_log(home));
    crate::trash::apply_typed_total(
        crate::trash::ApplyRequest {
            plan,
            confirm: "",
            home,
            home_dev: home_meta.dev,
            deny: &loaded.deny,
            safe_rules: &loaded.safe_rules,
            project_rules: &loaded.project_rules,
            fs: &filesystem,
            renamer: &crate::trash::FsRename,
            log: &mut log,
            now: SystemTime::now(),
            interrupt: Some(crate::tty::interrupt_flag()),
        },
        typed,
    )
}

fn apply_note(report: &ApplyReport, moved_bytes: u64) -> String {
    let unlogged = report.moved.iter().filter(|item| !item.logged).count();
    let mut note = format!(
        "moved {} ({})  skipped {}",
        report.moved.len(),
        format_bytes(moved_bytes),
        report.skipped.len()
    );
    if unlogged > 0 {
        // Writing to a `String` cannot fail.
        let _ = write!(note, "  {unlogged} not logged, restore by hand");
    }
    note
}

fn scan_note(summary: &ScanSummary) -> Option<String> {
    if let Some(failed) = &summary.failed {
        return Some(format!("scan failed: {failed}"));
    }

    let mut parts = Vec::new();
    if summary.unreadable > 0 {
        parts.push(format!("{} unreadable", summary.unreadable));
    }
    if summary.roots_missing > 0 {
        parts.push(format!("{} missing", roots(summary.roots_missing)));
    }
    if summary.roots_denied > 0 {
        parts.push(format!("{} refused", roots(summary.roots_denied)));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("scan done: {}", parts.join(", ")))
    }
}

fn roots(count: usize) -> String {
    if count == 1 {
        "1 root".to_owned()
    } else {
        format!("{count} roots")
    }
}

fn action_log(home: &Path) -> PathBuf {
    home.join("Library/Application Support/disk-health/actions.jsonl")
}

fn hostname() -> String {
    let output = std::process::Command::new("hostname").output();
    let Ok(output) = output else {
        return "unknown".to_owned();
    };
    if !output.status.success() {
        return "unknown".to_owned();
    }
    let text = String::from_utf8(output.stdout).unwrap_or_default();
    let text = text.trim();
    if text.is_empty() {
        "unknown".to_owned()
    } else {
        text.to_owned()
    }
}

fn motion(key: Key) -> Option<Motion> {
    match key {
        Key::Char('j') | Key::Down => Some(Motion::Down),
        Key::Char('k') | Key::Up => Some(Motion::Up),
        Key::PageDown => Some(Motion::PageDown),
        Key::PageUp => Some(Motion::PageUp),
        Key::Char('g') | Key::Home => Some(Motion::Top),
        Key::Char('G') | Key::End => Some(Motion::Bottom),
        _ => None,
    }
}

/// Rows a page key moves.
const PAGE: usize = 10;

fn moved(cursor: usize, motion: Motion, len: usize) -> usize {
    let last = len.saturating_sub(1);
    match motion {
        Motion::Up => cursor.saturating_sub(1),
        Motion::Down => cursor.saturating_add(1).min(last),
        Motion::PageUp => cursor.saturating_sub(PAGE),
        Motion::PageDown => cursor.saturating_add(PAGE).min(last),
        Motion::Top => 0,
        Motion::Bottom => last,
    }
}

fn row_from_finding(finding: Finding, now: SystemTime) -> Row {
    let kind = match finding.tier {
        Tier::Safe => RowKind::Safe,
        Tier::Caution => RowKind::Caution,
    };
    // The newest file inside, which is what the age gate looks at. A
    // directory's own mtime can be a month old while its tree is hot.
    let age = finding
        .newest
        .or(finding.mtime)
        .and_then(|newest| now.duration_since(newest).ok());
    Row {
        kind,
        rule: finding.rule.to_owned(),
        path: finding.path.clone(),
        bytes: finding.apparent_bytes,
        age,
        staged: finding.staged(),
        skipped: None,
        detail: finding_detail(&finding),
        finding: Some(finding),
    }
}

fn finding_detail(finding: &Finding) -> String {
    let mut detail = finding.rationale.to_owned();
    if let Some(skip) = finding.skip {
        detail.push_str("  held: ");
        detail.push_str(skip.as_str());
    }
    if let Some(regenerate) = finding.regenerate {
        detail.push_str("  refill: ");
        detail.push_str(regenerate);
    }
    if let Some(marker) = &finding.marker {
        detail.push_str("  marker: ");
        detail.push_str(&marker.display().to_string());
    }
    detail
}

fn row_from_review(item: Item) -> Row {
    let mut detail = item.note.to_owned();
    if let Some(branch) = &item.branch {
        detail.push_str("  branch: ");
        detail.push_str(branch);
    }
    if let Some(advice) = &item.advice {
        detail.push_str("  ");
        detail.push_str(advice);
    }
    Row {
        kind: RowKind::Review,
        rule: item.class.as_str().to_owned(),
        path: item.path,
        bytes: item.apparent_bytes,
        age: item.age,
        staged: false,
        skipped: None,
        detail,
        finding: None,
    }
}

fn entry_of(row: &Row) -> Option<Entry> {
    let finding = row.finding.as_ref()?;
    Some(Entry {
        rule: finding.rule.to_owned(),
        tier: finding.tier,
        path: finding.path.clone(),
        dev: finding.dev,
        ino: finding.ino,
        mtime_ns: finding.mtime.and_then(unix_nanos),
        newest_child_ns: finding.newest.and_then(unix_nanos),
        apparent_bytes: finding.apparent_bytes,
        staged: row.staged,
        regenerate: finding.regenerate.map(str::to_owned),
        marker: finding.marker.clone(),
    })
}

/// Why space leaves this row alone. `None` means it may be flipped.
///
/// The only gate an operator may override is age. A lock, a dirty tree, or
/// a tree the scan could not read all mean the scan does not know the row
/// is safe to move, and apply does not check git again.
fn toggle_refusal(row: &Row) -> Option<String> {
    let finding = match (row.kind, &row.finding) {
        (RowKind::Caution, Some(finding)) => finding,
        (RowKind::Safe, _) => return Some("safe rows follow the scan".to_owned()),
        (RowKind::Review | RowKind::Caution, _) => {
            return Some("review rows are never staged".to_owned());
        }
    };
    match finding.skip {
        None | Some(Skip::Young) => None,
        Some(skip) => Some(format!("held: {}", skip.as_str())),
    }
}

/// The few words of [`Skip`] that fit in a row.
const fn skip_label(skip: Skip) -> &'static str {
    match skip {
        Skip::Hot => "hot",
        Skip::Young => "young",
        Skip::Future => "future mtime",
        Skip::Locked => "locked",
        Skip::LockUnknown => "lock unknown",
        Skip::Dirty => "git dirty",
        Skip::GitUnknown => "git unknown",
        Skip::NestedGit => "nested git",
        Skip::CrossedDevice => "mount inside",
        Skip::UnknownAge => "no mtime",
        Skip::Partial => "unreadable",
    }
}

fn state_text(row: &Row) -> String {
    if row.kind == RowKind::Review {
        return "review".to_owned();
    }
    if row.staged {
        return "staged".to_owned();
    }
    if let Some(reason) = &row.skipped {
        return format!("skipped: {reason}");
    }
    match row.finding.as_ref().and_then(|finding| finding.skip) {
        Some(skip) => format!("held: {}", skip_label(skip)),
        None => "held".to_owned(),
    }
}
fn node_at<'a>(root: Option<&'a UsageNode>, path: &[usize]) -> Option<&'a UsageNode> {
    let mut node = root?;
    for index in path {
        node = node.children.get(*index)?;
    }
    Some(node)
}

fn node_at_mut<'a>(root: Option<&'a mut UsageNode>, path: &[usize]) -> Option<&'a mut UsageNode> {
    let mut node = root?;
    for index in path {
        node = node.children.get_mut(*index)?;
    }
    Some(node)
}

fn sort_children(node: &mut UsageNode, order: Order) {
    match order {
        Order::Size => node.children.sort_by(|left, right| {
            right
                .apparent_bytes
                .cmp(&left.apparent_bytes)
                .then(left.path.cmp(&right.path))
        }),
        Order::Name => node
            .children
            .sort_by(|left, right| left.path.cmp(&right.path)),
    }
}

/// The color of a word or of a bar's cells.
///
/// Plain ignores the ink and keeps the glyph, so a test can still see
/// which share is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ink {
    Safe,
    Caution,
    Review,
    Danger,
    Track,
    Title,
    Muted,
    Accent,
    Text,
    Slice(u8),
}

const SLICE_RGB: [(u8, u8, u8); 8] = [
    (88, 196, 184),
    (96, 168, 250),
    (184, 148, 255),
    (240, 176, 96),
    (240, 112, 144),
    (152, 214, 96),
    (120, 160, 190),
    (232, 130, 80),
];
const SLICE_256: [u8; 8] = [43, 75, 141, 215, 204, 149, 110, 209];
const SLICE_16: [u8; 8] = [36, 34, 35, 33, 31, 32, 37, 36];
const PLAIN_GLYPHS: [char; 5] = ['█', '▓', '▒', '░', '·'];

fn rule_line(model: &Model) -> String {
    let text = "─".repeat(model.columns.max(1));
    paint_fg(model.palette, Ink::Track, &text)
}

fn allocation_lines(model: &Model) -> Vec<String> {
    if model.screen == Screen::Usage {
        return Vec::new();
    }
    let totals = tier_totals(model);
    let total = totals
        .safe
        .saturating_add(totals.caution)
        .saturating_add(totals.review);
    if total == 0 {
        return Vec::new();
    }

    vec![
        String::new(),
        tier_legend(model, &totals),
        indent_meter(&tier_bar(model, &totals, total)),
        String::new(),
    ]
}

struct TierTotals {
    safe: u64,
    caution: u64,
    review: u64,
}

fn tier_totals(model: &Model) -> TierTotals {
    let mut totals = TierTotals {
        safe: 0,
        caution: 0,
        review: 0,
    };
    for row in &model.rows {
        match row.kind {
            RowKind::Safe => totals.safe = totals.safe.saturating_add(row.bytes),
            RowKind::Caution => totals.caution = totals.caution.saturating_add(row.bytes),
            RowKind::Review => totals.review = totals.review.saturating_add(row.bytes),
        }
    }
    totals
}

fn tier_legend(model: &Model, totals: &TierTotals) -> String {
    let safe = format!("SAFE {}", format_bytes(totals.safe));
    let caution = format!("CAUTION {}", format_bytes(totals.caution));
    let review = format!("REVIEW {}", format_bytes(totals.review));

    paint_line(
        model.palette,
        &[
            ("  ", Ink::Text),
            (safe.as_str(), Ink::Safe),
            ("   ", Ink::Text),
            (caution.as_str(), Ink::Caution),
            ("   ", Ink::Text),
            (review.as_str(), Ink::Review),
        ],
        model.columns,
    )
}

fn tier_bar(model: &Model, totals: &TierTotals, total: u64) -> String {
    let weights = [totals.safe, totals.caution, totals.review];
    let width = stacked_width(model.columns, &weights);
    let cells = shares(total, width, &weights);

    stack_meter(
        model.palette,
        &[
            (cells[0], Ink::Safe, tier_glyph(RowKind::Safe)),
            (cells[1], Ink::Caution, tier_glyph(RowKind::Caution)),
            (cells[2], Ink::Review, tier_glyph(RowKind::Review)),
        ],
    )
}

fn volume_card(model: &Model, volume: &Volume, selected: bool) -> Vec<String> {
    let pct = percent(volume.used_bytes, volume.total_bytes);
    let heat = heat_ink(pct);
    let mut lines = vec![volume_heading(model, volume, selected, heat, pct)];
    lines.push(indent_meter(&volume_meter(model, volume, heat)));
    if let Some(note) = volume.note {
        lines.push(paint_line(
            model.palette,
            &[("    ", Ink::Text), (note, Ink::Muted)],
            model.columns,
        ));
    }
    lines
}

fn volume_heading(model: &Model, volume: &Volume, selected: bool, heat: Ink, pct: u64) -> String {
    let marker = if selected { "▸ " } else { "  " };
    let marker_ink = if selected { Ink::Accent } else { Ink::Muted };
    let name_ink = if volume.walkable {
        Ink::Title
    } else {
        Ink::Muted
    };
    let name = format!("{}  {}", volume.mount.display(), volume.fstype);
    let stats = format!(
        "{} used  {} free  {pct:>3}%",
        format_bytes(volume.used_bytes),
        format_bytes(volume.available_bytes),
    );
    let used = cells(marker) + cells(&name) + cells(&stats);
    let gap = " ".repeat(gap_width(model.columns, used));

    paint_line(
        model.palette,
        &[
            (marker, marker_ink),
            (name.as_str(), name_ink),
            (gap.as_str(), Ink::Text),
            (stats.as_str(), heat),
        ],
        model.columns,
    )
}

fn volume_meter(model: &Model, volume: &Volume, heat: Ink) -> String {
    let width = guide_width(model.columns);
    let filled = magnitude(volume.used_bytes, volume.total_bytes, width);
    meter(model.palette, filled, width, heat, '█')
}

fn usage_body(model: &Model) -> (Vec<String>, usize) {
    let Some(node) = node_at(model.usage.as_ref(), &model.usage_path) else {
        return (vec!["  press u on a walkable volume".to_owned()], 0);
    };

    let mut lines = vec![
        usage_parent(model, node),
        usage_stack(model, node),
        String::new(),
    ];
    let parent_bytes = node.apparent_bytes;
    let mut focus = lines.len();
    for (index, child) in node.children.iter().enumerate() {
        if index == model.usage_cursor {
            focus = lines.len();
        }
        let selected = index == model.usage_cursor;
        lines.extend(usage_child(model, parent_bytes, index, child, selected));
    }
    (lines, focus)
}

fn usage_parent(model: &Model, node: &UsageNode) -> String {
    let path = node.path.display().to_string();
    let size = format_bytes(node.apparent_bytes);
    let gap = " ".repeat(gap_width(model.columns, cells(&path) + cells(&size) + 2));

    paint_line(
        model.palette,
        &[
            ("  ", Ink::Text),
            (path.as_str(), Ink::Title),
            (gap.as_str(), Ink::Text),
            (size.as_str(), Ink::Accent),
        ],
        model.columns,
    )
}

fn usage_stack(model: &Model, node: &UsageNode) -> String {
    let parts = usage_parts(node);
    let weights = parts.iter().map(|part| part.0).collect::<Vec<_>>();
    let width = stacked_width(model.columns, &weights);
    let total = weights
        .iter()
        .fold(0u64, |sum, weight| sum.saturating_add(*weight));
    let cells = shares(total, width, &weights);
    let painted = parts
        .iter()
        .zip(cells)
        .map(|(part, cells)| (cells, part.1, part.2))
        .collect::<Vec<_>>();

    indent_meter(&stack_meter(model.palette, &painted))
}

fn usage_parts(node: &UsageNode) -> Vec<(u64, Ink, char)> {
    let mut parts = Vec::new();
    for (index, child) in node.children.iter().enumerate() {
        parts.push((child.apparent_bytes, slice_ink(index), slice_glyph(index)));
    }

    let child_sum = parts
        .iter()
        .fold(0u64, |sum, part| sum.saturating_add(part.0));
    let rest = node.apparent_bytes.saturating_sub(child_sum);
    if rest > 0 {
        parts.push((rest, Ink::Track, '░'));
    }
    parts
}

fn usage_child(
    model: &Model,
    parent_bytes: u64,
    index: usize,
    child: &UsageNode,
    selected: bool,
) -> Vec<String> {
    let marker = if selected { "▸ " } else { "  " };
    let marker_ink = if selected { Ink::Accent } else { Ink::Muted };
    let ink = slice_ink(index);
    let name = file_label(&child.path);
    let share = pct_text(child.apparent_bytes, parent_bytes);
    let stats = format!("{}  {share}", format_bytes(child.apparent_bytes));
    let used = cells(marker) + cells(&name) + cells(&stats);
    let gap = " ".repeat(gap_width(model.columns, used));
    let heading = paint_line(
        model.palette,
        &[
            (marker, marker_ink),
            (name.as_str(), ink),
            (gap.as_str(), Ink::Text),
            (stats.as_str(), ink),
        ],
        model.columns,
    );

    let width = guide_width(model.columns);
    let filled = magnitude(child.apparent_bytes, parent_bytes, width);
    let bar = indent_meter(&meter(
        model.palette,
        filled,
        width,
        ink,
        slice_glyph(index),
    ));
    vec![heading, bar]
}

/// The three screens as tabs, the current one marked, and on the right
/// what the scan is doing and how much is staged.
fn title_line(model: &Model) -> String {
    let tabs = [
        (Screen::Volumes, "1 volumes"),
        (Screen::Reclaim, "2 reclaim"),
        (Screen::Usage, "3 usage"),
    ]
    .map(|(screen, label)| {
        if screen == model.screen {
            (format!("[{label}]"), Ink::Accent)
        } else {
            (format!(" {label} "), Ink::Muted)
        }
    });
    let scan = match (&model.walking, &model.scan) {
        (Some(mount), _) => {
            format!("walking {}  {} dirs", mount.display(), model.walk_dirs)
        }
        (_, ScanState::Running) => "scanning".to_owned(),
        (_, ScanState::Done) => "scan done".to_owned(),
        (_, ScanState::Failed) => "scan failed".to_owned(),
    };
    let staged = format!("   staged {}", format_bytes(model.staged_bytes()));

    let name = "disk-health ";
    let used = cells(name)
        + tabs
            .iter()
            .map(|(label, _)| cells(label) + 1)
            .sum::<usize>()
        + cells(&scan)
        + cells(&staged);
    let gap = " ".repeat(gap_width(model.columns, used));
    paint_line(
        model.palette,
        &[
            (name, Ink::Title),
            (" ", Ink::Text),
            (tabs[0].0.as_str(), tabs[0].1),
            (" ", Ink::Text),
            (tabs[1].0.as_str(), tabs[1].1),
            (" ", Ink::Text),
            (tabs[2].0.as_str(), tabs[2].1),
            (gap.as_str(), Ink::Text),
            (scan.as_str(), Ink::Muted),
            (staged.as_str(), Ink::Safe),
        ],
        model.columns,
    )
}

/// What the scan has done so far, on every screen while it runs.
///
/// The scan is on another thread and can take a while. Without this line
/// the only sign of it was a number in the corner of the title.
fn scan_line(model: &Model) -> Option<String> {
    if model.scan != ScanState::Running {
        return None;
    }
    let rows = model.rows.len();
    let found = model
        .rows
        .iter()
        .fold(0u64, |sum, row| sum.saturating_add(row.bytes));
    let noun = if rows == 1 { "row" } else { "rows" };
    let mut text = format!(
        "  scanning  {} project dirs walked, {rows} {noun} found ({})",
        model.scan_dirs,
        format_bytes(found)
    );
    if model.screen != Screen::Reclaim {
        text.push_str("  press 2 to see them");
    }
    Some(paint_line(
        model.palette,
        &[(text.as_str(), Ink::Accent)],
        model.columns,
    ))
}

fn help_body(model: &Model) -> Vec<String> {
    const LINES: &[&str] = &[
        "  everywhere",
        "    1 2 3, tab     switch screen",
        "    j k, arrows    move          g G, home end   first, last",
        "    page up, down  move a page   q               quit",
        "",
        "  volumes",
        "    u, enter       walk the selected volume into the usage screen",
        "    a              also list mounts that cannot be walked",
        "",
        "  reclaim",
        "    space          stage or hold a caution row (only age can be overridden)",
        "    d              show the full path, the rule's reason, and the marker",
        "    f              filter by tier",
        "    t              type the staged total to move those rows to the trash",
        "",
        "  usage",
        "    enter, right   open a directory   backspace, left   go up",
        "    s              sort by size or by name",
        "  any key closes this",
    ];
    LINES
        .iter()
        .map(|line| paint_line(model.palette, &[(line, Ink::Text)], model.columns))
        .collect()
}

fn volume_body(model: &Model) -> (Vec<String>, usize) {
    let shown = model.shown_volumes();
    if shown.is_empty() {
        return (vec!["  no walkable mounts; press a for all".to_owned()], 0);
    }

    let mut lines = Vec::new();
    let mut focus = 0;
    for (position, index) in shown.into_iter().enumerate() {
        let selected = position == model.volume_cursor;
        if position > 0 {
            lines.push(String::new());
        }
        if selected {
            focus = lines.len();
        }
        lines.extend(volume_card(model, &model.volumes[index], selected));
    }
    (lines, focus)
}

fn reclaim_body(model: &Model) -> (Vec<String>, usize) {
    let visible = model.visible();
    if visible.is_empty() {
        let text = match model.scan {
            ScanState::Running => "  rows appear here as the scan finds them",
            ScanState::Done => "  nothing to reclaim",
            ScanState::Failed => "  the scan failed before it found anything",
        };
        return (vec![text.to_owned()], 0);
    }

    let mut lines = Vec::new();
    let mut focus = 0;
    let mut group = None;
    let mut largest = 0;
    for (position, line) in visible.iter().enumerate() {
        let kind = model.rows[line[0]].kind;
        if group != Some(kind) {
            if group.is_some() {
                lines.push(String::new());
            }
            lines.push(group_heading(model, kind, &visible));
            group = Some(kind);
            // Lines are largest first within a tier, so this one is the scale.
            largest = model.line_bytes(line);
        }

        let selected = position == model.cursor;
        if selected {
            focus = lines.len();
        }
        lines.push(reclaim_line(model, line, selected, largest));
        if selected && model.detail {
            lines.extend(detail_lines(model, line));
        }
    }
    (lines, focus)
}

/// One line per tier: how many lines, how much, and how much of it is staged.
fn group_heading(model: &Model, kind: RowKind, visible: &[Vec<usize>]) -> String {
    let (mut count, mut bytes, mut staged) = (0usize, 0u64, 0u64);
    for line in visible {
        if model.rows[line[0]].kind != kind {
            continue;
        }
        count += 1;
        bytes = bytes.saturating_add(model.line_bytes(line));
        staged = staged.saturating_add(staged_bytes_of(model, line));
    }

    let word = format!("  {:<8}", tier_word(kind));
    let noun = if count == 1 { "row" } else { "rows" };
    let mut summary = format!("{count} {noun}  {}", format_bytes(bytes));
    if kind != RowKind::Review {
        // Writing to a `String` cannot fail.
        let _ = write!(summary, "  staged {}", format_bytes(staged));
    }
    paint_line(
        model.palette,
        &[
            (word.as_str(), tier_ink(kind)),
            (summary.as_str(), Ink::Muted),
        ],
        model.columns,
    )
}

fn staged_bytes_of(model: &Model, line: &[usize]) -> u64 {
    line.iter()
        .map(|index| &model.rows[*index])
        .filter(|row| row.staged)
        .fold(0, |sum, row| sum.saturating_add(row.bytes))
}

/// Cells in a reclaim row's bar.
const ROW_BAR: usize = 10;
/// Narrower than this, a row drops its bar and keeps the path.
const ROW_BAR_MIN_COLUMNS: usize = 72;
/// Narrower than this, a row drops the rule id, which `d` still shows.
const ROW_RULE_MIN_COLUMNS: usize = 100;

/// One line of the list. `largest` is the biggest line in the same tier:
/// the bar compares a row with its neighbours, and against the total of
/// every tier each of them would be a single cell.
fn reclaim_line(model: &Model, line: &[usize], selected: bool, largest: u64) -> String {
    let first = &model.rows[line[0]];
    let bytes = model.line_bytes(line);
    let marker = if selected { "▸ " } else { "  " };
    let marker_ink = if selected { Ink::Accent } else { Ink::Muted };
    let size = format!("{:>9} ", format_bytes(bytes));
    let lit = if selected { Ink::Title } else { Ink::Text };
    let mut out = paint_line(
        model.palette,
        &[(marker, marker_ink), (size.as_str(), lit)],
        model.columns,
    );
    let mut used = cells(marker) + cells(&size);

    if model.columns >= ROW_BAR_MIN_COLUMNS {
        let filled = magnitude(bytes, largest, ROW_BAR);
        out.push_str(&meter(
            model.palette,
            filled,
            ROW_BAR,
            tier_ink(first.kind),
            tier_glyph(first.kind),
        ));
        used += ROW_BAR;
    }

    let (state, state_ink) = line_state(model, line);
    let state = format!(" {state:<18}");
    let age = line.iter().filter_map(|index| model.rows[*index].age).min();
    let facts = if model.columns >= ROW_RULE_MIN_COLUMNS {
        format!("{:>5}  {:<22} ", age_text(age), first.rule)
    } else {
        format!("{:>5}  ", age_text(age))
    };
    let left = model.columns.saturating_sub(used);
    let room = left.saturating_sub(cells(&state) + cells(&facts));
    let path = line_label(model, line, room);
    let path_ink = if selected { Ink::Title } else { Ink::Muted };
    out.push_str(&paint_line(
        model.palette,
        &[
            (state.as_str(), state_ink),
            (facts.as_str(), Ink::Text),
            (path.as_str(), path_ink),
        ],
        left,
    ));
    out
}

/// The state column and its color: green moves, yellow waits, red failed.
fn line_state(model: &Model, line: &[usize]) -> (String, Ink) {
    if let [index] = line {
        let row = &model.rows[*index];
        let ink = match (row.kind, row.staged, &row.skipped) {
            (RowKind::Review, ..) => Ink::Review,
            (_, true, _) => Ink::Safe,
            (_, false, Some(_)) => Ink::Danger,
            (_, false, None) => Ink::Caution,
        };
        return (state_text(row), ink);
    }

    let staged = line
        .iter()
        .filter(|index| model.rows[**index].staged)
        .count();
    if staged == line.len() {
        ("staged".to_owned(), Ink::Safe)
    } else if staged == 0 {
        ("held".to_owned(), Ink::Caution)
    } else {
        (format!("staged {staged}/{}", line.len()), Ink::Safe)
    }
}

/// The path of a row, or the directory of a group and how many files it holds.
fn line_label(model: &Model, line: &[usize], room: usize) -> String {
    let path = shown_path(model, model.line_path(line));
    if line.len() == 1 && model.group_directory(&model.rows[line[0]]).is_none() {
        return short_tail(&path, room);
    }

    let noun = if line.len() == 1 { "file" } else { "files" };
    let count = format!("  {} {noun}", line.len());
    let mut label = short_tail(&path, room.saturating_sub(cells(&count)));
    label.push_str(&count);
    label
}

/// Files a group's detail lists before it says how many more there are.
const DETAIL_FILES: usize = 8;

/// The full path and the rule's reasons, wrapped so neither is cut. For a
/// group, the directory and then each file with its own state.
fn detail_lines(model: &Model, line: &[usize]) -> Vec<String> {
    const INDENT: &str = "      ";
    let width = model.columns.saturating_sub(INDENT.len()).max(1);
    let first = &model.rows[line[0]];
    let mut texts = vec![
        model.line_path(line).display().to_string(),
        format!("rule: {}", first.rule),
    ];
    if model.group_directory(first).is_none() {
        texts.push(first.detail.clone());
    } else {
        for index in line.iter().take(DETAIL_FILES) {
            let row = &model.rows[*index];
            texts.push(format!(
                "{:>9}  {:<14} {}",
                format_bytes(row.bytes),
                state_text(row),
                file_label(&row.path)
            ));
        }
        if line.len() > DETAIL_FILES {
            texts.push(format!("and {} more", line.len() - DETAIL_FILES));
        }
    }

    let mut lines = Vec::new();
    for text in &texts {
        for piece in wrapped(&printable(text), width) {
            lines.push(paint_line(
                model.palette,
                &[(INDENT, Ink::Text), (piece.as_str(), Ink::Muted)],
                model.columns,
            ));
        }
    }
    lines
}

/// `~/…` for a path under home, the whole path otherwise.
fn shown_path(model: &Model, path: &Path) -> String {
    let under_home = model
        .home
        .as_deref()
        .and_then(|home| path.strip_prefix(home).ok());
    match under_home {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

fn tier_word(kind: RowKind) -> &'static str {
    match kind {
        RowKind::Safe => "SAFE",
        RowKind::Caution => "CAUTION",
        RowKind::Review => "REVIEW",
    }
}

/// The keys that do something on this screen, and where the cursor is.
fn footer_line(model: &Model) -> String {
    let (keys, position) = match model.screen {
        Screen::Volumes => {
            let shown = model.shown_volumes().len();
            let hidden = model.volumes.len() - shown;
            let all = if model.all_volumes {
                "a walkable only".to_owned()
            } else {
                format!("a all mounts ({hidden} hidden)")
            };
            (
                format!("j/k move  u walk  {all}"),
                position_text(model.volume_cursor, shown),
            )
        }
        Screen::Reclaim => (
            format!(
                "space stage  d detail  f filter ({})  t apply",
                model.filter.as_str()
            ),
            position_text(model.cursor, model.visible().len()),
        ),
        Screen::Usage => {
            let order = match model.order {
                Order::Size => "size",
                Order::Name => "name",
            };
            (
                format!("j/k move  enter open  backspace up  s sort ({order})"),
                position_text(model.usage_cursor, model.child_count()),
            )
        }
    };

    // The position keeps its place. The key list is what gets cut, and `?`
    // has all of it.
    let room = model.columns.saturating_sub(cells(&position) + 1);
    let left = fit(&format!("{keys}  ? help  q quit"), room);
    let used = cells(&left) + cells(&position);
    let gap = " ".repeat(gap_width(model.columns, used));
    paint_line(
        model.palette,
        &[
            (left.as_str(), Ink::Muted),
            (gap.as_str(), Ink::Text),
            (position.as_str(), Ink::Muted),
        ],
        model.columns,
    )
}

fn position_text(cursor: usize, len: usize) -> String {
    if len == 0 {
        String::new()
    } else {
        format!("{}/{len}", cursor.min(len - 1) + 1)
    }
}

fn message_line(model: &Model) -> Option<String> {
    let (text, ink) = if model.mode == Mode::Confirm {
        let total = format_bytes(model.staged_bytes());
        let mut line = format!("confirm {total}  {}", model.typed);
        if !model.message.is_empty() {
            line.push_str("   ");
            line.push_str(&model.message);
        }
        (line, Ink::Caution)
    } else if model.applying() && model.message.is_empty() {
        let text = "applying  q stops after the current entry";
        (text.to_owned(), Ink::Caution)
    } else if model.message.is_empty() {
        return None;
    } else {
        (model.message.clone(), Ink::Accent)
    };
    Some(paint_line(model.palette, &[(&text, ink)], model.columns))
}

fn viewport(lines: Vec<String>, focus: usize, budget: usize) -> Vec<String> {
    if lines.len() <= budget {
        return lines;
    }

    let budget = budget.max(1);
    let focus = focus.min(lines.len() - 1);
    let mut start = focus.saturating_sub(budget / 2);
    if start + budget > lines.len() {
        start = lines.len() - budget;
    }
    lines.into_iter().skip(start).take(budget).collect()
}

/// Largest-remainder split. The cells sum to `width` when `total` is not 0,
/// so a stacked bar is the full guide and each segment is its share.
fn shares(total: u64, width: usize, weights: &[u64]) -> Vec<usize> {
    let mut cells = vec![0; weights.len()];
    if width == 0 || total == 0 {
        return cells;
    }

    let width_u = u64::try_from(width).unwrap_or(u64::MAX);
    let mut used = 0usize;
    let mut ranked = Vec::with_capacity(weights.len());
    for (index, weight) in weights.iter().copied().enumerate() {
        let product = weight.saturating_mul(width_u);
        let base = product.checked_div(total).unwrap_or(0);
        let rem = product.checked_rem(total).unwrap_or(0);
        cells[index] = usize::try_from(base).unwrap_or(width);
        used = used.saturating_add(cells[index]);
        ranked.push((rem, index));
    }
    if used >= width {
        return cells;
    }

    ranked.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let mut left = width - used;
    for (_, index) in ranked {
        if left == 0 {
            break;
        }
        cells[index] += 1;
        left -= 1;
    }
    cells
}

fn stacked_width(columns: usize, weights: &[u64]) -> usize {
    let gaps = weights
        .iter()
        .filter(|weight| **weight > 0)
        .count()
        .saturating_sub(1);
    guide_width(columns).saturating_sub(gaps).max(1)
}

fn guide_width(columns: usize) -> usize {
    columns.saturating_sub(2).max(1)
}

fn gap_width(columns: usize, used: usize) -> usize {
    columns.saturating_sub(used)
}

fn percent(part: u64, total: u64) -> u64 {
    part.saturating_mul(100).checked_div(total).unwrap_or(0)
}

fn pct_text(part: u64, total: u64) -> String {
    let pct = percent(part, total);
    if part > 0 && pct == 0 {
        " <1%".to_owned()
    } else {
        format!("{pct:>3}%")
    }
}

fn magnitude(part: u64, total: u64, width: usize) -> usize {
    if part == 0 || total == 0 || width == 0 {
        return 0;
    }
    let width_u = u64::try_from(width).unwrap_or(u64::MAX);
    let Some(cells) = part.saturating_mul(width_u).checked_div(total) else {
        return 0;
    };
    let cells = usize::try_from(cells).unwrap_or(width);
    cells.clamp(1, width)
}

fn meter(palette: Palette, filled: usize, width: usize, ink: Ink, glyph: char) -> String {
    let filled = filled.min(width);
    let mut out = paint_cells(palette, ink, glyph, filled);
    out.push_str(&paint_cells(palette, Ink::Track, '░', width - filled));
    out
}

fn stack_meter(palette: Palette, parts: &[(usize, Ink, char)]) -> String {
    let mut out = String::new();
    let mut drawn = false;
    for (cells, ink, glyph) in parts {
        if *cells == 0 {
            continue;
        }
        if drawn {
            out.push(' ');
        }
        out.push_str(&paint_cells(palette, *ink, *glyph, *cells));
        drawn = true;
    }
    out
}

fn indent_meter(meter: &str) -> String {
    format!("  {meter}")
}

fn paint_line(palette: Palette, pieces: &[(&str, Ink)], columns: usize) -> String {
    let mut left = columns;
    let mut out = String::new();
    for (text, ink) in pieces {
        if left == 0 {
            break;
        }
        let text = printable(text);
        let fitted = fit(&text, left);
        let taken = cells(&fitted);
        out.push_str(&paint_fg(palette, *ink, &fitted));
        left = left.saturating_sub(taken);
        if taken < cells(&text) {
            break;
        }
    }
    out
}

/// `text` with every control character replaced.
///
/// A file name can hold an escape sequence or a newline. Written as is, it
/// could move the cursor, clear the screen, or draw a line that looks like
/// the confirm prompt. Every path on screen goes through [`paint_line`].
fn printable(text: &str) -> std::borrow::Cow<'_, str> {
    if text.chars().any(char::is_control) {
        text.chars()
            .map(|ch| if ch.is_control() { '?' } else { ch })
            .collect::<String>()
            .into()
    } else {
        text.into()
    }
}

/// Terminal cells `text` takes.
fn cells(text: &str) -> usize {
    text.chars().map(char_cells).sum()
}

/// Cells one character takes: 2 for East Asian wide and emoji, 0 for
/// combining marks and joiners, 1 otherwise.
///
/// The ranges are the wide and zero-width blocks that turn up in file
/// names. A character outside them that a terminal draws wide makes a line
/// one cell too long.
fn char_cells(ch: char) -> usize {
    match u32::from(ch) {
        0x0300..=0x036F | 0x200B..=0x200F | 0xFE00..=0xFE0F => 0,
        0x1100..=0x115F
        | 0x2E80..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1FAFF
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

fn paint_fg(palette: Palette, ink: Ink, text: &str) -> String {
    wrap(fg_code(palette, ink), text)
}

/// Draws `count` cells of a bar.
///
/// The cells are block characters in the ink's color, not spaces on a
/// colored background. A dark track painted as background disappears on a
/// dark theme, and a bar that is one bright cell on an invisible track
/// reads as no bar at all. A glyph is there whatever the theme does.
fn paint_cells(palette: Palette, ink: Ink, glyph: char, count: usize) -> String {
    let shown = match (palette, ink) {
        (Palette::Plain, _) | (_, Ink::Track) => glyph,
        // With color, the color tells the tiers apart and the bar is solid.
        _ => '█',
    };
    let text: String = std::iter::repeat_n(shown, count).collect();
    paint_fg(palette, ink, &text)
}

fn wrap(code: Option<String>, text: &str) -> String {
    let Some(code) = code else {
        return text.to_owned();
    };
    if text.is_empty() {
        return String::new();
    }
    format!("\u{1b}[{code}m{text}\u{1b}[0m")
}

fn fg_code(palette: Palette, ink: Ink) -> Option<String> {
    match palette {
        Palette::Plain => None,
        Palette::Ansi16 => ansi16_fg(ink).map(|code| code.to_string()),
        Palette::Ansi256 => Some(format!("38;5;{}", ansi256(ink))),
        Palette::True => {
            let (red, green, blue) = rgb(ink);
            Some(format!("38;2;{red};{green};{blue}"))
        }
    }
}

fn rgb(ink: Ink) -> (u8, u8, u8) {
    match ink {
        Ink::Safe => (72, 201, 146),
        Ink::Caution => (240, 180, 70),
        Ink::Review => (138, 156, 240),
        Ink::Danger => (235, 98, 104),
        Ink::Track => (98, 104, 124),
        Ink::Title => (236, 238, 242),
        Ink::Muted => (140, 148, 162),
        Ink::Accent => (120, 210, 190),
        Ink::Text => (220, 224, 230),
        Ink::Slice(index) => SLICE_RGB[usize::from(index) % SLICE_RGB.len()],
    }
}

fn ansi256(ink: Ink) -> u8 {
    match ink {
        Ink::Safe => 42,
        Ink::Caution => 178,
        Ink::Review => 105,
        Ink::Danger => 196,
        Ink::Track => 240,
        Ink::Title => 255,
        Ink::Muted => 245,
        Ink::Accent => 43,
        Ink::Text => 252,
        Ink::Slice(index) => SLICE_256[usize::from(index) % SLICE_256.len()],
    }
}

fn ansi16_fg(ink: Ink) -> Option<u8> {
    let code = match ink {
        Ink::Text => return None,
        Ink::Safe => 32,
        Ink::Caution => 33,
        Ink::Review => 35,
        Ink::Danger => 31,
        Ink::Track | Ink::Muted => 2,
        Ink::Title => 97,
        Ink::Accent => 36,
        Ink::Slice(index) => SLICE_16[usize::from(index) % SLICE_16.len()],
    };
    Some(code)
}

fn tier_ink(kind: RowKind) -> Ink {
    match kind {
        RowKind::Safe => Ink::Safe,
        RowKind::Caution => Ink::Caution,
        RowKind::Review => Ink::Review,
    }
}

fn tier_glyph(kind: RowKind) -> char {
    match kind {
        RowKind::Safe => '█',
        RowKind::Caution => '▓',
        RowKind::Review => '·',
    }
}

fn heat_ink(pct: u64) -> Ink {
    if pct >= 90 {
        Ink::Danger
    } else if pct >= 75 {
        Ink::Caution
    } else {
        Ink::Safe
    }
}

fn slice_ink(index: usize) -> Ink {
    let index = u8::try_from(index % 8).unwrap_or(0);
    Ink::Slice(index)
}

fn slice_glyph(index: usize) -> char {
    PLAIN_GLYPHS[index % PLAIN_GLYPHS.len()]
}

fn file_label(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Keeps the end of `text`, which is the part of a path that tells rows apart.
fn short_tail(text: &str, columns: usize) -> String {
    if cells(text) <= columns {
        return text.to_owned();
    }
    if columns <= 1 {
        return String::new();
    }

    let mut kept = Vec::new();
    let mut used = 1;
    for ch in text.chars().rev() {
        used += char_cells(ch);
        if used > columns {
            break;
        }
        kept.push(ch);
    }
    std::iter::once('…').chain(kept.into_iter().rev()).collect()
}

fn age_text(age: Option<Duration>) -> String {
    let Some(age) = age else {
        return "n/a".to_owned();
    };
    let hours = age.as_secs() / 3600;
    if hours >= 48 {
        format!("{}d", hours / 24)
    } else {
        format!("{hours}h")
    }
}

fn fit(text: &str, columns: usize) -> String {
    if cells(text) <= columns {
        return text.to_owned();
    }
    if columns <= 1 {
        return String::new();
    }

    let mut out = String::new();
    let mut used = 1;
    for ch in text.chars() {
        used += char_cells(ch);
        if used > columns {
            break;
        }
        out.push(ch);
    }
    out.push('…');
    out
}

/// `text` cut into pieces of at most `columns` cells.
fn wrapped(text: &str, columns: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    let mut used = 0;
    for ch in text.chars() {
        let wide = char_cells(ch);
        if used + wide > columns && used > 0 {
            lines.push(String::new());
            used = 0;
        }
        if let Some(line) = lines.last_mut() {
            line.push(ch);
        }
        used += wide;
    }
    lines
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::rules::{Skip, Tier};

    fn finding(tier: Tier, path: &str, bytes: u64, staged: bool) -> Finding {
        Finding {
            rule: "fixture",
            tier,
            path: PathBuf::from(path),
            dev: 1,
            ino: 1,
            mtime: Some(UNIX_EPOCH),
            newest: Some(UNIX_EPOCH),
            apparent_bytes: bytes,
            regenerate: Some("refill"),
            marker: None,
            skip: if staged { None } else { Some(Skip::Young) },
            rationale: "because",
        }
    }

    fn review(path: &str) -> Item {
        Item {
            class: crate::review::Class::Inventory,
            path: PathBuf::from(path),
            apparent_bytes: 10,
            caution_child_bytes: 0,
            age: None,
            branch: None,
            dirty: None,
            upstream: None,
            ahead: None,
            behind: None,
            advice: None,
            active: false,
            note: "never delete",
        }
    }

    fn volume(mount: &str, walkable: bool) -> Volume {
        Volume {
            mount: PathBuf::from(mount),
            fstype: "apfs".to_owned(),
            total_bytes: 100,
            used_bytes: 40,
            available_bytes: 60,
            dev: 1,
            walkable,
            note: None,
        }
    }

    #[test]
    fn space_toggles_caution_only() {
        let caution = finding(Tier::Caution, "/proj/target", 50, false);
        let safe = finding(Tier::Safe, "/cache", 1536, true);
        let mut model = Model::new(
            Vec::new(),
            vec![caution, safe],
            vec![review("/sessions")],
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        // Largest row is first: the safe cache, then caution, then review.
        assert!(model.is_staged(Path::new("/cache")));
        model.handle(Key::Char(' '));
        assert!(model.is_staged(Path::new("/cache")));

        model.handle(Key::Char('j'));
        assert!(!model.is_staged(Path::new("/proj/target")));
        model.handle(Key::Char(' '));
        assert!(model.is_staged(Path::new("/proj/target")));
        model.handle(Key::Char(' '));
        assert!(!model.is_staged(Path::new("/proj/target")));

        model.handle(Key::Char('j'));
        model.handle(Key::Char(' '));
        assert!(!model.is_staged(Path::new("/sessions")));
    }

    #[test]
    fn confirm_requires_the_printed_total_and_quit_does_not_apply() {
        // 1, 2, and 3 are also the screen keys. Confirm must consume them.
        for (bytes, total) in [(1536, "1.5KiB"), (2048, "2.0KiB"), (3072, "3.0KiB")] {
            let safe = finding(Tier::Safe, "/cache", bytes, true);
            let mut model = Model::new(
                Vec::new(),
                vec![safe],
                Vec::new(),
                Palette::Plain,
                UNIX_EPOCH,
            );
            model.handle(Key::Char('2'));
            model.handle(Key::Char('t'));
            assert!(
                total.chars().any(|ch| matches!(ch, '1' | '2' | '3')),
                "{total}"
            );
            for ch in total.chars() {
                model.handle(Key::Char(ch));
            }
            assert_eq!(
                model.handle(Key::Enter),
                Effect::ConfirmApply {
                    typed: total.to_owned()
                }
            );
        }

        let safe = finding(Tier::Safe, "/cache", 1536, true);
        let mut model = Model::new(
            Vec::new(),
            vec![safe],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        model.handle(Key::Char('t'));
        model.handle(Key::Char('0'));
        assert_eq!(model.handle(Key::Enter), Effect::None);
        assert_eq!(model.handle(Key::Char('q')), Effect::Quit);
    }

    #[test]
    fn usage_screen_has_no_stage_effect() {
        let caution = finding(Tier::Caution, "/proj/target", 50, false);
        let mut model = Model::new(
            Vec::new(),
            vec![caution],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.set_usage(UsageNode {
            path: PathBuf::from("/vol"),
            apparent_bytes: 4,
            children: vec![UsageNode {
                path: PathBuf::from("/vol/dir"),
                apparent_bytes: 4,
                children: Vec::new(),
            }],
        });
        assert_eq!(model.handle(Key::Char(' ')), Effect::None);
        assert_eq!(model.handle(Key::Char('t')), Effect::None);
        assert!(!render(&model).contains("confirm"), "{}", render(&model));
        assert!(!model.is_staged(Path::new("/proj/target")));
        model.handle(Key::Enter);
        model.handle(Key::Backspace);
        assert_eq!(model.handle(Key::Char('q')), Effect::Quit);
    }

    #[test]
    fn plain_render_has_tier_words_and_no_color() {
        let mut model = Model::new(
            vec![volume("/Users", true)],
            vec![
                finding(Tier::Safe, "/cache", 10, true),
                finding(Tier::Caution, "/proj/target", 20, false),
            ],
            vec![review("/sessions")],
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        let frame = render(&model);
        assert!(frame.contains("SAFE"), "{frame}");
        assert!(frame.contains("CAUTION"), "{frame}");
        assert!(frame.contains("REVIEW"), "{frame}");
        assert!(frame.contains("f filter"), "{frame}");
        assert!(!frame.contains('\u{1b}'), "{frame}");
    }

    #[test]
    fn walk_usage_is_an_effect_and_dim_volumes_do_not_walk() {
        let mut model = Model::new(
            vec![volume("/System", false), volume("/Users", true)],
            Vec::new(),
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        // Only the walkable mount is listed until `a` asks for all of them.
        assert!(!render(&model).contains("/System"));
        model.handle(Key::Char('a'));
        assert!(render(&model).contains("/System"));
        model.handle(Key::Char('g'));
        assert_eq!(model.handle(Key::Char('u')), Effect::None);
        model.handle(Key::Char('j'));
        assert_eq!(
            model.handle(Key::Char('u')),
            Effect::WalkUsage {
                mount: PathBuf::from("/Users")
            }
        );
    }

    #[test]
    fn plan_omits_review_rows() {
        let mut model = Model::new(
            Vec::new(),
            vec![finding(Tier::Caution, "/proj/target", 50, false)],
            vec![review("/sessions")],
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        model.handle(Key::Char(' '));
        let plan = model.plan("host");
        assert_eq!(plan.entries.len(), 1);
        assert!(plan.entries[0].staged);
        assert_eq!(plan.entries[0].path, PathBuf::from("/proj/target"));
    }

    #[test]
    fn volume_bar_grows_with_used_space() {
        let low = render(&volume_model(10, Palette::Plain));
        let high = render(&volume_model(90, Palette::Plain));
        assert!(
            count_char(&high, '█') > count_char(&low, '█'),
            "{low}\n{high}"
        );
    }

    #[test]
    fn truecolor_volume_bar_uses_heat() {
        let cool = render(&volume_model(10, Palette::True));
        let hot = render(&volume_model(90, Palette::True));
        // Blocks in the foreground color. A background would vanish on a
        // theme whose own background is close to the track.
        assert!(cool.contains("\u{1b}[38;2;72;201;146m██"), "{cool}");
        assert!(hot.contains("\u{1b}[38;2;235;98;104m██"), "{hot}");
        assert!(!cool.contains("\u{1b}[48;"), "{cool}");
        assert!(cool.contains('░'), "{cool}");

        // With color every fill is the solid block. The shaded glyphs are
        // how the tiers are told apart without it.
        let mut model = Model::new(
            Vec::new(),
            vec![finding(Tier::Caution, "/proj/target", 20, false)],
            Vec::new(),
            Palette::True,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        let frame = render(&model);
        assert!(frame.contains('█') && !frame.contains('▓'), "{frame}");
    }

    #[test]
    fn reclaim_bars_follow_the_larger_share() {
        let mut model = Model::new(
            Vec::new(),
            vec![
                finding(Tier::Safe, "/cache", 80, true),
                finding(Tier::Caution, "/proj/target", 20, false),
            ],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        let frame = render(&model);
        assert!(count_char(&frame, '█') > count_char(&frame, '▓'), "{frame}");
        assert!(frame.contains("SAFE"));
        assert!(frame.contains("CAUTION"));
    }

    #[test]
    fn usage_bars_match_child_shares() {
        let mut model = Model::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.set_usage(UsageNode {
            path: PathBuf::from("/vol"),
            apparent_bytes: 100,
            children: vec![
                UsageNode {
                    path: PathBuf::from("/vol/big"),
                    apparent_bytes: 80,
                    children: Vec::new(),
                },
                UsageNode {
                    path: PathBuf::from("/vol/small"),
                    apparent_bytes: 20,
                    children: Vec::new(),
                },
            ],
        });
        let frame = render(&model);
        assert!(frame.contains("big"), "{frame}");
        assert!(frame.contains("small"), "{frame}");
        assert!(count_char(&frame, '█') > count_char(&frame, '▓'), "{frame}");
    }

    #[test]
    fn confirm_line_shows_the_typed_total() {
        let safe = finding(Tier::Safe, "/cache", 1536, true);
        let mut model = Model::new(
            Vec::new(),
            vec![safe],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        model.handle(Key::Char('t'));
        model.handle(Key::Char('1'));
        let frame = render(&model);
        assert!(frame.contains("confirm 1.5KiB  1"), "{frame}");
    }

    #[test]
    fn narrow_window_keeps_the_selected_row() {
        let findings = (0..12u64)
            .map(|index| {
                finding(
                    Tier::Safe,
                    &format!("/cache/{index:02}"),
                    1_000 - index,
                    true,
                )
            })
            .collect();
        let mut model = Model::new(Vec::new(), findings, Vec::new(), Palette::Plain, UNIX_EPOCH);
        model.handle(Key::Char('2'));
        model.set_rows(18);
        for _ in 0..11 {
            model.handle(Key::Char('j'));
        }
        let frame = render(&model);
        assert!(frame.contains("/cache/11"), "{frame}");
        assert!(!frame.contains("/cache/00"), "{frame}");
    }

    #[test]
    fn new_finding_keeps_the_selected_path() {
        let caution = finding(Tier::Caution, "/proj/target", 10, false);
        let mut model = Model::new(
            Vec::new(),
            vec![caution],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        model.push_finding(finding(Tier::Safe, "/cache", 500, true));
        model.handle(Key::Char(' '));
        assert!(model.is_staged(Path::new("/proj/target")));
    }

    fn held(tier: Tier, path: &str, skip: Skip) -> Finding {
        Finding {
            skip: Some(skip),
            ..finding(tier, path, 100, false)
        }
    }

    #[test]
    fn space_overrides_age_and_nothing_else() {
        let mut model = Model::new(
            Vec::new(),
            vec![
                held(Tier::Caution, "/a/target", Skip::Dirty),
                held(Tier::Caution, "/b/target", Skip::Locked),
                held(Tier::Caution, "/c/target", Skip::Partial),
                held(Tier::Caution, "/d/target", Skip::Young),
            ],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        let refused = [
            ("/a/target", "held: git tree is dirty"),
            ("/b/target", "held: another process holds a file lock"),
            ("/c/target", "held: could not read every entry"),
        ];
        for (path, why) in refused {
            model.handle(Key::Char(' '));
            assert!(!model.is_staged(Path::new(path)), "{path}");
            assert!(render(&model).contains(why), "{}", render(&model));
            model.handle(Key::Down);
        }
        model.handle(Key::Char(' '));
        assert!(model.is_staged(Path::new("/d/target")));
        let staged = model
            .plan("host")
            .entries
            .iter()
            .filter(|entry| entry.staged)
            .count();
        assert_eq!(staged, 1);
    }

    #[test]
    fn a_burst_is_every_key_in_it() {
        assert_eq!(
            decode(b"1.5GiB\r"),
            [
                Key::Char('1'),
                Key::Char('.'),
                Key::Char('5'),
                Key::Char('G'),
                Key::Char('i'),
                Key::Char('B'),
                Key::Enter
            ]
        );
        assert_eq!(
            decode(b"\x1b[A\x1b[B\x1bOC\x1b[D\x1b[5~\x1b[6~\x1b[H\x1b[F\t"),
            [
                Key::Up,
                Key::Down,
                Key::Right,
                Key::Left,
                Key::PageUp,
                Key::PageDown,
                Key::Home,
                Key::End,
                Key::Tab
            ]
        );
        // An unknown sequence is dropped whole. Its tail is not typed.
        assert_eq!(decode(b"\x1b[1;5Aq"), [Key::Char('q')]);
        assert_eq!(decode(b"\x1b["), []);
    }

    #[test]
    fn pasted_total_confirms() {
        let safe = finding(Tier::Safe, "/cache", 1536, true);
        let mut model = Model::new(
            Vec::new(),
            vec![safe],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        model.handle(Key::Char('t'));
        let effects = decode(b"1.5KiB\r")
            .into_iter()
            .map(|key| model.handle(key))
            .collect::<Vec<_>>();
        assert_eq!(
            effects.last(),
            Some(&Effect::ConfirmApply {
                typed: "1.5KiB".to_owned()
            })
        );
    }

    /// A model with every kind of row, a usage tree, and names that are
    /// hostile to a terminal: wide characters, an escape sequence, a newline.
    fn crowded_model() -> Model {
        let mut findings = (0..40u64)
            .map(|index| {
                finding(
                    Tier::Safe,
                    &format!("/cache/{index:02}"),
                    1_000 - index,
                    true,
                )
            })
            .collect::<Vec<_>>();
        findings.push(held(
            Tier::Caution,
            "/h/日本語のプロジェクト/ターゲット/target",
            Skip::Dirty,
        ));
        findings.push(held(
            Tier::Caution,
            "/h/a\u{1b}[2J\nb\nc/target",
            Skip::Young,
        ));
        let mut model = Model::new(
            vec![volume("/Data", true), volume("/System", false)],
            findings,
            vec![review("/sessions")],
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.set_usage(UsageNode {
            path: PathBuf::from("/vol"),
            apparent_bytes: 100,
            children: vec![
                UsageNode {
                    path: PathBuf::from("/vol/x\u{1b}]0;pwned\u{7}"),
                    apparent_bytes: 60,
                    children: Vec::new(),
                },
                UsageNode {
                    path: PathBuf::from("/vol/写真"),
                    apparent_bytes: 40,
                    children: Vec::new(),
                },
            ],
        });
        model
    }

    #[test]
    fn no_frame_is_taller_or_wider_than_the_terminal_or_holds_a_control_character() {
        // Each prefix leaves the model on another screen or in another mode.
        let scripts: [&[Key]; 7] = [
            &[Key::Char('1'), Key::Char('a')],
            &[Key::Char('2')],
            &[Key::Char('2'), Key::End, Key::Char('d')],
            &[Key::Char('2'), Key::Char('t'), Key::Char('9')],
            &[Key::Char('2'), Key::Char('t'), Key::Char('9'), Key::Enter],
            &[Key::Char('3')],
            &[Key::Char('?')],
        ];
        for keys in scripts {
            let mut model = crowded_model();
            for key in keys {
                model.handle(*key);
            }
            for (columns, rows) in [(1, 1), (7, 2), (20, 3), (40, 9), (80, 24), (131, 45)] {
                model.set_columns(columns);
                model.set_rows(rows);
                let frame = render(&model);
                assert!(
                    !frame.contains(|ch: char| ch.is_control() && ch != '\n'),
                    "{keys:?}"
                );
                let lines = frame.split('\n').collect::<Vec<_>>();
                assert!(
                    lines.len() <= rows,
                    "{keys:?} at {columns}x{rows}:\n{frame}"
                );
                for line in lines {
                    assert!(
                        cells(line) <= columns,
                        "{keys:?} at {columns}x{rows}: {line:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_full_frame_does_not_scroll_the_terminal() {
        let mut model = crowded_model();
        model.handle(Key::Char('2'));
        for rows in [1, 3, 12, 24] {
            model.set_rows(rows);
            assert_eq!(render(&model).split('\n').count(), rows, "{rows}");

            // A newline after the last row would scroll a full screen and
            // push the title off the top.
            let painted = frame_bytes(&model);
            assert_eq!(painted.matches("\r\n").count(), rows - 1, "{rows}");
            assert!(!painted.contains("\u{1b}[J"), "{rows}");
        }

        // A frame shorter than the screen erases what is below it.
        let mut model = volume_model(10, Palette::Plain);
        model.set_rows(30);
        assert!(frame_bytes(&model).ends_with("\r\n\u{1b}[J"));
    }

    #[test]
    fn the_prompt_is_drawn_on_any_terminal_that_accepts_it() {
        let safe = finding(Tier::Safe, "/cache", 1536, true);
        let mut model = Model::new(
            Vec::new(),
            vec![safe],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        model.handle(Key::Char('t'));
        model.handle(Key::Char('1'));
        for rows in 1..12 {
            model.set_rows(rows);
            assert!(
                render(&model).contains("confirm 1.5KiB  1"),
                "{rows} rows:\n{}",
                render(&model)
            );
        }
    }

    #[test]
    fn a_row_staged_while_the_total_is_typed_cancels_the_prompt() {
        let big = finding(Tier::Safe, "/cache", 1536 * 1024 * 1024, true);
        let mut model = Model::new(
            Vec::new(),
            vec![big],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        model.handle(Key::Char('t'));
        for key in decode(b"1.5GiB") {
            model.handle(key);
        }
        // A held row changes nothing that Enter would move.
        model.push_finding(held(Tier::Caution, "/proj/target", Skip::Dirty));
        assert!(render(&model).contains("confirm 1.5GiB  1.5GiB"));

        // 50 MiB more is still "1.5GiB" to one decimal place.
        model.push_finding(finding(Tier::Safe, "/more", 50 * 1024 * 1024, true));
        assert_eq!(format_bytes(model.staged_bytes()), "1.5GiB");
        assert!(render(&model).contains("the staged rows changed"));
        assert_eq!(model.handle(Key::Enter), Effect::None);
    }

    #[test]
    fn a_finished_walk_does_not_take_the_screen_from_a_prompt() {
        let safe = finding(Tier::Safe, "/cache", 1536, true);
        let mut model = Model::new(
            vec![volume("/Data", true)],
            vec![safe],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('u'));
        model.begin_walk(PathBuf::from("/Data"));
        model.handle(Key::Char('2'));
        model.handle(Key::Char('t'));
        model.set_usage(UsageNode {
            path: PathBuf::from("/Data"),
            apparent_bytes: 1,
            children: Vec::new(),
        });
        let frame = render(&model);
        assert!(frame.contains("[2 reclaim]"), "{frame}");
        assert!(frame.contains("confirm 1.5KiB"), "{frame}");
        assert!(frame.contains("press 3 to see it"), "{frame}");
    }

    #[test]
    fn a_walk_is_not_forgotten_when_an_apply_starts() {
        let mut model = volume_model(10, Palette::Plain);
        model.begin_walk(PathBuf::from("/Data"));
        model.begin_apply();
        model.finish_apply(&ApplyReport {
            moved: Vec::new(),
            skipped: Vec::new(),
        });
        // Still walking, so a second walk does not start.
        assert_eq!(model.handle(Key::Char('u')), Effect::None);
        assert!(render(&model).contains("still walking /Data"));
    }

    #[test]
    fn an_escape_sequence_split_across_two_reads_is_one_key() {
        let mut pending = Pending::default();
        assert_eq!(pending.take(Some(b"j\x1b")), [Key::Char('j')]);
        assert_eq!(pending.take(Some(b"[")), []);
        assert_eq!(pending.take(Some(b"B\x1b[5")), [Key::Down]);
        assert_eq!(pending.take(Some(b"~q")), [Key::PageUp, Key::Char('q')]);

        // Nothing follows a real Escape. The timed-out read delivers it.
        assert_eq!(pending.take(Some(b"\x1b")), []);
        assert_eq!(pending.take(None), [Key::Escape]);
        assert_eq!(pending.take(None), []);

        // An ESC inside what looked like a sequence starts a new one.
        assert_eq!(decode(b"\x1b[\x1b[B"), [Key::Down]);
    }

    #[test]
    fn going_up_sorts_the_parent_and_keeps_the_directory_selected() {
        let leaf = |path: &str, bytes| UsageNode {
            path: PathBuf::from(path),
            apparent_bytes: bytes,
            children: Vec::new(),
        };
        let mut model = Model::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.set_usage(UsageNode {
            path: PathBuf::from("/vol"),
            apparent_bytes: 100,
            children: vec![
                UsageNode {
                    children: vec![leaf("/vol/zebra/file", 70)],
                    ..leaf("/vol/zebra", 70)
                },
                leaf("/vol/apple", 30),
            ],
        });
        model.handle(Key::Enter);
        model.handle(Key::Char('s'));
        model.handle(Key::Backspace);

        let frame = render(&model);
        assert!(frame.contains("sort (name)"), "{frame}");
        assert!(frame.find("apple") < frame.find("zebra"), "{frame}");
        // The cursor is on the directory that was left, now second.
        assert!(frame.contains("▸ zebra"), "{frame}");
    }

    #[test]
    fn one_line_per_row_under_a_tier_heading() {
        let findings = (0..12u64)
            .map(|index| {
                finding(
                    Tier::Safe,
                    &format!("/cache/{index:02}"),
                    1_000 - index,
                    true,
                )
            })
            .collect();
        let mut model = Model::new(Vec::new(), findings, Vec::new(), Palette::Plain, UNIX_EPOCH);
        model.handle(Key::Char('2'));
        model.set_rows(18);
        let frame = render(&model);
        let shown = frame.matches("/cache/").count();
        assert!(shown >= 8, "{shown} rows in 18 lines:\n{frame}");
        assert!(
            frame.contains("SAFE    12 rows  11.6KiB  staged 11.6KiB"),
            "{frame}"
        );
        assert!(frame.contains("1/12"), "{frame}");
    }

    #[test]
    fn applied_rows_leave_and_skipped_rows_say_why() {
        let mut model = Model::new(
            Vec::new(),
            vec![
                finding(Tier::Safe, "/moved", 2048, true),
                finding(Tier::Safe, "/busy", 1024, true),
            ],
            vec![review("/sessions")],
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        model.begin_apply();
        assert_eq!(model.handle(Key::Char('2')), Effect::None);
        assert_eq!(model.handle(Key::Char('q')), Effect::Interrupt);

        model.finish_apply(&ApplyReport {
            moved: vec![crate::trash::Moved {
                from: PathBuf::from("/moved"),
                to: PathBuf::from("/trash/0-moved"),
                id: "id".to_owned(),
                logged: true,
            }],
            skipped: vec![crate::trash::Skipped {
                path: PathBuf::from("/busy"),
                reason: crate::trash::SkipMove::Locked,
            }],
        });
        assert!(!model.applying());
        assert_eq!(model.staged_bytes(), 0);
        let frame = render(&model);
        assert!(!frame.contains("/moved"), "{frame}");
        assert!(frame.contains("skipped: path is locked"), "{frame}");
        assert!(frame.contains("moved 1 (2.0KiB)  skipped 1"), "{frame}");
        assert!(frame.contains("/sessions"), "{frame}");
    }

    #[test]
    fn no_color_draws_plain_and_is_not_refused() {
        assert_eq!(refuse(true, Some("xterm-256color")), None);
        let palette = palette_from(Some("truecolor"), Some("xterm-256color"), true);
        let frame = render(&volume_model(50, palette));
        assert!(!frame.contains('\u{1b}'), "{frame}");
        assert!(frame.contains('█'), "{frame}");
    }

    #[test]
    fn title_follows_the_scan_and_a_walk() {
        let mut model = volume_model(10, Palette::Plain);
        model.set_scan_progress(4_000);
        let frame = render(&model);
        assert!(
            frame.contains("[1 volumes]  2 reclaim   3 usage"),
            "{frame}"
        );
        assert!(
            frame.contains("scanning  4000 project dirs walked, 0 rows found (0B)  press 2"),
            "{frame}"
        );
        model.finish_scan(&ScanSummary {
            unreadable: 3,
            roots_missing: 1,
            ..ScanSummary::default()
        });
        let frame = render(&model);
        assert!(frame.contains("scan done"), "{frame}");
        assert!(!frame.contains("project dirs walked"), "{frame}");
        assert!(frame.contains("3 unreadable, 1 root missing"), "{frame}");

        assert_eq!(
            model.handle(Key::Char('u')),
            Effect::WalkUsage {
                mount: PathBuf::from("/Data")
            }
        );
        model.begin_walk(PathBuf::from("/Data"));
        model.set_walk_progress(12);
        assert!(render(&model).contains("walking /Data  12 dirs"));
        // The walk is elsewhere. Keys still answer, and a second walk waits.
        assert_eq!(model.handle(Key::Char('u')), Effect::None);
        assert!(render(&model).contains("still walking /Data"));
    }

    #[test]
    fn a_leaf_is_not_entered() {
        let mut model = Model::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.set_usage(UsageNode {
            path: PathBuf::from("/vol"),
            apparent_bytes: 4,
            children: vec![UsageNode {
                path: PathBuf::from("/vol/file"),
                apparent_bytes: 4,
                children: Vec::new(),
            }],
        });
        model.handle(Key::Enter);
        let frame = render(&model);
        assert!(frame.contains("nothing listed below file"), "{frame}");
        assert!(frame.contains("/vol"), "{frame}");
    }

    #[test]
    fn paths_under_home_are_shortened_and_keep_their_tail() {
        let long =
            "/Users/ada/Documents/Github/some-organisation/some-repository/crates/inner/target";
        let mut model = Model::new(
            Vec::new(),
            vec![finding(Tier::Caution, long, 10, false)],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.set_home(Path::new("/Users/ada"));
        model.handle(Key::Char('2'));
        let frame = render(&model);
        assert!(frame.contains("inner/target"), "{frame}");
        assert!(!frame.contains("/Users/ada"), "{frame}");
        // Detail wraps the whole path. Nothing is cut.
        model.handle(Key::Char('d'));
        let frame = render(&model);
        let (first, second) = long.split_at(74);
        assert!(frame.contains(first) && frame.contains(second), "{frame}");
    }

    #[test]
    fn loose_files_of_one_rule_are_one_line_and_stay_separate_plan_entries() {
        let mut findings = (0..12u64)
            .map(|index| Finding {
                rule: "logs",
                ..finding(
                    Tier::Safe,
                    &format!("/h/.tool/logs/{index:02}.log"),
                    100,
                    index < 9,
                )
            })
            .collect::<Vec<_>>();
        findings.push(finding(Tier::Safe, "/h/.cargo/registry", 5_000, true));
        let mut model = Model::new(Vec::new(), findings, Vec::new(), Palette::Plain, UNIX_EPOCH);
        model.set_grouped_rules(vec!["logs".to_owned()]);
        model.set_home(Path::new("/h"));
        model.handle(Key::Char('2'));

        let frame = render(&model);
        assert!(frame.contains("SAFE    2 rows"), "{frame}");
        assert!(frame.contains("staged 9/12"), "{frame}");
        assert!(frame.contains("~/.tool/logs  12 files"), "{frame}");
        assert!(!frame.contains("00.log"), "{frame}");
        assert!(frame.contains("1/2"), "{frame}");

        // Detail lists the files, and stops before it fills the screen.
        model.handle(Key::Down);
        model.handle(Key::Char('d'));
        let frame = render(&model);
        assert!(
            frame.contains("00.log") && frame.contains("and 4 more"),
            "{frame}"
        );

        // Space leaves a group alone, and the plan still names every file.
        model.handle(Key::Char(' '));
        let plan = model.plan("host");
        assert_eq!(plan.entries.len(), 13);
        assert_eq!(plan.entries.iter().filter(|entry| entry.staged).count(), 10);
    }

    #[test]
    fn a_row_bar_compares_rows_within_their_tier() {
        let mut model = Model::new(
            Vec::new(),
            vec![
                finding(Tier::Caution, "/huge/target", 100_000, false),
                finding(Tier::Safe, "/a", 1_000, true),
                finding(Tier::Safe, "/b", 500, true),
            ],
            Vec::new(),
            Palette::Plain,
            UNIX_EPOCH,
        );
        model.handle(Key::Char('2'));
        let frame = render(&model);
        let bar = |path: &str| {
            let line = frame.lines().find(|line| line.ends_with(path)).unwrap();
            count_char(line, '█')
        };
        // Against the total of every tier both would be a single cell.
        assert_eq!(bar("/a"), 10, "{frame}");
        assert_eq!(bar("/b"), 5, "{frame}");
    }

    #[test]
    fn age_is_the_newest_file_not_the_directory() {
        let now = UNIX_EPOCH + Duration::from_hours(100 * 24);
        let hot = Finding {
            mtime: Some(UNIX_EPOCH),
            newest: Some(now - Duration::from_hours(3)),
            skip: Some(Skip::Hot),
            ..finding(Tier::Safe, "/cache", 10, false)
        };
        let mut model = Model::new(Vec::new(), vec![hot], Vec::new(), Palette::Plain, now);
        model.handle(Key::Char('2'));
        let frame = render(&model);
        assert!(frame.contains("held: hot"), "{frame}");
        assert!(frame.contains("   3h  "), "{frame}");
        assert!(!frame.contains("100d"), "{frame}");
    }

    fn volume_model(used: u64, palette: Palette) -> Model {
        let mut disk = volume("/Data", true);
        disk.used_bytes = used;
        disk.total_bytes = 100;
        disk.available_bytes = 100 - used;
        Model::new(vec![disk], Vec::new(), Vec::new(), palette, UNIX_EPOCH)
    }

    fn count_char(text: &str, glyph: char) -> usize {
        text.chars().filter(|ch| *ch == glyph).count()
    }
}
