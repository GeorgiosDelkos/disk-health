//! Three screens over the scan, the review inventory, and one usage tree.
//!
//! Each screen leads with a bar. Volumes show used and free. Reclaim shows
//! how the measured bytes split across safe, caution, and review. Usage shows
//! each child as a share of its parent. [`Palette::Plain`] draws those bars
//! with block characters and no color.
//!
//! [`Model::handle`] is a pure function of a key. Tests drive it without a
//! terminal. The only mutation it can ask for is [`Effect::ConfirmApply`],
//! and the caller fulfills that by [`crate::trash::apply_typed_total`].
//! Space changes a caution row. It does not change a safe row or a review row.
//! The usage screen has no stage key.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::plan::{Entry, Plan};
use crate::report::format_bytes;
use crate::review::Item;
use crate::rules::Tier;
use crate::scan::Finding;
use crate::time::unix_nanos;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    Safe,
    Caution,
    Review,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Toggle {
    /// Space does nothing.
    Fixed,
    /// Space flips [`Row::staged`].
    Caution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    kind: RowKind,
    word: &'static str,
    rule: String,
    path: PathBuf,
    bytes: u64,
    age: Option<Duration>,
    regenerate: Option<String>,
    staged: bool,
    toggle: Toggle,
    detail: String,
    finding: Option<Finding>,
}

/// The UI state. Rendering reads it. Keys go through [`Self::handle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    screen: Screen,
    palette: Palette,
    columns: usize,
    volumes: Vec<Volume>,
    rows: Vec<Row>,
    usage: Option<UsageNode>,
    now: SystemTime,
    cursor: usize,
    volume_cursor: usize,
    usage_cursor: usize,
    usage_path: Vec<usize>,
    filter: Filter,
    detail: bool,
    confirming: bool,
    typed: String,
    message: String,
    sort_by_size: bool,
    /// Terminal height. The list scrolls inside what this leaves after the
    /// title and the footer.
    term_rows: usize,
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
            volumes,
            rows,
            usage: None,
            now,
            cursor: 0,
            volume_cursor: 0,
            usage_cursor: 0,
            usage_path: Vec::new(),
            filter: Filter::All,
            detail: false,
            confirming: false,
            typed: String::new(),
            message: String::new(),
            sort_by_size: true,
            term_rows: 40,
            revision: 1,
        }
    }

    fn bump(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    /// Applies one key.
    ///
    /// `q` quits while a total is being typed. `1`, `2`, and `3` are
    /// characters during confirm: the printed total contains those digits,
    /// and treating them as screen changes would drop the prompt.
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
        if key == Key::Char('q') {
            return Effect::Quit;
        }
        if self.confirming && self.screen == Screen::Reclaim {
            return self.handle_confirm(key);
        }
        if self.switch_screen(key) {
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
        let anchor = self.anchor();
        let path = finding.path.clone();
        let rule = finding.rule;

        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|row| row.rule == rule && row.path == path)
        {
            *row = row_from_finding(finding, self.now);
        } else {
            self.rows.push(row_from_finding(finding, self.now));
        }

        self.restore_anchor(anchor);
        self.bump();
    }

    /// Replaces review rows. Finding rows stay, including their staged bits.
    pub fn set_review(&mut self, items: Vec<Item>) {
        let anchor = self.anchor();
        self.rows.retain(|row| row.finding.is_some());
        self.rows.extend(items.into_iter().map(row_from_review));
        self.restore_anchor(anchor);
        self.bump();
    }

    /// Shows a usage tree and switches to that screen.
    pub fn set_usage(&mut self, node: UsageNode) {
        self.usage = Some(node);
        self.usage_path.clear();
        self.usage_cursor = 0;
        self.screen = Screen::Usage;
        self.sort_current();
        self.bump();
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

    fn switch_screen(&mut self, key: Key) -> bool {
        let Some(screen) = screen_key(key) else {
            return false;
        };
        self.screen = screen;
        self.confirming = false;
        self.typed.clear();
        true
    }

    fn handle_volumes(&mut self, key: Key) -> Effect {
        match key {
            Key::Char('j') => {
                self.volume_cursor = step(self.volume_cursor, 1, self.volumes.len());
                Effect::None
            }
            Key::Char('k') => {
                self.volume_cursor = step(self.volume_cursor, -1, self.volumes.len());
                Effect::None
            }
            Key::Char('u') => self.walk_selected(),
            _ => Effect::None,
        }
    }

    fn walk_selected(&mut self) -> Effect {
        let Some(volume) = self.volumes.get(self.volume_cursor) else {
            return Effect::None;
        };
        if !volume.walkable {
            self.message = format!("not walkable: {}", volume.mount.display());
            return Effect::None;
        }
        Effect::WalkUsage {
            mount: volume.mount.clone(),
        }
    }

    fn handle_reclaim(&mut self, key: Key) -> Effect {
        match key {
            Key::Char('j') => {
                self.cursor = step(self.cursor, 1, self.visible().len());
                Effect::None
            }
            Key::Char('k') => {
                self.cursor = step(self.cursor, -1, self.visible().len());
                Effect::None
            }
            Key::Char(' ') => {
                self.toggle_selected();
                Effect::None
            }
            Key::Char('d') => {
                self.detail = !self.detail;
                Effect::None
            }
            Key::Char('t') => {
                self.begin_confirm();
                Effect::None
            }
            Key::Char('f') => {
                self.filter = self.filter.next();
                self.clamp_reclaim();
                Effect::None
            }
            _ => Effect::None,
        }
    }

    fn toggle_selected(&mut self) {
        let Some(index) = self.selected_row() else {
            return;
        };
        if self.rows[index].toggle != Toggle::Caution {
            return;
        }
        self.rows[index].staged = !self.rows[index].staged;
    }

    fn begin_confirm(&mut self) {
        self.confirming = true;
        self.typed.clear();
        let total = format_bytes(self.staged_bytes());
        self.message = format!("type {total} and press enter");
    }

    fn handle_confirm(&mut self, key: Key) -> Effect {
        match key {
            Key::Enter => self.finish_confirm(),
            Key::Backspace => {
                self.typed.pop();
                Effect::None
            }
            Key::Escape => {
                self.confirming = false;
                self.typed.clear();
                Effect::None
            }
            Key::Char(ch) => {
                self.typed.push(ch);
                Effect::None
            }
        }
    }

    fn finish_confirm(&mut self) -> Effect {
        let expected = format_bytes(self.staged_bytes());
        if self.typed == expected {
            self.confirming = false;
            Effect::ConfirmApply { typed: expected }
        } else {
            self.message = format!("type {expected} to confirm");
            Effect::None
        }
    }

    fn handle_usage(&mut self, key: Key) -> Effect {
        match key {
            Key::Char('j') => {
                self.usage_cursor = step(self.usage_cursor, 1, self.child_count());
                Effect::None
            }
            Key::Char('k') => {
                self.usage_cursor = step(self.usage_cursor, -1, self.child_count());
                Effect::None
            }
            Key::Char('s') => {
                self.sort_by_size = !self.sort_by_size;
                self.sort_current();
                Effect::None
            }
            Key::Enter => {
                self.descend();
                Effect::None
            }
            Key::Backspace => {
                self.ascend();
                Effect::None
            }
            _ => Effect::None,
        }
    }

    fn descend(&mut self) {
        let count = self.child_count();
        if count == 0 || self.usage_cursor >= count {
            return;
        }
        self.usage_path.push(self.usage_cursor);
        self.usage_cursor = 0;
    }

    fn ascend(&mut self) {
        if let Some(index) = self.usage_path.pop() {
            self.usage_cursor = index;
        }
    }

    fn sort_current(&mut self) {
        let by_size = self.sort_by_size;
        let path = self.usage_path.clone();
        let Some(node) = node_at_mut(self.usage.as_mut(), &path) else {
            return;
        };
        sort_children(node, by_size);
    }

    fn child_count(&self) -> usize {
        node_at(self.usage.as_ref(), &self.usage_path).map_or(0, |node| node.children.len())
    }

    fn visible(&self) -> Vec<usize> {
        let mut indexes = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| self.filter.matches(row.kind))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        // Largest allocation first, so the bar the eye meets is the heavy one.
        indexes.sort_by(|&left, &right| {
            self.rows[right]
                .bytes
                .cmp(&self.rows[left].bytes)
                .then(self.rows[left].path.cmp(&self.rows[right].path))
                .then(self.rows[left].rule.cmp(&self.rows[right].rule))
        });
        indexes
    }

    fn anchor(&self) -> Option<PathBuf> {
        let index = *self.visible().get(self.cursor)?;
        Some(self.rows[index].path.clone())
    }

    fn restore_anchor(&mut self, path: Option<PathBuf>) {
        let Some(path) = path else {
            self.clamp_reclaim();
            return;
        };
        let visible = self.visible();
        if let Some(pos) = visible
            .iter()
            .position(|index| self.rows[*index].path == path)
        {
            self.cursor = pos;
        } else {
            self.clamp_reclaim();
        }
    }

    fn selected_row(&self) -> Option<usize> {
        self.visible().get(self.cursor).copied()
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
/// `NO_COLOR`, `TERM=dumb`, and a captured stdout all name `scan --format text`.
///
/// # Examples
///
/// ```
/// use disk_health::ui::refuse;
///
/// let message = refuse(false, Some("dumb"), true).unwrap();
/// assert!(message.contains("scan --format text"));
/// assert!(refuse(true, Some("xterm-256color"), false).is_none());
/// ```
#[must_use]
pub fn refuse(tty: bool, term: Option<&str>, no_color: bool) -> Option<&'static str> {
    if !tty || term == Some("dumb") || no_color {
        Some("the terminal cannot draw the tui; run scan --format text")
    } else {
        None
    }
}

/// Picks a palette from `COLORTERM`, then from `TERM`.
///
/// # Examples
///
/// ```
/// use disk_health::ui::{Palette, palette_from};
///
/// assert_eq!(palette_from(Some("truecolor"), None), Palette::True);
/// assert_eq!(palette_from(None, None), Palette::Ansi16);
/// assert_eq!(palette_from(Some("256"), None), Palette::Ansi256);
/// assert_eq!(palette_from(None, Some("xterm-256color")), Palette::Ansi256);
/// ```
#[must_use]
pub fn palette_from(colorterm: Option<&str>, term: Option<&str>) -> Palette {
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

/// Decodes one read burst. Arrow keys are `j` and `k`.
///
/// # Examples
///
/// ```
/// use disk_health::ui::{Key, decode};
///
/// assert_eq!(decode(b"q"), Some(Key::Char('q')));
/// assert_eq!(decode(&[0x1b, b'[', b'A']), Some(Key::Char('k')));
/// assert_eq!(decode(b"\r"), Some(Key::Enter));
/// ```
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<Key> {
    match bytes {
        [0x1b, b'[', b'A'] => Some(Key::Char('k')),
        [0x1b, b'[', b'B'] => Some(Key::Char('j')),
        [0x1b] => Some(Key::Escape),
        [0x7f | 0x08] => Some(Key::Backspace),
        [b'\r' | b'\n'] => Some(Key::Enter),
        [byte] if byte.is_ascii() && !byte.is_ascii_control() => Some(Key::Char(char::from(*byte))),
        _ => None,
    }
}

/// Renders `model` to a string.
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
/// assert!(frame.contains("f filter"));
/// assert!(frame.contains('─'));
/// assert!(!frame.contains('\u{1b}'));
/// ```
#[must_use]
pub fn render(model: &Model) -> String {
    let mut head = vec![title_line(model), rule_line(model)];
    head.extend(allocation_lines(model));

    let (body, focus) = match model.screen {
        Screen::Volumes => volume_body(model),
        Screen::Reclaim => reclaim_body(model),
        Screen::Usage => usage_body(model),
    };
    let mut foot = vec![String::new()];
    foot.extend(footer_lines(model));
    if let Some(message) = message_line(model) {
        foot.push(message);
    }

    let budget = model
        .term_rows
        .saturating_sub(head.len() + foot.len())
        .max(1);
    let mut lines = head;
    lines.extend(viewport(body, focus, budget));
    lines.extend(foot);
    lines.join("\n")
}

/// Starts the UI, or refuses when the terminal cannot draw it.
///
/// A refused call does not scan and does not change the terminal.
///
/// # Errors
///
/// Returns [`crate::Error::Usage`] when stdout is not a terminal, `TERM` is
/// `dumb`, or `NO_COLOR` is set. Later errors are a failed mount table,
/// config file, or terminal mode.
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
    if let Some(message) = refuse(session.tty, session.term, session.no_color) {
        return Err(crate::Error::Usage {
            message: message.to_owned(),
        });
    }
    drive(session)
}

/// Inputs for [`run`]. The terminal flags are explicit so tests do not read
/// the process environment.
#[derive(Debug, Clone, Copy)]
pub struct Session<'a> {
    /// Whether stdout is a terminal.
    pub tty: bool,
    /// `TERM`, when set.
    pub term: Option<&'a str>,
    /// `NO_COLOR` was present.
    pub no_color: bool,
    /// `COLORTERM`, when set.
    pub colorterm: Option<&'a str>,
    /// Home directory passed to the scan.
    pub home: &'a Path,
}

fn drive(session: &Session<'_>) -> crate::Result<i32> {
    let loaded = crate::config::load(session.home)?;
    let volumes = crate::volumes::list_mounts()?;
    let palette = palette_from(session.colorterm, session.term);
    let mut model = Model::new(volumes, Vec::new(), Vec::new(), palette, SystemTime::now());
    if let Ok((rows, cols)) = crate::tty::window_size(0) {
        model.set_columns(usize::from(cols));
        model.set_rows(usize::from(rows));
    }

    let raw = crate::tty::RawMode::enter(0, 1)
        .map_err(|source| crate::Error::io("set terminal mode", "/dev/tty", source))?;
    let _panic = crate::tty::PanicGuard::install(0, 1, raw.previous());
    let _signals = crate::tty::Signals::install_with_resize()
        .map_err(|source| crate::Error::io("install signals", "/dev/tty", source))?;
    let (finding_tx, finding_rx) = std::sync::mpsc::channel();
    let (review_tx, review_rx) = std::sync::mpsc::channel();
    // Detached on purpose. Quitting must not wait for a walk of a large volume.
    let _scan = spawn_scan(session.home, loaded.clone(), finding_tx);
    let _review = spawn_review(session.home.to_path_buf(), review_tx);

    // `read_input` times out ten times a second. Painting an unchanged
    // frame at that rate flickers, so the revision has to move first.
    let mut drawn = 0;
    loop {
        if crate::tty::interrupted() {
            break;
        }
        drain(&mut model, &finding_rx, &review_rx);
        if crate::tty::take_resized()
            && let Ok((rows, cols)) = crate::tty::window_size(0)
        {
            model.set_columns(usize::from(cols));
            model.set_rows(usize::from(rows));
        }
        if model.revision != drawn {
            paint_frame(&model)?;
            drawn = model.revision;
        }
        let Some(bytes) = crate::tty::read_input(0)
            .map_err(|source| crate::Error::io("read key", "/dev/tty", source))?
        else {
            continue;
        };
        let Some(key) = decode(&bytes) else {
            continue;
        };
        if apply_key(&mut model, session, &loaded.deny, key)? {
            break;
        }
    }
    Ok(0)
}

fn paint_frame(model: &Model) -> crate::Result<()> {
    let frame = render(model);
    let mut painted = String::new();

    // Erase the rest of each line and everything below the frame. The
    // previous frame is not cleared by cursor-home alone, so a shorter
    // list would leave the old rows on screen.
    for line in frame.split('\n') {
        painted.push_str(line);
        painted.push_str("\u{1b}[K\r\n");
    }
    painted.push_str("\u{1b}[J");

    crate::tty::write_frame(1, &painted)
        .map_err(|source| crate::Error::io("draw", "/dev/tty", source))
}

fn drain(
    model: &mut Model,
    findings: &std::sync::mpsc::Receiver<Finding>,
    review: &std::sync::mpsc::Receiver<Vec<Item>>,
) {
    while let Ok(finding) = findings.try_recv() {
        model.push_finding(finding);
    }
    if let Ok(items) = review.try_recv() {
        model.set_review(items);
    }
}

fn apply_key(
    model: &mut Model,
    session: &Session<'_>,
    deny: &[PathBuf],
    key: Key,
) -> crate::Result<bool> {
    match model.handle(key) {
        Effect::Quit => Ok(true),
        Effect::None => Ok(false),
        Effect::WalkUsage { mount } => {
            match crate::usage::walk(&crate::walk::RealFs, &mount, crate::usage::DEFAULT_DEPTH) {
                Ok(tree) => model.set_usage(tree),
                Err(err) => model.set_message(err.to_string()),
            }
            Ok(false)
        }
        Effect::ConfirmApply { typed } => {
            // Typed size, not the plan id. `apply` would reject this path.
            confirm(model, session, deny, &typed)?;
            Ok(false)
        }
    }
}

fn confirm(
    model: &mut Model,
    session: &Session<'_>,
    deny: &[PathBuf],
    typed: &str,
) -> crate::Result<()> {
    let plan = model.plan(&hostname());
    let filesystem = crate::walk::RealFs;
    let home_meta = filesystem.meta(session.home)?;
    let mut log = crate::log::FileLog::new(action_log(session.home));
    let renamer = crate::trash::FsRename;
    let report = crate::trash::apply_typed_total(
        crate::trash::ApplyRequest {
            plan: &plan,
            confirm: "",
            home: session.home,
            home_dev: home_meta.dev,
            uid: crate::volumes::current_uid(),
            deny,
            fs: &filesystem,
            renamer: &renamer,
            log: &mut log,
            now: SystemTime::now(),
            interrupt: Some(crate::tty::interrupt_flag()),
        },
        typed,
    )?;
    model.set_message(apply_message(&report));
    Ok(())
}

fn apply_message(report: &crate::trash::ApplyReport) -> String {
    format!(
        "moved {}  skipped {}  exit {}",
        report.moved.len(),
        report.skipped.len(),
        report.exit_code()
    )
}

fn spawn_scan(
    home: &Path,
    loaded: crate::config::Loaded,
    tx: std::sync::mpsc::Sender<Finding>,
) -> std::thread::JoinHandle<()> {
    let home = home.to_path_buf();
    std::thread::spawn(move || {
        let git = crate::git::SystemGit;
        let filesystem = crate::walk::RealFs;
        let notify = move |finding: &Finding| {
            let _ = tx.send(finding.clone());
        };
        let _ = crate::scan::scan(&crate::scan::ScanOptions {
            home: &home,
            roots: &loaded.roots,
            safe_rules: &loaded.safe_rules,
            project_rules: &loaded.project_rules,
            deny: &loaded.deny,
            now: SystemTime::now(),
            git: &git,
            fs: &filesystem,
            progress: None,
            on_finding: Some(&notify),
        });
    })
}

fn spawn_review(
    home: PathBuf,
    tx: std::sync::mpsc::Sender<Vec<Item>>,
) -> std::thread::JoinHandle<()> {
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
        let _ = tx.send(rows);
    })
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

fn screen_key(key: Key) -> Option<Screen> {
    match key {
        Key::Char('1') => Some(Screen::Volumes),
        Key::Char('2') => Some(Screen::Reclaim),
        Key::Char('3') => Some(Screen::Usage),
        _ => None,
    }
}

fn row_from_finding(finding: Finding, now: SystemTime) -> Row {
    let (kind, word) = match finding.tier {
        Tier::Safe => (RowKind::Safe, "SAFE"),
        Tier::Caution => (RowKind::Caution, "CAUTION"),
    };
    let toggle = match finding.tier {
        Tier::Caution => Toggle::Caution,
        Tier::Safe => Toggle::Fixed,
    };
    let age = finding
        .mtime
        .and_then(|mtime| now.duration_since(mtime).ok());
    let detail = finding_detail(&finding);
    Row {
        kind,
        word,
        rule: finding.rule.to_owned(),
        path: finding.path.clone(),
        bytes: finding.apparent_bytes,
        age,
        regenerate: finding.regenerate.map(str::to_owned),
        staged: finding.staged(),
        toggle,
        detail,
        finding: Some(finding),
    }
}

fn finding_detail(finding: &Finding) -> String {
    let mut detail = finding.rationale.to_owned();
    if let Some(skip) = finding.skip {
        detail.push_str("  skip: ");
        detail.push_str(skip.as_str());
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
        word: "REVIEW",
        rule: item.class.as_str().to_owned(),
        path: item.path,
        bytes: item.apparent_bytes,
        age: item.age,
        regenerate: item.advice,
        staged: false,
        toggle: Toggle::Fixed,
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

fn step(cursor: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let next = isize::try_from(cursor).unwrap_or(0) + delta;
    if next <= 0 {
        0
    } else {
        usize::try_from(next).unwrap_or(len - 1).min(len - 1)
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

fn sort_children(node: &mut UsageNode, by_size: bool) {
    if by_size {
        node.children.sort_by(|left, right| {
            right
                .apparent_bytes
                .cmp(&left.apparent_bytes)
                .then(left.path.cmp(&right.path))
        });
    } else {
        node.children
            .sort_by(|left, right| left.path.cmp(&right.path));
    }
}

/// Foreground for words, background for meter cells.
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
const SLICE_BG16: [u8; 8] = [46, 44, 45, 43, 41, 42, 47, 46];
const PLAIN_GLYPHS: [char; 5] = ['█', '▓', '▒', '░', '·'];

fn title_line(model: &Model) -> String {
    let name = match model.screen {
        Screen::Volumes => "volumes",
        Screen::Reclaim => "reclaim",
        Screen::Usage => "usage",
    };
    let left = format!("disk-health  {name}");
    let right = format!("staged {}", format_bytes(model.staged_bytes()));
    let gap = " ".repeat(gap_width(
        model.columns,
        left.chars().count() + right.chars().count(),
    ));

    paint_line(
        model.palette,
        &[
            (left.as_str(), Ink::Title),
            (gap.as_str(), Ink::Text),
            (right.as_str(), Ink::Safe),
        ],
        model.columns,
    )
}

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

fn volume_body(model: &Model) -> (Vec<String>, usize) {
    if model.volumes.is_empty() {
        return (vec!["  no mounts".to_owned()], 0);
    }

    let mut lines = Vec::new();
    let mut focus = 0;
    for (index, volume) in model.volumes.iter().enumerate() {
        if index == model.volume_cursor {
            focus = lines.len();
        }
        if index > 0 {
            lines.push(String::new());
        }
        lines.extend(volume_card(model, volume, index == model.volume_cursor));
    }
    (lines, focus)
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
    let used = marker.chars().count() + name.chars().count() + stats.chars().count();
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

fn reclaim_body(model: &Model) -> (Vec<String>, usize) {
    let visible = model.visible();
    if visible.is_empty() {
        return (vec!["  no reclaim rows yet".to_owned()], 0);
    }

    let total = visible.iter().fold(0u64, |sum, index| {
        sum.saturating_add(model.rows[*index].bytes)
    });
    let mut lines = Vec::new();
    let mut focus = 0;
    for (shown, index) in visible.into_iter().enumerate() {
        if shown == model.cursor {
            focus = lines.len();
        }
        if shown > 0 {
            lines.push(String::new());
        }
        let selected = shown == model.cursor;
        lines.extend(reclaim_card(model, &model.rows[index], selected, total));
    }
    (lines, focus)
}

fn reclaim_card(model: &Model, row: &Row, selected: bool, total: u64) -> Vec<String> {
    let mut lines = vec![reclaim_heading(model, row, selected, total)];
    lines.push(indent_meter(&reclaim_meter(model, row, total)));

    let path = short_tail(&row.path, model.columns.saturating_sub(4));
    lines.push(paint_line(
        model.palette,
        &[("    ", Ink::Text), (path.as_str(), Ink::Muted)],
        model.columns,
    ));
    if selected && model.detail {
        lines.push(paint_line(
            model.palette,
            &[("    ", Ink::Text), (row.detail.as_str(), Ink::Muted)],
            model.columns,
        ));
    }
    lines
}

fn reclaim_heading(model: &Model, row: &Row, selected: bool, total: u64) -> String {
    let marker = if selected { "▸ " } else { "  " };
    let marker_ink = if selected { Ink::Accent } else { Ink::Muted };
    let word = format!("{:<7}", row.word);
    let state = if row.staged { "staged" } else { "held" };
    let meta = format!(
        "  {:>9}  {:<6}  {:>6}  {}",
        format_bytes(row.bytes),
        state,
        age_text(row.age),
        row.rule,
    );
    let share = pct_text(row.bytes, total);
    let used = marker.chars().count()
        + word.chars().count()
        + meta.chars().count()
        + share.chars().count();
    let gap = " ".repeat(gap_width(model.columns, used));

    paint_line(
        model.palette,
        &[
            (marker, marker_ink),
            (word.as_str(), tier_ink(row.kind)),
            (meta.as_str(), Ink::Text),
            (gap.as_str(), Ink::Text),
            (share.as_str(), tier_ink(row.kind)),
        ],
        model.columns,
    )
}

fn reclaim_meter(model: &Model, row: &Row, total: u64) -> String {
    let width = guide_width(model.columns);
    let filled = magnitude(row.bytes, total, width);
    meter(
        model.palette,
        filled,
        width,
        tier_ink(row.kind),
        tier_glyph(row.kind),
    )
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
    let gap = " ".repeat(gap_width(
        model.columns,
        path.chars().count() + size.chars().count() + 2,
    ));

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
    let used = marker.chars().count() + name.chars().count() + stats.chars().count();
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

fn footer_lines(model: &Model) -> Vec<String> {
    let filter = model.filter.as_str();
    let first = format!("1 volumes  2 reclaim  3 usage  f filter ({filter})  q quit");
    let second = "j/k move   space caution   d detail   t confirm   u walk   s sort";

    vec![
        paint_line(model.palette, &[(&first, Ink::Muted)], model.columns),
        paint_line(model.palette, &[(second, Ink::Muted)], model.columns),
    ]
}

fn message_line(model: &Model) -> Option<String> {
    if model.confirming {
        let line = format!(
            "confirm {}  {}",
            format_bytes(model.staged_bytes()),
            model.typed
        );
        return Some(paint_line(
            model.palette,
            &[(&line, Ink::Caution)],
            model.columns,
        ));
    }
    if model.message.is_empty() {
        return None;
    }
    Some(paint_line(
        model.palette,
        &[(&model.message, Ink::Accent)],
        model.columns,
    ))
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

fn paint_line(palette: Palette, pieces: &[(&str, Ink)], width: usize) -> String {
    let mut left = width;
    let mut out = String::new();
    for (text, ink) in pieces {
        if left == 0 {
            break;
        }
        let fitted = fit(text, left);
        let taken = fitted.chars().count();
        out.push_str(&paint_fg(palette, *ink, &fitted));
        left = left.saturating_sub(taken);
        if taken < text.chars().count() {
            break;
        }
    }
    out
}

fn paint_fg(palette: Palette, ink: Ink, text: &str) -> String {
    wrap(fg_code(palette, ink), text)
}

fn paint_cells(palette: Palette, ink: Ink, glyph: char, count: usize) -> String {
    if count == 0 {
        return String::new();
    }
    let shown = if palette == Palette::Plain {
        glyph
    } else {
        ' '
    };
    let text: String = std::iter::repeat_n(shown, count).collect();
    if palette == Palette::Plain {
        text
    } else {
        wrap(bg_code(palette, ink), &text)
    }
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

fn bg_code(palette: Palette, ink: Ink) -> Option<String> {
    match palette {
        Palette::Plain => None,
        Palette::Ansi16 => Some(ansi16_bg(ink).to_string()),
        Palette::Ansi256 => Some(format!("48;5;{}", ansi256_bg(ink))),
        Palette::True => {
            let (red, green, blue) = rgb(ink);
            Some(format!("48;2;{red};{green};{blue}"))
        }
    }
}

fn rgb(ink: Ink) -> (u8, u8, u8) {
    match ink {
        Ink::Safe => (72, 201, 146),
        Ink::Caution => (240, 180, 70),
        Ink::Review => (138, 156, 240),
        Ink::Danger => (235, 98, 104),
        Ink::Track => (54, 58, 69),
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

fn ansi256_bg(ink: Ink) -> u8 {
    match ink {
        Ink::Track | Ink::Muted => 236,
        Ink::Slice(index) => SLICE_256[usize::from(index) % SLICE_256.len()],
        other => ansi256(other),
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

fn ansi16_bg(ink: Ink) -> u8 {
    match ink {
        Ink::Safe => 42,
        Ink::Caution => 43,
        Ink::Review => 45,
        Ink::Danger => 41,
        Ink::Track | Ink::Muted => 100,
        Ink::Title | Ink::Text | Ink::Accent => 47,
        Ink::Slice(index) => SLICE_BG16[usize::from(index) % SLICE_BG16.len()],
    }
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

fn short_tail(path: &Path, width: usize) -> String {
    let text = path.display().to_string();
    if text.chars().count() <= width || width == 0 {
        return fit(&text, width);
    }

    let keep = width.saturating_sub(1);
    let tail = text
        .chars()
        .rev()
        .take(keep)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("…{tail}")
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

fn fit(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return text.to_owned();
    }
    if width <= 1 {
        return String::new();
    }
    let mut out: String = text.chars().take(width - 1).collect();
    out.push('…');
    out
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
        assert!(cool.contains("\u{1b}[48;2;72;201;146m"), "{cool}");
        assert!(hot.contains("\u{1b}[48;2;235;98;104m"), "{hot}");
        assert!(!cool.contains('█'));
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
