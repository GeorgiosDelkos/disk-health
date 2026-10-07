//! Three screens over the scan, the review inventory, and one usage tree.
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
        }
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
        self.clamp_reclaim();
    }

    /// Replaces review rows. Finding rows stay, including their staged bits.
    pub fn set_review(&mut self, items: Vec<Item>) {
        self.rows.retain(|row| row.finding.is_some());
        self.rows.extend(items.into_iter().map(row_from_review));
        self.clamp_reclaim();
    }

    /// Shows a usage tree and switches to that screen.
    pub fn set_usage(&mut self, node: UsageNode) {
        self.usage = Some(node);
        self.usage_path.clear();
        self.usage_cursor = 0;
        self.screen = Screen::Usage;
        self.sort_current();
    }

    /// Sets the render width. A resize redraws from this snapshot.
    pub fn set_columns(&mut self, columns: usize) {
        self.columns = columns.max(1);
    }

    /// Replaces the status line.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = message.into();
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
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| self.filter.matches(row.kind))
            .map(|(index, _)| index)
            .collect()
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

/// Picks a palette from `COLORTERM`.
///
/// # Examples
///
/// ```
/// use disk_health::ui::{Palette, palette_from};
///
/// assert_eq!(palette_from(Some("truecolor")), Palette::True);
/// assert_eq!(palette_from(None), Palette::Ansi16);
/// assert_eq!(palette_from(Some("256")), Palette::Ansi256);
/// ```
#[must_use]
pub fn palette_from(colorterm: Option<&str>) -> Palette {
    match colorterm {
        Some("truecolor" | "24bit") => Palette::True,
        Some(_) => Palette::Ansi256,
        None => Palette::Ansi16,
    }
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

/// Renders `model` to a string. [`Palette::Plain`] has tier words and no escapes.
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
/// assert!(!frame.contains('\u{1b}'));
/// ```
#[must_use]
pub fn render(model: &Model) -> String {
    let mut out = String::new();
    match model.screen {
        Screen::Volumes => render_volumes(&mut out, model),
        Screen::Reclaim => render_reclaim(&mut out, model),
        Screen::Usage => render_usage(&mut out, model),
    }
    out.push('\n');
    out.push_str(&footer(model));
    if !model.message.is_empty() {
        out.push('\n');
        out.push_str(&model.message);
    }
    out
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
    let palette = palette_from(session.colorterm);
    let mut model = Model::new(volumes, Vec::new(), Vec::new(), palette, SystemTime::now());
    if let Ok((rows, cols)) = crate::tty::window_size(0) {
        model.set_columns(usize::from(cols));
        let _ = rows;
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

    loop {
        if crate::tty::interrupted() {
            break;
        }
        drain(&mut model, &finding_rx, &review_rx);
        if crate::tty::take_resized()
            && let Ok((_, cols)) = crate::tty::window_size(0)
        {
            model.set_columns(usize::from(cols));
        }
        paint_frame(&model)?;
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
    let frame = render(model).replace('\n', "\r\n");
    crate::tty::write_frame(1, &frame)
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

fn render_volumes(out: &mut String, model: &Model) {
    if model.volumes.is_empty() {
        out.push_str("no mounts");
        return;
    }
    for (index, volume) in model.volumes.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let mark = if index == model.volume_cursor {
            ">"
        } else {
            " "
        };
        let used = format_bytes(volume.used_bytes);
        let avail = format_bytes(volume.available_bytes);
        let bar = capacity_bar(volume.used_bytes, volume.total_bytes, 16);
        let line = format!(
            "{mark} {}  {}  used {used}  avail {avail}  {bar}",
            volume.mount.display(),
            volume.fstype
        );
        out.push_str(&fit(&line, model.columns));
        if let Some(note) = volume.note {
            out.push('\n');
            out.push_str(&fit(&format!("  {note}"), model.columns));
        }
    }
}

fn render_reclaim(out: &mut String, model: &Model) {
    let visible = model.visible();
    if visible.is_empty() {
        out.push_str("no rows");
        return;
    }
    for (shown, index) in visible.iter().enumerate() {
        if shown > 0 {
            out.push('\n');
        }
        let row = &model.rows[*index];
        let mark = if shown == model.cursor { ">" } else { " " };
        let staged = if row.staged { "staged" } else { "held" };
        let age = age_text(row.age);
        let line = format!(
            "{mark} {}  {staged}  {}  {age}  {}  {}",
            paint(model.palette, row.word),
            format_bytes(row.bytes),
            row.rule,
            row.path.display()
        );
        out.push_str(&fit(&line, model.columns));
        if model.detail && shown == model.cursor {
            out.push('\n');
            out.push_str(&fit(&format!("  {}", row.detail), model.columns));
        }
    }
}

fn render_usage(out: &mut String, model: &Model) {
    let Some(node) = node_at(model.usage.as_ref(), &model.usage_path) else {
        out.push_str("no usage tree  press u on a walkable volume");
        return;
    };
    let line = format!(
        "{}  {}",
        format_bytes(node.apparent_bytes),
        node.path.display()
    );
    out.push_str(&fit(&line, model.columns));
    for (index, child) in node.children.iter().enumerate() {
        out.push('\n');
        let mark = if index == model.usage_cursor {
            ">"
        } else {
            " "
        };
        let line = format!(
            "{mark} {}  {}",
            format_bytes(child.apparent_bytes),
            child.path.display()
        );
        out.push_str(&fit(&line, model.columns));
    }
}

fn footer(model: &Model) -> String {
    let filter = model.filter.as_str();
    format!(
        "1 volumes  2 reclaim  3 usage  j/k  space stages caution  \
         d detail  t confirm  f filter ({filter})  u usage  q quit"
    )
}

fn paint(palette: Palette, word: &str) -> String {
    if palette == Palette::Plain {
        return word.to_owned();
    }
    let (red, green, blue, ansi16, ansi256) = match word {
        "SAFE" => (80, 180, 120, 32, 35),
        "CAUTION" => (210, 160, 60, 33, 178),
        "REVIEW" => (160, 140, 210, 35, 141),
        _ => (200, 200, 200, 37, 250),
    };
    match palette {
        Palette::Plain => word.to_owned(),
        Palette::Ansi16 => format!("\u{1b}[{ansi16}m{word}\u{1b}[0m"),
        Palette::Ansi256 => format!("\u{1b}[38;5;{ansi256}m{word}\u{1b}[0m"),
        Palette::True => format!("\u{1b}[38;2;{red};{green};{blue}m{word}\u{1b}[0m"),
    }
}

fn capacity_bar(used: u64, total: u64, width: usize) -> String {
    if total == 0 || width == 0 {
        return "[]".to_owned();
    }
    let filled = used.saturating_mul(u64::try_from(width).unwrap_or(0)) / total;
    let filled = usize::try_from(filled).unwrap_or(width).min(width);
    format!("[{}{}]", "#".repeat(filled), "-".repeat(width - filled))
}

fn age_text(age: Option<Duration>) -> String {
    let Some(age) = age else {
        return "age unknown".to_owned();
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
        assert!(!model.is_staged(Path::new("/proj/target")));
        model.handle(Key::Char(' '));
        assert!(model.is_staged(Path::new("/proj/target")));
        model.handle(Key::Char(' '));
        assert!(!model.is_staged(Path::new("/proj/target")));

        model.handle(Key::Char('j'));
        model.handle(Key::Char(' '));
        assert!(model.is_staged(Path::new("/cache")));

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
}
