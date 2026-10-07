//! Inventory that is printed and never deleted.
//!
//! These rows are a different type from [`crate::scan::Finding`]. They have
//! no staged bit, so a plan file cannot name them and `apply` has nothing
//! to accept. Application Support is on the deletion denylist; this walk
//! does not consult that list, or the Cursor snapshots would disappear.
//!
//! Worktree columns come from [`crate::git::WORKTREE_ARGV`] only. Ahead and
//! behind stay empty because a count would be a fourth `git` command.
//! `pnpm` and `rustup` are advice text. Nothing here execs them.

use std::ffi::OsString;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::git::{WorktreeGit, WorktreeStatus};
use crate::json;
use crate::walk::{Fs, Kind, measure_children};

/// Why the row is inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// A checkout that may hold uncommitted work.
    Worktree,
    /// Transcripts, sessions, or editor state.
    Inventory,
    /// An installed toolchain. Removal is `rustup`, not a rename.
    Toolchain,
    /// A content-addressed store. Removal is the store's own prune.
    Store,
}

impl Class {
    /// Stable word used in text and JSON.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::review::Class;
    ///
    /// assert_eq!(Class::Worktree.as_str(), "worktree");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Worktree => "worktree",
            Self::Inventory => "inventory",
            Self::Toolchain => "toolchain",
            Self::Store => "store",
        }
    }
}

/// One review row.
///
/// The fields are the whole record. There is no `staged` field on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Kind of inventory.
    pub class: Class,
    /// Absolute path. Not reached by following a symlink.
    pub path: PathBuf,
    /// Apparent size. Hardlinks inside the tree are counted once.
    pub apparent_bytes: u64,
    /// Apparent size of `target/` and `node_modules/` inside a worktree.
    pub caution_child_bytes: u64,
    /// Age of the row's own mtime. A future mtime is `None`.
    pub age: Option<Duration>,
    /// Branch, when `git` could print one.
    pub branch: Option<String>,
    /// `Some(true)` when porcelain was non-empty. `None` when `git` failed.
    pub dirty: Option<bool>,
    /// Upstream ref. `None` when the repo has no upstream or `git` failed.
    pub upstream: Option<String>,
    /// Always `None` in v1. See the module docs.
    pub ahead: Option<u64>,
    /// Always `None` in v1. See the module docs.
    pub behind: Option<u64>,
    /// Command the operator can run. This module does not run it.
    pub advice: Option<String>,
    /// Set on the toolchain named by `settings.toml`.
    pub active: bool,
    /// Why the row is not a candidate.
    pub note: &'static str,
}

struct Fixed {
    relative: &'static str,
    class: Class,
    note: &'static str,
    advice: Option<&'static str>,
}

const FIXED: &[Fixed] = &[
    Fixed {
        relative: ".grok/sessions",
        class: Class::Inventory,
        note: "session state",
        advice: None,
    },
    Fixed {
        relative: ".grok/downloads",
        class: Class::Inventory,
        note: "agent downloads",
        advice: None,
    },
    Fixed {
        relative: ".grok/memory-v2",
        class: Class::Inventory,
        note: "agent memory",
        advice: None,
    },
    Fixed {
        relative: ".claude/projects",
        class: Class::Inventory,
        note: "transcripts and project memory",
        advice: None,
    },
    Fixed {
        relative: ".claude/file-history",
        class: Class::Inventory,
        note: "editor file history",
        advice: None,
    },
    Fixed {
        relative: ".claude/backups",
        class: Class::Inventory,
        note: "editor backups",
        advice: None,
    },
    Fixed {
        relative: ".claude/security",
        class: Class::Inventory,
        note: "never delete until the format is documented",
        advice: None,
    },
    Fixed {
        relative: ".claude/plugins",
        class: Class::Inventory,
        note: "installed plugins",
        advice: None,
    },
    Fixed {
        relative: ".codex/sessions",
        class: Class::Inventory,
        note: "session transcripts",
        advice: None,
    },
    Fixed {
        relative: ".codex/archived_sessions",
        class: Class::Inventory,
        note: "archived transcripts",
        advice: None,
    },
    Fixed {
        relative: ".codex/sqlite",
        class: Class::Inventory,
        note: "session database",
        advice: None,
    },
    Fixed {
        relative: ".cache/codex-runtimes",
        class: Class::Inventory,
        note: "installed runtime, not a scratch cache",
        advice: None,
    },
    Fixed {
        relative: "Library/Application Support/Cursor/snapshots",
        class: Class::Inventory,
        note: "editor snapshots",
        advice: None,
    },
    Fixed {
        relative: "Library/Application Support/Cursor/User",
        class: Class::Inventory,
        note: "never delete editor state",
        advice: None,
    },
    Fixed {
        relative: "Library/pnpm/store",
        class: Class::Store,
        note: "content-addressed store",
        advice: Some("pnpm store prune"),
    },
];

/// Lists review rows under `home`.
///
/// A missing directory is omitted. A symlink or a dataless directory is
/// omitted. `git` failing does not drop a worktree.
///
/// `rustup_settings` is the text of `~/.rustup/settings.toml`, when the
/// caller could read it. The active toolchain is marked from
/// `default_toolchain`.
///
/// # Examples
///
/// ```
/// use disk_health::git::MapWorktree;
/// use disk_health::review::inventory;
/// use disk_health::walk::MemFs;
/// use std::path::Path;
/// use std::time::SystemTime;
///
/// let fs = MemFs::new();
/// fs.dir("/home/.grok/sessions", 1, SystemTime::UNIX_EPOCH);
/// let rows = inventory(
///     &fs,
///     Path::new("/home"),
///     SystemTime::UNIX_EPOCH,
///     &MapWorktree::default(),
///     None,
/// );
/// assert_eq!(rows.len(), 1);
/// assert!(rows[0].advice.is_none());
/// ```
#[must_use]
pub fn inventory(
    fs: &dyn Fs,
    home: &Path,
    now: SystemTime,
    git: &dyn WorktreeGit,
    rustup_settings: Option<&str>,
) -> Vec<Item> {
    let mut rows = FIXED
        .iter()
        .map(|fixed| Row::Fixed(home.join(fixed.relative), fixed))
        .collect::<Vec<_>>();
    worktree_rows(&mut rows, fs, home);
    toolchain_rows(&mut rows, fs, home, rustup_settings);

    let mut items = measure_rows(&rows, &Sizing { fs, now, git });
    items.sort_by(|left, right| left.path.cmp(&right.path));
    items
}

/// A row that still has to be sized. Finding the rows is a few listings;
/// sizing one is a walk of everything under it.
enum Row {
    Fixed(PathBuf, &'static Fixed),
    Worktree(PathBuf),
    Toolchain {
        path: PathBuf,
        name: String,
        active: bool,
    },
}

struct Sizing<'a> {
    fs: &'a dyn Fs,
    now: SystemTime,
    git: &'a dyn WorktreeGit,
}

/// Most rows sized at once. The work is waiting on directory reads.
const MAX_SIZERS: usize = 8;

/// Sizes the rows on a few threads. Each takes the next unsized row.
fn measure_rows(rows: &[Row], sizing: &Sizing<'_>) -> Vec<Item> {
    let next = AtomicUsize::new(0);
    let take = || {
        let mut items = Vec::new();
        // `Relaxed`: the counter only hands out indexes. Nothing else is
        // published through it.
        while let Some(row) = rows.get(next.fetch_add(1, Ordering::Relaxed)) {
            items.extend(row.item(sizing));
        }
        items
    };

    let sizers = thread::available_parallelism()
        .map_or(1, NonZero::get)
        .min(MAX_SIZERS)
        .min(rows.len());
    thread::scope(|scope| {
        let handles = (1..sizers)
            .filter_map(|_| thread::Builder::new().spawn_scoped(scope, take).ok())
            .collect::<Vec<_>>();
        // This thread works too, so a refused spawn only makes the rest slower.
        let mut items = take();
        for handle in handles {
            items.extend(handle.join().expect("review sizing panicked"));
        }
        items
    })
}

impl Row {
    fn item(&self, sizing: &Sizing<'_>) -> Option<Item> {
        match self {
            Self::Fixed(path, fixed) => {
                let size = size_of(sizing.fs, path, sizing.now)?;
                Some(fixed_item(path, size, fixed))
            }
            Self::Worktree(path) => {
                let (size, caution_child_bytes) =
                    size_with(sizing.fs, path, sizing.now, CAUTION_CHILDREN)?;
                let status = sizing.git.inspect(path);
                Some(worktree_item(path, size, caution_child_bytes, status))
            }
            Self::Toolchain { path, name, active } => {
                let size = size_of(sizing.fs, path, sizing.now)?;
                Some(toolchain_item(path, size, name, *active))
            }
        }
    }
}

/// Appends review objects. The caller writes the surrounding array.
///
/// Objects do not contain `staged` or `tier`.
///
/// # Examples
///
/// ```
/// use disk_health::review::{Class, Item, append_json};
/// use std::path::PathBuf;
///
/// let item = sample(Class::Store);
/// let mut out = String::new();
/// append_json(&mut out, &[item]);
/// assert!(!out.contains("staged"));
/// assert!(out.contains("pnpm store prune"));
///
/// fn sample(class: Class) -> Item {
///     Item {
///         class,
///         path: PathBuf::from("/store"),
///         apparent_bytes: 4,
///         caution_child_bytes: 0,
///         age: None,
///         branch: None,
///         dirty: None,
///         upstream: None,
///         ahead: None,
///         behind: None,
///         advice: Some("pnpm store prune".to_owned()),
///         active: false,
///         note: "content-addressed store",
///     }
/// }
/// ```
pub fn append_json(out: &mut String, items: &[Item]) {
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        push_item(out, item);
    }
}

fn fixed_item(path: &Path, size: Size, fixed: &Fixed) -> Item {
    Item {
        class: fixed.class,
        path: path.to_path_buf(),
        apparent_bytes: size.bytes,
        caution_child_bytes: 0,
        age: size.age,
        branch: None,
        dirty: None,
        upstream: None,
        ahead: None,
        behind: None,
        advice: fixed.advice.map(str::to_owned),
        active: false,
        note: fixed.note,
    }
}

fn worktree_rows(rows: &mut Vec<Row>, fs: &dyn Fs, home: &Path) {
    let root = home.join(".grok/worktrees");
    for name in sorted_names(fs, &root) {
        let child = root.join(&name);
        if is_checkout(fs, &child) {
            rows.push(Row::Worktree(child));
            continue;
        }
        if !is_directory(fs, &child) {
            continue;
        }
        for nested in sorted_names(fs, &child) {
            let checkout = child.join(&nested);
            if is_checkout(fs, &checkout) {
                rows.push(Row::Worktree(checkout));
            }
        }
    }
}

fn worktree_item(
    path: &Path,
    size: Size,
    caution_child_bytes: u64,
    status: WorktreeStatus,
) -> Item {
    Item {
        class: Class::Worktree,
        path: path.to_path_buf(),
        apparent_bytes: size.bytes,
        caution_child_bytes,
        age: size.age,
        branch: status.branch,
        dirty: status.dirty,
        upstream: status.upstream,
        ahead: None,
        behind: None,
        advice: None,
        active: false,
        note: "checkout; not deleted",
    }
}

fn toolchain_rows(rows: &mut Vec<Row>, fs: &dyn Fs, home: &Path, settings: Option<&str>) {
    let root = home.join(".rustup/toolchains");
    let default = settings.and_then(default_toolchain);
    for name in sorted_names(fs, &root) {
        let path = root.join(&name);
        if !is_directory(fs, &path) {
            continue;
        }
        let name = name.to_string_lossy().into_owned();
        let active = default.as_deref() == Some(name.as_str());
        rows.push(Row::Toolchain { path, name, active });
    }
}

fn toolchain_item(path: &Path, size: Size, name: &str, active: bool) -> Item {
    let note = if active {
        "active toolchain"
    } else {
        "installed toolchain"
    };
    Item {
        class: Class::Toolchain,
        path: path.to_path_buf(),
        apparent_bytes: size.bytes,
        caution_child_bytes: 0,
        age: size.age,
        branch: None,
        dirty: None,
        upstream: None,
        ahead: None,
        behind: None,
        advice: Some(format!("rustup toolchain uninstall {name}")),
        active,
        note,
    }
}

#[derive(Clone, Copy)]
struct Size {
    bytes: u64,
    age: Option<Duration>,
}

/// Build output a worktree row reports separately from its own size.
const CAUTION_CHILDREN: &[&str] = &["target", "node_modules"];

fn size_of(fs: &dyn Fs, path: &Path, now: SystemTime) -> Option<Size> {
    size_with(fs, path, now, &[]).map(|(size, _)| size)
}

/// Size of `path`, and of its direct children in `named`, from one walk.
fn size_with(fs: &dyn Fs, path: &Path, now: SystemTime, named: &[&str]) -> Option<(Size, u64)> {
    let meta = fs.meta(path).ok()?;
    if meta.is_dataless() {
        return None;
    }
    let (bytes, named_bytes) = match meta.kind {
        Kind::File => (meta.len, 0),
        Kind::Directory => measure_children(fs, path, &meta, named)
            .map_or((0, 0), |(measured, named)| (measured.apparent_bytes, named)),
        Kind::Symlink | Kind::Other => return None,
    };
    let size = Size {
        bytes,
        age: age_of(now, meta.mtime),
    };
    Some((size, named_bytes))
}

fn is_checkout(fs: &dyn Fs, path: &Path) -> bool {
    match fs.meta(&path.join(".git")) {
        Ok(meta) => matches!(meta.kind, Kind::File | Kind::Directory),
        Err(_) => false,
    }
}

fn is_directory(fs: &dyn Fs, path: &Path) -> bool {
    match fs.meta(path) {
        Ok(meta) => meta.kind == Kind::Directory && !meta.is_dataless(),
        Err(_) => false,
    }
}

fn sorted_names(fs: &dyn Fs, path: &Path) -> Vec<OsString> {
    let Ok(listing) = fs.read_dir(path) else {
        return Vec::new();
    };
    let mut names = listing
        .entries
        .into_iter()
        .map(|entry| entry.name)
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn age_of(now: SystemTime, mtime: Option<SystemTime>) -> Option<Duration> {
    now.duration_since(mtime?).ok()
}

/// Reads `default_toolchain` from a `settings.toml` body.
///
/// The file is line-oriented. There is no TOML crate. Quotes around the
/// value are optional.
fn default_toolchain(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = strip_comment(line.trim());
        let Some(rest) = line.strip_prefix("default_toolchain") else {
            continue;
        };
        let rest = rest.trim().strip_prefix('=')?.trim();
        let rest = rest.trim_matches('"').trim_matches('\'');
        if !rest.is_empty() {
            return Some(rest.to_owned());
        }
    }
    None
}

fn strip_comment(line: &str) -> &str {
    match line.split_once('#') {
        Some((head, _)) => head.trim(),
        None => line,
    }
}

fn push_item(out: &mut String, item: &Item) {
    out.push_str("    {\n");
    field_str(out, "class", item.class.as_str());
    field_str(out, "path", &item.path.to_string_lossy());
    field_raw(out, "apparent_bytes", &item.apparent_bytes.to_string());
    field_raw(
        out,
        "caution_child_bytes",
        &item.caution_child_bytes.to_string(),
    );
    field_opt_u64(out, "age_secs", item.age.map(|age| age.as_secs()));
    field_opt_str(out, "branch", item.branch.as_deref());
    field_opt_bool(out, "dirty", item.dirty);
    field_opt_str(out, "upstream", item.upstream.as_deref());
    field_opt_u64(out, "ahead", item.ahead);
    field_opt_u64(out, "behind", item.behind);
    field_opt_str(out, "advice", item.advice.as_deref());
    field_bool(out, "active", item.active);
    field_last(out, "note", item.note);
    out.push_str("    }");
}

fn field_str(out: &mut String, key: &str, value: &str) {
    pad(out);
    out.push('"');
    json::escape_into(out, key);
    out.push_str("\": \"");
    json::escape_into(out, value);
    out.push_str("\",\n");
}

fn field_raw(out: &mut String, key: &str, value: &str) {
    pad(out);
    out.push('"');
    json::escape_into(out, key);
    out.push_str("\": ");
    out.push_str(value);
    out.push_str(",\n");
}

fn field_opt_str(out: &mut String, key: &str, value: Option<&str>) {
    match value {
        Some(value) => field_str(out, key, value),
        None => field_null(out, key),
    }
}

fn field_opt_u64(out: &mut String, key: &str, value: Option<u64>) {
    match value {
        Some(value) => field_raw(out, key, &value.to_string()),
        None => field_null(out, key),
    }
}

fn field_opt_bool(out: &mut String, key: &str, value: Option<bool>) {
    match value {
        Some(value) => field_bool(out, key, value),
        None => field_null(out, key),
    }
}

fn field_bool(out: &mut String, key: &str, value: bool) {
    let text = if value { "true" } else { "false" };
    field_raw(out, key, text);
}

fn field_null(out: &mut String, key: &str) {
    field_raw(out, key, "null");
}

fn field_last(out: &mut String, key: &str, value: &str) {
    pad(out);
    out.push('"');
    json::escape_into(out, key);
    out.push_str("\": \"");
    json::escape_into(out, value);
    out.push_str("\"\n");
}

fn pad(out: &mut String) {
    out.push_str("      ");
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::config::{deny_prefixes, path_is_denied};
    use crate::git::{MapWorktree, WorktreeStatus};
    use crate::json::Value;
    use crate::walk::{MemFs, SF_DATALESS};

    #[allow(
        clippy::duration_suboptimal_units,
        reason = "fixed unix timestamp used as the scan clock"
    )]
    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    #[test]
    fn json_objects_have_no_staged_key() {
        let fs = MemFs::new();
        fs.dir("/home/Library/pnpm/store", 1, now());
        fs.file("/home/Library/pnpm/store/pkg", 1, 8, now());
        let rows = inventory(
            &fs,
            Path::new("/home"),
            now(),
            &MapWorktree::default(),
            None,
        );
        let mut body = String::from("[\n");
        append_json(&mut body, &rows);
        body.push_str("\n]\n");

        let value = crate::json::parse(&body).expect("review json parses");
        let Value::Array(items) = value else {
            panic!("array");
        };
        let Value::Object(map) = &items[0] else {
            panic!("object");
        };
        assert!(!map.contains_key("staged"), "{body}");
        assert!(!map.contains_key("tier"), "{body}");
        assert_eq!(
            map.get("advice").and_then(Value::as_str),
            Some("pnpm store prune")
        );
        assert_eq!(map.get("ahead").and_then(Value::as_u64), None);
        assert!(matches!(map.get("ahead"), Some(Value::Null)));
    }

    #[test]
    fn cursor_snapshots_are_listed_even_though_application_support_is_denied() {
        let home = Path::new("/Users/ada");
        let snapshots = home.join("Library/Application Support/Cursor/snapshots");
        let deny = deny_prefixes(home, &[]);
        assert!(path_is_denied(&snapshots, &deny));

        let fs = MemFs::new();
        fs.dir(&snapshots, 1, now());
        let rows = inventory(&fs, home, now(), &MapWorktree::default(), None);
        assert!(rows.iter().any(|row| row.path == snapshots));
    }

    #[test]
    fn worktrees_are_two_levels_and_git_failure_keeps_the_row() {
        let fs = MemFs::new();
        let when = now();
        let checkout = Path::new("/home/.grok/worktrees/group/repo");
        fs.dir("/home/.grok/worktrees", 1, when);
        fs.dir("/home/.grok/worktrees/group", 1, when);
        fs.dir(checkout, 1, when);
        fs.file(checkout.join(".git"), 1, 12, when);
        fs.dir(checkout.join("target"), 1, when);
        fs.file(checkout.join("target/app"), 1, 40, when);
        fs.symlink(checkout.join("node_modules"), when);

        let rows = inventory(&fs, Path::new("/home"), when, &MapWorktree::default(), None);
        let row = rows.iter().find(|row| row.path == checkout).expect("row");
        assert_eq!(row.class, Class::Worktree);
        assert_eq!(row.dirty, None);
        assert_eq!(row.branch, None);
        assert_eq!(row.upstream, None);
        assert_eq!(row.ahead, None);
        assert_eq!(row.behind, None);
        assert_eq!(row.caution_child_bytes, 40);
    }

    #[test]
    fn dirty_status_is_recorded_and_the_row_stays_review() {
        let fs = MemFs::new();
        let when = now();
        let checkout = Path::new("/home/.grok/worktrees/repo");
        fs.dir("/home/.grok/worktrees", 1, when);
        fs.dir(checkout, 1, when);
        fs.dir(checkout.join(".git"), 1, when);

        let mut git = MapWorktree::default();
        git.by_path.insert(
            checkout.to_path_buf(),
            WorktreeStatus {
                dirty: Some(true),
                branch: Some("agent".to_owned()),
                upstream: None,
            },
        );
        let rows = inventory(&fs, Path::new("/home"), when, &git, None);
        let row = rows.iter().find(|row| row.path == checkout).expect("row");
        assert_eq!(row.dirty, Some(true));
        assert_eq!(row.branch.as_deref(), Some("agent"));
        assert!(row.advice.is_none());
    }

    #[test]
    fn symlink_checkout_is_not_a_row() {
        let fs = MemFs::new();
        let when = now();
        fs.dir("/home/.grok/worktrees", 1, when);
        fs.symlink("/home/.grok/worktrees/link", when);
        let rows = inventory(&fs, Path::new("/home"), when, &MapWorktree::default(), None);
        assert_eq!(rows, []);
    }

    #[test]
    fn dataless_inventory_is_omitted() {
        let fs = MemFs::new();
        fs.dir("/home/.grok/sessions", 1, now());
        fs.set_flags(Path::new("/home/.grok/sessions"), SF_DATALESS);
        let rows = inventory(
            &fs,
            Path::new("/home"),
            now(),
            &MapWorktree::default(),
            None,
        );
        assert_eq!(rows, []);
    }

    #[test]
    fn active_toolchain_is_marked_and_advice_is_text() {
        let fs = MemFs::new();
        let when = now();
        fs.dir("/home/.rustup/toolchains", 1, when);
        fs.dir(
            "/home/.rustup/toolchains/stable-aarch64-apple-darwin",
            1,
            when,
        );
        fs.file(
            "/home/.rustup/toolchains/stable-aarch64-apple-darwin/bin",
            1,
            9,
            when,
        );
        fs.dir(
            "/home/.rustup/toolchains/nightly-aarch64-apple-darwin",
            1,
            when,
        );
        let settings = "default_toolchain = \"stable-aarch64-apple-darwin\"\n";
        let rows = inventory(
            &fs,
            Path::new("/home"),
            when,
            &MapWorktree::default(),
            Some(settings),
        );

        let stable = rows
            .iter()
            .find(|row| row.active)
            .expect("active toolchain");
        assert!(stable.path.ends_with("stable-aarch64-apple-darwin"));
        assert_eq!(
            stable.advice.as_deref(),
            Some("rustup toolchain uninstall stable-aarch64-apple-darwin")
        );
        let nightly = rows.iter().find(|row| !row.active).expect("nightly");
        assert_eq!(
            nightly.advice.as_deref(),
            Some("rustup toolchain uninstall nightly-aarch64-apple-darwin")
        );
    }

    #[test]
    fn settings_ignore_comments_and_quotes() {
        assert_eq!(
            default_toolchain("# default_toolchain = \"nope\"\ndefault_toolchain = 'nightly'\n"),
            Some("nightly".to_owned())
        );
        assert_eq!(default_toolchain("other = 1\n"), None);
    }
}
