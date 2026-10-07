//! Turn rules into findings.
//!
//! The scan is read-only. It does not create, rename, or remove anything.
//! A finding is staged only when every gate for its tier passed. Review paths
//! are not findings. [`crate::review`] owns that inventory, and [`Report::review`]
//! starts empty so a scan cannot smuggle those rows into a plan.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::config::path_is_denied;
use crate::error::{Error, Result};
use crate::git::{GitProbe, GitTree};
use crate::rules::{HOT_WINDOW, ProjectRule, SafeAnchor, SafeRule, Skip, Tier};
use crate::walk::{EntryMeta, Fs, Kind, LockProbe, Measure, measure};

/// Deepest project directory the discovery walk will inspect.
///
/// Depth 0 is the walk root. Build directories below this are ignored so a
/// huge tree cannot wander off through nested dependencies.
const MAX_PROJECT_DEPTH: u32 = 8;

/// One matched path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Rule id.
    pub rule: &'static str,
    /// Safe or caution.
    pub tier: Tier,
    /// Candidate path. Never a path reached by following a symlink.
    pub path: PathBuf,
    /// `st_dev` of the candidate.
    pub dev: u64,
    /// `st_ino` of the candidate.
    pub ino: u64,
    /// Mtime of the candidate itself.
    pub mtime: Option<SystemTime>,
    /// Newest mtime in the candidate tree.
    pub newest: Option<SystemTime>,
    /// Sum of regular-file lengths, hardlinks counted once inside this tree.
    pub apparent_bytes: u64,
    /// How to get the bytes back.
    pub regenerate: Option<&'static str>,
    /// Marker file the caution rule required, when there was one.
    pub marker: Option<PathBuf>,
    /// Why this finding is not staged. `None` means it is staged.
    pub skip: Option<Skip>,
    /// Why the rule exists.
    pub rationale: &'static str,
}

impl Finding {
    /// Reports whether a later apply is allowed to move this path.
    ///
    /// This is derived from [`Self::skip`] so the two cannot disagree.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::rules::Tier;
    /// use disk_health::scan::Finding;
    /// use std::path::PathBuf;
    ///
    /// let finding = Finding {
    ///     rule: "example",
    ///     tier: Tier::Safe,
    ///     path: PathBuf::from("/cache"),
    ///     dev: 1,
    ///     ino: 1,
    ///     mtime: None,
    ///     newest: None,
    ///     apparent_bytes: 4,
    ///     regenerate: None,
    ///     marker: None,
    ///     skip: None,
    ///     rationale: "example",
    /// };
    /// assert!(finding.staged());
    /// ```
    #[must_use]
    pub const fn staged(&self) -> bool {
        self.skip.is_none()
    }
}

/// Everything a scan learned. Nothing in here has been deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Report {
    /// Matched paths, ordered by tier, rule id, then path.
    pub findings: Vec<Finding>,
    /// Directory entries that could not be read.
    pub unreadable: u64,
    /// Project directories inspected.
    pub dirs_visited: u64,
    /// Requested project roots that do not exist.
    pub roots_missing: Vec<PathBuf>,
    /// Requested project roots that sit on the denylist.
    pub roots_denied: Vec<PathBuf>,
    /// Review inventory. Empty until the caller fills it. Not part of a plan.
    pub review: Vec<crate::review::Item>,
}

impl Report {
    /// Apparent bytes of staged safe findings.
    ///
    /// Caution bytes are not included. They are not removed unless someone
    /// stages them, and this scan never stages them on its own when a gate fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::scan::Report;
    ///
    /// let report = Report {
    ///     findings: Vec::new(),
    ///     unreadable: 0,
    ///     dirs_visited: 0,
    ///     roots_missing: Vec::new(),
    ///     roots_denied: Vec::new(),
    ///     review: Vec::new(),
    /// };
    /// assert_eq!(report.safe_staged_bytes(), 0);
    /// ```
    #[must_use]
    pub fn safe_staged_bytes(&self) -> u64 {
        self.findings
            .iter()
            .filter(|finding| finding.tier == Tier::Safe && finding.staged())
            .fold(0, |sum, finding| sum.saturating_add(finding.apparent_bytes))
    }
}

/// Inputs for [`scan`]. The filesystem and git status are injected.
pub struct ScanOptions<'a> {
    /// Home directory safe rules are resolved against.
    pub home: &'a Path,
    /// Project walk roots. Missing and denylisted roots are reported, not entered.
    pub roots: &'a [PathBuf],
    /// Safe rules to apply.
    pub safe_rules: &'a [SafeRule],
    /// Caution rules to apply while walking `roots`.
    pub project_rules: &'a [ProjectRule],
    /// Prefixes that are never candidates. Component-wise, so `/usr` does not match `/Users`.
    pub deny: &'a [PathBuf],
    /// Clock used for ages. Tests pass a fixed time.
    pub now: SystemTime,
    /// Cleanliness of a project directory.
    pub git: &'a dyn GitProbe,
    /// Filesystem that does not follow symlinks.
    pub fs: &'a dyn Fs,
    /// Called with the number of project directories visited so far.
    pub progress: Option<&'a (dyn Fn(u64) + Sync)>,
    /// Called with each finding before it is stored. May run on a worker thread.
    ///
    /// The callback receives a borrow. It must copy anything it keeps: the
    /// scan reuses no buffer, but the reference does not outlive the call.
    pub on_finding: Option<&'a (dyn Fn(&Finding) + Sync)>,
}

impl std::fmt::Debug for ScanOptions<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScanOptions")
            .field("home", &self.home)
            .field("roots", &self.roots)
            .field("now", &self.now)
            .field("progress", &self.progress.is_some())
            .finish_non_exhaustive()
    }
}

/// Scans `opts` and returns the report.
///
/// A missing cache is an empty contribution. Unreadable entries are counted
/// on the report.
///
/// # Errors
///
/// Returns an error when the OS refuses a worker thread.
///
/// # Panics
///
/// Panics if a worker panics. That is a bug in the scan.
///
/// # Examples
///
/// ```
/// use disk_health::git::MapGit;
/// use disk_health::scan::{ScanOptions, scan};
/// use disk_health::walk::MemFs;
/// use std::path::PathBuf;
/// use std::time::SystemTime;
///
/// let fs = MemFs::new();
/// let git = MapGit::default();
/// let home = PathBuf::from("/home");
/// let report = scan(&ScanOptions {
///     home: &home,
///     roots: &[],
///     safe_rules: &[],
///     project_rules: &[],
///     deny: &[],
///     now: SystemTime::UNIX_EPOCH,
///     git: &git,
///     fs: &fs,
///     progress: None,
///     on_finding: None,
/// })
/// .unwrap();
/// assert!(report.findings.is_empty());
/// ```
pub fn scan(opts: &ScanOptions<'_>) -> Result<Report> {
    let mut chunk = eval_safe_rules(opts)?;
    chunk.merge(discover_projects(opts));

    chunk.findings.sort_by(|left, right| {
        left.tier
            .cmp(&right.tier)
            .then(left.rule.cmp(right.rule))
            .then(left.path.cmp(&right.path))
    });
    chunk
        .findings
        .dedup_by(|left, right| left.rule == right.rule && left.path == right.path);

    Ok(Report {
        findings: chunk.findings,
        unreadable: chunk.unreadable,
        dirs_visited: chunk.dirs_visited,
        roots_missing: chunk.roots_missing,
        roots_denied: chunk.roots_denied,
        review: Vec::new(),
    })
}

#[derive(Default)]
struct Chunk {
    findings: Vec<Finding>,
    unreadable: u64,
    dirs_visited: u64,
    roots_missing: Vec<PathBuf>,
    roots_denied: Vec<PathBuf>,
}

impl Chunk {
    fn merge(&mut self, other: Self) {
        self.findings.extend(other.findings);
        self.unreadable = self.unreadable.saturating_add(other.unreadable);
        self.dirs_visited = self.dirs_visited.saturating_add(other.dirs_visited);
        self.roots_missing.extend(other.roots_missing);
        self.roots_denied.extend(other.roots_denied);
    }
}

fn eval_safe_rules(opts: &ScanOptions<'_>) -> Result<Chunk> {
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for rule in opts.safe_rules {
            let handle = thread::Builder::new()
                .spawn_scoped(scope, || eval_safe(opts, rule))
                .map_err(|source| Error::io("spawn scan worker", opts.home, source))?;
            handles.push(handle);
        }

        let mut merged = Chunk::default();
        for handle in handles {
            merged.merge(handle.join().expect("safe-rule scan panicked"));
        }
        Ok(merged)
    })
}

fn eval_safe(opts: &ScanOptions<'_>, rule: &SafeRule) -> Chunk {
    let mut chunk = Chunk::default();
    match rule.anchor {
        SafeAnchor::Directory(relative) => eval_directory(&mut chunk, opts, rule, relative),
        SafeAnchor::Files(relative) => eval_aged_files(&mut chunk, opts, rule, relative),
    }
    chunk
}

fn eval_directory(chunk: &mut Chunk, opts: &ScanOptions<'_>, rule: &SafeRule, relative: &str) {
    let path = opts.home.join(relative);
    consider(
        chunk,
        opts,
        Candidate {
            rule: rule.id,
            tier: Tier::Safe,
            path: &path,
            min_age: rule.min_age,
            regenerate: rule.regenerate,
            rationale: rule.rationale,
            marker: None,
            project: None,
            directory: true,
        },
    );
}

fn eval_aged_files(chunk: &mut Chunk, opts: &ScanOptions<'_>, rule: &SafeRule, relative: &str) {
    let dir = opts.home.join(relative);
    if path_is_denied(&dir, opts.deny) {
        return;
    }

    let meta = match opts.fs.meta(&dir) {
        Ok(meta) => meta,
        Err(err) if err.is_not_found() => return,
        Err(_) => {
            chunk.unreadable = chunk.unreadable.saturating_add(1);
            return;
        }
    };
    if meta.is_dataless() || meta.kind == Kind::Symlink {
        return;
    }
    if meta.kind == Kind::File {
        consider_known(chunk, opts, file_candidate(rule, &dir), &meta);
        return;
    }
    if meta.kind != Kind::Directory {
        return;
    }

    let names = match opts.fs.read_dir(&dir) {
        Ok(names) => names,
        Err(err) if err.is_not_found() => return,
        Err(_) => {
            chunk.unreadable = chunk.unreadable.saturating_add(1);
            return;
        }
    };

    for name in names {
        let path = dir.join(&name);
        if path_is_denied(&path, opts.deny) {
            continue;
        }

        let child = match opts.fs.meta(&path) {
            Ok(child) => child,
            Err(err) if err.is_not_found() => continue,
            Err(_) => {
                chunk.unreadable = chunk.unreadable.saturating_add(1);
                continue;
            }
        };
        // Subdirectories can hold tool state. Only loose files are candidates.
        if child.kind == Kind::File && !child.is_dataless() {
            consider_known(chunk, opts, file_candidate(rule, &path), &child);
        }
    }
}

fn file_candidate<'a>(rule: &'a SafeRule, path: &'a Path) -> Candidate<'a> {
    Candidate {
        rule: rule.id,
        tier: Tier::Safe,
        path,
        min_age: rule.min_age,
        regenerate: rule.regenerate,
        rationale: rule.rationale,
        marker: None,
        project: None,
        directory: false,
    }
}

fn discover_projects(opts: &ScanOptions<'_>) -> Chunk {
    let mut chunk = Chunk::default();
    for root in opts.roots {
        if path_is_denied(root, opts.deny) {
            chunk.roots_denied.push(root.clone());
            continue;
        }

        match opts.fs.meta(root) {
            Err(err) if err.is_not_found() => {
                chunk.roots_missing.push(root.clone());
            }
            Err(_) => {
                chunk.unreadable = chunk.unreadable.saturating_add(1);
            }
            Ok(meta) if meta.kind != Kind::Directory || meta.is_dataless() => {}
            Ok(meta) => walk_project(opts, root, 0, meta.dev, &mut chunk),
        }
    }
    chunk
}

fn walk_project(opts: &ScanOptions<'_>, dir: &Path, depth: u32, root_dev: u64, chunk: &mut Chunk) {
    if depth > MAX_PROJECT_DEPTH || path_is_denied(dir, opts.deny) {
        return;
    }

    chunk.dirs_visited = chunk.dirs_visited.saturating_add(1);
    if let Some(progress) = opts.progress {
        progress(chunk.dirs_visited);
    }

    let Some(children) = list_children(opts.fs, dir, chunk) else {
        return;
    };
    consider_project_rules(opts, dir, &children, chunk);
    if depth == MAX_PROJECT_DEPTH {
        return;
    }

    for (name, meta) in &children.dirs {
        if pruned(name) || meta.dev != root_dev || meta.is_dataless() {
            continue;
        }
        walk_project(
            opts,
            &dir.join(name),
            depth.saturating_add(1),
            root_dev,
            chunk,
        );
    }
}

struct Children {
    files: BTreeSet<std::ffi::OsString>,
    dirs: Vec<(std::ffi::OsString, EntryMeta)>,
}

fn list_children(fs: &dyn Fs, dir: &Path, chunk: &mut Chunk) -> Option<Children> {
    let names = match fs.read_dir(dir) {
        Ok(names) => names,
        Err(err) if err.is_not_found() => return None,
        Err(_) => {
            chunk.unreadable = chunk.unreadable.saturating_add(1);
            return None;
        }
    };

    let mut children = Children {
        files: BTreeSet::new(),
        dirs: Vec::new(),
    };
    for name in names {
        let meta = match fs.meta(&dir.join(&name)) {
            Ok(meta) => meta,
            Err(err) if err.is_not_found() => continue,
            Err(_) => {
                chunk.unreadable = chunk.unreadable.saturating_add(1);
                continue;
            }
        };

        match meta.kind {
            Kind::File => {
                children.files.insert(name);
            }
            Kind::Directory => {
                children.dirs.push((name, meta));
            }
            Kind::Symlink | Kind::Other => {}
        }
    }
    Some(children)
}

fn consider_project_rules(
    opts: &ScanOptions<'_>,
    dir: &Path,
    children: &Children,
    chunk: &mut Chunk,
) {
    for rule in opts.project_rules {
        let Some(marker) = matched_marker(rule, &children.files) else {
            continue;
        };
        let Some((name, meta)) = children
            .dirs
            .iter()
            .find(|(name, _)| name.as_os_str() == rule.child)
        else {
            continue;
        };
        if meta.is_dataless() {
            continue;
        }

        let path = dir.join(name);
        consider(
            chunk,
            opts,
            Candidate {
                rule: rule.id,
                tier: Tier::Caution,
                path: &path,
                min_age: rule.min_age,
                regenerate: Some(rule.regenerate),
                rationale: rule.rationale,
                marker: Some(dir.join(marker)),
                project: Some(dir),
                directory: true,
            },
        );
    }
}

fn matched_marker(
    rule: &ProjectRule,
    files: &BTreeSet<std::ffi::OsString>,
) -> Option<std::ffi::OsString> {
    for required in rule.require_all {
        if !files.contains(OsStr::new(required)) {
            return None;
        }
    }

    if rule.require_any.is_empty() {
        return rule
            .require_all
            .first()
            .copied()
            .map(std::ffi::OsString::from);
    }
    rule.require_any
        .iter()
        .copied()
        .find(|name| files.contains(OsStr::new(name)))
        .map(std::ffi::OsString::from)
}

fn pruned(name: &OsStr) -> bool {
    const NAMES: &[&str] = &[
        ".git",
        "node_modules",
        "target",
        ".next",
        ".turbo",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "Library",
        ".Trash",
        ".Trashes",
    ];
    NAMES.iter().any(|prune| OsStr::new(prune) == name)
}

struct Candidate<'a> {
    rule: &'static str,
    tier: Tier,
    path: &'a Path,
    min_age: Duration,
    regenerate: Option<&'static str>,
    rationale: &'static str,
    marker: Option<PathBuf>,
    project: Option<&'a Path>,
    /// `true` when the rule named a directory. A file at that path is ignored.
    directory: bool,
}

fn consider(chunk: &mut Chunk, opts: &ScanOptions<'_>, candidate: Candidate<'_>) {
    if path_is_denied(candidate.path, opts.deny) {
        return;
    }

    let meta = match opts.fs.meta(candidate.path) {
        Ok(meta) => meta,
        Err(err) if err.is_not_found() => return,
        Err(_) => {
            chunk.unreadable = chunk.unreadable.saturating_add(1);
            return;
        }
    };
    if meta.kind == Kind::Symlink || meta.is_dataless() {
        return;
    }
    if candidate.directory && meta.kind != Kind::Directory {
        return;
    }

    consider_known(chunk, opts, candidate, &meta);
}

fn consider_known(
    chunk: &mut Chunk,
    opts: &ScanOptions<'_>,
    candidate: Candidate<'_>,
    meta: &EntryMeta,
) {
    let measured = match measure(opts.fs, candidate.path, meta) {
        Ok(measured) => measured,
        Err(err) if err.is_not_found() => return,
        Err(_) => {
            chunk.unreadable = chunk.unreadable.saturating_add(1);
            return;
        }
    };
    chunk.unreadable = chunk.unreadable.saturating_add(measured.unreadable);

    let lock = match opts.fs.probe_lock(candidate.path) {
        Ok(LockProbe::Free) => LockState::Free,
        Ok(LockProbe::Held) => LockState::Held,
        Err(err) if err.is_not_found() => return,
        Err(_) => LockState::Unknown,
    };

    // Age and lock first. `git status` is the expensive check, and a young or
    // locked tree is already not staged.
    let mut skip = gate(&Gate {
        now: opts.now,
        tier: candidate.tier,
        min_age: candidate.min_age,
        measured: &measured,
        lock,
        git: None,
    });
    if skip.is_none()
        && let Some(project) = candidate.project
    {
        let status = opts.git.status(project);
        skip = gate(&Gate {
            now: opts.now,
            tier: candidate.tier,
            min_age: candidate.min_age,
            measured: &measured,
            lock,
            git: Some(status),
        });
    }

    let finding = Finding {
        rule: candidate.rule,
        tier: candidate.tier,
        path: candidate.path.to_path_buf(),
        dev: meta.dev,
        ino: meta.ino,
        mtime: meta.mtime,
        newest: measured.newest,
        apparent_bytes: measured.apparent_bytes,
        regenerate: candidate.regenerate,
        marker: candidate.marker,
        skip,
        rationale: candidate.rationale,
    };
    if let Some(notify) = opts.on_finding {
        notify(&finding);
    }
    chunk.findings.push(finding);
}

#[derive(Clone, Copy)]
enum LockState {
    Free,
    Held,
    Unknown,
}

struct Gate<'a> {
    now: SystemTime,
    tier: Tier,
    min_age: Duration,
    measured: &'a Measure,
    lock: LockState,
    git: Option<GitTree>,
}

fn gate(query: &Gate<'_>) -> Option<Skip> {
    if query.measured.crossed_device() {
        return Some(Skip::CrossedDevice);
    }
    if query.measured.nested_git() {
        return Some(Skip::NestedGit);
    }
    if query.measured.partial() {
        return Some(Skip::Partial);
    }
    if query.measured.unknown_age() {
        return Some(Skip::UnknownAge);
    }

    match query.lock {
        LockState::Held => return Some(Skip::Locked),
        LockState::Unknown => return Some(Skip::LockUnknown),
        LockState::Free => {}
    }

    let Some(newest) = query.measured.newest else {
        return Some(Skip::UnknownAge);
    };
    if newest > query.now {
        return Some(Skip::Future);
    }
    let age = query
        .now
        .duration_since(newest)
        .expect("newest was not after now");
    if age < query.min_age {
        // The 12 hour hot window is the safe-cache default. A longer minimum,
        // including caution builds and aged logs, gets its own reason.
        return Some(if query.tier == Tier::Safe && query.min_age <= HOT_WINDOW {
            Skip::Hot
        } else {
            Skip::Young
        });
    }

    match query.git {
        Some(GitTree::Dirty) => Some(Skip::Dirty),
        Some(GitTree::Unknown) => Some(Skip::GitUnknown),
        Some(GitTree::Clean | GitTree::NotARepo) | None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(now: SystemTime, measured: &Measure) -> Gate<'_> {
        Gate {
            now,
            tier: Tier::Safe,
            min_age: HOT_WINDOW,
            measured,
            lock: LockState::Free,
            git: None,
        }
    }

    fn assert_send<T: Send + ?Sized>() {}

    fn assert_sync<T: Sync + ?Sized>() {}

    #[test]
    fn workers_can_share_the_filesystem_and_git() {
        // `dyn Fs` is shared, not sent. The workers receive `&dyn Fs`.
        assert_sync::<dyn Fs>();
        assert_send::<&dyn Fs>();
        assert_sync::<dyn GitProbe>();
        assert_send::<&dyn GitProbe>();
    }

    #[test]
    fn age_equal_to_the_window_is_staged() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let measured = Measure::known(1, Some(now - HOT_WINDOW));
        let skip = gate(&query(now, &measured));
        assert!(skip.is_none());
    }

    #[test]
    fn one_second_inside_the_window_is_hot() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let inside = HOT_WINDOW
            .checked_sub(Duration::from_secs(1))
            .expect("the hot window is longer than one second");
        let newest = now - inside;
        let measured = Measure::known(1, Some(newest));
        let skip = gate(&query(now, &measured));
        assert_eq!(skip, Some(Skip::Hot));
    }
}
