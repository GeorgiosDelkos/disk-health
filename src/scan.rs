//! Turn rules into findings.
//!
//! The scan is read-only. It does not create, rename, or remove anything.
//! It only reads the volume the home directory is on. A project root or a
//! cache on any other device, such as a USB disk, is refused before it is
//! listed: those disks are slow to walk and are not what this tool reclaims.
//! A finding is staged only when every gate for its tier passed. Review paths
//! are not findings. [`crate::review`] owns that inventory, and [`Report::review`]
//! starts empty so a scan cannot smuggle those rows into a plan.

use std::collections::{BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
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
    /// Requested project roots that sit on the denylist, or on another
    /// volume than the home directory.
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
    /// Project walk roots. A root that is missing, denylisted, or not on the
    /// home volume is reported, not entered.
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
    // A home that cannot be stated has no volume, so nothing is on it.
    let home_dev = opts.fs.meta(opts.home).ok().map(|meta| meta.dev);
    let shared = Shared::new(opts.git, home_dev);
    let mut chunk = run_workers(opts, &shared)?;

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

/// Most threads that measure project candidates at once.
///
/// The work is waiting on directory reads. Past a handful of readers a
/// spinning disk only seeks more.
const MAX_MEASURERS: usize = 8;

/// Runs the three kinds of work side by side.
///
/// Each safe rule has a thread. The calling thread walks the
/// project roots, which is cheap, and hands every candidate it finds to a
/// pool that does the expensive part: measuring the tree and asking `git`.
fn run_workers(opts: &ScanOptions<'_>, shared: &Shared<'_>) -> Result<Chunk> {
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(rx);

    thread::scope(|scope| {
        // Owned by this closure so that every way out of it, including `?`,
        // hangs up the channel. The pool waits on that, and the scope waits
        // on the pool.
        let tx = tx;
        let mut handles = Vec::new();

        let measurers = thread::available_parallelism().map_or(1, NonZero::get);
        for _ in 0..measurers.min(MAX_MEASURERS) {
            handles.push(spawn(scope, opts, || measure_queue(opts, shared, &rx))?);
        }
        for rule in opts.safe_rules {
            handles.push(spawn(scope, opts, move || eval_safe(opts, shared, rule))?);
        }

        let mut merged = discover_projects(opts, &tx, shared.home_dev);
        drop(tx);
        for handle in handles {
            // A worker's panic is this scan's panic. It is not swallowed here.
            merged.merge(
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
            );
        }
        Ok(merged)
    })
}

fn spawn<'scope>(
    scope: &'scope thread::Scope<'scope, '_>,
    opts: &ScanOptions<'_>,
    work: impl FnOnce() -> Chunk + Send + 'scope,
) -> Result<thread::ScopedJoinHandle<'scope, Chunk>> {
    thread::Builder::new()
        .spawn_scoped(scope, work)
        .map_err(|source| Error::io("spawn scan worker", opts.home, source))
}

fn measure_queue(
    opts: &ScanOptions<'_>,
    shared: &Shared<'_>,
    queue: &Mutex<mpsc::Receiver<Candidate>>,
) -> Chunk {
    let mut chunk = Chunk::default();
    loop {
        // The guard is dropped before the candidate is measured, so the
        // pool only queues up to take the next one.
        let next = queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv();
        let Ok(candidate) = next else {
            return chunk;
        };
        consider(&mut chunk, opts, shared, &candidate);
    }
}

/// What every scan thread reads: the home volume, and one `git status`
/// per project directory however many rules match there.
struct Shared<'a> {
    /// Device of the home directory. Nothing on another device is a candidate.
    home_dev: Option<u64>,
    probe: &'a dyn GitProbe,
    seen: Mutex<HashMap<PathBuf, Arc<OnceLock<GitTree>>>>,
}

impl<'a> Shared<'a> {
    fn new(probe: &'a dyn GitProbe, home_dev: Option<u64>) -> Self {
        Self {
            home_dev,
            probe,
            seen: Mutex::new(HashMap::new()),
        }
    }

    fn status(&self, project: &Path) -> GitTree {
        let cell = Arc::clone(self.lock().entry(project.to_path_buf()).or_default());
        // The map is unlocked again. A second worker with the same project
        // waits on this cell for the first one's answer, and workers with
        // other projects do not wait at all.
        *cell.get_or_init(|| self.probe.status(project))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, Arc<OnceLock<GitTree>>>> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
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

    fn note_unreadable(&mut self) {
        self.unreadable = self.unreadable.saturating_add(1);
    }
}

fn eval_safe(opts: &ScanOptions<'_>, shared: &Shared<'_>, rule: &SafeRule) -> Chunk {
    let mut chunk = Chunk::default();
    let relative = match rule.anchor {
        SafeAnchor::Directory(relative) | SafeAnchor::Files(relative) => relative,
    };
    let anchor = match safe_anchor(opts.fs, opts.home, relative) {
        Ok(Some(anchor)) => anchor,
        Ok(None) => return chunk,
        Err(_) => {
            chunk.note_unreadable();
            return chunk;
        }
    };

    match rule.anchor {
        SafeAnchor::Directory(_) => {
            let candidate = safe_candidate(opts, rule, anchor, true);
            consider(&mut chunk, opts, shared, &candidate);
        }
        SafeAnchor::Files(_) => eval_aged_files(&mut chunk, opts, shared, rule, &anchor),
    }
    chunk
}

/// Where a safe rule's path really is, or `None` when it names nothing.
///
/// A directory above the anchor may be a symlink: a relocated `~/.cache` is
/// still the cache, and resolving it is what lets the denylist see where
/// the bytes are. The anchor itself may not be. A link there would point the
/// rule at whatever it names, and `~/.cache/uv -> ~/Documents` must not make
/// a cache out of a home folder.
fn safe_anchor(fs: &dyn Fs, home: &Path, relative: &str) -> Result<Option<PathBuf>> {
    let named = home.join(relative);
    match fs.meta(&named) {
        Ok(meta) if meta.kind == Kind::Symlink => return Ok(None),
        Ok(_) => {}
        Err(err) if err.is_not_found() => return Ok(None),
        Err(err) => return Err(err),
    }
    match fs.canonical(&named) {
        Ok(anchor) => Ok(Some(anchor)),
        Err(err) if err.is_not_found() => Ok(None),
        Err(err) => Err(err),
    }
}

fn safe_candidate(
    opts: &ScanOptions<'_>,
    rule: &SafeRule,
    path: PathBuf,
    directory: bool,
) -> Candidate {
    Candidate {
        rule: rule.id,
        tier: Tier::Safe,
        path,
        min_age: rule.min_age,
        regenerate: rule.regenerate,
        rationale: rule.rationale,
        marker: None,
        project: None,
        directory,
        locks: safe_locks(opts.home, rule),
    }
}

fn safe_locks(home: &Path, rule: &SafeRule) -> Vec<PathBuf> {
    rule.locks.iter().map(|lock| home.join(lock)).collect()
}

fn eval_aged_files(
    chunk: &mut Chunk,
    opts: &ScanOptions<'_>,
    shared: &Shared<'_>,
    rule: &SafeRule,
    dir: &Path,
) {
    if path_is_denied(dir, opts.deny) {
        return;
    }

    let meta = match opts.fs.meta(dir) {
        Ok(meta) => meta,
        Err(err) if err.is_not_found() => return,
        Err(_) => {
            chunk.note_unreadable();
            return;
        }
    };
    if meta.is_dataless() || meta.kind == Kind::Symlink {
        return;
    }
    if meta.kind == Kind::File {
        let candidate = safe_candidate(opts, rule, dir.to_path_buf(), false);
        consider_known(chunk, opts, shared, &candidate, &meta);
        return;
    }
    if meta.kind != Kind::Directory {
        return;
    }

    let listing = match opts.fs.read_dir(dir) {
        Ok(listing) => listing,
        Err(err) if err.is_not_found() => return,
        Err(_) => {
            chunk.note_unreadable();
            return;
        }
    };

    for entry in listing.entries {
        let Some(child) = entry.meta else {
            chunk.note_unreadable();
            continue;
        };
        // Subdirectories can hold tool state. Only loose files are candidates.
        if child.kind != Kind::File || child.is_dataless() {
            continue;
        }

        let path = dir.join(&entry.name);
        if path_is_denied(&path, opts.deny) {
            continue;
        }
        let candidate = safe_candidate(opts, rule, path, false);
        consider_known(chunk, opts, shared, &candidate, &child);
    }
}

fn discover_projects(
    opts: &ScanOptions<'_>,
    queue: &mpsc::Sender<Candidate>,
    home_dev: Option<u64>,
) -> Chunk {
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
            Err(_) => chunk.note_unreadable(),
            Ok(meta) if meta.kind != Kind::Directory || meta.is_dataless() => {}
            Ok(meta) if Some(meta.dev) != home_dev => chunk.roots_denied.push(root.clone()),
            Ok(meta) => {
                let walk = ProjectWalk {
                    opts,
                    queue,
                    root_dev: meta.dev,
                };
                walk.visit(root, 0, &mut chunk);
            }
        }
    }
    chunk
}

struct ProjectWalk<'a, 'opts> {
    opts: &'a ScanOptions<'opts>,
    queue: &'a mpsc::Sender<Candidate>,
    root_dev: u64,
}

impl ProjectWalk<'_, '_> {
    fn visit(&self, dir: &Path, depth: u32, chunk: &mut Chunk) {
        if depth > MAX_PROJECT_DEPTH || path_is_denied(dir, self.opts.deny) {
            return;
        }

        chunk.dirs_visited = chunk.dirs_visited.saturating_add(1);
        if let Some(progress) = self.opts.progress {
            progress(chunk.dirs_visited);
        }

        let Some(children) = list_children(self.opts.fs, dir, chunk) else {
            return;
        };
        // A mount point looks like a plain directory in its parent's listing.
        if children.dev != self.root_dev {
            return;
        }
        self.match_rules(dir, &children);
        if depth == MAX_PROJECT_DEPTH {
            return;
        }

        for (name, meta) in &children.dirs {
            if pruned(name) || meta.dev != self.root_dev || meta.is_dataless() {
                continue;
            }
            self.visit(&dir.join(name), depth.saturating_add(1), chunk);
        }
    }

    fn match_rules(&self, dir: &Path, children: &Children) {
        for rule in self.opts.project_rules {
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
            if !written_by_tool(self.opts.fs, &path, rule) {
                continue;
            }
            let candidate = Candidate {
                rule: rule.id,
                tier: Tier::Caution,
                locks: project_locks(self.opts.fs, &path, rule),
                path,
                min_age: rule.min_age,
                regenerate: Some(rule.regenerate),
                rationale: rule.rationale,
                marker: Some(dir.join(marker)),
                project: Some(dir.to_path_buf()),
                directory: true,
            };
            self.queue
                .send(candidate)
                .expect("the receiver is owned by the caller of the scope");
        }
    }
}

struct Children {
    dev: u64,
    files: BTreeSet<OsString>,
    dirs: Vec<(OsString, EntryMeta)>,
}

fn list_children(fs: &dyn Fs, dir: &Path, chunk: &mut Chunk) -> Option<Children> {
    let listing = match fs.read_dir(dir) {
        Ok(listing) => listing,
        Err(err) if err.is_not_found() => return None,
        Err(_) => {
            chunk.note_unreadable();
            return None;
        }
    };

    let mut children = Children {
        dev: listing.dev,
        files: BTreeSet::new(),
        dirs: Vec::new(),
    };
    for entry in listing.entries {
        let Some(meta) = entry.meta else {
            chunk.note_unreadable();
            continue;
        };

        match meta.kind {
            Kind::File => {
                children.files.insert(entry.name);
            }
            Kind::Directory => children.dirs.push((entry.name, meta)),
            Kind::Symlink | Kind::Other => {}
        }
    }
    Some(children)
}

fn matched_marker(rule: &ProjectRule, files: &BTreeSet<OsString>) -> Option<OsString> {
    for required in rule.require_all {
        if !files.contains(OsStr::new(required)) {
            return None;
        }
    }

    if rule.require_any.is_empty() {
        return rule.require_all.first().copied().map(OsString::from);
    }
    rule.require_any
        .iter()
        .copied()
        .find(|name| files.contains(OsStr::new(name)))
        .map(OsString::from)
}

/// Whether `child` holds one of the files the rule's tool writes there.
fn written_by_tool(fs: &dyn Fs, child: &Path, rule: &ProjectRule) -> bool {
    rule.inside_any.is_empty()
        || rule
            .inside_any
            .iter()
            .any(|name| is_file(fs, &child.join(name)))
}

fn is_file(fs: &dyn Fs, path: &Path) -> bool {
    fs.meta(path).is_ok_and(|meta| meta.kind == Kind::File)
}

/// Paths where the rule's tool would hold a lock while writing `child`.
///
/// The names are tried one and two levels down. Cargo's build lock is at
/// `target/debug/.cargo-lock` or, with `--target`, `target/<triple>/debug/.cargo-lock`.
/// A path that does not exist costs one failed open when it is probed.
fn project_locks(fs: &dyn Fs, child: &Path, rule: &ProjectRule) -> Vec<PathBuf> {
    let mut locks = Vec::new();
    if rule.locks.is_empty() {
        return locks;
    }

    for first in subdirectories(fs, child) {
        for name in rule.locks {
            locks.push(first.join(name));
        }
        for second in subdirectories(fs, &first) {
            for name in rule.locks {
                locks.push(second.join(name));
            }
        }
    }
    locks
}

fn subdirectories(fs: &dyn Fs, dir: &Path) -> Vec<PathBuf> {
    let Ok(listing) = fs.read_dir(dir) else {
        return Vec::new();
    };
    listing
        .entries
        .into_iter()
        .filter(|entry| {
            entry
                .meta
                .is_some_and(|meta| meta.kind == Kind::Directory && !meta.is_dataless())
        })
        .map(|entry| dir.join(entry.name))
        .collect()
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

/// What a plan entry says about itself.
pub(crate) struct Claim<'a> {
    /// Rule id the entry names.
    pub(crate) rule: &'a str,
    /// Tier the entry names.
    pub(crate) tier: Tier,
    /// Path the entry asks to move.
    pub(crate) path: &'a Path,
    /// What is at that path now.
    pub(crate) kind: Kind,
    /// Marker the entry recorded, for a caution rule.
    pub(crate) marker: Option<&'a Path>,
}

/// The rules a claim is checked against.
pub(crate) struct RuleSet<'a> {
    /// Home directory safe rules are resolved against.
    pub(crate) home: &'a Path,
    /// Safe rules.
    pub(crate) safe: &'a [SafeRule],
    /// Caution rules.
    pub(crate) project: &'a [ProjectRule],
}

/// Checks that a rule names `claim` on the disk as it is now.
///
/// The path has to be what the rule's own match would accept: the right
/// name, in the right place, of the right kind, with its markers present.
/// A caution project may not sit below a directory the walk prunes. The
/// project roots and the walk's depth limit are not part of this: a caution
/// directory outside every root still passes, and is still a build
/// directory next to its marker.
///
/// Returns the tool lock files to probe, or `None` when no rule admits the
/// path. A plan file is text anyone can write, with an id anyone can
/// compute, so the plan is not the allowlist. The rule tables are.
pub(crate) fn admit(fs: &dyn Fs, rules: &RuleSet<'_>, claim: &Claim<'_>) -> Option<Vec<PathBuf>> {
    match claim.tier {
        Tier::Safe => admit_safe(fs, rules, claim),
        Tier::Caution => admit_caution(fs, rules, claim),
    }
}

fn admit_safe(fs: &dyn Fs, rules: &RuleSet<'_>, claim: &Claim<'_>) -> Option<Vec<PathBuf>> {
    let rule = rules.safe.iter().find(|rule| rule.id == claim.rule)?;
    let named = match rule.anchor {
        SafeAnchor::Directory(relative) => {
            let anchor = safe_anchor(fs, rules.home, relative).ok()??;
            claim.kind == Kind::Directory && claim.path == anchor
        }
        // Only loose files. The directory stays, and so does anything in it
        // that is not a regular file.
        SafeAnchor::Files(relative) => {
            let anchor = safe_anchor(fs, rules.home, relative).ok()??;
            claim.kind == Kind::File
                && (claim.path == anchor || claim.path.parent() == Some(anchor.as_path()))
        }
    };
    named.then(|| safe_locks(rules.home, rule))
}

fn admit_caution(fs: &dyn Fs, rules: &RuleSet<'_>, claim: &Claim<'_>) -> Option<Vec<PathBuf>> {
    let rule = rules.project.iter().find(|rule| rule.id == claim.rule)?;
    if claim.kind != Kind::Directory || claim.path.file_name()? != rule.child {
        return None;
    }
    let project = claim.path.parent()?;
    // The walk never looks inside these, so no project it finds is below one.
    // `node_modules/pkg/node_modules` belongs to the outer install.
    if project.components().any(|part| pruned(part.as_os_str())) {
        return None;
    }
    let marker = claim.marker?;
    if marker.parent() != Some(project) {
        return None;
    }

    let mut files = BTreeSet::new();
    for name in rule.require_all.iter().chain(rule.require_any) {
        if is_file(fs, &project.join(name)) {
            files.insert(OsString::from(name));
        }
    }
    matched_marker(rule, &files)?;
    if !files.contains(marker.file_name()?) || !written_by_tool(fs, claim.path, rule) {
        return None;
    }
    Some(project_locks(fs, claim.path, rule))
}

struct Candidate {
    rule: &'static str,
    tier: Tier,
    path: PathBuf,
    min_age: Duration,
    regenerate: Option<&'static str>,
    rationale: &'static str,
    marker: Option<PathBuf>,
    project: Option<PathBuf>,
    /// `true` when the rule named a directory. A file at that path is ignored.
    directory: bool,
    /// Lock files of the tool that owns the path.
    locks: Vec<PathBuf>,
}

fn consider(chunk: &mut Chunk, opts: &ScanOptions<'_>, shared: &Shared<'_>, candidate: &Candidate) {
    if path_is_denied(&candidate.path, opts.deny) {
        return;
    }

    let meta = match opts.fs.meta(&candidate.path) {
        Ok(meta) => meta,
        Err(err) if err.is_not_found() => return,
        Err(_) => {
            chunk.note_unreadable();
            return;
        }
    };
    if meta.kind == Kind::Symlink || meta.is_dataless() {
        return;
    }
    if candidate.directory && meta.kind != Kind::Directory {
        return;
    }

    consider_known(chunk, opts, shared, candidate, &meta);
}

fn consider_known(
    chunk: &mut Chunk,
    opts: &ScanOptions<'_>,
    shared: &Shared<'_>,
    candidate: &Candidate,
    meta: &EntryMeta,
) {
    // Here and not earlier, because this is the first `lstat` of the path
    // itself. `~/.cargo` linked onto an external disk, or a `target` that is
    // a mount point, looks local until then. An unknown home volume holds nothing.
    if Some(meta.dev) != shared.home_dev {
        return;
    }

    let measured = match measure(opts.fs, &candidate.path, meta) {
        Ok(measured) => measured,
        Err(err) if err.is_not_found() => return,
        Err(_) => {
            chunk.note_unreadable();
            return;
        }
    };
    chunk.unreadable = chunk.unreadable.saturating_add(measured.unreadable);

    let lock = probe_locks(opts.fs, &candidate.path, &candidate.locks);
    if lock == LockState::Gone {
        return;
    }

    // Lock and the tree's own problems first. `git status` is the expensive
    // check, and a locked or unreadable tree is already not staged. A tree
    // that is only young is still asked: the UI lets an operator override
    // age, and must not hand them a dirty tree that was never looked at.
    let mut query = Gate {
        now: opts.now,
        tier: candidate.tier,
        min_age: candidate.min_age,
        measured: &measured,
        lock,
        git: None,
    };
    let mut skip = gate(&query);
    if matches!(skip, None | Some(Skip::Young))
        && let Some(project) = &candidate.project
    {
        query.git = Some(shared.status(project));
        skip = gate(&query);
    }

    let finding = Finding {
        rule: candidate.rule,
        tier: candidate.tier,
        path: candidate.path.clone(),
        dev: meta.dev,
        ino: meta.ino,
        mtime: meta.mtime,
        newest: measured.newest,
        apparent_bytes: measured.apparent_bytes,
        regenerate: candidate.regenerate,
        marker: candidate.marker.clone(),
        skip,
        rationale: candidate.rationale,
    };
    if let Some(notify) = opts.on_finding {
        notify(&finding);
    }
    chunk.findings.push(finding);
}

/// Whether anything holds the candidate or one of its tool's lock files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockState {
    /// Nothing is held.
    Free,
    /// Another process holds a lock.
    Held,
    /// A probe failed, so the path might be in use.
    Unknown,
    /// The candidate itself is gone.
    Gone,
}

/// Probes `path` and then each of `locks`. A lock file that does not exist is free.
pub(crate) fn probe_locks(fs: &dyn Fs, path: &Path, locks: &[PathBuf]) -> LockState {
    match fs.probe_lock(path) {
        Ok(LockProbe::Free) => {}
        Ok(LockProbe::Held) => return LockState::Held,
        Err(err) if err.is_not_found() => return LockState::Gone,
        Err(_) => return LockState::Unknown,
    }

    let mut state = LockState::Free;
    for lock in locks {
        match fs.probe_lock(lock) {
            Ok(LockProbe::Held) => return LockState::Held,
            Ok(LockProbe::Free) => {}
            Err(err) if err.is_not_found() => {}
            Err(_) => state = LockState::Unknown,
        }
    }
    state
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
        LockState::Free | LockState::Gone => {}
    }

    let Some(newest) = query.measured.newest else {
        return Some(Skip::UnknownAge);
    };
    if newest > query.now {
        return Some(Skip::Future);
    }
    // Before age. A dirty tree stays held when it gets old, and age is the
    // one reason an operator may override.
    match query.git {
        Some(GitTree::Dirty) => return Some(Skip::Dirty),
        Some(GitTree::Unknown) => return Some(Skip::GitUnknown),
        Some(GitTree::Clean | GitTree::NotARepo) | None => {}
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
    None
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
