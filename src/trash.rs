//! Move a staged plan entry onto the same volume, or leave it alone.
//!
//! The only mutation is `rename`. A cross-device error is a skip: nothing is
//! copied and nothing is unlinked. `purge` is the only unlink, and it only
//! unlinks a path whose canonical location is still inside a quarantine
//! directory named in the action log.
//!
//! A plan is not trusted for what it names. Its id is a hash anyone can
//! compute, so before a rename the entry has to be a path one of the rules
//! given to [`apply`] produces on the disk as it is now, spelled canonically.
//! The rename itself refuses to replace an existing destination.

use std::collections::HashMap;
use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use crate::config::{normalize, path_is_denied};
use crate::error::{Error, Result};
use crate::log::{Action, ActionLog};
use crate::plan::{Entry, Plan};
use crate::report::format_bytes;
use crate::rules::{ProjectRule, SafeRule, Tier};
use crate::scan::{Claim, LockState, RuleSet, admit, probe_locks};
use crate::time::unix_nanos;
use crate::walk::{EntryMeta, Fs, Kind, measure};

/// Renames `from` to `to`. The real implementation is [`FsRename`].
pub trait Renamer {
    /// `rename(2)`, except that an existing `to` is an error and is left alone.
    ///
    /// # Errors
    ///
    /// Returns the system error. [`ErrorKind::CrossesDevices`] must not be
    /// turned into a copy, and [`ErrorKind::AlreadyExists`] must not be
    /// turned into a replace.
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()>;
}

/// `renamex_np` with `RENAME_EXCL`.
///
/// Plain `rename` replaces a file at the destination. Checking first leaves
/// a window, and what would be replaced is something already in the trash
/// or, on restore, something written where the original used to be.
///
/// # Examples
///
/// ```
/// use disk_health::trash::{FsRename, Renamer};
///
/// let dir = std::env::temp_dir().join(format!("disk-health-doc-excl-{}", std::process::id()));
/// let _ = std::fs::remove_dir_all(&dir);
/// std::fs::create_dir_all(&dir).unwrap();
/// std::fs::write(dir.join("from"), b"new").unwrap();
/// std::fs::write(dir.join("to"), b"kept").unwrap();
///
/// let err = FsRename.rename(&dir.join("from"), &dir.join("to")).unwrap_err();
/// assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
/// assert_eq!(std::fs::read(dir.join("to")).unwrap(), b"kept");
/// let _ = std::fs::remove_dir_all(&dir);
/// ```
#[derive(Debug, Default)]
pub struct FsRename;

impl Renamer for FsRename {
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        match sys::rename_exclusive(from, to) {
            Err(source) if exclusive_unsupported(&source) => rename_after_check(from, to),
            result => result,
        }
    }
}

/// `ENOTSUP` from the macOS SDK header `sys/errno.h`.
fn exclusive_unsupported(source: &std::io::Error) -> bool {
    source.kind() == ErrorKind::Unsupported || source.raw_os_error() == Some(45)
}

/// For a filesystem without `RENAME_EXCL`. The check and the rename are two
/// calls, which is the window the exclusive rename closes where it exists.
fn rename_after_check(from: &Path, to: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(to) {
        Ok(_) => Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "rename destination exists",
        )),
        Err(source) if source.kind() == ErrorKind::NotFound => fs::rename(from, to),
        Err(source) => Err(source),
    }
}

/// Everything [`apply`] needs, in one place so the function stays small.
pub struct ApplyRequest<'a> {
    /// Plan to act on.
    pub plan: &'a Plan,
    /// Must equal [`Plan::plan_id`]. Checked before any rename.
    pub confirm: &'a str,
    /// Home directory. Its `.Trash` is the same-volume trash.
    pub home: &'a Path,
    /// `st_dev` of `home`.
    pub home_dev: u64,
    /// `getuid`, used for `/.Trashes/<uid>` on other volumes.
    pub uid: u32,
    /// Prefixes that are never moved, even if the plan names them.
    pub deny: &'a [PathBuf],
    /// Safe rules. An entry is moved only when one of these names its path.
    pub safe_rules: &'a [SafeRule],
    /// Caution rules. An entry is moved only when its marker is still there.
    pub project_rules: &'a [ProjectRule],
    /// `lstat` and the lock probe. Destination directories use the process filesystem.
    pub fs: &'a dyn Fs,
    /// Rename implementation.
    pub renamer: &'a dyn Renamer,
    /// Action log. Appended only after a rename returns.
    pub log: &'a mut dyn ActionLog,
    /// Clock for the log line and for purge age. Not used to re-age entries.
    pub now: SystemTime,
    /// Set by the interrupt handler. Checked between entries.
    pub interrupt: Option<&'a AtomicBool>,
}

impl std::fmt::Debug for ApplyRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApplyRequest")
            .field("confirm", &self.confirm)
            .field("home", &self.home)
            .field("home_dev", &self.home_dev)
            .field("uid", &self.uid)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// What apply did. Skipped rows are staged entries that stayed in place.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ApplyReport {
    /// Renames that returned success.
    pub moved: Vec<Moved>,
    /// Staged entries that were not moved.
    pub skipped: Vec<Skipped>,
}

/// One rename that succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    /// Original path.
    pub from: PathBuf,
    /// Trash or quarantine path.
    pub to: PathBuf,
    /// Action id, also written to the log when `logged` is set.
    pub id: String,
    /// Whether the log accepted the line.
    pub logged: bool,
}

/// A staged entry that was left in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Plan path.
    pub path: PathBuf,
    /// Why it was not moved.
    pub reason: SkipMove,
}

/// Why a staged entry was not moved.
///
/// Exhaustive until a new skip has a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipMove {
    /// `lstat` said the path is gone.
    Missing,
    /// The path is a symlink.
    Symlink,
    /// The path is an iCloud placeholder.
    Dataless,
    /// Device, inode, or mtime does not match the plan.
    Identity,
    /// A child is newer than the scan.
    Newer,
    /// The tree could not be reread, or it grew a mount or a nested checkout.
    Partial,
    /// The path is on the denylist or is not absolute.
    Denied,
    /// The path is not canonical: it goes through a symlink, or is spelled
    /// in a different case than the disk stores.
    NotCanonical,
    /// No rule produces this path, or its marker files are gone.
    Rule,
    /// A caution entry has no marker.
    Marker,
    /// A file lock is held, or the probe failed.
    Locked,
    /// `rename` returned `EXDEV`. The source was not copied.
    Exdev,
    /// The operator interrupted the loop.
    Interrupted,
    /// `rename` failed for another reason.
    Rename(String),
}

impl ApplyReport {
    /// `0` when every staged entry moved and was logged, otherwise `3`.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::trash::ApplyReport;
    ///
    /// let report = ApplyReport { moved: Vec::new(), skipped: Vec::new() };
    /// assert_eq!(report.exit_code(), 0);
    /// ```
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        let unlogged = self.moved.iter().any(|item| !item.logged);
        if self.skipped.is_empty() && !unlogged {
            0
        } else {
            3
        }
    }
}

impl std::fmt::Display for SkipMove {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str("path is missing"),
            Self::Symlink => formatter.write_str("path is a symlink"),
            Self::Dataless => formatter.write_str("path is dataless"),
            Self::Identity => formatter.write_str("inode or mtime changed"),
            Self::Newer => formatter.write_str("a child is newer than the scan"),
            Self::Partial => formatter.write_str("tree could not be reread"),
            Self::Denied => formatter.write_str("path is denied"),
            Self::NotCanonical => formatter.write_str("path is not canonical"),
            Self::Rule => formatter.write_str("no rule names this path"),
            Self::Marker => formatter.write_str("caution entry has no marker"),
            Self::Locked => formatter.write_str("path is locked"),
            Self::Exdev => formatter.write_str("rename crossed devices"),
            Self::Interrupted => formatter.write_str("interrupted"),
            Self::Rename(message) => write!(formatter, "rename failed: {message}"),
        }
    }
}

/// Moves staged entries whose identity still matches.
///
/// # Errors
///
/// Returns [`Error::PlanMismatch`] before any rename when `confirm` is wrong.
///
/// # Examples
///
/// ```
/// use disk_health::log::MemoryLog;
/// use disk_health::plan::Plan;
/// use disk_health::scan::Report;
/// use disk_health::trash::{ApplyRequest, FsRename, apply};
/// use disk_health::walk::MemFs;
/// use std::path::Path;
/// use std::time::UNIX_EPOCH;
///
/// let plan = Plan::from_report(&Report::empty(), "host", UNIX_EPOCH);
/// let fs = MemFs::new();
/// let renamer = FsRename;
/// let mut log = MemoryLog::default();
/// let err = apply(ApplyRequest {
///     plan: &plan,
///     confirm: "nope",
///     home: Path::new("/home"),
///     home_dev: 1,
///     uid: 0,
///     deny: &[],
///     safe_rules: &[],
///     project_rules: &[],
///     fs: &fs,
///     renamer: &renamer,
///     log: &mut log,
///     now: UNIX_EPOCH,
///     interrupt: None,
/// })
/// .unwrap_err();
/// assert!(err.to_string().contains("does not match"));
/// ```
pub fn apply(mut request: ApplyRequest<'_>) -> Result<ApplyReport> {
    if request.confirm != request.plan.plan_id {
        return Err(Error::PlanMismatch {
            message: format!(
                "confirm {} does not match plan {}",
                request.confirm, request.plan.plan_id
            ),
        });
    }
    Ok(move_staged(&mut request))
}

/// Same move as [`apply`], after the typed byte total matches [`format_bytes`].
///
/// # Errors
///
/// Returns [`Error::PlanMismatch`] when `typed` is not the staged total.
/// Nothing is renamed in that case.
///
/// # Examples
///
/// ```
/// use disk_health::log::MemoryLog;
/// use disk_health::plan::Plan;
/// use disk_health::scan::Report;
/// use disk_health::trash::{ApplyRequest, FsRename, apply_typed_total};
/// use disk_health::walk::MemFs;
/// use std::path::Path;
/// use std::time::UNIX_EPOCH;
///
/// let plan = Plan::from_report(&Report::empty(), "host", UNIX_EPOCH);
/// let fs = MemFs::new();
/// let renamer = FsRename;
/// let mut log = MemoryLog::default();
/// let err = apply_typed_total(
///     ApplyRequest {
///         plan: &plan,
///         confirm: plan.plan_id.as_str(),
///         home: Path::new("/home"),
///         home_dev: 1,
///         uid: 0,
///         deny: &[],
///         safe_rules: &[],
///         project_rules: &[],
///         fs: &fs,
///         renamer: &renamer,
///         log: &mut log,
///         now: UNIX_EPOCH,
///         interrupt: None,
///     },
///     "1B",
/// )
/// .unwrap_err();
/// assert!(err.to_string().contains("1B"));
/// ```
pub fn apply_typed_total(mut request: ApplyRequest<'_>, typed: &str) -> Result<ApplyReport> {
    let expected = format_bytes(request.plan.staged_bytes());
    if typed != expected {
        return Err(Error::PlanMismatch {
            message: format!("typed total {typed} does not match {expected}"),
        });
    }
    Ok(move_staged(&mut request))
}

fn move_staged(request: &mut ApplyRequest<'_>) -> ApplyReport {
    let mut moved = Vec::new();
    let mut skipped = Vec::new();
    for (index, entry) in request.plan.entries.iter().enumerate() {
        if interrupted(request.interrupt) {
            if entry.staged {
                skipped.push(skip(entry, SkipMove::Interrupted));
            }
            continue;
        }
        if !entry.staged {
            continue;
        }

        match stage_one(request, entry, index) {
            Ok(item) => moved.push(item),
            Err(reason) => skipped.push(skip(entry, reason)),
        }
    }
    ApplyReport { moved, skipped }
}

fn stage_one(
    request: &mut ApplyRequest<'_>,
    entry: &Entry,
    index: usize,
) -> std::result::Result<Moved, SkipMove> {
    if let Some(reason) = revalidate(request, entry) {
        return Err(reason);
    }

    let dest = choose_dest(request, entry, index)?;
    rename_and_log(request, entry, &dest)
}

fn revalidate(request: &ApplyRequest<'_>, entry: &Entry) -> Option<SkipMove> {
    let fs = request.fs;
    if !entry.path.is_absolute() || path_is_denied(&entry.path, request.deny) {
        return Some(SkipMove::Denied);
    }
    if entry.tier == Tier::Caution && entry.marker.is_none() {
        return Some(SkipMove::Marker);
    }

    let meta = match fs.meta(&entry.path) {
        Ok(meta) => meta,
        Err(err) if err.is_not_found() => return Some(SkipMove::Missing),
        Err(_) => return Some(SkipMove::Partial),
    };
    if let Some(reason) = wrong_object(entry, &meta) {
        return Some(reason);
    }
    let locks = match admitted(request, entry) {
        Ok(locks) => locks,
        Err(reason) => return Some(reason),
    };

    if probe_locks(fs, &entry.path, &locks) != LockState::Free {
        return Some(SkipMove::Locked);
    }
    if meta.kind == Kind::Directory {
        return directory_still_cold(fs, entry, &meta);
    }
    None
}

/// The path now holds something other than what the scan recorded.
fn wrong_object(entry: &Entry, meta: &EntryMeta) -> Option<SkipMove> {
    if meta.kind == Kind::Symlink {
        return Some(SkipMove::Symlink);
    }
    if meta.is_dataless() {
        return Some(SkipMove::Dataless);
    }
    if !matches!(meta.kind, Kind::Directory | Kind::File) {
        return Some(SkipMove::Identity);
    }
    if meta.dev != entry.dev || meta.ino != entry.ino {
        return Some(SkipMove::Identity);
    }

    let fresh = meta.mtime.and_then(unix_nanos);
    if fresh.is_none() || fresh != entry.mtime_ns {
        return Some(SkipMove::Identity);
    }
    None
}

/// The tool lock files to probe, once the path is canonical and a rule names it.
///
/// The denylist was compared against the path as written. That only means
/// something when the path is the canonical one, so `~/link/keys` and
/// `~/.SSH` stop here.
fn admitted(
    request: &ApplyRequest<'_>,
    entry: &Entry,
) -> std::result::Result<Vec<PathBuf>, SkipMove> {
    match request.fs.canonical(&entry.path) {
        Ok(canonical) if canonical == entry.path => {}
        Ok(_) => return Err(SkipMove::NotCanonical),
        Err(_) => return Err(SkipMove::Partial),
    }

    let rules = RuleSet {
        home: request.home,
        safe: request.safe_rules,
        project: request.project_rules,
    };
    let claim = Claim {
        rule: &entry.rule,
        tier: entry.tier,
        path: &entry.path,
        marker: entry.marker.as_deref(),
    };
    admit(request.fs, &rules, &claim).ok_or(SkipMove::Rule)
}

fn directory_still_cold(fs: &dyn Fs, entry: &Entry, meta: &EntryMeta) -> Option<SkipMove> {
    let Ok(measured) = measure(fs, &entry.path, meta) else {
        return Some(SkipMove::Partial);
    };
    if measured.partial()
        || measured.unknown_age()
        || measured.nested_git()
        || measured.crossed_device()
    {
        return Some(SkipMove::Partial);
    }

    let fresh = measured.newest.and_then(unix_nanos);
    match (fresh, entry.newest_child_ns) {
        (Some(fresh), Some(recorded)) if fresh > recorded => Some(SkipMove::Newer),
        (Some(_), Some(_)) => None,
        _ => Some(SkipMove::Newer),
    }
}

fn choose_dest(
    request: &ApplyRequest<'_>,
    entry: &Entry,
    index: usize,
) -> std::result::Result<PathBuf, SkipMove> {
    let volume = volume_root(request.fs, &entry.path).map_err(|_| SkipMove::Partial)?;
    let trash = platform_trash(
        request.home,
        request.home_dev,
        request.uid,
        entry.dev,
        &volume,
    );
    if let Some(dir) = prepare_dir(&trash) {
        return Ok(indexed_path(&dir, &entry.path, index));
    }

    let root = volume.join(".disk-health-quarantine");
    let bucket = root.join(&request.plan.plan_id);
    if bucket.starts_with(&entry.path) || root.starts_with(&entry.path) {
        return Err(SkipMove::Rename(
            "quarantine would sit inside the candidate".to_owned(),
        ));
    }
    prepare_private(&root)
        .ok_or_else(|| SkipMove::Rename("cannot create quarantine".to_owned()))?;
    prepare_private(&bucket)
        .ok_or_else(|| SkipMove::Rename("cannot create quarantine".to_owned()))?;
    Ok(indexed_path(&bucket, &entry.path, index))
}

fn rename_and_log(
    request: &mut ApplyRequest<'_>,
    entry: &Entry,
    dest: &Path,
) -> std::result::Result<Moved, SkipMove> {
    if let Err(source) = request.renamer.rename(&entry.path, dest) {
        return Err(if source.kind() == ErrorKind::CrossesDevices {
            SkipMove::Exdev
        } else {
            SkipMove::Rename(source.to_string())
        });
    }

    let action = Action {
        id: String::new(),
        plan_id: request.plan.plan_id.clone(),
        rule: entry.rule.clone(),
        from: entry.path.clone(),
        to: dest.to_path_buf(),
        dev: entry.dev,
        ino: entry.ino,
        apparent_bytes: entry.apparent_bytes,
        at: request.now,
    }
    .stamp();
    let logged = request.log.append(&action).is_ok();
    Ok(Moved {
        from: entry.path.clone(),
        to: dest.to_path_buf(),
        id: action.id,
        logged,
    })
}

fn volume_root(fs: &dyn Fs, path: &Path) -> Result<PathBuf> {
    let dev = fs.meta(path)?.dev;
    let mut current = path.to_path_buf();
    while let Some(parent) = current.parent() {
        if parent.as_os_str().is_empty() {
            break;
        }
        let Ok(meta) = fs.meta(parent) else { break };
        if meta.dev != dev || meta.kind != Kind::Directory {
            break;
        }
        current = parent.to_path_buf();
    }
    Ok(current)
}

fn platform_trash(home: &Path, home_dev: u64, uid: u32, dev: u64, volume: &Path) -> PathBuf {
    if dev == home_dev {
        home.join(".Trash")
    } else {
        volume.join(".Trashes").join(uid.to_string())
    }
}

fn prepare_dir(path: &Path) -> Option<PathBuf> {
    prepare_final(path, false)
}

fn prepare_private(path: &Path) -> Option<PathBuf> {
    prepare_final(path, true)
}

/// Creates the last component when it is missing.
///
/// Ancestors are not walked. An intermediate symlink such as `/var` is how
/// macOS lays out `/var/folders`, and rejecting it would make `~/.Trash`
/// unreachable. The directory we create or reuse is still `lstat`ed, so a
/// `.Trash` symlink is not used.
fn prepare_final(path: &Path, private: bool) -> Option<PathBuf> {
    ensure_parent(path, private)?;
    ensure_dir(path, private).then(|| path.to_path_buf())
}

fn ensure_parent(path: &Path, private: bool) -> Option<()> {
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        return Some(());
    }
    match fs::symlink_metadata(parent) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Some(()),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let grand = parent.parent()?;
            let grand_meta = fs::symlink_metadata(grand).ok()?;
            if grand_meta.is_dir() && !grand_meta.file_type().is_symlink() {
                ensure_dir(parent, private).then_some(())
            } else {
                None
            }
        }
        Ok(_) | Err(_) => None,
    }
}

fn ensure_dir(path: &Path, private: bool) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.is_dir() && !meta.file_type().is_symlink(),
        Err(err) if err.kind() == ErrorKind::NotFound => create_dir(path, private),
        Err(_) => false,
    }
}

fn create_dir(path: &Path, private: bool) -> bool {
    if !private {
        return fs::create_dir(path).is_ok();
    }
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).is_ok()
}

fn indexed_path(dir: &Path, source: &Path, index: usize) -> PathBuf {
    let name = source
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("entry"));
    let first = dir.join(format!("{index}-{}", name.to_string_lossy()));
    if fs::symlink_metadata(&first).is_err() {
        return first;
    }
    for index in 1..10_000 {
        let candidate = dir.join(format!("{}-{index}", name.to_string_lossy()));
        if fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
    }
    dir.join(format!("{}-last", name.to_string_lossy()))
}

fn interrupted(flag: Option<&AtomicBool>) -> bool {
    flag.is_some_and(|flag| flag.load(Ordering::Acquire))
}

fn skip(entry: &Entry, reason: SkipMove) -> Skipped {
    Skipped {
        path: entry.path.clone(),
        reason,
    }
}

/// Inputs for [`restore`].
pub struct RestoreRequest<'a> {
    /// Action id to put back.
    pub id: &'a str,
    /// Home directory, used to recognize `~/.Trash`.
    pub home: &'a Path,
    /// `getuid`, used to recognize `/.Trashes/<uid>`.
    pub uid: u32,
    /// Log that recorded the move.
    pub log: &'a dyn ActionLog,
    /// Rename implementation.
    pub renamer: &'a dyn Renamer,
}

impl std::fmt::Debug for RestoreRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestoreRequest")
            .field("id", &self.id)
            .field("home", &self.home)
            .field("uid", &self.uid)
            .finish_non_exhaustive()
    }
}

/// Moves one logged path back when the original path is gone.
///
/// # Errors
///
/// Returns an error when the id is unknown, the destination is outside trash,
/// the original path exists, or the rename fails. An existing original is
/// left untouched.
///
/// # Examples
///
/// ```
/// use disk_health::log::MemoryLog;
/// use disk_health::trash::{FsRename, RestoreRequest, restore};
/// use std::path::Path;
///
/// let log = MemoryLog::default();
/// let err = restore(&RestoreRequest {
///     id: "missing",
///     home: Path::new("/home"),
///     uid: 0,
///     log: &log,
///     renamer: &FsRename,
/// })
/// .unwrap_err();
/// assert!(err.to_string().contains("unknown action"));
/// ```
pub fn restore(request: &RestoreRequest<'_>) -> Result<PathBuf> {
    let actions = request.log.load()?;
    let action = actions
        .iter()
        .rev()
        .find(|action| action.id == request.id)
        .ok_or_else(|| Error::Plan {
            message: format!("unknown action {}", request.id),
        })?;
    if trusted_root(&action.to, request.home, request.uid).is_none() {
        return Err(Error::Plan {
            message: "action destination is outside trash".to_owned(),
        });
    }
    match fs::symlink_metadata(&action.from) {
        Ok(_) => {
            return Err(Error::Plan {
                message: "original path exists".to_owned(),
            });
        }
        Err(source) if source.kind() == ErrorKind::NotFound => {}
        Err(source) => return Err(Error::io("stat original", &action.from, source)),
    }

    request
        .renamer
        .rename(&action.to, &action.from)
        .map_err(|source| Error::io("restore", &action.to, source))?;
    Ok(action.from.clone())
}

/// Inputs for [`purge`].
pub struct PurgeRequest<'a> {
    /// Log whose quarantine rows are candidates.
    pub log: &'a dyn ActionLog,
    /// Clock the 7 day age is measured from.
    pub now: SystemTime,
}

impl std::fmt::Debug for PurgeRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PurgeRequest")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// What purge removed. Rows outside quarantine are counted in `ignored`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct PurgeReport {
    /// Paths that were unlinked.
    pub removed: Vec<PathBuf>,
    /// Rows that were too new, outside quarantine, or already gone.
    pub ignored: u64,
}

/// Unlinks quarantine entries older than 7 days.
///
/// Platform trash is not touched. A row whose canonical path is outside the
/// quarantine directory named in that row is ignored, and so is every row
/// but the last for a destination.
///
/// # Errors
///
/// Returns an error when the log cannot be read, or an unlink inside a
/// trusted quarantine path fails.
///
/// # Examples
///
/// ```
/// use disk_health::log::MemoryLog;
/// use disk_health::trash::{PurgeRequest, purge};
/// use std::time::UNIX_EPOCH;
///
/// let log = MemoryLog::default();
/// let report = purge(&PurgeRequest { log: &log, now: UNIX_EPOCH }).unwrap();
/// assert!(report.removed.is_empty());
/// ```
pub fn purge(request: &PurgeRequest<'_>) -> Result<PurgeReport> {
    let actions = request.log.load()?;
    // A path can be quarantined, restored, and quarantined again at the same
    // destination. Only the last move says how long it has been there.
    let latest: HashMap<&Path, usize> = actions
        .iter()
        .enumerate()
        .map(|(index, action)| (action.to.as_path(), index))
        .collect();

    let mut removed = Vec::new();
    let mut ignored = 0;
    for (index, action) in actions.iter().enumerate() {
        if latest.get(action.to.as_path()) != Some(&index) {
            ignored += 1;
            continue;
        }
        if !old_enough(action.at, request.now) {
            ignored += 1;
            continue;
        }
        let Some(root) = quarantine_root(&action.to) else {
            ignored += 1;
            continue;
        };
        if !still_inside(&action.to, &root) {
            ignored += 1;
            continue;
        }
        unlink_inside(&action.to)?;
        removed.push(action.to.clone());
    }
    Ok(PurgeReport { removed, ignored })
}

fn old_enough(at: SystemTime, now: SystemTime) -> bool {
    now.duration_since(at)
        .is_ok_and(|age| age >= Duration::from_hours(7 * 24))
}

fn trusted_root(path: &Path, home: &Path, uid: u32) -> Option<PathBuf> {
    if let Some(root) = quarantine_root(path) {
        return still_inside(path, &root).then_some(root);
    }
    let home_trash = normalize(&home.join(".Trash"));
    if normalize(path).starts_with(&home_trash) && still_inside(path, &home_trash) {
        return Some(home_trash);
    }
    let trashes = trashes_root(path, uid)?;
    still_inside(path, &trashes).then_some(trashes)
}

fn quarantine_root(path: &Path) -> Option<PathBuf> {
    named_ancestor(path, ".disk-health-quarantine")
}

fn trashes_root(path: &Path, uid: u32) -> Option<PathBuf> {
    let path = normalize(path);
    let uid = uid.to_string();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        if component.as_os_str() != ".Trashes" {
            continue;
        }
        let next = components.get(index + 1)?;
        if next.as_os_str() != std::ffi::OsStr::new(&uid) {
            continue;
        }
        let mut root = PathBuf::new();
        for component in &components[..=index + 1] {
            root.push(component);
        }
        return Some(root);
    }
    None
}

fn named_ancestor(path: &Path, name: &str) -> Option<PathBuf> {
    let path = normalize(path);
    let mut acc = PathBuf::new();
    let mut found = None;
    for component in path.components() {
        acc.push(component);
        if component.as_os_str() == name {
            found = Some(acc.clone());
        }
    }
    found
}

fn still_inside(path: &Path, root: &Path) -> bool {
    let Ok(canon) = fs::canonicalize(path) else {
        return false;
    };
    let Ok(canon_root) = fs::canonicalize(root) else {
        return false;
    };
    canon.starts_with(&canon_root) && canon != canon_root
}

fn unlink_inside(path: &Path) -> Result<()> {
    let meta =
        fs::symlink_metadata(path).map_err(|source| Error::io("stat quarantine", path, source))?;
    if meta.file_type().is_symlink() || meta.is_file() {
        fs::remove_file(path).map_err(|source| Error::io("unlink quarantine", path, source))
    } else if meta.is_dir() {
        fs::remove_dir_all(path).map_err(|source| Error::io("unlink quarantine", path, source))
    } else {
        Err(Error::Plan {
            message: "quarantine entry is not a file or directory".to_owned(),
        })
    }
}

#[cfg(target_os = "macos")]
mod sys {
    #![allow(unsafe_code, reason = "renamex_np from the system headers")]

    use std::ffi::{CString, c_char, c_int, c_uint};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    /// `RENAME_EXCL` from the macOS SDK header `sys/stdio.h`.
    const RENAME_EXCL: c_uint = 0x0000_0004;

    unsafe extern "C" {
        /// `int renamex_np(const char *, const char *, unsigned int)` from `stdio.h`.
        fn renamex_np(from: *const c_char, to: *const c_char, flags: c_uint) -> c_int;
    }

    pub(super) fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
        let from = CString::new(from.as_os_str().as_bytes())?;
        let to = CString::new(to.as_os_str().as_bytes())?;
        // SAFETY: both pointers are NUL-terminated strings owned by this
        // frame for the whole call, and `renamex_np` does not retain them.
        let rc = unsafe { renamex_np(from.as_ptr(), to.as_ptr(), RENAME_EXCL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod sys {
    use std::io;
    use std::path::Path;

    pub(super) fn rename_exclusive(_from: &Path, _to: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "disk-health runs on macOS",
        ))
    }
}
