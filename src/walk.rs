//! Filesystem reads that do not follow symlinks.
//!
//! [`RealFs`] uses `symlink_metadata` (lstat). A symlink is [`Kind::Symlink`]
//! and is never opened. That is the difference between reporting a
//! `node_modules` link and sizing the directory it points at.
//!
//! [`MemFs`] is the in-memory double the safety tests drive. It is public
//! because those tests live outside this crate. It is not a scan root.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::fs::TryLockError;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::error::{Error, Result};

/// `SF_DATALESS` from the macOS SDK header `sys/stat.h`.
///
/// A dataless directory is an iCloud placeholder. Listing it can download the
/// contents, so the walk does not enter one.
pub const SF_DATALESS: u32 = 0x4000_0000;

/// What `lstat` reported. Sockets and devices are [`Kind::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A directory.
    Directory,
    /// A regular file.
    File,
    /// A symlink. The target is not resolved.
    Symlink,
    /// Anything else `lstat` can return.
    Other,
}

/// `lstat` fields the walk actually uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryMeta {
    /// File type, from `lstat` so a symlink is not a directory.
    pub kind: Kind,
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
    /// `st_size` for a regular file. Directory sizes are not added up.
    pub len: u64,
    /// `mtime`. `None` when the system did not provide one.
    pub mtime: Option<SystemTime>,
    /// `st_flags`, including [`SF_DATALESS`].
    pub flags: u32,
}

impl EntryMeta {
    /// Reports whether this entry is an iCloud placeholder.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{EntryMeta, Kind, SF_DATALESS};
    /// use std::time::SystemTime;
    ///
    /// let meta = EntryMeta {
    ///     kind: Kind::Directory,
    ///     dev: 1,
    ///     ino: 1,
    ///     len: 0,
    ///     mtime: Some(SystemTime::UNIX_EPOCH),
    ///     flags: SF_DATALESS,
    /// };
    /// assert!(meta.is_dataless());
    /// ```
    #[must_use]
    pub const fn is_dataless(self) -> bool {
        self.flags & SF_DATALESS != 0
    }
}

/// Result of a non-blocking exclusive lock probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockProbe {
    /// No conflicting lock was held.
    Free,
    /// A shared or exclusive lock is already held.
    Held,
}

/// Read-only filesystem view. Implementations must not follow symlinks.
pub trait Fs: Sync {
    /// `lstat` of `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be stated, including when it is missing.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, Kind, MemFs};
    /// use std::path::Path;
    /// use std::time::{Duration, SystemTime};
    ///
    /// let fs = MemFs::new();
    /// let when = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    /// fs.symlink("/link", when);
    /// assert_eq!(fs.meta(Path::new("/link")).unwrap().kind, Kind::Symlink);
    /// ```
    fn meta(&self, path: &Path) -> Result<EntryMeta>;

    /// Names in a directory. Each name is stated separately with [`Fs::meta`].
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be listed.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, MemFs};
    /// use std::path::Path;
    /// use std::time::{Duration, SystemTime};
    ///
    /// let fs = MemFs::new();
    /// let when = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    /// fs.dir("/cache", 1, when);
    /// fs.file("/cache/blob", 1, 4, when);
    /// let names = fs.read_dir(Path::new("/cache")).unwrap();
    /// assert_eq!(names, [std::ffi::OsString::from("blob")]);
    /// ```
    fn read_dir(&self, path: &Path) -> Result<Vec<std::ffi::OsString>>;

    /// Tries an exclusive non-blocking lock and releases it.
    ///
    /// `flock` is per process on macOS, so this sees other processes, which is
    /// what a running `cargo` or agent is. It does not see a lock held by this
    /// same process.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be opened or the lock call fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, LockProbe, MemFs};
    /// use std::path::Path;
    /// use std::time::{Duration, SystemTime};
    ///
    /// let fs = MemFs::new();
    /// let when = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    /// fs.dir("/cache", 1, when);
    /// fs.lock_path(Path::new("/cache"));
    /// assert_eq!(fs.probe_lock(Path::new("/cache")).unwrap(), LockProbe::Held);
    /// ```
    fn probe_lock(&self, path: &Path) -> Result<LockProbe>;
}

/// The process filesystem.
#[derive(Debug, Default)]
pub struct RealFs;

impl Fs for RealFs {
    fn meta(&self, path: &Path) -> Result<EntryMeta> {
        // `symlink_metadata` is the whole safety property. `metadata` would
        // follow a `node_modules` symlink into the directory it points at.
        let meta =
            std::fs::symlink_metadata(path).map_err(|source| Error::io("stat", path, source))?;
        Ok(entry_from(&meta))
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<std::ffi::OsString>> {
        let entries =
            std::fs::read_dir(path).map_err(|source| Error::io("read directory", path, source))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| Error::io("read directory", path, source))?;
            names.push(entry.file_name());
        }
        Ok(names)
    }

    fn probe_lock(&self, path: &Path) -> Result<LockProbe> {
        let file =
            File::open(path).map_err(|source| Error::io("open for lock probe", path, source))?;
        match file.try_lock() {
            Ok(()) => {
                // Drop releases the flock if unlock itself fails. Still report
                // that failure: a probe that cannot let go is not a clean "free".
                file.unlock()
                    .map_err(|source| Error::io("unlock", path, source))?;
                Ok(LockProbe::Free)
            }
            Err(TryLockError::WouldBlock) => Ok(LockProbe::Held),
            Err(TryLockError::Error(source)) => Err(Error::io("lock probe", path, source)),
        }
    }
}

fn entry_from(meta: &std::fs::Metadata) -> EntryMeta {
    use std::os::darwin::fs::MetadataExt;

    let kind = if meta.file_type().is_symlink() {
        Kind::Symlink
    } else if meta.is_dir() {
        Kind::Directory
    } else if meta.is_file() {
        Kind::File
    } else {
        Kind::Other
    };
    EntryMeta {
        kind,
        dev: meta.st_dev(),
        ino: meta.st_ino(),
        len: meta.len(),
        mtime: meta.modified().ok(),
        flags: meta.st_flags(),
    }
}

const ISSUE_NESTED_GIT: u8 = 1;
const ISSUE_CROSSED: u8 = 2;
const ISSUE_PARTIAL: u8 = 4;
const ISSUE_UNKNOWN_AGE: u8 = 8;

/// Apparent size of one candidate, without crossing a symlink or a device.
///
/// The problem bits are a mask rather than four booleans so a new problem
/// does not turn the struct into a pile of flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measure {
    /// Sum of regular-file lengths. Each `(dev, ino)` is counted once.
    pub apparent_bytes: u64,
    /// Newest mtime seen, including the candidate itself.
    pub newest: Option<SystemTime>,
    issues: u8,
    /// How many children could not be read.
    pub unreadable: u64,
}

impl Measure {
    /// A `.git` directory (a nested checkout) was found inside.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, MemFs, measure};
    /// use std::path::Path;
    /// use std::time::{Duration, SystemTime};
    ///
    /// let fs = MemFs::new();
    /// let when = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    /// fs.dir("/cache", 1, when);
    /// fs.dir("/cache/.git", 1, when);
    /// let meta = fs.meta(Path::new("/cache")).unwrap();
    /// let measured = measure(&fs, Path::new("/cache"), &meta).unwrap();
    /// assert!(measured.nested_git());
    /// ```
    #[must_use]
    pub const fn nested_git(self) -> bool {
        self.issues & ISSUE_NESTED_GIT != 0
    }

    /// A child was on a different device and was not entered.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, MemFs, measure};
    /// use std::path::Path;
    /// use std::time::{Duration, SystemTime};
    ///
    /// let fs = MemFs::new();
    /// let when = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
    /// fs.dir("/cache", 1, when);
    /// fs.file("/cache/keep", 1, 4, when);
    /// fs.dir("/cache/mnt", 2, when);
    /// fs.file("/cache/mnt/other", 2, 100, when);
    /// let meta = fs.meta(Path::new("/cache")).unwrap();
    /// let measured = measure(&fs, Path::new("/cache"), &meta).unwrap();
    /// assert!(measured.crossed_device());
    /// assert_eq!(measured.apparent_bytes, 4);
    /// ```
    #[must_use]
    pub const fn crossed_device(self) -> bool {
        self.issues & ISSUE_CROSSED != 0
    }

    /// At least one child could not be stated or listed.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{EntryMeta, Kind, MemFs, measure};
    /// use std::path::Path;
    ///
    /// let meta = EntryMeta {
    ///     kind: Kind::Other,
    ///     dev: 1,
    ///     ino: 1,
    ///     len: 0,
    ///     mtime: None,
    ///     flags: 0,
    /// };
    /// let measured = measure(&MemFs::new(), Path::new("/socket"), &meta).unwrap();
    /// assert!(measured.partial());
    /// ```
    #[must_use]
    pub const fn partial(self) -> bool {
        self.issues & ISSUE_PARTIAL != 0
    }

    /// At least one entry had no mtime.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{EntryMeta, Kind, MemFs, measure};
    /// use std::path::Path;
    ///
    /// let meta = EntryMeta {
    ///     kind: Kind::File,
    ///     dev: 1,
    ///     ino: 1,
    ///     len: 3,
    ///     mtime: None,
    ///     flags: 0,
    /// };
    /// let measured = measure(&MemFs::new(), Path::new("/blob"), &meta).unwrap();
    /// assert!(measured.unknown_age());
    /// ```
    #[must_use]
    pub const fn unknown_age(self) -> bool {
        self.issues & ISSUE_UNKNOWN_AGE != 0
    }

    const fn leaf(len: u64, mtime: Option<SystemTime>, extra: u8) -> Self {
        let mut issues = extra;
        if mtime.is_none() {
            issues |= ISSUE_UNKNOWN_AGE;
        }
        Self {
            apparent_bytes: len,
            newest: mtime,
            issues,
            unreadable: 0,
        }
    }

    /// A measure with no walk problems. A missing `newest` is unknown age.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn known(apparent_bytes: u64, newest: Option<SystemTime>) -> Self {
        Self::leaf(apparent_bytes, newest, 0)
    }
}

/// Measures `root` without following symlinks or entering another device.
///
/// # Errors
///
/// Returns an error when `root` itself cannot be listed. A child that cannot
/// be read sets [`Measure::partial`] and the walk continues.
///
/// # Examples
///
/// ```
/// use disk_health::walk::{Fs, MemFs, measure};
/// use std::path::Path;
/// use std::time::{Duration, SystemTime};
///
/// let fs = MemFs::new();
/// let when = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
/// fs.dir("/cache", 1, when);
/// fs.file("/cache/blob", 1, 4, when);
/// let meta = fs.meta(Path::new("/cache")).unwrap();
/// let measured = measure(&fs, Path::new("/cache"), &meta).unwrap();
/// assert_eq!(measured.apparent_bytes, 4);
/// ```
pub fn measure(fs: &dyn Fs, root: &Path, root_meta: &EntryMeta) -> Result<Measure> {
    if root_meta.kind == Kind::File {
        return Ok(Measure::leaf(root_meta.len, root_meta.mtime, 0));
    }
    if root_meta.kind != Kind::Directory {
        return Ok(Measure::leaf(0, root_meta.mtime, ISSUE_PARTIAL));
    }

    let mut state = MeasureState::new(root_meta);
    let mut stack = Vec::new();

    // Only the candidate's own listing is an error. A child that cannot be
    // listed is a partial measure: the candidate still exists, the size does not.
    for name in fs.read_dir(root)? {
        state.child(fs, &root.join(name), root_meta, &mut stack);
    }
    while let Some(dir) = stack.pop() {
        state.enter(fs, &dir, root_meta, &mut stack);
    }

    Ok(state.finish())
}

struct MeasureState {
    bytes: u64,
    newest: Option<SystemTime>,
    seen: HashSet<(u64, u64)>,
    issues: u8,
    unreadable: u64,
}

impl MeasureState {
    fn new(root_meta: &EntryMeta) -> Self {
        let mut seen = HashSet::new();
        seen.insert((root_meta.dev, root_meta.ino));
        Self {
            bytes: 0,
            newest: root_meta.mtime,
            seen,
            issues: if root_meta.mtime.is_none() {
                ISSUE_UNKNOWN_AGE
            } else {
                0
            },
            unreadable: 0,
        }
    }

    fn enter(&mut self, fs: &dyn Fs, dir: &Path, root_meta: &EntryMeta, stack: &mut Vec<PathBuf>) {
        let names = match fs.read_dir(dir) {
            Ok(names) => names,
            Err(err) if err.is_not_found() => return,
            Err(_) => {
                self.note_unreadable();
                return;
            }
        };

        for name in names {
            self.child(fs, &dir.join(name), root_meta, stack);
        }
    }

    fn child(&mut self, fs: &dyn Fs, path: &Path, root_meta: &EntryMeta, stack: &mut Vec<PathBuf>) {
        let meta = match fs.meta(path) {
            Ok(meta) => meta,
            Err(err) if err.is_not_found() => return,
            Err(_) => {
                self.note_unreadable();
                return;
            }
        };

        self.observe_time(meta.mtime);
        if meta.kind == Kind::Symlink || meta.is_dataless() {
            return;
        }
        if meta.dev != root_meta.dev {
            self.issues |= ISSUE_CROSSED;
            return;
        }
        if !self.seen.insert((meta.dev, meta.ino)) {
            return;
        }

        match meta.kind {
            Kind::Directory if path.file_name().is_some_and(|name| name == ".git") => {
                self.issues |= ISSUE_NESTED_GIT;
            }
            Kind::Directory => stack.push(path.to_path_buf()),
            Kind::File => self.bytes = self.bytes.saturating_add(meta.len),
            Kind::Symlink | Kind::Other => {}
        }
    }

    fn observe_time(&mut self, mtime: Option<SystemTime>) {
        if mtime.is_none() {
            self.issues |= ISSUE_UNKNOWN_AGE;
        }

        self.newest = later(self.newest, mtime);
    }

    fn note_unreadable(&mut self) {
        self.issues |= ISSUE_PARTIAL;
        self.unreadable = self.unreadable.saturating_add(1);
    }

    fn finish(self) -> Measure {
        Measure {
            apparent_bytes: self.bytes,
            newest: self.newest,
            issues: self.issues,
            unreadable: self.unreadable,
        }
    }
}

fn later(left: Option<SystemTime>, right: Option<SystemTime>) -> Option<SystemTime> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[derive(Clone, Copy)]
struct NodeSeed {
    kind: Kind,
    dev: u64,
    len: u64,
    mtime: Option<SystemTime>,
    flags: u32,
}

#[derive(Debug)]
struct Node {
    kind: Kind,
    dev: u64,
    ino: u64,
    len: u64,
    mtime: Option<SystemTime>,
    flags: u32,
    locked: bool,
}

#[derive(Debug, Default)]
struct MemState {
    nodes: BTreeMap<PathBuf, Node>,
    next_ino: u64,
}

/// In-memory filesystem for safety tests.
///
/// Paths are stored as given. The scan never asks this type to resolve a symlink.
#[derive(Debug, Default)]
pub struct MemFs {
    state: Mutex<MemState>,
}

impl MemFs {
    /// Empty filesystem.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::MemFs;
    ///
    /// let fs = MemFs::new();
    /// assert!(fs.kind(std::path::Path::new("/missing")).is_none());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Kind, MemFs};
    /// use std::path::Path;
    /// use std::time::SystemTime;
    ///
    /// let fs = MemFs::new();
    /// fs.dir("/cache", 1, SystemTime::UNIX_EPOCH);
    /// assert_eq!(fs.kind(Path::new("/cache")), Some(Kind::Directory));
    /// ```
    pub fn dir(&self, path: impl Into<PathBuf>, dev: u64, mtime: SystemTime) {
        self.insert(
            path.into(),
            NodeSeed {
                kind: Kind::Directory,
                dev,
                len: 0,
                mtime: Some(mtime),
                flags: 0,
            },
        );
    }

    /// Inserts a regular file.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, MemFs};
    /// use std::path::Path;
    /// use std::time::SystemTime;
    ///
    /// let fs = MemFs::new();
    /// fs.file("/blob", 1, 4, SystemTime::UNIX_EPOCH);
    /// assert_eq!(fs.meta(Path::new("/blob")).unwrap().len, 4);
    /// ```
    pub fn file(&self, path: impl Into<PathBuf>, dev: u64, len: u64, mtime: SystemTime) {
        self.insert(
            path.into(),
            NodeSeed {
                kind: Kind::File,
                dev,
                len,
                mtime: Some(mtime),
                flags: 0,
            },
        );
    }

    /// Inserts a symlink. The target is not stored, because nothing may follow it.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Kind, MemFs};
    /// use std::path::Path;
    /// use std::time::SystemTime;
    ///
    /// let fs = MemFs::new();
    /// fs.symlink("/link", SystemTime::UNIX_EPOCH);
    /// assert_eq!(fs.kind(Path::new("/link")), Some(Kind::Symlink));
    /// ```
    pub fn symlink(&self, path: impl Into<PathBuf>, mtime: SystemTime) {
        self.insert(
            path.into(),
            NodeSeed {
                kind: Kind::Symlink,
                dev: 1,
                len: 0,
                mtime: Some(mtime),
                flags: 0,
            },
        );
    }

    /// Sets `st_flags` on an existing path.
    ///
    /// # Panics
    ///
    /// Panics if `path` was never inserted. A missing fixture must not look
    /// like a node without the dataless flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, MemFs, SF_DATALESS};
    /// use std::path::Path;
    /// use std::time::SystemTime;
    ///
    /// let fs = MemFs::new();
    /// fs.dir("/cloud", 1, SystemTime::UNIX_EPOCH);
    /// fs.set_flags(Path::new("/cloud"), SF_DATALESS);
    /// assert!(fs.meta(Path::new("/cloud")).unwrap().is_dataless());
    /// ```
    #[track_caller]
    pub fn set_flags(&self, path: &Path, flags: u32) {
        let mut state = self.lock();
        let Some(node) = state.nodes.get_mut(path) else {
            panic!("no fixture node at {}", path.display());
        };
        node.flags = flags;
    }

    /// Makes [`Fs::probe_lock`] report [`LockProbe::Held`].
    ///
    /// # Panics
    ///
    /// Panics if `path` was never inserted. A missing fixture must not look unlocked.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, LockProbe, MemFs};
    /// use std::path::Path;
    /// use std::time::SystemTime;
    ///
    /// let fs = MemFs::new();
    /// fs.dir("/cache", 1, SystemTime::UNIX_EPOCH);
    /// fs.lock_path(Path::new("/cache"));
    /// assert_eq!(
    ///     fs.probe_lock(Path::new("/cache")).unwrap(),
    ///     LockProbe::Held
    /// );
    /// ```
    #[track_caller]
    pub fn lock_path(&self, path: &Path) {
        let mut state = self.lock();
        let Some(node) = state.nodes.get_mut(path) else {
            panic!("no fixture node at {}", path.display());
        };
        node.locked = true;
    }

    /// `lstat` kind, for assertions.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Kind, MemFs};
    /// use std::path::Path;
    /// use std::time::SystemTime;
    ///
    /// let fs = MemFs::new();
    /// fs.dir("/cache", 1, SystemTime::UNIX_EPOCH);
    /// assert_eq!(fs.kind(Path::new("/cache")), Some(Kind::Directory));
    /// ```
    #[must_use]
    pub fn kind(&self, path: &Path) -> Option<Kind> {
        self.lock().nodes.get(path).map(|node| node.kind)
    }

    fn insert(&self, path: PathBuf, node: NodeSeed) {
        let mut state = self.lock();
        state.next_ino = state.next_ino.saturating_add(1);
        let ino = state.next_ino;
        state.nodes.insert(
            path,
            Node {
                kind: node.kind,
                dev: node.dev,
                ino,
                len: node.len,
                mtime: node.mtime,
                flags: node.flags,
                locked: false,
            },
        );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Fs for MemFs {
    fn meta(&self, path: &Path) -> Result<EntryMeta> {
        let state = self.lock();
        let Some(node) = state.nodes.get(path) else {
            return Err(missing(path));
        };
        Ok(EntryMeta {
            kind: node.kind,
            dev: node.dev,
            ino: node.ino,
            len: node.len,
            mtime: node.mtime,
            flags: node.flags,
        })
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<std::ffi::OsString>> {
        let state = self.lock();
        let Some(node) = state.nodes.get(path) else {
            return Err(missing(path));
        };
        if node.kind != Kind::Directory {
            return Err(Error::io(
                "read directory",
                path,
                std::io::Error::new(ErrorKind::InvalidInput, "not a directory"),
            ));
        }
        let mut names = Vec::new();
        for child in state.nodes.keys() {
            if child.parent() == Some(path)
                && let Some(name) = child.file_name()
            {
                names.push(name.to_os_string());
            }
        }
        Ok(names)
    }

    fn probe_lock(&self, path: &Path) -> Result<LockProbe> {
        let state = self.lock();
        let Some(node) = state.nodes.get(path) else {
            return Err(missing(path));
        };
        Ok(if node.locked {
            LockProbe::Held
        } else {
            LockProbe::Free
        })
    }
}

fn missing(path: &Path) -> Error {
    Error::io(
        "stat",
        path,
        std::io::Error::new(ErrorKind::NotFound, "no such path"),
    )
}
