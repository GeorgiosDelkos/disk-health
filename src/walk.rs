//! Filesystem reads that do not follow symlinks.
//!
//! [`RealFs`] uses `symlink_metadata` (lstat) for a single path. A symlink is
//! [`Kind::Symlink`] and is never opened. That is the difference between
//! reporting a `node_modules` link and sizing the directory it points at.
//!
//! A directory is listed with `getattrlistbulk`, which returns each child's
//! attributes in the same call. One `lstat` per file was 98% of the wall time
//! of a scan. Two things keep the bulk listing as strict as `lstat` was:
//!
//! - The directory is opened with `O_NOFOLLOW`, so a symlink swapped in after
//!   the parent was listed is an error and not a walk of its target.
//! - [`Listing::dev`] is the device of the directory that was opened. A bulk
//!   listing describes a mount point as the directory underneath it, so the
//!   walk compares this device and does not trust the child's own.
//!
//! [`MemFs`] is the in-memory double the safety tests drive. It is public
//! because those tests live outside this crate. It is not a scan root.

use std::collections::{BTreeMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::error::{Error, Result};

/// `SF_DATALESS` from the macOS SDK header `sys/stat.h`.
///
/// A dataless directory is an iCloud placeholder. Listing it can download the
/// contents, so the walk does not enter one.
pub const SF_DATALESS: u32 = 0x4000_0000;

/// `O_NOFOLLOW` from the macOS SDK header `sys/fcntl.h`.
const O_NOFOLLOW: i32 = 0x0100;
/// `O_DIRECTORY` from the macOS SDK header `sys/fcntl.h`.
const O_DIRECTORY: i32 = 0x0010_0000;

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
    /// `st_nlink` for a regular file. A listing reports 1 for everything else.
    pub nlink: u64,
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
    ///     nlink: 1,
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

/// One name in a directory, with the attributes read alongside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// File name, without the directory.
    pub name: OsString,
    /// Attributes of the name itself. `None` when they could not be read.
    pub meta: Option<EntryMeta>,
}

/// The children of one directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// Device of the directory that was opened.
    ///
    /// This is the mounted filesystem when the path is a mount point, even
    /// though the parent's listing reported the directory underneath.
    pub dev: u64,
    /// Children in the order the filesystem returned them.
    pub entries: Vec<Listed>,
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

    /// Children of a directory, each with its own attributes.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be listed, or when `path`
    /// is a symlink.
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
    /// let listing = fs.read_dir(Path::new("/cache")).unwrap();
    /// assert_eq!(listing.entries[0].name, "blob");
    /// assert_eq!(listing.entries[0].meta.unwrap().len, 4);
    /// ```
    fn read_dir(&self, path: &Path) -> Result<Listing>;

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

    /// The path with every symlink resolved and every name in its stored case.
    ///
    /// The denylist is compared against paths as text. A path that reaches a
    /// denied directory through a symlink only matches after this.
    ///
    /// # Errors
    ///
    /// Returns an error when the path does not exist or cannot be resolved.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, MemFs};
    /// use std::path::Path;
    /// use std::time::SystemTime;
    ///
    /// let fs = MemFs::new();
    /// fs.dir("/cache", 1, SystemTime::UNIX_EPOCH);
    /// assert_eq!(fs.canonical(Path::new("/cache")).unwrap(), Path::new("/cache"));
    /// ```
    fn canonical(&self, path: &Path) -> Result<PathBuf>;
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

    fn read_dir(&self, path: &Path) -> Result<Listing> {
        use std::os::darwin::fs::MetadataExt;

        let failed = |source| Error::io("read directory", path, source);
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(path)
            .map_err(failed)?;
        let dev = dir.metadata().map_err(failed)?.st_dev();

        let entries = match sys::list_bulk(&dir) {
            Ok(entries) => entries,
            // Not every filesystem implements the bulk call. `lstat` works on all of them.
            Err(source) if bulk_unsupported(&source) => list_by_stat(path).map_err(failed)?,
            Err(source) => return Err(failed(source)),
        };
        Ok(Listing { dev, entries })
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

    fn canonical(&self, path: &Path) -> Result<PathBuf> {
        std::fs::canonicalize(path).map_err(|source| Error::io("resolve", path, source))
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
        nlink: meta.st_nlink(),
        mtime: meta.modified().ok(),
        flags: meta.st_flags(),
    }
}

/// `ENOTSUP` and `EOPNOTSUPP` from the macOS SDK header `sys/errno.h`.
fn bulk_unsupported(source: &std::io::Error) -> bool {
    source.kind() == ErrorKind::Unsupported || matches!(source.raw_os_error(), Some(45 | 102))
}

/// One `lstat` per name, for a filesystem without the bulk call.
fn list_by_stat(path: &Path) -> std::io::Result<Vec<Listed>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = match std::fs::symlink_metadata(entry.path()) {
            Ok(meta) => Some(entry_from(&meta)),
            // Removed between the listing and the stat. It is not a child any more.
            Err(source) if source.kind() == ErrorKind::NotFound => continue,
            Err(_) => None,
        };
        entries.push(Listed {
            name: entry.file_name(),
            meta,
        });
    }
    Ok(entries)
}

/// Decodes `getattrlistbulk` records. The layout is in `man 2 getattrlistbulk`.
///
/// Every field is copied out with `from_ne_bytes` after a bounds check, so a
/// record this code does not understand is an error and not a wrong size.
mod bulk {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::time::{Duration, SystemTime};

    use super::{EntryMeta, Kind, Listed};

    /// `ATTR_BIT_MAP_COUNT` from `sys/attr.h`.
    pub(super) const BIT_MAP_COUNT: u16 = 5;

    const CMN_NAME: u32 = 0x0000_0001;
    const CMN_DEVID: u32 = 0x0000_0002;
    const CMN_OBJTYPE: u32 = 0x0000_0008;
    const CMN_MODTIME: u32 = 0x0000_0400;
    const CMN_FLAGS: u32 = 0x0004_0000;
    const CMN_FILEID: u32 = 0x0200_0000;
    const CMN_ERROR: u32 = 0x2000_0000;
    const CMN_RETURNED_ATTRS: u32 = 0x8000_0000;
    const FILE_LINKCOUNT: u32 = 0x0000_0001;
    const FILE_DATALENGTH: u32 = 0x0000_0200;

    /// `commonattr` bits this module asks for and knows how to skip over.
    pub(super) const COMMON: u32 = CMN_RETURNED_ATTRS
        | CMN_ERROR
        | CMN_NAME
        | CMN_DEVID
        | CMN_OBJTYPE
        | CMN_MODTIME
        | CMN_FLAGS
        | CMN_FILEID;
    /// `fileattr` bits this module asks for.
    pub(super) const FILE: u32 = FILE_LINKCOUNT | FILE_DATALENGTH;

    /// `enum vtype` from `sys/vnode.h`.
    const VREG: u32 = 1;
    const VDIR: u32 = 2;
    const VLNK: u32 = 5;

    /// Reads `count` records from the front of `buf`.
    ///
    /// `None` means a record ran past the buffer or carried an attribute
    /// that was not requested.
    pub(super) fn decode(buf: &[u8], count: usize, out: &mut Vec<Listed>) -> Option<()> {
        let mut rest = buf;
        for _ in 0..count {
            let length = usize::try_from(Cursor::new(rest).u32()?).ok()?;
            let record = rest.get(..length)?;
            rest = rest.get(length..)?;

            let listed = record_entry(record)?;
            if listed.name != "." && listed.name != ".." {
                out.push(listed);
            }
        }
        Some(())
    }

    fn record_entry(record: &[u8]) -> Option<Listed> {
        let mut cursor = Cursor::new(record);
        cursor.u32()?;
        let common = cursor.u32()?;
        // volattr and dirattr were not requested. forkattr follows fileattr.
        cursor.u32()?;
        cursor.u32()?;
        let file = cursor.u32()?;
        cursor.u32()?;
        if common & !COMMON != 0 || file & !FILE != 0 {
            return None;
        }

        let error = if common & CMN_ERROR == 0 {
            0
        } else {
            cursor.u32()?
        };
        if common & CMN_NAME == 0 {
            return None;
        }
        let name = cursor.name()?;
        if error != 0 {
            return Some(Listed { name, meta: None });
        }

        let meta = record_meta(&mut cursor, common, file);
        Some(Listed { name, meta })
    }

    /// `None` leaves the name listed and unreadable, which the walk counts.
    fn record_meta(cursor: &mut Cursor<'_>, common: u32, file: u32) -> Option<EntryMeta> {
        let required = CMN_DEVID | CMN_OBJTYPE | CMN_FLAGS | CMN_FILEID;
        if common & required != required {
            return None;
        }

        let dev = u64::from(cursor.u32()?);
        let kind = match cursor.u32()? {
            VREG => Kind::File,
            VDIR => Kind::Directory,
            VLNK => Kind::Symlink,
            _ => Kind::Other,
        };
        let mtime = if common & CMN_MODTIME == 0 {
            None
        } else {
            timespec(cursor.i64()?, cursor.i64()?)
        };
        let flags = cursor.u32()?;
        let ino = cursor.u64()?;

        let nlink = if file & FILE_LINKCOUNT == 0 {
            1
        } else {
            u64::from(cursor.u32()?)
        };
        let len = if file & FILE_DATALENGTH == 0 {
            // A regular file without a length cannot be sized.
            if kind == Kind::File {
                return None;
            }
            0
        } else {
            u64::try_from(cursor.i64()?).ok()?
        };

        Some(EntryMeta {
            kind,
            dev,
            ino,
            len,
            nlink,
            mtime,
            flags,
        })
    }

    fn timespec(seconds: i64, nanos: i64) -> Option<SystemTime> {
        let nanos = u32::try_from(nanos).ok()?;
        let seconds = u64::try_from(seconds).ok()?;
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
    }

    struct Cursor<'a> {
        record: &'a [u8],
        at: usize,
    }

    impl<'a> Cursor<'a> {
        const fn new(record: &'a [u8]) -> Self {
            Self { record, at: 0 }
        }

        fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
            let end = self.at.checked_add(N)?;
            let bytes = self.record.get(self.at..end)?.try_into().ok()?;
            self.at = end;
            Some(bytes)
        }

        fn u32(&mut self) -> Option<u32> {
            self.take().map(u32::from_ne_bytes)
        }

        fn u64(&mut self) -> Option<u64> {
            self.take().map(u64::from_ne_bytes)
        }

        fn i64(&mut self) -> Option<i64> {
            self.take().map(i64::from_ne_bytes)
        }

        /// An `attrreference_t`: a signed offset from its own first byte, and
        /// a length that counts the trailing NUL.
        fn name(&mut self) -> Option<OsString> {
            let base = self.at;
            let offset = i32::from_ne_bytes(self.take()?);
            let length = usize::try_from(self.u32()?).ok()?;

            let start = base.checked_add(usize::try_from(offset).ok()?)?;
            let end = start.checked_add(length.checked_sub(1)?)?;
            let bytes = self.record.get(start..end)?;
            Some(OsString::from_vec(bytes.to_vec()))
        }
    }
}

#[cfg(target_os = "macos")]
mod sys {
    #![allow(unsafe_code, reason = "getattrlistbulk from the system headers")]

    use std::ffi::{c_int, c_void};
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    use super::{Listed, bulk};

    /// `struct attrlist` from `sys/attr.h`.
    #[repr(C)]
    struct AttrList {
        bitmapcount: u16,
        reserved: u16,
        commonattr: u32,
        volattr: u32,
        dirattr: u32,
        fileattr: u32,
        forkattr: u32,
    }

    /// Room for a few hundred children per call.
    const BUFFER_LEN: usize = 64 * 1024;

    unsafe extern "C" {
        /// `int getattrlistbulk(int, struct attrlist *, void *, size_t, uint64_t)`
        /// from `unistd.h`.
        fn getattrlistbulk(
            dirfd: c_int,
            alist: *const AttrList,
            buf: *mut c_void,
            size: usize,
            options: u64,
        ) -> c_int;
    }

    pub(super) fn list_bulk(dir: &File) -> io::Result<Vec<Listed>> {
        let request = AttrList {
            bitmapcount: bulk::BIT_MAP_COUNT,
            reserved: 0,
            commonattr: bulk::COMMON,
            volattr: 0,
            dirattr: 0,
            fileattr: bulk::FILE,
            forkattr: 0,
        };
        let mut buf = vec![0u8; BUFFER_LEN];
        let mut entries = Vec::new();

        loop {
            // SAFETY: `dir` is an open descriptor for the whole call. `request`
            // is a live `struct attrlist`. `buf` is `BUFFER_LEN` writable bytes
            // and that is the size passed. The kernel retains neither pointer.
            let rc = unsafe {
                getattrlistbulk(
                    dir.as_raw_fd(),
                    &raw const request,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if rc == 0 {
                return Ok(entries);
            }

            let count = usize::try_from(rc).expect("a positive c_int fits in usize");
            bulk::decode(&buf, count, &mut entries).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unexpected attribute record")
            })?;
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod sys {
    use std::fs::File;
    use std::io;

    use super::Listed;

    pub(super) fn list_bulk(_dir: &File) -> io::Result<Vec<Listed>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "disk-health runs on macOS",
        ))
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
    ///     nlink: 1,
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
    ///     nlink: 1,
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
    measure_children(fs, root, root_meta, &[]).map(|(measured, _)| measured)
}

/// Measures `root` and, in the same walk, the bytes under some of its children.
///
/// The second value is the apparent size below the direct children of `root`
/// whose names are in `named`. A worktree row reports its build output this
/// way without walking that output twice.
///
/// # Errors
///
/// Returns an error when `root` itself cannot be listed.
///
/// # Examples
///
/// ```
/// use disk_health::walk::{Fs, MemFs, measure_children};
/// use std::path::Path;
/// use std::time::SystemTime;
///
/// let fs = MemFs::new();
/// let when = SystemTime::UNIX_EPOCH;
/// fs.dir("/repo", 1, when);
/// fs.file("/repo/main.rs", 1, 3, when);
/// fs.dir("/repo/target", 1, when);
/// fs.file("/repo/target/app", 1, 40, when);
/// let meta = fs.meta(Path::new("/repo")).unwrap();
/// let (whole, build) = measure_children(&fs, Path::new("/repo"), &meta, &["target"]).unwrap();
/// assert_eq!(whole.apparent_bytes, 43);
/// assert_eq!(build, 40);
/// ```
pub fn measure_children(
    fs: &dyn Fs,
    root: &Path,
    root_meta: &EntryMeta,
    named: &[&str],
) -> Result<(Measure, u64)> {
    if root_meta.kind == Kind::File {
        return Ok((Measure::leaf(root_meta.len, root_meta.mtime, 0), 0));
    }
    if root_meta.kind != Kind::Directory {
        return Ok((Measure::leaf(0, root_meta.mtime, ISSUE_PARTIAL), 0));
    }

    let mut state = MeasureState::new(root_meta);
    // Only the candidate's own listing is an error. A child that cannot be
    // listed is a partial measure: the candidate still exists, the size does not.
    let listing = fs.read_dir(root)?;
    for entry in listing.entries {
        let tallied = named.iter().any(|name| entry.name == *name);
        state.child(root, entry, tallied);
    }
    while let Some((dir, tallied)) = state.stack.pop() {
        state.enter(fs, &dir, tallied);
    }

    Ok((state.finish(), state.tally))
}

struct MeasureState {
    root_dev: u64,
    bytes: u64,
    /// Bytes below the named children. Always part of `bytes` too.
    tally: u64,
    newest: Option<SystemTime>,
    /// Hardlinked files already counted. A file with one link cannot repeat.
    seen: HashSet<(u64, u64)>,
    /// Directories still to list, and whether they sit below a named child.
    stack: Vec<(PathBuf, bool)>,
    issues: u8,
    unreadable: u64,
}

impl MeasureState {
    fn new(root_meta: &EntryMeta) -> Self {
        Self {
            root_dev: root_meta.dev,
            bytes: 0,
            tally: 0,
            newest: root_meta.mtime,
            seen: HashSet::new(),
            stack: Vec::new(),
            issues: if root_meta.mtime.is_none() {
                ISSUE_UNKNOWN_AGE
            } else {
                0
            },
            unreadable: 0,
        }
    }

    fn enter(&mut self, fs: &dyn Fs, dir: &Path, tallied: bool) {
        let listing = match fs.read_dir(dir) {
            Ok(listing) => listing,
            Err(err) if err.is_not_found() => return,
            Err(_) => {
                self.note_unreadable();
                return;
            }
        };
        // The parent's listing can describe a mount point as the directory
        // under it. The directory that was actually opened cannot.
        if listing.dev != self.root_dev {
            self.issues |= ISSUE_CROSSED;
            return;
        }

        for entry in listing.entries {
            self.child(dir, entry, tallied);
        }
    }

    fn child(&mut self, dir: &Path, entry: Listed, tallied: bool) {
        let Some(meta) = entry.meta else {
            self.note_unreadable();
            return;
        };

        self.observe_time(meta.mtime);
        if meta.kind == Kind::Symlink || meta.is_dataless() {
            return;
        }
        if meta.dev != self.root_dev {
            self.issues |= ISSUE_CROSSED;
            return;
        }

        match meta.kind {
            Kind::Directory if entry.name == OsStr::new(".git") => {
                self.issues |= ISSUE_NESTED_GIT;
            }
            Kind::Directory => self.stack.push((dir.join(entry.name), tallied)),
            Kind::File => self.count(&meta, tallied),
            Kind::Symlink | Kind::Other => {}
        }
    }

    fn count(&mut self, meta: &EntryMeta, tallied: bool) {
        if meta.nlink > 1 && !self.seen.insert((meta.dev, meta.ino)) {
            return;
        }
        self.bytes = self.bytes.saturating_add(meta.len);
        if tallied {
            self.tally = self.tally.saturating_add(meta.len);
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

    fn finish(&self) -> Measure {
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
    nlink: u64,
    mtime: Option<SystemTime>,
    flags: u32,
    locked: bool,
    /// Device a listing of this directory reports, when it is a mount point.
    mounted: Option<u64>,
}

impl Node {
    const fn meta(&self) -> EntryMeta {
        EntryMeta {
            kind: self.kind,
            dev: self.dev,
            ino: self.ino,
            len: self.len,
            nlink: self.nlink,
            mtime: self.mtime,
            flags: self.flags,
        }
    }
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

    /// Inserts a second name for the regular file at `existing`.
    ///
    /// # Panics
    ///
    /// Panics if `existing` was never inserted or is not a regular file.
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
    /// fs.hardlink("/again", Path::new("/blob"));
    /// let first = fs.meta(Path::new("/blob")).unwrap();
    /// let second = fs.meta(Path::new("/again")).unwrap();
    /// assert_eq!(first.ino, second.ino);
    /// assert_eq!(second.nlink, 2);
    /// ```
    #[track_caller]
    pub fn hardlink(&self, path: impl Into<PathBuf>, existing: &Path) {
        let mut state = self.lock();
        let linked = match state.nodes.get_mut(existing) {
            Some(node) if node.kind == Kind::File => {
                node.nlink += 1;
                Node {
                    locked: false,
                    ..*node
                }
            }
            _ => panic!("no fixture file at {}", existing.display()),
        };
        state.nodes.insert(path.into(), linked);
    }

    /// Makes an existing directory a mount point for device `dev`.
    ///
    /// Its parent's listing keeps reporting the directory's own device, the
    /// way a bulk listing describes what is under a mount. Only opening the
    /// directory shows `dev`.
    ///
    /// # Panics
    ///
    /// Panics if `path` was never inserted.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::walk::{Fs, MemFs};
    /// use std::path::Path;
    /// use std::time::SystemTime;
    ///
    /// let fs = MemFs::new();
    /// fs.dir("/cache", 1, SystemTime::UNIX_EPOCH);
    /// fs.dir("/cache/mnt", 1, SystemTime::UNIX_EPOCH);
    /// fs.mount(Path::new("/cache/mnt"), 2);
    /// let parent = fs.read_dir(Path::new("/cache")).unwrap();
    /// assert_eq!(parent.entries[0].meta.unwrap().dev, 1);
    /// assert_eq!(fs.read_dir(Path::new("/cache/mnt")).unwrap().dev, 2);
    /// ```
    #[track_caller]
    pub fn mount(&self, path: &Path, dev: u64) {
        let mut state = self.lock();
        let Some(node) = state.nodes.get_mut(path) else {
            panic!("no fixture node at {}", path.display());
        };
        node.mounted = Some(dev);
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
                nlink: 1,
                mtime: node.mtime,
                flags: node.flags,
                locked: false,
                mounted: None,
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
        state
            .nodes
            .get(path)
            .map(Node::meta)
            .ok_or_else(|| missing(path))
    }

    fn read_dir(&self, path: &Path) -> Result<Listing> {
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

        let mut entries = Vec::new();
        for (child, child_node) in &state.nodes {
            if child.parent() == Some(path)
                && let Some(name) = child.file_name()
            {
                entries.push(Listed {
                    name: name.to_os_string(),
                    meta: Some(child_node.meta()),
                });
            }
        }
        Ok(Listing {
            dev: node.mounted.unwrap_or(node.dev),
            entries,
        })
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

    fn canonical(&self, path: &Path) -> Result<PathBuf> {
        // No node stores a symlink target, so there is nothing to resolve.
        if self.lock().nodes.contains_key(path) {
            Ok(path.to_path_buf())
        } else {
            Err(missing(path))
        }
    }
}

fn missing(path: &Path) -> Error {
    Error::io(
        "stat",
        path,
        std::io::Error::new(ErrorKind::NotFound, "no such path"),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("disk-health-walk-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(fs::canonicalize(&path).unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Every field the walk reads must be what `lstat` says. Age gates and
    /// the identity check at apply compare these values.
    fn assert_listing_matches_lstat(dir: &Path) {
        let listing = RealFs.read_dir(dir).unwrap();
        let mut names = Vec::new();
        for entry in &listing.entries {
            let path = dir.join(&entry.name);
            let Ok(expected) = RealFs.meta(&path) else {
                continue;
            };
            let mut listed = entry.meta.unwrap_or_else(|| panic!("{}", path.display()));
            // A listing only reports sizes and link counts for regular files.
            if expected.kind != Kind::File {
                listed.len = expected.len;
                listed.nlink = expected.nlink;
            }
            assert_eq!(listed, expected, "{}", path.display());
            names.push(entry.name.clone());
        }

        let mut expected = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        expected.sort();
        assert_eq!(names, expected, "{}", dir.display());
    }

    #[test]
    fn bulk_listing_agrees_with_lstat() {
        let scratch = Scratch::new("bulk");
        let dir = &scratch.0;
        fs::write(dir.join("empty"), b"").unwrap();
        fs::write(dir.join("blob"), vec![7u8; 70_000]).unwrap();
        fs::write(dir.join("na\u{ef}ve \u{1f980}.txt"), b"unicode").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        fs::hard_link(dir.join("blob"), dir.join("blob-again")).unwrap();
        symlink(dir.join("sub"), dir.join("to-sub")).unwrap();
        symlink("/nowhere", dir.join("dangling")).unwrap();
        assert_listing_matches_lstat(dir);

        // More names than one buffer holds, so the call loops.
        let many = dir.join("many");
        fs::create_dir(&many).unwrap();
        for index in 0..3_000 {
            fs::write(
                many.join(format!("file-with-a-longer-name-{index:05}")),
                b"x",
            )
            .unwrap();
        }
        assert_eq!(RealFs.read_dir(&many).unwrap().entries.len(), 3_000);
        assert_listing_matches_lstat(&many);
    }

    #[test]
    fn bulk_listing_agrees_with_lstat_on_system_directories() {
        // `/usr/bin` holds transparently compressed files, whose stored
        // length is not their size.
        for dir in ["/usr/bin", "/private/etc", env!("CARGO_MANIFEST_DIR")] {
            assert_listing_matches_lstat(Path::new(dir));
        }
    }

    #[test]
    fn listing_does_not_open_a_symlink_to_a_directory() {
        let scratch = Scratch::new("nofollow");
        let precious = scratch.0.join("precious");
        fs::create_dir(&precious).unwrap();
        fs::write(precious.join("secret"), b"keep").unwrap();
        symlink(&precious, scratch.0.join("link")).unwrap();

        assert!(RealFs.read_dir(&scratch.0.join("link")).is_err());
        assert_eq!(RealFs.read_dir(&precious).unwrap().entries.len(), 1);
    }

    #[test]
    fn canonical_resolves_symlinks_and_stored_case() {
        let scratch = Scratch::new("canonical");
        let real = scratch.0.join("Real");
        fs::create_dir(&real).unwrap();
        symlink(&real, scratch.0.join("alias")).unwrap();
        assert_eq!(RealFs.canonical(&scratch.0.join("alias")).unwrap(), real);

        // Only a case-insensitive volume resolves this spelling at all.
        let shouted = scratch.0.join("REAL");
        if shouted.exists() {
            assert_eq!(RealFs.canonical(&shouted).unwrap(), real);
        }
    }

    #[test]
    fn hardlinked_file_is_counted_once_and_single_links_are_not_tracked() {
        let fs = MemFs::new();
        let when = SystemTime::UNIX_EPOCH;
        fs.dir("/cache", 1, when);
        fs.file("/cache/a", 1, 100, when);
        fs.hardlink("/cache/b", Path::new("/cache/a"));
        fs.file("/cache/c", 1, 5, when);

        let meta = fs.meta(Path::new("/cache")).unwrap();
        let measured = measure(&fs, Path::new("/cache"), &meta).unwrap();
        assert_eq!(measured.apparent_bytes, 105);
    }

    #[test]
    fn truncated_or_unrequested_record_is_an_error() {
        let mut out = Vec::new();
        // Claims 64 bytes and has 8.
        let short = [64u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(bulk::decode(&short, 1, &mut out).is_none());

        // 24 bytes: length, then a returned set with a bit nobody asked for.
        let mut record = [0u8; 24];
        record[..4].copy_from_slice(&24u32.to_ne_bytes());
        record[4..8].copy_from_slice(&0x0000_0004u32.to_ne_bytes());
        assert!(bulk::decode(&record, 1, &mut out).is_none());
        assert_eq!(out, []);
    }
}
