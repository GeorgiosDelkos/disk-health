//! Local volumes from `getmntinfo_r_np`.
//!
//! The bytes are `struct statfs` as laid out by the macOS SDK
//! (`__DARWIN_STRUCT_STATFS64` in `sys/mount.h`). On this machine that
//! struct is 2168 bytes. Values are copied out of the buffer with
//! `from_ne_bytes`, so a padding mistake cannot move `f_bavail` by a
//! field width without failing the fixture test.
//!
//! Classification is pure. The unsafe call only fills the buffer.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// `MNT_LOCAL` from `sys/mount.h`.
const MNT_LOCAL: u32 = 0x1000;
/// `MNT_DONTBROWSE` from `sys/mount.h`.
const MNT_DONTBROWSE: u32 = 0x0010_0000;
/// `MNT_AUTOMOUNTED` from `sys/mount.h`.
const MNT_AUTOMOUNTED: u32 = 0x0040_0000;

const STATFS_SIZE: usize = 2168;
const OFF_BSIZE: usize = 0;
const OFF_BLOCKS: usize = 8;
const OFF_BFREE: usize = 16;
const OFF_BAVAIL: usize = 24;
const OFF_FLAGS: usize = 64;
const OFF_FSTYPE: usize = 72;
const FSTYPE_LEN: usize = 16;
const OFF_MOUNT: usize = 88;
const MOUNT_LEN: usize = 1024;

/// One mount, after the walkable / not-walkable decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    /// Mount point.
    pub mount: PathBuf,
    /// `f_fstypename`, for example `apfs`.
    pub fstype: String,
    /// `f_blocks * f_bsize`.
    pub total_bytes: u64,
    /// `(f_blocks - f_bfree) * f_bsize`.
    pub used_bytes: u64,
    /// `f_bavail * f_bsize`. On the Data volume this excludes purgeable snapshots.
    pub available_bytes: u64,
    /// Whether a usage walk may start here.
    pub walkable: bool,
    /// Why it is dimmed, or the Data-volume purgeable note.
    pub note: Option<&'static str>,
}

/// Fields read from one `statfs` record. Flags stay numeric so tests can set them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRaw {
    /// Mount point.
    pub mount: String,
    /// Filesystem type name.
    pub fstype: String,
    /// `f_flags`.
    pub flags: u32,
    /// `f_bsize` widened to a byte count.
    pub bsize: u64,
    /// `f_blocks`.
    pub blocks: u64,
    /// `f_bfree`.
    pub bfree: u64,
    /// `f_bavail`.
    pub bavail: u64,
}

/// Reads one measured `statfs` record.
///
/// # Errors
///
/// Returns an error when `record` is shorter than the measured struct.
///
/// # Examples
///
/// ```
/// use disk_health::volumes::{STATFS_LEN, parse_statfs};
///
/// let mut record = vec![0; STATFS_LEN];
/// record[8..16].copy_from_slice(&10u64.to_ne_bytes());
/// assert_eq!(parse_statfs(&record).unwrap().blocks, 10);
/// ```
pub fn parse_statfs(record: &[u8]) -> Result<MountRaw> {
    if record.len() < STATFS_SIZE {
        return Err(Error::io(
            "parse mount table",
            "/",
            std::io::Error::new(std::io::ErrorKind::InvalidData, "short statfs record"),
        ));
    }
    Ok(MountRaw {
        bsize: u64::from(read_u32(record, OFF_BSIZE)),
        blocks: read_u64(record, OFF_BLOCKS),
        bfree: read_u64(record, OFF_BFREE),
        bavail: read_u64(record, OFF_BAVAIL),
        flags: read_u32(record, OFF_FLAGS),
        fstype: c_string(record, OFF_FSTYPE, FSTYPE_LEN),
        mount: c_string(record, OFF_MOUNT, MOUNT_LEN),
    })
}

/// Decides whether a volume may be walked.
///
/// Remote, automounted, `devfs`, `autofs`, and nobrowse mounts are listed
/// and are not walkable. `/System` and the VM volume are not walkable even
/// when the flags say they are local.
///
/// # Examples
///
/// ```
/// use disk_health::volumes::{MountRaw, describe};
///
/// let volume = describe(&MountRaw {
///     mount: "/Volumes/Source".to_owned(),
///     fstype: "apfs".to_owned(),
///     flags: 0x1000,
///     bsize: 4096,
///     blocks: 10,
///     bfree: 4,
///     bavail: 3,
/// });
/// assert!(volume.walkable);
/// assert_eq!(volume.total_bytes, 40_960);
/// ```
#[must_use]
pub fn describe(raw: &MountRaw) -> Volume {
    let total_bytes = raw.blocks.saturating_mul(raw.bsize);
    let used_blocks = raw.blocks.saturating_sub(raw.bfree);
    let used_bytes = used_blocks.saturating_mul(raw.bsize);
    let available_bytes = raw.bavail.saturating_mul(raw.bsize);
    let (walkable, note) = classify(&raw.mount, &raw.fstype, raw.flags);
    Volume {
        mount: PathBuf::from(&raw.mount),
        fstype: raw.fstype.clone(),
        total_bytes,
        used_bytes,
        available_bytes,
        walkable,
        note,
    }
}

/// Lists mounts. On macOS this calls `getmntinfo_r_np`.
///
/// # Errors
///
/// Returns an error when the system call fails or a record is short.
///
/// # Examples
///
/// ```
/// use disk_health::volumes::list_mounts;
///
/// let mounts = list_mounts().unwrap();
/// assert!(mounts.iter().any(|volume| volume.mount == std::path::Path::new("/")));
/// ```
pub fn list_mounts() -> Result<Vec<Volume>> {
    #[cfg(target_os = "macos")]
    {
        sys::list()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(Error::Usage {
            message: "disk-health runs on macOS".to_owned(),
        })
    }
}

/// Process uid, for `/.Trashes/<uid>` on a volume that is not the home volume.
///
/// # Examples
///
/// ```
/// use disk_health::volumes::current_uid;
///
/// let _uid = current_uid();
/// ```
#[must_use]
pub fn current_uid() -> u32 {
    #[cfg(target_os = "macos")]
    {
        sys::uid()
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

/// Reports whether this process is the operating system the tool supports.
///
/// # Examples
///
/// ```
/// use disk_health::platform_supported;
///
/// assert!(platform_supported());
/// ```
#[must_use]
pub const fn supported_here() -> bool {
    cfg!(target_os = "macos")
}

/// Length of one `statfs` record. Public so the fixture test can size a buffer.
pub const STATFS_LEN: usize = STATFS_SIZE;

/// Longest walkable mount that is a prefix of `home`, excluding `/`.
///
/// `/` is a prefix of every absolute path. Using it as the usage root would
/// walk the whole machine. When home is not under a more specific walkable
/// mount, the caller passes `--volume`.
///
/// # Examples
///
/// ```
/// use disk_health::volumes::{Volume, home_volume};
/// use std::path::Path;
///
/// let volumes = vec![volume("/", true), volume("/Users", true)];
/// let found = home_volume(Path::new("/Users/ada"), &volumes);
/// assert_eq!(found.map(|item| item.mount.clone()).as_deref(), Some(Path::new("/Users")));
///
/// fn volume(mount: &str, walkable: bool) -> Volume {
///     Volume {
///         mount: std::path::PathBuf::from(mount),
///         fstype: "apfs".to_owned(),
///         total_bytes: 1,
///         used_bytes: 1,
///         available_bytes: 1,
///         walkable,
///         note: None,
///     }
/// }
/// ```
#[must_use]
pub fn home_volume<'a>(home: &Path, volumes: &'a [Volume]) -> Option<&'a Volume> {
    volumes
        .iter()
        .filter(|volume| volume.walkable)
        .filter(|volume| volume.mount != Path::new("/"))
        .filter(|volume| home.starts_with(&volume.mount))
        .max_by_key(|volume| volume.mount.components().count())
}

fn classify(mount: &str, fstype: &str, flags: u32) -> (bool, Option<&'static str>) {
    if let Some(note) = refused_mount(mount) {
        return (false, Some(note));
    }
    if fstype == "devfs" || fstype == "autofs" {
        return (false, Some("filesystem is not walked"));
    }
    if flags & MNT_LOCAL == 0 {
        return (false, Some("remote filesystem"));
    }
    if flags & MNT_AUTOMOUNTED != 0 {
        return (false, Some("automounted"));
    }
    if flags & MNT_DONTBROWSE != 0 {
        return (false, Some("nobrowse"));
    }
    if mount == "/System/Volumes/Data" {
        return (true, Some("available excludes purgeable snapshots"));
    }
    (true, None)
}

fn refused_mount(mount: &str) -> Option<&'static str> {
    // Data is the writable volume a person can walk. Everything else under
    // /System is sealed, preboot, or VM.
    if mount == "/private/var/vm" || mount == "/System/Volumes/VM" {
        return Some("system or vm volume");
    }
    if mount == "/System" || (mount.starts_with("/System/") && mount != "/System/Volumes/Data") {
        return Some("system or vm volume");
    }
    None
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    let bytes = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    u32::from_ne_bytes(bytes)
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_ne_bytes(bytes)
}

fn c_string(buf: &[u8], offset: usize, len: usize) -> String {
    let slice = &buf[offset..offset + len];
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

#[cfg(target_os = "macos")]
mod sys {
    #![allow(unsafe_code, reason = "getmntinfo and getuid from the system headers")]

    use std::ffi::{c_int, c_void};

    use super::{STATFS_SIZE, Volume, describe, parse_statfs};
    use crate::error::{Error, Result};

    const MNT_NOWAIT: c_int = 2;

    unsafe extern "C" {
        /// `int getmntinfo_r_np(struct statfs **mntbufp, int flags)` from `sys/mount.h`.
        /// The caller frees the buffer.
        fn getmntinfo_r_np(mntbufp: *mut *mut u8, flags: c_int) -> c_int;
        /// `void free(void *)` from `stdlib.h`.
        fn free(ptr: *mut c_void);
        /// `uid_t getuid(void)` from `unistd.h`.
        fn getuid() -> u32;
    }

    pub(super) fn uid() -> u32 {
        // SAFETY: getuid reads the process credential. It takes no pointer.
        unsafe { getuid() }
    }

    pub(super) fn list() -> Result<Vec<Volume>> {
        let mut buf: *mut u8 = std::ptr::null_mut();
        // SAFETY: on success the call mallocs an array of `count` statfs
        // records and writes the pointer to `buf`. `Free` releases that
        // pointer, including when parsing a record returns early.
        let count = unsafe { getmntinfo_r_np(&raw mut buf, MNT_NOWAIT) };
        let _guard = Free(buf);
        if count < 0 {
            return Err(Error::io(
                "list mounts",
                "/",
                std::io::Error::last_os_error(),
            ));
        }
        let count = usize::try_from(count).expect("mount count is non-negative");
        if count == 0 || buf.is_null() {
            return Ok(Vec::new());
        }
        let bytes = count
            .checked_mul(STATFS_SIZE)
            .expect("mount table fits in memory");
        // SAFETY: `count` records of `STATFS_SIZE` were allocated by malloc,
        // which is suitably aligned for `u8`. The slice ends before `Free` runs.
        let slice = unsafe { std::slice::from_raw_parts(buf, bytes) };
        let mut volumes = Vec::with_capacity(count);
        for index in 0..count {
            let start = index * STATFS_SIZE;
            let raw = parse_statfs(&slice[start..start + STATFS_SIZE])?;
            volumes.push(describe(&raw));
        }
        Ok(volumes)
    }

    struct Free(*mut u8);

    impl Drop for Free {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from getmntinfo_r_np's malloc, or it is
                // null and this branch does not run. free is called once.
                unsafe { free(self.0.cast()) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(fstype: &str, mount: &str, flags: u32) -> Vec<u8> {
        let mut buf = vec![0; STATFS_LEN];
        buf[OFF_BSIZE..OFF_BSIZE + 4].copy_from_slice(&4096u32.to_ne_bytes());
        buf[OFF_BLOCKS..OFF_BLOCKS + 8].copy_from_slice(&1000u64.to_ne_bytes());
        buf[OFF_BFREE..OFF_BFREE + 8].copy_from_slice(&100u64.to_ne_bytes());
        buf[OFF_BAVAIL..OFF_BAVAIL + 8].copy_from_slice(&80u64.to_ne_bytes());
        buf[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_ne_bytes());
        write_at(&mut buf, OFF_FSTYPE, fstype);
        write_at(&mut buf, OFF_MOUNT, mount);
        buf
    }

    fn write_at(buf: &mut [u8], offset: usize, text: &str) {
        buf[offset..offset + text.len()].copy_from_slice(text.as_bytes());
    }

    #[test]
    fn local_apfs_is_walkable_and_sizes_match() {
        let volume =
            describe(&parse_statfs(&record("apfs", "/Volumes/Source", MNT_LOCAL)).unwrap());
        assert!(volume.walkable);
        assert_eq!(volume.total_bytes, 1000 * 4096);
        assert_eq!(volume.used_bytes, 900 * 4096);
        assert_eq!(volume.available_bytes, 80 * 4096);
    }

    #[test]
    fn system_devfs_and_remote_are_not_walkable() {
        let system = describe(&parse_statfs(&record("apfs", "/System", MNT_LOCAL)).unwrap());
        assert!(!system.walkable);
        let devfs = describe(&parse_statfs(&record("devfs", "/dev", MNT_LOCAL)).unwrap());
        assert!(!devfs.walkable);
        let remote = describe(&parse_statfs(&record("apfs", "/Volumes/Net", 0)).unwrap());
        assert!(!remote.walkable);
        let data =
            describe(&parse_statfs(&record("apfs", "/System/Volumes/Data", MNT_LOCAL)).unwrap());
        assert!(data.walkable);
        assert!(data.note.unwrap().contains("purgeable"));
    }
}
