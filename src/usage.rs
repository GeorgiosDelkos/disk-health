//! Report-only walk of one volume.
//!
//! A usage node has no tier and no staged bit. The JSON writer does not emit
//! either word. Symlinks are not followed, a different device is not entered,
//! and a dataless directory is not listed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::json;
use crate::walk::{EntryMeta, Fs, Kind, measure};

/// How many directory levels below the root are expanded.
pub const DEFAULT_DEPTH: u32 = 4;

/// One directory or file in a usage tree.
///
/// There is no tier field. Adding one would let a usage row be mistaken for
/// something apply can move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageNode {
    /// Full path.
    pub path: PathBuf,
    /// Apparent bytes. Hardlinks are counted once in the tree.
    pub apparent_bytes: u64,
    /// Children, largest first. Empty when `depth` stopped the expansion.
    pub children: Vec<Self>,
}

/// Called with the number of directories expanded so far.
pub type Progress<'a> = &'a (dyn Fn(u64) + Sync);

/// Walks `root` without staging anything.
///
/// # Errors
///
/// Returns an error when `root` is a system or VM volume, or when `root`
/// itself cannot be stated.
///
/// # Examples
///
/// ```
/// use disk_health::usage::walk;
/// use disk_health::walk::MemFs;
/// use std::path::Path;
/// use std::time::SystemTime;
///
/// let fs = MemFs::new();
/// fs.dir("/vol", 1, SystemTime::UNIX_EPOCH);
/// fs.file("/vol/blob", 1, 4, SystemTime::UNIX_EPOCH);
/// let tree = walk(&fs, Path::new("/vol"), 4, None).unwrap();
/// assert_eq!(tree.apparent_bytes, 4);
/// ```
pub fn walk(
    fs: &dyn Fs,
    root: &Path,
    depth: u32,
    progress: Option<Progress<'_>>,
) -> Result<UsageNode> {
    refuse(root)?;
    let meta = fs.meta(root)?;
    let mut walker = Walker {
        fs,
        root_dev: meta.dev,
        seen: HashSet::new(),
        expanded: 0,
        progress,
    };
    Ok(walker.node(root.to_path_buf(), &meta, depth))
}

/// JSON document for a usage tree. It has no `staged` and no `tier` key.
///
/// # Examples
///
/// ```
/// use disk_health::usage::{UsageNode, to_json};
/// use std::path::PathBuf;
///
/// let node = UsageNode {
///     path: PathBuf::from("/vol"),
///     apparent_bytes: 4,
///     children: Vec::new(),
/// };
/// let json = to_json(&node);
/// assert!(json.contains("\"kind\": \"usage\""));
/// assert!(!json.contains("\"staged\""));
/// assert!(!json.contains("\"tier\""));
/// ```
#[must_use]
pub fn to_json(node: &UsageNode) -> String {
    let mut out = String::from("{\n");
    push_raw(&mut out, 2, "schema", "1");
    out.push_str(",\n");
    push_str(&mut out, 2, "kind", "usage");
    out.push_str(",\n");
    push_node(&mut out, node, 2);
    out.push_str("\n}\n");
    out
}

fn refuse(root: &Path) -> Result<()> {
    let text = root.to_string_lossy();
    let blocked = root == Path::new("/System")
        || root == Path::new("/System/Volumes/VM")
        || root == Path::new("/private/var/vm")
        || text.starts_with("/System/") && root != Path::new("/System/Volumes/Data");
    if blocked && root != Path::new("/System/Volumes/Data") {
        return Err(Error::Usage {
            message: format!("usage refuses {}", root.display()),
        });
    }
    Ok(())
}

struct Walker<'a> {
    fs: &'a dyn Fs,
    root_dev: u64,
    /// Hardlinked files already counted. A file with one link cannot repeat.
    seen: HashSet<(u64, u64)>,
    expanded: u64,
    progress: Option<Progress<'a>>,
}

impl Walker<'_> {
    fn node(&mut self, path: PathBuf, meta: &EntryMeta, depth: u32) -> UsageNode {
        if meta.kind == Kind::Symlink || meta.is_dataless() || meta.dev != self.root_dev {
            return leaf(path, 0);
        }
        match meta.kind {
            Kind::File => {
                let repeat = meta.nlink > 1 && !self.seen.insert((meta.dev, meta.ino));
                leaf(path, if repeat { 0 } else { meta.len })
            }
            Kind::Directory if depth == 0 => {
                let bytes =
                    measure(self.fs, &path, meta).map_or(0, |measured| measured.apparent_bytes);
                leaf(path, bytes)
            }
            Kind::Directory => self.expand(path, depth),
            Kind::Symlink | Kind::Other => leaf(path, 0),
        }
    }

    fn expand(&mut self, path: PathBuf, depth: u32) -> UsageNode {
        self.expanded = self.expanded.saturating_add(1);
        if let Some(progress) = self.progress {
            progress(self.expanded);
        }

        let Ok(listing) = self.fs.read_dir(&path) else {
            return leaf(path, 0);
        };
        // A mount point looks like a plain directory in its parent's listing.
        if listing.dev != self.root_dev {
            return leaf(path, 0);
        }

        let mut children = Vec::new();
        let mut total: u64 = 0;
        for entry in listing.entries {
            let Some(meta) = entry.meta else {
                continue;
            };
            let child = self.node(path.join(entry.name), &meta, depth - 1);
            total = total.saturating_add(child.apparent_bytes);
            children.push(child);
        }
        children.sort_by(|left, right| {
            right
                .apparent_bytes
                .cmp(&left.apparent_bytes)
                .then(left.path.cmp(&right.path))
        });
        UsageNode {
            path,
            apparent_bytes: total,
            children,
        }
    }
}

fn leaf(path: PathBuf, apparent_bytes: u64) -> UsageNode {
    UsageNode {
        path,
        apparent_bytes,
        children: Vec::new(),
    }
}

fn push_node(out: &mut String, node: &UsageNode, indent: usize) {
    push_str(out, indent, "path", &node.path.to_string_lossy());
    out.push_str(",\n");
    push_raw(
        out,
        indent,
        "apparent_bytes",
        &node.apparent_bytes.to_string(),
    );
    out.push_str(",\n");
    pad(out, indent);
    out.push_str("\"children\": [\n");
    for (index, child) in node.children.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        pad(out, indent + 2);
        out.push_str("{\n");
        push_node(out, child, indent + 4);
        out.push('\n');
        pad(out, indent + 2);
        out.push('}');
    }
    if !node.children.is_empty() {
        out.push('\n');
        pad(out, indent);
    }
    out.push(']');
}

fn push_str(out: &mut String, indent: usize, key: &str, value: &str) {
    pad(out, indent);
    out.push('"');
    json::escape_into(out, key);
    out.push_str("\": \"");
    json::escape_into(out, value);
    out.push('"');
}

fn push_raw(out: &mut String, indent: usize, key: &str, value: &str) {
    pad(out, indent);
    out.push('"');
    json::escape_into(out, key);
    out.push_str("\": ");
    out.push_str(value);
}

fn pad(out: &mut String, indent: usize) {
    out.push_str(&" ".repeat(indent));
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::walk::{MemFs, SF_DATALESS};

    #[test]
    fn json_has_no_tier_and_symlink_is_not_followed() {
        let fs = MemFs::new();
        let when = SystemTime::UNIX_EPOCH;
        fs.dir("/vol", 1, when);
        fs.file("/vol/blob", 1, 4, when);
        fs.file("/secret", 1, 100, when);
        fs.symlink("/vol/link", when);
        let tree = walk(&fs, Path::new("/vol"), 4, None).unwrap();
        let json = to_json(&tree);
        assert!(!json.contains("\"staged\""), "{json}");
        assert!(!json.contains("\"tier\""), "{json}");
        assert_eq!(tree.apparent_bytes, 4);
        assert!(
            tree.children
                .iter()
                .all(|child| child.apparent_bytes != 100)
        );
    }

    #[test]
    fn other_device_and_dataless_are_not_entered() {
        let fs = MemFs::new();
        let when = SystemTime::UNIX_EPOCH;
        fs.dir("/vol", 1, when);
        fs.dir("/vol/mnt", 2, when);
        fs.file("/vol/mnt/other", 2, 50, when);
        fs.dir("/vol/cloud", 1, when);
        fs.set_flags(Path::new("/vol/cloud"), SF_DATALESS);
        fs.file("/vol/cloud/hidden", 1, 80, when);
        let tree = walk(&fs, Path::new("/vol"), 4, None).unwrap();
        assert_eq!(tree.apparent_bytes, 0);
    }

    #[test]
    fn system_volume_is_refused() {
        let fs = MemFs::new();
        let err = walk(&fs, Path::new("/System"), 4, None).unwrap_err();
        assert!(err.to_string().contains("refuses"));
    }
}
