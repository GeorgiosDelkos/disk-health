//! Report-only walk of one volume.
//!
//! A usage node has no tier and no staged bit. The JSON writer does not emit
//! either word. Symlinks are not followed, a different device is not entered,
//! and a dataless directory is not listed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::json;
use crate::walk::{Fs, Kind, measure};

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
/// let tree = walk(&fs, Path::new("/vol"), 4).unwrap();
/// assert_eq!(tree.apparent_bytes, 4);
/// ```
pub fn walk(fs: &dyn Fs, root: &Path, depth: u32) -> Result<UsageNode> {
    refuse(root)?;
    let meta = fs.meta(root)?;
    let mut seen = HashSet::new();
    Ok(descend(fs, root, meta.dev, depth, &mut seen))
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

fn descend(
    fs: &dyn Fs,
    path: &Path,
    root_dev: u64,
    depth: u32,
    seen: &mut HashSet<(u64, u64)>,
) -> UsageNode {
    let Ok(meta) = fs.meta(path) else {
        return leaf(path, 0);
    };
    if meta.kind == Kind::Symlink || meta.is_dataless() || meta.dev != root_dev {
        return leaf(path, 0);
    }
    if meta.kind == Kind::File {
        let bytes = if seen.insert((meta.dev, meta.ino)) {
            meta.len
        } else {
            0
        };
        return leaf(path, bytes);
    }
    if meta.kind != Kind::Directory {
        return leaf(path, 0);
    }
    if depth == 0 {
        let bytes = measure(fs, path, &meta).map_or(0, |measured| measured.apparent_bytes);
        return leaf(path, bytes);
    }

    let names = fs.read_dir(path).unwrap_or_default();
    let mut children = Vec::new();
    let mut total: u64 = 0;
    for name in names {
        let child = descend(fs, &path.join(name), root_dev, depth - 1, seen);
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
        path: path.to_path_buf(),
        apparent_bytes: total,
        children,
    }
}

fn leaf(path: &Path, apparent_bytes: u64) -> UsageNode {
    UsageNode {
        path: path.to_path_buf(),
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
        let tree = walk(&fs, Path::new("/vol"), 4).unwrap();
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
        let tree = walk(&fs, Path::new("/vol"), 4).unwrap();
        assert_eq!(tree.apparent_bytes, 0);
    }

    #[test]
    fn system_volume_is_refused() {
        let fs = MemFs::new();
        let err = walk(&fs, Path::new("/System"), 4).unwrap_err();
        assert!(err.to_string().contains("refuses"));
    }
}
