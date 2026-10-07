//! Roots, excludes, and age overrides.
//!
//! The files are line oriented. A line cannot name a new rule or a command.
//! Ages can only make a builtin rule older or younger. Zero is rejected:
//! systemd-tmpfiles treats age `0` as unconditional deletion, and that is the
//! setting that does not belong on a home directory.
//!
//! The denylist is compared as text, one path component at a time, ignoring
//! case. The default macOS volume is case-insensitive, so `~/.SSH` is
//! `~/.ssh` on disk. On a case-sensitive volume this denies a sibling that
//! differs only by case, which is the safe direction. A path that reaches a
//! denied directory through a symlink is only caught once it is canonical:
//! [`resolve_home`], [`prepare_root`], and the exclude lines all resolve
//! what exists before it is compared.

use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::rules::{self, ProjectRule, SafeRule};

/// Absolute prefixes that are never reclaim candidates.
///
/// `/usr` is here and `/Users` is not. Matching goes through [`Path::starts_with`],
/// which compares components, so the first does not swallow the second.
const ABSOLUTE_DENY: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/opt/homebrew",
    "/Library",
    "/Applications",
    "/etc",
    "/private/etc",
    "/private/var/vm",
    "/private/var/db",
    "/dev",
    "/Volumes/Recovery",
];

/// Home-relative prefixes that are never reclaim candidates.
///
/// `Library/Application Support` is on this list. Editor state lives there.
/// A later inventory of Cursor snapshots has to read that tree on purpose,
/// not by relaxing this list for every rule.
const HOME_DENY: &[&str] = &[
    "Library/Keychains",
    "Library/Mail",
    "Library/Messages",
    "Library/Photos",
    "Library/Containers",
    "Library/Group Containers",
    "Library/Mobile Documents",
    "Library/CloudStorage",
    "Library/Application Support",
    "Library/Preferences",
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".netrc",
    ".config/disk-health",
    ".Trash",
];

/// Builtin rules plus the user's roots, excludes, and ages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    /// Project walk roots.
    pub roots: Vec<PathBuf>,
    /// Denylist, absolute and normalized.
    pub deny: Vec<PathBuf>,
    /// Safe rules, with age overrides applied.
    pub safe_rules: Vec<SafeRule>,
    /// Caution rules, with age overrides applied.
    pub project_rules: Vec<ProjectRule>,
}

/// What to do with one user-supplied project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootStatus {
    /// Canonical directory, not on the denylist.
    Ready(PathBuf),
    /// The path does not exist.
    Missing(PathBuf),
    /// The path, or its symlink target, is on the denylist.
    Denied(PathBuf),
}

/// Loads `~/.config/disk-health/{roots,exclude,ages}` under `home`.
///
/// A missing file uses the builtin default. For `roots` that is whichever of
/// [`default_roots`] exist. An empty `roots` file means the user cleared the
/// project walk.
///
/// # Errors
///
/// Returns an error when a file exists but cannot be read, a path is relative,
/// an age is not `<number><h|d>`, an age is zero, or an age names an unknown rule.
///
/// # Examples
///
/// ```
/// use disk_health::config::load;
///
/// let home = std::env::temp_dir().join(format!(
///     "disk-health-doc-load-{}",
///     std::process::id()
/// ));
/// let _ = std::fs::remove_dir_all(&home);
/// std::fs::create_dir_all(&home).unwrap();
/// let loaded = load(&home).unwrap();
/// assert!(
///     loaded
///         .safe_rules
///         .iter()
///         .any(|rule| rule.id == "cargo-registry")
/// );
/// let _ = std::fs::remove_dir_all(&home);
/// ```
pub fn load(home: &Path) -> Result<Loaded> {
    let dir = home.join(".config/disk-health");

    let roots = match read_lines(&dir.join("roots"))? {
        // The defaults are guesses. One that is not there is not something
        // the operator asked for, so it is not reported as missing.
        None => default_roots(home)
            .into_iter()
            .filter(|root| fs::symlink_metadata(root).is_ok())
            .collect(),
        Some(lines) => lines
            .iter()
            .map(|line| expand(home, line))
            .collect::<Result<Vec<_>>>()?,
    };
    let extra = match read_lines(&dir.join("exclude"))? {
        None => Vec::new(),
        Some(lines) => lines
            .iter()
            .map(|line| expand(home, line).and_then(|path| settle(&path)))
            .collect::<Result<Vec<_>>>()?,
    };

    let mut safe_rules = rules::builtin_safe();
    let mut project_rules = rules::builtin_project();
    if let Some(lines) = read_lines(&dir.join("ages"))? {
        for line in lines {
            let (id, age) = parse_age_line(&line)?;
            rules::set_age(&mut safe_rules, &mut project_rules, &id, age)?;
        }
    }

    Ok(Loaded {
        roots,
        deny: deny_prefixes(home, &extra),
        safe_rules,
        project_rules,
    })
}

/// Default project roots when the user has no `roots` file.
///
/// Both are under home. The scan only reads the volume home is on, so a
/// root on an external disk would be refused anyway.
///
/// # Examples
///
/// ```
/// use disk_health::config::default_roots;
/// use std::path::Path;
///
/// let roots = default_roots(Path::new("/Users/ada"));
/// assert!(roots.iter().any(|root| root.ends_with("Documents/Github")));
/// ```
#[must_use]
pub fn default_roots(home: &Path) -> Vec<PathBuf> {
    vec![home.join("Documents/Github"), home.join("Documents/Source")]
}

/// Builtin denylist plus `extra` exclude prefixes.
///
/// # Examples
///
/// ```
/// use disk_health::config::deny_prefixes;
/// use std::path::Path;
///
/// let deny = deny_prefixes(Path::new("/Users/ada"), &[]);
/// assert!(deny.iter().any(|prefix| prefix == Path::new("/System")));
/// ```
#[must_use]
pub fn deny_prefixes(home: &Path, extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut prefixes: Vec<PathBuf> = ABSOLUTE_DENY.iter().map(PathBuf::from).collect();
    prefixes.extend(HOME_DENY.iter().map(|relative| home.join(relative)));

    prefixes.extend(extra.iter().map(|path| normalize(path)));
    prefixes
}

/// Returns the home directory with symlinks resolved.
///
/// It then compares equal to the canonical paths the scan produces. A home
/// that does not exist is returned as given.
///
/// # Errors
///
/// Returns an error when the path exists but cannot be resolved.
///
/// # Examples
///
/// ```
/// use disk_health::config::resolve_home;
/// use std::path::Path;
///
/// let home = resolve_home(Path::new("/no/such/home")).unwrap();
/// assert_eq!(home, Path::new("/no/such/home"));
/// ```
pub fn resolve_home(home: &Path) -> Result<PathBuf> {
    match fs::canonicalize(home) {
        Ok(canonical) => Ok(canonical),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(normalize(home)),
        Err(err) => Err(Error::io("resolve home", home, err)),
    }
}

/// Splits requested project roots into the ones to walk and the ones refused.
///
/// A missing root is in the first list so the scan can report it.
///
/// # Errors
///
/// Returns an error when a root exists but cannot be resolved.
///
/// # Examples
///
/// ```
/// use disk_health::config::prepare_roots;
/// use std::path::PathBuf;
///
/// let deny = [PathBuf::from("/System")];
/// let (walk, denied) = prepare_roots(&[PathBuf::from("/System/Library")], &deny).unwrap();
/// assert!(walk.is_empty());
/// assert_eq!(denied, [PathBuf::from("/System/Library")]);
/// ```
pub fn prepare_roots(
    requested: &[PathBuf],
    deny: &[PathBuf],
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut roots = Vec::new();
    let mut denied = Vec::new();
    for root in requested {
        match prepare_root(root, deny)? {
            RootStatus::Ready(path) | RootStatus::Missing(path) => roots.push(path),
            RootStatus::Denied(path) => denied.push(path),
        }
    }
    Ok((roots, denied))
}

/// Reports whether `path` is the same as a prefix or lives under one.
///
/// `..` is resolved lexically before the comparison, and names are compared
/// without regard to case. Symlinks are not resolved here: pass a canonical path.
///
/// # Examples
///
/// ```
/// use disk_health::config::{deny_prefixes, path_is_denied};
/// use std::path::Path;
///
/// let deny = deny_prefixes(Path::new("/Users/ada"), &[]);
/// assert!(path_is_denied(Path::new("/usr/bin"), &deny));
/// assert!(path_is_denied(Path::new("/Volumes/Source/.Trashes/501"), &deny));
/// assert!(path_is_denied(Path::new("/Users/ada/.SSH/id_ed25519"), &deny));
/// assert!(!path_is_denied(Path::new("/Users/ada/code"), &deny));
/// ```
#[must_use]
pub fn path_is_denied(path: &Path, prefixes: &[PathBuf]) -> bool {
    let path = normalize(path);
    if path.components().any(|component| {
        let name = component.as_os_str();
        DENY_COMPONENTS
            .iter()
            .any(|denied| same_name(name, OsStr::new(denied)))
    }) {
        return true;
    }

    prefixes.iter().any(|prefix| is_under(&path, prefix))
}

/// [`Path::starts_with`], with each component compared by [`same_name`].
fn is_under(path: &Path, prefix: &Path) -> bool {
    let mut have = path.components();
    prefix.components().all(|want| {
        have.next()
            .is_some_and(|have| same_name(have.as_os_str(), want.as_os_str()))
    })
}

/// Compares two names after lowercasing them. Unicode is not normalized, so
/// a precomposed and a decomposed spelling of one name still differ.
fn same_name(left: &OsStr, right: &OsStr) -> bool {
    if left == right {
        return true;
    }
    let (left, right) = (left.to_string_lossy(), right.to_string_lossy());
    left.chars()
        .flat_map(char::to_lowercase)
        .eq(right.chars().flat_map(char::to_lowercase))
}

/// Directory names that are never candidates, on any volume.
///
/// Trash and the quarantine directory hold bytes we already decided to
/// remove. A rule, or an edited plan, must not be able to name them again.
const DENY_COMPONENTS: &[&str] = &[".Trash", ".Trashes", ".disk-health-quarantine"];

/// Drops `.` and resolves `..` without touching the filesystem.
///
/// # Examples
///
/// ```
/// use disk_health::config::normalize;
/// use std::path::Path;
///
/// assert_eq!(normalize(Path::new("/usr/../Users")), Path::new("/Users"));
/// ```
#[must_use]
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Classifies a project root.
///
/// Canonicalization follows a symlink root on purpose: a root that points at
/// `/System` must not be walked. Candidates inside an accepted root are not
/// canonicalized, so a child symlink is still just a symlink.
///
/// # Errors
///
/// Returns an error when the path exists but cannot be resolved.
///
/// # Examples
///
/// ```
/// use disk_health::config::{RootStatus, prepare_root};
///
/// let path = std::env::temp_dir().join(format!(
///     "disk-health-doc-missing-{}",
///     std::process::id()
/// ));
/// let _ = std::fs::remove_dir_all(&path);
/// let status = prepare_root(&path, &[]).unwrap();
/// assert!(matches!(status, RootStatus::Missing(_)));
/// ```
pub fn prepare_root(path: &Path, deny: &[PathBuf]) -> Result<RootStatus> {
    let path = normalize(path);
    if path_is_denied(&path, deny) {
        return Ok(RootStatus::Denied(path));
    }

    match fs::canonicalize(&path) {
        Ok(canonical) if path_is_denied(&canonical, deny) => Ok(RootStatus::Denied(canonical)),
        Ok(canonical) => Ok(RootStatus::Ready(canonical)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(RootStatus::Missing(path)),
        Err(err) => Err(Error::io("resolve root", path, err)),
    }
}

/// Parses `20GiB`, `500MiB`, `1KiB`, `1TiB`, or `10B`. Units are 1024-based.
///
/// # Errors
///
/// Returns an error when the unit is missing or the number overflows.
///
/// # Examples
///
/// ```
/// use disk_health::config::parse_size;
///
/// assert_eq!(parse_size("500MiB").unwrap(), 500 * 1024 * 1024);
/// ```
pub fn parse_size(input: &str) -> Result<u64> {
    let input = input.trim();
    let split = input.find(|ch: char| !ch.is_ascii_digit());
    let Some(split) = split else {
        return Err(size_error(input));
    };
    let (number, unit) = input.split_at(split);
    let number: u64 = number.parse().map_err(|_| size_error(input))?;

    let factor: u64 = match unit {
        "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        "TiB" => 1024 * 1024 * 1024 * 1024,
        _ => return Err(size_error(input)),
    };

    number.checked_mul(factor).ok_or_else(|| size_error(input))
}

fn size_error(input: &str) -> Error {
    Error::Config {
        message: format!("size must look like 20GiB or 500MiB, not {input}"),
    }
}

fn parse_age_line(line: &str) -> Result<(String, Duration)> {
    let mut parts = line.split_whitespace();
    let Some(id) = parts.next() else {
        return Err(Error::Config {
            message: format!("age line needs a rule id and a duration: {line}"),
        });
    };
    let Some(age) = parts.next() else {
        return Err(Error::Config {
            message: format!("age line needs a duration: {line}"),
        });
    };
    if parts.next().is_some() {
        return Err(Error::Config {
            message: format!("age line has extra words: {line}"),
        });
    }

    Ok((id.to_owned(), parse_age(age)?))
}

fn parse_age(input: &str) -> Result<Duration> {
    let Some(unit) = input.chars().last() else {
        return Err(age_error(input));
    };
    let number = &input[..input.len() - unit.len_utf8()];
    let Ok(number) = number.parse::<u64>() else {
        return Err(age_error(input));
    };
    if number == 0 || number > 10_000 {
        return Err(Error::Config {
            message: format!("age must be from 1h to 10000d, not {input}"),
        });
    }

    let seconds = match unit {
        'h' => number.checked_mul(60 * 60),
        'd' => number.checked_mul(24 * 60 * 60),
        _ => None,
    };
    seconds
        .map(Duration::from_secs)
        .ok_or_else(|| age_error(input))
}

fn age_error(input: &str) -> Error {
    Error::Config {
        message: format!("age must look like 12h or 7d, not {input}"),
    }
}

fn expand(home: &Path, line: &str) -> Result<PathBuf> {
    if let Some(rest) = line.strip_prefix("~/") {
        Ok(home.join(rest))
    } else if line == "~" {
        Ok(home.to_path_buf())
    } else if line.starts_with('/') {
        Ok(PathBuf::from(line))
    } else {
        Err(Error::Config {
            message: format!("path must be absolute or start with ~/: {line}"),
        })
    }
}

/// Resolves an exclude line when it exists, so a line that names a symlink or
/// uses a different case still matches the canonical paths the walk produces.
///
/// A line for a path that does not exist yet is kept as written. Any other
/// failure is an error: an exclude that silently stops matching is a tree
/// the operator asked to leave alone and the scan walks anyway.
fn settle(path: &Path) -> Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(canonical) => Ok(canonical),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(normalize(path)),
        Err(err) => Err(Error::io("resolve exclude", path, err)),
    }
}

fn read_lines(path: &Path) -> Result<Option<Vec<String>>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(Error::io("read config", path, err)),
    };
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect();
    Ok(Some(lines))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usr_does_not_deny_users() {
        let deny = vec![PathBuf::from("/usr")];
        assert!(path_is_denied(Path::new("/usr/local/share"), &deny));
        assert!(!path_is_denied(Path::new("/Users/ada/.cargo"), &deny));
    }

    #[test]
    fn parent_dir_cannot_walk_out_of_a_prefix() {
        let deny = vec![PathBuf::from("/safe")];
        assert!(path_is_denied(Path::new("/safe/../safe/secret"), &deny));
        assert!(!path_is_denied(Path::new("/safe/../other"), &deny));
    }

    #[test]
    fn deny_ignores_case_and_still_splits_on_components() {
        let deny = deny_prefixes(Path::new("/Users/ada"), &[]);
        assert!(path_is_denied(Path::new("/system/Library"), &deny));
        assert!(path_is_denied(
            Path::new("/users/ADA/library/keychains/login"),
            &deny
        ));
        assert!(path_is_denied(Path::new("/Volumes/X/.trashes/501"), &deny));
        assert!(!path_is_denied(Path::new("/Users/ada/Librarian"), &deny));
        assert!(!path_is_denied(Path::new("/usrlocal"), &deny));
    }

    #[test]
    fn exclude_line_matches_the_canonical_spelling() {
        let home = std::env::temp_dir().join(format!("disk-health-settle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let kept = home.join("Kept");
        fs::create_dir_all(&kept).unwrap();
        fs::create_dir_all(home.join(".config/disk-health")).unwrap();
        std::os::unix::fs::symlink(&kept, home.join("alias")).unwrap();
        fs::write(home.join(".config/disk-health/exclude"), "~/alias\n").unwrap();

        let loaded = load(&home).unwrap();
        let canonical = fs::canonicalize(&kept).unwrap();
        assert!(path_is_denied(&canonical.join("target"), &loaded.deny));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn default_root_that_does_not_exist_is_dropped_and_a_configured_one_is_kept() {
        let home = std::env::temp_dir().join(format!("disk-health-roots-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join("Documents/Github")).unwrap();
        assert_eq!(load(&home).unwrap().roots, [home.join("Documents/Github")]);

        fs::create_dir_all(home.join(".config/disk-health")).unwrap();
        fs::write(home.join(".config/disk-health/roots"), "~/nowhere\n").unwrap();
        assert_eq!(load(&home).unwrap().roots, [home.join("nowhere")]);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn zero_age_is_rejected() {
        let err = parse_age("0h").unwrap_err();
        assert!(err.to_string().contains("1h"));
    }

    #[test]
    fn size_units_are_powers_of_1024() {
        assert_eq!(parse_size("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("500MiB").unwrap(), 500 * 1024 * 1024);
    }
}
