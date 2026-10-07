//! Compiled-in reclaim rules.
//!
//! A path becomes a candidate only when one of these rules names it. The
//! tables are the allowlist. Config may raise an age. It cannot add a rule
//! or a command to run.

use std::time::Duration;

use crate::error::{Error, Result};

/// How a matched path may be removed, once a later command exists.
///
/// Exhaustive on purpose. Adding a tier should fail the build at every match
/// until that tier has a decision about deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Regenerable cache. Staged when it is older than its minimum age.
    Safe,
    /// Build output next to a project marker. Reported, staged only when every caution gate passes.
    Caution,
}

impl Tier {
    /// Stable word used in text and JSON.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::rules::Tier;
    ///
    /// assert_eq!(Tier::Safe.as_str(), "safe");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Caution => "caution",
        }
    }
}

/// Why a matched path is reported and not staged.
///
/// Exhaustive on purpose, same as [`Tier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Newer than the safe-rule hot window.
    Hot,
    /// Newer than this rule's minimum age.
    ///
    /// Used when that minimum is longer than the 12 hour hot window, including
    /// caution builds and aged logs.
    Young,
    /// `mtime` is after the scan clock.
    Future,
    /// Another process holds a BSD file lock.
    Locked,
    /// The lock probe failed, so the path might be in use.
    LockUnknown,
    /// `git status` reported a dirty tree.
    Dirty,
    /// `git` was missing or failed. Staging would be a guess.
    GitUnknown,
    /// A nested checkout (a `.git` directory) sits inside the candidate.
    NestedGit,
    /// A child is on a different device, so the tree is a mount point.
    CrossedDevice,
    /// A stat inside the tree had no mtime.
    UnknownAge,
    /// A stat inside the tree failed. The size is incomplete.
    Partial,
}

impl Skip {
    /// One line for the report.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::rules::Skip;
    ///
    /// assert_eq!(Skip::Locked.as_str(), "another process holds a file lock");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "modified inside the hot window",
            Self::Young => "newer than the rule's minimum age",
            Self::Future => "mtime is in the future",
            Self::Locked => "another process holds a file lock",
            Self::LockUnknown => "could not tell whether a file lock is held",
            Self::Dirty => "git tree is dirty",
            Self::GitUnknown => "git status failed",
            Self::NestedGit => "contains a nested git checkout",
            Self::CrossedDevice => "contains a mount point",
            Self::UnknownAge => "mtime is missing",
            Self::Partial => "could not read every entry",
        }
    }
}

/// Where a safe rule looks, relative to the home directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeAnchor {
    /// The directory itself is the candidate.
    Directory(&'static str),
    /// Each regular file directly inside this directory is its own candidate.
    ///
    /// The directory is left in place so a running tool can keep writing new files.
    Files(&'static str),
}

/// A regenerable cache or an aged log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeRule {
    /// Stable id. Config ages refer to this.
    pub id: &'static str,
    /// Path relative to the home directory.
    pub anchor: SafeAnchor,
    /// Younger candidates are reported and not staged.
    pub min_age: Duration,
    /// How the bytes come back. `None` for logs.
    pub regenerate: Option<&'static str>,
    /// Why this path is safe to remove.
    pub rationale: &'static str,
    /// Lock files the owning tool holds while it uses the path, relative to home.
    ///
    /// The candidate is not staged while another process holds one of them.
    pub locks: &'static [&'static str],
}

/// A build directory that is only a candidate next to a marker file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRule {
    /// Stable id.
    pub id: &'static str,
    /// Directory name that must be a direct child of the project.
    pub child: &'static str,
    /// Marker files that must all be regular files in the project directory.
    pub require_all: &'static [&'static str],
    /// At least one of these regular files must also be present.
    ///
    /// Empty means [`Self::require_all`] is the whole check.
    pub require_any: &'static [&'static str],
    /// Younger trees are reported and not staged.
    pub min_age: Duration,
    /// How to rebuild.
    pub regenerate: &'static str,
    /// Why the child is rebuildable.
    pub rationale: &'static str,
    /// Regular files the tool writes inside the child. One must be present.
    ///
    /// A directory that only shares the name is not the tool's output. Empty
    /// means the name and the markers next to it are the whole check.
    pub inside_any: &'static [&'static str],
    /// Names of lock files the tool holds while it writes the child.
    ///
    /// They are looked for one and two levels inside the child.
    pub locks: &'static [&'static str],
}

/// Safe caches younger than this are not staged.
pub const HOT_WINDOW: Duration = Duration::from_hours(12);

/// Caution build trees younger than this are not staged.
///
/// `Duration::from_days` is still unstable, so this is 7 days in hours.
pub const CAUTION_AGE: Duration = Duration::from_hours(7 * 24);

/// Log files younger than this are not staged.
///
/// `Duration::from_days` is still unstable, so this is 14 days in hours.
pub const LOG_AGE: Duration = Duration::from_hours(14 * 24);

/// Shell snapshots younger than this are not staged.
///
/// `Duration::from_days` is still unstable, so this is 7 days in hours.
pub const SNAPSHOT_AGE: Duration = Duration::from_hours(7 * 24);

const fn cache(
    id: &'static str,
    path: &'static str,
    regenerate: &'static str,
    rationale: &'static str,
) -> SafeRule {
    SafeRule {
        id,
        anchor: SafeAnchor::Directory(path),
        min_age: HOT_WINDOW,
        regenerate: Some(regenerate),
        rationale,
        locks: &[],
    }
}

/// Cargo takes an exclusive `flock` on these while it downloads or unpacks.
///
/// Both exist in a `CARGO_HOME` that cargo has used. The directory itself is
/// never locked, so probing only the candidate sees nothing.
const CARGO_HOME_LOCKS: &[&str] = &[".cargo/.package-cache", ".cargo/.package-cache-mutate"];

const fn cargo_cache(id: &'static str, path: &'static str, rationale: &'static str) -> SafeRule {
    SafeRule {
        id,
        anchor: SafeAnchor::Directory(path),
        min_age: HOT_WINDOW,
        regenerate: Some("cargo fetch"),
        rationale,
        locks: CARGO_HOME_LOCKS,
    }
}

const fn aged_files(id: &'static str, path: &'static str, min_age: Duration) -> SafeRule {
    SafeRule {
        id,
        anchor: SafeAnchor::Files(path),
        min_age,
        regenerate: None,
        rationale: "aged files in a tool directory; the directory itself stays",
        locks: &[],
    }
}

/// Safe rules shipped with the binary.
///
/// # Examples
///
/// ```
/// use disk_health::rules::builtin_safe;
///
/// assert!(builtin_safe().iter().any(|rule| rule.id == "cargo-registry"));
/// ```
#[must_use]
pub fn builtin_safe() -> Vec<SafeRule> {
    vec![
        cargo_cache(
            "cargo-registry",
            ".cargo/registry",
            "crate downloads; cargo fetch refills the registry",
        ),
        cargo_cache(
            "cargo-git",
            ".cargo/git",
            "git dependency checkouts; cargo fetch refills them",
        ),
        cache(
            "rustup-tmp",
            ".rustup/tmp",
            "rustup downloads again",
            "incomplete rustup downloads, not installed toolchains",
        ),
        cache(
            "npm-cache",
            ".npm/_cacache",
            "npm refills the cache on demand",
            "npm content-addressed cache",
        ),
        cache(
            "uv-cache",
            ".cache/uv",
            "uv refills the cache",
            "uv download cache",
        ),
        cache(
            "pip-cache",
            "Library/Caches/pip",
            "pip refills the cache",
            "pip download cache",
        ),
        cache(
            "playwright",
            "Library/Caches/ms-playwright",
            "npx playwright install",
            "playwright browser downloads",
        ),
        cache(
            "playwright-go",
            "Library/Caches/ms-playwright-go",
            "npx playwright install",
            "playwright-go browser downloads",
        ),
        cache(
            "homebrew-cache",
            "Library/Caches/Homebrew",
            "brew redownloads",
            "homebrew download cache, not the cellar",
        ),
        cache(
            "node-gyp",
            "Library/Caches/node-gyp",
            "node-gyp rebuilds",
            "node-gyp header cache",
        ),
        cache(
            "miri-cache",
            "Library/Caches/org.rust-lang.miri",
            "the next miri run refills it",
            "miri cache",
        ),
        cache(
            "grok-marketplace-cache",
            ".grok/marketplace-cache",
            "the plugin fetch refills it",
            "marketplace downloads, not sessions or worktrees",
        ),
        aged_files("grok-logs", ".grok/logs", LOG_AGE),
        aged_files(
            "claude-shell-snapshots",
            ".claude/shell-snapshots",
            SNAPSHOT_AGE,
        ),
        aged_files("claude-paste-cache", ".claude/paste-cache", HOT_WINDOW),
        aged_files(
            "codex-shell-snapshots",
            ".codex/shell_snapshots",
            SNAPSHOT_AGE,
        ),
        aged_files("codex-log", ".codex/log", LOG_AGE),
    ]
}

#[derive(Clone, Copy)]
struct ProjectParts {
    id: &'static str,
    child: &'static str,
    require_all: &'static [&'static str],
    require_any: &'static [&'static str],
    regenerate: &'static str,
    rationale: &'static str,
    inside_any: &'static [&'static str],
    locks: &'static [&'static str],
}

const PYTHON_MARKERS: &[&str] = &["pyproject.toml", "setup.cfg", "requirements.txt"];

const fn project(parts: ProjectParts) -> ProjectRule {
    ProjectRule {
        id: parts.id,
        child: parts.child,
        require_all: parts.require_all,
        require_any: parts.require_any,
        min_age: CAUTION_AGE,
        regenerate: parts.regenerate,
        rationale: parts.rationale,
        inside_any: parts.inside_any,
        locks: parts.locks,
    }
}

/// Caution rules shipped with the binary.
///
/// # Examples
///
/// ```
/// use disk_health::rules::builtin_project;
///
/// assert!(builtin_project()
///     .iter()
///     .any(|rule| rule.id == "cargo-target"));
/// ```
#[must_use]
pub fn builtin_project() -> Vec<ProjectRule> {
    vec![
        project(ProjectParts {
            id: "cargo-target",
            child: "target",
            require_all: &["Cargo.toml"],
            require_any: &[],
            regenerate: "cargo build",
            rationale: "cargo build output next to Cargo.toml",
            // Cargo writes both at the top of every target directory it creates.
            inside_any: &["CACHEDIR.TAG", ".rustc_info.json"],
            // Held for the length of a build, in `debug/`, `release/`, or `<triple>/debug/`.
            locks: &[".cargo-lock"],
        }),
        project(ProjectParts {
            id: "node-modules",
            child: "node_modules",
            require_all: &["package.json"],
            require_any: &[
                "pnpm-lock.yaml",
                "package-lock.json",
                "yarn.lock",
                "bun.lock",
                "bun.lockb",
            ],
            regenerate: "reinstall from the lockfile",
            rationale: "installed packages next to a lockfile",
            inside_any: &[],
            locks: &[],
        }),
        project(ProjectParts {
            id: "next-build",
            child: ".next",
            require_all: &["package.json"],
            require_any: &[],
            regenerate: "next build",
            rationale: "Next.js build output",
            inside_any: &[],
            locks: &[],
        }),
        project(ProjectParts {
            id: "turbo-cache",
            child: ".turbo",
            require_all: &[],
            require_any: &["package.json", "turbo.json"],
            regenerate: "turbo refills the cache",
            rationale: "Turborepo cache",
            inside_any: &[],
            locks: &[],
        }),
        project(ProjectParts {
            id: "pycache",
            child: "__pycache__",
            require_all: &[],
            require_any: PYTHON_MARKERS,
            regenerate: "python recreates bytecode",
            rationale: "python bytecode",
            inside_any: &[],
            locks: &[],
        }),
        project(ProjectParts {
            id: "pytest-cache",
            child: ".pytest_cache",
            require_all: &[],
            require_any: PYTHON_MARKERS,
            regenerate: "pytest recreates the cache",
            rationale: "pytest cache",
            inside_any: &[],
            locks: &[],
        }),
        project(ProjectParts {
            id: "mypy-cache",
            child: ".mypy_cache",
            require_all: &[],
            require_any: PYTHON_MARKERS,
            regenerate: "mypy recreates the cache",
            rationale: "mypy cache",
            inside_any: &[],
            locks: &[],
        }),
        project(ProjectParts {
            id: "ruff-cache",
            child: ".ruff_cache",
            require_all: &[],
            require_any: PYTHON_MARKERS,
            regenerate: "ruff recreates the cache",
            rationale: "ruff cache",
            inside_any: &[],
            locks: &[],
        }),
    ]
}

/// Replaces the minimum age of one builtin rule.
///
/// # Errors
///
/// Returns an error when `id` is not a builtin rule.
///
/// # Examples
///
/// ```
/// use disk_health::rules::set_age;
/// use disk_health::rules::{builtin_project, builtin_safe};
/// use std::time::Duration;
///
/// let mut safe = builtin_safe();
/// let mut project = builtin_project();
/// set_age(
///     &mut safe,
///     &mut project,
///     "cargo-registry",
///     Duration::from_hours(48),
/// )
/// .unwrap();
/// let rule = safe.iter().find(|rule| rule.id == "cargo-registry").unwrap();
/// assert_eq!(rule.min_age, Duration::from_hours(48));
/// ```
pub fn set_age(
    safe: &mut [SafeRule],
    project: &mut [ProjectRule],
    id: &str,
    age: Duration,
) -> Result<()> {
    if let Some(rule) = safe.iter_mut().find(|rule| rule.id == id) {
        rule.min_age = age;
        return Ok(());
    }

    if let Some(rule) = project.iter_mut().find(|rule| rule.id == id) {
        rule.min_age = age;
        return Ok(());
    }
    Err(Error::Config {
        message: format!("unknown rule id {id}"),
    })
}
