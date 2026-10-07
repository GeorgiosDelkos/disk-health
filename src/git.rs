//! Git cleanliness, behind a trait so tests do not spawn `git`.
//!
//! A dirty tree, or a `git` we could not run, blocks staging. The build
//! directory may be the only copy of an uncommitted agent edit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// What `git status --porcelain` said about a project directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GitTree {
    /// No output and a successful exit.
    Clean,
    /// Porcelain reported at least one line.
    Dirty,
    /// The directory is not inside a work tree.
    #[default]
    NotARepo,
    /// `git` was missing, or it failed for another reason.
    Unknown,
}

/// Looks up whether a project directory is clean.
pub trait GitProbe: Sync {
    /// Status of `project`. Implementations must not use a shell.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::git::{GitProbe, GitTree, MapGit};
    /// use std::path::Path;
    ///
    /// let git = MapGit {
    ///     default: GitTree::Dirty,
    ///     ..MapGit::default()
    /// };
    /// assert_eq!(git.status(Path::new("/proj")), GitTree::Dirty);
    /// ```
    fn status(&self, project: &Path) -> GitTree;
}

/// `git -C <project> status --porcelain`.
#[derive(Debug, Default)]
pub struct SystemGit;

impl GitProbe for SystemGit {
    fn status(&self, project: &Path) -> GitTree {
        let output = Command::new("git")
            .arg("-C")
            .arg(project)
            .args(["status", "--porcelain"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output();
        let Ok(output) = output else {
            return GitTree::Unknown;
        };

        if output.status.success() {
            return if output.stdout.is_empty() {
                GitTree::Clean
            } else {
                GitTree::Dirty
            };
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not a git repository") {
            GitTree::NotARepo
        } else {
            GitTree::Unknown
        }
    }
}

/// Fixed answers for tests, keyed by the project directory.
#[derive(Debug, Clone, Default)]
pub struct MapGit {
    /// Status to return for a specific project path.
    pub by_path: BTreeMap<PathBuf, GitTree>,
    /// Status when `by_path` has no entry.
    pub default: GitTree,
}

impl GitProbe for MapGit {
    fn status(&self, project: &Path) -> GitTree {
        self.by_path.get(project).copied().unwrap_or(self.default)
    }
}

/// Branch and cleanliness of one worktree.
///
/// `ahead` and `behind` are not here. Those counts need `git rev-list`,
/// and v1 runs only the three commands in [`WORKTREE_ARGV`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorktreeStatus {
    /// `Some` when `git status --porcelain` exited 0. `true` means non-empty.
    pub dirty: Option<bool>,
    /// `HEAD`'s abbreviated branch, when `rev-parse` exited 0.
    pub branch: Option<String>,
    /// Upstream ref, when `rev-parse @{upstream}` exited 0.
    pub upstream: Option<String>,
}

/// The only `git` argument lists a worktree inspection may run.
///
/// A fourth command would invent ahead/behind. The test locks this list.
pub const WORKTREE_ARGV: &[&[&str]] = &[
    &["status", "--porcelain"],
    &["rev-parse", "--abbrev-ref", "HEAD"],
    &["rev-parse", "--abbrev-ref", "@{upstream}"],
];

/// Reads worktree columns without a shell.
pub trait WorktreeGit: Sync {
    /// Runs [`WORKTREE_ARGV`] and nothing else.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::git::{MapWorktree, WorktreeGit, WorktreeStatus};
    /// use std::path::Path;
    ///
    /// let git = MapWorktree {
    ///     default: WorktreeStatus {
    ///         dirty: Some(true),
    ///         branch: Some("main".to_owned()),
    ///         upstream: None,
    ///     },
    ///     ..MapWorktree::default()
    /// };
    /// assert_eq!(git.inspect(Path::new("/wt")).dirty, Some(true));
    /// ```
    fn inspect(&self, checkout: &Path) -> WorktreeStatus;
}

/// `git` for review rows. Failure leaves the row in place with empty columns.
#[derive(Debug, Default)]
pub struct SystemWorktree;

impl WorktreeGit for SystemWorktree {
    fn inspect(&self, checkout: &Path) -> WorktreeStatus {
        let porcelain = git_text(checkout, WORKTREE_ARGV[0]);
        let branch = git_text(checkout, WORKTREE_ARGV[1]);
        let upstream = git_text(checkout, WORKTREE_ARGV[2]);

        WorktreeStatus {
            dirty: porcelain.ok.then(|| !porcelain.text.trim().is_empty()),
            branch: line_of(&branch),
            upstream: line_of(&upstream),
        }
    }
}

/// Fixed answers for tests.
#[derive(Debug, Clone, Default)]
pub struct MapWorktree {
    /// Status for one checkout path.
    pub by_path: BTreeMap<PathBuf, WorktreeStatus>,
    /// Status when `by_path` has no entry.
    pub default: WorktreeStatus,
}

impl WorktreeGit for MapWorktree {
    fn inspect(&self, checkout: &Path) -> WorktreeStatus {
        self.by_path
            .get(checkout)
            .cloned()
            .unwrap_or_else(|| self.default.clone())
    }
}

struct GitText {
    ok: bool,
    text: String,
}

fn git_text(path: &Path, args: &[&str]) -> GitText {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output();
    let Ok(output) = output else {
        return GitText {
            ok: false,
            text: String::new(),
        };
    };
    if !output.status.success() {
        return GitText {
            ok: false,
            text: String::new(),
        };
    }

    GitText {
        ok: true,
        text: String::from_utf8(output.stdout).unwrap_or_default(),
    }
}

fn line_of(text: &GitText) -> Option<String> {
    if !text.ok {
        return None;
    }
    let line = text.text.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worktree_git_is_three_fixed_commands() {
        assert_eq!(WORKTREE_ARGV.len(), 3);
        assert_eq!(WORKTREE_ARGV[0], ["status", "--porcelain"]);
        assert_eq!(WORKTREE_ARGV[1], ["rev-parse", "--abbrev-ref", "HEAD"]);
        assert_eq!(
            WORKTREE_ARGV[2],
            ["rev-parse", "--abbrev-ref", "@{upstream}"]
        );
    }
}
