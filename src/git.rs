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
