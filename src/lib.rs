//! Read-only scan for regenerable caches and cold build outputs.
//!
//! [`scan`](scan::scan) never deletes, renames, or follows a symlink. A path
//! is a candidate only when a compiled-in rule names it. A denylisted prefix
//! wins over a rule, so a rule cannot be pointed at `/System` or a keychain
//! and produce a finding.
//!
//! Agent sessions, worktrees, and editor snapshots are not rules. They cannot
//! show up as something to remove.

#![deny(unsafe_code)]

pub mod cli;
pub mod config;
pub mod error;
pub mod git;
pub mod report;
pub mod rules;
pub mod scan;
pub mod walk;

pub use error::{Error, Result};
