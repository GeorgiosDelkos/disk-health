//! Scan macOS for regenerable caches and cold build output.
//!
//! [`scan`](scan::scan) never deletes, renames, or follows a symlink. A path
//! is a candidate only when a compiled-in rule names it. A denylisted prefix
//! wins over a rule, so a rule cannot be pointed at `/System` or a keychain
//! and produce a finding.
//!
//! [`trash::apply`] is the only rename. It reads a plan file
//! and moves staged safe and caution entries on the same volume. Review
//! inventory is a different type and has no staged bit, so apply cannot
//! accept those rows.

#![deny(unsafe_code)]

pub mod cli;
pub mod config;
pub mod error;
pub mod git;
pub mod hash;
pub mod json;
pub mod log;
pub mod plan;
pub mod report;
pub mod review;
pub mod rules;
pub mod scan;
pub mod time;
pub mod trash;
pub mod tty;
pub mod ui;
pub mod usage;
pub mod volumes;
pub mod walk;

pub use error::{Error, Result};
pub use volumes::supported_here as platform_supported;
