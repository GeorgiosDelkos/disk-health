//! Command line for the read-only scan.
//!
//! `scan` has no delete flag. A plan file written here is the JSON report,
//! not a request to remove anything.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::config::{self, RootStatus};
use crate::error::{Error, Result};
use crate::git::SystemGit;
use crate::report::{self, format_bytes};
use crate::scan::{self, ScanOptions};
use crate::walk::RealFs;

const HELP: &str = "\
disk-health scan

Read-only. Finds regenerable caches and cold build outputs.
Does not delete.

  disk-health scan [--format text|json] [--plan PATH]
                   [--fail-over SIZE] [--home PATH] [--root PATH]

SIZE is 500MiB or 20GiB (1024-based).
Exit 2 when staged safe bytes exceed --fail-over.
--root replaces project roots and may be repeated.
--plan writes the JSON report and does not delete anything.
";

/// Parsed argv, not including the program name.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Print help and exit 0.
    Help,
    /// Run a scan.
    Scan(ScanFlags),
}

/// Where the project walk gets its roots.
///
/// These two states are the whole set until the next version of the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectRoots {
    /// The config file, or the built-in defaults when that file is absent.
    FromConfig,
    /// Exactly these paths. An empty list walks no projects.
    Replace(Vec<PathBuf>),
}

/// Flags for [`Command::Scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanFlags {
    /// Text or JSON on stdout.
    pub format: Format,
    /// Where to write the JSON report, if requested.
    pub plan: Option<PathBuf>,
    /// Exit 2 when staged safe bytes are strictly greater than this.
    pub fail_over: Option<u64>,
    /// Home directory. `None` means `$HOME`.
    pub home: Option<PathBuf>,
    /// Project roots. [`ProjectRoots::Replace`] replaces config even when empty.
    pub roots: ProjectRoots,
}

impl Default for ScanFlags {
    fn default() -> Self {
        Self {
            format: Format::Text,
            plan: None,
            fail_over: None,
            home: None,
            roots: ProjectRoots::FromConfig,
        }
    }
}

/// Stdout format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// Multi-line report.
    #[default]
    Text,
    /// One JSON document.
    Json,
}

/// Parses `args`, whose first item is the program name, and runs the command.
///
/// # Errors
///
/// Returns an error for a bad flag, an unreadable config, or a plan path that
/// cannot be written. The scan itself skips paths it cannot read.
///
/// # Examples
///
/// ```
/// use disk_health::cli::main_from;
/// use std::ffi::OsString;
///
/// let code = main_from([OsString::from("disk-health"), OsString::from("--help")]).unwrap();
/// assert_eq!(code, 0);
/// ```
#[allow(clippy::print_stdout, reason = "help and the JSON report are stdout")]
pub fn main_from(args: impl IntoIterator<Item = OsString>) -> Result<i32> {
    match parse(args)? {
        Command::Help => {
            print!("{HELP}");
            Ok(0)
        }
        Command::Scan(flags) => execute_scan(&flags),
    }
}

/// Parses argv. The first item is the program name and is ignored.
///
/// # Errors
///
/// Returns [`Error::Usage`] when the command or a flag is not recognized.
///
/// # Examples
///
/// ```
/// use disk_health::cli::{Command, parse};
/// use std::ffi::OsString;
///
/// let command = parse([OsString::from("disk-health"), OsString::from("--help")]).unwrap();
/// assert!(matches!(command, Command::Help));
/// ```
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command> {
    let mut args = args.into_iter();
    if args.next().is_none() {
        return Err(usage());
    }
    let Some(command) = args.next() else {
        return Err(usage());
    };
    match command.to_str() {
        Some("scan") => parse_scan(args),
        Some("--help" | "-h" | "help") => Ok(Command::Help),
        Some(other) => Err(Error::Usage {
            message: format!("unknown command {other}\n{HELP}"),
        }),
        None => Err(Error::Usage {
            message: format!("argument is not utf-8\n{HELP}"),
        }),
    }
}

fn parse_scan(args: impl IntoIterator<Item = OsString>) -> Result<Command> {
    let mut flags = ScanFlags::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let Some(arg) = arg.to_str() else {
            return Err(Error::Usage {
                message: format!("argument is not utf-8\n{HELP}"),
            });
        };
        match arg {
            "--format" => {
                let value = need(&mut args, "--format")?;
                flags.format = parse_format(&value)?;
            }
            "--plan" => {
                let path = need(&mut args, "--plan")?;
                flags.plan = Some(PathBuf::from(path));
            }
            "--fail-over" => {
                let value = need(&mut args, "--fail-over")?;
                flags.fail_over = Some(config::parse_size(&value)?);
            }
            "--home" => {
                let path = need(&mut args, "--home")?;
                flags.home = Some(PathBuf::from(path));
            }
            "--root" => {
                let path = PathBuf::from(need(&mut args, "--root")?);
                match &mut flags.roots {
                    ProjectRoots::FromConfig => {
                        flags.roots = ProjectRoots::Replace(vec![path]);
                    }
                    ProjectRoots::Replace(roots) => roots.push(path),
                }
            }
            "--help" | "-h" => return Ok(Command::Help),
            other => {
                return Err(Error::Usage {
                    message: format!("unknown flag {other}\n{HELP}"),
                });
            }
        }
    }
    Ok(Command::Scan(flags))
}

fn parse_format(value: &str) -> Result<Format> {
    match value {
        "text" => Ok(Format::Text),
        "json" => Ok(Format::Json),
        _ => Err(Error::Usage {
            message: format!("--format must be text or json, not {value}\n{HELP}"),
        }),
    }
}

fn need(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<String> {
    let value = args.next().ok_or_else(|| Error::Usage {
        message: format!("{flag} needs a value\n{HELP}"),
    })?;
    value.into_string().map_err(|_| Error::Usage {
        message: format!("{flag} value is not utf-8\n{HELP}"),
    })
}

fn usage() -> Error {
    Error::Usage {
        message: HELP.to_owned(),
    }
}

#[allow(clippy::print_stdout, reason = "the scan report is stdout")]
#[allow(
    clippy::print_stderr,
    reason = "progress and the fail-over notice go to stderr"
)]
fn execute_scan(flags: &ScanFlags) -> Result<i32> {
    let home = match &flags.home {
        Some(home) => home.clone(),
        None => PathBuf::from(std::env::var_os("HOME").ok_or_else(|| Error::Config {
            message: "HOME is not set; pass --home".to_owned(),
        })?),
    };
    let loaded = config::load(&home)?;

    let requested = match &flags.roots {
        ProjectRoots::FromConfig => loaded.roots.clone(),
        ProjectRoots::Replace(roots) => roots.clone(),
    };
    let mut roots = Vec::new();
    let mut denied = Vec::new();
    for root in &requested {
        match config::prepare_root(root, &loaded.deny)? {
            RootStatus::Ready(path) | RootStatus::Missing(path) => roots.push(path),
            RootStatus::Denied(path) => denied.push(path),
        }
    }

    let filesystem = RealFs;
    let git = SystemGit;
    let progress = |visited: u64| {
        if visited.is_multiple_of(2_000) {
            eprintln!("visited {visited} directories");
        }
    };
    let mut report = scan::scan(&ScanOptions {
        home: &home,
        roots: &roots,
        safe_rules: &loaded.safe_rules,
        project_rules: &loaded.project_rules,
        deny: &loaded.deny,
        now: SystemTime::now(),
        git: &git,
        fs: &filesystem,
        progress: Some(&progress),
    })?;
    report.roots_denied.extend(denied);

    let json = report::to_json(&report);
    if let Some(path) = &flags.plan {
        std::fs::write(path, &json).map_err(|source| Error::io("write report", path, source))?;
    }

    match flags.format {
        Format::Json => println!("{json}"),
        Format::Text => report::write_text(&report),
    }

    if let Some(limit) = flags.fail_over {
        let bytes = report.safe_staged_bytes();
        if bytes > limit {
            eprintln!(
                "safe staged bytes {} exceed {}",
                format_bytes(bytes),
                format_bytes(limit)
            );
            return Ok(2);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        std::iter::once("disk-health")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn scan_flags_round_trip() {
        let command = parse(argv(&[
            "scan",
            "--format",
            "json",
            "--fail-over",
            "20GiB",
            "--root",
            "/tmp/one",
            "--root",
            "/tmp/two",
        ]))
        .unwrap();
        match command {
            Command::Scan(flags) => {
                assert_eq!(flags.format, Format::Json);
                assert_eq!(flags.fail_over, Some(20 * 1024 * 1024 * 1024));
                assert_eq!(
                    flags.roots,
                    ProjectRoots::Replace(vec![
                        PathBuf::from("/tmp/one"),
                        PathBuf::from("/tmp/two"),
                    ])
                );
            }
            Command::Help => panic!("expected scan"),
        }
    }

    #[test]
    fn unknown_flag_is_usage() {
        let err = parse(argv(&["scan", "--delete"])).unwrap_err();
        assert!(err.to_string().contains("unknown flag"));
    }

    #[test]
    fn no_command_is_usage() {
        let err = parse(argv(&[])).unwrap_err();
        assert!(err.to_string().contains("disk-health scan"));
    }
}
