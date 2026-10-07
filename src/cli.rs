//! Command line.
//!
//! `scan` has no delete flag. `--plan` writes a plan file, which `apply`
//! reads back. The scan report stays on stdout. With no subcommand, a
//! terminal starts the TUI and anything else prints help and exits 1.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::time::SystemTime;

use crate::config::{self, RootStatus};
use crate::error::{Error, Result};
use crate::git::{SystemGit, SystemWorktree};
use crate::log::FileLog;
use crate::plan::Plan;
use crate::report::{self, format_bytes};
use crate::scan::{self, ScanOptions};
use crate::trash::{self, ApplyRequest, FsRename, PurgeRequest, RestoreRequest};
use crate::tty::{self, Signals};
use crate::ui::{self, Session};
use crate::usage::{self, UsageNode};
use crate::volumes::{self, Volume};
use crate::walk::{Fs, RealFs};

const HELP: &str = "\
disk-health

Scan is read-only. apply renames only staged plan entries, and only
after --confirm matches the plan id. Review rows are not in the plan.

  disk-health
  disk-health scan [--format text|json] [--plan PATH]
                   [--fail-over SIZE] [--home PATH] [--root PATH]
  disk-health apply --plan PATH --confirm PLAN_ID [--home PATH]
  disk-health restore --id ACTION_ID [--home PATH]
  disk-health purge [--home PATH]
  disk-health usage [--volume PATH] [--format text|json] [--home PATH]
  disk-health tui [--home PATH]

SIZE is 500MiB or 20GiB (1024-based).
Exit 2 when staged safe bytes exceed --fail-over.
Exit 3 when apply skips a staged entry or cannot log a move.
--root replaces project roots and may be repeated.
--plan writes the plan file. It does not delete anything.
A terminal is required for the tui. Otherwise run scan --format text.
";

/// Parsed argv, not including the program name.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Print help and exit 0.
    Help,
    /// No subcommand. A terminal starts the TUI.
    Launch,
    /// Run a scan.
    Scan(ScanFlags),
    /// Rename staged plan entries.
    Apply(ApplyFlags),
    /// Put one logged path back.
    Restore(RestoreFlags),
    /// Unlink old quarantine entries.
    Purge(HomeFlags),
    /// Report-only usage tree.
    Usage(UsageFlags),
    /// Draw the three screens.
    Tui(HomeFlags),
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
    /// Where to write the plan file, if requested.
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

/// Flags for [`Command::Apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyFlags {
    /// Plan file written by `scan --plan`.
    pub plan: PathBuf,
    /// Must equal the plan id. Checked before any rename.
    pub confirm: String,
    /// Home directory. `None` means `$HOME`.
    pub home: Option<PathBuf>,
}

/// Flags for [`Command::Restore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreFlags {
    /// Action id from the log.
    pub id: String,
    /// Home directory. `None` means `$HOME`.
    pub home: Option<PathBuf>,
}

/// Commands whose only flag is `--home`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeFlags {
    /// Home directory. `None` means `$HOME`.
    pub home: Option<PathBuf>,
}

/// Flags for [`Command::Usage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageFlags {
    /// Volume to walk. `None` picks the longest walkable mount under home.
    pub volume: Option<PathBuf>,
    /// Text or JSON on stdout.
    pub format: Format,
    /// Home directory. `None` means `$HOME`.
    pub home: Option<PathBuf>,
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
/// Returns an error for a bad flag, an unreadable config, a plan that does
/// not match `--confirm`, or a path that cannot be written. A partial apply
/// is `Ok(3)`, not an error.
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
#[allow(clippy::print_stdout, reason = "help is stdout")]
pub fn main_from(args: impl IntoIterator<Item = OsString>) -> Result<i32> {
    dispatch(parse(args)?, tty::stdout_is_tty())
}

/// Parses argv. The first item is the program name and is ignored.
///
/// No subcommand is [`Command::Launch`], not a usage error. The caller
/// decides whether the terminal can draw the TUI.
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
        return Ok(Command::Launch);
    };
    match command.to_str() {
        Some("scan") => parse_scan(args),
        Some("apply") => parse_apply(args),
        Some("restore") => parse_restore(args),
        Some("purge") => parse_home_command(args, Command::Purge),
        Some("usage") => parse_usage(args),
        Some("tui") => parse_home_command(args, Command::Tui),
        Some("--help" | "-h" | "help") => Ok(Command::Help),
        Some(other) => Err(Error::Usage {
            message: format!("unknown command {other}\n{HELP}"),
        }),
        None => Err(Error::Usage {
            message: format!("argument is not utf-8\n{HELP}"),
        }),
    }
}

#[allow(clippy::print_stdout, reason = "help is stdout")]
fn dispatch(command: Command, stdout_is_tty: bool) -> Result<i32> {
    match command {
        Command::Help => {
            print!("{HELP}");
            Ok(0)
        }
        Command::Launch => {
            if stdout_is_tty {
                execute_tui(&HomeFlags { home: None }, true)
            } else {
                Err(usage())
            }
        }
        Command::Scan(flags) => execute_scan(&flags),
        Command::Apply(flags) => execute_apply(&flags),
        Command::Restore(flags) => execute_restore(&flags),
        Command::Purge(flags) => execute_purge(&flags),
        Command::Usage(flags) => execute_usage(&flags),
        Command::Tui(flags) => execute_tui(&flags, stdout_is_tty),
    }
}

fn parse_scan(args: impl IntoIterator<Item = OsString>) -> Result<Command> {
    let mut flags = ScanFlags::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let Some(arg) = arg.to_str() else {
            return Err(not_utf8());
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
            "--root" => push_root(&mut flags.roots, &need(&mut args, "--root")?),
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(unknown_flag(other)),
        }
    }
    Ok(Command::Scan(flags))
}

fn parse_apply(args: impl IntoIterator<Item = OsString>) -> Result<Command> {
    let mut plan = None;
    let mut confirm = None;
    let mut home = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let Some(arg) = arg.to_str() else {
            return Err(not_utf8());
        };
        match arg {
            "--plan" => plan = Some(PathBuf::from(need(&mut args, "--plan")?)),
            "--confirm" => confirm = Some(need(&mut args, "--confirm")?),
            "--home" => home = Some(PathBuf::from(need(&mut args, "--home")?)),
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(unknown_flag(other)),
        }
    }
    let plan = plan.ok_or_else(|| Error::Usage {
        message: format!("apply needs --plan\n{HELP}"),
    })?;
    let confirm = confirm.ok_or_else(|| Error::Usage {
        message: format!("apply needs --confirm\n{HELP}"),
    })?;
    Ok(Command::Apply(ApplyFlags {
        plan,
        confirm,
        home,
    }))
}

fn parse_restore(args: impl IntoIterator<Item = OsString>) -> Result<Command> {
    let mut id = None;
    let mut home = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let Some(arg) = arg.to_str() else {
            return Err(not_utf8());
        };
        match arg {
            "--id" => id = Some(need(&mut args, "--id")?),
            "--home" => home = Some(PathBuf::from(need(&mut args, "--home")?)),
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(unknown_flag(other)),
        }
    }
    let id = id.ok_or_else(|| Error::Usage {
        message: format!("restore needs --id\n{HELP}"),
    })?;
    Ok(Command::Restore(RestoreFlags { id, home }))
}

fn parse_usage(args: impl IntoIterator<Item = OsString>) -> Result<Command> {
    let mut volume = None;
    let mut format = Format::Text;
    let mut home = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let Some(arg) = arg.to_str() else {
            return Err(not_utf8());
        };
        match arg {
            "--volume" => volume = Some(PathBuf::from(need(&mut args, "--volume")?)),
            "--format" => {
                let value = need(&mut args, "--format")?;
                format = parse_format(&value)?;
            }
            "--home" => home = Some(PathBuf::from(need(&mut args, "--home")?)),
            "--help" | "-h" => return Ok(Command::Help),
            other => return Err(unknown_flag(other)),
        }
    }
    Ok(Command::Usage(UsageFlags {
        volume,
        format,
        home,
    }))
}

fn parse_home(args: impl IntoIterator<Item = OsString>) -> Result<Option<HomeFlags>> {
    let mut home = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let Some(arg) = arg.to_str() else {
            return Err(not_utf8());
        };
        match arg {
            "--home" => home = Some(PathBuf::from(need(&mut args, "--home")?)),
            "--help" | "-h" => return Ok(None),
            other => return Err(unknown_flag(other)),
        }
    }
    Ok(Some(HomeFlags { home }))
}

fn parse_home_command(
    args: impl IntoIterator<Item = OsString>,
    wrap: impl FnOnce(HomeFlags) -> Command,
) -> Result<Command> {
    match parse_home(args)? {
        Some(flags) => Ok(wrap(flags)),
        None => Ok(Command::Help),
    }
}

fn push_root(roots: &mut ProjectRoots, path: &str) {
    let path = PathBuf::from(path);
    match roots {
        ProjectRoots::FromConfig => *roots = ProjectRoots::Replace(vec![path]),
        ProjectRoots::Replace(list) => list.push(path),
    }
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

fn not_utf8() -> Error {
    Error::Usage {
        message: format!("argument is not utf-8\n{HELP}"),
    }
}

fn unknown_flag(flag: &str) -> Error {
    Error::Usage {
        message: format!("unknown flag {flag}\n{HELP}"),
    }
}

fn resolve_home(home: Option<&Path>) -> Result<PathBuf> {
    match home {
        Some(home) => Ok(home.to_path_buf()),
        None => std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| Error::Config {
                message: "HOME is not set; pass --home".to_owned(),
            }),
    }
}

fn hostname() -> String {
    let Ok(output) = Process::new("hostname").output() else {
        return "unknown".to_owned();
    };
    if !output.status.success() {
        return "unknown".to_owned();
    }
    let text = String::from_utf8(output.stdout).unwrap_or_default();
    let text = text.trim();
    if text.is_empty() {
        "unknown".to_owned()
    } else {
        text.to_owned()
    }
}

fn action_log(home: &Path) -> PathBuf {
    home.join("Library/Application Support/disk-health/actions.jsonl")
}

#[allow(clippy::print_stdout, reason = "the scan report is stdout")]
#[allow(
    clippy::print_stderr,
    reason = "progress and the fail-over notice go to stderr"
)]
fn execute_scan(flags: &ScanFlags) -> Result<i32> {
    let home = resolve_home(flags.home.as_deref())?;
    let loaded = config::load(&home)?;
    let (roots, denied) = prepare_roots(&flags.roots, &loaded)?;
    let now = SystemTime::now();
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
        now,
        git: &git,
        fs: &filesystem,
        progress: Some(&progress),
        on_finding: None,
    })?;
    report.roots_denied.extend(denied);
    let settings = std::fs::read_to_string(home.join(".rustup/settings.toml")).ok();
    report.review = crate::review::inventory(
        &filesystem,
        &home,
        now,
        &SystemWorktree,
        settings.as_deref(),
    );

    if let Some(path) = &flags.plan {
        write_plan(&report, path, now)?;
    }
    publish_scan(&report, flags.format);
    Ok(fail_over(&report, flags.fail_over))
}

fn prepare_roots(
    requested: &ProjectRoots,
    loaded: &config::Loaded,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let paths = match requested {
        ProjectRoots::FromConfig => &loaded.roots,
        ProjectRoots::Replace(roots) => roots,
    };
    let mut roots = Vec::new();
    let mut denied = Vec::new();
    for root in paths {
        match config::prepare_root(root, &loaded.deny)? {
            RootStatus::Ready(path) | RootStatus::Missing(path) => roots.push(path),
            RootStatus::Denied(path) => denied.push(path),
        }
    }
    Ok((roots, denied))
}

fn write_plan(report: &crate::scan::Report, path: &Path, now: SystemTime) -> Result<()> {
    let plan = Plan::from_report(report, &hostname(), now);
    std::fs::write(path, plan.to_json()).map_err(|source| Error::io("write plan", path, source))
}

#[allow(clippy::print_stdout, reason = "the scan report is stdout")]
fn publish_scan(report: &crate::scan::Report, format: Format) {
    match format {
        Format::Json => println!("{}", report::to_json(report)),
        Format::Text => report::write_text(report),
    }
}

#[allow(clippy::print_stderr, reason = "the fail-over notice goes to stderr")]
fn fail_over(report: &crate::scan::Report, limit: Option<u64>) -> i32 {
    let Some(limit) = limit else {
        return 0;
    };
    let bytes = report.safe_staged_bytes();
    if bytes > limit {
        eprintln!(
            "safe staged bytes {} exceed {}",
            format_bytes(bytes),
            format_bytes(limit)
        );
        return 2;
    }
    0
}

#[allow(clippy::print_stdout, reason = "apply prints what it moved")]
#[allow(clippy::print_stderr, reason = "apply prints why a row stayed")]
fn execute_apply(flags: &ApplyFlags) -> Result<i32> {
    let home = resolve_home(flags.home.as_deref())?;
    let loaded = config::load(&home)?;
    let text = std::fs::read_to_string(&flags.plan)
        .map_err(|source| Error::io("read plan", &flags.plan, source))?;
    let plan = Plan::parse(&text)?;
    let filesystem = RealFs;
    let home_meta = filesystem.meta(&home)?;
    let mut log = FileLog::new(action_log(&home));
    let renamer = FsRename;
    let signals = Signals::install_interrupt().ok();
    let report = trash::apply(ApplyRequest {
        plan: &plan,
        confirm: &flags.confirm,
        home: &home,
        home_dev: home_meta.dev,
        uid: volumes::current_uid(),
        deny: &loaded.deny,
        fs: &filesystem,
        renamer: &renamer,
        log: &mut log,
        now: SystemTime::now(),
        interrupt: signals.as_ref().map(|_| tty::interrupt_flag()),
    })?;
    for item in &report.moved {
        println!("moved {} -> {}", item.from.display(), item.to.display());
    }
    for item in &report.skipped {
        eprintln!("skipped {}: {}", item.path.display(), item.reason);
    }
    Ok(report.exit_code())
}

#[allow(clippy::print_stdout, reason = "restore prints the original path")]
fn execute_restore(flags: &RestoreFlags) -> Result<i32> {
    let home = resolve_home(flags.home.as_deref())?;
    let log = FileLog::new(action_log(&home));
    let renamer = FsRename;
    let path = trash::restore(&RestoreRequest {
        id: &flags.id,
        home: &home,
        uid: volumes::current_uid(),
        log: &log,
        renamer: &renamer,
    })?;
    println!("{}", path.display());
    Ok(0)
}

#[allow(clippy::print_stdout, reason = "purge prints what it unlinked")]
fn execute_purge(flags: &HomeFlags) -> Result<i32> {
    let home = resolve_home(flags.home.as_deref())?;
    let log = FileLog::new(action_log(&home));
    let report = trash::purge(&PurgeRequest {
        log: &log,
        now: SystemTime::now(),
    })?;
    for path in &report.removed {
        println!("purged {}", path.display());
    }
    println!(
        "removed {} ignored {}",
        report.removed.len(),
        report.ignored
    );
    Ok(0)
}

#[allow(clippy::print_stdout, reason = "the usage tree is stdout")]
fn execute_usage(flags: &UsageFlags) -> Result<i32> {
    let home = resolve_home(flags.home.as_deref())?;
    let volume = choose_volume(&home, flags.volume.as_deref())?;
    let tree = usage::walk(&RealFs, &volume, usage::DEFAULT_DEPTH)?;
    match flags.format {
        Format::Json => println!("{}", usage::to_json(&tree)),
        Format::Text => print_usage(&tree, 0),
    }
    Ok(0)
}

fn choose_volume(home: &Path, requested: Option<&Path>) -> Result<PathBuf> {
    if let Some(volume) = requested {
        return Ok(volume.to_path_buf());
    }
    let mounts = volumes::list_mounts()?;
    home_mount(home, &mounts).ok_or_else(|| Error::Usage {
        message: format!("pass --volume; home is not under a walkable mount\n{HELP}"),
    })
}

fn home_mount(home: &Path, mounts: &[Volume]) -> Option<PathBuf> {
    volumes::home_volume(home, mounts).map(|volume| volume.mount.clone())
}

#[allow(clippy::print_stdout, reason = "the usage tree is stdout")]
fn print_usage(node: &UsageNode, depth: usize) {
    let indent = "  ".repeat(depth);
    println!(
        "{indent}{}  {}",
        format_bytes(node.apparent_bytes),
        node.path.display()
    );
    for child in &node.children {
        print_usage(child, depth + 1);
    }
}

fn execute_tui(flags: &HomeFlags, stdout_is_tty: bool) -> Result<i32> {
    let home = resolve_home(flags.home.as_deref())?;
    let term = std::env::var("TERM").ok();
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let colorterm = std::env::var("COLORTERM").ok();
    ui::run(&Session {
        tty: stdout_is_tty,
        term: term.as_deref(),
        no_color,
        colorterm: colorterm.as_deref(),
        home: &home,
    })
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
        let Command::Scan(flags) = command else {
            panic!("expected scan");
        };
        assert_eq!(flags.format, Format::Json);
        assert_eq!(flags.fail_over, Some(20 * 1024 * 1024 * 1024));
        assert_eq!(
            flags.roots,
            ProjectRoots::Replace(vec![PathBuf::from("/tmp/one"), PathBuf::from("/tmp/two")])
        );
    }

    #[test]
    fn unknown_flag_is_usage() {
        let err = parse(argv(&["scan", "--delete"])).unwrap_err();
        assert!(err.to_string().contains("unknown flag"));
    }

    #[test]
    fn no_command_launches_and_a_captured_stdout_is_usage() {
        assert!(matches!(parse(argv(&[])).unwrap(), Command::Launch));
        let err = dispatch(Command::Launch, false).unwrap_err();
        assert!(err.to_string().contains("scan --format text"));
    }

    #[test]
    fn apply_requires_plan_and_confirm() {
        let err = parse(argv(&["apply", "--plan", "/tmp/plan.json"])).unwrap_err();
        assert!(err.to_string().contains("--confirm"));
        let command = parse(argv(&[
            "apply",
            "--plan",
            "/tmp/plan.json",
            "--confirm",
            "abc",
            "--home",
            "/tmp/home",
        ]))
        .unwrap();
        let Command::Apply(flags) = command else {
            panic!("expected apply");
        };
        assert_eq!(flags.confirm, "abc");
        assert_eq!(flags.home.as_deref(), Some(Path::new("/tmp/home")));
    }

    #[test]
    fn restore_requires_an_id() {
        let err = parse(argv(&["restore"])).unwrap_err();
        assert!(err.to_string().contains("--id"));
    }
}
