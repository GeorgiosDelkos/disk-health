//! `disk-health` binary.
//!
//! Scan is read-only. `apply` is the command that renames, and only after
//! the plan id matches.

fn main() {
    if !disk_health::platform_supported() {
        refuse_platform();
        std::process::exit(1);
    }
    let code = match disk_health::cli::main_from(std::env::args_os()) {
        Ok(code) => code,
        Err(err) => {
            print_error(&err);
            1
        }
    };
    std::process::exit(code);
}

#[allow(
    clippy::print_stderr,
    reason = "a non-macOS binary has no other channel"
)]
fn refuse_platform() {
    eprintln!("disk-health: disk-health runs on macOS");
}

#[allow(clippy::print_stderr, reason = "operational errors go to stderr")]
fn print_error(err: &disk_health::Error) {
    eprintln!("disk-health: {err}");
    let mut source = std::error::Error::source(err);
    while let Some(next) = source {
        eprintln!("  caused by: {next}");
        source = next.source();
    }
}
