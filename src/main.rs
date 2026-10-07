//! `disk-health` binary. The scan is read-only.

fn main() {
    let code = match disk_health::cli::main_from(std::env::args_os()) {
        Ok(code) => code,
        Err(err) => {
            print_error(&err);
            1
        }
    };
    std::process::exit(code);
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
