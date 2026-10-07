//! The TUI in a real pseudo-terminal. `script(1)` provides the terminal and
//! `stty` gives it a size, so this fails if the window size is not read.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// Columns of the rule under the title in the first frame the UI draws.
fn rule_columns(rows: u16, columns: u16) -> usize {
    let home = std::env::temp_dir().join(format!(
        "disk-health-pty-{}-{rows}x{columns}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("fixture home can be created");

    let run = format!(
        "stty rows {rows} cols {columns} && exec '{}' tui --home '{}'",
        env!("CARGO_BIN_EXE_disk-health"),
        home.display()
    );
    let mut child = Command::new("script")
        .args(["-q", "/dev/null", "sh", "-c", &run])
        .env("TERM", "xterm-256color")
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("script(1) is on macOS");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stdin = child.stdin.take().expect("stdin is piped");

    // Read until the rule has been drawn, however long the UI takes to
    // start, and only then ask it to quit.
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    let mut rule = None;
    while rule.is_none() {
        let read = stdout.read(&mut buf).expect("the pty can be read");
        if read == 0 {
            break;
        }
        seen.extend_from_slice(&buf[..read]);
        let text = String::from_utf8_lossy(&seen);
        rule = text
            .split("\r\n")
            .map(|line| line.chars().filter(|ch| *ch == '─').count())
            .find(|dashes| *dashes > 0);
    }
    stdin.write_all(b"q").expect("the pty takes a key");
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&home);

    rule.unwrap_or_else(|| panic!("no frame: {}", String::from_utf8_lossy(&seen)))
}

#[test]
fn the_frame_is_as_wide_as_the_terminal() {
    // Neither is the built-in 80, so a size that was not read shows.
    assert_eq!(rule_columns(31, 97), 97);
    assert_eq!(rule_columns(20, 52), 52);
}
