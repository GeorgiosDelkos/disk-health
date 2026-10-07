//! Text and JSON renderings of a scan.
//!
//! JSON numbers are not exact past 2^53. Device, inode, and timestamp fields
//! are strings so a later plan file can round-trip them. Byte totals are
//! numbers because a disk this tool will see fits in that range.

use std::fmt::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::rules::Tier;
use crate::scan::{Finding, Report};

/// Renders `bytes` with a 1024-based unit and one decimal place.
///
/// # Examples
///
/// ```
/// use disk_health::report::format_bytes;
///
/// assert_eq!(format_bytes(1536), "1.5KiB");
/// ```
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;
    if bytes >= TIB {
        one_decimal(bytes, TIB, "TiB")
    } else if bytes >= GIB {
        one_decimal(bytes, GIB, "GiB")
    } else if bytes >= MIB {
        one_decimal(bytes, MIB, "MiB")
    } else if bytes >= KIB {
        one_decimal(bytes, KIB, "KiB")
    } else {
        format!("{bytes}B")
    }
}

fn one_decimal(bytes: u64, unit: u64, suffix: &str) -> String {
    let whole = bytes / unit;
    let frac = (bytes % unit) * 10 / unit;
    format!("{whole}.{frac}{suffix}")
}

/// Writes the human report to stdout.
///
/// # Examples
///
/// ```
/// use disk_health::report::write_text;
/// use disk_health::scan::Report;
///
/// let report = Report {
///     findings: Vec::new(),
///     unreadable: 0,
///     dirs_visited: 0,
///     roots_missing: Vec::new(),
///     roots_denied: Vec::new(),
/// };
/// write_text(&report);
/// ```
#[allow(
    clippy::print_stdout,
    reason = "this is the scan command's text report"
)]
pub fn write_text(report: &Report) {
    if report.findings.is_empty() {
        println!("no reclaim candidates");
    }
    for finding in &report.findings {
        let state = if finding.staged() {
            "staged"
        } else {
            "skipped"
        };
        println!(
            "{}  {state}  {}  {}",
            finding.tier.as_str(),
            format_bytes(finding.apparent_bytes),
            finding.rule
        );
        println!("      {}", finding.path.display());

        if let Some(skip) = finding.skip {
            println!("      skip: {}", skip.as_str());
        }
        if let Some(regenerate) = finding.regenerate {
            let verb = if finding.tier == Tier::Safe {
                "refill"
            } else {
                "rebuild"
            };
            println!("      {verb}: {regenerate}");
        }
        if let Some(marker) = &finding.marker {
            println!("      marker: {}", marker.display());
        }
        println!("      {}", finding.rationale);
    }

    println!();
    println!(
        "safe staged: {} ({})",
        report
            .findings
            .iter()
            .filter(|finding| finding.tier == Tier::Safe && finding.staged())
            .count(),
        format_bytes(report.safe_staged_bytes())
    );
    print_paths("roots missing", &report.roots_missing);
    print_paths("roots denied", &report.roots_denied);
    println!("unreadable entries: {}", report.unreadable);
    println!("project directories visited: {}", report.dirs_visited);
}

#[allow(
    clippy::print_stdout,
    reason = "this is the scan command's text report"
)]
fn print_paths(label: &str, paths: &[std::path::PathBuf]) {
    if paths.is_empty() {
        return;
    }
    println!("{label}:");
    for path in paths {
        println!("  {}", path.display());
    }
}

/// Serializes `report` as one JSON document.
///
/// # Examples
///
/// ```
/// use disk_health::report::to_json;
/// use disk_health::scan::Report;
///
/// let report = Report {
///     findings: Vec::new(),
///     unreadable: 0,
///     dirs_visited: 0,
///     roots_missing: Vec::new(),
///     roots_denied: Vec::new(),
/// };
/// assert!(to_json(&report).contains("\"kind\": \"scan\""));
/// ```
#[must_use]
pub fn to_json(report: &Report) -> String {
    let mut out = String::from("{\n");
    push_raw(&mut out, "schema", "1");
    out.push_str(",\n");
    push_string(&mut out, "kind", "scan");
    out.push_str(",\n");
    push_raw(
        &mut out,
        "safe_staged_bytes",
        &report.safe_staged_bytes().to_string(),
    );
    out.push_str(",\n");
    push_raw(&mut out, "unreadable", &report.unreadable.to_string());
    out.push_str(",\n");
    push_raw(&mut out, "dirs_visited", &report.dirs_visited.to_string());
    out.push_str(",\n");

    push_paths(&mut out, "roots_missing", &report.roots_missing);
    out.push_str(",\n");
    push_paths(&mut out, "roots_denied", &report.roots_denied);
    out.push_str(",\n  \"findings\": [\n");
    for (index, finding) in report.findings.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        push_finding(&mut out, finding);
    }
    out.push_str("\n  ]\n}\n");
    out
}

fn push_finding(out: &mut String, finding: &Finding) {
    out.push_str("    {\n");
    push_string_at(out, 6, "rule", finding.rule);
    out.push_str(",\n");
    push_string_at(out, 6, "tier", finding.tier.as_str());
    out.push_str(",\n");
    push_string_at(out, 6, "path", &display_path(&finding.path));
    out.push_str(",\n");
    push_string_at(out, 6, "dev", &finding.dev.to_string());
    out.push_str(",\n");
    push_string_at(out, 6, "ino", &finding.ino.to_string());
    out.push_str(",\n");

    push_time(out, "mtime_unix_ns", finding.mtime);
    out.push_str(",\n");
    push_time(out, "newest_unix_ns", finding.newest);
    out.push_str(",\n");

    push_raw_at(
        out,
        6,
        "apparent_bytes",
        &finding.apparent_bytes.to_string(),
    );
    out.push_str(",\n");
    push_raw_at(
        out,
        6,
        "staged",
        if finding.staged() { "true" } else { "false" },
    );
    out.push_str(",\n");

    match finding.skip {
        Some(skip) => push_string_at(out, 6, "skip", skip.as_str()),
        None => push_raw_at(out, 6, "skip", "null"),
    }
    out.push_str(",\n");
    match finding.regenerate {
        Some(value) => push_string_at(out, 6, "regenerate", value),
        None => push_raw_at(out, 6, "regenerate", "null"),
    }
    out.push_str(",\n");
    match &finding.marker {
        Some(path) => push_string_at(out, 6, "marker", &display_path(path)),
        None => push_raw_at(out, 6, "marker", "null"),
    }
    out.push_str(",\n");
    push_string_at(out, 6, "rationale", finding.rationale);
    out.push_str("\n    }");
}

fn push_time(out: &mut String, key: &str, time: Option<SystemTime>) {
    match time.and_then(unix_ns) {
        Some(nanos) => push_string_at(out, 6, key, &nanos),
        None => push_raw_at(out, 6, key, "null"),
    }
}

fn push_paths(out: &mut String, key: &str, paths: &[std::path::PathBuf]) {
    out.push_str("  \"");
    push_escaped(out, key);
    out.push_str("\": [");
    for (index, path) in paths.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push('"');
        push_escaped(out, &display_path(path));
        out.push('"');
    }
    out.push(']');
}

fn push_string(out: &mut String, key: &str, value: &str) {
    push_string_at(out, 2, key, value);
}

fn push_string_at(out: &mut String, indent: usize, key: &str, value: &str) {
    pad(out, indent);
    out.push('"');
    push_escaped(out, key);
    out.push_str("\": \"");
    push_escaped(out, value);
    out.push('"');
}

fn push_raw(out: &mut String, key: &str, value: &str) {
    push_raw_at(out, 2, key, value);
}

fn push_raw_at(out: &mut String, indent: usize, key: &str, value: &str) {
    pad(out, indent);
    out.push('"');
    push_escaped(out, key);
    out.push_str("\": ");
    out.push_str(value);
}

fn pad(out: &mut String, indent: usize) {
    out.push_str(&" ".repeat(indent));
}

fn push_escaped(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let code = u32::from(ch);
                write!(out, "\\u{code:04x}").expect("formatting into a String is infallible");
            }
            ch => out.push(ch),
        }
    }
}

fn display_path(path: &Path) -> String {
    path.to_str()
        .map_or_else(|| path.to_string_lossy().into_owned(), ToOwned::to_owned)
}

/// Nanoseconds since the Unix epoch, if `time` is representable.
fn unix_ns(time: SystemTime) -> Option<String> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_use_1024_and_one_decimal() {
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(1024), "1.0KiB");
        assert_eq!(format_bytes(1536), "1.5KiB");
    }

    #[test]
    fn json_escapes_quotes_and_newlines() {
        let escaped = {
            let mut out = String::new();
            push_escaped(&mut out, "a\"b\\c\nd");
            out
        };
        assert_eq!(escaped, r#"a\"b\\c\nd"#);
    }
}
