//! Plan file: the only input `apply` will act on.
//!
//! `plan_id` is the hex SHA-256 of the entry identities, sorted, one per
//! line. The line is tier, path, device, inode, both mtimes, and staged.
//! Host, scan time, apparent size, and the refill text are not in the hash:
//! editing them must not look like a different plan, and editing a path or
//! flipping `staged` must. Device, inode, and timestamps are JSON strings
//! because a JSON number is not exact past 2^53.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{Error, Result};
use crate::hash::{self, sha256};
use crate::json::{self, Value};
use crate::rules::Tier;
use crate::scan::{Finding, Report};
use crate::time::{format_rfc3339, parse_rfc3339, unix_nanos};

/// Schema this writer emits and this parser accepts.
pub const SCHEMA: u32 = 1;

/// One path a later apply may move.
///
/// The fields are the whole record until the next plan schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Rule id.
    pub rule: String,
    /// Safe or caution. Review is not representable here.
    pub tier: Tier,
    /// Candidate path.
    pub path: PathBuf,
    /// `st_dev` at scan time.
    pub dev: u64,
    /// `st_ino` at scan time.
    pub ino: u64,
    /// Mtime of the candidate, nanoseconds since the epoch.
    pub mtime_ns: Option<u128>,
    /// Newest mtime in the candidate tree.
    pub newest_child_ns: Option<u128>,
    /// Apparent size at scan time. Not part of [`Plan::plan_id`].
    pub apparent_bytes: u64,
    /// Whether apply should move it.
    pub staged: bool,
    /// How to get the bytes back.
    pub regenerate: Option<String>,
    /// Marker the caution rule recorded. Absent means apply will not move it.
    pub marker: Option<PathBuf>,
}

/// A sealed plan. The id matches the entries or the value was not built here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Plan {
    /// [`SCHEMA`].
    pub schema: u32,
    /// Hex SHA-256 of the sorted identity lines.
    pub plan_id: String,
    /// Hostname recorded for the operator. Not part of the id.
    pub host: String,
    /// When the scan ran.
    pub scanned_at: SystemTime,
    /// Every safe and caution finding, staged or not.
    pub entries: Vec<Entry>,
}

impl Plan {
    /// Builds a plan from a scan.
    ///
    /// Unstaged caution rows stay in the file so the id covers the choice
    /// not to move them. They are not a request to delete.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::plan::Plan;
    /// use disk_health::scan::Report;
    /// use std::time::UNIX_EPOCH;
    ///
    /// let plan = Plan::from_report(&Report::empty(), "host", UNIX_EPOCH);
    /// assert_eq!(plan.entries.len(), 0);
    /// assert!(!plan.plan_id.is_empty());
    /// ```
    pub fn from_report(report: &Report, host: &str, scanned_at: SystemTime) -> Self {
        let entries = report.findings.iter().map(Entry::from_finding).collect();
        Self::from_entries(entries, host, scanned_at)
    }

    /// Seals `entries`. Order in the slice does not change the id.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::plan::{Entry, Plan};
    /// use disk_health::rules::Tier;
    /// use std::path::PathBuf;
    /// use std::time::UNIX_EPOCH;
    ///
    /// let entry = Entry {
    ///     rule: "cargo-registry".to_owned(),
    ///     tier: Tier::Safe,
    ///     path: PathBuf::from("/cache"),
    ///     dev: 1,
    ///     ino: 2,
    ///     mtime_ns: Some(3),
    ///     newest_child_ns: Some(4),
    ///     apparent_bytes: 9,
    ///     staged: true,
    ///     regenerate: None,
    ///     marker: None,
    /// };
    /// let plan = Plan::from_entries(vec![entry], "host", UNIX_EPOCH);
    /// assert_eq!(plan.plan_id.len(), 64);
    /// ```
    pub fn from_entries(mut entries: Vec<Entry>, host: &str, scanned_at: SystemTime) -> Self {
        entries.sort_by_key(identity);
        let plan_id = id_of(&entries);
        Self {
            schema: SCHEMA,
            plan_id,
            host: host.to_owned(),
            scanned_at,
            entries,
        }
    }

    /// Apparent bytes of staged entries.
    ///
    /// This is the total a person has to type back. Caution counts once it
    /// was staged. Unstaged rows do not.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::plan::Plan;
    /// use disk_health::scan::Report;
    /// use std::time::UNIX_EPOCH;
    ///
    /// let plan = Plan::from_report(&Report::empty(), "host", UNIX_EPOCH);
    /// assert_eq!(plan.staged_bytes(), 0);
    /// ```
    #[must_use]
    pub fn staged_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|entry| entry.staged)
            .fold(0, |sum, entry| sum.saturating_add(entry.apparent_bytes))
    }

    /// Writes the plan document.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::plan::Plan;
    /// use disk_health::scan::Report;
    /// use std::time::UNIX_EPOCH;
    ///
    /// let json = Plan::from_report(&Report::empty(), "host", UNIX_EPOCH).to_json();
    /// assert!(json.contains("\"schema\": 1"));
    /// ```
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\n");
        push_raw(&mut out, 2, "schema", &self.schema.to_string());
        out.push_str(",\n");
        push_str(&mut out, 2, "plan_id", &self.plan_id);
        out.push_str(",\n");
        push_str(&mut out, 2, "host", &self.host);
        out.push_str(",\n");
        let scanned =
            format_rfc3339(self.scanned_at).unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned());
        push_str(&mut out, 2, "scanned_at", &scanned);
        out.push_str(",\n");
        out.push_str("  \"entries\": [\n");
        for (index, entry) in self.entries.iter().enumerate() {
            if index > 0 {
                out.push_str(",\n");
            }
            push_entry(&mut out, entry);
        }
        out.push_str("\n  ]\n}\n");
        out
    }

    /// Reads a plan and rejects an id that does not match the entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Plan`] when the document is not schema 1, a tier is
    /// not safe or caution, or the stored id was edited.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::plan::Plan;
    /// use disk_health::scan::Report;
    /// use std::time::UNIX_EPOCH;
    ///
    /// let plan = Plan::from_report(&Report::empty(), "host", UNIX_EPOCH);
    /// let loaded = Plan::parse(&plan.to_json()).unwrap();
    /// assert_eq!(loaded.plan_id, plan.plan_id);
    /// ```
    pub fn parse(text: &str) -> Result<Self> {
        let value = json::parse(text).map_err(|err| plan_err(err.to_string()))?;
        let map = object(&value)?;
        let schema = required(map, "schema")?
            .as_u64()
            .ok_or_else(|| plan_err("schema is not an integer"))?;
        if schema != u64::from(SCHEMA) {
            return Err(plan_err(format!("plan schema {schema} is not {SCHEMA}")));
        }

        let plan_id = text_field(map, "plan_id")?;
        let host = text_field(map, "host")?;
        let scanned_at = parse_rfc3339(&text_field(map, "scanned_at")?)
            .ok_or_else(|| plan_err("scanned_at is not utc rfc3339"))?;
        let entries = parse_entries(required(map, "entries")?)?;
        let computed = id_of(&entries);
        if computed != plan_id {
            return Err(plan_err("plan id does not match the entries"));
        }

        Ok(Self {
            schema: SCHEMA,
            plan_id,
            host,
            scanned_at,
            entries,
        })
    }
}

impl Entry {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            rule: finding.rule.to_owned(),
            tier: finding.tier,
            path: finding.path.clone(),
            dev: finding.dev,
            ino: finding.ino,
            mtime_ns: finding.mtime.and_then(unix_nanos),
            newest_child_ns: finding.newest.and_then(unix_nanos),
            apparent_bytes: finding.apparent_bytes,
            staged: finding.staged(),
            regenerate: finding.regenerate.map(str::to_owned),
            marker: finding.marker.clone(),
        }
    }
}

impl Report {
    /// An empty report, for callers that only need the shape.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::scan::Report;
    ///
    /// assert!(Report::empty().findings.is_empty());
    /// ```
    pub fn empty() -> Self {
        Self {
            findings: Vec::new(),
            unreadable: 0,
            dirs_visited: 0,
            roots_missing: Vec::new(),
            roots_denied: Vec::new(),
            review: Vec::new(),
        }
    }
}

fn id_of(entries: &[Entry]) -> String {
    let mut lines = entries.iter().map(identity).collect::<Vec<_>>();
    lines.sort();
    hash::to_hex(&sha256(lines.join("\n").as_bytes()))
}

fn identity(entry: &Entry) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        entry.tier.as_str(),
        path_text(&entry.path),
        entry.dev,
        entry.ino,
        ns_text(entry.mtime_ns),
        ns_text(entry.newest_child_ns),
        u8::from(entry.staged)
    )
}

fn ns_text(value: Option<u128>) -> String {
    value.map_or_else(String::new, |value| value.to_string())
}

fn path_text(path: &Path) -> String {
    path.to_str()
        .map_or_else(|| path.to_string_lossy().into_owned(), ToOwned::to_owned)
}

fn parse_entries(value: &Value) -> Result<Vec<Entry>> {
    let items = value
        .as_array()
        .ok_or_else(|| plan_err("entries is not an array"))?;
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        entries.push(parse_entry(item)?);
    }
    Ok(entries)
}

fn parse_entry(value: &Value) -> Result<Entry> {
    let map = object(value)?;
    let tier = match text_field(map, "tier")?.as_str() {
        "safe" => Tier::Safe,
        "caution" => Tier::Caution,
        "review" => return Err(plan_err("tier review is not a plan entry")),
        other => return Err(plan_err(format!("unknown tier {other}"))),
    };

    Ok(Entry {
        rule: text_field(map, "rule")?,
        tier,
        path: PathBuf::from(text_field(map, "path")?),
        dev: digits(map, "dev")?,
        ino: digits(map, "ino")?,
        mtime_ns: optional_digits(map, "mtime_ns")?,
        newest_child_ns: optional_digits(map, "newest_child_ns")?,
        apparent_bytes: required(map, "apparent_bytes")?
            .as_u64()
            .ok_or_else(|| plan_err("apparent_bytes is not an integer"))?,
        staged: required(map, "staged")?
            .as_bool()
            .ok_or_else(|| plan_err("staged is not a boolean"))?,
        regenerate: optional_text(map, "regenerate")?,
        marker: optional_text(map, "marker")?.map(PathBuf::from),
    })
}

fn object(value: &Value) -> Result<&std::collections::BTreeMap<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| plan_err("expected a json object"))
}

fn required<'a>(
    map: &'a std::collections::BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a Value> {
    map.get(key)
        .ok_or_else(|| plan_err(format!("missing {key}")))
}

fn text_field(map: &std::collections::BTreeMap<String, Value>, key: &str) -> Result<String> {
    required(map, key)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| plan_err(format!("{key} is not a string")))
}

fn digits(map: &std::collections::BTreeMap<String, Value>, key: &str) -> Result<u64> {
    let text = text_field(map, key)?;
    parse_u128(&text)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| plan_err(format!("{key} is not a decimal string")))
}

fn optional_digits(
    map: &std::collections::BTreeMap<String, Value>,
    key: &str,
) -> Result<Option<u128>> {
    let value = required(map, key)?;
    if value.is_null() {
        return Ok(None);
    }
    let text = value
        .as_str()
        .ok_or_else(|| plan_err(format!("{key} is not a string")))?;
    parse_u128(text)
        .map(Some)
        .ok_or_else(|| plan_err(format!("{key} is not a decimal string")))
}

fn optional_text(
    map: &std::collections::BTreeMap<String, Value>,
    key: &str,
) -> Result<Option<String>> {
    let value = required(map, key)?;
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .map(|text| Some(text.to_owned()))
        .ok_or_else(|| plan_err(format!("{key} is not a string")))
}

fn parse_u128(text: &str) -> Option<u128> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

fn push_entry(out: &mut String, entry: &Entry) {
    out.push_str("    {\n");
    push_str(out, 6, "rule", &entry.rule);
    out.push_str(",\n");
    push_str(out, 6, "tier", entry.tier.as_str());
    out.push_str(",\n");
    push_str(out, 6, "path", &path_text(&entry.path));
    out.push_str(",\n");
    push_str(out, 6, "dev", &entry.dev.to_string());
    out.push_str(",\n");
    push_str(out, 6, "ino", &entry.ino.to_string());
    out.push_str(",\n");
    push_ns(out, "mtime_ns", entry.mtime_ns);
    out.push_str(",\n");
    push_ns(out, "newest_child_ns", entry.newest_child_ns);
    out.push_str(",\n");
    push_raw(out, 6, "apparent_bytes", &entry.apparent_bytes.to_string());
    out.push_str(",\n");
    push_raw(
        out,
        6,
        "staged",
        if entry.staged { "true" } else { "false" },
    );
    out.push_str(",\n");
    push_optional(out, "regenerate", entry.regenerate.as_deref());
    out.push_str(",\n");
    push_optional(
        out,
        "marker",
        entry.marker.as_deref().map(path_text).as_deref(),
    );
    out.push_str("\n    }");
}

fn push_ns(out: &mut String, key: &str, value: Option<u128>) {
    match value {
        Some(value) => push_str(out, 6, key, &value.to_string()),
        None => push_raw(out, 6, key, "null"),
    }
}

fn push_optional(out: &mut String, key: &str, value: Option<&str>) {
    match value {
        Some(value) => push_str(out, 6, key, value),
        None => push_raw(out, 6, key, "null"),
    }
}

fn push_str(out: &mut String, indent: usize, key: &str, value: &str) {
    pad(out, indent);
    out.push('"');
    json::escape_into(out, key);
    out.push_str("\": \"");
    json::escape_into(out, value);
    out.push('"');
}

fn push_raw(out: &mut String, indent: usize, key: &str, value: &str) {
    pad(out, indent);
    out.push('"');
    json::escape_into(out, key);
    out.push_str("\": ");
    out.push_str(value);
}

fn pad(out: &mut String, indent: usize) {
    out.push_str(&" ".repeat(indent));
}

fn plan_err(message: impl Into<String>) -> Error {
    Error::Plan {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    fn sample(staged: bool, bytes: u64) -> Entry {
        Entry {
            rule: "cargo-registry".to_owned(),
            tier: Tier::Safe,
            path: PathBuf::from("/cache"),
            dev: 7,
            ino: 9,
            mtime_ns: Some(11),
            newest_child_ns: Some(13),
            apparent_bytes: bytes,
            staged,
            regenerate: Some("cargo fetch".to_owned()),
            marker: None,
        }
    }

    #[test]
    fn id_ignores_order_host_and_size_and_tracks_staged() {
        let forward = Plan::from_entries(vec![sample(true, 1), sample(false, 2)], "a", UNIX_EPOCH);
        let backward = Plan::from_entries(
            vec![sample(false, 99), sample(true, 1)],
            "b",
            UNIX_EPOCH + std::time::Duration::from_secs(5),
        );
        assert_eq!(forward.plan_id, backward.plan_id);

        let flipped = Plan::from_entries(vec![sample(false, 1)], "a", UNIX_EPOCH);
        let staged = Plan::from_entries(vec![sample(true, 1)], "a", UNIX_EPOCH);
        assert_ne!(flipped.plan_id, staged.plan_id);
    }

    #[test]
    fn round_trip_and_review_tier_is_rejected() {
        let plan = Plan::from_entries(vec![sample(true, 4)], "host", UNIX_EPOCH);
        let loaded = Plan::parse(&plan.to_json()).unwrap();
        assert_eq!(loaded, plan);

        let mut edited = plan.to_json();
        edited = edited.replace("\"safe\"", "\"review\"");
        let err = Plan::parse(&edited).unwrap_err();
        assert!(err.to_string().contains("review"), "{err}");
    }

    #[test]
    fn edited_id_is_rejected() {
        let plan = Plan::from_entries(vec![sample(true, 4)], "host", UNIX_EPOCH);
        let edited = plan.to_json().replace(&plan.plan_id, &"ab".repeat(32));
        let err = Plan::parse(&edited).unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }
}
