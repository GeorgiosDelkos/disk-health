//! Append-only record of moves.
//!
//! One JSON object per line. Restore and purge read it back and then still
//! check that the destination is inside a trash directory: a line is not
//! permission to unlink an arbitrary path. The id is a prefix of the SHA-256
//! of the other fields, so editing `to` without editing the id does not load.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{Error, Result};
use crate::hash::{self, sha256};
use crate::json::{self, Value};
use crate::time::{format_rfc3339, parse_rfc3339};

/// One successful rename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// Short hex id derived from the action fields.
    pub id: String,
    /// Plan that authorized the move.
    pub plan_id: String,
    /// Rule id.
    pub rule: String,
    /// Path before the rename.
    pub from: PathBuf,
    /// Path after the rename.
    pub to: PathBuf,
    /// `st_dev` at apply time.
    pub dev: u64,
    /// `st_ino` at apply time.
    pub ino: u64,
    /// Apparent size recorded in the plan.
    pub apparent_bytes: u64,
    /// When the rename was attempted.
    pub at: SystemTime,
}

impl Action {
    /// Fills [`Self::id`] from the other fields.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::log::Action;
    /// use std::path::PathBuf;
    /// use std::time::UNIX_EPOCH;
    ///
    /// let action = Action {
    ///     id: String::new(),
    ///     plan_id: "plan".to_owned(),
    ///     rule: "cargo-registry".to_owned(),
    ///     from: PathBuf::from("/cache"),
    ///     to: PathBuf::from("/trash/cache"),
    ///     dev: 1,
    ///     ino: 2,
    ///     apparent_bytes: 3,
    ///     at: UNIX_EPOCH,
    /// }
    /// .stamp();
    /// assert_eq!(action.id.len(), 32);
    /// ```
    #[must_use]
    pub fn stamp(mut self) -> Self {
        self.id = id_of(&self);
        self
    }
}

/// Where completed moves are stored.
pub trait ActionLog {
    /// Appends one action. The id must already match the fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the id does not match or the store cannot be written.
    fn append(&mut self, action: &Action) -> Result<()>;

    /// Reads every action back.
    ///
    /// # Errors
    ///
    /// Returns an error when a line is not the JSON this writer emits, or an
    /// id does not match its fields.
    fn load(&self) -> Result<Vec<Action>>;
}

/// In-memory log for tests.
#[derive(Debug, Default, Clone)]
pub struct MemoryLog {
    actions: Vec<Action>,
}

impl MemoryLog {
    /// Actions in append order.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::log::MemoryLog;
    ///
    /// assert!(MemoryLog::default().actions().is_empty());
    /// ```
    #[must_use]
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }
}

impl ActionLog for MemoryLog {
    fn append(&mut self, action: &Action) -> Result<()> {
        check_id(action)?;
        self.actions.push(action.clone());
        Ok(())
    }

    fn load(&self) -> Result<Vec<Action>> {
        Ok(self.actions.clone())
    }
}

/// `actions.jsonl` on disk.
#[derive(Debug, Clone)]
pub struct FileLog {
    path: PathBuf,
}

impl FileLog {
    /// Records that `path` is the log file. Parent directories are created on append.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::log::{ActionLog, FileLog};
    /// use std::path::Path;
    ///
    /// let log = FileLog::new(Path::new("/tmp/does-not-need-to-exist.jsonl"));
    /// assert!(log.load().is_ok());
    /// ```
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ActionLog for FileLog {
    fn append(&mut self, action: &Action) -> Result<()> {
        check_id(action)?;
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|source| Error::io("create log directory", parent, source))?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| Error::io("append action log", &self.path, source))?;
        let line = to_line(action);
        writeln!(file, "{line}")
            .map_err(|source| Error::io("append action log", &self.path, source))?;
        Ok(())
    }

    fn load(&self) -> Result<Vec<Action>> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(Error::io("read action log", &self.path, source)),
        };
        let mut actions = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let action = parse_line(line).map_err(|err| Error::Plan {
                message: format!("action log line {}: {err}", index + 1),
            })?;
            actions.push(action);
        }
        Ok(actions)
    }
}

fn check_id(action: &Action) -> Result<()> {
    if action.id == id_of(action) {
        Ok(())
    } else {
        Err(Error::Plan {
            message: "action id does not match its fields".to_owned(),
        })
    }
}

fn id_of(action: &Action) -> String {
    let at = format_rfc3339(action.at).unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned());
    let line = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{at}",
        action.plan_id,
        path_text(&action.from),
        path_text(&action.to),
        action.rule,
        action.dev,
        action.ino,
        action.apparent_bytes
    );
    let hex = hash::to_hex(&sha256(line.as_bytes()));
    hex[..32].to_owned()
}

fn to_line(action: &Action) -> String {
    let at = format_rfc3339(action.at).unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned());
    [
        format!("{{\"id\":\"{}\"", escape(&action.id)),
        format!("\"plan_id\":\"{}\"", escape(&action.plan_id)),
        format!("\"rule\":\"{}\"", escape(&action.rule)),
        format!("\"from\":\"{}\"", escape(&path_text(&action.from))),
        format!("\"to\":\"{}\"", escape(&path_text(&action.to))),
        format!("\"dev\":\"{}\"", action.dev),
        format!("\"ino\":\"{}\"", action.ino),
        format!("\"apparent_bytes\":{}", action.apparent_bytes),
        format!("\"at\":\"{at}\"}}"),
    ]
    .join(",")
}

fn escape(value: &str) -> String {
    let mut out = String::new();
    json::escape_into(&mut out, value);
    out
}

fn parse_line(line: &str) -> std::result::Result<Action, String> {
    let value = json::parse(line).map_err(|err| err.to_string())?;
    let map = value
        .as_object()
        .ok_or_else(|| "action is not an object".to_owned())?;
    let action = Action {
        id: field(map, "id")?,
        plan_id: field(map, "plan_id")?,
        rule: field(map, "rule")?,
        from: PathBuf::from(field(map, "from")?),
        to: PathBuf::from(field(map, "to")?),
        dev: digits(map, "dev")?,
        ino: digits(map, "ino")?,
        apparent_bytes: map
            .get("apparent_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| "apparent_bytes is not an integer".to_owned())?,
        at: parse_rfc3339(&field(map, "at")?).ok_or_else(|| "at is not utc rfc3339".to_owned())?,
    };
    if action.id != id_of(&action) {
        return Err("action id does not match its fields".to_owned());
    }
    Ok(action)
}

fn field(
    map: &std::collections::BTreeMap<String, Value>,
    key: &str,
) -> std::result::Result<String, String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{key} is not a string"))
}

fn digits(
    map: &std::collections::BTreeMap<String, Value>,
    key: &str,
) -> std::result::Result<u64, String> {
    let text = field(map, key)?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{key} is not a decimal string"));
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(format!("{key} is not a decimal string"));
    }
    text.parse().map_err(|_| format!("{key} is out of range"))
}

fn path_text(path: &Path) -> String {
    path.to_str()
        .map_or_else(|| path.to_string_lossy().into_owned(), ToOwned::to_owned)
}
