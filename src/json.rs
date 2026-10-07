//! The JSON subset plan files, the action log, and reports share.
//!
//! Objects, arrays, strings, booleans, null, and non-negative integers.
//! Floats, negatives, and leading zeros are rejected: device and inode
//! values are strings, and a byte count does not need a fraction. One
//! escape path is used by every writer so a quote in a path cannot be
//! encoded two different ways.

use std::collections::BTreeMap;
use std::fmt::Write;

/// One JSON value this crate reads or writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// JSON null.
    Null,
    /// JSON true or false.
    Bool(bool),
    /// Integer with no sign and no fraction.
    Number(u64),
    /// Decoded string.
    String(String),
    /// Array, order preserved.
    Array(Vec<Self>),
    /// Object. Keys are ordered so a rewritten file is stable.
    Object(BTreeMap<String, Self>),
}

/// Why a document was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    message: String,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for JsonError {}

impl Value {
    /// Borrows the string, if this is one.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::json::Value;
    ///
    /// assert_eq!(Value::String("a".to_owned()).as_str(), Some("a"));
    /// ```
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// Returns the integer, if this is one.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::json::Value;
    ///
    /// assert_eq!(Value::Number(3).as_u64(), Some(3));
    /// ```
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the boolean, if this is one.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::json::Value;
    ///
    /// assert_eq!(Value::Bool(true).as_bool(), Some(true));
    /// ```
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Reports whether this is null.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::json::Value;
    ///
    /// assert!(Value::Null.is_null());
    /// ```
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Borrows the object map, if this is one.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::json::Value;
    /// use std::collections::BTreeMap;
    ///
    /// assert!(Value::Object(BTreeMap::new()).as_object().is_some());
    /// ```
    #[must_use]
    pub const fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    /// Borrows the array, if this is one.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::json::Value;
    ///
    /// let value = Value::Array(Vec::new());
    /// assert!(value.as_array().unwrap().is_empty());
    /// ```
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// Parses one JSON document. Trailing data is an error.
///
/// # Errors
///
/// Returns an error when `input` is not the accepted subset.
///
/// # Examples
///
/// ```
/// use disk_health::json::{Value, parse};
///
/// let value = parse("{\"a\": 1}").unwrap();
/// assert_eq!(value.as_object().unwrap()["a"].as_u64(), Some(1));
/// ```
pub fn parse(input: &str) -> Result<Value, JsonError> {
    let mut parser = Parser { input, index: 0 };
    parser.skip_ws();
    let value = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.index != input.len() {
        return Err(parser.fail("trailing data"));
    }
    Ok(value)
}

/// Appends `value` as a JSON string body, without the surrounding quotes.
///
/// # Examples
///
/// ```
/// use disk_health::json::escape_into;
///
/// let mut out = String::new();
/// escape_into(&mut out, "a\"b\n");
/// assert_eq!(out, "a\\\"b\\n");
/// ```
pub fn escape_into(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let code = u32::from(ch);
                // `String`'s formatter does not fail.
                let _ = write!(out, "\\u{code:04x}");
            }
            ch => out.push(ch),
        }
    }
}

/// Writes `value` with a trailing newline. Objects use sorted keys.
///
/// # Examples
///
/// ```
/// use disk_health::json::{Value, write};
///
/// assert_eq!(write(&Value::Bool(true)), "true\n");
/// ```
#[must_use]
pub fn write(value: &Value) -> String {
    let mut out = String::new();
    write_pretty(&mut out, value, 0);
    out.push('\n');
    out
}

const MAX_DEPTH: u32 = 32;

struct Parser<'a> {
    input: &'a str,
    index: usize,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: u32) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return Err(self.fail("json nested too deeply"));
        }
        self.skip_ws();
        match self.peek() {
            Some('n') => self.literal("null", Value::Null),
            Some('t') => self.literal("true", Value::Bool(true)),
            Some('f') => self.literal("false", Value::Bool(false)),
            Some('"') => Ok(Value::String(self.parse_string()?)),
            Some('[') => self.parse_array(depth),
            Some('{') => self.parse_object(depth),
            Some(ch) if ch.is_ascii_digit() => Ok(Value::Number(self.parse_number()?)),
            _ => Err(self.fail("expected a json value")),
        }
    }

    fn literal(&mut self, text: &str, value: Value) -> Result<Value, JsonError> {
        if self.input[self.index..].starts_with(text) {
            self.index += text.len();
            Ok(value)
        } else {
            Err(self.fail("bad literal"))
        }
    }

    fn parse_array(&mut self, depth: u32) -> Result<Value, JsonError> {
        self.bump('[');
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(']') {
                self.index += 1;
                break;
            }
            if !items.is_empty() {
                self.expect(',')?;
            }
            items.push(self.parse_value(depth + 1)?);
        }
        Ok(Value::Array(items))
    }

    fn parse_object(&mut self, depth: u32) -> Result<Value, JsonError> {
        self.bump('{');
        let mut map = BTreeMap::new();
        loop {
            self.skip_ws();
            if self.peek() == Some('}') {
                self.index += 1;
                break;
            }
            if !map.is_empty() {
                self.expect(',')?;
                self.skip_ws();
            }
            if self.peek() != Some('"') {
                return Err(self.fail("expected an object key"));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(':')?;
            if map
                .insert(key.clone(), self.parse_value(depth + 1)?)
                .is_some()
            {
                return Err(self.fail("duplicate object key"));
            }
        }
        Ok(Value::Object(map))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.bump('"');
        let mut out = String::new();
        loop {
            let ch = self
                .next_char()
                .ok_or_else(|| self.fail("unterminated string"))?;
            match ch {
                '"' => return Ok(out),
                '\\' => out.push(self.escape()?),
                ch if ch.is_control() => return Err(self.fail("raw control character in string")),
                ch => out.push(ch),
            }
        }
    }

    fn escape(&mut self) -> Result<char, JsonError> {
        let ch = self
            .next_char()
            .ok_or_else(|| self.fail("truncated escape"))?;
        Ok(match ch {
            '"' | '\\' | '/' => ch,
            'b' => '\u{0008}',
            'f' => '\u{000c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => self.unicode()?,
            _ => return Err(self.fail("bad string escape")),
        })
    }

    fn unicode(&mut self) -> Result<char, JsonError> {
        let start = self.index;
        let end = start + 4;
        if end > self.input.len() {
            return Err(self.fail("short unicode escape"));
        }
        let hex = &self.input[start..end];
        self.index = end;
        let code = u32::from_str_radix(hex, 16).map_err(|_| self.fail("bad unicode escape"))?;
        char::from_u32(code).ok_or_else(|| self.fail("unicode escape is not a scalar"))
    }

    fn parse_number(&mut self) -> Result<u64, JsonError> {
        let start = self.index;
        let bytes = self.input.as_bytes();
        if bytes[start] == b'0' {
            self.index += 1;
            if self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                return Err(self.fail("leading zero"));
            }
            return Ok(0);
        }
        while self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
            self.index += 1;
        }
        if self
            .peek()
            .is_some_and(|ch| matches!(ch, '.' | 'e' | 'E' | '-' | '+'))
        {
            return Err(self.fail("json number must be an integer"));
        }
        self.input[start..self.index]
            .parse()
            .map_err(|_| self.fail("json number is out of range"))
    }

    fn skip_ws(&mut self) {
        while self
            .peek()
            .is_some_and(|ch| matches!(ch, ' ' | '\n' | '\r' | '\t'))
        {
            self.index += 1;
        }
    }

    fn expect(&mut self, want: char) -> Result<(), JsonError> {
        self.skip_ws();
        if self.peek() == Some(want) {
            self.index += want.len_utf8();
            Ok(())
        } else {
            Err(self.fail("unexpected character"))
        }
    }

    fn bump(&mut self, want: char) {
        debug_assert_eq!(self.peek(), Some(want));
        self.index += want.len_utf8();
    }

    fn peek(&self) -> Option<char> {
        self.input[self.index..].chars().next()
    }

    fn next_char(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.index += ch.len_utf8();
        Some(ch)
    }

    fn fail(&self, message: &str) -> JsonError {
        JsonError {
            message: format!("{message} at byte {}", self.index),
        }
    }
}

fn write_pretty(out: &mut String, value: &Value, indent: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => {
            out.push('"');
            escape_into(out, text);
            out.push('"');
        }
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Array(items) => write_list(out, items, indent),
        Value::Object(map) if map.is_empty() => out.push_str("{}"),
        Value::Object(map) => write_map(out, map, indent),
    }
}

fn write_list(out: &mut String, items: &[Value], indent: usize) {
    out.push_str("[\n");
    for (index, item) in items.iter().enumerate() {
        pad(out, indent + 2);
        write_pretty(out, item, indent + 2);
        if index + 1 != items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    pad(out, indent);
    out.push(']');
}

fn write_map(out: &mut String, map: &BTreeMap<String, Value>, indent: usize) {
    out.push_str("{\n");
    for (index, (key, value)) in map.iter().enumerate() {
        pad(out, indent + 2);
        out.push('"');
        escape_into(out, key);
        out.push_str("\": ");
        write_pretty(out, value, indent + 2);
        if index + 1 != map.len() {
            out.push(',');
        }
        out.push('\n');
    }
    pad(out, indent);
    out.push('}');
}

fn pad(out: &mut String, indent: usize) {
    out.push_str(&" ".repeat(indent));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_floats_negatives_and_leading_zeros() {
        assert!(parse("-1").is_err());
        assert!(parse("1.5").is_err());
        assert!(parse("01").is_err());
        assert!(parse("{\"a\":1,\"a\":2}").is_err());
    }

    #[test]
    fn string_round_trip_includes_controls() {
        let original = "quote \" slash \\ line\n tab\t unit\u{0001}";
        let mut escaped = String::from('"');
        escape_into(&mut escaped, original);
        escaped.push('"');
        let value = parse(&escaped).expect("escaped string is json");
        assert_eq!(value.as_str(), Some(original));
    }

    #[test]
    fn random_strings_round_trip() {
        let mut state = 0xD15C_5AFEu64;
        for iteration in 0..200 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut text = String::new();
            let len = usize::try_from(state % 24).expect("length fits");
            for index in 0..len {
                let code = u8::try_from((state >> (index % 8)) & 0x7f).expect("masked to 7 bits");
                if code == 0 {
                    text.push('x');
                } else {
                    text.push(char::from(code));
                }
            }
            let mut body = String::from('"');
            escape_into(&mut body, &text);
            body.push('"');
            let parsed = parse(&body).unwrap_or_else(|err| {
                panic!("seed {state:#x} iteration {iteration}: {err} body {body:?}")
            });
            assert_eq!(parsed.as_str(), Some(text.as_str()));
        }
    }
}
