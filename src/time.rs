//! UTC timestamps with no clock crate.
//!
//! Plan files and the action log store time as `YYYY-MM-DDTHH:MM:SSZ`.
//! Offsets and fractional seconds are rejected so one instant has one
//! spelling. The conversion is Howard Hinnant's civil-from-days algorithm.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Formats `time` as UTC RFC3339 with a `Z` suffix and no fraction.
///
/// Returns `None` when `time` is before the Unix epoch.
///
/// # Examples
///
/// ```
/// use disk_health::time::format_rfc3339;
/// use std::time::{Duration, SystemTime, UNIX_EPOCH};
///
/// let instant = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
/// assert_eq!(format_rfc3339(instant).as_deref(), Some("2027-01-15T08:00:00Z"));
/// ```
#[must_use]
pub fn format_rfc3339(time: SystemTime) -> Option<String> {
    let unix = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let (year, month, day, hour, minute, second) = ymd_hms(unix);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Parses the form produced by [`format_rfc3339`].
///
/// # Examples
///
/// ```
/// use disk_health::time::{format_rfc3339, parse_rfc3339};
/// use std::time::{Duration, SystemTime, UNIX_EPOCH};
///
/// let instant = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
/// let text = format_rfc3339(instant).unwrap();
/// assert_eq!(parse_rfc3339(&text), Some(instant));
/// ```
#[must_use]
pub fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let bytes = text.as_bytes();
    if bytes.len() != 20 || bytes[10] != b'T' || bytes[19] != b'Z' {
        return None;
    }
    let year = number(&bytes[0..4])?;
    let month = number(&bytes[5..7])?;
    let day = number(&bytes[8..10])?;
    let hour = number(&bytes[11..13])?;
    let minute = number(&bytes[14..16])?;
    let second = number(&bytes[17..19])?;
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let tod = u64::from(hour) * 3600 + u64::from(minute) * 60 + u64::from(second);
    let unix = days.checked_mul(86_400)?.checked_add(tod)?;
    let instant = UNIX_EPOCH.checked_add(Duration::from_secs(unix))?;
    // A date like February 31 still has a day number. Only a spelling that
    // formats back to itself is a real civil date.
    if format_rfc3339(instant).as_deref() != Some(text) {
        return None;
    }
    Some(instant)
}

/// Nanoseconds since the epoch, for plan identity fields.
///
/// # Examples
///
/// ```
/// use disk_health::time::unix_nanos;
/// use std::time::UNIX_EPOCH;
///
/// assert_eq!(unix_nanos(UNIX_EPOCH), Some(0));
/// ```
#[must_use]
pub fn unix_nanos(time: SystemTime) -> Option<u128> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
}

/// Inverse of [`unix_nanos`] for a non-negative timestamp.
///
/// # Examples
///
/// ```
/// use disk_health::time::{unix_nanos, from_unix_nanos};
/// use std::time::UNIX_EPOCH;
///
/// assert_eq!(from_unix_nanos(0), Some(UNIX_EPOCH));
/// assert_eq!(unix_nanos(from_unix_nanos(5).unwrap()), Some(5));
/// ```
#[must_use]
pub fn from_unix_nanos(nanos: u128) -> Option<SystemTime> {
    let secs = u64::try_from(nanos / 1_000_000_000).ok()?;
    let sub = u32::try_from(nanos % 1_000_000_000).ok()?;
    UNIX_EPOCH.checked_add(Duration::new(secs, sub))
}

fn ymd_hms(unix: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = unix / 86_400;
    let tod = unix % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = u32::try_from(tod / 3600).expect("hour fits in u32");
    let minute = u32::try_from((tod % 3600) / 60).expect("minute fits in u32");
    let second = u32::try_from(tod % 60).expect("second fits in u32");
    (year, month, day, hour, minute, second)
}

fn civil_from_days(days: u64) -> (i32, u32, u32) {
    let z = i64::try_from(days).expect("day count fits") + 719_468;
    let era = z.div_euclid(146_097);
    let doe = u64::try_from(z.rem_euclid(146_097)).expect("day of era is non-negative");
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let mut year = i64::try_from(yoe).expect("year of era fits") + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_index = (5 * doy + 2) / 153;
    let day = doy - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    if month <= 2 {
        year += 1;
    }
    let year = i32::try_from(year).expect("year fits in i32");
    let month = u32::try_from(month).expect("month fits in u32");
    let day = u32::try_from(day).expect("day fits in u32");
    (year, month, day)
}

fn days_from_civil(year: u32, month: u32, day: u32) -> Option<u64> {
    if month == 0 || month > 12 || day == 0 || day > 31 {
        return None;
    }
    let mut year = i64::from(year);
    if month <= 2 {
        year -= 1;
    }
    let era = year.div_euclid(400);
    let yoe = u64::try_from(year.rem_euclid(400)).ok()?;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * u64::from(month_index) + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let shifted = era * 146_097 + i64::try_from(doe).ok()? - 719_468;
    u64::try_from(shifted).ok()
}

fn number(bytes: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_instant() {
        assert_eq!(
            format_rfc3339(UNIX_EPOCH).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        let instant = UNIX_EPOCH + Duration::from_hours(500_000);
        assert_eq!(
            format_rfc3339(instant).as_deref(),
            Some("2027-01-15T08:00:00Z")
        );
        assert_eq!(parse_rfc3339("2027-01-15T08:00:00Z"), Some(instant));
    }

    #[test]
    fn rejects_offsets_and_fractions() {
        assert_eq!(parse_rfc3339("2027-01-15T08:00:00+00:00"), None);
        assert_eq!(parse_rfc3339("2027-01-15T08:00:00.0Z"), None);
    }

    #[test]
    fn random_seconds_round_trip() {
        let mut state = 0xD15C_5AFEu64;
        for _ in 0..200 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let unix = state % (86_400 * 365 * 200);
            let instant = UNIX_EPOCH + Duration::from_secs(unix);
            let text = format_rfc3339(instant).expect("instant is after the epoch");
            assert_eq!(parse_rfc3339(&text), Some(instant), "{text}");
        }
    }
}
