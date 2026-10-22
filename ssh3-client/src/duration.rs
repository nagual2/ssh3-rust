//! Parsing of the duration values of the command line.
//!
//! The Go implementation parses its timeout options with `time.ParseDuration`,
//! so the Rust client accepts the same syntax: a possibly signed sequence of
//! decimal numbers, each with an optional fraction and a unit suffix
//! ("300ms", "-1.5h", "2h45m"). The valid units are "ns", "us" (or "µs"),
//! "ms", "s", "m" and "h"; the bare value "0" is a duration of zero.

use std::fmt;
use std::time::Duration;

/// The error of a duration the Go syntax does not accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3DurationError {
    value: String,
    reason: &'static str,
}

impl Ssh3DurationError {
    fn new(value: &str, reason: &'static str) -> Self {
        Self {
            value: value.to_string(),
            reason,
        }
    }
}

impl fmt::Display for Ssh3DurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "time: invalid duration {:?}: {}",
            self.value, self.reason
        )
    }
}

impl std::error::Error for Ssh3DurationError {}

/// Parses a duration with the syntax of Go's `time.ParseDuration`.
///
/// A negative duration is refused: the client uses the durations as timeouts,
/// and a negative timeout has no meaning.
pub fn parse_duration(value: &str) -> Result<Duration, Ssh3DurationError> {
    let original = value;
    let trimmed = value.trim();
    let rest = match trimmed.strip_prefix('-') {
        Some(_) => {
            return Err(Ssh3DurationError::new(original, "negative duration"));
        }
        None => trimmed.strip_prefix('+').unwrap_or(trimmed),
    };

    if rest.is_empty() {
        return Err(Ssh3DurationError::new(original, "invalid duration"));
    }
    if rest == "0" {
        return Ok(Duration::ZERO);
    }

    let bytes = rest.as_bytes();
    let mut index = 0usize;
    let mut total_seconds = 0f64;
    while index < bytes.len() {
        let integer_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == integer_start {
            return Err(Ssh3DurationError::new(original, "invalid duration"));
        }
        let mut number: f64 = rest[integer_start..index]
            .parse()
            .map_err(|_| Ssh3DurationError::new(original, "invalid duration"))?;

        if index < bytes.len() && bytes[index] == b'.' {
            index += 1;
            let fraction_start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if index == fraction_start {
                return Err(Ssh3DurationError::new(original, "invalid duration"));
            }
            let fraction: f64 = format!("0.{}", &rest[fraction_start..index])
                .parse()
                .map_err(|_| Ssh3DurationError::new(original, "invalid duration"))?;
            number += fraction;
        }

        let unit_start = index;
        while index < bytes.len() && !bytes[index].is_ascii_digit() && bytes[index] != b'.' {
            index += 1;
        }
        let unit = &rest[unit_start..index];
        let multiplier = match unit {
            "ns" => 1e-9,
            "us" | "\u{00b5}s" | "\u{03bc}s" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "" => return Err(Ssh3DurationError::new(original, "missing unit in duration")),
            _ => return Err(Ssh3DurationError::new(original, "unknown unit in duration")),
        };
        total_seconds += number * multiplier;
    }

    if !total_seconds.is_finite() || total_seconds < 0.0 {
        return Err(Ssh3DurationError::new(original, "invalid duration"));
    }
    if total_seconds > u64::MAX as f64 {
        return Err(Ssh3DurationError::new(original, "duration out of range"));
    }
    Ok(Duration::from_secs_f64(total_seconds))
}

#[cfg(test)]
mod tests {
    use super::parse_duration;
    use std::time::Duration;

    #[test]
    fn parses_the_go_duration_syntax() {
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("120s").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::from_secs(5_400));
        assert_eq!(parse_duration("2h45m").unwrap(), Duration::from_secs(9_900));
        assert_eq!(parse_duration("300ms").unwrap(), Duration::from_millis(300));
        assert_eq!(parse_duration("500us").unwrap(), Duration::from_micros(500));
        assert_eq!(parse_duration("500ns").unwrap(), Duration::from_nanos(500));
        assert_eq!(parse_duration(" 90s ").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("+90s").unwrap(), Duration::from_secs(90));
    }

    #[test]
    fn refuses_the_values_the_go_syntax_refuses() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("120").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("1x").is_err());
        assert!(parse_duration("1.").is_err());
        assert!(parse_duration("-1s").is_err());
    }
}
