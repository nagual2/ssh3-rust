//! The leveled log of the server.
//!
//! The `SSH3_LOG_LEVEL` / `SSH3_LOG_FILE` pair of the Go reference
//! (`cmd/ssh3-server.go:1234-1251`, `util/util.go:64`): the level names ride
//! the `zerolog` ladder, an unknown name keeps the default, and the file is
//! opened in the append mode. The records are the one-line JSON shapes of
//! the reference (`{"level":"info","time":...,"message":"..."}`), written to
//! the standard error under systemd and to the file otherwise.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// The levels of the `zerolog` ladder, from the chattiest to the quietest.
///
/// The order of the variants is the severity order: a message passes the
/// gate when its level is at least the configured one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// The rank of the level in the severity ladder, for the atomic gate.
    const fn rank(self) -> u8 {
        match self {
            LogLevel::Trace => 0,
            LogLevel::Debug => 1,
            LogLevel::Info => 2,
            LogLevel::Warn => 3,
            LogLevel::Error => 4,
        }
    }

    /// The level a rank stands for, the inverse of [`LogLevel::rank`].
    fn from_rank(rank: u8) -> Self {
        match rank {
            0 => LogLevel::Trace,
            1 => LogLevel::Debug,
            2 => LogLevel::Info,
            3 => LogLevel::Warn,
            _ => LogLevel::Error,
        }
    }

    /// The lowercase name the reference writes into the JSON records.
    pub const fn name(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    /// Parses a level name the way `util.ConfigureLogger` of the reference
    /// does (`util/util.go:64-79`): the names are case-insensitive, and the
    /// `warn` spelling lands on the same level the default case of the
    /// reference gives it.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "trace" => Some(LogLevel::Trace),
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warning" | "warn" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }

    /// Parses a level name, falling back to the default of the reference
    /// (`WarnLevel`): an unknown, empty or unset name keeps the default.
    pub fn parse_default(name: &str) -> Self {
        Self::parse(name).unwrap_or_default()
    }
}

impl Default for LogLevel {
    /// The default of `util.ConfigureLogger` of the reference: `warn`.
    fn default() -> Self {
        LogLevel::Warn
    }
}

/// The destination of the log: the standard error, or the file the
/// `SSH3_LOG_FILE` names.
enum Sink {
    Stderr,
    File(Mutex<File>),
}

static LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Warn.rank());
static SINK: OnceLock<Sink> = OnceLock::new();

/// The default log file of the reference (`cmd/ssh3-server.go:1244-1246`).
const DEFAULT_LOG_FILE: &str = "/var/log/ssh3.log";

/// The log file the daemon writes to; `None` keeps the standard error.
///
/// The reference skips the file when the run is under systemd — the journal
/// captures the standard error — and takes the `SSH3_LOG_FILE` value, or the
/// `/var/log/ssh3.log` default, otherwise.
pub fn effective_log_path(configured: Option<&Path>, under_systemd: bool) -> Option<PathBuf> {
    if under_systemd {
        return None;
    }
    Some(
        configured
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_FILE)),
    )
}

/// Installs the level and the destination of the log.
///
/// The file is opened in the append mode with the permissions of the
/// reference (`0644`); the failure surfaces to the caller, which ends the
/// run the way the reference does (`cmd/ssh3-server.go:1247-1250`).
pub fn init(level: LogLevel, path: Option<&Path>) -> std::io::Result<()> {
    let _ = SINK.set(match path {
        None => Sink::Stderr,
        Some(path) => {
            let mut options = OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o644);
            }
            Sink::File(Mutex::new(options.open(path)?))
        }
    });
    set_level(level);
    Ok(())
}

/// Sets the level of the gate.
///
/// The internal SFTP child uses it to match the error-only level of the
/// reference (`cmd/internal_sftp.go:40`).
pub fn set_level(level: LogLevel) {
    LEVEL.store(level.rank(), Ordering::Relaxed);
}

/// Whether a message of the level passes the gate now.
pub fn passes(level: LogLevel) -> bool {
    level.rank() >= LEVEL.load(Ordering::Relaxed)
}

/// The level the gate currently carries.
pub fn current_level() -> LogLevel {
    LogLevel::from_rank(LEVEL.load(Ordering::Relaxed))
}

/// Writes one message at the given level, through the gate.
pub fn write(level: LogLevel, message: &str) {
    if !passes(level) {
        return;
    }
    // The one-line JSON record of the reference: the level, the time and
    // the message, in the field order of the zerolog output.
    let mut line = String::with_capacity(message.len() + 64);
    line.push_str("{\"level\":\"");
    line.push_str(level.name());
    line.push_str("\",\"time\":\"");
    line.push_str(&rfc3339_utc(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0),
    ));
    line.push_str("\",\"message\":\"");
    json_escape(message, &mut line);
    line.push_str("\"}\n");
    match SINK.get() {
        Some(Sink::File(file)) => {
            if let Ok(mut file) = file.lock() {
                let _ = file.write_all(line.as_bytes());
            }
        }
        _ => {
            let _ = std::io::stderr().lock().write_all(line.as_bytes());
        }
    }
}

/// Writes a trace line through the gate of the server log.
#[macro_export]
macro_rules! log_trace {
    ($($argument:tt)*) => {
        $crate::logging::write($crate::logging::LogLevel::Trace, &format!($($argument)*))
    };
}

/// Writes a debug line through the gate of the server log.
#[macro_export]
macro_rules! log_debug {
    ($($argument:tt)*) => {
        $crate::logging::write($crate::logging::LogLevel::Debug, &format!($($argument)*))
    };
}

/// Writes an info line through the gate of the server log.
#[macro_export]
macro_rules! log_info {
    ($($argument:tt)*) => {
        $crate::logging::write($crate::logging::LogLevel::Info, &format!($($argument)*))
    };
}

/// Writes a warning line through the gate of the server log.
#[macro_export]
macro_rules! log_warn {
    ($($argument:tt)*) => {
        $crate::logging::write($crate::logging::LogLevel::Warn, &format!($($argument)*))
    };
}

/// Writes an error line through the gate of the server log.
#[macro_export]
macro_rules! log_error {
    ($($argument:tt)*) => {
        $crate::logging::write($crate::logging::LogLevel::Error, &format!($($argument)*))
    };
}

/// The UTC wall-clock time of the seconds since the Unix epoch, in the RFC
/// 3339 shape the reference records carry (`2026-11-11T09:00:00Z`).
fn rfc3339_utc(seconds: u64) -> String {
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let rest = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

/// The civil date of the days since the Unix epoch (Howard Hinnant's
/// `civil_from_days`), so the timestamps carry no date dependency.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Escapes the message into the JSON string shape, the control characters
/// included.
fn json_escape(message: &str, line: &mut String) {
    for character in message.chars() {
        match character {
            '"' => line.push_str("\\\""),
            '\\' => line.push_str("\\\\"),
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                line.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => line.push(character),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The level names of the reference parse, the case included; the
    /// unknown, empty and unset names keep the `warn` default
    /// (`util/util.go:64-79`).
    #[test]
    fn the_reference_level_names_parse() {
        assert_eq!(LogLevel::parse_default("trace"), LogLevel::Trace);
        assert_eq!(LogLevel::parse_default("Debug"), LogLevel::Debug);
        assert_eq!(LogLevel::parse_default("INFO"), LogLevel::Info);
        assert_eq!(LogLevel::parse_default("warning"), LogLevel::Warn);
        // The bare `warn` of the man page: the default case of the reference
        // lands on the same level for it.
        assert_eq!(LogLevel::parse_default("warn"), LogLevel::Warn);
        assert_eq!(LogLevel::parse_default("error"), LogLevel::Error);
        for garbage in ["", "warnin", "fatal", "panic", "0", "all", "INFO "] {
            assert_eq!(
                LogLevel::parse_default(garbage),
                LogLevel::Warn,
                "{garbage:?} keeps the default"
            );
        }
        assert_eq!(LogLevel::parse("garbage"), None);
    }

    /// The severity ladder gates the messages: a record passes when its
    /// level is at least the configured one.
    #[test]
    fn the_gate_uses_the_severity_order() {
        set_level(LogLevel::Info);
        assert!(passes(LogLevel::Info));
        assert!(passes(LogLevel::Warn));
        assert!(passes(LogLevel::Error));
        assert!(!passes(LogLevel::Debug));
        assert!(!passes(LogLevel::Trace));
        set_level(LogLevel::Warn);
        assert!(!passes(LogLevel::Info));
        set_level(LogLevel::Error);
        assert!(!passes(LogLevel::Warn));
        set_level(LogLevel::Trace);
        assert!(passes(LogLevel::Trace));
        // The gate comes back to the default of the reference.
        set_level(LogLevel::default());
        assert_eq!(current_level(), LogLevel::Warn);
    }

    /// The log file is created in the append mode, the messages ride the
    /// gate, and the records carry the JSON fields of the reference.
    #[test]
    fn the_log_file_is_created_and_appended() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ssh3.log");
        set_level(LogLevel::Info);
        init(LogLevel::Info, Some(&path)).unwrap();
        write(LogLevel::Debug, "hidden detail");
        write(LogLevel::Info, "the first line");
        // A second init keeps the file: the daemon appends across runs.
        init(LogLevel::Error, Some(&path)).unwrap();
        write(LogLevel::Error, "quote \" backslash \\ newline\nend");
        let contents = std::fs::read_to_string(&path).unwrap();
        let mut lines = contents.lines();
        let first = lines.next().unwrap();
        assert!(first.contains("\"level\":\"info\""), "{first}");
        assert!(first.contains("\"message\":\"the first line\""), "{first}");
        assert!(!contents.contains("hidden detail"));
        let last = contents.lines().last().unwrap();
        assert!(last.contains("\"level\":\"error\""), "{last}");
        assert!(
            last.contains("\"message\":\"quote \\\" backslash \\\\ newline\\nend\""),
            "{last}"
        );
        // The records are one line each: the escaped newline stays inside.
        assert_eq!(contents.lines().count(), 2);
    }

    /// The time of the records carries the RFC 3339 UTC shape of the
    /// reference output.
    #[test]
    fn the_timestamps_read_the_reference_shape() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(86_400), "1970-01-02T00:00:00Z");
        assert_eq!(rfc3339_utc(946_684_800), "2000-01-01T00:00:00Z");
        // The leap day of 2000, both sides of the midnight.
        assert_eq!(rfc3339_utc(951_868_799), "2000-02-29T23:59:59Z");
        assert_eq!(rfc3339_utc(951_868_800), "2000-03-01T00:00:00Z");
        // A contemporary stamp, cross-checked against `date -u`.
        assert_eq!(rfc3339_utc(1_762_145_600), "2025-11-03T04:53:20Z");
    }

    /// The log destination of the reference: the standard error under
    /// systemd, the `SSH3_LOG_FILE` value or the `/var/log/ssh3.log` default
    /// otherwise (`cmd/ssh3-server.go:1236-1246`).
    #[test]
    fn the_log_file_follows_the_reference_rules() {
        assert_eq!(effective_log_path(None, true), None);
        assert_eq!(
            effective_log_path(Some(Path::new("/tmp/x.log")), true),
            None
        );
        assert_eq!(
            effective_log_path(Some(Path::new("/tmp/x.log")), false),
            Some(PathBuf::from("/tmp/x.log"))
        );
        assert_eq!(
            effective_log_path(None, false),
            Some(PathBuf::from(DEFAULT_LOG_FILE))
        );
    }
}
