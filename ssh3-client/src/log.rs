//! The diagnostic levels of the client.
//!
//! The `-q` flag of the ssh2 canon suppresses the diagnostics while the
//! errors stay, the `-v` flag adds the details of the connection, and the
//! default level carries the ordinary status lines. The flags of the
//! reference (`-v` / `-q`, PARITY H1) ride the same spelling, and the
//! `SSH3_LOG_LEVEL` of the reference (`cmd/ssh3.go:1335-1343`) folds onto
//! the same ladder.

use std::sync::atomic::{AtomicU8, Ordering};

const QUIET: u8 = 1;
const NORMAL: u8 = 2;
const VERBOSE: u8 = 3;

static LEVEL: AtomicU8 = AtomicU8::new(NORMAL);

/// Applies the `-q` / `-v` pair of the command line. The parser refuses
/// the conflicting pair, so the order of the checks here is free.
pub fn configure(quiet: bool, verbose: bool) {
    configure_with_env(quiet, verbose, None);
}

/// Applies the `-q` / `-v` pair and the `SSH3_LOG_LEVEL` of the environment,
/// with the precedence of the reference (`cmd/ssh3.go:1335-1343`): the exact
/// lowercase `trace` spelling of the variable beats both flags, every other
/// name yields to the flags, and the unset or unknown names keep the
/// ordinary default of the client.
///
/// The five levels of the reference fold onto the three levels of the
/// client by severity: `error` and `warning` quiet the client, `info`
/// carries the ordinary level, `debug` and `trace` add the details.
pub fn configure_with_env(quiet: bool, verbose: bool, log_level: Option<&str>) {
    if quiet && log_level != Some("trace") {
        LEVEL.store(QUIET, Ordering::Relaxed);
        return;
    }
    if verbose && log_level != Some("trace") {
        LEVEL.store(VERBOSE, Ordering::Relaxed);
        return;
    }
    let level = match log_level.map(|name| name.to_ascii_lowercase()).as_deref() {
        Some("trace") | Some("debug") => VERBOSE,
        Some("info") => NORMAL,
        // The error and warning names quiet the client: the ladder of the
        // reference has no rung between them and the errors.
        Some("warning") | Some("warn") | Some("error") => QUIET,
        // The unset or unknown names keep the default of the client: the
        // ordinary status lines ride.
        _ => NORMAL,
    };
    LEVEL.store(level, Ordering::Relaxed);
}

/// Writes an error: the level every mode keeps.
pub fn error(message: &str) {
    eprintln!("{message}");
}

/// Writes an ordinary diagnostic: visible by default, hidden by `-q`.
pub fn info(message: &str) {
    if LEVEL.load(Ordering::Relaxed) >= NORMAL {
        eprintln!("{message}");
    }
}

/// Writes a detail: visible under `-v` only.
pub fn debug(message: &str) {
    if LEVEL.load(Ordering::Relaxed) >= VERBOSE {
        eprintln!("{message}");
    }
}

/// Writes an error line through the level gate.
#[macro_export]
macro_rules! diag_error {
    ($($argument:tt)*) => { $crate::log::error(&format!($($argument)*)) };
}

/// Writes an ordinary diagnostic line through the level gate.
#[macro_export]
macro_rules! diag_info {
    ($($argument:tt)*) => { $crate::log::info(&format!($($argument)*)) };
}

/// Writes a detail line through the level gate.
#[macro_export]
macro_rules! diag_debug {
    ($($argument:tt)*) => { $crate::log::debug(&format!($($argument)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_levels_ride_the_flags() {
        configure(false, false);
        assert_eq!(LEVEL.load(Ordering::Relaxed), NORMAL);

        configure(false, true);
        assert_eq!(LEVEL.load(Ordering::Relaxed), VERBOSE);

        configure(true, false);
        assert_eq!(LEVEL.load(Ordering::Relaxed), QUIET);

        // The level of one invocation must not leak into the next one.
        configure(false, false);
        assert_eq!(LEVEL.load(Ordering::Relaxed), NORMAL);
    }

    /// The `SSH3_LOG_LEVEL` of the reference rides the precedence of
    /// `cmd/ssh3.go:1335-1343`: the exact `trace` spelling beats both flags,
    /// every other name yields to them, and the names fold onto the three
    /// levels of the client by severity.
    #[test]
    fn the_env_level_folds_onto_the_client_levels() {
        // The exact `trace` spelling beats `-q` and `-v` alike.
        configure_with_env(true, false, Some("trace"));
        assert_eq!(LEVEL.load(Ordering::Relaxed), VERBOSE);
        configure_with_env(false, true, Some("trace"));
        assert_eq!(LEVEL.load(Ordering::Relaxed), VERBOSE);
        // Any other spelling yields to the flags, the case of the variable
        // including: the reference compares the raw `trace` spelling.
        configure_with_env(true, false, Some("TRACE"));
        assert_eq!(LEVEL.load(Ordering::Relaxed), QUIET);
        configure_with_env(true, false, Some("info"));
        assert_eq!(LEVEL.load(Ordering::Relaxed), QUIET);
        configure_with_env(false, true, Some("error"));
        assert_eq!(LEVEL.load(Ordering::Relaxed), VERBOSE);

        // Without a flag the names fold by severity; the parse of the
        // reference is case-insensitive (`util.ConfigureLogger`).
        for (name, expected) in [
            ("error", QUIET),
            ("warning", QUIET),
            ("warn", QUIET),
            ("ERROR", QUIET),
            ("info", NORMAL),
            ("debug", VERBOSE),
            ("DEBUG", VERBOSE),
            ("garbage", NORMAL),
            ("", NORMAL),
        ] {
            configure_with_env(false, false, Some(name));
            assert_eq!(
                LEVEL.load(Ordering::Relaxed),
                expected,
                "{name:?} folds onto the wrong level"
            );
        }

        // The unset variable keeps the ordinary default of the client.
        configure_with_env(false, false, None);
        assert_eq!(LEVEL.load(Ordering::Relaxed), NORMAL);
    }
}
