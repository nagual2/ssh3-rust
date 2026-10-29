//! The diagnostic levels of the client.
//!
//! The `-q` flag of the ssh2 canon suppresses the diagnostics while the
//! errors stay, the `-v` flag adds the details of the connection, and the
//! default level carries the ordinary status lines. The flags of the
//! reference (`-v` / `-q`, PARITY H1) ride the same spelling.

use std::sync::atomic::{AtomicU8, Ordering};

const QUIET: u8 = 1;
const NORMAL: u8 = 2;
const VERBOSE: u8 = 3;

static LEVEL: AtomicU8 = AtomicU8::new(NORMAL);

/// Applies the `-q` / `-v` pair of the command line. The parser refuses
/// the conflicting pair, so the order of the checks here is free.
pub fn configure(quiet: bool, verbose: bool) {
    let level = if quiet {
        QUIET
    } else if verbose {
        VERBOSE
    } else {
        NORMAL
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
}
