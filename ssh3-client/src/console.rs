//! The local console of an interactive session.
//!
//! The console of the client is platform specific: unix drives the terminal
//! with termios and POSIX signals, Windows drives the console with the modes
//! of the Win32 API. The module hides the difference behind one small
//! surface, so that the session code of the client stays the same on every
//! platform.
//!
//! The behaviour follows the Go reference:
//!
//! - the console enters the raw mode for a session that owns a pty, and the
//!   mode is restored when the session ends,
//! - the size of the console is the size of the local terminal, and a
//!   console that cannot be queried falls back to 80x24,
//! - a resize of the console becomes a window-change request on the wire,
//! - the interrupts of the local console become signal requests on the wire.

#[cfg(not(any(unix, windows)))]
pub(crate) mod other;
#[cfg(unix)]
pub(crate) mod unix;
#[cfg(windows)]
pub(crate) mod windows;

#[cfg(not(any(unix, windows)))]
pub(crate) use self::other as platform;
#[cfg(unix)]
pub(crate) use self::unix as platform;
#[cfg(windows)]
pub(crate) use self::windows as platform;

pub use platform::detect_local_terminal;
pub(crate) use platform::{
    ConsoleModeGuard, PlatformTerminal, RawModeGuard, enable_console_modes, enable_raw_mode,
    spawn_resize_forwarder, spawn_signal_forwarders, suspend_local_process,
};
// The relay of the console events exists only where the control master
// does (see the control module gate): the with-variants of the watchers
// are unix only.
#[cfg(unix)]
pub(crate) use platform::{spawn_resize_forwarder_with, spawn_signal_forwarders_with};

use std::sync::{Arc, Mutex};

/// The size of the local console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalSize {
    /// The width of the console in characters.
    pub char_width: u16,
    /// The height of the console in characters.
    pub char_height: u16,
    /// The width of the console in pixels.
    pub pixel_width: u16,
    /// The height of the console in pixels.
    pub pixel_height: u16,
}

/// The metadata of the local console.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalTerminalInfo {
    /// The terminal type of the console, as the `TERM` variable reports it.
    pub term: Option<String>,
    /// The size of the console.
    pub size: TerminalSize,
}

/// The local console of the client.
pub struct LocalTerminal {
    /// The metadata of the console.
    pub info: LocalTerminalInfo,
    /// The platform specific handle of the console.
    pub(crate) platform: PlatformTerminal,
}

/// The handle of the raw mode guard of the local console.
///
/// The guard only exists where the console can be put in the raw mode;
/// elsewhere the handle stays empty. The mutex keeps the guard shareable
/// between the session and the stdin pump.
pub(crate) type RawModeGuardHandle = Option<Arc<Mutex<RawModeGuard>>>;

/// Builds a local terminal with the given metadata for the tests.
///
/// The platform handle is a placeholder: the tests that use it look at the
/// metadata of the console, not at the console itself.
#[cfg(test)]
pub(crate) fn test_local_terminal(info: LocalTerminalInfo) -> LocalTerminal {
    LocalTerminal {
        info,
        platform: platform::test_platform_terminal(),
    }
}
