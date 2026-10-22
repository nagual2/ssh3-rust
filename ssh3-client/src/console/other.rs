//! The local console of the client on the platforms without a console.
//!
//! The client still runs there, but the session is not interactive: there is
//! no terminal to read the size of, no raw mode to enter and no signal to
//! forward.

use std::io;
use std::sync::Arc;

use ssh3_core::Ssh3Channel;
use tokio::task::JoinHandle;

use crate::Ssh3ClientError;
use crate::console::{LocalTerminal, RawModeGuardHandle};

/// The platform specific handle of the local console.
#[derive(Clone, Copy)]
pub(crate) struct PlatformTerminal;

/// The guard of the raw mode of the local console.
pub(crate) struct RawModeGuard;

/// The guard of the console modes of the local console.
pub(crate) struct ConsoleModeGuard;

/// Builds the platform handle of a local terminal for the tests.
#[cfg(test)]
pub(crate) fn test_platform_terminal() -> PlatformTerminal {
    PlatformTerminal
}

/// Detects the local console of the client.
pub(crate) fn detect_local_terminal() -> Result<Option<LocalTerminal>, Ssh3ClientError> {
    Ok(None)
}

/// Turns the console modes of the local console on.
pub(crate) fn enable_console_modes() -> ConsoleModeGuard {
    ConsoleModeGuard
}

/// Puts the local console into the raw mode.
pub(crate) fn enable_raw_mode(
    _terminal: &PlatformTerminal,
) -> Result<RawModeGuard, Ssh3ClientError> {
    Err(Ssh3ClientError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "this platform has no console to put into the raw mode",
    )))
}

/// Forwards the resizes of the local console to the server.
pub(crate) fn spawn_resize_forwarder(
    _channel: Arc<Ssh3Channel>,
    _terminal: PlatformTerminal,
) -> JoinHandle<()> {
    tokio::spawn(async {})
}

/// Forwards the signals of the local console to the server.
pub(crate) fn spawn_signal_forwarders(
    _channel: Arc<Ssh3Channel>,
    _interactive: bool,
) -> Vec<JoinHandle<()>> {
    Vec::new()
}

/// Suspends the client locally.
pub(crate) fn suspend_local_process(_guard: &RawModeGuardHandle) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the local console cannot suspend the process",
    ))
}
