//! The local console of the client on unix.
//!
//! The terminal is driven with termios: the raw mode takes the echo and the
//! line buffering away, and the POSIX signals carry the interrupts and the
//! resizes of the window.

use std::env;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::sync::Arc;

use nix::sys::termios::{self, SetArg};
use ssh3_core::Ssh3Channel;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;

use crate::console::{LocalTerminal, LocalTerminalInfo, RawModeGuardHandle, TerminalSize};
use crate::{Ssh3ClientError, send_signal_request, send_window_change_request};

/// The platform specific handle of the local console.
#[derive(Clone, Copy)]
pub(crate) struct PlatformTerminal {
    /// The file descriptor of the standard input.
    fd: RawFd,
}

/// The guard of the raw mode of the local console.
pub(crate) struct RawModeGuard {
    fd: RawFd,
    original: termios::Termios,
}

impl RawModeGuard {
    /// Restores the terminal state the guard captured.
    fn restore(&self) -> io::Result<()> {
        let fd = unsafe { BorrowedFd::borrow_raw(self.fd) };
        termios::tcsetattr(fd, SetArg::TCSANOW, &self.original).map_err(io::Error::from)
    }

    /// Enters the raw mode again, after a suspend resumed the process.
    fn reenter(&self) -> io::Result<()> {
        let fd = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let mut state = termios::tcgetattr(fd).map_err(io::Error::from)?;
        termios::cfmakeraw(&mut state);
        termios::tcsetattr(fd, SetArg::TCSANOW, &state).map_err(io::Error::from)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// The guard of the console modes of the local console.
///
/// The unix terminals process the escape sequences natively, so the guard has
/// nothing to restore.
pub(crate) struct ConsoleModeGuard;

impl Drop for ConsoleModeGuard {
    fn drop(&mut self) {}
}

/// Builds the platform handle of a local terminal for the tests.
#[cfg(test)]
pub(crate) fn test_platform_terminal() -> PlatformTerminal {
    PlatformTerminal { fd: 0 }
}

/// Turns the console modes of the local console on.
///
/// The unix terminals need no preparation: they process the escape sequences
/// and the UTF-8 text natively.
pub(crate) fn enable_console_modes() -> ConsoleModeGuard {
    ConsoleModeGuard
}

/// Detects the local console of the client.
pub fn detect_local_terminal() -> Result<Option<LocalTerminal>, Ssh3ClientError> {
    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
    let is_tty = unsafe { nix::libc::isatty(fd) } == 1;
    if !is_tty {
        return Ok(None);
    }

    Ok(Some(LocalTerminal {
        info: LocalTerminalInfo {
            term: env::var("TERM").ok().filter(|term| !term.is_empty()),
            size: read_terminal_size(fd)?,
        },
        platform: PlatformTerminal { fd },
    }))
}

/// Reads the size of the local terminal.
fn read_terminal_size(fd: RawFd) -> Result<TerminalSize, Ssh3ClientError> {
    let mut size = std::mem::MaybeUninit::<nix::libc::winsize>::zeroed();
    let result = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCGWINSZ, size.as_mut_ptr()) };
    if result == -1 {
        return Err(Ssh3ClientError::Io(io::Error::last_os_error()));
    }

    let size = unsafe { size.assume_init() };
    Ok(TerminalSize {
        char_width: size.ws_col,
        char_height: size.ws_row,
        pixel_width: size.ws_xpixel,
        pixel_height: size.ws_ypixel,
    })
}

/// Puts the local terminal into the raw mode.
pub(crate) fn enable_raw_mode(
    terminal: &PlatformTerminal,
) -> Result<RawModeGuard, Ssh3ClientError> {
    let fd = unsafe { BorrowedFd::borrow_raw(terminal.fd) };
    let mut termios_state = termios::tcgetattr(fd).map_err(io::Error::from)?;
    let original = termios_state.clone();
    termios::cfmakeraw(&mut termios_state);
    termios::tcsetattr(fd, SetArg::TCSANOW, &termios_state).map_err(io::Error::from)?;
    Ok(RawModeGuard {
        fd: fd.as_raw_fd(),
        original,
    })
}

/// Forwards the resizes of the local terminal to the server.
///
/// The unix terminal reports a resize through `SIGWINCH`; the request rides
/// out on the same channel request as on every other platform.
pub(crate) fn spawn_resize_forwarder(
    channel: Arc<Ssh3Channel>,
    terminal: PlatformTerminal,
) -> JoinHandle<()> {
    spawn_resize_forwarder_with(
        terminal,
        Arc::new(move |size| {
            let channel = channel.clone();
            tokio::spawn(async move {
                if send_window_change_request(channel.as_ref(), size)
                    .await
                    .is_err()
                {
                    // The channel died: the session is over anyway, and the
                    // caller owns the lifetime of the watcher.
                }
            });
        }),
    )
}

/// The sink of the resize watcher without a session channel: the control
/// master slave has no channel of its own, so the new size travels through
/// the callback (which relays it to the master over the control socket).
pub(crate) fn spawn_resize_forwarder_with(
    terminal: PlatformTerminal,
    on_resize: Arc<dyn Fn(TerminalSize) + Send + Sync>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut winsize_signal = match signal(SignalKind::window_change()) {
            Ok(signal) => signal,
            Err(_) => return,
        };

        while winsize_signal.recv().await.is_some() {
            let size = match read_terminal_size(terminal.fd) {
                Ok(size) => size,
                Err(_) => return,
            };
            on_resize(size);
        }
    })
}

/// Forwards the signals of the local terminal to the server.
///
/// The unix client forwards the signals of the session process as a whole;
/// the `interactive` flag of the Windows console is not used here.
pub(crate) fn spawn_signal_forwarders(
    channel: Arc<Ssh3Channel>,
    _interactive: bool,
) -> Vec<JoinHandle<()>> {
    spawn_signal_forwarders_with(Arc::new(move |signal_name| {
        let channel = channel.clone();
        tokio::spawn(async move {
            if send_signal_request(channel.as_ref(), signal_name)
                .await
                .is_err()
            {
                // The channel died: the session is over anyway, and the
                // caller owns the lifetime of the watcher.
            }
        });
    }))
}

/// The sink of the signal watcher without a session channel: the control
/// master slave relays the console interrupts to the master over the
/// control socket.
pub(crate) fn spawn_signal_forwarders_with(
    on_signal: Arc<dyn Fn(&'static str) + Send + Sync>,
) -> Vec<JoinHandle<()>> {
    [
        ("INT", SignalKind::interrupt()),
        ("TERM", SignalKind::terminate()),
        ("QUIT", SignalKind::quit()),
        ("HUP", SignalKind::hangup()),
    ]
    .into_iter()
    .filter_map(|(signal_name, kind)| {
        let mut signal = signal(kind).ok()?;
        let on_signal = on_signal.clone();
        Some(tokio::spawn(async move {
            while signal.recv().await.is_some() {
                on_signal(signal_name);
            }
        }))
    })
    .collect()
}

/// Suspends the client locally: the terminal is restored, the process stops
/// itself with `SIGTSTP` and the raw mode is entered again on resume.
pub(crate) fn suspend_local_process(guard: &RawModeGuardHandle) -> io::Result<()> {
    let Some(guard) = guard.as_ref() else {
        return Ok(());
    };
    let guard = guard
        .lock()
        .map_err(|_| io::Error::other("the raw mode guard is poisoned"))?;
    guard.restore()?;
    let result = unsafe { nix::libc::kill(nix::libc::getpid(), nix::libc::SIGTSTP) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    guard.reenter()
}
