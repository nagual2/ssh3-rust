//! The local console of the client on Windows.
//!
//! The Windows console has no termios and no POSIX signals: the console
//! modes of the Win32 API drive the input and the output, and the control
//! events of the console carry the interrupts. The module follows the Go
//! reference (`client/signals_windows.go`, `client/winsize`):
//!
//! - the input handle enters the raw mode: the echo, the line buffering and
//!   the processed input are cleared, and the keys arrive as VT sequences
//!   (`ENABLE_VIRTUAL_TERMINAL_INPUT`),
//! - the output handles interpret the escape sequences of the remote side
//!   (`ENABLE_VIRTUAL_TERMINAL_PROCESSING`) and both code pages switch to
//!   UTF-8, so that the remote UTF-8 text renders correctly,
//! - the size of the console is the size of the visible window of the screen
//!   buffer; a console that cannot be queried falls back to 80x24,
//! - a resize is polled: Windows has no `SIGWINCH`, and draining the console
//!   input events for a resize notification would steal the keystrokes of
//!   the stdin pump,
//! - the control events of the console carry the interrupts: `CTRL_C_EVENT`
//!   and `CTRL_BREAK_EVENT` become `SIGINT`, the close, the logoff and the
//!   shutdown events become `SIGTERM`.

use std::env;
use std::ffi::c_void;
use std::io;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use ssh3_core::Ssh3Channel;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::console::{LocalTerminal, LocalTerminalInfo, RawModeGuardHandle, TerminalSize};
use crate::{Ssh3ClientError, send_signal_request, send_window_change_request};

/// The standard input handle of the process.
const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
/// The standard output handle of the process.
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
/// The standard error handle of the process.
const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4;

/// The console mode that processes the Ctrl+C key of the keyboard.
const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
/// The console mode that buffers the input until the enter key.
const ENABLE_LINE_INPUT: u32 = 0x0002;
/// The console mode that echoes the typed characters.
const ENABLE_ECHO_INPUT: u32 = 0x0004;
/// The console mode that interprets the escape sequences of the output.
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
/// The console mode that reads the keys as VT sequences.
const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;

/// The code page of UTF-8.
const CP_UTF8: u32 = 65001;

/// The control event of the Ctrl+C key.
const CTRL_C_EVENT: u32 = 0;
/// The control event of the Ctrl+Break key.
const CTRL_BREAK_EVENT: u32 = 1;
/// The control event of the closing of the console.
const CTRL_CLOSE_EVENT: u32 = 2;
/// The control event of the logoff of the session.
const CTRL_LOGOFF_EVENT: u32 = 5;
/// The control event of the shutdown of the system.
const CTRL_SHUTDOWN_EVENT: u32 = 6;

/// The width of a console that cannot be queried.
const DEFAULT_COLUMNS: u16 = 80;
/// The height of a console that cannot be queried.
const DEFAULT_ROWS: u16 = 24;

/// The interval of the polling of the console geometry.
const RESIZE_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The handle of a console.
///
/// The handle is kept as an integer, so that the guards of the console stay
/// `Send` and can travel between the tasks of the runtime.
type ConsoleHandle = usize;

/// The routine of the console control handler.
type CtrlHandlerRoutine = unsafe extern "system" fn(ctrl_type: u32) -> i32;

/// The coordinates of a console.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Coord {
    x: i16,
    y: i16,
}

/// A rectangle of a console.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SmallRect {
    left: i16,
    top: i16,
    right: i16,
    bottom: i16,
}

/// The state of the screen buffer of a console.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ConsoleScreenBufferInfo {
    size: Coord,
    cursor_position: Coord,
    attributes: u16,
    window: SmallRect,
    maximum_window_size: Coord,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetStdHandle(n_std_handle: u32) -> *mut c_void;
    fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
    fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
    fn GetConsoleScreenBufferInfo(handle: *mut c_void, info: *mut ConsoleScreenBufferInfo) -> i32;
    fn GetConsoleCP() -> u32;
    fn SetConsoleCP(code_page: u32) -> i32;
    fn GetConsoleOutputCP() -> u32;
    fn SetConsoleOutputCP(code_page: u32) -> i32;
    fn SetConsoleCtrlHandler(handler: Option<CtrlHandlerRoutine>, add: i32) -> i32;
}

/// The platform specific handle of the local console.
#[derive(Clone, Copy)]
pub struct PlatformTerminal {
    /// The handle of the console input.
    input: ConsoleHandle,
    /// Tells whether the geometry of the console can be queried.
    size_available: bool,
}

/// The guard of the raw mode of the local console.
pub(crate) struct RawModeGuard {
    handle: ConsoleHandle,
    mode: u32,
}

/// Builds the platform handle of a local terminal for the tests.
#[cfg(test)]
pub(crate) fn test_platform_terminal() -> PlatformTerminal {
    PlatformTerminal {
        input: 0,
        size_available: true,
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            SetConsoleMode(self.handle as *mut c_void, self.mode);
        }
    }
}

/// The guard of the console modes of the local console.
pub(crate) struct ConsoleModeGuard {
    code_page_in: u32,
    code_page_out: u32,
    handles: Vec<(ConsoleHandle, u32)>,
}

impl Drop for ConsoleModeGuard {
    fn drop(&mut self) {
        for (handle, mode) in &self.handles {
            unsafe {
                SetConsoleMode(*handle as *mut c_void, *mode);
            }
        }
        unsafe {
            SetConsoleCP(self.code_page_in);
            SetConsoleOutputCP(self.code_page_out);
        }
    }
}

/// Returns the handle of a standard stream, if the stream exists.
fn standard_handle(kind: u32) -> Option<ConsoleHandle> {
    let handle = unsafe { GetStdHandle(kind) } as isize;
    if handle <= 0 {
        return None;
    }
    Some(handle as usize)
}

/// Tells whether a handle belongs to a console.
fn is_console(handle: ConsoleHandle) -> bool {
    let mut mode = 0u32;
    let result = unsafe { GetConsoleMode(handle as *mut c_void, &mut mode) };
    result != 0
}

/// Returns the size of the visible window of a console.
///
/// The screen buffer of a console is usually larger than the window that
/// shows it: the window is the geometry the user sees.
fn console_window_size(handle: ConsoleHandle) -> Option<(u16, u16)> {
    let mut info = ConsoleScreenBufferInfo::default();
    if unsafe { GetConsoleScreenBufferInfo(handle as *mut c_void, &mut info) } == 0 {
        return None;
    }
    window_size(&info)
}

/// Returns the size of the visible window of a screen buffer.
fn window_size(info: &ConsoleScreenBufferInfo) -> Option<(u16, u16)> {
    let width = i32::from(info.window.right) - i32::from(info.window.left) + 1;
    let height = i32::from(info.window.bottom) - i32::from(info.window.top) + 1;
    if width <= 0 || height <= 0 {
        return None;
    }
    Some((u16::try_from(width).ok()?, u16::try_from(height).ok()?))
}

/// Reads the size of the local console.
///
/// The input handle of a Windows console carries no screen buffer, so the
/// query falls back to the output handles, like the Go reference does.
fn read_terminal_size() -> Option<TerminalSize> {
    for kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let Some(handle) = standard_handle(kind) else {
            continue;
        };
        let Some((width, height)) = console_window_size(handle) else {
            continue;
        };
        return Some(TerminalSize {
            char_width: width,
            char_height: height,
            pixel_width: 0,
            pixel_height: 0,
        });
    }
    None
}

/// Detects the local console of the client.
pub fn detect_local_terminal() -> Result<Option<LocalTerminal>, Ssh3ClientError> {
    let Some(input) = standard_handle(STD_INPUT_HANDLE) else {
        return Ok(None);
    };
    if !is_console(input) {
        return Ok(None);
    }

    // A console that cannot be queried falls back to 80x24: a pty with a
    // default geometry still beats a raw pipe session.
    let size = read_terminal_size();
    let size_available = size.is_some();
    let size = size.unwrap_or(TerminalSize {
        char_width: DEFAULT_COLUMNS,
        char_height: DEFAULT_ROWS,
        pixel_width: 0,
        pixel_height: 0,
    });

    Ok(Some(LocalTerminal {
        info: LocalTerminalInfo {
            term: env::var("TERM").ok().filter(|term| !term.is_empty()),
            size,
        },
        platform: PlatformTerminal {
            input,
            size_available,
        },
    }))
}

/// Puts the local console into the raw mode.
///
/// The echo, the line buffering and the processed input are cleared, so that
/// the keys travel to the remote side as they are typed, and the virtual
/// terminal input is turned on, so that the arrow keys arrive as VT
/// sequences.
pub(crate) fn enable_raw_mode(
    terminal: &PlatformTerminal,
) -> Result<RawModeGuard, Ssh3ClientError> {
    let mut mode = 0u32;
    if unsafe { GetConsoleMode(terminal.input as *mut c_void, &mut mode) } == 0 {
        return Err(Ssh3ClientError::Io(io::Error::last_os_error()));
    }
    let raw = raw_input_mode(mode);
    if unsafe { SetConsoleMode(terminal.input as *mut c_void, raw) } == 0 {
        return Err(Ssh3ClientError::Io(io::Error::last_os_error()));
    }
    Ok(RawModeGuard {
        handle: terminal.input,
        mode,
    })
}

/// Returns the console mode of the raw input.
///
/// The echo, the line buffering and the processed input are cleared, so that
/// the keys travel to the remote side as they are typed, and the virtual
/// terminal input is turned on, so that the arrow keys arrive as VT
/// sequences.
fn raw_input_mode(mode: u32) -> u32 {
    (mode & !(ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT))
        | ENABLE_VIRTUAL_TERMINAL_INPUT
}

/// Turns the console modes of the local console on.
///
/// The output handles interpret the escape sequences of the remote side, and
/// both code pages switch to UTF-8. The guard restores the previous modes
/// and code pages when the session ends.
pub(crate) fn enable_console_modes() -> ConsoleModeGuard {
    let mut guard = ConsoleModeGuard {
        code_page_in: 0,
        code_page_out: 0,
        handles: Vec::new(),
    };

    guard.code_page_in = unsafe { GetConsoleCP() };
    guard.code_page_out = unsafe { GetConsoleOutputCP() };
    unsafe {
        SetConsoleCP(CP_UTF8);
        SetConsoleOutputCP(CP_UTF8);
    }

    for kind in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let Some(handle) = standard_handle(kind) else {
            continue;
        };
        let mut mode = 0u32;
        if unsafe { GetConsoleMode(handle as *mut c_void, &mut mode) } == 0 {
            continue;
        }
        if unsafe {
            SetConsoleMode(
                handle as *mut c_void,
                mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            )
        } == 0
        {
            continue;
        }
        guard.handles.push((handle, mode));
    }

    guard
}

/// Forwards the resizes of the local console to the server.
///
/// Windows has no `SIGWINCH`: the console reports a resize as an event, and
/// draining the console input events for the notification would steal the
/// keystrokes of the stdin pump. The geometry is polled instead, and the
/// window-change request rides out on a change, exactly like the Go
/// reference does.
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
/// master slave relays the new size to the master over the control socket.
pub(crate) fn spawn_resize_forwarder_with(
    terminal: PlatformTerminal,
    on_resize: Arc<dyn Fn(TerminalSize) + Send + Sync>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if !terminal.size_available {
            return;
        }

        let mut last: Option<(u16, u16)> = None;
        let mut ticker = tokio::time::interval(RESIZE_POLL_INTERVAL);
        // The first tick is immediate: it only primes the baseline, because
        // the pty request already carried the geometry of the console.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let Some(size) = read_terminal_size() else {
                continue;
            };
            let current = (size.char_width, size.char_height);
            let Some(previous) = last else {
                last = Some(current);
                continue;
            };
            if previous == current {
                continue;
            }
            last = Some(current);
            on_resize(size);
        }
    })
}

/// The control events of the Windows console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CtrlEvent {
    /// The user pressed Ctrl+C or Ctrl+Break.
    Interrupt,
    /// The console is closing, the session logs off or the system shuts down.
    Terminate,
}

/// The state of the console control handler of the process.
struct CtrlHandlerState {
    /// The senders of the live signal forwarders.
    senders: Vec<mpsc::UnboundedSender<CtrlEvent>>,
}

/// The state of the console control handler of the process.
static CTRL_HANDLER: OnceLock<Mutex<CtrlHandlerState>> = OnceLock::new();

/// Returns the state of the console control handler of the process.
fn ctrl_handler_state() -> &'static Mutex<CtrlHandlerState> {
    CTRL_HANDLER.get_or_init(|| {
        Mutex::new(CtrlHandlerState {
            senders: Vec::new(),
        })
    })
}

/// Handles a control event of the console.
///
/// The event is forwarded to the live signal forwarders, and the default
/// handling of the console is skipped: the session of the client decides
/// what the interrupt means.
unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> i32 {
    let Some(event) = ctrl_event(ctrl_type) else {
        return 0;
    };

    let Some(state) = CTRL_HANDLER.get() else {
        return 0;
    };
    let Ok(state) = state.lock() else {
        return 0;
    };
    for sender in &state.senders {
        let _ = sender.send(event);
    }
    1
}

/// Returns the interrupt a control event of the console carries.
///
/// The Windows console has no `SIGINT` and no `SIGTERM`: the control
/// events carry them. The Ctrl+C and the Ctrl+Break keys are the
/// interrupts, the closing of the console, the logoff and the shutdown of
/// the system are the terminations.
fn ctrl_event(ctrl_type: u32) -> Option<CtrlEvent> {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => Some(CtrlEvent::Interrupt),
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => Some(CtrlEvent::Terminate),
        _ => None,
    }
}

/// Forwards the interrupts of the local console to the server.
///
/// The Windows console has no `SIGINT` and no `SIGTERM`: the control events
/// of the console carry them. The handler of the console is a registration
/// of the whole process, so it is only installed for an interactive console
/// session: an exec session keeps the default handling of the console, and
/// the Ctrl+C key still stops the client.
pub(crate) fn spawn_signal_forwarders(
    channel: Arc<Ssh3Channel>,
    interactive: bool,
) -> Vec<JoinHandle<()>> {
    spawn_signal_forwarders_with(
        interactive,
        Arc::new(move |signal_name| {
            let channel = channel.clone();
            tokio::spawn(async move {
                if send_signal_request(channel.as_ref(), signal_name)
                    .await
                    .is_err()
                {
                    // The channel died: the session is over anyway.
                }
            });
        }),
    )
}

/// The sink of the console ctrl events without a session channel: the
/// control master slave relays the interrupts to the master over the
/// control socket.
pub(crate) fn spawn_signal_forwarders_with(
    interactive: bool,
    on_signal: Arc<dyn Fn(&'static str) + Send + Sync>,
) -> Vec<JoinHandle<()>> {
    if !interactive {
        return Vec::new();
    }

    let (sender, mut receiver) = mpsc::unbounded_channel::<CtrlEvent>();
    {
        let mut state = ctrl_handler_state()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.senders.push(sender);
        if state.senders.len() == 1 {
            unsafe {
                SetConsoleCtrlHandler(Some(console_ctrl_handler), 1);
            }
        }
    }

    vec![tokio::spawn(async move {
        while let Some(event) = receiver.recv().await {
            let signal_name = match event {
                CtrlEvent::Interrupt => "INT",
                CtrlEvent::Terminate => "TERM",
            };
            on_signal(signal_name);
        }

        // The handler of the console is removed when the last forwarder of
        // the process stops.
        drop(receiver);
        let mut state = ctrl_handler_state()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.senders.retain(|sender| !sender.is_closed());
        if state.senders.is_empty() {
            unsafe {
                SetConsoleCtrlHandler(Some(console_ctrl_handler), 0);
            }
        }
    })]
}

/// Suspends the client locally.
///
/// The Windows console has no `SIGTSTP`: the `~^Z` escape sequence travels
/// to the remote side literally.
pub(crate) fn suspend_local_process(_guard: &RawModeGuardHandle) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the local console cannot suspend the process",
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
        ConsoleScreenBufferInfo, Coord, CtrlEvent, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
        ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, SmallRect, ctrl_event,
        raw_input_mode, window_size,
    };

    /// Builds a screen buffer with the given window rectangle.
    fn screen_buffer(left: i16, top: i16, right: i16, bottom: i16) -> ConsoleScreenBufferInfo {
        ConsoleScreenBufferInfo {
            size: Coord {
                x: right + 1,
                y: bottom + 1,
            },
            cursor_position: Coord { x: 0, y: 0 },
            attributes: 0,
            window: SmallRect {
                left,
                top,
                right,
                bottom,
            },
            maximum_window_size: Coord {
                x: right + 1,
                y: bottom + 1,
            },
        }
    }

    #[test]
    fn the_window_rect_gives_the_visible_size() {
        assert_eq!(window_size(&screen_buffer(0, 0, 119, 39)), Some((120, 40)));
    }

    #[test]
    fn the_window_rect_is_relative_to_the_screen_buffer() {
        // A console whose screen buffer is scrolled: the window starts
        // somewhere in the middle of the buffer.
        assert_eq!(window_size(&screen_buffer(10, 5, 89, 24)), Some((80, 20)));
    }

    #[test]
    fn an_empty_window_has_no_size() {
        assert_eq!(window_size(&screen_buffer(0, 0, -1, -1)), None);
    }

    #[test]
    fn the_raw_mode_clears_the_echo_and_the_line_buffering() {
        let mode = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
        let raw = raw_input_mode(mode);
        assert_eq!(raw & ENABLE_ECHO_INPUT, 0);
        assert_eq!(raw & ENABLE_LINE_INPUT, 0);
        assert_eq!(raw & ENABLE_PROCESSED_INPUT, 0);
    }

    #[test]
    fn the_raw_mode_reads_the_keys_as_vt_sequences() {
        let raw = raw_input_mode(ENABLE_PROCESSED_INPUT);
        assert_ne!(raw & ENABLE_VIRTUAL_TERMINAL_INPUT, 0);
    }

    #[test]
    fn the_raw_mode_keeps_the_other_modes() {
        let mode = 0x0100 | ENABLE_ECHO_INPUT;
        let raw = raw_input_mode(mode);
        assert_eq!(raw & 0x0100, 0x0100);
    }

    #[test]
    fn the_control_events_carry_the_interrupts() {
        assert_eq!(ctrl_event(CTRL_C_EVENT), Some(CtrlEvent::Interrupt));
        assert_eq!(ctrl_event(CTRL_BREAK_EVENT), Some(CtrlEvent::Interrupt));
    }

    #[test]
    fn the_control_events_carry_the_terminations() {
        assert_eq!(ctrl_event(CTRL_CLOSE_EVENT), Some(CtrlEvent::Terminate));
        assert_eq!(ctrl_event(CTRL_LOGOFF_EVENT), Some(CtrlEvent::Terminate));
        assert_eq!(ctrl_event(CTRL_SHUTDOWN_EVENT), Some(CtrlEvent::Terminate));
    }

    #[test]
    fn an_unknown_control_event_carries_nothing() {
        assert_eq!(ctrl_event(42), None);
    }
}
