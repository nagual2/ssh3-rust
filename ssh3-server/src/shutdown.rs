//! Graceful shutdown of the server: the shutdown request and its drain window.
//!
//! On a shutdown signal the server stops accepting new connections and lets
//! the conversations it is serving drain up to the window of the
//! `SSH3_SHUTDOWN_DRAIN` variable (5 seconds by default, `0` closes the
//! connections immediately): the stage 3 of the Go reference
//! (`cmd/ssh3-server.go`). The pieces live here, the drain itself runs in
//! [`crate::runtime`].

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::config::DEFAULT_SHUTDOWN_DRAIN;
use crate::log_error;
use crate::log_warn;

/// The application error code a connection is closed with when a graceful
/// shutdown ends it: the `ApplicationErrorCode(0)` of the Go reference.
pub(crate) const SHUTDOWN_ERROR_CODE: u32 = 0;

/// The close reason a connection is closed with when a graceful shutdown ends
/// it, the `server shutdown` of the Go reference.
pub(crate) const SHUTDOWN_REASON: &[u8] = b"server shutdown";

/// Returns the graceful-shutdown drain window from the raw value of
/// `SSH3_SHUTDOWN_DRAIN`.
///
/// The value is a plain number of seconds, parsed like the Go reference
/// parses it with `strconv.Atoi`: the default is 5, and a negative or
/// unparsable value falls back to the default with a warning. An absent or
/// empty value silently keeps the default.
pub fn shutdown_drain_period(value: Option<&str>) -> Duration {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        // the raw value is used unpadded on purpose: the strconv.Atoi of the
        // Go reference rejects the padding too, so ` 5` falls back to the
        // default like the `5s` unit suffix does
        match value.parse::<i64>() {
            // the cast is guarded by the comparison above
            Ok(seconds) if seconds >= 0 => return Duration::from_secs(seconds as u64),
            _ => {
                log_warn!(
                    "ssh3-rust-server invalid SSH3_SHUTDOWN_DRAIN {value:?}, using the default"
                );
            }
        }
    }
    DEFAULT_SHUTDOWN_DRAIN
}

/// The request to shut the server down, shared between the signal handler and
/// the accept loop.
///
/// Cloning the signal hands the request around: the OS signal task calls
/// [`trigger`](ShutdownSignal::trigger) when the operator signals the process,
/// the accept loop [`waits`](ShutdownSignal::wait) for the request. The tests
/// trigger a signal directly, which keeps the shutdown deterministic without a
/// real `kill` of a server process.
#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    inner: Arc<ShutdownSignalInner>,
}

/// The watch channel behind a [`ShutdownSignal`].
///
/// A watch channel keeps the last value, so a trigger that happens while the
/// accept loop is between two polls can never be missed.
#[derive(Debug)]
struct ShutdownSignalInner {
    sender: watch::Sender<bool>,
    receiver: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Creates a signal that has not been requested yet.
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self {
            inner: Arc::new(ShutdownSignalInner { sender, receiver }),
        }
    }

    /// Requests the graceful shutdown.
    ///
    /// The request is idempotent: the runtime reacts to the first one only.
    pub fn trigger(&self) {
        let _ = self.inner.sender.send(true);
    }

    /// Resolves once the shutdown has been requested.
    ///
    /// A request made before the wait started resolves immediately.
    pub async fn wait(&self) {
        let mut receiver = self.inner.receiver.clone();
        let _ = receiver.wait_for(|requested| *requested).await;
    }

    /// Returns whether the shutdown has been requested.
    pub fn is_triggered(&self) -> bool {
        *self.inner.receiver.borrow()
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolves when the operator signals the server process to shut down.
///
/// On Unix the signals are `SIGINT` and `SIGTERM`, the pair the Go reference
/// installs (`os.Interrupt` and `syscall.SIGTERM`); on Windows only Ctrl-C
/// can be received, which is what `os.Interrupt` maps to there.
///
/// The handlers stay armed after the first signal: the signals that arrive
/// while the drain runs are consumed and ignored, like the `NotifyContext` of
/// the Go reference stays armed until its serve function returns.
///
/// When a handler cannot be installed the future never resolves: the process
/// keeps the default disposition of the signal, and the operator's signal
/// kills it outright — the honest fallback for a shutdown that cannot be made
/// graceful.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
        ) {
            (Ok(mut interrupt), Ok(mut terminate)) => {
                tokio::select! {
                    _ = interrupt.recv() => {}
                    _ = terminate.recv() => {}
                }
                // the drain of the runtime is running: keep consuming the
                // signals so neither kills the process mid-drain
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = interrupt.recv() => {}
                            _ = terminate.recv() => {}
                        }
                    }
                });
            }
            (Err(err), _) | (_, Err(err)) => {
                log_error!("ssh3-rust-server cannot listen for the shutdown signals: {err}");
                std::future::pending::<()>().await;
            }
        }
    }
    #[cfg(windows)]
    {
        // SIGTERM does not exist on Windows: the Go reference registers it
        // without ever receiving it, Ctrl-C is the only signal an operator
        // can send
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                // the drain of the runtime is running: keep consuming the
                // signals so Ctrl-C does not kill the process mid-drain
                tokio::spawn(async { while tokio::signal::ctrl_c().await.is_ok() {} });
            }
            Err(err) => {
                log_error!("ssh3-rust-server cannot listen for Ctrl-C: {err}");
                std::future::pending::<()>().await;
            }
        }
    }
}
