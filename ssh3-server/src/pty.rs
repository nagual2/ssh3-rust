//! Pseudo-terminal support: allocation, sizing and signal delivery.
//!
//! A session that requested a `pty-req` runs on a pseudo-terminal instead of
//! plain pipes. The terminal is created with `openpty(3)`, the child process
//! gets the slave side as its controlling terminal (`setsid(2)` plus
//! `TIOCSCTTY`), and the server keeps the master side to feed input into the
//! process and to read its output.

use ssh3_proto::{Ssh3PtyRequest, Ssh3WindowChangeRequest};

/// The size of a pseudo-terminal, in characters and pixels.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionPtySize {
    /// Width in characters.
    pub(crate) char_width: u16,
    /// Height in characters.
    pub(crate) char_height: u16,
    /// Width in pixels.
    pub(crate) pixel_width: u16,
    /// Height in pixels.
    pub(crate) pixel_height: u16,
}

impl SessionPtySize {
    /// Builds a size from a `pty-req` channel request.
    pub(crate) fn from_pty_request(request: &Ssh3PtyRequest) -> Self {
        Self {
            char_width: clamp_u64_to_u16(request.char_width),
            char_height: clamp_u64_to_u16(request.char_height),
            pixel_width: clamp_u64_to_u16(request.pixel_width),
            pixel_height: clamp_u64_to_u16(request.pixel_height),
        }
    }

    /// Builds a size from a `window-change` channel request.
    pub(crate) fn from_window_change(request: &Ssh3WindowChangeRequest) -> Self {
        Self {
            char_width: clamp_u64_to_u16(request.char_width),
            char_height: clamp_u64_to_u16(request.char_height),
            pixel_width: clamp_u64_to_u16(request.pixel_width),
            pixel_height: clamp_u64_to_u16(request.pixel_height),
        }
    }

    /// Converts the size into the `winsize` structure used by the kernel.
    #[cfg(unix)]
    pub(crate) fn to_winsize(self) -> nix::pty::Winsize {
        nix::pty::Winsize {
            ws_row: self.char_height,
            ws_col: self.char_width,
            ws_xpixel: self.pixel_width,
            ws_ypixel: self.pixel_height,
        }
    }
}

/// Clamps a wire value to the 16 bit range used by terminal sizes.
pub(crate) fn clamp_u64_to_u16(value: u64) -> u16 {
    value.min(u16::MAX as u64) as u16
}

#[cfg(unix)]
mod unix {
    use std::fs::File as StdFile;
    use std::io;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;
    use std::process::Stdio;
    use std::sync::Arc;

    use nix::pty::openpty;
    use nix::sys::signal::Signal;
    use tokio::fs::File as TokioFile;
    use tokio::process::Command;

    use ssh3_core::Ssh3Channel;
    use ssh3_proto::{
        SSH_EXTENDED_DATA_NONE, Ssh3ChannelRequest, Ssh3ChannelRequestMessage,
        Ssh3ExitStatusRequest, Ssh3SignalRequest,
    };

    use crate::config::Ssh3ServerConfig;
    use crate::error::Ssh3ServerError;
    use crate::session::{
        PendingPty, RunningSession, SessionCommand, SessionInput, SessionUser, configure_process,
        effective_shell, pump_process_output,
    };

    use super::SessionPtySize;

    /// The master side of a pseudo-terminal, used to resize it while it runs.
    pub(crate) struct PtyController {
        master: StdFile,
    }

    impl PtyController {
        /// Applies a new terminal size to the pseudo-terminal (`TIOCSWINSZ`).
        pub(crate) fn resize(&self, size: SessionPtySize) -> io::Result<()> {
            let winsize = size.to_winsize();
            let result = unsafe {
                nix::libc::ioctl(self.master.as_raw_fd(), nix::libc::TIOCSWINSZ, &winsize)
            };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Maps a `signal` channel request to a Unix signal number.
    ///
    /// The name is matched case-insensitively and the optional `SIG` prefix is
    /// ignored. Unknown names are rejected.
    pub(crate) fn parse_signal_request(request: &Ssh3SignalRequest) -> Option<Signal> {
        let signal_name =
            String::from_utf8_lossy(&request.signal_name_without_sig).to_ascii_uppercase();
        let signal_name = signal_name
            .strip_prefix("SIG")
            .unwrap_or(signal_name.as_str());
        match signal_name {
            "ABRT" | "IOT" => Some(Signal::SIGABRT),
            "ALRM" => Some(Signal::SIGALRM),
            "BUS" => Some(Signal::SIGBUS),
            "CHLD" | "CLD" => Some(Signal::SIGCHLD),
            "CONT" => Some(Signal::SIGCONT),
            "FPE" => Some(Signal::SIGFPE),
            "HUP" => Some(Signal::SIGHUP),
            "ILL" => Some(Signal::SIGILL),
            "INT" => Some(Signal::SIGINT),
            "PIPE" => Some(Signal::SIGPIPE),
            "QUIT" => Some(Signal::SIGQUIT),
            "SEGV" => Some(Signal::SIGSEGV),
            "STOP" => Some(Signal::SIGSTOP),
            "TERM" => Some(Signal::SIGTERM),
            "TRAP" => Some(Signal::SIGTRAP),
            "TSTP" => Some(Signal::SIGTSTP),
            "TTIN" => Some(Signal::SIGTTIN),
            "TTOU" => Some(Signal::SIGTTOU),
            "USR1" => Some(Signal::SIGUSR1),
            "USR2" => Some(Signal::SIGUSR2),
            "WINCH" => Some(Signal::SIGWINCH),
            "XCPU" => Some(Signal::SIGXCPU),
            "XFSZ" => Some(Signal::SIGXFSZ),
            _ => None,
        }
    }

    /// Starts a session process attached to a freshly allocated pseudo-terminal.
    ///
    /// The child is placed in its own session and receives the slave side as
    /// its controlling terminal, so that job control and `isatty(3)` behave
    /// as expected.
    pub(crate) async fn spawn_pty_session_process(
        channel: Arc<Ssh3Channel>,
        config: &Ssh3ServerConfig,
        session_user: &SessionUser,
        pending_pty: PendingPty,
        agent_socket_path: Option<&Path>,
        command: SessionCommand,
    ) -> Result<RunningSession, Ssh3ServerError> {
        let openpty =
            openpty(Some(&pending_pty.size.to_winsize()), None).map_err(io::Error::from)?;
        let master = StdFile::from(openpty.master);
        let slave = StdFile::from(openpty.slave);

        let shell = effective_shell(config, session_user);
        let mut process = Command::new(&shell);
        if let SessionCommand::Exec(command) = &command {
            process.arg("-c").arg(command);
        }
        configure_process(
            &mut process,
            config,
            session_user,
            &command,
            agent_socket_path,
        );
        process.kill_on_drop(true);
        if let Some(term) = &pending_pty.term {
            process.env("TERM", term);
        }

        let slave_fd = slave.as_raw_fd();
        process
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave.try_clone()?));
        unsafe {
            process.pre_exec(move || {
                if nix::libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                if nix::libc::ioctl(slave_fd, nix::libc::TIOCSCTTY, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = process.spawn()?;
        drop(slave);

        let child_id = child.id();
        let input = TokioFile::from_std(master.try_clone()?);
        let output = TokioFile::from_std(master.try_clone()?);
        let controller = PtyController { master };

        let output_task = tokio::spawn(pump_process_output(
            Some(output),
            channel.clone(),
            SSH_EXTENDED_DATA_NONE,
        ));
        tokio::spawn(async move {
            let status = child.wait().await;
            let _ = output_task.await;

            let exit_status = status
                .ok()
                .and_then(|status| status.code())
                .unwrap_or(1)
                .max(0) as u64;
            let _ = channel
                .send_request(Ssh3ChannelRequestMessage {
                    want_reply: false,
                    request: Ssh3ChannelRequest::ExitStatus(Ssh3ExitStatusRequest { exit_status }),
                })
                .await;
            // The exit status ends the session. The Go server does not close
            // the channel here either: closing it right away races the
            // delivery of the status, and a client that reads an EOF before
            // the status reports a failure.
        });

        Ok(RunningSession {
            input: SessionInput::Pty(input),
            child_id,
            pty: Some(controller),
        })
    }
}

#[cfg(unix)]
pub(crate) use unix::{PtyController, parse_signal_request, spawn_pty_session_process};
