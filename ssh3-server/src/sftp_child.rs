//! The internal SFTP child: the chroot jail of the sshd model.
//!
//! The child is the `internal-sftp` of the `sshd` transposed to a re-exec:
//! the network-facing server never opens a path of the user, it starts this
//! child, the child chroots into the home directory of the user and drops to
//! the uid/gid of the user before the first path is opened, and it serves the
//! SFTP protocol over its standard input and output. After the chroot the
//! confinement of the paths is the kernel's: neither an absolute symlink nor
//! a `..` reaches outside of the jail.
//!
//! The child never escalates: the chroot and the drop only run when the
//! process is already root, and a child that was started by hand without
//! the privileges serves with its own identity or fails.
//!
//! The reference implementation of this behavior lives in `nagual2/ssh3-go`,
//! files `cmd/sftp_subsystem.go` (the parent) and `cmd/internal_sftp.go`
//! (the child).

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use ssh3_core::Ssh3Channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::error::Ssh3ServerError;
use crate::session::SessionUser;
use crate::sftp::SftpJail;
use crate::sftp_stream::{ChannelStream, StdioStream};

/// The options of the internal SFTP child.
#[derive(Clone, Debug, Default)]
pub struct InternalSftpOptions {
    /// The directory the child chroots into; `None` disables the chroot.
    pub chroot_dir: Option<PathBuf>,
    /// The root the child serves when it runs without a chroot.
    pub root_dir: Option<PathBuf>,
    /// The uid the child drops to.
    pub uid: Option<u32>,
    /// The gid the child drops to.
    pub gid: Option<u32>,
}

/// The outcome of the attempt to serve a channel with the chroot jail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildOutcome {
    /// The child served the channel.
    Served,
    /// The server does not hold the privileges the chroot jail needs: the
    /// channel is served in process, with the lexical jail.
    FallbackToInProcess,
}

/// Serves the SFTP subsystem of a channel with the chroot jail.
///
/// The child is started for the channel and the bytes of the channel are
/// pumped into the child and back. The parent never opens a path of the
/// user: the confinement happens entirely inside the child.
pub(crate) async fn spawn_chroot_child(
    channel: &Arc<Ssh3Channel>,
    jail_root: &Path,
    session_user: &SessionUser,
) -> Result<ChildOutcome, Ssh3ServerError> {
    #[cfg(not(unix))]
    let _ = session_user;
    if !chroot_is_available() {
        // a server that does not hold the privileges of the operating system
        // has nothing to jail: the channel is served in process, with the
        // lexical jail, exactly like the Go implementation does
        return Ok(ChildOutcome::FallbackToInProcess);
    }

    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("--sftp-server-internal")
        .arg("--sftp-chroot")
        .arg(jail_root)
        // the child is sanitized like the child of the sshd: it execs nothing
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        command
            .arg("--sftp-uid")
            .arg(session_user.uid.to_string())
            .arg("--sftp-gid")
            .arg(session_user.gid.to_string());
    }

    let mut child = command.spawn()?;
    let mut child_stdin = child.stdin.take().ok_or_else(|| {
        Ssh3ServerError::Io(io::Error::other("the sftp child did not expose stdin"))
    })?;
    let mut child_stdout = child.stdout.take().ok_or_else(|| {
        Ssh3ServerError::Io(io::Error::other("the sftp child did not expose stdout"))
    })?;

    let (stream, _done) = ChannelStream::new(channel.clone());
    let (mut reader, mut writer) = tokio::io::split(stream);

    let mut to_child = tokio::spawn(async move {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            child_stdin.write_all(&buffer[..read]).await?;
            child_stdin.flush().await?;
        }
        // the end of the input of the child is the end of its session
        drop(child_stdin);
        Ok::<(), io::Error>(())
    });

    let from_child = tokio::spawn(async move {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = child_stdout.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            writer.write_all(&buffer[..read]).await?;
            writer.flush().await?;
        }
        Ok::<(), io::Error>(())
    });

    let status = child.wait().await;
    if let Ok(status) = &status
        && !status.success()
    {
        eprintln!("ssh3-rust-server the sftp child ended with {status}");
    }
    // the pumps are unblocked when the peer keeps the channel open past the
    // death of the child; the close of the channel does the final teardown
    let _ = tokio::time::timeout(Duration::from_secs(2), &mut to_child).await;
    to_child.abort();
    from_child.abort();
    let _ = channel.close().await;
    Ok(ChildOutcome::Served)
}

/// Returns `true` when the process may chroot into the jail.
#[cfg(unix)]
fn chroot_is_available() -> bool {
    nix::unistd::Uid::effective().is_root()
}

/// Returns `true` when the process may chroot into the jail.
#[cfg(not(unix))]
fn chroot_is_available() -> bool {
    // a Windows server has no chroot at all: the lexical jail is the only
    // isolation it can offer
    false
}

/// Serves the SFTP protocol over the standard streams of the process.
///
/// This is the entry point of the internal child: the chroot jail is applied
/// before the first path is opened, and the protocol is served over the
/// standard input and the standard output of the process.
pub async fn run_internal_sftp_server(options: InternalSftpOptions) -> io::Result<()> {
    let (jail_root, chrooted) = match (&options.chroot_dir, &options.root_dir) {
        (Some(chroot_dir), _) => {
            apply_chroot_and_drop(chroot_dir, options.uid, options.gid)?;
            (PathBuf::from("/"), true)
        }
        (None, Some(root_dir)) => (root_dir.clone(), false),
        (None, None) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the internal sftp server needs a chroot or a root directory",
            ));
        }
    };

    let jail = SftpJail::new(jail_root, chrooted)?;
    // the child already runs as the account of the user: the owner of the
    // files it creates needs no correction
    let handler = crate::sftp::SftpHandler::new(jail, None);
    let (stream, mut done) = StdioStream::new();
    russh_sftp::server::run(stream, handler).await;
    // the session of the child ends when the parent closes the input
    done.wait().await;
    Ok(())
}

/// Chroots into the directory and drops to the uid/gid of the user.
///
/// The chroot needs the privileges, the drop removes them before any path is
/// served. The supplementary groups are cleared: the child gets the groups
/// of the user it serves and nothing else.
#[cfg(unix)]
fn apply_chroot_and_drop(directory: &Path, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    use nix::unistd::{Gid, Uid, chdir, chroot, setgid, setgroups, setuid};

    if !nix::unistd::Uid::effective().is_root() {
        // fail closed: the caller asked for the chroot jail, serving the
        // paths of the user unjailed is exactly the bug class the jail
        // removes
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the chroot jail of the sftp subsystem requires root",
        ));
    }
    let metadata = std::fs::metadata(directory)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", directory.display()),
        ));
    }
    // the sshd rule, adapted: the jail root must not be group/world-writable,
    // another user must not be able to plant content in it
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is group/world-writable, refusing to chroot into it",
                directory.display()
            ),
        ));
    }
    chdir(directory).map_err(io::Error::from)?;
    chroot(directory).map_err(io::Error::from)?;
    chdir("/").map_err(io::Error::from)?;
    if let (Some(uid), Some(gid)) = (uid, gid)
        && (uid != 0 || gid != 0)
    {
        setgroups(&[]).map_err(io::Error::from)?;
        setgid(Gid::from_raw(gid)).map_err(io::Error::from)?;
        setuid(Uid::from_raw(uid)).map_err(io::Error::from)?;
    }
    Ok(())
}

/// Chroots into the directory and drops to the uid/gid of the user.
#[cfg(not(unix))]
fn apply_chroot_and_drop(
    _directory: &Path,
    _uid: Option<u32>,
    _gid: Option<u32>,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the chroot jail of the sftp subsystem needs a unix platform",
    ))
}
