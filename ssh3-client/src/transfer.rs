//! The client side of the file transfer mode.
//!
//! The transfer mode moves files between the local file system and the SFTP
//! subsystem of the server. The reference implementation of this behavior
//! lives in `nagual2/ssh3-go`, file `cmd/sftp_client.go` (the client) and
//! `cmd/ssh3.go` (the parsing of the operand and of the flags).
//!
//! # The shape of the operand
//!
//! The remote side of a transfer is spelled `user@host:remote_path`; the
//! explicit form `user@host:port/url_path:remote_path` carries the port and
//! the URL path of the server as well. The local side of a transfer is an
//! ordinary local path. Which of the two operands is the remote one decides
//! the direction of the transfer: the remote operand is the source of a
//! download and the destination of an upload.
//!
//! # The modes
//!
//! * a single file, uploaded or downloaded;
//! * a tree, uploaded or downloaded recursively (`-r`): the directories that
//!   are missing on the destination are created, the files that are not
//!   regular are skipped and an empty directory is created on the other side;
//! * `--continue` resumes an interrupted transfer: the destination is
//!   compared with the source by size **and** modification time, a file whose
//!   size matches but whose modification time does not is transferred again;
//! * `--checksum` verifies the transfer with a SHA-256 re-read of the remote
//!   file; the verification happens on its own for the files over
//!   [`CHECKSUM_AUTO_THRESHOLD`] bytes.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use russh_sftp::client::SftpSession;
use russh_sftp::client::error::Error as SftpClientError;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// The size above which the transfer is verified with a SHA-256 re-read.
///
/// The threshold is the one of the Go implementation: the verification of a
/// big file costs a second read of the remote file, and a broken transfer is
/// worth the price.
pub const CHECKSUM_AUTO_THRESHOLD: u64 = 32 * 1024 * 1024;

/// The default port of the server in the transfer mode.
pub const DEFAULT_TRANSFER_PORT: u16 = 443;

/// The default URL path of the server in the transfer mode.
pub const DEFAULT_TRANSFER_URL_PATH: &str = "/ssh3-term";

/// The label the progress reports of the upload carry.
const UPLOAD_LABEL: &str = "upload";

/// The label the progress reports of the download carry.
const DOWNLOAD_LABEL: &str = "download";

/// The prefix of the progress reports.
///
/// The wording is the one of the Go implementation, which prints the same
/// prefix for the transfer and for the other modes of its client.
const PROGRESS_PREFIX: &str = "[ssh3 -f]";

/// The permissions a local file gets when the transfer creates it.
#[cfg(unix)]
const LOCAL_FILE_MODE: u32 = 0o644;

/// The permissions a local directory gets when the transfer creates it.
#[cfg(unix)]
const LOCAL_DIRECTORY_MODE: u32 = 0o755;

/// The size of the buffer the transfers copy with.
const COPY_BUFFER_SIZE: usize = 32 * 1024;

/// The remote side of a transfer.
///
/// The type carries the pieces of the `user@host:port/url_path:remote_path`
/// operand: the user of the connection, the host of the server, the port of
/// the server, the URL path of the server and the path of the file on the
/// remote side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3TransferTarget {
    /// The user of the connection.
    pub username: String,
    /// The host of the server.
    pub hostname: String,
    /// The port of the server.
    pub port: u16,
    /// The URL path of the server.
    pub url_path: String,
    /// The path of the file on the remote side.
    pub remote_path: String,
}

/// The options of a transfer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ssh3TransferOptions {
    /// The transfer walks the directories of the source.
    pub recursive: bool,
    /// The transfer resumes an interrupted transfer instead of overwriting.
    pub resume: bool,
    /// The transfer verifies the file with a SHA-256 re-read.
    pub checksum: bool,
}

/// The class of a failure of a transfer.
///
/// The class tells the caller what kind of problem the transfer ran into: a
/// path that does not exist, a path the peer refuses to open, an interrupted
/// transfer or a file whose content does not match its checksum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ssh3TransferFailure {
    /// The operand of the transfer is malformed.
    Operand,
    /// The path does not exist.
    NotFound,
    /// The peer refused the operation: no permission, no space or a path the
    /// peer cannot reach.
    Access,
    /// The transfer was interrupted.
    Interrupted,
    /// The content of the file does not match its checksum.
    Checksum,
    /// The local file system refused the operation.
    LocalIo,
    /// The remote file system refused the operation.
    RemoteIo,
    /// The connection to the server failed.
    Connection,
}

/// A failure of a transfer.
///
/// The message of the failure is the one the Go implementation prints, so
/// that the two clients speak the same language.
#[derive(Debug)]
pub enum Ssh3TransferError {
    /// The remote operand does not have the `user@host:remote_path` shape.
    InvalidOperand { spec: String, reason: String },
    /// The remote operand carries a port that is not a number.
    InvalidPort { spec: String, port: String },
    /// The remote operand carries too many `:` separators.
    TooManySeparators { spec: String },
    /// The remote operand carries no remote path.
    MissingRemotePath { spec: String },
    /// A local path cannot be read.
    LocalStat { path: PathBuf, error: io::Error },
    /// A local file cannot be opened for reading.
    LocalOpen { path: PathBuf, error: io::Error },
    /// A local file cannot be created or written.
    LocalCreate { path: PathBuf, error: io::Error },
    /// The modification time of a local path cannot be stamped.
    LocalMtime { path: PathBuf, error: io::Error },
    /// A local path cannot be listed.
    LocalReadDir { path: PathBuf, error: io::Error },
    /// A remote path cannot be read.
    RemoteStat {
        path: String,
        error: SftpClientError,
    },
    /// A remote file cannot be opened.
    RemoteOpen {
        path: String,
        error: SftpClientError,
    },
    /// A remote file cannot be created.
    RemoteCreate {
        path: String,
        error: SftpClientError,
    },
    /// A remote directory cannot be created.
    RemoteMkdir {
        path: String,
        error: SftpClientError,
    },
    /// The modification time of a remote path cannot be stamped.
    RemoteMtime {
        path: String,
        error: SftpClientError,
    },
    /// The copy of a file failed.
    Transfer { path: String, error: io::Error },
    /// The size of the transferred file does not match the size of the source.
    SizeMismatch {
        path: String,
        source: u64,
        destination: u64,
    },
    /// The checksums of the transferred file and of its source differ.
    ChecksumMismatch { path: String },
    /// The remote file is larger than the local one, so the transfer cannot
    /// be resumed.
    RemoteLarger {
        path: String,
        remote: u64,
        local: u64,
    },
    /// The local file is larger than the remote one, so the transfer cannot
    /// be resumed.
    LocalLarger {
        path: String,
        local: u64,
        remote: u64,
    },
    /// The local path is a directory and the transfer is not recursive.
    LocalIsDirectory { path: PathBuf },
    /// The remote path is a directory and the transfer is not recursive.
    RemoteIsDirectory { path: String },
    /// The local path is not a directory and the transfer is recursive.
    LocalNotDirectory { path: PathBuf },
    /// The remote path is not a directory and the transfer is recursive.
    RemoteNotDirectory { path: String },
    /// Some files of a tree could not be transferred.
    FailedFiles { count: u64 },
    /// The connection to the server could not be established.
    Connection(crate::Ssh3ClientError),
    /// The SFTP session could not be started.
    Session { error: SftpClientError },
}

impl Ssh3TransferError {
    /// Returns the class of the failure.
    pub fn failure(&self) -> Ssh3TransferFailure {
        match self {
            Self::InvalidOperand { .. }
            | Self::InvalidPort { .. }
            | Self::TooManySeparators { .. }
            | Self::MissingRemotePath { .. } => Ssh3TransferFailure::Operand,
            Self::LocalStat { .. }
            | Self::LocalOpen { .. }
            | Self::LocalCreate { .. }
            | Self::LocalMtime { .. }
            | Self::LocalReadDir { .. } => Ssh3TransferFailure::LocalIo,
            Self::RemoteStat { error, .. }
            | Self::RemoteOpen { error, .. }
            | Self::RemoteCreate { error, .. }
            | Self::RemoteMkdir { error, .. }
            | Self::RemoteMtime { error, .. } => classify_remote_error(error),
            Self::Transfer { error, .. } => {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    Ssh3TransferFailure::Interrupted
                } else {
                    Ssh3TransferFailure::RemoteIo
                }
            }
            Self::SizeMismatch { .. } => Ssh3TransferFailure::RemoteIo,
            Self::ChecksumMismatch { .. } => Ssh3TransferFailure::Checksum,
            Self::RemoteLarger { .. } | Self::LocalLarger { .. } => Ssh3TransferFailure::RemoteIo,
            Self::LocalIsDirectory { .. } | Self::RemoteIsDirectory { .. } => {
                Ssh3TransferFailure::Operand
            }
            Self::LocalNotDirectory { .. } | Self::RemoteNotDirectory { .. } => {
                Ssh3TransferFailure::Operand
            }
            Self::FailedFiles { .. } => Ssh3TransferFailure::RemoteIo,
            Self::Connection(_) => Ssh3TransferFailure::Connection,
            Self::Session { .. } => Ssh3TransferFailure::Connection,
        }
    }
}

/// Maps the status of the peer onto the class of the failure.
fn classify_remote_error(error: &SftpClientError) -> Ssh3TransferFailure {
    match error {
        SftpClientError::Status(status) => match status.status_code {
            StatusCode::NoSuchFile => Ssh3TransferFailure::NotFound,
            StatusCode::PermissionDenied => Ssh3TransferFailure::Access,
            StatusCode::Failure => Ssh3TransferFailure::Access,
            StatusCode::OpUnsupported => Ssh3TransferFailure::Access,
            _ => Ssh3TransferFailure::RemoteIo,
        },
        SftpClientError::Timeout => Ssh3TransferFailure::Interrupted,
        _ => Ssh3TransferFailure::RemoteIo,
    }
}

impl fmt::Display for Ssh3TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOperand { spec, reason } => {
                write!(formatter, "{spec:?} is not a remote operand ({reason})")
            }
            Self::InvalidPort { spec, port } => {
                write!(formatter, "{spec:?} has an invalid port {port:?}")
            }
            Self::TooManySeparators { spec } => {
                write!(formatter, "{spec:?} has too many ':' separators")
            }
            Self::MissingRemotePath { spec } => {
                write!(formatter, "{spec:?} is missing the remote path")
            }
            Self::LocalStat { path, error } => {
                write!(formatter, "cannot stat {}: {error}", path.display())
            }
            Self::LocalOpen { path, error } => {
                write!(formatter, "cannot open {}: {error}", path.display())
            }
            Self::LocalCreate { path, error } => {
                write!(formatter, "cannot create {}: {error}", path.display())
            }
            Self::LocalMtime { path, error } => {
                write!(formatter, "cannot set mtime on {}: {error}", path.display())
            }
            Self::LocalReadDir { path, error } => {
                write!(
                    formatter,
                    "cannot read directory {}: {error}",
                    path.display()
                )
            }
            Self::RemoteStat { path, error } => {
                write!(formatter, "cannot stat remote {path}: {error}")
            }
            Self::RemoteOpen { path, error } => {
                write!(formatter, "cannot open remote file {path}: {error}")
            }
            Self::RemoteCreate { path, error } => {
                write!(formatter, "cannot create remote file {path}: {error}")
            }
            Self::RemoteMkdir { path, error } => {
                write!(formatter, "cannot create remote directory {path}: {error}")
            }
            Self::RemoteMtime { path, error } => {
                write!(formatter, "cannot set mtime on {path}: {error}")
            }
            Self::Transfer { path, error } => {
                write!(formatter, "transfer of {path} failed: {error}")
            }
            Self::SizeMismatch {
                path,
                source,
                destination,
            } => write!(
                formatter,
                "size mismatch after transfer of {path}: {source} bytes expected, {destination} bytes transferred"
            ),
            Self::ChecksumMismatch { path } => {
                write!(formatter, "checksum mismatch after transfer of {path}")
            }
            Self::RemoteLarger {
                path,
                remote,
                local,
            } => write!(
                formatter,
                "remote {path} is larger than local ({remote} > {local} bytes); remove it or drop --continue"
            ),
            Self::LocalLarger {
                path,
                local,
                remote,
            } => write!(
                formatter,
                "local {path} is larger than remote ({local} > {remote} bytes); remove it or drop --continue"
            ),
            Self::LocalIsDirectory { path } => write!(
                formatter,
                "{} is a directory: use -r for recursive transfer",
                path.display()
            ),
            Self::RemoteIsDirectory { path } => write!(
                formatter,
                "{path} is a remote directory: use -r for recursive transfer"
            ),
            Self::LocalNotDirectory { path } => write!(
                formatter,
                "{} is not a directory: drop -r for a single-file transfer",
                path.display()
            ),
            Self::RemoteNotDirectory { path } => write!(
                formatter,
                "{path} is not a remote directory: drop -r for a single-file transfer"
            ),
            Self::FailedFiles { count } => {
                write!(formatter, "transfer finished with {count} failed file(s)")
            }
            Self::Connection(error) => {
                write!(formatter, "could not open sftp channel: {error}")
            }
            Self::Session { error } => {
                write!(formatter, "could not start sftp client: {error}")
            }
        }
    }
}

impl std::error::Error for Ssh3TransferError {}

/// Reports whether the operand is the remote side of a transfer.
///
/// A remote operand always carries a user part (`user@host:remote_path`):
/// the transfer needs an explicit user, and the `@` keeps the local paths
/// (the Windows ones included) unambiguous.
pub fn is_remote_transfer_spec(operand: &str) -> bool {
    let Some(at) = operand.find('@') else {
        return false;
    };
    if at == 0 {
        return false;
    }
    operand[at..].contains(':')
}

/// Parses the remote operand of a transfer.
///
/// The accepted shapes are `user@host:remote_path`,
/// `user@host:port:remote_path` and `user@host:port/url_path:remote_path`;
/// the shape `user@host/url_path:remote_path` carries the URL path of the
/// server without a port. The port and the URL path of the operand win over
/// the defaults of the caller.
pub fn parse_remote_transfer_spec(
    spec: &str,
    default_port: u16,
    default_url_path: &str,
) -> Result<Ssh3TransferTarget, Ssh3TransferError> {
    let mut target = Ssh3TransferTarget {
        username: String::new(),
        hostname: String::new(),
        port: default_port,
        url_path: default_url_path.to_string(),
        remote_path: String::new(),
    };

    let mut hostname_part = spec;
    if let Some(at) = hostname_part.find('@') {
        target.username = hostname_part[..at].to_string();
        hostname_part = &hostname_part[at + 1..];
    }

    let parts: Vec<&str> = hostname_part.split(':').collect();
    if parts.len() < 2 || parts[0].is_empty() {
        return Err(Ssh3TransferError::InvalidOperand {
            spec: spec.to_string(),
            reason: "expected user@host:remote_path".to_string(),
        });
    }
    target.hostname = parts[0].to_string();
    if parts.len() == 2 {
        target.remote_path = parts[1].to_string();
        // the "user@host/url_path:remote" hybrid: a slash in the host part is
        // the URL path of the connection
        if let Some(slash) = target.hostname.find('/') {
            target.url_path = target.hostname[slash..].to_string();
            target.hostname = target.hostname[..slash].to_string();
        }
    } else if parts.len() == 3 {
        let (port_part, url_rest) = match parts[1].split_once('/') {
            Some((port_part, url_rest)) => (port_part, Some(url_rest)),
            None => (parts[1], None),
        };
        if port_part.is_empty() || !port_part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Ssh3TransferError::InvalidPort {
                spec: spec.to_string(),
                port: port_part.to_string(),
            });
        }
        target.port = port_part.parse::<u16>().unwrap_or(default_port);
        if target.port == 0 {
            target.port = default_port;
        }
        target.url_path = default_url_path.to_string();
        if let Some(url_rest) = url_rest {
            target.url_path = format!("/{url_rest}");
        }
        target.remote_path = parts[2].to_string();
    } else {
        return Err(Ssh3TransferError::TooManySeparators {
            spec: spec.to_string(),
        });
    }

    if target.remote_path.is_empty() {
        return Err(Ssh3TransferError::MissingRemotePath {
            spec: spec.to_string(),
        });
    }
    Ok(target)
}

/// The plan of a transfer: the remote side, the local side and the direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3TransferPlan {
    /// The remote side of the transfer.
    pub target: Ssh3TransferTarget,
    /// The local side of the transfer.
    pub local_path: PathBuf,
    /// `true` when the local side is the source of the transfer.
    pub upload: bool,
    /// The options of the transfer.
    pub options: Ssh3TransferOptions,
}

/// The decision the `--continue` mode takes about a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResumeDecision {
    /// The destination already holds the source: the file is skipped.
    Skip,
    /// The destination holds a prefix of the source: the transfer continues at
    /// the given offset.
    Resume(u64),
    /// The whole file is transferred again.
    Restart,
}

/// Uploads a file to the remote side.
///
/// The remote path that points at an existing directory receives the file
/// under the name of the local file, the scp way. The directories that are
/// missing on the remote side are created.
pub async fn upload_file(
    session: &SftpSession,
    local_path: &Path,
    remote_path: &str,
    options: &Ssh3TransferOptions,
) -> Result<(), Ssh3TransferError> {
    let progress = TransferProgress::start(UPLOAD_LABEL, &local_path.display().to_string(), true);
    let result =
        upload_file_with_progress(session, local_path, remote_path, options, &progress).await;
    progress.finish();
    result
}

/// Uploads a file to the remote side and reports the progress of the caller.
///
/// The recursive mode shares one progress between the files of the tree, the
/// way the Go implementation does.
async fn upload_file_with_progress(
    session: &SftpSession,
    local_path: &Path,
    remote_path: &str,
    options: &Ssh3TransferOptions,
    progress: &TransferProgress,
) -> Result<(), Ssh3TransferError> {
    let metadata =
        tokio::fs::metadata(local_path)
            .await
            .map_err(|error| Ssh3TransferError::LocalStat {
                path: local_path.to_path_buf(),
                error,
            })?;
    if metadata.is_dir() {
        return Err(Ssh3TransferError::LocalIsDirectory {
            path: local_path.to_path_buf(),
        });
    }
    let size = metadata.len();
    progress.rename(&local_path.display().to_string());

    // a remote path that points at an existing directory receives the file
    // under its local base name, scp-style
    let mut remote_path = remote_path.to_string();
    if let Ok(remote_metadata) = session.metadata(&remote_path).await
        && remote_metadata.file_type().is_dir()
    {
        remote_path = remote_join(&remote_path, &local_file_name(local_path));
    }

    // the missing parents of the remote file are created, so an upload into a
    // fresh destination works without a manual mkdir
    let parent = remote_dir(&remote_path);
    if parent != "." && parent != "/" && session.metadata(&parent).await.is_err() {
        remote_mkdir_all(session, &parent).await?;
    }

    // the decision of the --continue mode
    let mut start_offset = 0u64;
    let mut truncate = true;
    if options.resume
        && let Ok(remote_metadata) = session.metadata(&remote_path).await
    {
        let remote_size = remote_metadata.size.unwrap_or(0);
        let remote_mtime = remote_metadata.mtime.unwrap_or(0) as i64;
        let local_mtime = unix_seconds(metadata.modified().unwrap_or(UNIX_EPOCH));
        if remote_size > size {
            return Err(Ssh3TransferError::RemoteLarger {
                path: remote_path.clone(),
                remote: remote_size,
                local: size,
            });
        }
        match compare_size_and_mtime(remote_size, remote_mtime, size, local_mtime) {
            ResumeDecision::Skip => {
                eprintln!("{remote_path} is already up to date (same size and mtime), skipping");
                return Ok(());
            }
            ResumeDecision::Restart => {
                eprintln!("{remote_path} matches in size but the mtime differs, re-transferring");
            }
            ResumeDecision::Resume(offset) => {
                start_offset = offset;
                truncate = false;
            }
        }
    }
    progress.set_total(size.saturating_sub(start_offset));

    let mut local_file =
        tokio::fs::File::open(local_path)
            .await
            .map_err(|error| Ssh3TransferError::LocalOpen {
                path: local_path.to_path_buf(),
                error,
            })?;

    let mut remote_file = if truncate {
        session
            .open_with_flags(
                remote_path.clone(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            )
            .await
            .map_err(|error| Ssh3TransferError::RemoteCreate {
                path: remote_path.clone(),
                error,
            })?
    } else {
        session
            .open_with_flags(remote_path.clone(), OpenFlags::WRITE)
            .await
            .map_err(|error| Ssh3TransferError::RemoteCreate {
                path: remote_path.clone(),
                error,
            })?
    };

    let mut hasher = Sha256::new();
    if start_offset > 0 {
        // the prefix of the file is part of its checksum
        hash_local_prefix(&mut local_file, start_offset, &mut hasher)
            .await
            .map_err(|error| Ssh3TransferError::Transfer {
                path: remote_path.clone(),
                error,
            })?;
        remote_file
            .seek(io::SeekFrom::Start(start_offset))
            .await
            .map_err(|error| Ssh3TransferError::Transfer {
                path: remote_path.clone(),
                error,
            })?;
    }
    local_file
        .seek(io::SeekFrom::Start(start_offset))
        .await
        .map_err(|error| Ssh3TransferError::Transfer {
            path: remote_path.clone(),
            error,
        })?;

    copy_into_remote(&mut remote_file, &mut local_file, &mut hasher, progress)
        .await
        .map_err(|error| Ssh3TransferError::Transfer {
            path: remote_path.clone(),
            error,
        })?;
    remote_file
        .close()
        .await
        .map_err(|error| Ssh3TransferError::Transfer {
            path: remote_path.clone(),
            error,
        })?;

    let remote_metadata =
        session
            .metadata(&remote_path)
            .await
            .map_err(|error| Ssh3TransferError::RemoteStat {
                path: remote_path.clone(),
                error,
            })?;
    let remote_size = remote_metadata.size.unwrap_or(0);
    if remote_size != size {
        return Err(Ssh3TransferError::SizeMismatch {
            path: remote_path.clone(),
            source: size,
            destination: remote_size,
        });
    }
    if options.checksum || size > CHECKSUM_AUTO_THRESHOLD {
        verify_remote_checksum(session, &remote_path, &hasher).await?;
    }
    // the remote file is stamped with the modification time of the source: the
    // decision of the --continue mode compares the size and the modification
    // time. A failure is not fatal, it costs one redundant transfer later.
    if let Err(error) = stamp_remote_mtime(
        session,
        &remote_path,
        metadata.modified().unwrap_or(UNIX_EPOCH),
    )
    .await
    {
        eprintln!("{error}");
    }
    Ok(())
}

/// Downloads a file from the remote side.
///
/// The local path that points at an existing directory receives the file
/// under the name of the remote file, the scp way.
pub async fn download_file(
    session: &SftpSession,
    remote_path: &str,
    local_path: &Path,
    options: &Ssh3TransferOptions,
) -> Result<(), Ssh3TransferError> {
    let progress = TransferProgress::start(DOWNLOAD_LABEL, &remote_file_name(remote_path), true);
    let result =
        download_file_with_progress(session, remote_path, local_path, options, &progress).await;
    progress.finish();
    result
}

/// Downloads a file from the remote side and reports the progress of the
/// caller.
async fn download_file_with_progress(
    session: &SftpSession,
    remote_path: &str,
    local_path: &Path,
    options: &Ssh3TransferOptions,
    progress: &TransferProgress,
) -> Result<(), Ssh3TransferError> {
    let remote_metadata =
        session
            .metadata(remote_path)
            .await
            .map_err(|error| Ssh3TransferError::RemoteStat {
                path: remote_path.to_string(),
                error,
            })?;
    if remote_metadata.file_type().is_dir() {
        return Err(Ssh3TransferError::RemoteIsDirectory {
            path: remote_path.to_string(),
        });
    }
    let size = remote_metadata.size.unwrap_or(0);
    let remote_mtime = remote_metadata.mtime.unwrap_or(0) as i64;
    progress.rename(&remote_file_name(remote_path));

    // a local path that points at an existing directory receives the file
    // under the name of the remote file, scp-style
    let mut local_path = local_path.to_path_buf();
    if let Ok(local_metadata) = tokio::fs::metadata(&local_path).await
        && local_metadata.is_dir()
    {
        local_path = local_path.join(remote_file_name(remote_path));
    }

    // the decision of the --continue mode
    let mut start_offset = 0u64;
    let mut truncate = true;
    if options.resume
        && let Ok(local_metadata) = tokio::fs::metadata(&local_path).await
    {
        let local_size = local_metadata.len();
        let local_mtime = unix_seconds(local_metadata.modified().unwrap_or(UNIX_EPOCH));
        if local_size > size {
            return Err(Ssh3TransferError::LocalLarger {
                path: local_path.display().to_string(),
                local: local_size,
                remote: size,
            });
        }
        match compare_size_and_mtime(local_size, local_mtime, size, remote_mtime) {
            ResumeDecision::Skip => {
                eprintln!(
                    "{} is already up to date (same size and mtime), skipping",
                    local_path.display()
                );
                return Ok(());
            }
            ResumeDecision::Restart => {
                eprintln!(
                    "{} matches in size but the mtime differs, re-transferring",
                    local_path.display()
                );
            }
            ResumeDecision::Resume(offset) => {
                start_offset = offset;
                truncate = false;
            }
        }
    }
    progress.set_total(size.saturating_sub(start_offset));

    let mut local_file = open_local_file(&local_path, truncate)
        .await
        .map_err(|error| Ssh3TransferError::LocalCreate {
            path: local_path.clone(),
            error,
        })?;

    let mut remote_file =
        session
            .open(remote_path)
            .await
            .map_err(|error| Ssh3TransferError::RemoteOpen {
                path: remote_path.to_string(),
                error,
            })?;

    let mut hasher = Sha256::new();
    if start_offset > 0 {
        // the prefix of the file is part of its checksum
        hash_local_prefix(&mut local_file, start_offset, &mut hasher)
            .await
            .map_err(|error| Ssh3TransferError::Transfer {
                path: remote_path.to_string(),
                error,
            })?;
        remote_file
            .seek(io::SeekFrom::Start(start_offset))
            .await
            .map_err(|error| Ssh3TransferError::Transfer {
                path: remote_path.to_string(),
                error,
            })?;
    }
    local_file
        .seek(io::SeekFrom::Start(start_offset))
        .await
        .map_err(|error| Ssh3TransferError::Transfer {
            path: remote_path.to_string(),
            error,
        })?;

    copy_into_local(&mut local_file, &mut remote_file, &mut hasher, progress)
        .await
        .map_err(|error| Ssh3TransferError::Transfer {
            path: remote_path.to_string(),
            error,
        })?;
    remote_file
        .close()
        .await
        .map_err(|error| Ssh3TransferError::Transfer {
            path: remote_path.to_string(),
            error,
        })?;
    local_file
        .flush()
        .await
        .map_err(|error| Ssh3TransferError::LocalCreate {
            path: local_path.clone(),
            error,
        })?;

    if options.checksum || size > CHECKSUM_AUTO_THRESHOLD {
        verify_remote_checksum(session, remote_path, &hasher).await?;
    }
    // the local file is stamped with the modification time of the remote file:
    // the decision of the --continue mode compares the size and the
    // modification time. A failure is not fatal, it costs one redundant
    // transfer later.
    if let Err(error) = stamp_local_mtime(
        &local_path,
        UNIX_EPOCH + Duration::from_secs(remote_mtime.max(0) as u64),
    )
    .await
    {
        eprintln!("{error}");
    }
    Ok(())
}

/// Uploads a tree of files to the remote side.
///
/// The directories that are missing on the remote side are created, the files
/// that are not regular are skipped and an empty directory is created on the
/// remote side as well.
pub async fn upload_tree(
    session: &SftpSession,
    local_root: &Path,
    remote_root: &str,
    options: &Ssh3TransferOptions,
) -> Result<(), Ssh3TransferError> {
    let metadata =
        tokio::fs::metadata(local_root)
            .await
            .map_err(|error| Ssh3TransferError::LocalStat {
                path: local_root.to_path_buf(),
                error,
            })?;
    if !metadata.is_dir() {
        return Err(Ssh3TransferError::LocalNotDirectory {
            path: local_root.to_path_buf(),
        });
    }
    remote_mkdir_all(session, remote_root).await?;

    let progress = TransferProgress::start(UPLOAD_LABEL, &local_root.display().to_string(), false);
    let result = upload_tree_inner(session, local_root, remote_root, options, &progress).await;
    progress.finish();
    result
}

/// Walks a local tree and uploads its files.
async fn upload_tree_inner(
    session: &SftpSession,
    local_root: &Path,
    remote_root: &str,
    options: &Ssh3TransferOptions,
    progress: &TransferProgress,
) -> Result<(), Ssh3TransferError> {
    let mut failures = 0u64;
    let mut stack = vec![(local_root.to_path_buf(), remote_root.to_string())];
    while let Some((local_dir, remote_dir)) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&local_dir).await.map_err(|error| {
            Ssh3TransferError::LocalReadDir {
                path: local_dir.clone(),
                error,
            }
        })?;
        let mut children = Vec::new();
        while let Some(entry) =
            entries
                .next_entry()
                .await
                .map_err(|error| Ssh3TransferError::LocalReadDir {
                    path: local_dir.clone(),
                    error,
                })?
        {
            children.push(entry);
        }
        // the walk is sorted, so the transfer of a tree is reproducible
        children.sort_by_key(|entry| entry.file_name());
        for entry in children {
            let name = entry.file_name().to_string_lossy().into_owned();
            let local_path = entry.path();
            let remote_path = remote_join(&remote_dir, &name);
            let file_type =
                entry
                    .file_type()
                    .await
                    .map_err(|error| Ssh3TransferError::LocalStat {
                        path: local_path.clone(),
                        error,
                    })?;
            if file_type.is_dir() {
                remote_mkdir_all(session, &remote_path).await?;
                stack.push((local_path, remote_path));
                continue;
            }
            if !file_type.is_file() {
                // the files that are not regular (the symbolic links, the
                // sockets and the devices) are skipped
                continue;
            }
            if upload_file_with_progress(session, &local_path, &remote_path, options, progress)
                .await
                .is_err()
            {
                failures += 1;
            }
        }
    }
    if failures > 0 {
        return Err(Ssh3TransferError::FailedFiles { count: failures });
    }
    Ok(())
}

/// Downloads a tree of files from the remote side.
///
/// The directories that are missing on the local side are created, the files
/// that are not regular are skipped and an empty directory is created on the
/// local side as well.
pub async fn download_tree(
    session: &SftpSession,
    remote_root: &str,
    local_root: &Path,
    options: &Ssh3TransferOptions,
) -> Result<(), Ssh3TransferError> {
    let remote_metadata =
        session
            .metadata(remote_root)
            .await
            .map_err(|error| Ssh3TransferError::RemoteStat {
                path: remote_root.to_string(),
                error,
            })?;
    if !remote_metadata.file_type().is_dir() {
        return Err(Ssh3TransferError::RemoteNotDirectory {
            path: remote_root.to_string(),
        });
    }
    create_local_directory(local_root).await?;

    let progress = TransferProgress::start(DOWNLOAD_LABEL, remote_root, false);
    let result = download_tree_inner(session, remote_root, local_root, options, &progress).await;
    progress.finish();
    result
}

/// Walks a remote tree and downloads its files.
async fn download_tree_inner(
    session: &SftpSession,
    remote_root: &str,
    local_root: &Path,
    options: &Ssh3TransferOptions,
    progress: &TransferProgress,
) -> Result<(), Ssh3TransferError> {
    let mut failures = 0u64;
    let mut stack = vec![(remote_root.to_string(), local_root.to_path_buf())];
    while let Some((remote_dir, local_dir)) = stack.pop() {
        let entries =
            session
                .read_dir(&remote_dir)
                .await
                .map_err(|error| Ssh3TransferError::RemoteStat {
                    path: remote_dir.clone(),
                    error,
                })?;
        let mut children: Vec<(String, FileAttributes)> = Vec::new();
        for entry in entries {
            children.push((entry.file_name(), entry.metadata()));
        }
        // the walk is sorted, so the transfer of a tree is reproducible
        children.sort_by(|left, right| left.0.cmp(&right.0));
        for (name, attributes) in children {
            let remote_path = remote_join(&remote_dir, &name);
            let local_path = local_dir.join(&name);
            if attributes.file_type().is_dir() {
                create_local_directory(&local_path).await?;
                stack.push((remote_path, local_path));
                continue;
            }
            if !attributes.file_type().is_file() {
                // the files that are not regular are skipped
                continue;
            }
            if download_file_with_progress(session, &remote_path, &local_path, options, progress)
                .await
                .is_err()
            {
                failures += 1;
            }
        }
    }
    if failures > 0 {
        return Err(Ssh3TransferError::FailedFiles { count: failures });
    }
    Ok(())
}

/// Compares the size and the modification time of a destination with the ones
/// of its source.
///
/// The size alone cannot prove the content: a file that is rewritten in place
/// keeps its size, so the modification time decides as well.
fn compare_size_and_mtime(
    destination_size: u64,
    destination_mtime: i64,
    source_size: u64,
    source_mtime: i64,
) -> ResumeDecision {
    if destination_size == source_size {
        if destination_mtime == source_mtime {
            return ResumeDecision::Skip;
        }
        return ResumeDecision::Restart;
    }
    ResumeDecision::Resume(destination_size)
}

/// Returns the number of seconds of a time since the epoch.
fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(error) => -(error.duration().as_secs() as i64),
    }
}

/// Returns the name of a local file.
fn local_file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Returns the name of a remote file.
fn remote_file_name(path: &str) -> String {
    remote_base(path)
}

/// Returns the last element of a remote path.
fn remote_base(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    match trimmed.rsplit_once('/') {
        Some((_, name)) => name.to_string(),
        None => trimmed.to_string(),
    }
}

/// Returns the directory of a remote path.
fn remote_dir(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((head, _)) if !head.is_empty() => head.to_string(),
        Some(_) => "/".to_string(),
        None => ".".to_string(),
    }
}

/// Joins two remote paths, the way the POSIX `path.Join` of the Go
/// implementation does.
fn remote_join(base: &str, name: &str) -> String {
    if base.is_empty() {
        return remote_clean(name);
    }
    if name.is_empty() {
        return remote_clean(base);
    }
    remote_clean(&format!("{base}/{name}"))
}

/// Cleans a remote path, the way the POSIX `path.Clean` of the Go
/// implementation does.
fn remote_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let rooted = path.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if let Some(last) = segments.last() {
                    if *last != ".." {
                        segments.pop();
                        continue;
                    }
                }
                if !rooted {
                    segments.push("..");
                }
            }
            other => segments.push(other),
        }
    }
    let joined = segments.join("/");
    if rooted {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Creates the remote directories of a path, one level at a time.
async fn remote_mkdir_all(session: &SftpSession, directory: &str) -> Result<(), Ssh3TransferError> {
    let mut current = String::new();
    for segment in remote_clean(directory).split('/') {
        if segment.is_empty() {
            current = "/".to_string();
            continue;
        }
        current = remote_join(&current, segment);
        if let Err(error) = session.create_dir(&current).await {
            // the directory may already exist
            match session.metadata(&current).await {
                Ok(metadata) if metadata.file_type().is_dir() => continue,
                _ => {
                    return Err(Ssh3TransferError::RemoteMkdir {
                        path: current,
                        error,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Creates a local directory, with the parents it misses.
async fn create_local_directory(path: &Path) -> Result<(), Ssh3TransferError> {
    let target = path.to_path_buf();
    // the builder of the standard library carries the mode of the directory,
    // the one of the asynchronous file system does not
    let created = tokio::task::spawn_blocking(move || {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(LOCAL_DIRECTORY_MODE);
        }
        builder.create(&target)
    })
    .await
    .map_err(|error| Ssh3TransferError::LocalCreate {
        path: path.to_path_buf(),
        error: io::Error::other(error),
    })?;
    created.map_err(|error| Ssh3TransferError::LocalCreate {
        path: path.to_path_buf(),
        error,
    })
}

/// Opens a local file for writing.
///
/// The file is truncated unless the transfer resumes it, and it gets the
/// permissions of a file of the user.
async fn open_local_file(path: &Path, truncate: bool) -> io::Result<tokio::fs::File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true);
    if truncate {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        options.mode(LOCAL_FILE_MODE);
    }
    options.open(path).await
}

/// Stamps a local file with a modification time.
async fn stamp_local_mtime(path: &Path, time: SystemTime) -> Result<(), Ssh3TransferError> {
    let target = path.to_path_buf();
    // the file is opened for writing first and for reading next: a file that
    // cannot be written can still be stamped on the systems that allow it
    let stamped = tokio::task::spawn_blocking(move || {
        let times = std::fs::FileTimes::new()
            .set_accessed(time)
            .set_modified(time);
        match std::fs::File::options().write(true).open(&target) {
            Ok(file) => file.set_times(times),
            Err(error) => match std::fs::File::options().read(true).open(&target) {
                Ok(file) => file.set_times(times),
                Err(_) => Err(error),
            },
        }
    })
    .await
    .map_err(|error| Ssh3TransferError::LocalMtime {
        path: path.to_path_buf(),
        error: io::Error::other(error),
    })?;
    stamped.map_err(|error| Ssh3TransferError::LocalMtime {
        path: path.to_path_buf(),
        error,
    })
}

/// Stamps a remote file with a modification time.
async fn stamp_remote_mtime(
    session: &SftpSession,
    path: &str,
    time: SystemTime,
) -> Result<(), Ssh3TransferError> {
    let seconds = unix_seconds(time).max(0) as u32;
    let attributes = FileAttributes {
        atime: Some(seconds),
        mtime: Some(seconds),
        ..FileAttributes::default()
    };
    session
        .set_metadata(path, attributes)
        .await
        .map_err(|error| Ssh3TransferError::RemoteMtime {
            path: path.to_string(),
            error,
        })
}

/// Hashes the prefix of a local file.
async fn hash_local_prefix(
    file: &mut tokio::fs::File,
    length: u64,
    hasher: &mut Sha256,
) -> io::Result<()> {
    file.seek(io::SeekFrom::Start(0)).await?;
    let mut remaining = length;
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    while remaining > 0 {
        let wanted = buffer.len().min(remaining as usize);
        let read = file.read(&mut buffer[..wanted]).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(())
}

/// Copies the local file into the remote one, hashing the content on the way.
async fn copy_into_remote(
    remote: &mut russh_sftp::client::fs::File,
    local: &mut tokio::fs::File,
    hasher: &mut Sha256,
    progress: &TransferProgress,
) -> io::Result<()> {
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    loop {
        let read = local.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        remote.write_all(&buffer[..read]).await?;
        hasher.update(&buffer[..read]);
        progress.add_bytes(read as u64);
    }
    remote.flush().await
}

/// Copies the remote file into the local one, hashing the content on the way.
async fn copy_into_local(
    local: &mut tokio::fs::File,
    remote: &mut russh_sftp::client::fs::File,
    hasher: &mut Sha256,
    progress: &TransferProgress,
) -> io::Result<()> {
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    loop {
        let read = remote.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        local.write_all(&buffer[..read]).await?;
        hasher.update(&buffer[..read]);
        progress.add_bytes(read as u64);
    }
    local.flush().await
}

/// Re-reads the remote file and compares its checksum with the local one.
pub(crate) async fn verify_remote_checksum(
    session: &SftpSession,
    remote_path: &str,
    local_hasher: &Sha256,
) -> Result<(), Ssh3TransferError> {
    let mut remote_file =
        session
            .open(remote_path)
            .await
            .map_err(|error| Ssh3TransferError::RemoteOpen {
                path: remote_path.to_string(),
                error,
            })?;
    let mut remote_hasher = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    loop {
        let read =
            remote_file
                .read(&mut buffer)
                .await
                .map_err(|error| Ssh3TransferError::Transfer {
                    path: remote_path.to_string(),
                    error,
                })?;
        if read == 0 {
            break;
        }
        remote_hasher.update(&buffer[..read]);
    }
    let _ = remote_file.close().await;
    if remote_hasher.finalize() != local_hasher.clone().finalize() {
        return Err(Ssh3TransferError::ChecksumMismatch {
            path: remote_path.to_string(),
        });
    }
    Ok(())
}

/// The progress of a transfer.
///
/// The progress is reported on the standard error every 500 milliseconds and
/// a final line closes the report, the way the Go implementation does.
struct TransferProgress {
    /// The label of the transfer.
    label: &'static str,
    /// The name of the file the progress reports.
    name: Arc<std::sync::Mutex<String>>,
    /// The number of bytes the transfer moves; zero means that the size is
    /// unknown, the transfer moves a whole tree.
    total: Arc<AtomicU64>,
    /// Whether the size of the transfer is known; a tree does not know it.
    sized: bool,
    /// The number of bytes the transfer moved.
    transferred: Arc<AtomicU64>,
    /// The signal that stops the reporter.
    stop: tokio::sync::watch::Sender<bool>,
    /// The task that reports the progress.
    reporter: Option<tokio::task::JoinHandle<()>>,
}

impl TransferProgress {
    /// Starts the reporter of a transfer.
    ///
    /// `sized` tells whether the transfer knows the number of bytes it
    /// moves: a tree does not know it, and the report of a tree carries the
    /// bytes it moved alone.
    fn start(label: &'static str, name: &str, sized: bool) -> Self {
        let name = Arc::new(std::sync::Mutex::new(name.to_string()));
        let transferred = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(0));
        let (stop, mut stopped) = tokio::sync::watch::channel(false);

        let reporter_name = Arc::clone(&name);
        let reporter_transferred = Arc::clone(&transferred);
        let reporter_total = Arc::clone(&total);
        let reporter = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(500));
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    _ = ticker.tick() => {
                        let done = reporter_transferred.load(Ordering::Relaxed);
                        let total = reporter_total.load(Ordering::Relaxed);
                        let current = reporter_name
                            .lock()
                            .map(|name| name.clone())
                            .unwrap_or_default();
                        if total > 0 {
                            eprint!(
                                "\r{PROGRESS_PREFIX} {label} {current}: {} / {} ({}%)",
                                human_bytes(done),
                                human_bytes(total),
                                done * 100 / total
                            );
                        } else {
                            eprint!(
                                "\r{PROGRESS_PREFIX} {label} {current}: {}",
                                human_bytes(done)
                            );
                        }
                    }
                }
            }
        });

        Self {
            label,
            name,
            total,
            sized,
            transferred,
            stop,
            reporter: Some(reporter),
        }
    }

    /// Counts the bytes the transfer moved.
    fn add_bytes(&self, count: u64) {
        self.transferred.fetch_add(count, Ordering::Relaxed);
    }

    /// Sets the number of bytes the transfer moves.
    ///
    /// The size of a tree is unknown, so the report of a tree keeps the
    /// number of bytes it moved alone.
    fn set_total(&self, total: u64) {
        if self.sized {
            self.total.store(total, Ordering::Relaxed);
        }
    }

    /// Renames the file the progress reports.
    fn rename(&self, name: &str) {
        if let Ok(mut current) = self.name.lock() {
            *current = name.to_string();
        }
    }

    /// Stops the reporter and prints the final line.
    fn finish(mut self) {
        let done = self.transferred.load(Ordering::Relaxed);
        let current = self
            .name
            .lock()
            .map(|name| name.clone())
            .unwrap_or_default();
        self.stop_reporter();
        eprintln!(
            "{PROGRESS_PREFIX} {} {current}: {} done",
            self.label,
            human_bytes(done)
        );
    }

    /// Stops the reporter of the progress.
    fn stop_reporter(&mut self) {
        let _ = self.stop.send(true);
        if let Some(reporter) = self.reporter.take() {
            reporter.abort();
        }
    }
}

impl Drop for TransferProgress {
    fn drop(&mut self) {
        self.stop_reporter();
    }
}

/// Formats a number of bytes the way the Go implementation does.
fn human_bytes(count: u64) -> String {
    const UNIT: u64 = 1024;
    if count < UNIT {
        return format!("{count} B");
    }
    let units = ["KiB", "MiB", "GiB", "TiB"];
    let mut value = count as f64;
    let mut index = 0usize;
    while value >= UNIT as f64 && index < units.len() - 1 {
        value /= UNIT as f64;
        index += 1;
    }
    format!("{value:.1} {}", units[index])
}
