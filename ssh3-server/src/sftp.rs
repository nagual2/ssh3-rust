//! The SFTP subsystem: the file transfer channel of the server.
//!
//! The subsystem serves the SFTP protocol (version 3) over a channel of the
//! type `sftp`: the client opens the channel and the bytes of the channel are
//! the bytes of the protocol. The reference implementation of this behavior
//! lives in `nagual2/ssh3-go`, files `cmd/sftp_subsystem.go` (the subsystem
//! of the server), `cmd/internal_sftp.go` (the child of the chroot jail) and
//! `cmd/sftp_client.go` (the client).
//!
//! # Path isolation
//!
//! The isolation of the paths of the user follows the sshd model of the
//! reference implementation:
//!
//! * [`SftpJailMode::Chroot`] (the default) — the network-facing process
//!   never opens a path of the user. A short-lived child is started for the
//!   channel, it chroots into the home directory of the user and drops to the
//!   uid/gid of the user before the first path is opened. The confinement is
//!   the kernel's: after the chroot neither an absolute symlink nor a `..`
//!   reaches outside of the jail.
//! * [`SftpJailMode::Lexical`] — the in-process jail: the client paths are
//!   mapped onto the home directory of the user and the result is checked
//!   against the jail, symlinks included. The privileges of the server
//!   process apply, so the mode only makes sense for a server that holds no
//!   privileges worth abusing.
//!
//! The chroot jail needs the privileges of the operating system: a server
//! that does not run as root serves the subsystem in process, with the
//! lexical jail, exactly like the Go implementation does.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::{Handler, StatusReply};
use ssh3_core::Ssh3Channel;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::config::{SftpJailMode, Ssh3ServerConfig};
use crate::error::Ssh3ServerError;
use crate::session::SessionUser;
use crate::sftp_child;
use crate::sftp_stream::ChannelStream;

/// The type of the channel the SFTP subsystem runs on.
pub(crate) const CHANNEL_TYPE_SFTP: &[u8] = b"sftp";

/// The number of the entries a `READDIR` request answers with.
const DIRECTORY_BATCH: usize = 64;

/// The permissions the files of the user get when they are created.
#[cfg(unix)]
const CREATED_FILE_MODE: u32 = 0o644;

/// The permissions the directories of the user get when they are created.
#[cfg(unix)]
const CREATED_DIRECTORY_MODE: u32 = 0o755;

/// The failures of the SFTP subsystem.
///
/// The type is the error of the SFTP handler: every failure is reported to
/// the client as a status packet, never as a panic.
#[derive(Debug)]
pub(crate) enum SftpError {
    /// The client tried to leave the jail.
    Escape(String),
    /// A path of the jail does not exist.
    NotFound,
    /// The server refused the operation.
    PermissionDenied,
    /// The operation failed.
    Failure(String),
    /// The operation is not supported.
    Unsupported,
    /// The end of the file or of the directory was reached.
    Eof,
}

impl From<SftpError> for StatusReply {
    fn from(error: SftpError) -> Self {
        match error {
            SftpError::Escape(path) => StatusReply::new(StatusCode::PermissionDenied)
                .with_message(format!("path {path} escapes the home directory")),
            SftpError::NotFound => StatusReply::new(StatusCode::NoSuchFile),
            SftpError::PermissionDenied => StatusReply::new(StatusCode::PermissionDenied),
            SftpError::Failure(message) => {
                StatusReply::new(StatusCode::Failure).with_message(message)
            }
            SftpError::Unsupported => StatusReply::new(StatusCode::OpUnsupported),
            SftpError::Eof => StatusReply::new(StatusCode::Eof),
        }
    }
}

impl From<io::Error> for SftpError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => SftpError::NotFound,
            io::ErrorKind::PermissionDenied => SftpError::PermissionDenied,
            _ => SftpError::Failure(error.to_string()),
        }
    }
}

/// The number of the concurrent SFTP sessions of every user.
///
/// The budget bounds the work one account may start: the sessions of a user
/// are counted across their conversations, and a session over the cap is
/// refused with a readable reason. The limit is the
/// `-max-sftp-sessions-per-user` option of the Go implementation; `0`
/// disables the budget.
#[derive(Debug)]
pub struct SftpSessionBudget {
    /// The number of the sessions of every user.
    sessions: Mutex<HashMap<String, usize>>,
}

impl Default for SftpSessionBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpSessionBudget {
    /// Builds an empty budget.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Takes a slot of the user, if the budget allows it.
    pub fn try_acquire(&self, user: &str, limit: usize) -> bool {
        if limit == 0 {
            return true;
        }
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let counter = sessions.entry(user.to_string()).or_insert(0);
        if *counter >= limit {
            return false;
        }
        *counter += 1;
        true
    }

    /// Gives the slot of the user back.
    pub fn release(&self, user: &str) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(counter) = sessions.get_mut(user) {
            *counter = counter.saturating_sub(1);
            if *counter == 0 {
                sessions.remove(user);
            }
        }
    }

    /// Returns the number of the sessions the user holds.
    pub fn current(&self, user: &str) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(user)
            .copied()
            .unwrap_or(0)
    }
}

/// The jail of the SFTP subsystem: the mapping of the client paths onto the
/// paths of the server.
pub(crate) struct SftpJail {
    /// The directory the jail is rooted at.
    root: PathBuf,
    /// The canonical form of the root; it is the border the paths of the
    /// client must not cross.
    canonical_root: PathBuf,
    /// `true` when the process runs chrooted into the root.
    chrooted: bool,
}

impl SftpJail {
    /// Builds the jail of a root directory.
    ///
    /// A chrooted jail is rooted at the root of the file system of the
    /// process: the paths of the client are the paths of the jail.
    pub(crate) fn new(root: PathBuf, chrooted: bool) -> io::Result<Self> {
        let root = if chrooted { PathBuf::from("/") } else { root };
        let canonical_root = root.canonicalize()?;
        Ok(Self {
            root,
            canonical_root,
            chrooted,
        })
    }

    /// Maps a path of the client onto a path of the server.
    ///
    /// Two namespaces share the wire: the jail-relative paths (`docs/f` and
    /// `/docs/f`) resolve under the home directory of the user, while the
    /// server-absolute paths (`/home/user/docs/f`) are honored as they are
    /// when they already live inside the jail — the spelling a user knows
    /// from an interactive shell. The paths outside of the jail are mapped
    /// into it, so a client can never reach them.
    pub(crate) fn resolve(&self, client_path: &str) -> Result<PathBuf, SftpError> {
        let trimmed = client_path.trim();
        let trimmed = if trimmed.is_empty() { "/" } else { trimmed };
        if self.chrooted {
            // inside the chroot the path of the client is the path of the
            // jail: the kernel confines it, a ".." cannot leave the root
            return Ok(PathBuf::from(normalize_absolute(trimmed)));
        }
        let server_path = self.map_into_root(trimmed);
        self.ensure_within_root(&server_path)?;
        Ok(server_path)
    }

    /// Maps a path of the server onto the path the client sees.
    pub(crate) fn client_path(&self, server_path: &Path) -> String {
        match server_path.strip_prefix(&self.root) {
            Ok(relative) => {
                let relative = relative.to_string_lossy().replace('\\', "/");
                if relative.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{relative}")
                }
            }
            Err(_) => server_path.to_string_lossy().replace('\\', "/"),
        }
    }

    /// Maps a path of the client into the root of the jail.
    fn map_into_root(&self, client_path: &str) -> PathBuf {
        let normalized = normalize_absolute(client_path);
        if client_path.starts_with('/') && within_root(Path::new(&normalized), &self.root) {
            return PathBuf::from(normalized);
        }
        self.root.join(normalized.trim_start_matches('/'))
    }

    /// Rejects the paths that leave the root of the jail.
    ///
    /// The check resolves the symlinks of the path: a link inside the jail
    /// that points outside of it is an escape, not a path.
    fn ensure_within_root(&self, path: &Path) -> Result<(), SftpError> {
        let canonical = canonicalize_with_missing(path).map_err(SftpError::from)?;
        if canonical == self.canonical_root || canonical.starts_with(&self.canonical_root) {
            return Ok(());
        }
        Err(SftpError::Escape(path.display().to_string()))
    }
}

/// Normalizes a path of the client into an absolute path without `.` and `..`.
///
/// The function mirrors the `path.Clean("/" + p)` of the Go implementation:
/// the `..` components are resolved lexically and can never leave the root.
fn normalize_absolute(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return "/".to_string();
    }
    format!("/{}", components.join("/"))
}

/// Returns `true` when the path lives under the root.
///
/// The root itself counts as within, and the root of the file system
/// contains every absolute path.
fn within_root(path: &Path, root: &Path) -> bool {
    if root == Path::new("/") {
        return path.is_absolute();
    }
    path == root || path.starts_with(root)
}

/// Resolves a path as far as the file system allows.
///
/// The path of a file that does not exist yet is resolved through its
/// closest existing ancestor, so the check of the jail also covers the files
/// that are about to be created.
fn canonicalize_with_missing(path: &Path) -> io::Result<PathBuf> {
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        match current.canonicalize() {
            Ok(canonical) => {
                let mut resolved = canonical;
                for part in suffix.iter().rev() {
                    resolved.push(part);
                }
                return Ok(resolved);
            }
            Err(error) => {
                let Some(name) = current.file_name().map(std::ffi::OsStr::to_os_string) else {
                    return Err(error);
                };
                let Some(parent) = current.parent().map(Path::to_path_buf) else {
                    return Err(error);
                };
                if parent.as_os_str().is_empty() {
                    return Err(error);
                }
                suffix.push(name);
                current = parent;
            }
        }
    }
}

/// An open file or directory of the client.
enum SftpHandle {
    /// An open file.
    File {
        /// The file of the jail.
        file: tokio::fs::File,
        /// The path of the file in the jail.
        path: PathBuf,
    },
    /// An open directory and the entries it holds.
    Directory {
        /// The entries of the directory.
        entries: Vec<DirectoryEntry>,
        /// The number of the entries that were sent to the client.
        position: usize,
    },
}

/// An entry of a directory of the client.
struct DirectoryEntry {
    /// The name of the entry.
    name: String,
    /// The attributes of the entry.
    attributes: FileAttributes,
}

/// The handler of the SFTP protocol of the server.
///
/// The handler serves the paths of one jail: every path of the client is
/// mapped into the jail before it is opened, and a path that leaves the jail
/// is refused.
pub(crate) struct SftpHandler {
    /// The jail the paths of the client are mapped into.
    jail: SftpJail,
    /// The files and the directories the client opened.
    handles: HashMap<String, SftpHandle>,
    /// The number of the handles that were handed out.
    next_handle: u64,
    /// The account the files of the user belong to.
    ///
    /// The owner is set on the files the client creates, like the Go
    /// implementation does. It is empty when the server may not change the
    /// owner of a file, and it is empty in the chroot jail: there the child
    /// already runs as the user.
    owner: Option<(u32, u32)>,
}

impl SftpHandler {
    /// Builds the handler of a jail.
    pub(crate) fn new(jail: SftpJail, owner: Option<(u32, u32)>) -> Self {
        Self {
            jail,
            handles: HashMap::new(),
            next_handle: 0,
            owner,
        }
    }

    /// Gives a file the owner of the account of the user.
    ///
    /// The failure is not fatal: the file stays with the owner of the server
    /// process, like the Go implementation does.
    fn chown_to_user(&self, path: &Path) {
        let Some((uid, gid)) = self.owner else {
            return;
        };
        chown_to_user(path, uid, gid);
    }

    /// Registers a handle and returns its name.
    fn register(&mut self, handle: SftpHandle) -> String {
        self.next_handle += 1;
        let name = format!("h{}", self.next_handle);
        self.handles.insert(name.clone(), handle);
        name
    }

    /// Returns the file of a handle.
    fn file_mut(&mut self, handle: &str) -> Result<&mut tokio::fs::File, SftpError> {
        match self.handles.get_mut(handle) {
            Some(SftpHandle::File { file, .. }) => Ok(file),
            Some(SftpHandle::Directory { .. }) => {
                Err(SftpError::Failure("the handle is a directory".to_string()))
            }
            None => Err(SftpError::NotFound),
        }
    }

    /// Returns the path of a handle in the jail.
    fn handle_path(&self, handle: &str) -> Result<PathBuf, SftpError> {
        match self.handles.get(handle) {
            Some(SftpHandle::File { path, .. }) => Ok(path.clone()),
            Some(SftpHandle::Directory { .. }) => {
                Err(SftpError::Failure("the handle is a directory".to_string()))
            }
            None => Err(SftpError::NotFound),
        }
    }

    /// Returns the attributes of a path of the jail.
    async fn attributes(&self, path: &Path) -> Result<FileAttributes, SftpError> {
        let metadata = tokio::fs::metadata(path).await?;
        Ok(FileAttributes::from(&metadata))
    }

    /// Returns the attributes of a path of the jail, without following the
    /// symlinks.
    async fn link_attributes(&self, path: &Path) -> Result<FileAttributes, SftpError> {
        let metadata = tokio::fs::symlink_metadata(path).await?;
        Ok(FileAttributes::from(&metadata))
    }

    /// Builds the description of a directory entry.
    fn directory_entry(name: String, attributes: FileAttributes) -> DirectoryEntry {
        DirectoryEntry { name, attributes }
    }
}

/// Builds the status of a successful request.
fn status_ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_string(),
        language_tag: "en-US".to_string(),
    }
}

impl Handler for SftpHandler {
    type Error = SftpError;

    fn unimplemented(&self) -> Self::Error {
        SftpError::Unsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.jail.resolve(&filename)?;
        let mut options = tokio::fs::OpenOptions::new();
        let readable = pflags.contains(OpenFlags::READ);
        let writable = pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::CREATE);
        if readable {
            options.read(true);
        }
        if writable {
            options.write(true);
        }
        if pflags.contains(OpenFlags::CREATE) {
            if pflags.contains(OpenFlags::EXCLUDE) {
                options.create_new(true);
            } else {
                options.create(true);
            }
        }
        if pflags.contains(OpenFlags::TRUNCATE) {
            options.truncate(true);
        }
        #[cfg(unix)]
        {
            options.mode(CREATED_FILE_MODE);
        }
        let file = options.open(&path).await?;
        if pflags.contains(OpenFlags::CREATE) {
            // the files the client creates belong to the account of the user
            self.chown_to_user(&path);
        }
        let handle = self.register(SftpHandle::File { file, path });
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(status_ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let file = self.file_mut(&handle)?;
        let mut buffer = vec![0u8; len as usize];
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let read = file.read(&mut buffer).await?;
        buffer.truncate(read);
        Ok(Data { id, data: buffer })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self.file_mut(&handle)?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.write_all(&data).await?;
        file.flush().await?;
        Ok(status_ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let server_path = self.jail.resolve(&path)?;
        let attributes = self.link_attributes(&server_path).await?;
        Ok(Attrs {
            id,
            attrs: attributes,
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let file = self.file_mut(&handle)?;
        let metadata = file.metadata().await?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&metadata),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let server_path = self.jail.resolve(&path)?;
        set_timestamps(&server_path, &attrs).await?;
        Ok(status_ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self.handle_path(&handle)?;
        set_timestamps(&path, &attrs).await?;
        Ok(status_ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let server_path = self.jail.resolve(&path)?;
        let mut reader = tokio::fs::read_dir(&server_path).await?;
        let mut entries = Vec::new();
        while let Some(entry) = reader.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let attributes = match entry.metadata().await {
                Ok(metadata) => FileAttributes::from(&metadata),
                // the entry vanished between the listing and the metadata:
                // the entry is skipped, like the Go implementation does
                Err(_) => continue,
            };
            entries.push(Self::directory_entry(name, attributes));
        }
        let handle = self.register(SftpHandle::Directory {
            entries,
            position: 0,
        });
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(SftpHandle::Directory { entries, position }) = self.handles.get_mut(&handle)
        else {
            return Err(SftpError::NotFound);
        };
        if *position >= entries.len() {
            return Err(SftpError::Eof);
        }
        let end = (*position + DIRECTORY_BATCH).min(entries.len());
        let files: Vec<File> = entries[*position..end]
            .iter()
            .map(|entry| File {
                filename: entry.name.clone(),
                longname: long_name(&entry.name, &entry.attributes),
                attrs: entry.attributes.clone(),
            })
            .collect();
        *position = end;
        Ok(Name { id, files })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let server_path = self.jail.resolve(&filename)?;
        tokio::fs::remove_file(&server_path).await?;
        Ok(status_ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let server_path = self.jail.resolve(&path)?;
        create_directory(&server_path).await?;
        self.chown_to_user(&server_path);
        Ok(status_ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let server_path = self.jail.resolve(&path)?;
        tokio::fs::remove_dir(&server_path).await?;
        Ok(status_ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let server_path = self.jail.resolve(&path)?;
        let client_path = self.jail.client_path(&server_path);
        Ok(Name {
            id,
            files: vec![File::dummy(client_path)],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let server_path = self.jail.resolve(&path)?;
        let attributes = self.attributes(&server_path).await?;
        Ok(Attrs {
            id,
            attrs: attributes,
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let old_path = self.jail.resolve(&oldpath)?;
        let new_path = self.jail.resolve(&newpath)?;
        // the Go implementation refuses to overwrite an existing target
        if tokio::fs::symlink_metadata(&new_path).await.is_ok() {
            return Err(SftpError::Failure(
                "the target of the rename already exists".to_string(),
            ));
        }
        tokio::fs::rename(&old_path, &new_path).await?;
        Ok(status_ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let server_path = self.jail.resolve(&path)?;
        let target = tokio::fs::read_link(&server_path).await?;
        let target = target.to_string_lossy().replace('\\', "/");
        Ok(Name {
            id,
            files: vec![File::dummy(target)],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        let link_path = self.jail.resolve(&linkpath)?;
        let target_path = self.jail.resolve(&targetpath)?;
        create_symlink(&target_path, &link_path).await?;
        Ok(status_ok(id))
    }
}

/// Sets the timestamps of a path of the jail.
///
/// Only the timestamps are honored, like the Go implementation does: the
/// recursive transfer of the client stamps the remote with the mtime of the
/// source, the mode, the owner and the size stay untouched.
async fn set_timestamps(path: &Path, attrs: &FileAttributes) -> Result<(), SftpError> {
    let Some(modified) = attrs.mtime else {
        return Err(SftpError::Unsupported);
    };
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(modified));
    let accessed = attrs
        .atime
        .map(|atime| std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(atime)))
        .unwrap_or(modified);
    let file = std::fs::File::options().read(true).open(path)?;
    file.set_times(
        std::fs::FileTimes::new()
            .set_accessed(accessed)
            .set_modified(modified),
    )?;
    Ok(())
}

/// Creates a directory of the jail, with its missing parents.
#[cfg(unix)]
async fn create_directory(path: &Path) -> Result<(), SftpError> {
    tokio::fs::create_dir_all(path).await?;
    set_directory_mode(path).await
}

/// Creates a directory of the jail, with its missing parents.
#[cfg(not(unix))]
async fn create_directory(path: &Path) -> Result<(), SftpError> {
    tokio::fs::create_dir_all(path).await?;
    Ok(())
}

/// Sets the mode of the directories that were created.
#[cfg(unix)]
async fn set_directory_mode(path: &Path) -> Result<(), SftpError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = tokio::fs::metadata(path).await?;
    let mode = metadata.permissions().mode() & !0o777;
    tokio::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(mode | CREATED_DIRECTORY_MODE),
    )
    .await?;
    Ok(())
}

/// Gives a path the owner of the account of the user.
///
/// The failure is ignored on purpose: the file stays with the owner of the
/// server process, like the Go implementation does.
#[cfg(unix)]
fn chown_to_user(path: &Path, uid: u32, gid: u32) {
    use std::os::unix::fs::chown;

    let _ = chown(path, Some(uid), Some(gid));
}

/// Gives a path the owner of the account of the user.
#[cfg(not(unix))]
fn chown_to_user(_path: &Path, _uid: u32, _gid: u32) {
    // the owner of a file is a property of the account, Windows has none
}

/// Creates a symbolic link inside the jail.
#[cfg(unix)]
async fn create_symlink(target: &Path, link: &Path) -> Result<(), SftpError> {
    tokio::fs::symlink(target, link).await?;
    Ok(())
}

/// Creates a symbolic link inside the jail.
#[cfg(not(unix))]
async fn create_symlink(_target: &Path, _link: &Path) -> Result<(), SftpError> {
    // the creation of a symbolic link needs a privilege Windows does not
    // grant by default
    Err(SftpError::Unsupported)
}

/// Builds the long name of a directory entry.
fn long_name(name: &str, attributes: &FileAttributes) -> String {
    let mode = attributes
        .permissions
        .map(|permissions| format!("{:o}", permissions & 0o777))
        .unwrap_or_else(|| "0".to_string());
    let size = attributes.size.unwrap_or(0);
    format!("{mode} {size} {name}")
}

/// Serves the SFTP subsystem of a channel.
///
/// The subsystem is the file transfer of the server: the client opens a
/// channel of the type `sftp` and the bytes of the channel are the bytes of
/// the SFTP protocol. The channel has its own lifetime: closing it ends the
/// transfer, not the conversation.
pub(crate) async fn handle_sftp_channel(
    channel: Arc<Ssh3Channel>,
    config: &Ssh3ServerConfig,
    session_user: &SessionUser,
) -> Result<(), Ssh3ServerError> {
    let budget = &config.sftp_budget;
    if !budget.try_acquire(&session_user.username, config.max_sftp_sessions_per_user) {
        eprintln!(
            "ssh3-rust-server user {} hit the concurrent sftp session limit, refusing the sftp channel {}",
            session_user.username,
            channel.channel_id()
        );
        let _ = channel.close().await;
        return Ok(());
    }
    let result = serve_sftp_channel(channel, config, session_user).await;
    budget.release(&session_user.username);
    result
}

/// Serves the SFTP protocol over a channel.
async fn serve_sftp_channel(
    channel: Arc<Ssh3Channel>,
    config: &Ssh3ServerConfig,
    session_user: &SessionUser,
) -> Result<(), Ssh3ServerError> {
    let jail_root = config
        .sftp_root
        .clone()
        .unwrap_or_else(|| session_user.home_dir.clone());
    let mode = config.sftp_jail.effective();
    #[cfg(unix)]
    let owner = Some((session_user.uid, session_user.gid));
    #[cfg(not(unix))]
    let owner: Option<(u32, u32)> = None;
    match mode {
        SftpJailMode::Chroot => {
            match sftp_child::spawn_chroot_child(&channel, &jail_root, session_user).await {
                Ok(sftp_child::ChildOutcome::Served) => Ok(()),
                Ok(sftp_child::ChildOutcome::FallbackToInProcess) => {
                    serve_sftp_in_process(channel, &jail_root, false, owner).await
                }
                Err(error) => {
                    eprintln!(
                        "ssh3-rust-server could not start the sftp child for the channel {}: {error}",
                        channel.channel_id()
                    );
                    let _ = channel.close().await;
                    Ok(())
                }
            }
        }
        SftpJailMode::Lexical => serve_sftp_in_process(channel, &jail_root, false, owner).await,
    }
}

/// Serves the SFTP protocol in the process of the server.
///
/// The mode is the lexical jail of the Go implementation: the paths of the
/// client are mapped into the home directory of the user and the result is
/// checked against it, symlinks included.
pub(crate) async fn serve_sftp_in_process(
    channel: Arc<Ssh3Channel>,
    jail_root: &Path,
    chrooted: bool,
    owner: Option<(u32, u32)>,
) -> Result<(), Ssh3ServerError> {
    let jail = match SftpJail::new(jail_root.to_path_buf(), chrooted) {
        Ok(jail) => jail,
        Err(error) => {
            eprintln!(
                "ssh3-rust-server could not open the sftp jail {}: {error}",
                jail_root.display()
            );
            let _ = channel.close().await;
            return Ok(());
        }
    };
    let handler = SftpHandler::new(jail, owner);
    let (stream, mut done) = ChannelStream::new(channel.clone());
    russh_sftp::server::run(stream, handler).await;
    done.wait().await;
    let _ = channel.close().await;
    Ok(())
}
