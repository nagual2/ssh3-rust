use std::path::PathBuf;

use crate::{Ssh3ClientConfig, Ssh3ClientError};

#[cfg(any(unix, windows))]
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};
#[cfg(any(unix, windows))]
use ssh3_auth::{Ssh3JwtAlgorithm, build_bearer_token_with_signer};
#[cfg(any(unix, windows))]
use std::env;
#[cfg(any(unix, windows))]
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(any(unix, windows))]
use std::path::Path;

/// The prefix that marks an agent socket setting as a Windows named pipe.
#[cfg_attr(not(windows), allow(dead_code))]
const AGENT_PIPE_PREFIX: &str = r"\\.\";

/// The named pipe the OpenSSH for Windows agent service listens on.
#[cfg_attr(not(windows), allow(dead_code))]
const DEFAULT_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

#[cfg(any(unix, windows))]
const SSH_AGENT_FAILURE: u8 = 5;
#[cfg(any(unix, windows))]
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
#[cfg(any(unix, windows))]
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
#[cfg(any(unix, windows))]
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
#[cfg(any(unix, windows))]
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
#[cfg(any(unix, windows))]
const SSH_AGENT_RSA_SHA2_256: u32 = 2;

/// The explicit Windows named pipe of a socket setting: `None` when the
/// value does not name a pipe (an unset variable or a unix-style socket
/// path inherited from an ssh config), so the caller rides the default
/// OpenSSH pipe.
#[cfg_attr(not(windows), allow(dead_code))]
fn explicit_agent_pipe_name(sock_path: Option<&str>) -> Option<String> {
    sock_path
        .filter(|value| value.starts_with(AGENT_PIPE_PREFIX))
        .map(str::to_string)
}

/// The Windows pipe name of a socket setting: an explicit named-pipe path
/// wins, anything else (an unset variable or a unix-style socket path) rides
/// the default OpenSSH pipe (the resolution of the Go reference
/// `agentPipeName`).
#[cfg_attr(not(windows), allow(dead_code))]
fn agent_pipe_name(sock_path: Option<&str>) -> String {
    explicit_agent_pipe_name(sock_path).unwrap_or_else(|| DEFAULT_AGENT_PIPE.to_string())
}

#[derive(Clone, Debug)]
pub enum Ssh3AgentSelection {
    First,
    PublicKey(PathBuf),
}

/// The resolved endpoint of the local SSH agent connection.
#[cfg(any(unix, windows))]
#[derive(Clone, Debug)]
struct AgentEndpoint {
    /// The unix socket path or the Windows pipe name of the agent.
    path: PathBuf,
    /// Whether the endpoint was explicitly configured: a failed connection
    /// of an explicit endpoint is a hard error, while a failure of the
    /// implicit default Windows pipe only means no agent is running.
    explicit: bool,
}

/// Resolves the local endpoint of the SSH agent: the explicit
/// `--agent-socket` value first, the `SSH_AUTH_SOCK` environment variable
/// next.
///
/// On Windows an explicit value only names an endpoint when it is a
/// `\\.\pipe\` path: any other value (or no value at all) rides the default
/// OpenSSH pipe, so a run without an agent keeps working (the semantics of
/// the Go reference `AgentDial`).
#[cfg(any(unix, windows))]
fn resolve_agent_endpoint(config: &Ssh3ClientConfig) -> Option<AgentEndpoint> {
    #[cfg(unix)]
    {
        let path = config
            .agent_socket
            .clone()
            .or_else(|| env::var_os("SSH_AUTH_SOCK").map(PathBuf::from))?;
        Some(AgentEndpoint {
            path,
            explicit: true,
        })
    }

    #[cfg(windows)]
    {
        let sock_path = config
            .agent_socket
            .as_ref()
            .and_then(|path| path.to_str())
            .map(str::to_string)
            .or_else(|| env::var("SSH_AUTH_SOCK").ok());
        let explicit = explicit_agent_pipe_name(sock_path.as_deref()).is_some();
        Some(AgentEndpoint {
            path: PathBuf::from(agent_pipe_name(sock_path.as_deref())),
            explicit,
        })
    }
}

/// The socket path or pipe name of the resolved SSH agent endpoint, for the
/// plumbing that only carries the endpoint value.
pub(crate) fn resolve_agent_socket_path(
    config: &Ssh3ClientConfig,
) -> Result<PathBuf, Ssh3ClientError> {
    #[cfg(any(unix, windows))]
    {
        resolve_agent_endpoint(config)
            .map(|endpoint| endpoint.path)
            .ok_or(Ssh3ClientError::AgentUnavailable)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = config;
        Err(Ssh3ClientError::AgentUnavailable)
    }
}

pub fn build_agent_bearer_token(
    config: &Ssh3ClientConfig,
    selection: &Ssh3AgentSelection,
    username: &str,
    conversation_id: &[u8; 32],
) -> Result<String, Ssh3ClientError> {
    #[cfg(any(unix, windows))]
    {
        let mut agent = SshAgentClient::connect(config)?;
        let identity = agent.select_identity(selection)?;
        build_bearer_token_with_signer(
            &identity.public_key,
            username,
            conversation_id,
            |jwt_algorithm, signing_input| {
                let signature = agent.sign(
                    &identity.key_blob,
                    signing_input,
                    agent_sign_flags(jwt_algorithm)?,
                )?;
                jwt_signature_from_agent_signature(jwt_algorithm, &signature)
            },
        )
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (config, selection, username, conversation_id);
        Err(Ssh3ClientError::AgentUnavailable)
    }
}

#[cfg(any(unix, windows))]
#[derive(Clone, Debug)]
struct AgentIdentity {
    key_blob: Vec<u8>,
    public_key: PublicKey,
}

/// The blocking transport of a local SSH agent connection: a unix domain
/// socket or a Windows named pipe, both behind the same `Read`/`Write`
/// surface so the agent protocol above them does not branch.
#[cfg(any(unix, windows))]
enum AgentStream {
    /// A unix domain socket.
    #[cfg(unix)]
    UnixSocket(UnixStream),
    /// A Windows named pipe.
    #[cfg(windows)]
    NamedPipe(NamedPipeStream),
}

#[cfg(any(unix, windows))]
impl AgentStream {
    /// Connects the transport of a resolved agent endpoint.
    fn connect(endpoint: &AgentEndpoint) -> Result<Self, Ssh3ClientError> {
        #[cfg(unix)]
        {
            Ok(Self::UnixSocket(
                UnixStream::connect(&endpoint.path).map_err(Ssh3ClientError::Io)?,
            ))
        }

        #[cfg(windows)]
        {
            let pipe_name = endpoint.path.to_str().ok_or_else(|| {
                Ssh3ClientError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the SSH agent pipe name is not valid Unicode",
                ))
            })?;
            Ok(Self::NamedPipe(
                NamedPipeStream::connect(pipe_name).map_err(Ssh3ClientError::Io)?,
            ))
        }
    }
}

#[cfg(any(unix, windows))]
impl Read for AgentStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::UnixSocket(stream) => stream.read(buf),
            #[cfg(windows)]
            Self::NamedPipe(pipe) => pipe.read(buf),
        }
    }
}

#[cfg(any(unix, windows))]
impl Write for AgentStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::UnixSocket(stream) => stream.write(buf),
            #[cfg(windows)]
            Self::NamedPipe(pipe) => pipe.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::UnixSocket(stream) => stream.flush(),
            #[cfg(windows)]
            Self::NamedPipe(pipe) => pipe.flush(),
        }
    }
}

/// The client side of a Windows named pipe, opened with the flags of the
/// dial of the Go reference (`winio.DialPipe`): the security quality of
/// service is pinned so a squatted pipe cannot impersonate the client.
#[cfg(windows)]
struct NamedPipeStream {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl NamedPipeStream {
    /// Opens a client connection of a named pipe.
    ///
    /// A busy pipe waits for a free instance the way the dial of the Go
    /// reference does: a retry every 10 ms within a 2 s deadline.
    fn connect(pipe_name: &str) -> io::Result<Self> {
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};

        let pipe_name_utf16: Vec<u16> =
            pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            // SAFETY: the name is null-terminated for the duration of the
            // call and the null attributes and template are documented as
            // unused for an existing pipe.
            let handle = unsafe {
                CreateFileW(
                    pipe_name_utf16.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    windows_sys::Win32::Storage::FileSystem::SECURITY_SQOS_PRESENT,
                    std::ptr::null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                return Ok(Self { handle });
            }
            let error = io::Error::last_os_error();
            let busy = error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_PIPE_BUSY as i32);
            if !busy || std::time::Instant::now() >= deadline {
                return Err(error);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[cfg(windows)]
impl Read for NamedPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use windows_sys::Win32::Storage::FileSystem::ReadFile;

        if buf.is_empty() {
            return Ok(0);
        }
        let mut read: u32 = 0;
        // SAFETY: the buffer is valid for the duration of the call and the
        // handle is an open file of the process.
        let ok = unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr(),
                u32::try_from(buf.len()).unwrap_or(u32::MAX),
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            // The peer closed the pipe: the read end sees the end of the
            // stream, exactly like a closed unix socket.
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE as i32)
            {
                return Ok(0);
            }
            return Err(error);
        }
        Ok(read as usize)
    }
}

#[cfg(windows)]
impl Write for NamedPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use windows_sys::Win32::Storage::FileSystem::WriteFile;

        if buf.is_empty() {
            return Ok(0);
        }
        let mut written: u32 = 0;
        // SAFETY: the buffer is valid for the duration of the call and the
        // handle is an open file of the process.
        let ok = unsafe {
            WriteFile(
                self.handle,
                buf.as_ptr(),
                u32::try_from(buf.len()).unwrap_or(u32::MAX),
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(written as usize)
    }

    // The pipe carries the bytes to the agent as they are written: there is
    // no userspace buffer to flush.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for NamedPipeStream {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        // SAFETY: the handle is owned by this stream and closed exactly once.
        unsafe { CloseHandle(self.handle) };
    }
}

#[cfg(any(unix, windows))]
struct SshAgentClient {
    stream: AgentStream,
}

#[cfg(any(unix, windows))]
impl SshAgentClient {
    /// Connects to the local SSH agent.
    ///
    /// The error semantics of the Go reference `AgentDial`: a failed
    /// connection of an explicitly configured endpoint is a hard error,
    /// while a failure of the implicit default Windows pipe only means no
    /// agent is running and comes back as `AgentUnavailable`, so a run
    /// without an agent keeps working.
    fn connect(config: &Ssh3ClientConfig) -> Result<Self, Ssh3ClientError> {
        let endpoint = resolve_agent_endpoint(config).ok_or(Ssh3ClientError::AgentUnavailable)?;
        let stream = match AgentStream::connect(&endpoint) {
            Ok(stream) => stream,
            Err(err) if endpoint.explicit => return Err(err),
            Err(_) => return Err(Ssh3ClientError::AgentUnavailable),
        };
        Ok(Self { stream })
    }

    fn select_identity(
        &mut self,
        selection: &Ssh3AgentSelection,
    ) -> Result<AgentIdentity, Ssh3ClientError> {
        let identities = self.list_identities()?;
        match selection {
            Ssh3AgentSelection::First => identities
                .into_iter()
                .find(|identity| is_supported_agent_key(&identity.public_key))
                .ok_or(Ssh3ClientError::AgentKeyNotFound),
            Ssh3AgentSelection::PublicKey(path) => {
                let expected = load_agent_public_key(path)?;
                let expected_blob = expected.to_bytes().map_err(Ssh3ClientError::SshKey)?;
                let identity = identities
                    .into_iter()
                    .find(|identity| identity.key_blob == expected_blob)
                    .ok_or(Ssh3ClientError::AgentKeyNotFound)?;
                if !is_supported_agent_key(&identity.public_key) {
                    return Err(Ssh3ClientError::UnsupportedAgentKey(
                        identity.public_key.algorithm().as_str().to_string(),
                    ));
                }
                Ok(identity)
            }
        }
    }

    fn list_identities(&mut self) -> Result<Vec<AgentIdentity>, Ssh3ClientError> {
        self.write_message(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        let response = self.read_message()?;
        let mut cursor = response.as_slice();
        match read_byte(&mut cursor)? {
            SSH_AGENT_IDENTITIES_ANSWER => {
                let count = read_u32(&mut cursor)? as usize;
                let mut identities = Vec::with_capacity(count);
                for _ in 0..count {
                    let key_blob = read_ssh_string(&mut cursor)?;
                    let _comment = read_ssh_string(&mut cursor)?;
                    identities.push(AgentIdentity {
                        public_key: PublicKey::from_bytes(&key_blob)
                            .map_err(Ssh3ClientError::SshKey)?,
                        key_blob,
                    });
                }
                if !cursor.is_empty() {
                    return Err(Ssh3ClientError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in SSH agent identities reply",
                    )));
                }
                Ok(identities)
            }
            SSH_AGENT_FAILURE => Err(Ssh3ClientError::AgentKeyNotFound),
            other => Err(Ssh3ClientError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected SSH agent reply type {other}"),
            ))),
        }
    }

    fn sign(
        &mut self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Signature, Ssh3ClientError> {
        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        append_ssh_string(&mut payload, key_blob);
        append_ssh_string(&mut payload, data);
        payload.extend_from_slice(&flags.to_be_bytes());
        self.write_message(&payload)?;

        let response = self.read_message()?;
        let mut cursor = response.as_slice();
        match read_byte(&mut cursor)? {
            SSH_AGENT_SIGN_RESPONSE => {
                let signature_blob = read_ssh_string(&mut cursor)?;
                if !cursor.is_empty() {
                    return Err(Ssh3ClientError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in SSH agent sign reply",
                    )));
                }
                Signature::try_from(signature_blob.as_slice()).map_err(Ssh3ClientError::SshKey)
            }
            SSH_AGENT_FAILURE => Err(Ssh3ClientError::AgentKeyNotFound),
            other => Err(Ssh3ClientError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected SSH agent sign reply type {other}"),
            ))),
        }
    }

    fn write_message(&mut self, payload: &[u8]) -> Result<(), Ssh3ClientError> {
        let len = u32::try_from(payload.len()).map_err(|_| {
            Ssh3ClientError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSH agent payload exceeds u32 length",
            ))
        })?;
        self.stream
            .write_all(&len.to_be_bytes())
            .map_err(Ssh3ClientError::Io)?;
        self.stream.write_all(payload).map_err(Ssh3ClientError::Io)
    }

    fn read_message(&mut self) -> Result<Vec<u8>, Ssh3ClientError> {
        let mut len = [0u8; 4];
        self.stream
            .read_exact(&mut len)
            .map_err(Ssh3ClientError::Io)?;
        let len = u32::from_be_bytes(len) as usize;
        let mut payload = vec![0u8; len];
        self.stream
            .read_exact(&mut payload)
            .map_err(Ssh3ClientError::Io)?;
        Ok(payload)
    }
}

#[cfg(any(unix, windows))]
fn load_agent_public_key(path: &Path) -> Result<PublicKey, Ssh3ClientError> {
    PublicKey::read_openssh_file(path)
        .or_else(|_| {
            PrivateKey::read_openssh_file(path).map(|private_key| private_key.public_key().clone())
        })
        .or_else(|_| {
            let pub_path = PathBuf::from(format!("{}.pub", path.display()));
            PublicKey::read_openssh_file(&pub_path)
        })
        .map_err(Ssh3ClientError::SshKey)
}

#[cfg(any(unix, windows))]
fn is_supported_agent_key(public_key: &PublicKey) -> bool {
    matches!(
        public_key.algorithm(),
        Algorithm::Ed25519 | Algorithm::Rsa { .. }
    )
}

#[cfg(any(unix, windows))]
fn agent_sign_flags(jwt_algorithm: Ssh3JwtAlgorithm) -> Result<u32, Ssh3ClientError> {
    match jwt_algorithm {
        Ssh3JwtAlgorithm::EdDsa => Ok(0),
        Ssh3JwtAlgorithm::Rs256 => Ok(SSH_AGENT_RSA_SHA2_256),
        Ssh3JwtAlgorithm::Es256 => Err(Ssh3ClientError::UnsupportedAgentKey(
            "ecdsa-sha2-nistp256".to_string(),
        )),
    }
}

#[cfg(any(unix, windows))]
fn jwt_signature_from_agent_signature(
    jwt_algorithm: Ssh3JwtAlgorithm,
    signature: &Signature,
) -> Result<Vec<u8>, Ssh3ClientError> {
    match jwt_algorithm {
        Ssh3JwtAlgorithm::EdDsa => {
            if signature.algorithm() != Algorithm::Ed25519 {
                return Err(Ssh3ClientError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSH agent returned the wrong Ed25519 signature algorithm",
                )));
            }
            Ok(signature.as_bytes().to_vec())
        }
        Ssh3JwtAlgorithm::Rs256 => {
            if signature.algorithm()
                != (Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                })
            {
                return Err(Ssh3ClientError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSH agent returned the wrong RSA signature algorithm",
                )));
            }
            Ok(signature.as_bytes().to_vec())
        }
        Ssh3JwtAlgorithm::Es256 => Err(Ssh3ClientError::UnsupportedAgentKey(
            "ecdsa-sha2-nistp256".to_string(),
        )),
    }
}

#[cfg(any(unix, windows))]
fn append_ssh_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(any(unix, windows))]
fn read_byte(cursor: &mut &[u8]) -> Result<u8, Ssh3ClientError> {
    let Some((&byte, rest)) = cursor.split_first() else {
        return Err(Ssh3ClientError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated SSH agent message",
        )));
    };
    *cursor = rest;
    Ok(byte)
}

#[cfg(any(unix, windows))]
fn read_u32(cursor: &mut &[u8]) -> Result<u32, Ssh3ClientError> {
    if cursor.len() < 4 {
        return Err(Ssh3ClientError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated SSH agent u32",
        )));
    }
    let (prefix, rest) = cursor.split_at(4);
    *cursor = rest;
    Ok(u32::from_be_bytes(prefix.try_into().unwrap()))
}

#[cfg(any(unix, windows))]
fn read_ssh_string(cursor: &mut &[u8]) -> Result<Vec<u8>, Ssh3ClientError> {
    let len = read_u32(cursor)? as usize;
    if cursor.len() < len {
        return Err(Ssh3ClientError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated SSH agent string",
        )));
    }
    let (value, rest) = cursor.split_at(len);
    *cursor = rest;
    Ok(value.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resolution of the pipe name mirrors the contract test of the Go
    /// reference (`agent_dial_windows_test.go`): an explicit named-pipe path
    /// wins, any other value (unset, unix path, windows path) rides the
    /// default OpenSSH pipe.
    #[test]
    fn the_agent_pipe_name_follows_the_go_reference_contract() {
        let cases = [
            (Some(r"\\.\pipe\custom-agent"), r"\\.\pipe\custom-agent"),
            (None, DEFAULT_AGENT_PIPE),
            (Some("/tmp/agent.sock"), DEFAULT_AGENT_PIPE),
            (Some(r"C:\pipe\agent"), DEFAULT_AGENT_PIPE),
        ];
        for (sock_path, expected) in cases {
            assert_eq!(
                agent_pipe_name(sock_path),
                expected,
                "sock_path {sock_path:?}"
            );
        }
    }

    /// Only a `\\.\pipe\` value is an explicit pipe: the other values leave
    /// the choice to the default rule.
    #[test]
    fn the_explicit_agent_pipe_name_selects_only_pipe_paths() {
        assert_eq!(
            explicit_agent_pipe_name(Some(r"\\.\pipe\custom-agent")).as_deref(),
            Some(r"\\.\pipe\custom-agent")
        );
        assert_eq!(explicit_agent_pipe_name(None), None);
        assert_eq!(explicit_agent_pipe_name(Some("")), None);
        assert_eq!(explicit_agent_pipe_name(Some("/tmp/agent.sock")), None);
        assert_eq!(explicit_agent_pipe_name(Some(r"C:\pipe\agent")), None);
    }

    /// Serializes the scenarios that touch the process-wide `SSH_AUTH_SOCK`.
    #[cfg(windows)]
    fn lock_agent_env_tests() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(windows)]
    fn test_config() -> Ssh3ClientConfig {
        Ssh3ClientConfig::new("https://localhost/ssh3-term".parse().unwrap())
    }

    /// Mirrors `TestAgentDialExplicitPipeFailure` of the Go reference: a
    /// pipe that was named explicitly and refuses the connection is a hard
    /// error, not the soft "no agent" one.
    #[cfg(windows)]
    #[test]
    fn the_explicit_agent_pipe_failure_is_a_hard_error() {
        let _guard = lock_agent_env_tests();
        let mut config = test_config();
        config.agent_socket = Some(r"\\.\pipe\ssh3-agent-dial-test-absent".into());
        let error = match SshAgentClient::connect(&config) {
            Ok(_) => panic!("dial on an absent explicit pipe must fail"),
            Err(error) => error,
        };
        assert!(
            !matches!(error, Ssh3ClientError::AgentUnavailable),
            "explicit pipe failure must be a hard error, got {error:?}"
        );
    }

    /// Mirrors `TestAgentDialDefaultPipeSoftFailure` of the Go reference: a
    /// failure of the implicit default pipe stays the soft "no agent" one,
    /// so a run without an agent keeps working.
    #[cfg(windows)]
    #[test]
    fn the_default_agent_pipe_failure_stays_soft() {
        let _guard = lock_agent_env_tests();
        let previous = env::var("SSH_AUTH_SOCK").ok();
        // SAFETY: the tests that touch the environment are serialized by the
        // lock above, and the previous value is restored before returning.
        unsafe { env::set_var("SSH_AUTH_SOCK", "") };
        let result = SshAgentClient::connect(&test_config());
        match previous {
            Some(value) => unsafe { env::set_var("SSH_AUTH_SOCK", value) },
            None => unsafe { env::remove_var("SSH_AUTH_SOCK") },
        }
        // An agent service on the host makes the connection succeed; any
        // failure must stay the soft "no agent" one.
        match result {
            Ok(_) => {}
            Err(Ssh3ClientError::AgentUnavailable) => {}
            Err(error) => {
                panic!("dial on the implicit default pipe must fail softly, got {error:?}")
            }
        }
    }
}
