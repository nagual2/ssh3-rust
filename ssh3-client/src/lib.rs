use std::env;
use std::fmt;
use std::future::poll_fn;
use std::io::{self, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[cfg(unix)]
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use http::{Uri, header::HeaderValue};
#[cfg(unix)]
use nix::sys::termios::{self, SetArg};
use quinn::{ConnectError, Connection, ConnectionError, Endpoint};
use rand::{RngCore, rngs::OsRng};
use reqwest::StatusCode as HttpStatusCode;
use rustls::{RootCertStore, pki_types::CertificateDer};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ssh3_auth::{
    Ssh3AuthError, bearer_authorization_value, build_bearer_token, conversation_id_base64,
    load_private_key,
};
use ssh3_core::{Ssh3Channel, Ssh3ChannelError, Ssh3Conversation, Ssh3ConversationError};
use ssh3_h3::{
    SSH3_USER_HEADER, SSH3_VERSION_STRING, Ssh3BuildConnectRequestError, Ssh3ClientControlStream,
    Ssh3ClientConversationError, Ssh3ConversationIdError, Ssh3EstablishedClientConversation,
    Ssh3SendRequest, generate_conversation_id, new_client, response_server_header,
};
use ssh3_proto::{
    SSH_EXTENDED_DATA_NONE, SSH_EXTENDED_DATA_STDERR, Ssh3ChannelRequest,
    Ssh3ChannelRequestMessage, Ssh3ExecRequest, Ssh3ExitSignalRequest, Ssh3Message, Ssh3PtyRequest,
    Ssh3SignalRequest, Ssh3WindowChangeRequest,
};
use ssh3_quinn::{
    Ssh3AcceptChannelError, Ssh3ConfigError as QuinnConfigError, Ssh3IncomingChannelRouter,
    Ssh3OpenChannelError, Ssh3RouteAcceptedChannelError, client_config_insecure,
    client_config_with_roots, client_config_with_webpki_roots, open_channel,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use url::Url;

mod agent;
mod duration;
mod escape;
mod forward;

pub use agent::Ssh3AgentSelection;
use agent::{build_agent_bearer_token, resolve_agent_socket_path};
pub use duration::{Ssh3DurationError, parse_duration};
pub use escape::{Ssh3EscapeAction, Ssh3EscapeCharError, Ssh3EscapeFilter, parse_escape_char};
pub use forward::{
    Ssh3ForwardParseError, Ssh3ForwardProtocol, Ssh3LocalForwardSpec, parse_local_forward_spec,
};

const DEFAULT_USER_AGENT: &str = SSH3_VERSION_STRING;
const DEFAULT_OIDC_SCOPE: &str = "openid email";
const OIDC_CALLBACK_PATH: &str = "/ssh";

/// The default QUIC handshake timeout of the client.
///
/// The value follows the ssh2 canon of the LoginGraceTime scale, like the Go
/// implementation does.
pub const DEFAULT_HANDSHAKE_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// The default QUIC idle timeout of the client.
///
/// The value follows the ssh2 canon of an idle session that is never killed
/// (ClientAliveInterval=0), like the Go implementation does.
pub const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// The default keep-alive period of the client.
///
/// The keep-alive packets keep an idle session alive, so the idle timeout
/// above only closes a connection the peer really went away.
pub const DEFAULT_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(1);

/// The default escape character of an interactive session.
pub const DEFAULT_ESCAPE_CHAR: u8 = b'~';

/// The geometry of a pty when the local console cannot be queried.
const DEFAULT_PTY_COLUMNS: u16 = 80;
const DEFAULT_PTY_ROWS: u16 = 24;

/// The terminal type reported to the server when neither the caller nor the
/// local environment provides one.
const DEFAULT_TERM_TYPE: &str = "xterm-256color";

#[derive(Clone, Debug)]
pub enum Ssh3TrustStrategy {
    WebPkiRoots,
    Certificates(Vec<CertificateDer<'static>>),
    Insecure,
}

#[derive(Clone, Debug)]
pub struct Ssh3OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub use_pkce: bool,
}

#[derive(Clone, Debug)]
pub struct Ssh3ClientConfig {
    pub target_url: Uri,
    pub server_name: Option<String>,
    pub username: Option<String>,
    pub identity_file: Option<PathBuf>,
    pub agent: Option<Ssh3AgentSelection>,
    pub agent_socket: Option<PathBuf>,
    pub forward_agent: bool,
    pub password: Option<String>,
    pub bearer_token: Option<String>,
    pub oidc: Option<Ssh3OidcConfig>,
    pub user_agent: String,
    pub max_packet_size: u64,
    pub default_datagrams_queue_size: usize,
    pub trust: Ssh3TrustStrategy,
    /// The policy that decides whether the session requests a pseudo-terminal.
    pub pty_policy: Ssh3PtyPolicy,
    /// The terminal type reported to the server; `None` takes the local `TERM`
    /// environment variable and falls back to a 256-color terminal.
    pub term_type: Option<String>,
    /// The escape character of the interactive escape sequences; zero disables
    /// them.
    pub escape_char: u8,
    /// The timeout of the QUIC handshake.
    pub handshake_idle_timeout: Duration,
    /// The timeout of an idle QUIC connection.
    pub max_idle_timeout: Duration,
    /// The period of the keep-alive packets; `None` disables them.
    pub keep_alive_interval: Option<Duration>,
    /// The local forwards (`-L`) the session opens.
    pub local_forwards: Vec<Ssh3LocalForwardSpec>,
}

impl Ssh3ClientConfig {
    pub fn new(target_url: Uri) -> Self {
        Self {
            target_url,
            server_name: None,
            username: None,
            identity_file: None,
            agent: None,
            agent_socket: None,
            forward_agent: false,
            password: None,
            bearer_token: None,
            oidc: None,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            max_packet_size: 30_000,
            default_datagrams_queue_size: 10,
            trust: Ssh3TrustStrategy::WebPkiRoots,
            pty_policy: Ssh3PtyPolicy::Auto,
            term_type: None,
            escape_char: DEFAULT_ESCAPE_CHAR,
            handshake_idle_timeout: DEFAULT_HANDSHAKE_IDLE_TIMEOUT,
            max_idle_timeout: DEFAULT_MAX_IDLE_TIMEOUT,
            keep_alive_interval: Some(DEFAULT_KEEP_ALIVE_INTERVAL),
            local_forwards: Vec::new(),
        }
    }
}

/// The policy that decides whether the client requests a pseudo-terminal.
///
/// The values are the ones of the `RequestTTY` keyword of ssh_config: `auto`
/// (the default) requests a pty for an interactive session driven by a local
/// terminal, `no` never requests one, `yes` always requests one and `force`
/// requests one even when the local side has no terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ssh3PtyPolicy {
    #[default]
    Auto,
    No,
    Yes,
    Force,
}

impl Ssh3PtyPolicy {
    /// Parses the value of the `RequestTTY` option.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "no" => Ok(Self::No),
            "yes" => Ok(Self::Yes),
            "force" => Ok(Self::Force),
            _ => Err(format!(
                "invalid RequestTTY policy {value:?}: want auto, no, yes or force"
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Ssh3SessionRequest {
    Shell,
    Exec(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalSize {
    char_width: u16,
    char_height: u16,
    pixel_width: u16,
    pixel_height: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalTerminalInfo {
    term: Option<String>,
    size: TerminalSize,
}

struct LocalTerminal {
    info: LocalTerminalInfo,
    #[cfg(unix)]
    fd: RawFd,
}

#[cfg(unix)]
struct RawModeGuard {
    fd: RawFd,
    original: termios::Termios,
}

#[cfg(unix)]
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

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[derive(Default)]
struct SessionRuntime {
    background_tasks: Vec<tokio::task::JoinHandle<()>>,
    raw_mode_guard: RawModeGuardHandle,
}

/// The handle of the raw mode guard of the local console.
///
/// The guard only exists on unix, where the console can be put in the raw
/// mode; elsewhere the handle stays empty. The mutex keeps the guard
/// shareable between the session and the stdin pump.
#[cfg(unix)]
type RawModeGuardHandle = Option<Arc<std::sync::Mutex<RawModeGuard>>>;
#[cfg(not(unix))]
type RawModeGuardHandle = Option<Arc<()>>;

impl Drop for SessionRuntime {
    fn drop(&mut self) {
        for task in &self.background_tasks {
            task.abort();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3CapturedSession {
    pub server_header: Option<String>,
    pub exit_status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// The parameters of the pseudo-terminal the client requests.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PtySpec {
    term: Vec<u8>,
    char_width: u16,
    char_height: u16,
    pixel_width: u16,
    pixel_height: u16,
}

impl PtySpec {
    /// Builds the pty request of a session.
    ///
    /// The geometry of the local console wins; a console that cannot be
    /// queried falls back to 80x24, because a pty with a default geometry
    /// still beats a raw pipe session: the remote ncurses programs refuse to
    /// start without one.
    fn new(terminal: Option<&LocalTerminal>, term_type: Option<&str>) -> Self {
        let size = terminal.map(|terminal| terminal.info.size);
        let term = term_type
            .map(|term| term.to_string())
            .or_else(|| {
                terminal
                    .and_then(|terminal| terminal.info.term.clone())
                    .or_else(|| env::var("TERM").ok().filter(|term| !term.is_empty()))
            })
            .unwrap_or_else(|| DEFAULT_TERM_TYPE.to_string());
        let width = size.map(|size| size.char_width).unwrap_or(0);
        let height = size.map(|size| size.char_height).unwrap_or(0);
        Self {
            term: term.into_bytes(),
            char_width: if width == 0 {
                DEFAULT_PTY_COLUMNS
            } else {
                width
            },
            char_height: if height == 0 {
                DEFAULT_PTY_ROWS
            } else {
                height
            },
            pixel_width: size.map(|size| size.pixel_width).unwrap_or(0),
            pixel_height: size.map(|size| size.pixel_height).unwrap_or(0),
        }
    }
}

/// Decides whether the session requests a pseudo-terminal.
///
/// The policy follows the `RequestTTY` canon: `auto` requests one for an
/// interactive session driven by a local terminal, `yes` and `force` always
/// request one (the `force` policy does not need a local terminal) and `no`
/// never requests one.
fn resolve_pty(
    policy: Ssh3PtyPolicy,
    request: &Ssh3SessionRequest,
    terminal: Option<&LocalTerminal>,
    term_type: Option<&str>,
) -> Option<PtySpec> {
    let wanted = match policy {
        Ssh3PtyPolicy::No => false,
        Ssh3PtyPolicy::Yes | Ssh3PtyPolicy::Force => true,
        Ssh3PtyPolicy::Auto => matches!(request, Ssh3SessionRequest::Shell) && terminal.is_some(),
    };
    if !wanted {
        return None;
    }
    Some(PtySpec::new(terminal, term_type))
}

#[derive(Debug)]
pub enum Ssh3OidcError {
    Io(io::Error),
    Reqwest(reqwest::Error),
    Url(url::ParseError),
    InvalidResponse(&'static str),
    ProviderError(String),
}

impl fmt::Display for Ssh3OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Reqwest(err) => write!(f, "{err}"),
            Self::Url(err) => write!(f, "{err}"),
            Self::InvalidResponse(message) => write!(f, "{message}"),
            Self::ProviderError(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for Ssh3OidcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Reqwest(err) => Some(err),
            Self::Url(err) => Some(err),
            Self::InvalidResponse(_) => None,
            Self::ProviderError(_) => None,
        }
    }
}

impl From<io::Error> for Ssh3OidcError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<reqwest::Error> for Ssh3OidcError {
    fn from(value: reqwest::Error) -> Self {
        Self::Reqwest(value)
    }
}

impl From<url::ParseError> for Ssh3OidcError {
    fn from(value: url::ParseError) -> Self {
        Self::Url(value)
    }
}

#[derive(Debug)]
pub enum Ssh3ClientError {
    MissingHost,
    Resolve(io::Error),
    Endpoint(io::Error),
    Connect(ConnectError),
    Connection(ConnectionError),
    QuinnConfig(QuinnConfigError),
    H3Connection(h3::error::ConnectionError),
    ConversationId(Ssh3ConversationIdError),
    BuildRequest(Ssh3BuildConnectRequestError),
    ClientConversation(Ssh3ClientConversationError),
    OpenChannel(Ssh3OpenChannelError),
    Channel(Ssh3ChannelError),
    Io(io::Error),
    InvalidCertificateBundle,
    InvalidHeaderValue(http::header::InvalidHeaderValue),
    SshKey(ssh_key::Error),
    Auth(Ssh3AuthError),
    Oidc(Ssh3OidcError),
    MissingUsernameForIdentity,
    MissingUsernameForAgent,
    MissingUsernameForPassword,
    AgentUnavailable,
    AgentKeyNotFound,
    UnsupportedAgentKey(String),
    ConflictingAuthenticationMethods,
    ExitSignal(Ssh3ExitSignalRequest),
    /// The QUIC handshake did not finish within the handshake timeout.
    HandshakeTimeout(Duration),
}

impl fmt::Display for Ssh3ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHost => write!(f, "target URL is missing a host"),
            Self::Resolve(err) => write!(f, "{err}"),
            Self::Endpoint(err) => write!(f, "{err}"),
            Self::Connect(err) => write!(f, "{err}"),
            Self::Connection(err) => write!(f, "{err}"),
            Self::QuinnConfig(err) => write!(f, "{err}"),
            Self::H3Connection(err) => write!(f, "{err}"),
            Self::ConversationId(err) => write!(f, "{err}"),
            Self::BuildRequest(err) => write!(f, "{err}"),
            Self::ClientConversation(err) => write!(f, "{err}"),
            Self::OpenChannel(err) => write!(f, "{err}"),
            Self::Channel(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::InvalidCertificateBundle => write!(
                f,
                "certificate bundle did not contain any valid certificates"
            ),
            Self::InvalidHeaderValue(err) => write!(f, "{err}"),
            Self::SshKey(err) => write!(f, "{err}"),
            Self::Auth(err) => write!(f, "{err}"),
            Self::Oidc(err) => write!(f, "{err}"),
            Self::MissingUsernameForIdentity => {
                write!(f, "an identity file requires an explicit username")
            }
            Self::MissingUsernameForAgent => {
                write!(f, "SSH agent authentication requires an explicit username")
            }
            Self::MissingUsernameForPassword => {
                write!(f, "password authentication requires an explicit username")
            }
            Self::AgentUnavailable => write!(f, "no SSH agent is available"),
            Self::AgentKeyNotFound => write!(f, "no matching SSH agent key was found"),
            Self::UnsupportedAgentKey(algorithm) => {
                write!(f, "unsupported SSH agent key algorithm: {algorithm}")
            }
            Self::ConflictingAuthenticationMethods => write!(
                f,
                "configure only one of: identity file, SSH agent, password, raw bearer token, or OIDC"
            ),
            Self::ExitSignal(signal) => write!(
                f,
                "remote process exited with signal {}: {}",
                String::from_utf8_lossy(&signal.signal_name_without_sig),
                String::from_utf8_lossy(&signal.error_message_utf8)
            ),
            Self::HandshakeTimeout(timeout) => {
                write!(f, "the QUIC handshake timed out after {timeout:?}")
            }
        }
    }
}

impl std::error::Error for Ssh3ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingHost => None,
            Self::Resolve(err) => Some(err),
            Self::Endpoint(err) => Some(err),
            Self::Connect(err) => Some(err),
            Self::Connection(err) => Some(err),
            Self::QuinnConfig(err) => Some(err),
            Self::H3Connection(err) => Some(err),
            Self::ConversationId(err) => Some(err),
            Self::BuildRequest(err) => Some(err),
            Self::ClientConversation(err) => Some(err),
            Self::OpenChannel(err) => Some(err),
            Self::Channel(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::InvalidCertificateBundle => None,
            Self::InvalidHeaderValue(err) => Some(err),
            Self::SshKey(err) => Some(err),
            Self::Auth(err) => Some(err),
            Self::Oidc(err) => Some(err),
            Self::MissingUsernameForIdentity => None,
            Self::MissingUsernameForAgent => None,
            Self::MissingUsernameForPassword => None,
            Self::AgentUnavailable => None,
            Self::AgentKeyNotFound => None,
            Self::UnsupportedAgentKey(_) => None,
            Self::ConflictingAuthenticationMethods => None,
            Self::ExitSignal(_) => None,
            Self::HandshakeTimeout(_) => None,
        }
    }
}

impl From<QuinnConfigError> for Ssh3ClientError {
    fn from(value: QuinnConfigError) -> Self {
        Self::QuinnConfig(value)
    }
}

impl From<h3::error::ConnectionError> for Ssh3ClientError {
    fn from(value: h3::error::ConnectionError) -> Self {
        Self::H3Connection(value)
    }
}

impl From<Ssh3ConversationIdError> for Ssh3ClientError {
    fn from(value: Ssh3ConversationIdError) -> Self {
        Self::ConversationId(value)
    }
}

impl From<Ssh3BuildConnectRequestError> for Ssh3ClientError {
    fn from(value: Ssh3BuildConnectRequestError) -> Self {
        Self::BuildRequest(value)
    }
}

impl From<Ssh3AuthError> for Ssh3ClientError {
    fn from(value: Ssh3AuthError) -> Self {
        Self::Auth(value)
    }
}

impl From<ssh_key::Error> for Ssh3ClientError {
    fn from(value: ssh_key::Error) -> Self {
        Self::SshKey(value)
    }
}

impl From<Ssh3OidcError> for Ssh3ClientError {
    fn from(value: Ssh3OidcError) -> Self {
        Self::Oidc(value)
    }
}

impl From<Ssh3ClientConversationError> for Ssh3ClientError {
    fn from(value: Ssh3ClientConversationError) -> Self {
        Self::ClientConversation(value)
    }
}

impl From<Ssh3OpenChannelError> for Ssh3ClientError {
    fn from(value: Ssh3OpenChannelError) -> Self {
        Self::OpenChannel(value)
    }
}

impl From<Ssh3ChannelError> for Ssh3ClientError {
    fn from(value: Ssh3ChannelError) -> Self {
        Self::Channel(value)
    }
}

impl From<io::Error> for Ssh3ClientError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<http::header::InvalidHeaderValue> for Ssh3ClientError {
    fn from(value: http::header::InvalidHeaderValue) -> Self {
        Self::InvalidHeaderValue(value)
    }
}

struct ResolvedTarget {
    remote_addr: SocketAddr,
    server_name: String,
}

/// The exit code of a session whose remote process died by a signal.
///
/// The convention of OpenSSH is 128 plus the number of the signal (SIGTERM is
/// 143, SIGSEGV is 139); an unknown signal falls back to 255, like the Go
/// implementation does.
pub fn exit_code_for_exit_signal(signal_name: &str) -> i32 {
    match signal_name {
        "HUP" => 129,
        "INT" => 130,
        "QUIT" => 131,
        "ILL" => 132,
        "ABRT" => 134,
        "FPE" => 136,
        "KILL" => 137,
        "SEGV" => 139,
        "PIPE" => 141,
        "ALRM" => 142,
        "TERM" => 143,
        "USR1" => 138,
        "USR2" => 140,
        "STOP" => 149,
        "TSTP" => 150,
        "CONT" => 151,
        "CHLD" => 152,
        "TTIN" => 153,
        "TTOU" => 154,
        "XCPU" => 155,
        "XFSZ" => 156,
        "VTALRM" => 157,
        "PROF" => 158,
        "WINCH" => 159,
        "IO" => 160,
        "POLL" => 161,
        "PWR" => 162,
        "SYS" => 163,
        _ => 255,
    }
}

struct ActiveClient {
    endpoint: Endpoint,
    connection: Connection,
    conversation: Arc<Ssh3Conversation>,
    _control_stream: Ssh3ClientControlStream,
    _send_request: Ssh3SendRequest,
    driver_task: tokio::task::JoinHandle<()>,
    incoming_channels_task: tokio::task::JoinHandle<()>,
    incoming_datagrams_task: tokio::task::JoinHandle<()>,
    server_header: Option<String>,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
}

impl ActiveClient {
    async fn shutdown(self) {
        self.connection.close(0u32.into(), b"done");
        let _ = self.driver_task.await;
        let _ = self.incoming_channels_task.await;
        let _ = self.incoming_datagrams_task.await;
        self.endpoint.wait_idle().await;
    }

    async fn open_session_channel(&self) -> Result<Arc<Ssh3Channel>, Ssh3ClientError> {
        open_channel(
            self.conversation.as_ref(),
            &self.connection,
            b"session".to_vec(),
            self.max_packet_size,
            self.default_datagrams_queue_size,
        )
        .await
        .map_err(Ssh3ClientError::from)
    }
}

pub fn load_certificates(
    path: impl AsRef<Path>,
) -> Result<Vec<CertificateDer<'static>>, Ssh3ClientError> {
    let bytes = std::fs::read(path).map_err(Ssh3ClientError::Io)?;
    if bytes.starts_with(b"-----BEGIN") {
        let mut reader = BufReader::new(bytes.as_slice());
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Ssh3ClientError::Io)?;
        if certificates.is_empty() {
            return Err(Ssh3ClientError::InvalidCertificateBundle);
        }
        Ok(certificates)
    } else {
        Ok(vec![CertificateDer::from(bytes)])
    }
}

async fn send_initial_session_requests(
    channel: &Ssh3Channel,
    request: &Ssh3SessionRequest,
    pty: Option<&PtySpec>,
) -> Result<(), Ssh3ClientError> {
    if let Some(pty) = pty {
        send_pty_request(channel, pty).await?;
    }

    let request = match request {
        Ssh3SessionRequest::Shell => Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Shell,
        },
        Ssh3SessionRequest::Exec(command) => Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: command.as_bytes().to_vec(),
            }),
        },
    };
    channel
        .send_request(request)
        .await
        .map_err(Ssh3ClientError::from)
}

async fn send_pty_request(channel: &Ssh3Channel, pty: &PtySpec) -> Result<(), Ssh3ClientError> {
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Pty(Ssh3PtyRequest {
                term: pty.term.clone(),
                char_width: pty.char_width.into(),
                char_height: pty.char_height.into(),
                pixel_width: pty.pixel_width.into(),
                pixel_height: pty.pixel_height.into(),
                encoded_terminal_modes: Vec::new(),
            }),
        })
        .await
        .map_err(Ssh3ClientError::from)
}

async fn send_forward_agent_request(channel: &Ssh3Channel) -> Result<(), Ssh3ClientError> {
    channel
        .write_data(b"forward-agent", SSH_EXTENDED_DATA_NONE)
        .await
        .map(|_| ())
        .map_err(Ssh3ClientError::from)
}

async fn send_window_change_request(
    channel: &Ssh3Channel,
    size: TerminalSize,
) -> Result<(), Ssh3ClientError> {
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::WindowChange(Ssh3WindowChangeRequest {
                char_width: size.char_width.into(),
                char_height: size.char_height.into(),
                pixel_width: size.pixel_width.into(),
                pixel_height: size.pixel_height.into(),
            }),
        })
        .await
        .map_err(Ssh3ClientError::from)
}

async fn send_signal_request(
    channel: &Ssh3Channel,
    signal_name: &str,
) -> Result<(), Ssh3ClientError> {
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::Signal(Ssh3SignalRequest {
                signal_name_without_sig: signal_name.as_bytes().to_vec(),
            }),
        })
        .await
        .map_err(Ssh3ClientError::from)
}

#[cfg(unix)]
fn detect_local_terminal() -> Result<Option<LocalTerminal>, Ssh3ClientError> {
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
        fd,
    }))
}

#[cfg(not(unix))]
fn detect_local_terminal() -> Result<Option<LocalTerminal>, Ssh3ClientError> {
    Ok(None)
}

#[cfg(unix)]
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

#[cfg(unix)]
fn enable_raw_mode(fd: RawFd) -> Result<RawModeGuard, Ssh3ClientError> {
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut termios_state = termios::tcgetattr(fd).map_err(io::Error::from)?;
    let original = termios_state.clone();
    termios::cfmakeraw(&mut termios_state);
    termios::tcsetattr(fd, SetArg::TCSANOW, &termios_state).map_err(io::Error::from)?;
    Ok(RawModeGuard {
        fd: fd.as_raw_fd(),
        original,
    })
}

#[cfg(unix)]
fn spawn_resize_forwarder(channel: Arc<Ssh3Channel>, fd: RawFd) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut winsize_signal = match signal(SignalKind::window_change()) {
            Ok(signal) => signal,
            Err(_) => return,
        };

        while winsize_signal.recv().await.is_some() {
            let size = match read_terminal_size(fd) {
                Ok(size) => size,
                Err(_) => return,
            };
            if send_window_change_request(channel.as_ref(), size)
                .await
                .is_err()
            {
                return;
            }
        }
    })
}

#[cfg(unix)]
fn spawn_signal_forwarders(channel: Arc<Ssh3Channel>) -> Vec<tokio::task::JoinHandle<()>> {
    [
        ("INT", SignalKind::interrupt()),
        ("TERM", SignalKind::terminate()),
        ("QUIT", SignalKind::quit()),
        ("HUP", SignalKind::hangup()),
    ]
    .into_iter()
    .filter_map(|(signal_name, kind)| {
        let mut signal = signal(kind).ok()?;
        let channel = channel.clone();
        Some(tokio::spawn(async move {
            while signal.recv().await.is_some() {
                if send_signal_request(channel.as_ref(), signal_name)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }))
    })
    .collect()
}

#[cfg(not(unix))]
fn spawn_signal_forwarders(_channel: Arc<Ssh3Channel>) -> Vec<tokio::task::JoinHandle<()>> {
    Vec::new()
}

fn build_session_runtime(
    client: &ActiveClient,
    config: &Ssh3ClientConfig,
    channel: Arc<Ssh3Channel>,
    pty: Option<&PtySpec>,
    terminal: Option<&LocalTerminal>,
) -> Result<SessionRuntime, Ssh3ClientError> {
    let mut runtime = SessionRuntime {
        background_tasks: spawn_signal_forwarders(channel.clone()),
        raw_mode_guard: None,
    };

    // The console only enters the raw mode for a session that owns a pty:
    // the remote program drives the terminal side of it.
    #[cfg(unix)]
    if pty.is_some()
        && let Some(terminal) = terminal
    {
        runtime.raw_mode_guard = Some(Arc::new(std::sync::Mutex::new(enable_raw_mode(
            terminal.fd,
        )?)));
        runtime
            .background_tasks
            .push(spawn_resize_forwarder(channel, terminal.fd));
    }

    if config.forward_agent {
        #[cfg(unix)]
        runtime.background_tasks.push(spawn_agent_forwarder(
            client.conversation.clone(),
            resolve_agent_socket_path(config)?,
        ));

        #[cfg(not(unix))]
        return Err(Ssh3ClientError::AgentUnavailable);
    }

    Ok(runtime)
}

/// Opens the local listeners of the `-L` forwards of the configuration.
///
/// The listeners ride the connection of the session: they only need the
/// conversation, so they stay usable for the whole lifetime of the session.
async fn start_local_forwards(
    client: &ActiveClient,
    config: &Ssh3ClientConfig,
) -> Result<Vec<tokio::task::JoinHandle<()>>, Ssh3ClientError> {
    let mut tasks = Vec::new();
    for spec in &config.local_forwards {
        let task = forward::start_local_forward(
            client.conversation.clone(),
            client.connection.clone(),
            config.max_packet_size,
            config.default_datagrams_queue_size,
            spec,
        )
        .await?;
        tasks.push(task);
    }
    Ok(tasks)
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    id_token: Option<String>,
}

fn auth_method_count(config: &Ssh3ClientConfig) -> usize {
    usize::from(config.identity_file.is_some())
        + usize::from(config.agent.is_some())
        + usize::from(config.password.is_some())
        + usize::from(
            config
                .bearer_token
                .as_deref()
                .map(str::trim)
                .is_some_and(|token| !token.is_empty()),
        )
        + usize::from(config.oidc.is_some())
}

fn basic_authorization_value(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{username}:{password}"))
    )
}

fn default_browser_opener(url: String) -> Result<(), Ssh3OidcError> {
    if try_open_browser(&url) {
        return Ok(());
    }
    eprintln!("Open this URL in your browser:\n{url}");
    Ok(())
}

fn try_open_browser(url: &str) -> bool {
    #[cfg(target_os = "android")]
    if StdCommand::new("termux-open-url").arg(url).spawn().is_ok() {
        return true;
    }

    #[cfg(target_os = "windows")]
    if StdCommand::new("cmd")
        .args(["/C", "start", "", url])
        .spawn()
        .is_ok()
    {
        return true;
    }

    #[cfg(target_os = "macos")]
    if StdCommand::new("open").arg(url).spawn().is_ok() {
        return true;
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    if StdCommand::new("xdg-open").arg(url).spawn().is_ok() {
        return true;
    }

    false
}

fn random_urlsafe(bytes_len: usize) -> String {
    let mut bytes = vec![0u8; bytes_len];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn oidc_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn fetch_oidc_discovery_document(
    issuer_url: &str,
) -> Result<OidcDiscoveryDocument, Ssh3OidcError> {
    let client = reqwest::Client::new();
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );
    client
        .get(discovery_url)
        .send()
        .await?
        .error_for_status()?
        .json::<OidcDiscoveryDocument>()
        .await
        .map_err(Ssh3OidcError::from)
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Result<String, Ssh3OidcError> {
    let mut buffer = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

async fn wait_for_oidc_callback(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, Ssh3OidcError> {
    fn callback_response(status_line: &str, body: &str) -> String {
        format!(
            "{status_line}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    let (mut stream, _) = listener.accept().await?;
    let request = read_http_request(&mut stream).await?;
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or(Ssh3OidcError::InvalidResponse(
            "malformed OIDC callback request",
        ))?;
    let callback_url = Url::parse(&format!("http://localhost{target}"))?;
    let mut code = None;
    let mut state = None;
    let mut provider_error = None;
    for (key, value) in callback_url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" => provider_error = Some(value.into_owned()),
            _ => {}
        }
    }

    if let Some(provider_error) = provider_error {
        let response =
            callback_response("HTTP/1.1 400 Bad Request", "OIDC authentication failed.\n");
        let _ = stream.write_all(response.as_bytes()).await;
        return Err(Ssh3OidcError::ProviderError(provider_error));
    }
    if state.as_deref() != Some(expected_state) {
        let response = callback_response("HTTP/1.1 400 Bad Request", "OIDC state mismatch.\n");
        let _ = stream.write_all(response.as_bytes()).await;
        return Err(Ssh3OidcError::InvalidResponse("OIDC state mismatch"));
    }
    let Some(code) = code else {
        let response =
            callback_response("HTTP/1.1 400 Bad Request", "OIDC callback missing code.\n");
        let _ = stream.write_all(response.as_bytes()).await;
        return Err(Ssh3OidcError::InvalidResponse("OIDC callback missing code"));
    };

    let response = callback_response("HTTP/1.1 200 OK", "you can now close this tab");
    let _ = stream.write_all(response.as_bytes()).await;
    Ok(code)
}

async fn exchange_oidc_code(
    token_endpoint: &str,
    oidc: &Ssh3OidcConfig,
    redirect_uri: &str,
    code: &str,
    code_verifier: Option<&str>,
) -> Result<String, Ssh3OidcError> {
    let client = reqwest::Client::new();
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("client_id", oidc.client_id.clone()),
        ("redirect_uri", redirect_uri.to_string()),
    ];
    if let Some(client_secret) = oidc.client_secret.as_deref() {
        form.push(("client_secret", client_secret.to_string()));
    }
    if let Some(code_verifier) = code_verifier {
        form.push(("code_verifier", code_verifier.to_string()));
    }

    let response = client.post(token_endpoint).form(&form).send().await?;
    if response.status() != HttpStatusCode::OK {
        return Err(Ssh3OidcError::ProviderError(format!(
            "OIDC token endpoint returned {}",
            response.status()
        )));
    }
    let token_response = response.json::<OidcTokenResponse>().await?;
    token_response
        .id_token
        .filter(|token| !token.is_empty())
        .ok_or(Ssh3OidcError::InvalidResponse(
            "OIDC token response did not include an id_token",
        ))
}

async fn authenticate_oidc_with_browser_opener(
    oidc: &Ssh3OidcConfig,
    expected_nonce: &str,
    browser_opener: fn(String) -> Result<(), Ssh3OidcError>,
) -> Result<String, Ssh3OidcError> {
    let discovery = fetch_oidc_discovery_document(&oidc.issuer_url).await?;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}{OIDC_CALLBACK_PATH}",
        listener.local_addr()?.port()
    );
    let state = random_urlsafe(24);
    let code_verifier = oidc.use_pkce.then(|| random_urlsafe(48));
    let mut auth_url = Url::parse(&discovery.authorization_endpoint)?;
    {
        let mut query = auth_url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &oidc.client_id);
        query.append_pair("redirect_uri", &redirect_uri);
        query.append_pair("scope", DEFAULT_OIDC_SCOPE);
        query.append_pair("state", &state);
        query.append_pair("nonce", expected_nonce);
        if let Some(code_verifier) = code_verifier.as_deref() {
            query.append_pair("code_challenge", &oidc_code_challenge(code_verifier));
            query.append_pair("code_challenge_method", "S256");
        }
    }
    browser_opener(auth_url.to_string())?;
    let code = wait_for_oidc_callback(listener, &state).await?;
    exchange_oidc_code(
        &discovery.token_endpoint,
        oidc,
        &redirect_uri,
        &code,
        code_verifier.as_deref(),
    )
    .await
}

async fn precomputed_authorization_header(
    config: &Ssh3ClientConfig,
) -> Result<Option<String>, Ssh3ClientError> {
    if auth_method_count(config) > 1 {
        return Err(Ssh3ClientError::ConflictingAuthenticationMethods);
    }

    if let Some(token) = config
        .bearer_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        return Ok(Some(bearer_authorization_value(token)));
    }

    if let Some(password) = config.password.as_deref() {
        let username = config
            .username
            .as_deref()
            .ok_or(Ssh3ClientError::MissingUsernameForPassword)?;
        return Ok(Some(basic_authorization_value(username, password)));
    }

    Ok(None)
}

fn activate_client(
    endpoint: Endpoint,
    connection: Connection,
    send_request: Ssh3SendRequest,
    driver_task: tokio::task::JoinHandle<()>,
    established: Ssh3EstablishedClientConversation,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
) -> ActiveClient {
    let channel_router = Arc::new(Ssh3IncomingChannelRouter::new());
    channel_router.register_conversation(established.conversation.clone());
    let incoming_channels_task = tokio::spawn({
        let channel_router = channel_router.clone();
        let connection = connection.clone();
        async move {
            if let Err(err) = channel_router
                .accept_and_route_channels_forever(connection)
                .await
                && !is_benign_route_error(&err)
            {
                eprintln!("ssh3-rust-client incoming channel error: {err}");
            }
        }
    });
    let incoming_datagrams_task = tokio::spawn({
        let connection = connection.clone();
        let conversation = established.conversation.clone();
        async move {
            // F-19: a malformed datagram is per-datagram garbage; it must not
            // end the reception of the datagrams, so the loop drops it and
            // carries on.
            loop {
                match ssh3_h3::dispatch_one_datagram(conversation.as_ref(), &connection).await {
                    Ok(()) => {}
                    Err(err) => {
                        if is_benign_datagram_dispatch_error(&err) {
                            eprintln!("ssh3-rust-client dropping malformed datagram: {err}");
                            continue;
                        }
                        if !is_benign_connection_dispatch_error(&err) {
                            eprintln!("ssh3-rust-client incoming datagram error: {err}");
                        }
                        return;
                    }
                }
            }
        }
    });

    ActiveClient {
        endpoint,
        connection,
        conversation: established.conversation,
        _control_stream: established.control_stream,
        _send_request: send_request,
        driver_task,
        incoming_channels_task,
        incoming_datagrams_task,
        server_header: response_server_header(&established.response).map(str::to_owned),
        max_packet_size,
        default_datagrams_queue_size,
    }
}

pub async fn run_exec_capture(
    config: &Ssh3ClientConfig,
    command: impl AsRef<str>,
) -> Result<Ssh3CapturedSession, Ssh3ClientError> {
    let client = connect_client(config).await?;
    let result = run_capture_on_client(
        &client,
        config,
        Ssh3SessionRequest::Exec(command.as_ref().to_string()),
    )
    .await;
    client.shutdown().await;
    result
}

#[cfg(test)]
async fn run_exec_capture_with_browser_opener(
    config: &Ssh3ClientConfig,
    command: impl AsRef<str>,
    browser_opener: fn(String) -> Result<(), Ssh3OidcError>,
) -> Result<Ssh3CapturedSession, Ssh3ClientError> {
    let client = connect_client_with_browser_opener(config, browser_opener).await?;
    let result = run_capture_on_client(
        &client,
        config,
        Ssh3SessionRequest::Exec(command.as_ref().to_string()),
    )
    .await;
    client.shutdown().await;
    result
}

pub async fn run_session_stdio(
    config: &Ssh3ClientConfig,
    request: Ssh3SessionRequest,
) -> Result<i32, Ssh3ClientError> {
    let client = connect_client(config).await?;
    let result = run_stdio_on_client(&client, config, request).await;
    client.shutdown().await;
    result
}

async fn connect_client(config: &Ssh3ClientConfig) -> Result<ActiveClient, Ssh3ClientError> {
    connect_client_with_browser_opener(config, default_browser_opener).await
}

async fn connect_client_with_browser_opener(
    config: &Ssh3ClientConfig,
    browser_opener: fn(String) -> Result<(), Ssh3OidcError>,
) -> Result<ActiveClient, Ssh3ClientError> {
    let precomputed_authorization = precomputed_authorization_header(config).await?;

    let resolved = resolve_target(&config.target_url, config.server_name.as_deref()).await?;
    let bind_addr = client_bind_addr(resolved.remote_addr);
    let mut endpoint = Endpoint::client(bind_addr).map_err(Ssh3ClientError::Endpoint)?;
    endpoint.set_default_client_config(client_quinn_config(config)?);

    let connection = tokio::time::timeout(
        config.handshake_idle_timeout,
        endpoint
            .connect(resolved.remote_addr, &resolved.server_name)
            .map_err(Ssh3ClientError::Connect)?,
    )
    .await
    .map_err(|_| Ssh3ClientError::HandshakeTimeout(config.handshake_idle_timeout))?
    .map_err(Ssh3ClientError::Connection)?;

    let (mut driver, mut send_request) = new_client(connection.clone()).await?;
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let conversation_id = generate_conversation_id(&connection)?;
    let mut request =
        ssh3_h3::build_connect_request(config.target_url.clone(), &config.user_agent)?;
    if let Some(username) = config.username.as_deref() {
        request
            .headers_mut()
            .insert(SSH3_USER_HEADER, HeaderValue::from_str(username)?);
    }
    if let Some(token) = precomputed_authorization.as_deref() {
        request
            .headers_mut()
            .insert(http::header::AUTHORIZATION, HeaderValue::from_str(token)?);
    } else if let Some(oidc) = config.oidc.as_ref() {
        let token = authenticate_oidc_with_browser_opener(
            oidc,
            &conversation_id_base64(&conversation_id),
            browser_opener,
        )
        .await?;
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&bearer_authorization_value(&token))?,
        );
    } else if let Some(identity_path) = config.identity_file.as_ref() {
        let username = config
            .username
            .as_deref()
            .ok_or(Ssh3ClientError::MissingUsernameForIdentity)?;
        let private_key = load_private_key(identity_path)?;
        let token = build_bearer_token(&private_key, username, &conversation_id)?;
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&bearer_authorization_value(&token))?,
        );
    } else if let Some(agent_selection) = config.agent.as_ref() {
        let username = config
            .username
            .as_deref()
            .ok_or(Ssh3ClientError::MissingUsernameForAgent)?;
        let config = config.clone();
        let agent_selection = agent_selection.clone();
        let username = username.to_string();
        let token = tokio::task::spawn_blocking(move || {
            build_agent_bearer_token(&config, &agent_selection, &username, &conversation_id)
        })
        .await
        .map_err(|err| Ssh3ClientError::Io(io::Error::other(err.to_string())))??;
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&bearer_authorization_value(&token))?,
        );
    }
    let established = ssh3_h3::establish_client_conversation(
        &mut send_request,
        connection.clone(),
        request,
        config.max_packet_size,
        config.default_datagrams_queue_size,
    )
    .await?;
    driver_task.abort();
    Ok(activate_client(
        endpoint,
        connection,
        send_request,
        driver_task,
        established,
        config.max_packet_size,
        config.default_datagrams_queue_size,
    ))
}

fn client_quinn_config(config: &Ssh3ClientConfig) -> Result<quinn::ClientConfig, Ssh3ClientError> {
    let mut client_config = match &config.trust {
        Ssh3TrustStrategy::WebPkiRoots => {
            client_config_with_webpki_roots().map_err(Ssh3ClientError::from)?
        }
        Ssh3TrustStrategy::Certificates(certificates) => {
            let mut roots = RootCertStore::empty();
            let (added, _) = roots.add_parsable_certificates(certificates.iter().cloned());
            if added == 0 {
                return Err(Ssh3ClientError::InvalidCertificateBundle);
            }
            client_config_with_roots(roots).map_err(Ssh3ClientError::from)?
        }
        Ssh3TrustStrategy::Insecure => client_config_insecure().map_err(Ssh3ClientError::from)?,
    };

    // The idle timeout of the ssh2 canon is an idle session that is never
    // killed, so the client raises its side too (QUIC negotiates the smaller
    // of the two values) and keeps the connection alive with keep-alive
    // packets.
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout = quinn::IdleTimeout::try_from(config.max_idle_timeout).map_err(|err| {
        Ssh3ClientError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid max idle timeout: {err}"),
        ))
    })?;
    transport.max_idle_timeout(Some(idle_timeout));
    transport.keep_alive_interval(config.keep_alive_interval);
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

async fn resolve_target(
    uri: &Uri,
    server_name_override: Option<&str>,
) -> Result<ResolvedTarget, Ssh3ClientError> {
    let host = uri.host().ok_or(Ssh3ClientError::MissingHost)?;
    let remote_addr = tokio::net::lookup_host((host, uri.port_u16().unwrap_or(443)))
        .await
        .map_err(Ssh3ClientError::Resolve)?
        .next()
        .ok_or_else(|| {
            Ssh3ClientError::Resolve(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "target host did not resolve to an address",
            ))
        })?;

    Ok(ResolvedTarget {
        remote_addr,
        server_name: server_name_override.unwrap_or(host).to_string(),
    })
}

fn client_bind_addr(remote_addr: SocketAddr) -> SocketAddr {
    match remote_addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    }
}

async fn run_capture_on_client(
    client: &ActiveClient,
    config: &Ssh3ClientConfig,
    request: Ssh3SessionRequest,
) -> Result<Ssh3CapturedSession, Ssh3ClientError> {
    let channel = client.open_session_channel().await?;
    let pty = resolve_pty(
        config.pty_policy,
        &request,
        None,
        config.term_type.as_deref(),
    );
    if config.forward_agent {
        send_forward_agent_request(channel.as_ref()).await?;
    }
    let mut session_runtime =
        build_session_runtime(client, config, channel.clone(), pty.as_ref(), None)?;
    session_runtime
        .background_tasks
        .extend(start_local_forwards(client, config).await?);
    send_initial_session_requests(channel.as_ref(), &request, pty.as_ref()).await?;
    if !config.forward_agent {
        channel.close().await?;
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = loop {
        match channel.next_message().await? {
            Ssh3Message::Data(data) => match data.data_type {
                SSH_EXTENDED_DATA_NONE => stdout.extend_from_slice(&data.data),
                SSH_EXTENDED_DATA_STDERR => stderr.extend_from_slice(&data.data),
                _ => {}
            },
            Ssh3Message::ChannelRequest(message) => match message.request {
                Ssh3ChannelRequest::ExitStatus(status) => {
                    break Ok(Ssh3CapturedSession {
                        server_header: client.server_header.clone(),
                        exit_status: status.exit_status as i32,
                        stdout,
                        stderr,
                    });
                }
                Ssh3ChannelRequest::ExitSignal(signal) => {
                    break Err(Ssh3ClientError::ExitSignal(signal));
                }
                _ => {}
            },
            _ => {}
        }
    };
    drop(session_runtime);
    result
}

async fn run_stdio_on_client(
    client: &ActiveClient,
    config: &Ssh3ClientConfig,
    request: Ssh3SessionRequest,
) -> Result<i32, Ssh3ClientError> {
    let channel = client.open_session_channel().await?;
    let terminal = detect_local_terminal()?;
    let pty = resolve_pty(
        config.pty_policy,
        &request,
        terminal.as_ref(),
        config.term_type.as_deref(),
    );
    if config.forward_agent {
        send_forward_agent_request(channel.as_ref()).await?;
    }
    send_initial_session_requests(channel.as_ref(), &request, pty.as_ref()).await?;
    let mut session_runtime = build_session_runtime(
        client,
        config,
        channel.clone(),
        pty.as_ref(),
        terminal.as_ref(),
    )?;
    session_runtime
        .background_tasks
        .extend(start_local_forwards(client, config).await?);

    // The escape sequences only arm for an interactive pty session: the
    // traffic of an exec session stays byte-exact.
    let escape_filter = pty.as_ref().and_then(|_| {
        (config.escape_char != 0)
            .then(|| Ssh3EscapeFilter::new(config.escape_char, suspend_supported()))
    });
    // The sender of the actions stays alive for the whole session: the
    // receiver must not report the end of the stream while the session of the
    // remote side is still running.
    let (action_tx, mut action_rx) = tokio::sync::mpsc::unbounded_channel::<Ssh3EscapeAction>();

    let stdin_task = tokio::spawn({
        let channel = channel.clone();
        let action_tx = action_tx.clone();
        let raw_mode_guard = session_runtime.raw_mode_guard.clone();
        async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            let mut filter = escape_filter;
            let mut payload: Vec<u8> = Vec::new();
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                if n == 0 {
                    let _ = channel.close().await;
                    return;
                }

                match filter.as_mut() {
                    Some(filter) => {
                        let (forwarded, action) = filter.feed(&buf[..n]);
                        match action {
                            Ssh3EscapeAction::Disconnect => {
                                if !forwarded.is_empty()
                                    && channel
                                        .write_data(&forwarded, SSH_EXTENDED_DATA_NONE)
                                        .await
                                        .is_err()
                                {
                                    return;
                                }
                                let _ = action_tx.send(Ssh3EscapeAction::Disconnect);
                                return;
                            }
                            Ssh3EscapeAction::Suspend => {
                                if let Err(err) = suspend_local_process(&raw_mode_guard) {
                                    eprintln!("ssh3-rust-client escape suspend failed: {err}");
                                }
                            }
                            Ssh3EscapeAction::None => {}
                        }
                        payload = forwarded;
                    }
                    None => {
                        payload.clear();
                        payload.extend_from_slice(&buf[..n]);
                    }
                }

                if payload.is_empty() {
                    continue;
                }
                if channel
                    .write_data(&payload, SSH_EXTENDED_DATA_NONE)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    });

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();

    let result = loop {
        let message = tokio::select! {
            biased;
            action = action_rx.recv() => {
                match action {
                    Some(Ssh3EscapeAction::Disconnect) => {
                        // the user tore the session down with the ~. escape
                        // sequence: the exit code of a closed connection
                        break Ok(255);
                    }
                    _ => continue,
                }
            }
            message = channel.next_message() => message?,
        };
        match message {
            Ssh3Message::Data(data) => match data.data_type {
                SSH_EXTENDED_DATA_NONE => {
                    stdout.write_all(&data.data).await?;
                    stdout.flush().await?;
                }
                SSH_EXTENDED_DATA_STDERR => {
                    stderr.write_all(&data.data).await?;
                    stderr.flush().await?;
                }
                _ => {}
            },
            Ssh3Message::ChannelRequest(message) => match message.request {
                Ssh3ChannelRequest::ExitStatus(status) => {
                    break Ok(status.exit_status as i32);
                }
                Ssh3ChannelRequest::ExitSignal(signal) => {
                    break Err(Ssh3ClientError::ExitSignal(signal));
                }
                _ => {}
            },
            _ => {}
        }
    };

    stdin_task.abort();
    drop(session_runtime);
    result
}

/// Tells whether the local console can suspend the process.
fn suspend_supported() -> bool {
    cfg!(unix)
}

/// Suspends the client locally: the terminal is restored, the process stops
/// itself with SIGTSTP and the raw mode is entered again on resume.
#[cfg(unix)]
fn suspend_local_process(guard: &RawModeGuardHandle) -> io::Result<()> {
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

#[cfg(not(unix))]
fn suspend_local_process(_guard: &RawModeGuardHandle) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the local console cannot suspend the process",
    ))
}

fn is_benign_connection_error(error: &ConnectionError) -> bool {
    matches!(
        error,
        ConnectionError::ApplicationClosed(_)
            | ConnectionError::ConnectionClosed(_)
            | ConnectionError::LocallyClosed
            | ConnectionError::TimedOut
    )
}

fn is_benign_io_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    ) {
        return true;
    }

    if error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ConnectionError>())
        .is_some_and(is_benign_connection_error)
    {
        return true;
    }

    let message = error.to_string().to_ascii_lowercase();
    message.contains("connection lost")
        || message.contains("closed stream")
        || message.contains("connection closed")
}

fn is_benign_channel_error(error: &Ssh3ChannelError) -> bool {
    matches!(error, Ssh3ChannelError::Io(error) if is_benign_io_error(error))
}

fn is_benign_open_channel_error(error: &Ssh3OpenChannelError) -> bool {
    matches!(error, Ssh3OpenChannelError::Connection(error) if is_benign_connection_error(error))
}

fn is_benign_client_error(error: &Ssh3ClientError) -> bool {
    match error {
        Ssh3ClientError::Connection(error) => is_benign_connection_error(error),
        Ssh3ClientError::OpenChannel(error) => is_benign_open_channel_error(error),
        Ssh3ClientError::Channel(error) => is_benign_channel_error(error),
        Ssh3ClientError::Io(error) => is_benign_io_error(error),
        _ => false,
    }
}

fn is_benign_route_error(error: &Ssh3RouteAcceptedChannelError) -> bool {
    matches!(
        error,
        Ssh3RouteAcceptedChannelError::Accept(Ssh3AcceptChannelError::Connection(error))
            if is_benign_connection_error(error)
    )
}

/// Tells whether the error of a datagram dispatch is a per-datagram failure.
///
/// A malformed datagram is garbage of a single datagram: dropping it must not
/// end the reception of the datagrams, like the Go implementation does.
fn is_benign_datagram_dispatch_error(error: &ssh3_h3::Ssh3DatagramDispatchError) -> bool {
    match error {
        ssh3_h3::Ssh3DatagramDispatchError::Proto(_) => true,
        ssh3_h3::Ssh3DatagramDispatchError::Conversation(error) => {
            is_benign_conversation_error(error)
        }
        ssh3_h3::Ssh3DatagramDispatchError::Connection(_) => false,
    }
}

/// Tells whether the error of a datagram dispatch is the end of the
/// connection: the peer went away, so the reception of the datagrams is over.
fn is_benign_connection_dispatch_error(error: &ssh3_h3::Ssh3DatagramDispatchError) -> bool {
    matches!(
        error,
        ssh3_h3::Ssh3DatagramDispatchError::Connection(error) if is_benign_connection_error(error)
    )
}

/// Tells whether the error of a conversation is a per-datagram failure.
fn is_benign_conversation_error(error: &Ssh3ConversationError) -> bool {
    match error {
        Ssh3ConversationError::Proto(_) => true,
        Ssh3ConversationError::ChannelNotFound { .. } => true,
        Ssh3ConversationError::Channel(error) => is_benign_channel_error(error),
    }
}

#[cfg(unix)]
fn spawn_agent_forwarder(
    conversation: Arc<Ssh3Conversation>,
    agent_socket: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let channel = match conversation.accept_channel().await {
                Ok(channel) => channel,
                Err(_) => return,
            };
            if channel.channel_type() != b"agent-connection" {
                let _ = channel.close().await;
                continue;
            }

            if let Err(err) = forward_agent_channel(channel, &agent_socket).await {
                if is_benign_client_error(&err) {
                    continue;
                }
                eprintln!("ssh3-rust-client agent forwarding error: {err}");
                return;
            }
        }
    })
}

#[cfg(unix)]
async fn forward_agent_channel(
    channel: Arc<Ssh3Channel>,
    agent_socket: &Path,
) -> Result<(), Ssh3ClientError> {
    let stream = UnixStream::connect(agent_socket).await?;
    let (mut reader, mut writer) = stream.into_split();

    let mut to_agent = tokio::spawn({
        let channel = channel.clone();
        async move {
            loop {
                let message = channel.next_message().await?;
                if let Ssh3Message::Data(data) = message
                    && data.data_type == SSH_EXTENDED_DATA_NONE
                {
                    writer.write_all(&data.data).await?;
                    writer.flush().await?;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), Ssh3ClientError>(())
        }
    });

    let mut from_agent = tokio::spawn({
        let channel = channel.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    let _ = channel.close().await;
                    return Ok::<(), Ssh3ClientError>(());
                }
                channel
                    .write_data(&buf[..n], SSH_EXTENDED_DATA_NONE)
                    .await?;
            }
        }
    });

    tokio::select! {
        result = &mut to_agent => {
            from_agent.abort();
            let _ = channel.close().await;
            result.map_err(|err| Ssh3ClientError::Io(io::Error::other(err.to_string())))?
        }
        result = &mut from_agent => {
            to_agent.abort();
            let _ = channel.close().await;
            result.map_err(|err| Ssh3ClientError::Io(io::Error::other(err.to_string())))?
        }
    }
}

#[cfg(test)]
mod tests {
    // The interop scenarios of this module are written for clarity, not for
    // the linter: they keep the diagnostic lock of the harness across await
    // points, they build the client configuration field by field and they
    // match a single variant in a few places. The production code of the
    // crate stays free of these lints.
    #![allow(
        clippy::await_holding_lock,
        clippy::field_reassign_with_default,
        clippy::single_match
    )]

    use std::fs;
    #[cfg(unix)]
    use std::fs::File as StdFile;
    use std::future::poll_fn;
    use std::io;
    #[cfg(unix)]
    use std::io::{Read, Write};
    #[cfg(unix)]
    use std::net::UdpSocket;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::process::{Command as StdCommand, Stdio};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use http::{StatusCode, header::HeaderValue};
    #[cfg(unix)]
    use nix::pty::{Winsize, openpty};
    #[cfg(unix)]
    use nix::unistd::{Uid, User};
    use p256::SecretKey as P256SecretKey;
    use quinn::Endpoint;
    use rand_core::OsRng;
    use rsa::BigUint as RsaBigUint;
    use rsa::RsaPrivateKey as JwtRsaPrivateKey;
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
    use rsa::traits::PublicKeyParts;
    use sha2::Sha256;
    use signature::{SignatureEncoding, Signer};
    use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
    use ssh_key::{Algorithm, HashAlg, Signature};
    use ssh3_auth::bearer_authorization_value;
    use ssh3_core::{Ssh3Channel, Ssh3ConversationError};
    use ssh3_h3::{
        SSH3_USER_HEADER, SSH3_VERSION_STRING, accept_server_conversation, build_connect_request,
        establish_client_conversation, generate_conversation_id, is_ssh3_connect, new_client,
        new_server, response_with_server_header,
    };
    use ssh3_proto::{SSH_EXTENDED_DATA_NONE, Ssh3ChannelRequest, Ssh3Message};
    use ssh3_quinn::{
        accept_bi_channel, open_tcp_forwarding_channel, open_udp_forwarding_channel,
        self_signed_server_config,
    };
    use ssh3_server::{Ssh3ServerConfig, serve_connection};
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    #[cfg(unix)]
    use tokio::net::UdpSocket as TokioUdpSocket;
    use tokio::net::{TcpListener, TcpStream};
    #[cfg(unix)]
    use tokio::net::{UnixListener, UnixStream};
    #[cfg(unix)]
    use tokio::process::Command as TokioCommand;
    use tokio::time::{sleep, timeout};
    use url::Url;

    use super::{
        LocalTerminalInfo, PtySpec, Ssh3CapturedSession, Ssh3ClientConfig, Ssh3ClientError,
        Ssh3ForwardProtocol, Ssh3LocalForwardSpec, Ssh3OidcConfig, Ssh3OidcError, Ssh3PtyPolicy,
        Ssh3SessionRequest, Ssh3TrustStrategy, TerminalSize, activate_client,
        build_session_runtime, client_bind_addr, client_quinn_config, connect_client,
        conversation_id_base64, exit_code_for_exit_signal, resolve_pty, resolve_target,
        run_capture_on_client, run_exec_capture, run_exec_capture_with_browser_opener,
        send_forward_agent_request, send_initial_session_requests, send_signal_request,
        send_window_change_request,
    };

    /// Builds the pty request of a session out of the metadata of a console.
    fn pty_spec_from_info(info: &LocalTerminalInfo) -> PtySpec {
        PtySpec {
            term: info.term.clone().unwrap_or_default().into_bytes(),
            char_width: info.size.char_width,
            char_height: info.size.char_height,
            pixel_width: info.size.pixel_width,
            pixel_height: info.size.pixel_height,
        }
    }

    /// Reserves a local TCP port for a listener of a test.
    fn reserve_local_tcp_port() -> u16 {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    /// Reserves a local UDP port for a listener of a test.
    fn reserve_local_udp_port() -> u16 {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.local_addr().unwrap().port()
    }

    async fn setup_request_capture_harness(
        expected_messages: usize,
    ) -> (
        super::ActiveClient,
        tokio::task::JoinHandle<Vec<Ssh3Message>>,
    ) {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut server = new_server(connection.clone()).await.unwrap();
            let mut accepted = timeout(
                Duration::from_secs(5),
                accept_server_conversation(&mut server, connection.clone(), 30_000, 10),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();
            assert!(is_ssh3_connect(&accepted.request));
            accepted
                .control_stream
                .send_response(
                    response_with_server_header(StatusCode::OK, SSH3_VERSION_STRING).unwrap(),
                )
                .await
                .unwrap();

            let (incoming_channel, send, recv) =
                timeout(Duration::from_secs(5), accept_bi_channel(&connection))
                    .await
                    .unwrap()
                    .unwrap();
            let channel = incoming_channel
                .into_accepted_channel_for_conversation(accepted.conversation.as_ref(), recv, send)
                .into_channel();
            channel.confirm_channel(30_000).await.unwrap();

            let mut messages = Vec::new();
            for _ in 0..expected_messages {
                messages.push(
                    timeout(Duration::from_secs(5), channel.next_message())
                        .await
                        .unwrap()
                        .unwrap(),
                );
            }
            messages
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        let client = connect_client(&config).await.unwrap();
        (client, server_task)
    }

    async fn connect_client_with_authorization_builder(
        config: &Ssh3ClientConfig,
        authorization_builder: impl FnOnce(&[u8; 32]) -> String,
    ) -> Result<super::ActiveClient, Ssh3ClientError> {
        let resolved = resolve_target(&config.target_url, config.server_name.as_deref()).await?;
        let bind_addr = client_bind_addr(resolved.remote_addr);
        let mut endpoint = Endpoint::client(bind_addr).map_err(Ssh3ClientError::Endpoint)?;
        endpoint.set_default_client_config(client_quinn_config(config)?);

        let connection = endpoint
            .connect(resolved.remote_addr, &resolved.server_name)
            .map_err(Ssh3ClientError::Connect)?
            .await
            .map_err(Ssh3ClientError::Connection)?;

        let (mut driver, mut send_request) = new_client(connection.clone()).await?;
        let driver_task = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let conversation_id = generate_conversation_id(&connection)?;
        let mut request = build_connect_request(config.target_url.clone(), &config.user_agent)?;
        if let Some(username) = config.username.as_deref() {
            request
                .headers_mut()
                .insert(SSH3_USER_HEADER, HeaderValue::from_str(username)?);
        }
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&authorization_builder(&conversation_id))?,
        );

        let established = establish_client_conversation(
            &mut send_request,
            connection.clone(),
            request,
            config.max_packet_size,
            config.default_datagrams_queue_size,
        )
        .await?;
        driver_task.abort();

        Ok(activate_client(
            endpoint,
            connection,
            send_request,
            driver_task,
            established,
            config.max_packet_size,
            config.default_datagrams_queue_size,
        ))
    }

    #[cfg(unix)]
    fn current_username() -> String {
        User::from_uid(Uid::current()).unwrap().unwrap().name
    }

    #[cfg(unix)]
    struct GoInteropBinaries {
        client: PathBuf,
        server: PathBuf,
    }

    #[cfg(unix)]
    struct GoAgentProbeBinary {
        path: PathBuf,
    }

    #[cfg(unix)]
    struct GoCliBinaries {
        client: PathBuf,
        server: PathBuf,
    }

    struct AuthFixture {
        _tempdir: TempDir,
        private_key_path: std::path::PathBuf,
        authorized_identities_path: std::path::PathBuf,
        username: String,
    }

    #[derive(Clone, Copy)]
    enum AuthKeyAlgorithm {
        Ed25519,
        NistP256,
        Rsa,
    }

    fn auth_private_key(algorithm: AuthKeyAlgorithm) -> ssh_key::PrivateKey {
        match algorithm {
            AuthKeyAlgorithm::Ed25519 => {
                ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[31; 32]))
            }
            AuthKeyAlgorithm::NistP256 => {
                let secret_key = P256SecretKey::from_slice(&[29; 32]).unwrap();
                ssh_key::PrivateKey::from(EcdsaKeypair::NistP256 {
                    public: secret_key.public_key().into(),
                    private: secret_key.into(),
                })
            }
            AuthKeyAlgorithm::Rsa => {
                let rsa_private_key = JwtRsaPrivateKey::new(&mut OsRng, 2048).unwrap();
                ssh_key::PrivateKey::from(RsaKeypair::try_from(&rsa_private_key).unwrap())
            }
        }
    }

    #[cfg(unix)]
    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    /// Reason reported when the Go reference implementation cannot be built.
    #[cfg(unix)]
    const GO_REPO_UNAVAILABLE: &str =
        "the Go reference repository is not available (set SSH3_GO_REPO)";

    /// Reason why the Go reference implementation is unavailable.
    ///
    /// The first reason wins: every scenario that needs the Go peers reports
    /// the same cause, so the log stays consistent.
    #[cfg(unix)]
    static GO_UNAVAILABLE_REASON: Mutex<Option<String>> = Mutex::new(None);

    /// Serializes the interop diagnostic writes.
    #[cfg(unix)]
    static INTEROP_LOG_LOCK: Mutex<()> = Mutex::new(());

    /// Writes a diagnostic line straight to the stderr handle.
    ///
    /// The test harness captures `eprintln!` output and keeps it hidden while
    /// a test passes, so interop diagnostics bypass the capture to stay
    /// visible in the test log. The write is serialized so that lines from
    /// concurrently running scenarios do not interleave.
    #[cfg(unix)]
    fn log_interop(message: &str) {
        let mut line = String::with_capacity(message.len() + 1);
        line.push_str(message);
        line.push('\n');
        let _guard = INTEROP_LOG_LOCK.lock().unwrap();
        let mut stderr = std::io::stderr();
        let _ = stderr.write_all(line.as_bytes());
        let _ = stderr.flush();
    }

    /// Records why the Go reference implementation cannot be used.
    #[cfg(unix)]
    fn set_go_unavailable(reason: impl Into<String>) {
        let mut guard = GO_UNAVAILABLE_REASON.lock().unwrap();
        if guard.is_none() {
            *guard = Some(reason.into());
        }
    }

    /// Returns the recorded reason why the Go reference implementation is
    /// unavailable, if one was recorded.
    #[cfg(unix)]
    fn recorded_go_unavailable_reason() -> Option<String> {
        GO_UNAVAILABLE_REASON.lock().unwrap().clone()
    }

    /// Returns the reason why the Go reference implementation is unavailable.
    #[cfg(unix)]
    fn go_unavailable_reason() -> String {
        recorded_go_unavailable_reason().unwrap_or_else(|| GO_REPO_UNAVAILABLE.to_string())
    }

    /// Reports that a cross-implementation scenario was skipped.
    ///
    /// Every early return of an interop scenario goes through this function,
    /// so a scenario that did not run is always visible in the test log and
    /// can never be mistaken for a scenario that really passed.
    #[cfg(unix)]
    fn skip_interop(scenario: &str) {
        log_interop(&format!(
            "skipping: {scenario}: {}",
            go_unavailable_reason()
        ));
    }

    /// Root of the Go reference repository that the cross-implementation
    /// suite builds its peers from.
    ///
    /// The location comes from `SSH3_GO_REPO`. When that is unset, the
    /// canonical `ssh3-go` checkout is probed next to this workspace; a
    /// directory named `ssh3` is not probed automatically because that name
    /// is ambiguous with the pre-split monorepo, so such a checkout has to be
    /// named explicitly through `SSH3_GO_REPO`. `None` means the Go
    /// repository is not available, and the interop scenarios skip instead of
    /// failing.
    #[cfg(unix)]
    fn go_repo_root() -> Option<PathBuf> {
        if let Ok(configured) = std::env::var("SSH3_GO_REPO") {
            let path = PathBuf::from(configured);
            if path.join("go.mod").is_file() {
                return Some(path.canonicalize().unwrap_or(path));
            }
            set_go_unavailable(format!(
                "SSH3_GO_REPO={} does not look like the Go repository (no go.mod)",
                path.display()
            ));
            return None;
        }
        let workspace = repo_root();
        let candidates = [
            workspace.join("ssh3-go"),
            workspace.join("../ssh3-go"),
            workspace.join("../../ssh3-go"),
        ];
        let found = candidates.into_iter().find_map(|candidate| {
            let candidate = candidate.canonicalize().ok()?;
            (candidate.join("go.mod").is_file() && candidate.join("cmd/ssh3").is_dir())
                .then_some(candidate)
        });
        if found.is_none() {
            set_go_unavailable(GO_REPO_UNAVAILABLE);
        }
        found
    }

    /// Builds a Go binary from the reference repository.
    ///
    /// Returns `false` when the build could not be performed or failed; the
    /// cause is recorded so the interop scenarios can report it instead of
    /// failing with an opaque panic.
    #[cfg(unix)]
    fn build_go_binary(go_root: &Path, package: &str, output_path: &Path) -> bool {
        let build_output = match StdCommand::new("go")
            .arg("build")
            .arg("-mod=mod")
            .arg("-tags")
            .arg("disable_password_auth")
            .arg("-o")
            .arg(output_path)
            .arg(package)
            .current_dir(go_root)
            .output()
        {
            Ok(output) => output,
            Err(err) => {
                set_go_unavailable(format!("the Go toolchain is not usable: {err}"));
                return false;
            }
        };
        if !build_output.status.success() {
            set_go_unavailable(format!(
                "go build {package} failed: {}",
                String::from_utf8_lossy(&build_output.stderr).trim()
            ));
            return false;
        }
        true
    }

    #[cfg(unix)]
    fn go_interop_binaries() -> Option<&'static GoInteropBinaries> {
        static BINARIES: OnceLock<Option<GoInteropBinaries>> = OnceLock::new();
        BINARIES
            .get_or_init(|| {
                let go_root = go_repo_root()?;
                let dir = repo_root().join("target/go-interop");
                fs::create_dir_all(&dir).unwrap();
                let client = dir.join("ssh3-go-interop-client");
                let server = dir.join("ssh3-go-interop-server");
                if !build_go_binary(&go_root, "./internal/interop/go_client", &client) {
                    return None;
                }
                if !build_go_binary(&go_root, "./internal/interop/go_server", &server) {
                    return None;
                }
                Some(GoInteropBinaries { client, server })
            })
            .as_ref()
    }

    #[cfg(unix)]
    fn go_cli_binaries() -> Option<&'static GoCliBinaries> {
        static BINARIES: OnceLock<Option<GoCliBinaries>> = OnceLock::new();
        BINARIES
            .get_or_init(|| {
                let go_root = go_repo_root()?;
                let dir = repo_root().join("target/go-interop");
                fs::create_dir_all(&dir).unwrap();
                let client = dir.join("ssh3-go-cli");
                let server = dir.join("ssh3-go-server");
                if !build_go_binary(&go_root, "./cmd/ssh3", &client) {
                    return None;
                }
                if !build_go_binary(&go_root, "./cmd/ssh3-server", &server) {
                    return None;
                }
                Some(GoCliBinaries { client, server })
            })
            .as_ref()
    }

    #[cfg(unix)]
    fn go_agent_probe_binary() -> Option<&'static GoAgentProbeBinary> {
        static BINARY: OnceLock<Option<GoAgentProbeBinary>> = OnceLock::new();
        BINARY
            .get_or_init(|| {
                let go_root = go_repo_root()?;
                let dir = repo_root().join("target/go-interop");
                fs::create_dir_all(&dir).unwrap();
                let path = dir.join("ssh3-agent-probe");
                if !build_go_binary(&go_root, "./internal/interop/agent_probe", &path) {
                    return None;
                }
                Some(GoAgentProbeBinary { path })
            })
            .as_ref()
    }

    #[cfg(unix)]
    fn reserve_udp_port() -> u16 {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.local_addr().unwrap().port()
    }

    #[cfg(unix)]
    fn reserve_tcp_port() -> u16 {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    #[cfg(unix)]
    async fn spawn_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0; 4096];
                    let n = match stream.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    if n == 0 {
                        return;
                    }
                    let _ = stream.write_all(&buf[..n]).await;
                    let _ = stream.flush().await;
                });
            }
        });
        (addr, task)
    }

    #[cfg(unix)]
    async fn spawn_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket =
            TokioUdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0; 4096];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(result) => result,
                    Err(_) => return,
                };
                let _ = socket.send_to(&buf[..n], peer).await;
            }
        });
        (addr, task)
    }

    #[cfg(unix)]
    async fn spawn_go_interop_server(
        bind_addr: &str,
        username: &str,
        authorized_identity_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> Option<(tokio::process::Child, SocketAddr)> {
        let binaries = go_interop_binaries()?;
        let mut child = TokioCommand::new(&binaries.server)
            .arg("--bind")
            .arg(bind_addr)
            .arg("--url-path")
            .arg("/ssh3-term")
            .arg("--user")
            .arg(username)
            .arg("--authorized-identity")
            .arg(authorized_identity_path)
            .arg("--cert")
            .arg(cert_path)
            .arg("--key")
            .arg(key_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let stdout = child.stdout.take().unwrap();
        let mut reader = tokio::io::BufReader::new(stdout);
        let mut ready_line = String::new();
        let bytes_read = timeout(Duration::from_secs(10), reader.read_line(&mut ready_line))
            .await
            .unwrap()
            .unwrap();
        assert!(
            bytes_read > 0,
            "go interop server exited before signaling readiness"
        );
        let ready_line = ready_line.trim();
        let (_, bind_addr) = ready_line
            .split_once(' ')
            .unwrap_or_else(|| panic!("unexpected go interop server readiness line: {ready_line}"));
        let bind_addr = bind_addr.parse::<SocketAddr>().unwrap_or_else(|err| {
            panic!("invalid go interop server bind address {bind_addr}: {err}")
        });
        drop(reader);
        Some((child, bind_addr))
    }

    #[cfg(unix)]
    async fn run_go_interop_client(
        url: &str,
        username: &str,
        private_key_path: &Path,
        command: &str,
    ) -> Option<std::process::Output> {
        let binaries = go_interop_binaries()?;
        Some(
            timeout(
                Duration::from_secs(20),
                TokioCommand::new(&binaries.client)
                    .arg("--url")
                    .arg(url)
                    .arg("--user")
                    .arg(username)
                    .arg("--privkey")
                    .arg(private_key_path)
                    .arg("--insecure")
                    .arg(command)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output(),
            )
            .await
            .unwrap()
            .unwrap(),
        )
    }

    #[cfg(unix)]
    async fn spawn_go_cli_server(
        bind_addr: &str,
        username: &str,
        home_dir: &Path,
        cert_path: &Path,
        key_path: &Path,
        log_path: &Path,
    ) -> Option<tokio::process::Child> {
        let binaries = go_cli_binaries()?;
        fs::create_dir_all(home_dir).unwrap();
        let stderr_log = fs::File::create(log_path).unwrap();
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut child = TokioCommand::new(&binaries.server)
            .arg("-bind")
            .arg(bind_addr)
            .arg("-v")
            .arg("-url-path")
            .arg("/ssh3-term")
            .arg("-generate-selfsigned-cert")
            .arg("-cert")
            .arg(cert_path)
            .arg("-key")
            .arg(key_path)
            .env("HOME", home_dir)
            .env("USER", username)
            .env("LOGNAME", username)
            .env("SHELL", shell)
            // the server resolves the session user through getpwnam, so its
            // identity files would come from the real /etc/passwd home; point
            // it at the fixture home instead (unix_util honors this override)
            .env("SSH3_USER_HOME", home_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_log))
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let ready_line = format!("Server started, listening on {bind_addr}/ssh3-term");
        timeout(Duration::from_secs(20), async {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    let logs = fs::read_to_string(log_path).unwrap_or_default();
                    panic!(
                        "go CLI server exited before signaling readiness with status {status}\nlogs:\n{logs}"
                    );
                }

                let logs = fs::read_to_string(log_path).unwrap_or_default();
                if logs.contains(&ready_line) {
                    break;
                }

                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        Some(child)
    }

    #[cfg(unix)]
    async fn spawn_go_cli_tcp_forwarder(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        local_port: u16,
        remote_addr: SocketAddr,
        log_path: &Path,
    ) -> Option<tokio::process::Child> {
        let binaries = go_cli_binaries()?;
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        let stderr_log = fs::File::create(log_path).unwrap();
        let forward_spec = format!("{local_port}/{}@{}", remote_addr.ip(), remote_addr.port());
        let mut child = TokioCommand::new(&binaries.client)
            .arg("-insecure")
            .arg("-privkey")
            .arg(private_key_path)
            .arg("-forward-tcp")
            .arg(&forward_spec)
            .arg(url)
            .arg("sleep")
            .arg("8")
            .env("HOME", home_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_log))
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_port));
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    let logs = fs::read_to_string(log_path).unwrap_or_default();
                    panic!(
                        "go CLI forwarder exited before the local port was reachable with status {status}\nlogs:\n{logs}"
                    );
                }

                if TcpStream::connect(local_addr).await.is_ok() {
                    break;
                }

                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        Some(child)
    }

    #[cfg(unix)]
    async fn spawn_go_cli_udp_forwarder(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        local_port: u16,
        remote_addr: SocketAddr,
        log_path: &Path,
    ) -> Option<tokio::process::Child> {
        let binaries = go_cli_binaries()?;
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        let stderr_log = fs::File::create(log_path).unwrap();
        let forward_spec = format!("{local_port}/{}@{}", remote_addr.ip(), remote_addr.port());
        let mut child = TokioCommand::new(&binaries.client)
            .arg("-insecure")
            .arg("-privkey")
            .arg(private_key_path)
            .arg("-forward-udp")
            .arg(&forward_spec)
            .arg(url)
            .arg("sleep")
            .arg("8")
            .env("HOME", home_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_log))
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_port));
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    let logs = fs::read_to_string(log_path).unwrap_or_default();
                    panic!(
                        "go CLI UDP forwarder exited before the local port was bound with status {status}\nlogs:\n{logs}"
                    );
                }

                match UdpSocket::bind(local_addr) {
                    Ok(socket) => drop(socket),
                    Err(err) if err.kind() == io::ErrorKind::AddrInUse => break,
                    Err(err) => panic!(
                        "could not probe local UDP forwarder port {local_addr}: {err}"
                    ),
                }

                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        Some(child)
    }

    #[cfg(unix)]
    async fn run_go_cli_client(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        command: &[&str],
    ) -> Option<std::process::Output> {
        let binaries = go_cli_binaries()?;
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        Some(
            timeout(
                Duration::from_secs(20),
                TokioCommand::new(&binaries.client)
                    .arg("-insecure")
                    .arg("-privkey")
                    .arg(private_key_path)
                    .arg(url)
                    .args(command)
                    .env("HOME", home_dir)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output(),
            )
            .await
            .unwrap()
            .unwrap(),
        )
    }

    #[cfg(unix)]
    async fn run_go_cli_client_with_forwarded_agent(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        agent_socket: &Path,
        command: &[&str],
    ) -> Option<std::process::Output> {
        let binaries = go_cli_binaries()?;
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        let mut child = TokioCommand::new(&binaries.client)
            .arg("-v")
            .arg("-insecure")
            .arg("-privkey")
            .arg(private_key_path)
            .arg("-forward-agent")
            .arg(url)
            .args(command)
            .env("HOME", home_dir)
            .env("SSH_AUTH_SOCK", agent_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdout = child.stdout.take().unwrap();
        let stdout_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            stdout.read_to_end(&mut buf).await.unwrap();
            buf
        });
        let mut stderr = child.stderr.take().unwrap();
        let stderr_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            stderr.read_to_end(&mut buf).await.unwrap();
            buf
        });

        Some(match timeout(Duration::from_secs(30), child.wait()).await {
            Ok(status) => std::process::Output {
                status: status.unwrap(),
                stdout: stdout_task.await.unwrap(),
                stderr: stderr_task.await.unwrap(),
            },
            Err(_) => {
                let _ = child.kill().await;
                let status = child.wait().await.unwrap();
                let output = std::process::Output {
                    status,
                    stdout: stdout_task.await.unwrap(),
                    stderr: stderr_task.await.unwrap(),
                };
                panic!(
                    "go client with forwarded agent timed out\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
        })
    }

    #[cfg(unix)]
    async fn run_go_cli_client_with_oidc(
        home_dir: &Path,
        url: &str,
        issuer_url: &str,
        oidc_config_path: &Path,
        command: &[&str],
    ) -> Option<std::process::Output> {
        let binaries = go_cli_binaries()?;
        let browser_dir = home_dir.join("browser-bin");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        fs::create_dir_all(&browser_dir).unwrap();

        let fake_browser = browser_dir.join("xdg-open");
        fs::write(
            &fake_browser,
            "#!/bin/sh\nexec curl -fsSL \"$1\" >/dev/null\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fake_browser, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let path = std::env::var("PATH").unwrap_or_default();
        let mut child = TokioCommand::new(&binaries.client)
            .arg("-v")
            .arg("-insecure")
            .arg("-use-oidc")
            .arg(issuer_url)
            .arg("-oidc-config")
            .arg(oidc_config_path)
            .arg(url)
            .args(command)
            .env("HOME", home_dir)
            .env("PATH", format!("{}:{path}", browser_dir.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdout = child.stdout.take().unwrap();
        let stdout_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            stdout.read_to_end(&mut buf).await.unwrap();
            buf
        });
        let mut stderr = child.stderr.take().unwrap();
        let stderr_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            stderr.read_to_end(&mut buf).await.unwrap();
            buf
        });

        Some(match timeout(Duration::from_secs(20), child.wait()).await {
            Ok(status) => std::process::Output {
                status: status.unwrap(),
                stdout: stdout_task.await.unwrap(),
                stderr: stderr_task.await.unwrap(),
            },
            Err(_) => {
                let _ = child.kill().await;
                let status = child.wait().await.unwrap();
                let output = std::process::Output {
                    status,
                    stdout: stdout_task.await.unwrap(),
                    stderr: stderr_task.await.unwrap(),
                };
                panic!(
                    "go client with oidc timed out\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
        })
    }

    #[cfg(unix)]
    async fn run_go_cli_client_with_password(
        home_dir: &Path,
        url: &str,
        password: &str,
        command: &[&str],
    ) -> Option<std::process::Output> {
        let binaries = go_cli_binaries()?;
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();

        let mut parts = vec![
            shell_quote(binaries.client.to_string_lossy().as_ref()),
            "-insecure".to_string(),
            "-use-password".to_string(),
            shell_quote(url),
        ];
        parts.extend(command.iter().map(|arg| shell_quote(arg)));
        let command = parts.join(" ");

        let mut child = TokioCommand::new("script")
            .arg("-qefc")
            .arg(command)
            .arg("/dev/null")
            .env("HOME", home_dir)
            .env("TERM", "xterm")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(format!("{password}\n").as_bytes())
            .await
            .unwrap();
        drop(stdin);

        Some(
            timeout(Duration::from_secs(20), child.wait_with_output())
                .await
                .unwrap()
                .unwrap(),
        )
    }

    #[cfg(unix)]
    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    #[cfg(unix)]
    struct GoCliPtySession {
        child: tokio::process::Child,
        writer: Arc<Mutex<StdFile>>,
        controller: StdFile,
        output: Arc<Mutex<Vec<u8>>>,
        output_task: tokio::task::JoinHandle<io::Result<()>>,
    }

    #[cfg(unix)]
    impl GoCliPtySession {
        async fn write_all(&self, input: &str) {
            let writer = self.writer.clone();
            let input = input.as_bytes().to_vec();
            tokio::task::spawn_blocking(move || -> io::Result<()> {
                let mut writer = writer.lock().unwrap();
                writer.write_all(&input)?;
                writer.flush()?;
                Ok(())
            })
            .await
            .unwrap()
            .unwrap();
        }

        fn resize(&self, size: TerminalSize) -> io::Result<()> {
            let winsize = Winsize {
                ws_row: size.char_height,
                ws_col: size.char_width,
                ws_xpixel: size.pixel_width,
                ws_ypixel: size.pixel_height,
            };
            let result = unsafe {
                nix::libc::ioctl(self.controller.as_raw_fd(), nix::libc::TIOCSWINSZ, &winsize)
            };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn send_signal(&self, signal: i32) -> io::Result<()> {
            let pid = self
                .child
                .id()
                .ok_or_else(|| io::Error::other("go CLI PTY child has no pid"))?
                as i32;
            let result = unsafe { nix::libc::kill(pid, signal) };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn output_string(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }

        async fn wait_for_output_fragment(&self, fragment: &str) {
            let fragment = fragment.to_string();
            timeout(Duration::from_secs(10), async {
                loop {
                    if self.output_string().replace('\r', "").contains(&fragment) {
                        break;
                    }
                    sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap();
        }

        async fn wait_with_output(mut self) -> std::process::Output {
            let status = timeout(Duration::from_secs(20), self.child.wait())
                .await
                .unwrap()
                .unwrap();
            self.output_task.await.unwrap().unwrap();
            std::process::Output {
                status,
                stdout: self.output.lock().unwrap().clone(),
                stderr: Vec::new(),
            }
        }
    }

    #[cfg(unix)]
    fn pty_eof(err: &io::Error) -> bool {
        matches!(err.raw_os_error(), Some(code) if code == nix::libc::EIO)
    }

    #[cfg(unix)]
    async fn spawn_go_cli_shell_with_pty(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        initial_size: TerminalSize,
    ) -> Option<GoCliPtySession> {
        let binaries = go_cli_binaries()?;
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();

        let openpty = openpty(
            Some(&Winsize {
                ws_row: initial_size.char_height,
                ws_col: initial_size.char_width,
                ws_xpixel: initial_size.pixel_width,
                ws_ypixel: initial_size.pixel_height,
            }),
            None,
        )
        .unwrap();
        let master = StdFile::from(openpty.master);
        let slave = StdFile::from(openpty.slave);

        let mut child = TokioCommand::new(&binaries.client);
        child
            .arg("-insecure")
            .arg("-privkey")
            .arg(private_key_path)
            .arg(url)
            .env("HOME", home_dir)
            .env("TERM", "xterm")
            .kill_on_drop(true);

        let slave_fd = slave.as_raw_fd();
        child
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        unsafe {
            child.pre_exec(move || {
                if nix::libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                if nix::libc::ioctl(slave_fd, nix::libc::TIOCSCTTY, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = child.spawn().unwrap();
        drop(slave);

        let output = Arc::new(Mutex::new(Vec::new()));
        let output_reader = output.clone();
        let mut reader = master.try_clone().unwrap();
        let writer = Arc::new(Mutex::new(master.try_clone().unwrap()));
        let output_task = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let mut chunk = [0_u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => return Ok(()),
                    Ok(n) => output_reader.lock().unwrap().extend_from_slice(&chunk[..n]),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) if pty_eof(&err) => return Ok(()),
                    Err(err) => return Err(err),
                }
            }
        });

        Some(GoCliPtySession {
            child,
            writer,
            controller: master,
            output,
            output_task,
        })
    }

    #[cfg(unix)]
    async fn run_go_cli_shell(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        input: &str,
    ) -> Option<std::process::Output> {
        let binaries = go_cli_binaries()?;
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();

        let command = format!(
            "{} -insecure -privkey {} {}",
            shell_quote(binaries.client.to_string_lossy().as_ref()),
            shell_quote(private_key_path.to_string_lossy().as_ref()),
            shell_quote(url),
        );

        let mut child = TokioCommand::new("script")
            .arg("-qefc")
            .arg(command)
            .arg("/dev/null")
            .env("HOME", home_dir)
            .env("TERM", "xterm")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input.as_bytes()).await.unwrap();
        drop(stdin);

        Some(
            timeout(Duration::from_secs(20), child.wait_with_output())
                .await
                .unwrap()
                .unwrap(),
        )
    }

    async fn run_shell_capture_with_resize_on_client(
        client: &super::ActiveClient,
        initial_terminal: LocalTerminalInfo,
        resized_terminal: TerminalSize,
        shell_input_prefix: &str,
        shell_input_suffix: &str,
    ) -> Result<Ssh3CapturedSession, Ssh3ClientError> {
        let channel = client.open_session_channel().await?;
        let pty = pty_spec_from_info(&initial_terminal);
        send_initial_session_requests(channel.as_ref(), &Ssh3SessionRequest::Shell, Some(&pty))
            .await?;
        channel
            .write_data(shell_input_prefix.as_bytes(), SSH_EXTENDED_DATA_NONE)
            .await
            .map_err(Ssh3ClientError::from)?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let initial_size_fragment = format!(
            "{} {}",
            initial_terminal.size.char_height, initial_terminal.size.char_width
        );
        let mut resize_sent = false;

        loop {
            match timeout(Duration::from_secs(10), channel.next_message())
                .await
                .unwrap()?
            {
                Ssh3Message::Data(data) => {
                    match data.data_type {
                        SSH_EXTENDED_DATA_NONE => stdout.extend_from_slice(&data.data),
                        ssh3_proto::SSH_EXTENDED_DATA_STDERR => {
                            stderr.extend_from_slice(&data.data)
                        }
                        _ => {}
                    }
                    if !resize_sent
                        && String::from_utf8_lossy(&stdout).contains(&initial_size_fragment)
                    {
                        send_window_change_request(channel.as_ref(), resized_terminal).await?;
                        channel
                            .write_data(shell_input_suffix.as_bytes(), SSH_EXTENDED_DATA_NONE)
                            .await
                            .map_err(Ssh3ClientError::from)?;
                        resize_sent = true;
                    }
                }
                Ssh3Message::ChannelRequest(message) => match message.request {
                    Ssh3ChannelRequest::ExitStatus(status) => {
                        return Ok(Ssh3CapturedSession {
                            server_header: client.server_header.clone(),
                            exit_status: status.exit_status as i32,
                            stdout,
                            stderr,
                        });
                    }
                    Ssh3ChannelRequest::ExitSignal(signal) => {
                        return Err(Ssh3ClientError::ExitSignal(signal));
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    async fn run_tcp_forwarding_round_trip_on_client(
        client: &super::ActiveClient,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, Ssh3ClientError> {
        let channel = open_tcp_forwarding_channel(
            client.conversation.as_ref(),
            &client.connection,
            client.max_packet_size,
            client.default_datagrams_queue_size,
            remote_addr,
        )
        .await
        .map_err(Ssh3ClientError::from)?;
        channel
            .write_data(payload, SSH_EXTENDED_DATA_NONE)
            .await
            .map_err(Ssh3ClientError::from)?;

        loop {
            match timeout(Duration::from_secs(10), channel.next_message())
                .await
                .unwrap()?
            {
                Ssh3Message::Data(data) if data.data_type == SSH_EXTENDED_DATA_NONE => {
                    let _ = channel.close().await;
                    return Ok(data.data);
                }
                _ => {}
            }
        }
    }

    async fn run_udp_forwarding_round_trip_on_client(
        client: &super::ActiveClient,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, Ssh3ClientError> {
        let channel = open_udp_forwarding_channel(
            client.conversation.as_ref(),
            &client.connection,
            client.max_packet_size,
            client.default_datagrams_queue_size,
            remote_addr,
        )
        .await
        .map_err(Ssh3ClientError::from)?;
        channel
            .send_datagram(payload.to_vec())
            .await
            .map_err(Ssh3ClientError::from)?;
        let echoed = timeout(Duration::from_secs(10), channel.receive_datagram())
            .await
            .unwrap();
        let _ = channel.close().await;
        Ok(echoed)
    }

    fn create_auth_fixture(algorithm: AuthKeyAlgorithm) -> AuthFixture {
        let tempdir = TempDir::new().unwrap();
        let private_key_path = tempdir.path().join("id_ed25519");
        let authorized_identities_path = tempdir.path().join("authorized_keys");
        let private_key = auth_private_key(algorithm);
        private_key
            .write_openssh_file(&private_key_path, ssh_key::LineEnding::LF)
            .unwrap();
        fs::write(
            &authorized_identities_path,
            format!("{}\n", private_key.public_key().to_openssh().unwrap()),
        )
        .unwrap();

        AuthFixture {
            _tempdir: tempdir,
            private_key_path,
            authorized_identities_path,
            username: {
                #[cfg(unix)]
                {
                    current_username()
                }
                #[cfg(not(unix))]
                {
                    "user".to_string()
                }
            },
        }
    }

    #[cfg(unix)]
    fn go_binary_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[cfg(unix)]
    fn lock_go_binary_tests() -> std::sync::MutexGuard<'static, ()> {
        go_binary_test_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(unix)]
    fn agent_socket_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Serializes the scenarios that make the Rust server open an agent
    /// forwarding socket.
    ///
    /// The server names that socket after the process id and a timestamp, so
    /// two of these scenarios running at the same time can ask for the same
    /// path and the second one fails with "File exists". The scenarios are
    /// serialized so that they cannot overlap; what each one checks is
    /// unchanged.
    #[cfg(unix)]
    fn lock_agent_socket_tests() -> std::sync::MutexGuard<'static, ()> {
        agent_socket_test_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(unix)]
    const SSH_AGENT_FAILURE: u8 = 5;
    #[cfg(unix)]
    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    #[cfg(unix)]
    const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    #[cfg(unix)]
    const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    #[cfg(unix)]
    const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    #[cfg(unix)]
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;

    #[cfg(unix)]
    struct MockAgent {
        _tempdir: TempDir,
        socket_path: PathBuf,
        sign_flags: Arc<Mutex<Vec<u32>>>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl MockAgent {
        fn sign_flags(&self) -> Vec<u32> {
            self.sign_flags.lock().unwrap().clone()
        }
    }

    #[cfg(unix)]
    impl Drop for MockAgent {
        fn drop(&mut self) {
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }

    #[cfg(unix)]
    async fn spawn_mock_agent(private_key: ssh_key::PrivateKey) -> MockAgent {
        let tempdir = TempDir::new().unwrap();
        let socket_path = tempdir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let private_key = Arc::new(private_key);
        let sign_flags = Arc::new(Mutex::new(Vec::new()));
        let sign_flags_task = sign_flags.clone();

        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let private_key = private_key.clone();
                let sign_flags = sign_flags_task.clone();

                tokio::spawn(async move {
                    loop {
                        let request = match read_agent_message(&mut stream).await {
                            Ok(Some(request)) => request,
                            Ok(None) => break,
                            Err(err)
                                if matches!(
                                    err.kind(),
                                    io::ErrorKind::BrokenPipe
                                        | io::ErrorKind::ConnectionAborted
                                        | io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::UnexpectedEof
                                ) =>
                            {
                                break;
                            }
                            Err(err) => panic!("mock agent read failed: {err}"),
                        };
                        let response =
                            handle_agent_request(&private_key, &sign_flags, request.as_slice())
                                .unwrap();
                        if let Err(err) =
                            write_agent_message(&mut stream, response.as_slice()).await
                        {
                            if matches!(
                                err.kind(),
                                io::ErrorKind::BrokenPipe
                                    | io::ErrorKind::ConnectionAborted
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::UnexpectedEof
                            ) {
                                break;
                            }
                            panic!("mock agent write failed: {err}");
                        }
                    }
                });
            }
        });

        MockAgent {
            _tempdir: tempdir,
            socket_path,
            sign_flags,
            task: Some(task),
        }
    }

    #[cfg(unix)]
    async fn read_agent_message(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
        let mut len = [0u8; 4];
        match stream.read_exact(&mut len).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err),
        }

        let mut payload = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut payload).await?;
        Ok(Some(payload))
    }

    #[cfg(unix)]
    async fn write_agent_message(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
        let len = u32::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "mock SSH agent payload exceeds u32 length",
            )
        })?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(payload).await
    }

    #[cfg(unix)]
    fn handle_agent_request(
        private_key: &ssh_key::PrivateKey,
        sign_flags: &Arc<Mutex<Vec<u32>>>,
        request: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut cursor = request;
        let message = match take_agent_byte(&mut cursor)? {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                if !cursor.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in mock agent identities request",
                    ));
                }

                let key_blob = private_key
                    .public_key()
                    .to_bytes()
                    .map_err(mock_agent_ssh_key_error)?;
                let mut response = vec![SSH_AGENT_IDENTITIES_ANSWER];
                response.extend_from_slice(&1u32.to_be_bytes());
                append_agent_string(&mut response, key_blob.as_slice());
                append_agent_string(&mut response, b"mock-agent");
                response
            }
            SSH_AGENTC_SIGN_REQUEST => {
                let key_blob = take_agent_string(&mut cursor)?;
                let signing_input = take_agent_string(&mut cursor)?;
                let flags = take_agent_u32(&mut cursor)?;
                if !cursor.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in mock agent sign request",
                    ));
                }

                let expected_key_blob = private_key
                    .public_key()
                    .to_bytes()
                    .map_err(mock_agent_ssh_key_error)?;
                if key_blob != expected_key_blob {
                    return Ok(vec![SSH_AGENT_FAILURE]);
                }

                sign_flags.lock().unwrap().push(flags);
                let signature = mock_agent_signature(private_key, signing_input.as_slice(), flags)?;
                let mut response = vec![SSH_AGENT_SIGN_RESPONSE];
                append_agent_string(&mut response, signature.as_slice());
                response
            }
            _ => vec![SSH_AGENT_FAILURE],
        };

        Ok(message)
    }

    #[cfg(unix)]
    fn mock_agent_signature(
        private_key: &ssh_key::PrivateKey,
        signing_input: &[u8],
        flags: u32,
    ) -> io::Result<Vec<u8>> {
        let signature = match private_key.key_data() {
            KeypairData::Ed25519(_) => {
                if flags != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unexpected Ed25519 agent sign flags: {flags}"),
                    ));
                }
                Signer::try_sign(private_key, signing_input)
                    .map_err(|_| io::Error::other("could not sign mock Ed25519 agent request"))?
            }
            KeypairData::Rsa(keypair) => {
                if flags != SSH_AGENT_RSA_SHA2_256 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unexpected RSA agent sign flags: {flags}"),
                    ));
                }
                let signing_key =
                    RsaSigningKey::<Sha256>::new(mock_agent_rsa_private_key(keypair)?);
                let signature: RsaSignature = Signer::try_sign(&signing_key, signing_input)
                    .map_err(|_| io::Error::other("could not sign mock RSA agent request"))?;
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    signature.to_vec(),
                )
                .map_err(mock_agent_ssh_key_error)?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mock agent only supports Ed25519 and RSA keys",
                ));
            }
        };

        Vec::<u8>::try_from(signature).map_err(mock_agent_ssh_key_error)
    }

    #[cfg(unix)]
    fn take_agent_byte(cursor: &mut &[u8]) -> io::Result<u8> {
        let Some((&byte, rest)) = cursor.split_first() else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated mock SSH agent message",
            ));
        };
        *cursor = rest;
        Ok(byte)
    }

    #[cfg(unix)]
    fn take_agent_u32(cursor: &mut &[u8]) -> io::Result<u32> {
        if cursor.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated mock SSH agent u32",
            ));
        }
        let (prefix, rest) = cursor.split_at(4);
        *cursor = rest;
        Ok(u32::from_be_bytes(prefix.try_into().unwrap()))
    }

    #[cfg(unix)]
    fn take_agent_string(cursor: &mut &[u8]) -> io::Result<Vec<u8>> {
        let len = take_agent_u32(cursor)? as usize;
        if cursor.len() < len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated mock SSH agent string",
            ));
        }
        let (value, rest) = cursor.split_at(len);
        *cursor = rest;
        Ok(value.to_vec())
    }

    #[cfg(unix)]
    fn append_agent_string(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    #[cfg(unix)]
    fn mock_agent_ssh_key_error(err: ssh_key::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }

    #[cfg(unix)]
    fn mock_agent_rsa_private_key(keypair: &RsaKeypair) -> io::Result<JwtRsaPrivateKey> {
        let private_key = JwtRsaPrivateKey::from_components(
            mock_agent_rsa_biguint(keypair.public.n.as_positive_bytes())?,
            mock_agent_rsa_biguint(keypair.public.e.as_positive_bytes())?,
            mock_agent_rsa_biguint(keypair.private.d.as_positive_bytes())?,
            vec![
                mock_agent_rsa_biguint(keypair.private.p.as_positive_bytes())?,
                mock_agent_rsa_biguint(keypair.private.q.as_positive_bytes())?,
            ],
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RSA private key"))?;
        private_key
            .validate()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RSA private key"))?;
        Ok(private_key)
    }

    #[cfg(unix)]
    fn mock_agent_rsa_biguint(bytes: Option<&[u8]>) -> io::Result<RsaBigUint> {
        let bytes = bytes.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid RSA key component")
        })?;
        Ok(RsaBigUint::from_bytes_be(bytes))
    }

    async fn read_stdout_line(channel: &Arc<Ssh3Channel>) -> Result<String, Ssh3ClientError> {
        let mut stdout = Vec::new();
        loop {
            match channel.next_message().await? {
                Ssh3Message::Data(data) if data.data_type == SSH_EXTENDED_DATA_NONE => {
                    stdout.extend_from_slice(&data.data);
                    if let Some(newline) = stdout.iter().position(|byte| *byte == b'\n') {
                        return Ok(String::from_utf8_lossy(&stdout[..newline]).to_string());
                    }
                }
                Ssh3Message::ChannelRequest(message) => match message.request {
                    Ssh3ChannelRequest::ExitStatus(status) => {
                        return Err(Ssh3ClientError::Io(io::Error::other(format!(
                            "session exited before producing stdout line: {}",
                            status.exit_status
                        ))));
                    }
                    Ssh3ChannelRequest::ExitSignal(signal) => {
                        return Err(Ssh3ClientError::ExitSignal(signal));
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    #[cfg(unix)]
    async fn request_forwarded_agent_signature(
        socket_path: &str,
        signing_input: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut forwarded_socket = UnixStream::connect(socket_path.trim()).await?;
        write_agent_message(&mut forwarded_socket, &[SSH_AGENTC_REQUEST_IDENTITIES]).await?;
        let identities = read_agent_message(&mut forwarded_socket)
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "forwarded agent closed before returning identities",
                )
            })?;
        let mut cursor = identities.as_slice();
        if take_agent_byte(&mut cursor)? != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected forwarded agent identities response",
            ));
        }
        if take_agent_u32(&mut cursor)? != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected forwarded agent identity count",
            ));
        }
        let key_blob = take_agent_string(&mut cursor)?;
        let _comment = take_agent_string(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in forwarded agent identities response",
            ));
        }

        let mut sign_request = vec![SSH_AGENTC_SIGN_REQUEST];
        append_agent_string(&mut sign_request, &key_blob);
        append_agent_string(&mut sign_request, signing_input);
        sign_request.extend_from_slice(&0u32.to_be_bytes());
        write_agent_message(&mut forwarded_socket, &sign_request).await?;
        let signature = read_agent_message(&mut forwarded_socket)
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "forwarded agent closed before returning a signature",
                )
            })?;
        let mut cursor = signature.as_slice();
        if take_agent_byte(&mut cursor)? != SSH_AGENT_SIGN_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected forwarded agent sign response",
            ));
        }
        let signature_blob = take_agent_string(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in forwarded agent sign response",
            ));
        }
        Ok(signature_blob)
    }

    struct OidcFixture {
        _tempdir: TempDir,
        authorized_identities_path: std::path::PathBuf,
        issuer_url: String,
        client_id: String,
        email: String,
        signing_key: JwtRsaPrivateKey,
        username: String,
        provider_task: tokio::task::JoinHandle<()>,
    }

    impl Drop for OidcFixture {
        fn drop(&mut self) {
            self.provider_task.abort();
        }
    }

    impl OidcFixture {
        fn bearer_token_for_nonce(&self, nonce: &str) -> String {
            build_oidc_token(
                &self.issuer_url,
                &self.client_id,
                &self.email,
                Some(nonce),
                &self.signing_key,
            )
        }
    }

    struct HttpRequest {
        method: String,
        target: String,
        body: Vec<u8>,
    }

    async fn read_http_request(
        stream: &mut tokio::net::TcpStream,
    ) -> Result<HttpRequest, std::io::Error> {
        let mut buffer = Vec::new();
        let mut header_end = None;
        loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n");
            }
            if let Some(header_end) = header_end {
                let header_text = String::from_utf8_lossy(&buffer[..header_end]);
                let content_length = header_text
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(0);
                if buffer.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }

        let header_end = header_end.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "missing HTTP headers")
        })?;
        let header_text = String::from_utf8_lossy(&buffer[..header_end]);
        let mut request_line = header_text
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let method = request_line.next().unwrap_or_default().to_string();
        let target = request_line.next().unwrap_or("/").to_string();
        let content_length = header_text
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);

        Ok(HttpRequest {
            method,
            target,
            body: buffer[header_end + 4..header_end + 4 + content_length].to_vec(),
        })
    }

    fn http_query_value(target: &str, key: &str) -> Option<String> {
        let url = Url::parse(&format!("http://localhost{target}")).ok()?;
        url.query_pairs()
            .find_map(|(current_key, value)| (current_key == key).then(|| value.into_owned()))
    }

    fn http_response(
        status_line: &str,
        content_type: &str,
        body: impl AsRef<str>,
        extra_headers: &[(&str, &str)],
    ) -> String {
        let body = body.as_ref();
        let mut response = format!(
            "{status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n",
            body.len()
        );
        for (name, value) in extra_headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        response.push_str(body);
        response
    }

    fn mock_browser_opener(url: String) -> Result<(), Ssh3OidcError> {
        tokio::spawn(async move {
            let _ = reqwest::Client::new().get(url).send().await;
        });
        Ok(())
    }

    fn build_oidc_token(
        issuer_url: &str,
        client_id: &str,
        email: &str,
        nonce: Option<&str>,
        private_key: &JwtRsaPrivateKey,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-key","typ":"JWT"}"#);
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let nonce_claim = nonce
            .map(|nonce| format!(r#","nonce":"{nonce}""#))
            .unwrap_or_default();
        let claims = URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"iss":"{issuer_url}","aud":"{client_id}","exp":{exp},"email":"{email}","email_verified":true{nonce_claim}}}"#
            )
            .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let signing_key = RsaSigningKey::<Sha256>::new(private_key.clone());
        let signature: RsaSignature =
            Signer::try_sign(&signing_key, signing_input.as_bytes()).unwrap();
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_vec())
        )
    }

    async fn create_oidc_fixture() -> OidcFixture {
        let tempdir = TempDir::new().unwrap();
        let authorized_identities_path = tempdir.path().join("authorized_identities");
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let issuer_url = format!("http://{}", listener.local_addr().unwrap());
        let client_id = "ssh3-client-id".to_string();
        let email = "alice@example.com";
        let signing_key = JwtRsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = signing_key.to_public_key();
        let discovery_body = format!(
            r#"{{"issuer":"{issuer_url}","jwks_uri":"{issuer_url}/keys","authorization_endpoint":"{issuer_url}/authorize","token_endpoint":"{issuer_url}/token"}}"#
        );
        let jwks_body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"test-key","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
            URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        );
        let expected_challenge = Arc::new(Mutex::new(None::<String>));
        let expected_nonce = Arc::new(Mutex::new(None::<String>));
        let provider_task = tokio::spawn({
            let expected_challenge = expected_challenge.clone();
            let expected_nonce = expected_nonce.clone();
            let client_id = client_id.clone();
            let issuer_url = issuer_url.clone();
            let signing_key = signing_key.clone();
            async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let discovery_body = discovery_body.clone();
                    let jwks_body = jwks_body.clone();
                    let token_body = format!(
                        r#"{{"access_token":"mock-access-token","token_type":"Bearer","id_token":"{}"}}"#,
                        build_oidc_token(
                            &issuer_url,
                            &client_id,
                            email,
                            expected_nonce.lock().unwrap().as_deref(),
                            &signing_key,
                        )
                    );
                    let expected_challenge = expected_challenge.clone();
                    let expected_nonce = expected_nonce.clone();
                    let client_id = client_id.clone();
                    tokio::spawn(async move {
                        let request = read_http_request(&mut stream).await.unwrap();
                        let response = match request.target.split('?').next().unwrap_or("/") {
                            "/.well-known/openid-configuration" => http_response(
                                "HTTP/1.1 200 OK",
                                "application/json",
                                discovery_body,
                                &[],
                            ),
                            "/keys" => {
                                http_response("HTTP/1.1 200 OK", "application/json", jwks_body, &[])
                            }
                            "/authorize" => {
                                assert_eq!(request.method, "GET");
                                assert_eq!(
                                    http_query_value(&request.target, "client_id").as_deref(),
                                    Some(client_id.as_str())
                                );
                                assert_eq!(
                                    http_query_value(&request.target, "scope").as_deref(),
                                    Some(super::DEFAULT_OIDC_SCOPE)
                                );
                                assert_eq!(
                                    http_query_value(&request.target, "code_challenge_method")
                                        .as_deref(),
                                    Some("S256")
                                );
                                *expected_challenge.lock().unwrap() =
                                    http_query_value(&request.target, "code_challenge");
                                *expected_nonce.lock().unwrap() =
                                    http_query_value(&request.target, "nonce");
                                let redirect_uri =
                                    http_query_value(&request.target, "redirect_uri").unwrap();
                                let state = http_query_value(&request.target, "state").unwrap();
                                let location =
                                    format!("{redirect_uri}?code=mock-auth-code&state={state}");
                                http_response(
                                    "HTTP/1.1 302 Found",
                                    "text/plain",
                                    "",
                                    &[("location", &location)],
                                )
                            }
                            "/token" => {
                                assert_eq!(request.method, "POST");
                                let form = url::form_urlencoded::parse(&request.body)
                                    .into_owned()
                                    .collect::<Vec<_>>();
                                let get = |name: &str| {
                                    form.iter().find_map(|(key, value)| {
                                        (key == name).then_some(value.clone())
                                    })
                                };
                                assert_eq!(
                                    get("grant_type").as_deref(),
                                    Some("authorization_code")
                                );
                                assert_eq!(get("code").as_deref(), Some("mock-auth-code"));
                                if let Some(token_client_id) = get("client_id") {
                                    assert_eq!(token_client_id, client_id);
                                }
                                let verifier = get("code_verifier").unwrap();
                                let expected = expected_challenge.lock().unwrap().clone().unwrap();
                                assert_eq!(super::oidc_code_challenge(&verifier), expected);
                                http_response(
                                    "HTTP/1.1 200 OK",
                                    "application/json",
                                    token_body,
                                    &[],
                                )
                            }
                            _ => http_response(
                                "HTTP/1.1 404 Not Found",
                                "application/json",
                                "{}",
                                &[],
                            ),
                        };
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
            }
        });
        fs::write(
            &authorized_identities_path,
            format!("oidc {client_id} {issuer_url} {email}\n"),
        )
        .unwrap();

        OidcFixture {
            _tempdir: tempdir,
            authorized_identities_path,
            issuer_url: issuer_url.clone(),
            client_id: client_id.clone(),
            email: email.to_string(),
            signing_key,
            username: {
                #[cfg(unix)]
                {
                    current_username()
                }
                #[cfg(not(unix))]
                {
                    "user".to_string()
                }
            },
            provider_task,
        }
    }

    /// The Go peer accessors that the interop scenarios depend on.
    ///
    /// Every one of them yields an `Option`, so a scenario that needs the Go
    /// peers cannot continue without them: it has to take the skip path and
    /// announce it.
    #[cfg(unix)]
    const GO_PEER_ACCESSORS: &[&str] = &[
        "spawn_go_interop_server",
        "run_go_interop_client",
        "spawn_go_cli_server",
        "spawn_go_cli_tcp_forwarder",
        "spawn_go_cli_udp_forwarder",
        "run_go_cli_client",
        "run_go_cli_client_with_forwarded_agent",
        "run_go_cli_client_with_oidc",
        "run_go_cli_client_with_password",
        "spawn_go_cli_shell_with_pty",
        "run_go_cli_shell",
        "go_agent_probe_binary",
    ];

    /// Guards the interop skip protocol.
    ///
    /// A scenario that needs the Go peers must not report success when they
    /// are unavailable: it has to take the skip path, which prints a
    /// `skipping:` line. This test checks that every site that consumes a Go
    /// peer is paired with such a skip, so a scenario that forgets it is
    /// caught here instead of silently passing.
    #[cfg(unix)]
    #[test]
    fn interop_scenarios_report_their_skip() {
        // The scan below looks at this file, so the guards themselves must
        // not be mistaken for interop scenarios. The marker is assembled at
        // runtime so that this test does not match its own source.
        let source = include_str!("lib.rs");
        let marker = format!("// --- {} scenarios ---", "interop");
        let scenarios = source
            .split(&marker)
            .nth(1)
            .expect("the interop scenarios are marked in this file");

        let mut peer_sites = 0usize;
        let mut skip_sites = 0usize;
        for accessor in GO_PEER_ACCESSORS {
            for (index, _) in scenarios.match_indices(&format!("= {accessor}(")) {
                peer_sites += 1;
                // The skip of the enclosing `let ... else` block follows the
                // call within a few lines.
                let block = &scenarios[index..(index + 600).min(scenarios.len())];
                assert!(
                    block.contains("skip_interop("),
                    "the Go peer `{accessor}` is consumed without a skip path",
                );
            }
        }
        for (index, _) in scenarios.match_indices("skip_interop(") {
            // The declaration of the helper itself is not a call site.
            if scenarios[..index].ends_with("fn ") {
                continue;
            }
            // The scenario name follows the call, possibly on the next line.
            let rest = &scenarios[index + "skip_interop(".len()..];
            assert!(
                rest.trim_start().starts_with('"'),
                "a skip announcement must name its scenario",
            );
            skip_sites += 1;
        }
        assert!(peer_sites > 0, "no interop scenario consumes the Go peers",);
        assert_eq!(
            peer_sites, skip_sites,
            "every Go peer access must be paired with a skip announcement",
        );
    }

    /// Reports whether each set of Go peers could be prepared.
    #[cfg(unix)]
    fn go_peers_available() -> (bool, bool, bool) {
        (
            go_interop_binaries().is_some(),
            go_cli_binaries().is_some(),
            go_agent_probe_binary().is_some(),
        )
    }

    /// Checks that the Go peers resolve consistently.
    ///
    /// All three peer sets come from the same checkout, so they must be
    /// available together. A mismatch would let some scenarios run against
    /// the Go peers while others silently skip.
    #[cfg(unix)]
    #[test]
    fn go_peers_resolve_consistently() {
        let (interop, cli, probe) = go_peers_available();
        assert_eq!(
            interop, cli,
            "the interop and the CLI peers must be available together",
        );
        assert_eq!(
            cli, probe,
            "the CLI peers and the agent probe must be available together",
        );
        if !interop {
            // No peers: the scenarios must have recorded why they skipped.
            assert!(
                recorded_go_unavailable_reason().is_some(),
                "the skip reason must be recorded so the log explains itself",
            );
        }
    }

    // --- interop scenarios ---

    #[tokio::test]
    async fn exec_capture_round_trips_against_the_rust_server() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, Ssh3ServerConfig::default()),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'hello from client\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            Ssh3CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"hello from client\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_exec_capture_round_trips_against_the_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");

        let Some((mut server, bind_addr)) = spawn_go_interop_server(
            "127.0.0.1:0",
            &fixture.username,
            &fixture.authorized_identities_path,
            &cert_path,
            &key_path,
        )
        .await
        else {
            skip_interop("rust_client_exec_capture_round_trips_against_the_go_server");
            return;
        };

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", bind_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let session = tokio::time::timeout(
            Duration::from_secs(40),
            run_exec_capture(&config, "printf 'hello from rust to go\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(session.exit_status, 0);
        assert_eq!(session.stdout, b"hello from rust to go\n".to_vec());
        assert!(session.stderr.is_empty());
        assert!(
            session
                .server_header
                .as_deref()
                .is_some_and(|value| value.starts_with("SSH "))
        );

        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_exec_capture_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");

        let Some(mut server) = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await
        else {
            skip_interop("rust_client_exec_capture_round_trips_against_the_real_go_server");
            return;
        };

        let mut config = Ssh3ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let session = tokio::time::timeout(
            Duration::from_secs(20),
            run_exec_capture(&config, "echo hello from rust to real go"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(session.exit_status, 0);
        assert_eq!(session.stdout, b"hello from rust to real go\n".to_vec());
        assert!(session.stderr.is_empty(), "{session:?}");
        assert!(
            session
                .server_header
                .as_deref()
                .is_some_and(|value| value.starts_with("SSH "))
        );

        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_exec_capture_round_trips_with_extra_pubkey_algorithms_against_the_real_go_server()
     {
        let _guard = lock_go_binary_tests();

        for (algorithm, label) in [
            (AuthKeyAlgorithm::NistP256, "p256"),
            (AuthKeyAlgorithm::Rsa, "rsa"),
        ] {
            let fixture = create_auth_fixture(algorithm);
            let tempdir = TempDir::new().unwrap();
            let home_dir = tempdir.path().join("home");
            fs::create_dir_all(home_dir.join(".ssh")).unwrap();
            fs::write(
                home_dir.join(".ssh").join("authorized_keys"),
                fs::read(&fixture.authorized_identities_path).unwrap(),
            )
            .unwrap();

            let bind_port = reserve_udp_port();
            let bind_addr = format!("127.0.0.1:{bind_port}");
            let cert_path = tempdir.path().join("cert.pem");
            let key_path = tempdir.path().join("key.pem");
            let log_path = tempdir.path().join("go-server.log");

            let Some(mut server) = spawn_go_cli_server(
                &bind_addr,
                &fixture.username,
                &home_dir,
                &cert_path,
                &key_path,
                &log_path,
            )
            .await
            else {
                skip_interop(
                    "rust_client_exec_capture_round_trips_with_extra_pubkey_algorithms_against_the_real_go_server",
                );
                return;
            };

            let mut config = Ssh3ClientConfig::new(
                format!(
                    "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                    fixture.username
                )
                .parse()
                .unwrap(),
            );
            config.trust = Ssh3TrustStrategy::Insecure;
            config.username = Some(fixture.username.clone());
            config.identity_file = Some(fixture.private_key_path.clone());

            let session = tokio::time::timeout(
                Duration::from_secs(20),
                run_exec_capture(&config, format!("echo hello from rust {label} to real go")),
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(session.exit_status, 0, "{label}: {session:?}");
            assert_eq!(
                session.stdout,
                format!("hello from rust {label} to real go\n").into_bytes(),
                "{label}: {session:?}"
            );
            assert!(session.stderr.is_empty(), "{label}: {session:?}");
            assert!(
                session
                    .server_header
                    .as_deref()
                    .is_some_and(|value| value.starts_with("SSH ")),
                "{label}: {session:?}"
            );

            let _ = server.kill().await;
            let _ = server.wait().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_exec_round_trips_with_oidc_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_oidc_fixture().await;
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        fs::write(
            home_dir.join(".ssh3").join("authorized_identities"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");

        let Some(mut server) = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await
        else {
            skip_interop("rust_client_exec_round_trips_with_oidc_against_the_real_go_server");
            return;
        };

        let mut config = Ssh3ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.oidc = Some(Ssh3OidcConfig {
            issuer_url: fixture.issuer_url.clone(),
            client_id: fixture.client_id.clone(),
            client_secret: None,
            use_pkce: true,
        });

        let session = tokio::time::timeout(
            Duration::from_secs(20),
            run_exec_capture_with_browser_opener(
                &config,
                "echo hello from rust oidc to real go",
                mock_browser_opener,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(session.exit_status, 0, "{session:?}");
        assert_eq!(
            session.stdout,
            b"hello from rust oidc to real go\n".to_vec()
        );
        assert!(session.stderr.is_empty(), "{session:?}");
        assert!(
            session
                .server_header
                .as_deref()
                .is_some_and(|value| value.starts_with("SSH ")),
            "{session:?}"
        );

        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_ed25519_bearer_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.identity_file = Some(private_key_path);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated client\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            Ssh3CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated client\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_nist_p256_bearer_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::NistP256);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.identity_file = Some(private_key_path);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via p256\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            Ssh3CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via p256\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_rsa_bearer_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Rsa);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.identity_file = Some(private_key_path);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via rsa\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            Ssh3CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via rsa\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn go_client_exec_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let Some(output) = run_go_interop_client(
            &format!("https://127.0.0.1:{}/ssh3-term", server_addr.port()),
            &username,
            &private_key_path,
            "printf 'hello from go to rust\\n'",
        )
        .await
        else {
            skip_interop("go_client_exec_round_trips_against_the_rust_server");
            return;
        };

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, b"hello from go to rust\n".to_vec());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("go interop client failed"), "{output:?}");
        assert!(!stderr.contains("could not establish"), "{output:?}");

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_exec_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let Some(output) = run_go_cli_client(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            &["echo", "hello from real go cli"],
        )
        .await
        else {
            skip_interop("real_go_client_exec_round_trips_against_the_rust_server");
            return;
        };

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert_eq!(stdout, "hello from real go cli\n");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_exec_round_trips_with_oidc_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_oidc_fixture().await;
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let issuer_url = fixture.issuer_url.clone();
        let client_id = fixture.client_id.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let oidc_config_path = tempdir.path().join("oidc_config.json");
        fs::write(
            &oidc_config_path,
            format!(
                r#"[{{"issuer_url":"{issuer_url}","client_id":"{client_id}","client_secret":""}}]"#
            ),
        )
        .unwrap();

        let Some(output) = run_go_cli_client_with_oidc(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &issuer_url,
            &oidc_config_path,
            &["echo", "hello from real go oidc"],
        )
        .await
        else {
            skip_interop("real_go_client_exec_round_trips_with_oidc_against_the_rust_server");
            return;
        };

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert_eq!(stdout, "hello from real go oidc\n");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("could not get token"), "{output:?}");
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_exec_round_trips_with_password_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let username = current_username();
        let password = "correct horse battery staple".to_string();
        let expected_username = username.clone();
        let expected_password = password.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.enable_password_login = true;
            config.password_verifier =
                Some(Arc::new(move |candidate_username, candidate_password| {
                    Ok(candidate_username == expected_username
                        && candidate_password == expected_password)
                }));
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let Some(output) = run_go_cli_client_with_password(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &password,
            &["echo", "hello from real go password"],
        )
        .await
        else {
            skip_interop("real_go_client_exec_round_trips_with_password_against_the_rust_server");
            return;
        };

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert!(stdout.contains("hello from real go password\n"), "{stdout}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("could not get password"), "{output:?}");
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_shell_with_pty_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");

        let Some(mut server) = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await
        else {
            skip_interop("rust_client_shell_with_pty_round_trips_against_the_real_go_server");
            return;
        };

        let mut config = Ssh3ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let client = connect_client(&config).await.unwrap();
        let session = timeout(
            Duration::from_secs(20),
            run_shell_capture_with_resize_on_client(
                &client,
                LocalTerminalInfo {
                    term: Some("xterm-256color".to_string()),
                    size: TerminalSize {
                        char_width: 80,
                        char_height: 24,
                        pixel_width: 640,
                        pixel_height: 480,
                    },
                },
                TerminalSize {
                    char_width: 100,
                    char_height: 40,
                    pixel_width: 800,
                    pixel_height: 600,
                },
                "stty size\n",
                "stty size\nprintf '__SSH3_PTY_RUST_CLIENT_OK__:%s\\n' \"$TERM\"\nexit\n",
            ),
        )
        .await
        .unwrap()
        .unwrap();
        client.shutdown().await;

        assert_eq!(session.exit_status, 0, "{session:?}");
        let stdout = String::from_utf8_lossy(&session.stdout);
        assert!(stdout.contains("24 80"), "{stdout}");
        assert!(stdout.contains("40 100"), "{stdout}");
        assert!(
            stdout.contains("__SSH3_PTY_RUST_CLIENT_OK__:xterm-256color"),
            "{stdout}"
        );
        assert!(
            session
                .server_header
                .as_deref()
                .is_some_and(|value| value.starts_with("SSH ")),
            "{session:?}"
        );

        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_shell_with_pty_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let Some(output) = run_go_cli_shell(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            "printf '__SSH3_PTY_GO_CLIENT_OK__:%s\\n' \"$TERM\"\nexit\n",
        )
        .await
        else {
            skip_interop("real_go_client_shell_with_pty_round_trips_against_the_rust_server");
            return;
        };

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert!(
            stdout.contains("__SSH3_PTY_GO_CLIENT_OK__:xterm"),
            "{stdout}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_window_change_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let Some(session) = spawn_go_cli_shell_with_pty(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            TerminalSize {
                char_width: 80,
                char_height: 24,
                pixel_width: 640,
                pixel_height: 480,
            },
        )
        .await
        else {
            skip_interop("real_go_client_window_change_round_trips_against_the_rust_server");
            return;
        };
        session.write_all("stty size\n").await;
        session.wait_for_output_fragment("24 80").await;
        session
            .resize(TerminalSize {
                char_width: 100,
                char_height: 40,
                pixel_width: 800,
                pixel_height: 600,
            })
            .unwrap();
        session
            .write_all("stty size\nprintf '__SSH3_GO_CLIENT_RESIZE_OK__\\n'\nexit\n")
            .await;
        let output = session.wait_with_output().await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert!(stdout.contains("24 80"), "{stdout}");
        assert!(stdout.contains("40 100"), "{stdout}");
        assert!(stdout.contains("__SSH3_GO_CLIENT_RESIZE_OK__"), "{stdout}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_signal_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let Some(session) = spawn_go_cli_shell_with_pty(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            TerminalSize {
                char_width: 80,
                char_height: 24,
                pixel_width: 640,
                pixel_height: 480,
            },
        )
        .await
        else {
            skip_interop("real_go_client_signal_round_trips_against_the_rust_server");
            return;
        };
        session.write_all("stty size\n").await;
        session.wait_for_output_fragment("24 80").await;
        session
            .write_all(
                "trap 'printf __SSH3_GO_CLIENT_SIGNAL_OK__\\\\n; exit 0' TERM\nprintf '__SSH3_SIGNAL_ARMED__:%s\\n' \"$TERM\"\nwhile :; do sleep 1; done\n",
            )
            .await;
        session
            .wait_for_output_fragment("__SSH3_SIGNAL_ARMED__:xterm")
            .await;
        session.send_signal(nix::libc::SIGTERM).unwrap();
        let output = session.wait_with_output().await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert!(stdout.contains("__SSH3_GO_CLIENT_SIGNAL_OK__"), "{stdout}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_tcp_forwarding_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");
        let (remote_addr, echo_task) = spawn_tcp_echo_server().await;

        let Some(mut server) = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await
        else {
            skip_interop("rust_client_tcp_forwarding_round_trips_against_the_real_go_server");
            return;
        };

        let mut config = Ssh3ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let client = connect_client(&config).await.unwrap();
        let payload = b"tcp forward rust to real go";
        let echoed = timeout(
            Duration::from_secs(20),
            run_tcp_forwarding_round_trip_on_client(&client, remote_addr, payload),
        )
        .await
        .unwrap()
        .unwrap();
        client.shutdown().await;

        assert_eq!(echoed, payload.to_vec());

        echo_task.abort();
        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_tcp_forwarding_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let (remote_addr, echo_task) = spawn_tcp_echo_server().await;

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let local_port = reserve_tcp_port();
        let log_path = tempdir.path().join("go-client-forward.log");
        let Some(mut forwarder) = spawn_go_cli_tcp_forwarder(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            local_port,
            remote_addr,
            &log_path,
        )
        .await
        else {
            skip_interop("real_go_client_tcp_forwarding_round_trips_against_the_rust_server");
            return;
        };

        let mut stream = TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            local_port,
        )))
        .await
        .unwrap();
        let payload = b"tcp forward real go to rust";
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);

        let status = timeout(Duration::from_secs(15), forwarder.wait())
            .await
            .unwrap()
            .unwrap();
        let logs = fs::read_to_string(&log_path).unwrap_or_default();
        assert_eq!(status.code(), Some(0), "logs:\n{logs}");
        assert!(!logs.contains("could not forward"), "{logs}");
        assert!(!logs.contains("could not dial"), "{logs}");
        assert!(!logs.contains("an error was encountered"), "{logs}");

        echo_task.abort();
        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_udp_forwarding_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");
        let (remote_addr, echo_task) = spawn_udp_echo_server().await;

        let Some(mut server) = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await
        else {
            skip_interop("rust_client_udp_forwarding_round_trips_against_the_real_go_server");
            return;
        };

        let mut config = Ssh3ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let client = connect_client(&config).await.unwrap();
        let payload = b"udp forward rust to real go";
        let echoed = timeout(
            Duration::from_secs(20),
            run_udp_forwarding_round_trip_on_client(&client, remote_addr, payload),
        )
        .await
        .unwrap()
        .unwrap();
        client.shutdown().await;

        assert_eq!(echoed, payload.to_vec());

        echo_task.abort();
        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_udp_forwarding_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let (remote_addr, echo_task) = spawn_udp_echo_server().await;

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let local_port = reserve_udp_port();
        let log_path = tempdir.path().join("go-client-forward.log");
        let Some(mut forwarder) = spawn_go_cli_udp_forwarder(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            local_port,
            remote_addr,
            &log_path,
        )
        .await
        else {
            skip_interop("real_go_client_udp_forwarding_round_trips_against_the_rust_server");
            return;
        };

        let socket =
            TokioUdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
        let forward_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_port));
        let payload = b"udp forward real go to rust";
        socket.send_to(payload, forward_addr).await.unwrap();

        let mut echoed = vec![0; 1024];
        let (n, source) = timeout(Duration::from_secs(10), socket.recv_from(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, forward_addr);
        assert_eq!(&echoed[..n], payload);

        let status = timeout(Duration::from_secs(15), forwarder.wait())
            .await
            .unwrap()
            .unwrap();
        let logs = fs::read_to_string(&log_path).unwrap_or_default();
        assert_eq!(status.code(), Some(0), "logs:\n{logs}");
        assert!(!logs.contains("could not forward"), "{logs}");
        assert!(!logs.contains("could not dial"), "{logs}");
        assert!(!logs.contains("an error was encountered"), "{logs}");

        echo_task.abort();
        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_capture_round_trips_with_ed25519_agent_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key = ssh3_auth::load_private_key(&fixture.private_key_path).unwrap();
        let agent = spawn_mock_agent(private_key).await;
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.agent = Some(super::Ssh3AgentSelection::First);
        config.agent_socket = Some(agent.socket_path.clone());

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via agent\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            Ssh3CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via agent\n".to_vec(),
                stderr: Vec::new(),
            }
        );
        assert_eq!(agent.sign_flags(), vec![0]);

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_capture_round_trips_with_rsa_agent_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Rsa);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let private_key = ssh3_auth::load_private_key(&private_key_path).unwrap();
        let agent = spawn_mock_agent(private_key).await;
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.agent = Some(super::Ssh3AgentSelection::PublicKey(private_key_path));
        config.agent_socket = Some(agent.socket_path.clone());

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via rsa agent\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            Ssh3CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via rsa agent\n".to_vec(),
                stderr: Vec::new(),
            }
        );
        assert_eq!(agent.sign_flags(), vec![SSH_AGENT_RSA_SHA2_256]);

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn forward_agent_exposes_remote_ssh_auth_sock_and_proxies_requests() {
        let _agent_socket_guard = lock_agent_socket_tests();
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, Ssh3ServerConfig::default()),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.forward_agent = true;
        config.agent_socket = Some(agent.socket_path.clone());

        let client = connect_client(&config).await.unwrap();
        let channel = client.open_session_channel().await.unwrap();
        let request =
            Ssh3SessionRequest::Exec("printf '%s\\n' \"$SSH_AUTH_SOCK\"; sleep 2".to_string());
        send_forward_agent_request(channel.as_ref()).await.unwrap();
        let session_runtime =
            build_session_runtime(&client, &config, channel.clone(), None, None).unwrap();
        send_initial_session_requests(channel.as_ref(), &request, None)
            .await
            .unwrap();

        let socket_path = tokio::time::timeout(Duration::from_secs(5), read_stdout_line(&channel))
            .await
            .unwrap()
            .unwrap();
        assert!(!socket_path.is_empty());

        let signature = request_forwarded_agent_signature(&socket_path, b"forwarded agent")
            .await
            .unwrap();
        assert!(!signature.is_empty());
        assert_eq!(agent.sign_flags(), vec![0]);

        loop {
            match channel.next_message().await.unwrap() {
                Ssh3Message::ChannelRequest(message) => match message.request {
                    Ssh3ChannelRequest::ExitStatus(status) => {
                        assert_eq!(status.exit_status, 0);
                        break;
                    }
                    Ssh3ChannelRequest::ExitSignal(signal) => {
                        panic!("unexpected exit signal: {signal:?}")
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        drop(session_runtime);
        client.shutdown().await;
        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn forward_agent_survives_multiple_remote_connections_in_one_session() {
        let _agent_socket_guard = lock_agent_socket_tests();
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, Ssh3ServerConfig::default()),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.forward_agent = true;
        config.agent_socket = Some(agent.socket_path.clone());

        let client = connect_client(&config).await.unwrap();
        let channel = client.open_session_channel().await.unwrap();
        let request =
            Ssh3SessionRequest::Exec("printf '%s\\n' \"$SSH_AUTH_SOCK\"; sleep 3".to_string());
        send_forward_agent_request(channel.as_ref()).await.unwrap();
        let session_runtime =
            build_session_runtime(&client, &config, channel.clone(), None, None).unwrap();
        send_initial_session_requests(channel.as_ref(), &request, None)
            .await
            .unwrap();

        let socket_path = tokio::time::timeout(Duration::from_secs(5), read_stdout_line(&channel))
            .await
            .unwrap()
            .unwrap();
        assert!(!socket_path.is_empty());

        let first_signature =
            request_forwarded_agent_signature(&socket_path, b"forwarded agent one")
                .await
                .unwrap();
        let second_signature =
            request_forwarded_agent_signature(&socket_path, b"forwarded agent two")
                .await
                .unwrap();
        assert!(!first_signature.is_empty());
        assert!(!second_signature.is_empty());
        assert_ne!(first_signature, second_signature);
        assert_eq!(agent.sign_flags(), vec![0, 0]);

        loop {
            match channel.next_message().await.unwrap() {
                Ssh3Message::ChannelRequest(message) => match message.request {
                    Ssh3ChannelRequest::ExitStatus(status) => {
                        assert_eq!(status.exit_status, 0);
                        break;
                    }
                    Ssh3ChannelRequest::ExitSignal(signal) => {
                        panic!("unexpected exit signal: {signal:?}")
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        drop(session_runtime);
        client.shutdown().await;
        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_forward_agent_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");

        let Some(mut server) = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await
        else {
            skip_interop("rust_client_forward_agent_round_trips_against_the_real_go_server");
            return;
        };

        let mut config = Ssh3ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());
        config.forward_agent = true;
        config.agent_socket = Some(agent.socket_path.clone());

        let client = connect_client(&config).await.unwrap();
        let channel = client.open_session_channel().await.unwrap();
        let request =
            Ssh3SessionRequest::Exec("printf '%s\\n' \"$SSH_AUTH_SOCK\"; sleep 2".to_string());
        send_forward_agent_request(channel.as_ref()).await.unwrap();
        let session_runtime =
            build_session_runtime(&client, &config, channel.clone(), None, None).unwrap();
        send_initial_session_requests(channel.as_ref(), &request, None)
            .await
            .unwrap();

        let socket_path = match timeout(Duration::from_secs(5), read_stdout_line(&channel)).await {
            Ok(Ok(path)) => path,
            Ok(Err(err)) => {
                let logs = fs::read_to_string(&log_path).unwrap_or_default();
                panic!(
                    "failed to read forwarded SSH_AUTH_SOCK from the real Go counterpart server: {err}\nlogs:\n{logs}"
                );
            }
            Err(_) => {
                let logs = fs::read_to_string(&log_path).unwrap_or_default();
                panic!(
                    "timed out reading forwarded SSH_AUTH_SOCK from the real Go counterpart server\nlogs:\n{logs}"
                );
            }
        };
        assert!(!socket_path.is_empty());

        let signature =
            request_forwarded_agent_signature(&socket_path, b"real go server forwarded agent")
                .await
                .unwrap();
        assert!(!signature.is_empty());
        assert_eq!(agent.sign_flags(), vec![0]);

        loop {
            match channel.next_message().await.unwrap() {
                Ssh3Message::ChannelRequest(message) => match message.request {
                    Ssh3ChannelRequest::ExitStatus(status) => {
                        assert_eq!(status.exit_status, 0);
                        break;
                    }
                    Ssh3ChannelRequest::ExitSignal(signal) => {
                        panic!("unexpected exit signal: {signal:?}")
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        drop(session_runtime);
        client.shutdown().await;
        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn go_agent_probe_talks_to_mock_agent_locally() {
        let _guard = lock_go_binary_tests();
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let Some(probe) = go_agent_probe_binary() else {
            skip_interop("go_agent_probe_talks_to_mock_agent_locally");
            return;
        };

        let output = timeout(
            Duration::from_secs(10),
            TokioCommand::new(&probe.path)
                .env("SSH_AUTH_SOCK", agent.socket_path.as_path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("SSH3_AGENT_PROBE_OK 1 ssh-ed25519"),
            "{stdout}"
        );
        assert_eq!(agent.sign_flags(), vec![0]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_forward_agent_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let _agent_socket_guard = lock_agent_socket_tests();
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let Some(probe) = go_agent_probe_binary() else {
            skip_interop("real_go_client_forward_agent_round_trips_against_the_rust_server");
            return;
        };
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let Some(output) = run_go_cli_client_with_forwarded_agent(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            agent.socket_path.as_path(),
            &[probe.path.to_string_lossy().as_ref()],
        )
        .await
        else {
            skip_interop("real_go_client_forward_agent_round_trips_against_the_rust_server");
            return;
        };

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("SSH3_AGENT_PROBE_OK 1 ssh-ed25519"),
            "{stdout}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("agent forwarding error"), "{output:?}");
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");
        assert_eq!(agent.sign_flags(), vec![0]);

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_oidc_bearer_auth() {
        let fixture = create_oidc_fixture().await;
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        let client = connect_client_with_authorization_builder(&config, |conversation_id| {
            bearer_authorization_value(
                &fixture.bearer_token_for_nonce(&conversation_id_base64(conversation_id)),
            )
        })
        .await
        .unwrap();
        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_capture_on_client(
                &client,
                &config,
                Ssh3SessionRequest::Exec("printf 'authenticated via oidc\\n'".to_string()),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        client.shutdown().await;

        assert_eq!(
            session,
            Ssh3CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via oidc\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_interactive_oidc_login() {
        let fixture = create_oidc_fixture().await;
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let issuer_url = fixture.issuer_url.clone();
        let client_id = fixture.client_id.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.oidc = Some(Ssh3OidcConfig {
            issuer_url,
            client_id,
            client_secret: None,
            use_pkce: true,
        });

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture_with_browser_opener(
                &config,
                "printf 'authenticated via oidc login\\n'",
                mock_browser_opener,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            Ssh3CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via oidc login\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_basic_password_auth() {
        let username = {
            #[cfg(unix)]
            {
                current_username()
            }
            #[cfg(not(unix))]
            {
                "user".to_string()
            }
        };
        let password = "correct horse battery staple".to_string();
        let expected_username = username.clone();
        let expected_password = password.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = Ssh3ServerConfig::default();
            config.enable_password_login = true;
            config.default_user = Some("does-not-exist".to_string());
            config.password_verifier =
                Some(Arc::new(move |candidate_username, candidate_password| {
                    Ok(candidate_username == expected_username
                        && candidate_password == expected_password)
                }));
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.password = Some(password);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via password\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            Ssh3CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via password\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn shell_requests_send_pty_before_shell_when_terminal_metadata_is_available() {
        let (client, server_task) = setup_request_capture_harness(2).await;
        let channel = client.open_session_channel().await.unwrap();
        let pty = pty_spec_from_info(&LocalTerminalInfo {
            term: Some("xterm-256color".to_string()),
            size: TerminalSize {
                char_width: 80,
                char_height: 24,
                pixel_width: 640,
                pixel_height: 480,
            },
        });
        send_initial_session_requests(channel.as_ref(), &Ssh3SessionRequest::Shell, Some(&pty))
            .await
            .unwrap();

        let messages = server_task.await.unwrap();
        match &messages[0] {
            Ssh3Message::ChannelRequest(message) => match &message.request {
                Ssh3ChannelRequest::Pty(request) => {
                    assert_eq!(request.term, b"xterm-256color".to_vec());
                    assert_eq!(request.char_width, 80);
                    assert_eq!(request.char_height, 24);
                    assert_eq!(request.pixel_width, 640);
                    assert_eq!(request.pixel_height, 480);
                }
                other => panic!("expected pty request, got {other:?}"),
            },
            other => panic!("expected channel request, got {other:?}"),
        }
        match &messages[1] {
            Ssh3Message::ChannelRequest(message) => {
                assert!(matches!(message.request, Ssh3ChannelRequest::Shell));
            }
            other => panic!("expected channel request, got {other:?}"),
        }

        client.shutdown().await;
    }

    #[test]
    fn the_pty_policy_decides_the_pty_request() {
        // auto: a pty only for an interactive session driven by a terminal
        assert!(resolve_pty(Ssh3PtyPolicy::Auto, &Ssh3SessionRequest::Shell, None, None).is_none());
        assert!(
            resolve_pty(
                Ssh3PtyPolicy::Auto,
                &Ssh3SessionRequest::Exec("ls".to_string()),
                None,
                None
            )
            .is_none()
        );

        // no: never a pty
        assert!(resolve_pty(Ssh3PtyPolicy::No, &Ssh3SessionRequest::Shell, None, None).is_none());

        // yes and force: a pty even without a local terminal
        let forced = resolve_pty(
            Ssh3PtyPolicy::Force,
            &Ssh3SessionRequest::Exec("ls".to_string()),
            None,
            Some("xterm-256color"),
        )
        .expect("the force policy requests a pty");
        assert_eq!(forced.term, b"xterm-256color".to_vec());
        assert_eq!(forced.char_width, 80);
        assert_eq!(forced.char_height, 24);

        let yes = resolve_pty(Ssh3PtyPolicy::Yes, &Ssh3SessionRequest::Shell, None, None)
            .expect("the yes policy requests a pty");
        assert_eq!(yes.char_width, 80);
        assert_eq!(yes.char_height, 24);
    }

    #[cfg(unix)]
    #[test]
    fn the_auto_pty_policy_follows_the_local_terminal() {
        let terminal = super::LocalTerminal {
            info: LocalTerminalInfo {
                term: Some("xterm-256color".to_string()),
                size: TerminalSize {
                    char_width: 120,
                    char_height: 40,
                    pixel_width: 0,
                    pixel_height: 0,
                },
            },
            fd: 0,
        };
        let pty = resolve_pty(
            Ssh3PtyPolicy::Auto,
            &Ssh3SessionRequest::Shell,
            Some(&terminal),
            None,
        )
        .expect("an interactive session on a terminal requests a pty");
        assert_eq!(pty.term, b"xterm-256color".to_vec());
        assert_eq!(pty.char_width, 120);
        assert_eq!(pty.char_height, 40);
    }

    #[test]
    fn the_exit_codes_of_the_signals_follow_the_open_ssh_convention() {
        assert_eq!(exit_code_for_exit_signal("TERM"), 143);
        assert_eq!(exit_code_for_exit_signal("SEGV"), 139);
        assert_eq!(exit_code_for_exit_signal("KILL"), 137);
        assert_eq!(exit_code_for_exit_signal("INT"), 130);
        assert_eq!(exit_code_for_exit_signal("HUP"), 129);
        assert_eq!(exit_code_for_exit_signal("WHATEVER"), 255);
    }

    #[tokio::test]
    async fn a_local_tcp_forward_bridges_a_connection_to_the_target() {
        // the target the forward dials on the client behalf
        let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buffer = [0u8; 64];
            loop {
                let read = match stream.read(&mut buffer).await {
                    Ok(read) => read,
                    Err(_) => return,
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buffer[..read]).await.is_err() {
                    return;
                }
            }
        });

        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            serve_connection(connection, Ssh3ServerConfig::default())
                .await
                .unwrap();
        });

        let forward_port = reserve_local_tcp_port();
        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.local_forwards = vec![Ssh3LocalForwardSpec {
            bind_address: Some("127.0.0.1".to_string()),
            bind_port: forward_port,
            target_host: "127.0.0.1".to_string(),
            target_port: echo_addr.port(),
            protocol: Ssh3ForwardProtocol::Tcp,
        }];

        let session = tokio::spawn({
            let config = config.clone();
            async move { run_exec_capture(&config, "sleep 10").await }
        });

        let mut stream = None;
        for _ in 0..100 {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, forward_port)).await {
                Ok(connected) => {
                    stream = Some(connected);
                    break;
                }
                Err(_) => sleep(Duration::from_millis(100)).await,
            }
        }
        let mut stream = stream.expect("the local forward did not open its listener");
        stream.write_all(b"ping").await.unwrap();
        let mut buffer = [0u8; 4];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"ping");

        drop(stream);
        session.abort();
        echo_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn a_local_udp_forward_bridges_a_datagram_to_the_target() {
        // the target the forward dials on the client behalf
        let echo = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 64];
            loop {
                let (read, source) = match echo.recv_from(&mut buffer).await {
                    Ok(received) => received,
                    Err(_) => return,
                };
                if echo.send_to(&buffer[..read], source).await.is_err() {
                    return;
                }
            }
        });

        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            serve_connection(connection, Ssh3ServerConfig::default())
                .await
                .unwrap();
        });

        let forward_port = reserve_local_udp_port();
        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        config.local_forwards = vec![Ssh3LocalForwardSpec {
            bind_address: Some("127.0.0.1".to_string()),
            bind_port: forward_port,
            target_host: "127.0.0.1".to_string(),
            target_port: echo_addr.port(),
            protocol: Ssh3ForwardProtocol::Udp,
        }];

        let session = tokio::spawn({
            let config = config.clone();
            async move { run_exec_capture(&config, "sleep 10").await }
        });

        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let mut buffer = vec![0u8; 64];
        let mut echoed = None;
        for _ in 0..100 {
            let _ = socket
                .send_to(b"ping", (Ipv4Addr::LOCALHOST, forward_port))
                .await;
            match tokio::time::timeout(Duration::from_millis(200), socket.recv_from(&mut buffer))
                .await
            {
                Ok(Ok((read, _))) => {
                    echoed = Some(buffer[..read].to_vec());
                    break;
                }
                _ => continue,
            }
        }
        assert_eq!(echoed.as_deref(), Some(&b"ping"[..]));

        session.abort();
        echo_task.abort();
        server_task.abort();
    }

    #[test]
    fn a_malformed_datagram_does_not_end_the_datagram_reception() {
        // a datagram that cannot be parsed is per-datagram garbage
        assert!(super::is_benign_datagram_dispatch_error(
            &ssh3_h3::Ssh3DatagramDispatchError::Proto(ssh3_proto::Ssh3Error::UnknownMessageType(
                42
            ))
        ));
        // a datagram for a channel that does not exist is dropped too
        assert!(super::is_benign_datagram_dispatch_error(
            &ssh3_h3::Ssh3DatagramDispatchError::Conversation(
                Ssh3ConversationError::ChannelNotFound { channel_id: 7 }
            )
        ));
        // the end of the connection is not a malformed datagram
        assert!(!super::is_benign_datagram_dispatch_error(
            &ssh3_h3::Ssh3DatagramDispatchError::Connection(quinn::ConnectionError::LocallyClosed)
        ));
    }

    #[tokio::test]
    async fn window_change_helper_sends_resize_request() {
        let (client, server_task) = setup_request_capture_harness(1).await;
        let channel = client.open_session_channel().await.unwrap();
        send_window_change_request(
            channel.as_ref(),
            TerminalSize {
                char_width: 101,
                char_height: 33,
                pixel_width: 0,
                pixel_height: 0,
            },
        )
        .await
        .unwrap();

        let messages = server_task.await.unwrap();
        match &messages[0] {
            Ssh3Message::ChannelRequest(message) => match &message.request {
                Ssh3ChannelRequest::WindowChange(request) => {
                    assert_eq!(request.char_width, 101);
                    assert_eq!(request.char_height, 33);
                }
                other => panic!("expected window-change request, got {other:?}"),
            },
            other => panic!("expected channel request, got {other:?}"),
        }

        client.shutdown().await;
    }

    #[tokio::test]
    async fn signal_helper_sends_signal_request() {
        let (client, server_task) = setup_request_capture_harness(1).await;
        let channel = client.open_session_channel().await.unwrap();
        send_signal_request(channel.as_ref(), "TERM").await.unwrap();

        let messages = server_task.await.unwrap();
        match &messages[0] {
            Ssh3Message::ChannelRequest(message) => match &message.request {
                Ssh3ChannelRequest::Signal(request) => {
                    assert_eq!(request.signal_name_without_sig, b"TERM".to_vec());
                }
                other => panic!("expected signal request, got {other:?}"),
            },
            other => panic!("expected channel request, got {other:?}"),
        }

        client.shutdown().await;
    }
}
