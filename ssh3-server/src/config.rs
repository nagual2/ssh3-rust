//! Server configuration: [`Ssh3ServerConfig`], its defaults and validation.

use std::env;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ssh3_h3::SSH3_VERSION_STRING;

use crate::auth::{Ssh3AuthGuard, password_auth_available};
use crate::error::Ssh3ServerError;
use crate::forwarding::ForwardPolicy;
use crate::sftp::SftpSessionBudget;

/// Callback that decides whether a username/password pair is valid.
///
/// The server calls it with the username requested by the client and the
/// password taken from the `Authorization: Basic` header. Returning `Ok(false)`
/// rejects the request, `Err(..)` aborts it with an I/O error.
///
/// When no verifier is configured the server falls back to the platform
/// default: on Linux the shadow password database is consulted through
/// `crypt(3)`.
pub type Ssh3PasswordVerifier = Arc<dyn Fn(&str, &str) -> io::Result<bool> + Send + Sync + 'static>;

/// The `GatewayPorts` policy of the reverse forwards.
///
/// The policy follows the `sshd_config` semantics: `no` (the default) forces
/// every client-requested bind back to the loopback, `clientspecified` honors
/// the bind address the client asked for and `yes` binds the wildcard
/// address regardless of the request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GatewayPortsPolicy {
    /// Force every client-requested bind back to the loopback.
    #[default]
    No,
    /// Honor the bind address the client asked for.
    ClientSpecified,
    /// Bind the wildcard address regardless of the request.
    Yes,
}

impl GatewayPortsPolicy {
    /// Parses the policy of the `GatewayPorts` directive.
    ///
    /// The accepted spellings are `no`, `clientspecified` and `yes`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        match spec.trim() {
            "no" => Ok(Self::No),
            "clientspecified" => Ok(Self::ClientSpecified),
            "yes" => Ok(Self::Yes),
            other => Err(format!(
                "invalid GatewayPorts policy {other:?}: want no, clientspecified or yes"
            )),
        }
    }

    /// Returns the canonical spelling of the policy.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::ClientSpecified => "clientspecified",
            Self::Yes => "yes",
        }
    }
}

impl fmt::Display for GatewayPortsPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The path isolation mode of the SFTP subsystem.
///
/// The modes follow the `sshd` model of the Go implementation
/// (`cmd/sftp_subsystem.go` of `nagual2/ssh3-go`):
///
/// * [`SftpJailMode::Chroot`] — the sshd model: the network-facing process
///   never opens a path of the user. A short-lived child is started for the
///   channel, it chroots into the home directory of the user and drops to
///   the uid/gid of the user before the first path is opened. The confinement
///   is the kernel's: after the chroot neither an absolute symlink nor a
///   `..` reaches outside of the jail.
/// * [`SftpJailMode::Lexical`] — the historical in-process jail: the client
///   paths are mapped onto the home directory of the user and the result is
///   checked against the jail, symlinks included. The privileges of the
///   server process apply, so the mode only makes sense for a server that
///   holds no privileges worth abusing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SftpJailMode {
    /// The sshd model: a per-session child chroots into the home directory.
    #[default]
    Chroot,
    /// The in-process jail: the paths are checked in the server process.
    Lexical,
}

impl SftpJailMode {
    /// Parses the spelling of the jail mode.
    ///
    /// The accepted spellings are `chroot` and `lexical`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        match spec.trim() {
            "chroot" => Ok(Self::Chroot),
            "lexical" => Ok(Self::Lexical),
            other => Err(format!(
                "invalid sftp jail mode {other:?}: want chroot or lexical"
            )),
        }
    }

    /// Returns the canonical spelling of the jail mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chroot => "chroot",
            Self::Lexical => "lexical",
        }
    }

    /// Returns the jail mode the server can actually run.
    ///
    /// The chroot jail needs the privileges of the operating system, so it
    /// only exists on Unix. On the other platforms the lexical jail is used
    /// instead: a Windows server has no chroot at all.
    pub fn effective(self) -> Self {
        if cfg!(unix) { self } else { Self::Lexical }
    }
}

impl fmt::Display for SftpJailMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything that describes how an SSH3 server behaves.
///
/// The struct is cheap to clone: it is cloned per accepted connection, so all
/// fields must stay `Clone` and cheap to duplicate.
#[derive(Clone)]
pub struct Ssh3ServerConfig {
    /// Address the QUIC endpoint binds to.
    pub bind_addr: SocketAddr,
    /// Subject alternative names put into the generated self-signed certificate.
    pub cert_subject_alt_names: Vec<String>,
    /// Value of the `server` header sent in the CONNECT response.
    pub server_header: String,
    /// Maximum payload size negotiated for channels, in bytes.
    pub max_packet_size: u64,
    /// Capacity of the per-channel datagram queue used when none is requested.
    pub default_datagrams_queue_size: usize,
    /// When `true`, a request without valid credentials is rejected.
    pub require_authentication: bool,
    /// When `true`, `Authorization: Basic` requests are accepted.
    pub enable_password_login: bool,
    /// Files with authorized identities (SSH public keys or OIDC entries).
    ///
    /// When empty, the per-user defaults are used
    /// (`~/.ssh3/authorized_identities` and `~/.ssh/authorized_keys`).
    pub authorized_identity_paths: Vec<PathBuf>,
    /// User sessions run as when the client does not request one.
    pub default_user: Option<String>,
    /// Shell used for interactive sessions; falls back to the user's login shell.
    pub shell: Option<String>,
    /// Custom password verifier; `None` selects the platform default.
    pub password_verifier: Option<Ssh3PasswordVerifier>,
    /// Secret URL path the server accepts its CONNECT requests on.
    ///
    /// Any other path is answered with `404 Not Found`, the sshd `PidFile`
    /// style secret path of the SSH3 canon.
    pub url_path: String,
    /// Policy that bounds the server-side dials of forwarded channels.
    ///
    /// `None` keeps the historical unrestricted behavior.
    pub permit_open: Option<ForwardPolicy>,
    /// Policy that bounds the server-side binds of reverse-forward listeners.
    ///
    /// `None` keeps the historical unrestricted behavior.
    pub permit_listen: Option<ForwardPolicy>,
    /// The `GatewayPorts` policy of the reverse forwards.
    ///
    /// The default forces every client-requested bind back to the loopback.
    pub gateway_ports: GatewayPortsPolicy,
    /// Maximum number of active reverse-forward listeners one user may hold.
    ///
    /// The listeners of a user are counted across their conversations; a
    /// request over the cap is refused with a readable reason.
    pub max_reverse_forwards_per_user: usize,
    /// Maximum number of conversations that may wait for their authentication.
    ///
    /// A conversation over the cap is refused with `503 Service Unavailable`
    /// before any identity work happens; this is the `MaxStartups` analog.
    pub max_unauthenticated_conversations: usize,
    /// Number of failed password attempts that locks an account out.
    pub max_password_failures: u32,
    /// How long an account stays locked out after too many failed attempts.
    pub password_lockout: Duration,
    /// Idle timeout of an established QUIC connection.
    pub max_idle_timeout: Duration,
    /// How long the server waits for a connection to complete its handshake.
    pub handshake_idle_timeout: Duration,
    /// Shared state of the authentication-phase DoS guards.
    ///
    /// The guard is shared by all connections of a server; cloning the
    /// configuration keeps sharing it.
    pub auth_guard: Arc<Ssh3AuthGuard>,
    /// The path isolation mode of the SFTP subsystem.
    ///
    /// The default is the sshd model: a per-session child chroots into the
    /// home directory of the user and drops to its uid/gid.
    pub sftp_jail: SftpJailMode,
    /// Maximum number of concurrent SFTP sessions one user may hold.
    ///
    /// The sessions of a user are counted across their conversations; a
    /// request over the cap is refused with a readable reason. `0` disables
    /// the budget.
    pub max_sftp_sessions_per_user: usize,
    /// The directory the SFTP subsystem is jailed into.
    ///
    /// `None` jails the subsystem into the home directory of the session
    /// user, the `ChrootDirectory` analog of the `sshd_config`.
    pub sftp_root: Option<PathBuf>,
    /// The number of the concurrent SFTP sessions of every user.
    ///
    /// The budget is shared by the conversations of the server: the sessions
    /// of a user are counted across them.
    pub sftp_budget: Arc<SftpSessionBudget>,
}

impl fmt::Debug for Ssh3ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("bind_addr", &self.bind_addr)
            .field("cert_subject_alt_names", &self.cert_subject_alt_names)
            .field("server_header", &self.server_header)
            .field("max_packet_size", &self.max_packet_size)
            .field(
                "default_datagrams_queue_size",
                &self.default_datagrams_queue_size,
            )
            .field("require_authentication", &self.require_authentication)
            .field("enable_password_login", &self.enable_password_login)
            .field("authorized_identity_paths", &self.authorized_identity_paths)
            .field("default_user", &self.default_user)
            .field("shell", &self.shell)
            .field(
                "password_verifier",
                &self.password_verifier.as_ref().map(|_| "<custom>"),
            )
            .field("url_path", &self.url_path)
            .field("permit_open", &self.permit_open)
            .field("permit_listen", &self.permit_listen)
            .field("gateway_ports", &self.gateway_ports)
            .field(
                "max_reverse_forwards_per_user",
                &self.max_reverse_forwards_per_user,
            )
            .field(
                "max_unauthenticated_conversations",
                &self.max_unauthenticated_conversations,
            )
            .field("max_password_failures", &self.max_password_failures)
            .field("password_lockout", &self.password_lockout)
            .field("max_idle_timeout", &self.max_idle_timeout)
            .field("handshake_idle_timeout", &self.handshake_idle_timeout)
            .field("auth_guard", &self.auth_guard)
            .field("sftp_jail", &self.sftp_jail)
            .field(
                "max_sftp_sessions_per_user",
                &self.max_sftp_sessions_per_user,
            )
            .field("sftp_root", &self.sftp_root)
            .field("sftp_budget", &self.sftp_budget)
            .finish()
    }
}

impl Default for Ssh3ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4433)),
            cert_subject_alt_names: vec!["localhost".to_string()],
            server_header: SSH3_VERSION_STRING.to_string(),
            max_packet_size: 30_000,
            default_datagrams_queue_size: 10,
            require_authentication: false,
            enable_password_login: false,
            authorized_identity_paths: Vec::new(),
            default_user: current_username(),
            shell: env::var("SHELL").ok().filter(|shell| !shell.is_empty()),
            password_verifier: None,
            url_path: DEFAULT_URL_PATH.to_string(),
            permit_open: None,
            permit_listen: None,
            gateway_ports: GatewayPortsPolicy::default(),
            max_reverse_forwards_per_user: DEFAULT_MAX_REVERSE_FORWARDS_PER_USER,
            max_unauthenticated_conversations: DEFAULT_MAX_UNAUTHENTICATED_CONVERSATIONS,
            max_password_failures: DEFAULT_MAX_PASSWORD_FAILURES,
            password_lockout: DEFAULT_PASSWORD_LOCKOUT,
            max_idle_timeout: DEFAULT_MAX_IDLE_TIMEOUT,
            handshake_idle_timeout: DEFAULT_HANDSHAKE_IDLE_TIMEOUT,
            auth_guard: Arc::new(Ssh3AuthGuard::default()),
            sftp_jail: SftpJailMode::default(),
            max_sftp_sessions_per_user: DEFAULT_MAX_SFTP_SESSIONS_PER_USER,
            sftp_root: None,
            sftp_budget: Arc::new(SftpSessionBudget::new()),
        }
    }
}

/// The secret URL path the server listens on by default.
pub const DEFAULT_URL_PATH: &str = "/ssh3-term";

/// The default cap of conversations that may wait for their authentication.
pub const DEFAULT_MAX_UNAUTHENTICATED_CONVERSATIONS: usize = 100;

/// The default number of failed password attempts that locks an account out.
pub const DEFAULT_MAX_PASSWORD_FAILURES: u32 = 10;

/// The default lockout duration of a brute-forced account.
pub const DEFAULT_PASSWORD_LOCKOUT: Duration = Duration::from_secs(60);

/// The default idle timeout of an established connection (the ssh2 canon).
pub const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// The default handshake timeout of a connection (the ssh2 `LoginGraceTime` scale).
pub const DEFAULT_HANDSHAKE_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// The default number of active reverse-forward listeners one user may hold.
pub const DEFAULT_MAX_REVERSE_FORWARDS_PER_USER: usize = 10;

/// The default number of concurrent SFTP sessions one user may hold.
///
/// The value is the default of the `-max-sftp-sessions-per-user` option of the
/// Go implementation; `0` disables the budget.
pub const DEFAULT_MAX_SFTP_SESSIONS_PER_USER: usize = 16;

/// Returns the name of the user the server process runs as.
///
/// On Unix the passwd database is consulted, elsewhere the `USER`/`USERNAME`
/// environment variables are used.
pub(crate) fn current_username() -> Option<String> {
    #[cfg(unix)]
    {
        nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .ok()
            .flatten()
            .map(|user| user.name)
    }

    #[cfg(not(unix))]
    {
        env::var("USER").ok().or_else(|| env::var("USERNAME").ok())
    }
}

/// Rejects configurations that cannot work on the current platform.
///
/// Currently the only unsupported combination is password login without a
/// password verifier on a platform that has no `crypt(3)`-based default.
pub(crate) fn validate_server_config(config: &Ssh3ServerConfig) -> Result<(), Ssh3ServerError> {
    if config.enable_password_login && !password_auth_available(config) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "password authentication is not supported on this platform",
        )
        .into());
    }
    Ok(())
}

/// Parses a duration in the Go `time.ParseDuration` syntax.
///
/// The syntax is a sequence of decimal numbers with an optional fraction,
/// each followed by a unit suffix: `ns`, `us` (`µs`), `ms`, `s`, `m` or `h`,
/// for example `2m`, `1h30m` or `250ms`. A bare number is read as seconds,
/// which keeps the Go implementation's second-based environment variables
/// (`SSH3_MAX_IDLE_TIMEOUT=86400`) working unchanged.
pub fn parse_duration(spec: &str) -> Result<Duration, String> {
    let text = spec.trim();
    if text.is_empty() {
        return Err("the duration is empty".to_string());
    }
    if text == "0" {
        return Ok(Duration::ZERO);
    }
    if let Ok(seconds) = text.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }

    let mut total = Duration::ZERO;
    let mut rest = text;
    while !rest.is_empty() {
        let digits_end = rest
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(rest.len());
        if digits_end == 0 {
            return Err(format!("invalid duration {spec:?}: expected a number"));
        }
        let (number, tail) = rest.split_at(digits_end);
        let (integer_part, fraction_part) = match number.split_once('.') {
            Some((integer_part, fraction_part)) => (integer_part, fraction_part),
            None => (number, ""),
        };
        if integer_part.is_empty() && fraction_part.is_empty() {
            return Err(format!("invalid duration {spec:?}: expected a number"));
        }
        if !fraction_part
            .chars()
            .all(|character| character.is_ascii_digit())
        {
            return Err(format!("invalid duration {spec:?}: bad number {number:?}"));
        }

        let unit_end = tail
            .find(|character: char| character.is_ascii_digit() || character == '.')
            .unwrap_or(tail.len());
        let (unit, tail) = tail.split_at(unit_end);
        let unit_nanos: u64 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 3_600 * 1_000_000_000,
            "" => return Err(format!("invalid duration {spec:?}: missing unit")),
            other => {
                return Err(format!("invalid duration {spec:?}: unknown unit {other:?}"));
            }
        };

        let integer: u128 = integer_part
            .parse::<u128>()
            .map_err(|_| format!("invalid duration {spec:?}: bad number {number:?}"))?;
        let mut nanos = integer
            .checked_mul(unit_nanos as u128)
            .ok_or_else(|| format!("invalid duration {spec:?}: the value is too large"))?;

        if !fraction_part.is_empty() {
            let digits: u128 = fraction_part
                .parse::<u128>()
                .map_err(|_| format!("invalid duration {spec:?}: bad number {number:?}"))?;
            let scale = 10u128.pow(fraction_part.len() as u32);
            let fraction_nanos = digits
                .checked_mul(unit_nanos as u128)
                .ok_or_else(|| format!("invalid duration {spec:?}: the value is too large"))?
                / scale;
            nanos += fraction_nanos;
        }

        let nanos = u64::try_from(nanos)
            .map_err(|_| format!("invalid duration {spec:?}: the value is too large"))?;
        total = total
            .checked_add(Duration::from_nanos(nanos))
            .ok_or_else(|| format!("invalid duration {spec:?}: the value is too large"))?;
        rest = tail;
    }

    Ok(total)
}
