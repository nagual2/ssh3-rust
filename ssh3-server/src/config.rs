//! Server configuration: [`Ssh3ServerConfig`], its defaults and validation.

use std::env;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;

use ssh3_h3::SSH3_VERSION_STRING;

use crate::auth::password_auth_available;
use crate::error::Ssh3ServerError;

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
        }
    }
}

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
