use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, ValueHint, error::ErrorKind};
use ssh3_server::{
    ForwardPolicy, GatewayPortsPolicy, InternalSftpOptions, SftpJailMode, Ssh3ServerConfig,
    parse_duration, run_internal_sftp_server, run_with_self_signed,
};

/// The environment variables the server options can be set with.
const ENV_PERMIT_OPEN: &str = "SSH3_PERMIT_OPEN";
const ENV_PERMIT_LISTEN: &str = "SSH3_PERMIT_LISTEN";
const ENV_GATEWAY_PORTS: &str = "SSH3_GATEWAY_PORTS";
const ENV_MAX_REVERSE_FORWARDS: &str = "SSH3_MAX_REVERSE_FORWARDS";
const ENV_URL_PATH: &str = "SSH3_URL_PATH";
const ENV_HANDSHAKE_IDLE_TIMEOUT: &str = "SSH3_HANDSHAKE_IDLE_TIMEOUT";
const ENV_MAX_IDLE_TIMEOUT: &str = "SSH3_MAX_IDLE_TIMEOUT";
const ENV_MAX_UNAUTH_CONVERSATIONS: &str = "SSH3_MAX_UNAUTH_CONVERSATIONS";
const ENV_MAX_CONNECTIONS: &str = "SSH3_MAX_CONNECTIONS";
const ENV_MAX_CHANNELS_PER_CONVERSATION: &str = "SSH3_MAX_CHANNELS_PER_CONVERSATION";
const ENV_MAX_INCOMING_STREAMS: &str = "SSH3_MAX_INCOMING_STREAMS";
const ENV_MAX_INCOMING_UNI_STREAMS: &str = "SSH3_MAX_INCOMING_UNI_STREAMS";
const ENV_MAX_PASSWORD_FAILURES: &str = "SSH3_MAX_PASSWORD_FAILURES";
const ENV_PASSWORD_LOCKOUT: &str = "SSH3_PASSWORD_LOCKOUT_SECONDS";
const ENV_PASSWORD_LOCKOUT_ALIAS: &str = "SSH3_MAX_PASSWORD_FAILOUT_SECONDS";
const ENV_ENABLE_PASSWORD_LOGIN: &str = "SSH3_ENABLE_PASSWORD_LOGIN";
const ENV_SFTP_JAIL: &str = "SSH3_SFTP_JAIL";
const ENV_MAX_SFTP_SESSIONS: &str = "SSH3_MAX_SFTP_SESSIONS_PER_USER";

#[derive(Debug, Parser)]
#[command(
    name = "ssh3-rust-server",
    version,
    about = "Starts a minimal Rust SSH3 server with a self-signed certificate."
)]
struct Cli {
    #[arg(long, value_name = "ADDR")]
    bind: Option<SocketAddr>,

    #[arg(long, value_name = "NAME", action = clap::ArgAction::Append)]
    hostname: Vec<String>,

    #[arg(long = "server-header", value_name = "TEXT")]
    server_header: Option<String>,

    #[arg(long)]
    require_auth: bool,

    #[arg(long)]
    enable_password_login: bool,

    #[arg(
        long = "authorized-identity",
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        action = clap::ArgAction::Append
    )]
    authorized_identity: Vec<PathBuf>,

    #[arg(long, value_name = "NAME")]
    user: Option<String>,

    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    shell: Option<String>,

    /// Comma/space-separated `host:port` targets the server may forward to.
    ///
    /// `*` wildcards the host and `!` negates an entry; an empty value keeps
    /// the forwarding unrestricted.
    #[arg(long = "permit-open", value_name = "SPEC")]
    permit_open: Option<String>,

    /// Comma/space-separated `host:port` binds the server may listen on.
    ///
    /// `*` wildcards the host and `!` negates an entry; an empty value keeps
    /// the reverse-forward listeners unrestricted.
    #[arg(long = "permit-listen", value_name = "SPEC")]
    permit_listen: Option<String>,

    /// The `GatewayPorts` policy of the reverse forwards.
    ///
    /// `no` (the default) forces every client-requested bind back to the
    /// loopback, `clientspecified` honors the requested address and `yes`
    /// binds the wildcard address.
    #[arg(long = "gateway-ports", value_name = "POLICY")]
    gateway_ports: Option<String>,

    /// Maximum number of active reverse-forward listeners one user may hold.
    #[arg(long = "max-reverse-forwards", value_name = "COUNT")]
    max_reverse_forwards: Option<usize>,

    /// The secret URL path the server accepts its CONNECT requests on.
    #[arg(long = "url-path", value_name = "PATH")]
    url_path: Option<String>,

    /// How long the server waits for a connection to complete its handshake.
    #[arg(
        long = "handshake-idle-timeout",
        value_name = "DURATION",
        value_parser = parse_duration,
    )]
    handshake_idle_timeout: Option<Duration>,

    /// The idle timeout of an established connection.
    #[arg(
        long = "max-idle-timeout",
        value_name = "DURATION",
        value_parser = parse_duration,
    )]
    max_idle_timeout: Option<Duration>,

    /// Maximum number of conversations that may wait for their authentication.
    #[arg(long = "max-unauth-conversations", value_name = "COUNT")]
    max_unauthenticated_conversations: Option<usize>,

    /// Maximum number of concurrent QUIC connections; `0` disables the cap.
    #[arg(long = "max-connections", value_name = "COUNT")]
    max_connections: Option<usize>,

    /// Maximum number of concurrently open channels per conversation; `0`
    /// disables the budget.
    #[arg(long = "max-channels-per-conversation", value_name = "COUNT")]
    max_channels_per_conversation: Option<usize>,

    /// Maximum number of concurrent peer-initiated bidirectional QUIC streams
    /// per connection.
    #[arg(long = "max-incoming-streams", value_name = "COUNT")]
    max_incoming_streams: Option<u32>,

    /// Maximum number of concurrent peer-initiated unidirectional QUIC streams
    /// per connection.
    #[arg(long = "max-incoming-uni-streams", value_name = "COUNT")]
    max_incoming_uni_streams: Option<u32>,

    /// Number of failed password attempts that locks an account out.
    #[arg(long = "max-password-failures", value_name = "COUNT")]
    max_password_failures: Option<u32>,

    /// How long an account stays locked out after too many failed attempts.
    #[arg(
        long = "password-lockout",
        value_name = "DURATION",
        value_parser = parse_duration,
    )]
    password_lockout: Option<Duration>,

    /// The path isolation mode of the SFTP subsystem.
    ///
    /// `chroot` (the default) is the sshd model: a per-session child chroots
    /// into the home directory of the user and drops to its uid/gid, so the
    /// network-facing process never opens a path of the user. `lexical` is
    /// the in-process jail: the paths are checked in the server process.
    #[arg(long = "sftp-jail", value_name = "MODE")]
    sftp_jail: Option<String>,

    /// Maximum number of concurrent SFTP sessions one user may hold.
    ///
    /// `0` disables the budget.
    #[arg(long = "max-sftp-sessions-per-user", value_name = "COUNT")]
    max_sftp_sessions_per_user: Option<usize>,

    /// Internal: run the SFTP child server on stdin/stdout.
    ///
    /// The option is set by the server itself, when it starts the child of
    /// the chroot jail; it is not meant for direct use.
    #[arg(long = "sftp-server-internal", hide = true)]
    sftp_server_internal: bool,

    /// Internal: the directory the SFTP child chroots into.
    #[arg(long = "sftp-chroot", value_name = "DIR", hide = true)]
    sftp_chroot: Option<PathBuf>,

    /// Internal: the root the SFTP child serves when it runs without a chroot.
    #[arg(long = "sftp-root", value_name = "DIR", hide = true)]
    sftp_root: Option<PathBuf>,

    /// Internal: the uid the SFTP child drops to.
    #[arg(long = "sftp-uid", value_name = "UID", hide = true)]
    sftp_uid: Option<u32>,

    /// Internal: the gid the SFTP child drops to.
    #[arg(long = "sftp-gid", value_name = "GID", hide = true)]
    sftp_gid: Option<u32>,
}

/// The long options that are also accepted with a single dash.
///
/// The Go implementation of the server uses the single-dash spelling of the
/// `flag` package; the Rust server accepts it as well, so an operator can
/// move a Go command line over unchanged.
const GO_STYLE_OPTIONS: &[&str] = &[
    "permit-open",
    "permit-listen",
    "gateway-ports",
    "max-reverse-forwards",
    "url-path",
    "handshake-idle-timeout",
    "max-idle-timeout",
    "max-unauth-conversations",
    "max-connections",
    "max-channels-per-conversation",
    "max-incoming-streams",
    "max-incoming-uni-streams",
    "max-password-failures",
    "password-lockout",
    "sftp-jail",
    "max-sftp-sessions-per-user",
];

/// Rewrites the Go-style single-dash options into their clap spelling.
fn normalize_go_style_args<I, T>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    args.into_iter()
        .map(Into::into)
        .map(|argument| {
            let Some(rest) = argument.strip_prefix('-') else {
                return argument;
            };
            if rest.starts_with('-') {
                return argument;
            }
            let name = rest.split_once('=').map(|(name, _)| name).unwrap_or(rest);
            if GO_STYLE_OPTIONS.contains(&name) {
                format!("--{}", &argument[1..])
            } else {
                argument
            }
        })
        .collect()
}

/// Reads an environment variable, ignoring an empty value.
fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Reads a duration from the environment, ignoring an unparsable value.
fn env_duration(name: &str) -> Option<Duration> {
    let value = env_value(name)?;
    match parse_duration(&value) {
        Ok(duration) => Some(duration),
        Err(err) => {
            eprintln!("ssh3-rust-server ignoring {name}: {err}");
            None
        }
    }
}

/// Reads a number from the environment, ignoring an unparsable value.
fn env_number<T: std::str::FromStr>(name: &str) -> Option<T> {
    let value = env_value(name)?;
    match value.parse::<T>() {
        Ok(number) => Some(number),
        Err(_) => {
            eprintln!("ssh3-rust-server ignoring {name}: {value:?} is not a number");
            None
        }
    }
}

/// Builds the configuration of the server from the command line.
fn build_config(cli: Cli) -> Result<Ssh3ServerConfig, clap::Error> {
    let mut config = Ssh3ServerConfig::default();
    if let Some(bind_addr) = cli.bind {
        config.bind_addr = bind_addr;
    }
    if !cli.hostname.is_empty() {
        config.cert_subject_alt_names = cli.hostname;
    }
    if let Some(server_header) = cli.server_header {
        config.server_header = server_header;
    }
    config.require_authentication = cli.require_auth;
    config.enable_password_login = cli.enable_password_login
        || env_value(ENV_ENABLE_PASSWORD_LOGIN).is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        });
    if !cli.authorized_identity.is_empty() {
        config.authorized_identity_paths = cli.authorized_identity;
    }
    if let Some(user) = cli.user {
        config.default_user = Some(user);
    }
    if let Some(shell) = cli.shell {
        config.shell = Some(shell);
    }

    let permit_open = match cli.permit_open {
        Some(spec) => Some(spec),
        None => env_value(ENV_PERMIT_OPEN),
    };
    if let Some(spec) = permit_open {
        config.permit_open = match ForwardPolicy::parse(&spec) {
            Ok(policy) => policy,
            Err(err) => {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ValueValidation,
                    err,
                ));
            }
        };
    }

    let permit_listen = match cli.permit_listen {
        Some(spec) => Some(spec),
        None => env_value(ENV_PERMIT_LISTEN),
    };
    if let Some(spec) = permit_listen {
        config.permit_listen = match ForwardPolicy::parse(&spec) {
            Ok(policy) => policy,
            Err(err) => {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ValueValidation,
                    err,
                ));
            }
        };
    }

    if let Some(url_path) = cli.url_path.or_else(|| env_value(ENV_URL_PATH)) {
        config.url_path = url_path;
    }

    if let Some(policy) = cli.gateway_ports.or_else(|| env_value(ENV_GATEWAY_PORTS)) {
        config.gateway_ports = match GatewayPortsPolicy::parse(&policy) {
            Ok(policy) => policy,
            Err(err) => {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ValueValidation,
                    err,
                ));
            }
        };
    }

    if let Some(max) = cli
        .max_reverse_forwards
        .or_else(|| env_number(ENV_MAX_REVERSE_FORWARDS))
    {
        config.max_reverse_forwards_per_user = max;
    }

    if let Some(timeout) = cli
        .handshake_idle_timeout
        .or_else(|| env_duration(ENV_HANDSHAKE_IDLE_TIMEOUT))
    {
        config.handshake_idle_timeout = timeout;
    }

    if let Some(timeout) = cli
        .max_idle_timeout
        .or_else(|| env_duration(ENV_MAX_IDLE_TIMEOUT))
    {
        config.max_idle_timeout = timeout;
    }

    if let Some(max) = cli
        .max_unauthenticated_conversations
        .or_else(|| env_number(ENV_MAX_UNAUTH_CONVERSATIONS))
    {
        config.max_unauthenticated_conversations = max;
    }

    if let Some(max) = cli
        .max_connections
        .or_else(|| env_number(ENV_MAX_CONNECTIONS))
    {
        config.max_connections = max;
    }

    if let Some(max) = cli
        .max_channels_per_conversation
        .or_else(|| env_number(ENV_MAX_CHANNELS_PER_CONVERSATION))
    {
        config.max_channels_per_conversation = max;
    }

    if let Some(max) = cli
        .max_incoming_streams
        .or_else(|| env_number(ENV_MAX_INCOMING_STREAMS))
    {
        config.max_incoming_streams = max;
    }

    if let Some(max) = cli
        .max_incoming_uni_streams
        .or_else(|| env_number(ENV_MAX_INCOMING_UNI_STREAMS))
    {
        config.max_incoming_uni_streams = max;
    }

    if let Some(max) = cli
        .max_password_failures
        .or_else(|| env_number(ENV_MAX_PASSWORD_FAILURES))
    {
        config.max_password_failures = max;
    }

    if let Some(lockout) = cli.password_lockout.or_else(|| {
        env_duration(ENV_PASSWORD_LOCKOUT).or_else(|| env_duration(ENV_PASSWORD_LOCKOUT_ALIAS))
    }) {
        config.password_lockout = lockout;
    }

    if let Some(mode) = cli.sftp_jail.clone().or_else(|| env_value(ENV_SFTP_JAIL)) {
        config.sftp_jail = match SftpJailMode::parse(&mode) {
            Ok(mode) => mode,
            Err(err) => {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ValueValidation,
                    err,
                ));
            }
        };
    }
    if config.sftp_jail.effective() != config.sftp_jail {
        eprintln!(
            "ssh3-rust-server the {} jail of the sftp subsystem needs a unix platform, using the {} jail",
            config.sftp_jail,
            config.sftp_jail.effective()
        );
    }

    if let Some(max) = cli
        .max_sftp_sessions_per_user
        .or_else(|| env_number(ENV_MAX_SFTP_SESSIONS))
    {
        config.max_sftp_sessions_per_user = max;
    }

    Ok(config)
}

/// Runs the internal SFTP child of the chroot jail.
async fn run_internal_child(cli: &Cli) -> ExitCode {
    let options = InternalSftpOptions {
        chroot_dir: cli.sftp_chroot.clone(),
        root_dir: cli.sftp_root.clone(),
        uid: cli.sftp_uid,
        gid: cli.sftp_gid,
    };
    match run_internal_sftp_server(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ssh3-rust-server the internal sftp server failed: {err}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse_from(normalize_go_style_args(std::env::args())) {
        Ok(cli) => cli,
        Err(err) => {
            let status = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            };
            err.print().ok();
            return status;
        }
    };

    // the internal child of the chroot jail: it serves the protocol over its
    // standard streams and never listens on a socket
    if cli.sftp_server_internal {
        return run_internal_child(&cli).await;
    }

    let config = match build_config(cli) {
        Ok(config) => config,
        Err(err) => {
            let status = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            };
            err.print().ok();
            return status;
        }
    };

    match run_with_self_signed(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ssh3-rust-server failed: {err}");
            ExitCode::FAILURE
        }
    }
}
