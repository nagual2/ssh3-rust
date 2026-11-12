use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, ValueHint, error::ErrorKind};
use ssh3_server::{
    ForwardPolicy, GatewayPortsPolicy, InternalSftpOptions, LogLevel, SftpJailMode,
    Ssh3ServerConfig, log_error, log_warn, logging, parse_duration, run_internal_sftp_server,
    run_with_certificates, run_with_self_signed, shutdown_drain_period,
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
const ENV_SHUTDOWN_DRAIN: &str = "SSH3_SHUTDOWN_DRAIN";
const ENV_LOG_LEVEL: &str = "SSH3_LOG_LEVEL";
const ENV_LOG_FILE: &str = "SSH3_LOG_FILE";

#[derive(Debug, Parser)]
#[command(
    name = "ssh3-rust-server",
    version,
    disable_help_flag = true,
    about = "Starts a minimal Rust SSH3 server with a self-signed certificate."
)]
struct Cli {
    #[arg(long, value_name = "ADDR")]
    bind: Option<SocketAddr>,

    #[arg(long, value_name = "NAME", action = clap::ArgAction::Append)]
    hostname: Vec<String>,

    /// The certificate chain (or fullchain) the server serves, the `-cert`
    /// of the reference.
    ///
    /// The flag rides with its private key: `-key` is mandatory with it, and
    /// a server started with the pair skips the self-signed generation.
    #[arg(
        long = "cert",
        value_name = "FILE",
        value_hint = ValueHint::FilePath
    )]
    cert: Option<PathBuf>,

    /// The private key of the `-cert` certificate.
    #[arg(
        long = "key",
        value_name = "FILE",
        value_hint = ValueHint::FilePath
    )]
    key: Option<PathBuf>,

    /// The sshd-shaped alias of `-cert` (`sshd -c`).
    #[arg(short = 'c', value_name = "FILE", value_hint = ValueHint::FilePath)]
    cert_alias: Option<PathBuf>,

    /// The sshd-shaped alias of `-key` (`sshd -h`).
    ///
    /// The alias takes over the `-h` short flag, like in the reference where
    /// `-h` is the host key; the usage rides the long `--help`.
    #[arg(short = 'h', value_name = "FILE", value_hint = ValueHint::FilePath)]
    key_alias: Option<PathBuf>,

    /// Prints the usage.
    ///
    /// The help is long-only: the `-h` short flag belongs to the host key,
    /// the sshd shape of the reference.
    #[arg(long, action = clap::ArgAction::Help)]
    help: (),

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

    /// Initial QUIC packet size in bytes; the transport floors the value at
    /// the QUIC minimum of 1200, like in the reference.
    #[arg(long = "initial-packet-size", value_name = "BYTES")]
    initial_packet_size: Option<u16>,

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
    "cert",
    "key",
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

/// Applies the sshd(8)-shaped `-c`/`-h` aliases to the `-cert`/`-key` values,
/// the way the reference does (`cmd/ssh2_parity.go:206-220`): the alias wins
/// when only it is given, and giving both forms of the same knob is an error
/// instead of a silent last-one-wins.
fn resolve_server_cert_key_aliases(
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    cert_alias: Option<PathBuf>,
    key_alias: Option<PathBuf>,
) -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
    if cert.is_some() && cert_alias.is_some() {
        return Err("-c and -cert are mutually exclusive".to_string());
    }
    if key.is_some() && key_alias.is_some() {
        return Err("-h and -key are mutually exclusive".to_string());
    }
    Ok((cert.or(cert_alias), key.or(key_alias)))
}

/// Resolves the TLS identity of the server from the command line flags.
///
/// `Some` carries the `-cert`/`-key` pair the server serves instead of the
/// generated self-signed certificate; `None` keeps the self-signed default.
/// A lone half of the pair is refused: the certificate and its private key
/// are configured together, the half-configured pair of the reference is a
/// startup failure (`cmd/ssh3-server.go:1185-1200`).
fn resolve_server_identity(cli: &Cli) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let (cert, key) = resolve_server_cert_key_aliases(
        cli.cert.clone(),
        cli.key.clone(),
        cli.cert_alias.clone(),
        cli.key_alias.clone(),
    )?;
    match (cert, key) {
        (Some(cert), Some(key)) => Ok(Some((cert, key))),
        (Some(_), None) => Err(
            "-cert requires -key: the certificate and its private key are configured as a pair"
                .to_string(),
        ),
        (None, Some(_)) => Err(
            "-key requires -cert: the certificate and its private key are configured as a pair"
                .to_string(),
        ),
        (None, None) => Ok(None),
    }
}

/// The source of the environment the configuration reads: the process
/// environment of the server in production, an injected map in the tests.
trait EnvLookup {
    fn lookup(&self, name: &str) -> Option<String>;
}

/// The process environment the server runs with.
struct ProcessEnv;

impl EnvLookup for ProcessEnv {
    fn lookup(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Reads an environment variable, ignoring an empty value.
fn env_value(env: &impl EnvLookup, name: &str) -> Option<String> {
    env.lookup(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Reads a duration from the environment, ignoring an unparsable value.
fn env_duration(env: &impl EnvLookup, name: &str) -> Option<Duration> {
    let value = env_value(env, name)?;
    match parse_duration(&value) {
        Ok(duration) => Some(duration),
        Err(err) => {
            log_warn!("ssh3-rust-server ignoring {name}: {err}");
            None
        }
    }
}

/// Reads a number from the environment, ignoring an unparsable value.
fn env_number<T: std::str::FromStr>(env: &impl EnvLookup, name: &str) -> Option<T> {
    let value = env_value(env, name)?;
    match value.parse::<T>() {
        Ok(number) => Some(number),
        Err(_) => {
            log_warn!("ssh3-rust-server ignoring {name}: {value:?} is not a number");
            None
        }
    }
}

/// Builds the configuration of the server from the command line.
fn build_config(cli: Cli) -> Result<Ssh3ServerConfig, clap::Error> {
    build_config_with_env(cli, &ProcessEnv)
}

/// Builds the configuration of the server from the command line and the
/// given environment source.
///
/// The environment variables are the `SSH3_*` policy knobs of the Go
/// reference (`cmd/ssh3-server.go:993-1083`): every one of them has a
/// command-line counterpart, and the command line wins over the environment.
fn build_config_with_env(cli: Cli, env: &impl EnvLookup) -> Result<Ssh3ServerConfig, clap::Error> {
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
        || env_value(env, ENV_ENABLE_PASSWORD_LOGIN).is_some_and(|value| {
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
        None => env_value(env, ENV_PERMIT_OPEN),
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
        None => env_value(env, ENV_PERMIT_LISTEN),
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

    if let Some(url_path) = cli.url_path.or_else(|| env_value(env, ENV_URL_PATH)) {
        config.url_path = url_path;
    }

    if let Some(policy) = cli
        .gateway_ports
        .or_else(|| env_value(env, ENV_GATEWAY_PORTS))
    {
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
        .or_else(|| env_number(env, ENV_MAX_REVERSE_FORWARDS))
    {
        config.max_reverse_forwards_per_user = max;
    }

    if let Some(timeout) = cli
        .handshake_idle_timeout
        .or_else(|| env_duration(env, ENV_HANDSHAKE_IDLE_TIMEOUT))
    {
        config.handshake_idle_timeout = timeout;
    }

    if let Some(timeout) = cli
        .max_idle_timeout
        .or_else(|| env_duration(env, ENV_MAX_IDLE_TIMEOUT))
    {
        config.max_idle_timeout = timeout;
    }

    if let Some(max) = cli
        .max_unauthenticated_conversations
        .or_else(|| env_number(env, ENV_MAX_UNAUTH_CONVERSATIONS))
    {
        config.max_unauthenticated_conversations = max;
    }

    if let Some(max) = cli
        .max_connections
        .or_else(|| env_number(env, ENV_MAX_CONNECTIONS))
    {
        config.max_connections = max;
    }

    if let Some(max) = cli
        .max_channels_per_conversation
        .or_else(|| env_number(env, ENV_MAX_CHANNELS_PER_CONVERSATION))
    {
        config.max_channels_per_conversation = max;
    }

    if let Some(max) = cli
        .max_incoming_streams
        .or_else(|| env_number(env, ENV_MAX_INCOMING_STREAMS))
    {
        config.max_incoming_streams = max;
    }

    if let Some(max) = cli
        .max_incoming_uni_streams
        .or_else(|| env_number(env, ENV_MAX_INCOMING_UNI_STREAMS))
    {
        config.max_incoming_uni_streams = max;
    }

    if let Some(max) = cli
        .max_password_failures
        .or_else(|| env_number(env, ENV_MAX_PASSWORD_FAILURES))
    {
        config.max_password_failures = max;
    }

    if let Some(lockout) = cli.password_lockout.or_else(|| {
        env_duration(env, ENV_PASSWORD_LOCKOUT)
            .or_else(|| env_duration(env, ENV_PASSWORD_LOCKOUT_ALIAS))
    }) {
        config.password_lockout = lockout;
    }

    if let Some(mode) = cli
        .sftp_jail
        .clone()
        .or_else(|| env_value(env, ENV_SFTP_JAIL))
    {
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
        log_warn!(
            "ssh3-rust-server the {} jail of the sftp subsystem needs a unix platform, using the {} jail",
            config.sftp_jail,
            config.sftp_jail.effective()
        );
    }

    if let Some(max) = cli
        .max_sftp_sessions_per_user
        .or_else(|| env_number(env, ENV_MAX_SFTP_SESSIONS))
    {
        config.max_sftp_sessions_per_user = max;
    }

    // the initial QUIC packet size: the same flag and default as in the Go
    // reference (`cmd/ssh3-server.go`, `-initial-packet-size`)
    if let Some(size) = cli.initial_packet_size {
        config.initial_packet_size = size;
    }

    // the drain window of the graceful shutdown: a plain number of seconds,
    // parsed like the Go reference parses it (there is no command-line flag
    // for it, like there is none in the Go implementation)
    config.shutdown_drain = shutdown_drain_period(env.lookup(ENV_SHUTDOWN_DRAIN).as_deref());

    // the log of the daemon: the SSH3_LOG_LEVEL / SSH3_LOG_FILE pair of the
    // Go reference (`cmd/ssh3-server.go:1238-1251`); there is no command
    // line counterpart, like in the Go implementation
    if let Some(value) = env_value(env, ENV_LOG_LEVEL) {
        config.log_level = LogLevel::parse_default(&value);
    }
    if let Some(file) = env_value(env, ENV_LOG_FILE) {
        config.log_file = Some(PathBuf::from(file));
    }

    Ok(config)
}

/// Runs the internal SFTP child of the chroot jail.
async fn run_internal_child(cli: &Cli) -> ExitCode {
    // The child of the reference serves the protocol over its standard
    // streams with an error-only log (`cmd/internal_sftp.go:40`).
    logging::set_level(LogLevel::Error);
    let options = InternalSftpOptions {
        chroot_dir: cli.sftp_chroot.clone(),
        root_dir: cli.sftp_root.clone(),
        uid: cli.sftp_uid,
        gid: cli.sftp_gid,
    };
    match run_internal_sftp_server(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log_error!("ssh3-rust-server the internal sftp server failed: {err}");
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

    // the TLS identity of the server: the -cert/-key pair of the operator or
    // the generated self-signed certificate
    let identity = match resolve_server_identity(&cli) {
        Ok(identity) => identity,
        Err(message) => {
            eprintln!("ssh3-rust-server {message}");
            return ExitCode::FAILURE;
        }
    };

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

    // The log of the daemon: the level and the file of the reference
    // (`cmd/ssh3-server.go:1228-1258`), the standard error under systemd
    // and `/var/log/ssh3.log` otherwise. A file that cannot be opened ends
    // the run on the standard error, the way the reference exits.
    let under_systemd = std::env::var_os("INVOCATION_ID").is_some_and(|id| !id.is_empty());
    let log_path = logging::effective_log_path(config.log_file.as_deref(), under_systemd);
    if let Err(err) = logging::init(config.log_level, log_path.as_deref()) {
        if let Some(path) = &log_path {
            eprintln!(
                "ssh3-rust-server cannot open log file {}: {err}",
                path.display()
            );
        }
        return ExitCode::FAILURE;
    }

    // the -cert/-key pair of the operator goes over the serve_endpoint path
    // with the loaded identity; without the pair the server generates its
    // self-signed certificate, the L2 behavior
    let run = match identity {
        Some((cert, key)) => run_with_certificates(config, &cert, &key).await,
        None => run_with_self_signed(config).await,
    };
    match run {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log_error!("ssh3-rust-server failed: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;

    use clap::Parser;

    use super::{Cli, build_config_with_env};
    use ssh3_server::{GatewayPortsPolicy, SftpJailMode, Ssh3ServerConfig};

    /// The environment the tests inject: a map instead of the process
    /// environment, so the parallel tests never race on global state.
    struct FakeEnv(HashMap<String, String>);

    impl FakeEnv {
        /// Builds an environment from `name=value` pairs.
        fn from_pairs(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
            )
        }
    }

    impl super::EnvLookup for FakeEnv {
        fn lookup(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
    }

    /// Builds the configuration the given environment and command line
    /// produce, the way the binary puts them together.
    fn config_of(env: &FakeEnv, arguments: &[&str]) -> Ssh3ServerConfig {
        let cli = Cli::try_parse_from(arguments).unwrap();
        build_config_with_env(cli, env).unwrap()
    }

    /// Every policy variable of the reference configures the server without
    /// a single command line option: a systemd EnvironmentFile carries the
    /// whole policy (`packaging/ssh3-rust-server.env`).
    #[test]
    fn the_environment_configures_the_server_without_the_command_line() {
        let env = FakeEnv::from_pairs(&[
            ("SSH3_PERMIT_OPEN", "*.example.org:443"),
            ("SSH3_PERMIT_LISTEN", "127.0.0.1:*"),
            ("SSH3_GATEWAY_PORTS", "clientspecified"),
            ("SSH3_MAX_REVERSE_FORWARDS", "7"),
            ("SSH3_MAX_UNAUTH_CONVERSATIONS", "33"),
            ("SSH3_MAX_PASSWORD_FAILURES", "4"),
            ("SSH3_PASSWORD_LOCKOUT_SECONDS", "9"),
            ("SSH3_MAX_CONNECTIONS", "11"),
            ("SSH3_MAX_CHANNELS_PER_CONVERSATION", "12"),
            ("SSH3_MAX_INCOMING_STREAMS", "13"),
            ("SSH3_MAX_INCOMING_UNI_STREAMS", "14"),
            ("SSH3_MAX_SFTP_SESSIONS_PER_USER", "15"),
            ("SSH3_SFTP_JAIL", "lexical"),
            ("SSH3_URL_PATH", "/secret-term"),
            ("SSH3_HANDSHAKE_IDLE_TIMEOUT", "7"),
            ("SSH3_MAX_IDLE_TIMEOUT", "86400"),
            ("SSH3_SHUTDOWN_DRAIN", "42"),
        ]);
        let config = config_of(&env, &["ssh3-rust-server"]);
        assert_eq!(config.max_reverse_forwards_per_user, 7);
        assert_eq!(config.max_unauthenticated_conversations, 33);
        assert_eq!(config.max_password_failures, 4);
        assert_eq!(config.password_lockout, Duration::from_secs(9));
        assert_eq!(config.max_connections, 11);
        assert_eq!(config.max_channels_per_conversation, 12);
        assert_eq!(config.max_incoming_streams, 13);
        assert_eq!(config.max_incoming_uni_streams, 14);
        assert_eq!(config.max_sftp_sessions_per_user, 15);
        assert_eq!(config.sftp_jail, SftpJailMode::Lexical);
        assert_eq!(config.url_path, "/secret-term");
        assert_eq!(config.handshake_idle_timeout, Duration::from_secs(7));
        assert_eq!(config.max_idle_timeout, Duration::from_secs(86400));
        assert_eq!(config.shutdown_drain, Duration::from_secs(42));
        assert_eq!(config.gateway_ports, GatewayPortsPolicy::ClientSpecified);
        let permit_open = config
            .permit_open
            .expect("the env set a permit-open policy");
        assert!(permit_open.allows("srv.example.org", 443));
        assert!(!permit_open.allows("srv.example.org", 80));
        let permit_listen = config
            .permit_listen
            .expect("the env set a permit-listen policy");
        assert!(permit_listen.allows("127.0.0.1", 8080));
        assert!(!permit_listen.allows("192.0.2.1", 8080));
    }

    /// The password login of the I4 semantics: the environment only enables
    /// it, the default stays the safe side (off), and the garbage keeps the
    /// default like a failed `strconv.ParseBool` of the reference does.
    #[test]
    fn the_password_login_env_only_enables_the_login() {
        for affirmative in ["1", "true", "TRUE", "True", "yes", "on"] {
            let env = FakeEnv::from_pairs(&[("SSH3_ENABLE_PASSWORD_LOGIN", affirmative)]);
            assert!(
                config_of(&env, &["ssh3-rust-server"]).enable_password_login,
                "{affirmative} enables the password login"
            );
        }
        for negative in ["0", "false", "no", "off", "garbage", ""] {
            let env = FakeEnv::from_pairs(&[("SSH3_ENABLE_PASSWORD_LOGIN", negative)]);
            assert!(
                !config_of(&env, &["ssh3-rust-server"]).enable_password_login,
                "{negative} keeps the login off"
            );
        }
        // Without the variable the default stays off, the documented I4
        // divergence from the Go default on the safe side.
        let env = FakeEnv::from_pairs(&[]);
        assert!(!config_of(&env, &["ssh3-rust-server"]).enable_password_login);
    }

    /// The numeric variables fall back to the defaults on garbage, the way
    /// the `strconv.Atoi` of the reference keeps its default on a parse
    /// error (`cmd/ssh3-server.go:1004` and the other `SSH3_MAX_*` knobs).
    #[test]
    fn the_garbage_numbers_fall_back_to_the_defaults() {
        let env = FakeEnv::from_pairs(&[
            ("SSH3_MAX_REVERSE_FORWARDS", "many"),
            ("SSH3_MAX_UNAUTH_CONVERSATIONS", "1e3"),
            ("SSH3_MAX_PASSWORD_FAILURES", "-3"),
            ("SSH3_MAX_CONNECTIONS", "four"),
            ("SSH3_MAX_CHANNELS_PER_CONVERSATION", "0x10"),
            ("SSH3_MAX_INCOMING_STREAMS", "much"),
            ("SSH3_MAX_INCOMING_UNI_STREAMS", "more"),
            ("SSH3_MAX_SFTP_SESSIONS_PER_USER", "unbounded"),
        ]);
        let config = config_of(&env, &["ssh3-rust-server"]);
        assert_eq!(config.max_reverse_forwards_per_user, 10);
        assert_eq!(config.max_unauthenticated_conversations, 100);
        assert_eq!(config.max_password_failures, 10);
        assert_eq!(config.max_connections, 0);
        assert_eq!(config.max_channels_per_conversation, 64);
        assert_eq!(config.max_incoming_streams, 100);
        assert_eq!(config.max_incoming_uni_streams, 100);
        assert_eq!(config.max_sftp_sessions_per_user, 16);
    }

    /// The command line wins over the environment, like in the reference.
    #[test]
    fn the_command_line_wins_over_the_environment() {
        let env = FakeEnv::from_pairs(&[
            ("SSH3_MAX_CONNECTIONS", "9"),
            ("SSH3_GATEWAY_PORTS", "clientspecified"),
        ]);
        let config = config_of(
            &env,
            &[
                "ssh3-rust-server",
                "--max-connections",
                "5",
                "--gateway-ports",
                "yes",
            ],
        );
        assert_eq!(config.max_connections, 5);
        assert_eq!(config.gateway_ports, GatewayPortsPolicy::Yes);
    }

    /// The policy values are validated like the reference validates them: a
    /// garbage policy refuses the configuration instead of being ignored.
    #[test]
    fn the_garbage_policy_values_refuse_the_configuration() {
        for (name, value) in [
            ("SSH3_GATEWAY_PORTS", "sometimes"),
            ("SSH3_SFTP_JAIL", "none"),
            ("SSH3_PERMIT_OPEN", "host-without-port"),
            ("SSH3_PERMIT_LISTEN", "*.example.org"),
        ] {
            let env = FakeEnv::from_pairs(&[(name, value)]);
            let cli = Cli::try_parse_from(["ssh3-rust-server"]).unwrap();
            assert!(
                build_config_with_env(cli, &env).is_err(),
                "{name}={value} refuses the configuration"
            );
        }
    }

    /// The duration variables read the second-based spellings of the
    /// reference; the unit suffixes ride along as a superset.
    #[test]
    fn the_duration_variables_read_the_reference_spellings() {
        let env = FakeEnv::from_pairs(&[
            ("SSH3_HANDSHAKE_IDLE_TIMEOUT", "7"),
            ("SSH3_MAX_IDLE_TIMEOUT", "2m"),
            ("SSH3_PASSWORD_LOCKOUT_SECONDS", "90"),
        ]);
        let config = config_of(&env, &["ssh3-rust-server"]);
        assert_eq!(config.handshake_idle_timeout, Duration::from_secs(7));
        assert_eq!(config.max_idle_timeout, Duration::from_secs(120));
        assert_eq!(config.password_lockout, Duration::from_secs(90));
        // The lockout alias of the earlier waves keeps working.
        let env = FakeEnv::from_pairs(&[("SSH3_MAX_PASSWORD_FAILOUT_SECONDS", "120")]);
        let config = config_of(&env, &["ssh3-rust-server"]);
        assert_eq!(config.password_lockout, Duration::from_secs(120));
    }

    /// The drain window of the graceful shutdown: a plain number of seconds
    /// like the reference parses it, the default on garbage and on the unit
    /// suffixes (`SSH3_SHUTDOWN_DRAIN` of the Go implementation).
    #[test]
    fn the_shutdown_drain_env_sets_the_drain_window() {
        let env = FakeEnv::from_pairs(&[("SSH3_SHUTDOWN_DRAIN", "30")]);
        assert_eq!(
            config_of(&env, &["ssh3-rust-server"]).shutdown_drain,
            Duration::from_secs(30)
        );
        for garbage in ["5s", " 5", "-2", "soon"] {
            let env = FakeEnv::from_pairs(&[("SSH3_SHUTDOWN_DRAIN", garbage)]);
            assert_eq!(
                config_of(&env, &["ssh3-rust-server"]).shutdown_drain,
                Duration::from_secs(5),
                "{garbage} falls back to the default drain"
            );
        }
    }

    /// Parses the certificate flags the way the binary does: the arguments
    /// ride the Go-style normalizer first, then the resolver of the identity.
    fn identity_of(arguments: &[&str]) -> Result<Option<(PathBuf, PathBuf)>, String> {
        let mut owned = vec!["ssh3-rust-server"];
        owned.extend_from_slice(arguments);
        let normalized = super::normalize_go_style_args(owned);
        let cli = Cli::try_parse_from(normalized).unwrap();
        super::resolve_server_identity(&cli)
    }

    /// The `-cert`/`-key` pair of the reference
    /// (`cmd/ssh3-server.go:969-970`) reaches the server identity: both the
    /// clap spelling and the single-dash Go shape of the same flags.
    #[test]
    fn the_cert_and_key_flags_take_the_pair() {
        let identity = identity_of(&["--cert", "cert.pem", "--key", "priv.key"]).unwrap();
        assert_eq!(
            identity,
            Some((PathBuf::from("cert.pem"), PathBuf::from("priv.key")))
        );
        let identity = identity_of(&["-cert", "cert.pem", "-key", "priv.key"]).unwrap();
        assert_eq!(
            identity,
            Some((PathBuf::from("cert.pem"), PathBuf::from("priv.key"))),
            "the single-dash Go spelling of the reference works"
        );
    }

    /// The sshd-shaped aliases of the reference
    /// (`cmd/ssh3-server.go:973-974`, `cmd/ssh2_parity.go:206-220`): the
    /// alias wins when only it is given, and the two spellings of the same
    /// knob ride together (`-cert` with `-h`).
    #[test]
    fn the_cert_key_aliases_apply_like_the_reference() {
        let identity = identity_of(&["-c", "host.crt", "-h", "host.key"]).unwrap();
        assert_eq!(
            identity,
            Some((PathBuf::from("host.crt"), PathBuf::from("host.key"))),
            "the sshd aliases alone configure the pair"
        );
        let identity = identity_of(&["--cert", "cert.pem", "-h", "host.key"]).unwrap();
        assert_eq!(
            identity,
            Some((PathBuf::from("cert.pem"), PathBuf::from("host.key"))),
            "the long cert rides with the short key alias"
        );
        let identity = identity_of(&["-c", "host.crt", "--key", "priv.key"]).unwrap();
        assert_eq!(
            identity,
            Some((PathBuf::from("host.crt"), PathBuf::from("priv.key"))),
            "the short cert alias rides with the long key"
        );
    }

    /// Giving both forms of the same knob is an error instead of a silent
    /// last-one-wins, with the messages of the reference
    /// (`cmd/ssh2_parity.go:207-211`).
    #[test]
    fn the_doubled_cert_or_key_forms_refuse_the_start() {
        assert_eq!(
            identity_of(&["--cert", "cert.pem", "-c", "host.crt"]).unwrap_err(),
            "-c and -cert are mutually exclusive"
        );
        assert_eq!(
            identity_of(&["--key", "priv.key", "-h", "host.key"]).unwrap_err(),
            "-h and -key are mutually exclusive"
        );
    }

    /// A lone half of the pair is refused: the certificate and its private
    /// key are configured together.
    #[test]
    fn a_lone_cert_or_key_flag_refuses_the_start() {
        for lone in [
            &["--cert", "cert.pem"][..],
            &["--key", "priv.key"][..],
            &["-c", "host.crt"][..],
            &["-h", "host.key"][..],
        ] {
            assert!(identity_of(lone).is_err(), "{lone:?} refuses the start");
        }
        // and the plain start keeps the self-signed default
        assert_eq!(identity_of(&[]).unwrap(), None);
    }

    /// The `-h` alias of the host key takes over the help short flag, like
    /// in the Go reference where `-h` is the host key; the long `--help`
    /// keeps showing the usage.
    #[test]
    fn the_h_alias_does_not_shadow_the_long_help() {
        let normalized = super::normalize_go_style_args(["ssh3-rust-server", "-h", "host.key"]);
        let cli = Cli::try_parse_from(normalized).unwrap();
        assert_eq!(cli.key_alias, Some(PathBuf::from("host.key")));
        let help = Cli::try_parse_from(["ssh3-rust-server", "--help"]).unwrap_err();
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
    }
}
