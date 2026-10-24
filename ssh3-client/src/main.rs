use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgGroup, CommandFactory, Parser, ValueHint, error::ErrorKind};
use http::Uri;
use ssh3_client::{
    DEFAULT_HANDSHAKE_IDLE_TIMEOUT, DEFAULT_MAX_IDLE_TIMEOUT, DEFAULT_TRANSFER_PORT,
    DEFAULT_TRANSFER_URL_PATH, SSH3_CLIENT_VERSION_STRING, Ssh3AgentSelection, Ssh3ClientConfig,
    Ssh3ClientError, Ssh3DynamicForwardSpec, Ssh3KnownHostsTrust, Ssh3LocalForwardSpec,
    Ssh3OidcConfig, Ssh3PtyPolicy, Ssh3ReverseForwardSpec, Ssh3SessionRequest,
    Ssh3StrictHostKeyChecking, Ssh3TransferOptions, Ssh3TransferPlan, Ssh3TrustStrategy, SshConfig,
    default_known_hosts_path, default_ssh_config_path, exit_code_for_exit_signal,
    is_remote_transfer_spec, load_certificates, load_ssh_config, parse_duration,
    parse_dynamic_forward_spec, parse_escape_char, parse_local_forward_spec,
    parse_remote_transfer_spec, parse_reverse_forward_spec, resolve_strict_host_key_checking,
    run_file_transfer, run_forwards_only, run_session_stdio,
};

#[derive(Debug, Parser)]
#[command(
    name = "ssh3-rust-client",
    version = SSH3_CLIENT_VERSION_STRING,
    disable_version_flag = true,
    about = "Connects to an SSH3 server over QUIC/HTTP3. If COMMAND is omitted, requests a shell.",
    group(
        ArgGroup::new("auth")
            .args([
                "identity",
                "agent",
                "agent_key",
                "password",
                "password_file",
                "bearer_token",
                "bearer_token_file",
                "oidc_issuer_url",
            ])
            .multiple(false)
    )
)]
struct Cli {
    #[arg(long, value_name = "NAME")]
    server_name: Option<String>,

    #[arg(long, value_name = "NAME")]
    user: Option<String>,

    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    identity: Option<PathBuf>,

    #[arg(long, requires = "user", conflicts_with = "agent_key")]
    agent: bool,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        requires = "user",
        conflicts_with = "agent"
    )]
    agent_key: Option<PathBuf>,

    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    agent_socket: Option<PathBuf>,

    #[arg(long)]
    forward_agent: bool,

    #[arg(
        long,
        value_name = "PASS",
        requires = "user",
        conflicts_with = "password_file",
        help = "Password for basic authentication. Prefer --password-file to avoid exposing secrets in argv."
    )]
    password: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        requires = "user",
        conflicts_with = "password",
        help = "Read the basic-auth password from a file."
    )]
    password_file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "TOKEN",
        conflicts_with = "bearer_token_file",
        help = "Bearer token to send in Authorization. Prefer --bearer-token-file to avoid exposing secrets in argv."
    )]
    bearer_token: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        conflicts_with = "bearer_token",
        help = "Read the bearer token from a file."
    )]
    bearer_token_file: Option<PathBuf>,

    #[arg(long = "use-oidc", value_name = "ISSUER", requires = "oidc_client_id")]
    oidc_issuer_url: Option<String>,

    #[arg(long, value_name = "ID", requires = "oidc_issuer_url")]
    oidc_client_id: Option<String>,

    #[arg(
        long,
        value_name = "SECRET",
        requires_all = ["oidc_issuer_url", "oidc_client_id"],
        conflicts_with = "oidc_client_secret_file",
        help = "OIDC client secret. Prefer --oidc-client-secret-file to avoid exposing secrets in argv."
    )]
    oidc_client_secret: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        requires_all = ["oidc_issuer_url", "oidc_client_id"],
        conflicts_with = "oidc_client_secret",
        help = "Read the OIDC client secret from a file."
    )]
    oidc_client_secret_file: Option<PathBuf>,

    #[arg(long)]
    no_pkce: bool,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        conflicts_with = "insecure"
    )]
    ca_cert: Option<PathBuf>,

    #[arg(long, conflicts_with = "ca_cert")]
    insecure: bool,

    /// The URL of the server, or the first operand of a transfer.
    ///
    /// In the transfer mode the operand is either the remote side of the
    /// transfer (the `user@host:remote_path` form) or the local one.
    #[arg(value_name = "URL", required_unless_present = "print_version")]
    url: Option<String>,

    /// Move files between the local machine and the server over SFTP.
    ///
    /// The mode takes exactly two operands: one in the `user@host:remote_path`
    /// form and one local path. The remote operand is the source of a
    /// download and the destination of an upload.
    #[arg(long)]
    transfer: bool,

    /// Transfer the directories recursively (transfer mode).
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Resume an interrupted transfer instead of overwriting it (transfer
    /// mode).
    ///
    /// The destination is compared with the source by size and modification
    /// time; a file whose size matches but whose modification time does not
    /// is transferred again.
    #[arg(long = "continue")]
    resume: bool,

    /// Verify the transfer with a SHA-256 re-read of the remote file (transfer
    /// mode).
    ///
    /// The verification happens on its own for the files over 32 MiB.
    #[arg(long)]
    checksum: bool,

    /// The port of the server (transfer mode).
    ///
    /// The port wins over the port of the operand of the transfer.
    #[arg(short = 'p', long, value_name = "PORT")]
    port: Option<u16>,

    /// The URL path of the server (transfer mode).
    ///
    /// The path wins over the default one; the operand of the transfer wins
    /// over the flag.
    #[arg(short = 'U', long = "url-path", value_name = "PATH")]
    url_path: Option<String>,

    /// Force the allocation of a pseudo-terminal.
    #[arg(short = 't', conflicts_with = "no_pty")]
    force_pty: bool,

    /// Never allocate a pseudo-terminal.
    #[arg(short = 'T', conflicts_with = "force_pty")]
    no_pty: bool,

    /// Set an option: RequestTTY=auto|yes|no|force, Term=<type>, EscapeChar=<char>,
    /// StrictHostKeyChecking=ask|yes|accept-new|no, LocalForward=<spec>,
    /// RemoteForward=<spec>, DynamicForward=<spec>, ProxyJump=<chain>,
    /// ServerAliveInterval=<seconds>.
    #[arg(short = 'o', value_name = "KEY=VALUE")]
    option: Vec<String>,

    /// Do not execute a remote command or session; hold the connection open
    /// for the forwards.
    #[arg(short = 'N')]
    no_session: bool,

    /// Connect through the jump hosts of the chain, every destination in the
    /// `[user@]host[:port]` form separated by commas (-J). Each hop must run
    /// an SSH3 server.
    #[arg(short = 'J', long = "jump", value_name = "DESTINATION")]
    jump: Option<String>,

    /// The deprecated alias of `-J`.
    #[arg(long = "proxy-jump", value_name = "DESTINATION")]
    proxy_jump: Option<String>,

    /// Print the version string of the client and exit.
    ///
    /// The string has the format of the Go implementation: the name of the
    /// protocol, the version of the protocol, the name of the implementation
    /// and its version, then the version of the experimental specification.
    #[arg(short = 'V', long = "version")]
    print_version: bool,

    /// The policy of the known_hosts check: ask, yes, accept-new or no.
    ///
    /// The flag wins over the `-o StrictHostKeyChecking` option, which wins
    /// over the keyword of the same name of the ssh_config file.
    #[arg(long = "strict-host-key-checking", value_name = "VALUE")]
    strict_host_key_checking: Option<String>,

    /// The known_hosts file that pins the certificates of the servers.
    #[arg(long = "known-hosts", value_name = "PATH", value_hint = ValueHint::FilePath)]
    known_hosts: Option<PathBuf>,

    /// The ssh_config file of the user.
    ///
    /// The `-F` option names another file, like the Go implementation does.
    #[arg(
        short = 'F',
        long = "ssh-config",
        value_name = "PATH",
        value_hint = ValueHint::FilePath
    )]
    ssh_config: Option<PathBuf>,

    /// Forward a local port to the remote host: [bind_address:]port:host:hostport.
    #[arg(short = 'L', value_name = "SPEC")]
    local_forward: Vec<String>,

    /// Ask the server to bind a port and forward it to a local target:
    /// [bind_address:]bind_port[/udp]:target_host:target_port.
    #[arg(short = 'R', value_name = "SPEC")]
    reverse_forward: Vec<String>,

    /// Forward a local SOCKS5 proxy to the remote host: [bind_address:]port.
    #[arg(short = 'D', value_name = "SPEC")]
    dynamic_forward: Vec<String>,

    /// The timeout of the QUIC handshake.
    #[arg(long, value_name = "DURATION")]
    handshake_idle_timeout: Option<String>,

    /// The timeout of an idle QUIC connection.
    #[arg(long, value_name = "DURATION")]
    max_idle_timeout: Option<String>,

    #[arg(value_name = "COMMAND", trailing_var_arg = true, num_args = 0..)]
    command: Vec<String>,
}

fn cli_error(kind: ErrorKind, message: impl Into<String>) -> clap::Error {
    Cli::command().error(kind, message.into())
}

/// The values of the `-o` options the client understands.
#[derive(Debug, Default)]
struct OptionOverrides {
    request_tty: Option<Ssh3PtyPolicy>,
    term: Option<String>,
    escape_char: Option<u8>,
    strict_host_key_checking: Option<String>,
    local_forwards: Vec<Ssh3LocalForwardSpec>,
    reverse_forwards: Vec<Ssh3ReverseForwardSpec>,
    dynamic_forwards: Vec<Ssh3DynamicForwardSpec>,
    proxy_jump: Option<String>,
    server_alive_interval: Option<Duration>,
}

/// Parses the `-o KEY=VALUE` options.
///
/// Only the keywords the client implements are accepted; an unknown keyword is
/// refused before a single packet is sent, so a typo costs a process start and
/// nothing else.
fn parse_options(options: &[String]) -> Result<OptionOverrides, clap::Error> {
    let mut overrides = OptionOverrides::default();
    for option in options {
        let (key, value) = match option.split_once('=') {
            Some((key, value)) => (key.trim().to_string(), value.trim().to_string()),
            None => (option.trim().to_string(), String::new()),
        };
        match key.to_ascii_lowercase().as_str() {
            "requesttty" => {
                overrides.request_tty = Some(
                    Ssh3PtyPolicy::parse(&value)
                        .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?,
                );
            }
            "term" => {
                if value.is_empty() {
                    return Err(cli_error(
                        ErrorKind::ValueValidation,
                        "empty Term value: want a terminal name, e.g. xterm-256color",
                    ));
                }
                overrides.term = Some(value);
            }
            "escapechar" => {
                overrides.escape_char = Some(
                    parse_escape_char(&value)
                        .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))?,
                );
            }
            "stricthostkeychecking" => {
                // The value is checked right away: a typo must cost a process
                // start and nothing else.
                Ssh3StrictHostKeyChecking::parse(&value)
                    .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))?;
                overrides.strict_host_key_checking = Some(value);
            }
            "localforward" => {
                overrides.local_forwards.push(
                    parse_local_forward_spec(&value)
                        .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))?,
                );
            }
            "remoteforward" => {
                overrides.reverse_forwards.push(
                    parse_reverse_forward_spec(&value)
                        .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))?,
                );
            }
            "dynamicforward" => {
                overrides.dynamic_forwards.push(
                    parse_dynamic_forward_spec(&value)
                        .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))?,
                );
            }
            "proxyjump" => {
                // The chain is validated like the Go implementation does: a
                // comma-separated list of non-empty destinations.
                validate_proxy_jump(&value)
                    .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?;
                overrides.proxy_jump = Some(value);
            }
            "serveraliveinterval" => {
                overrides.server_alive_interval = Some(
                    parse_timeout(&value)
                        .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?,
                );
            }
            other => {
                return Err(cli_error(
                    ErrorKind::ValueValidation,
                    format!("unknown option {other:?}"),
                ));
            }
        }
    }
    Ok(overrides)
}

/// Validates the value of a `ProxyJump` keyword.
///
/// The value is a comma-separated list of destinations, like the `-J` option
/// of ssh(1); no destination may be empty or hold a space.
fn validate_proxy_jump(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err("empty ProxyJump value: want a destination, e.g. jump.example.org".to_string());
    }
    for hop in value.split(',') {
        let hop = hop.trim();
        if hop.is_empty() {
            return Err(format!(
                "invalid ProxyJump value {value:?}: empty destination"
            ));
        }
        if hop.contains([' ', '\t']) {
            return Err(format!(
                "invalid ProxyJump destination {hop:?} in {value:?}"
            ));
        }
    }
    Ok(())
}

/// Parses a timeout value.
///
/// The value is a duration of the Go syntax ("120s", "2m", "1.5h"); a bare
/// number is a number of seconds, like the environment variable of the Go
/// implementation.
fn parse_timeout(value: &str) -> Result<Duration, String> {
    let trimmed = value.trim();
    if let Ok(seconds) = trimmed.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }
    parse_duration(trimmed).map_err(|err| err.to_string())
}

/// The timeout of a client: the flag wins over the environment variable.
fn resolve_timeout(
    flag: Option<&str>,
    env_name: &str,
    default: Duration,
) -> Result<Duration, clap::Error> {
    let value = match flag {
        Some(value) => Some(value.to_string()),
        None => std::env::var(env_name).ok(),
    };
    let Some(value) = value else {
        return Ok(default);
    };
    parse_timeout(&value).map_err(|err| {
        cli_error(
            ErrorKind::ValueValidation,
            format!("invalid timeout {value:?} ({env_name}): {err}"),
        )
    })
}

fn read_secret_file(path: &Path, label: &str) -> Result<String, clap::Error> {
    std::fs::read_to_string(path)
        .map(|contents| contents.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|err| cli_error(ErrorKind::Io, format!("failed to read {label}: {err}")))
}

/// The values the ssh_config file of the user provides.
///
/// The keywords are read for the host of the connection and for the user of
/// the connection, like the Go implementation does.
struct SshConfigValues {
    strict_host_key_checking: Option<String>,
    request_tty: Option<Ssh3PtyPolicy>,
    term: Option<String>,
    escape_char: Option<u8>,
    forward_agent: bool,
    server_alive_interval: Option<Duration>,
    proxy_jump: Option<String>,
}

/// Loads the ssh_config file of the user.
///
/// A file that cannot be read is ignored, like the Go implementation does:
/// the error goes to the standard error and the connection goes on. A file
/// that does not exist is skipped silently.
fn load_user_ssh_config(path: Option<&Path>) -> SshConfig {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => match default_ssh_config_path() {
            Some(path) => path,
            None => return SshConfig::default(),
        },
    };
    match load_ssh_config(&path) {
        Ok(configuration) => configuration,
        Err(err) => {
            eprintln!(
                "ssh3-rust-client: could not open {}: {err}, ignoring config",
                path.display()
            );
            SshConfig::default()
        }
    }
}

/// Reads the keywords of the ssh_config file the client uses.
///
/// The host is the one of the connection and the user the one of the
/// connection; an empty user means the local user of the process.
fn ssh_config_values(
    configuration: &SshConfig,
    host: Option<&str>,
    user: Option<&str>,
) -> Result<SshConfigValues, clap::Error> {
    let mut values = SshConfigValues {
        strict_host_key_checking: None,
        request_tty: None,
        term: None,
        escape_char: None,
        forward_agent: false,
        server_alive_interval: None,
        proxy_jump: None,
    };
    let Some(host) = host else {
        return Ok(values);
    };
    let user = user.unwrap_or("");
    let get = |keyword: &str| -> Option<String> {
        configuration
            .get_for_user(host, user, keyword)
            .map(str::to_string)
    };

    if let Some(value) = get("StrictHostKeyChecking") {
        values.strict_host_key_checking = Some(value);
    }
    if let Some(value) = get("RequestTTY") {
        values.request_tty = Some(
            Ssh3PtyPolicy::parse(&value)
                .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?,
        );
    }
    if let Some(value) = get("Term") {
        if value.is_empty() {
            return Err(cli_error(
                ErrorKind::ValueValidation,
                "empty Term value: want a terminal name, e.g. xterm-256color",
            ));
        }
        values.term = Some(value);
    }
    if let Some(value) = get("EscapeChar") {
        values.escape_char = Some(
            parse_escape_char(&value)
                .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))?,
        );
    }
    if let Some(value) = get("ForwardAgent") {
        // The Go implementation only reads the affirmative value.
        values.forward_agent = value.eq_ignore_ascii_case("yes");
    }
    if let Some(value) = get("ServerAliveInterval") {
        // The value of the keyword is a number of seconds; the Go
        // implementation ignores a value it cannot read.
        if let Ok(seconds) = value.trim().parse::<u64>() {
            if seconds > 0 {
                values.server_alive_interval = Some(Duration::from_secs(seconds));
            }
        }
    }
    if let Some(value) = get("UDPProxyJump").or_else(|| get("ProxyJump")) {
        validate_proxy_jump(&value).map_err(|err| cli_error(ErrorKind::ValueValidation, err))?;
        values.proxy_jump = Some(value);
    }
    Ok(values)
}

/// The plan the command line describes.
#[derive(Debug)]
struct ClientPlan {
    /// The configuration of the connection.
    config: Ssh3ClientConfig,
    /// The request of the session.
    request: Ssh3SessionRequest,
    /// The connection is held open for the forwards only.
    no_session: bool,
    /// The transfer the mode asks for; `None` for the other modes.
    transfer: Option<Ssh3TransferPlan>,
}

/// Builds the plan of the command line.
///
/// The transfer mode owns the two operands of the command line, so it is
/// resolved before the configuration of the connection is built.
fn build_config(cli: Cli) -> Result<ClientPlan, clap::Error> {
    if cli.transfer {
        return build_transfer_config(cli);
    }
    let command = cli.command.clone();
    let no_session = cli.no_session;
    let url = cli.url.clone().ok_or_else(|| {
        cli_error(
            ErrorKind::MissingRequiredArgument,
            "the following required arguments were not provided: <URL>",
        )
    })?;
    let url = url.parse::<Uri>().map_err(|err| {
        cli_error(
            ErrorKind::ValueValidation,
            format!("invalid URL {url:?}: {err}"),
        )
    })?;
    let config = build_connection_config(cli, url, None)?;
    let request = if command.is_empty() {
        Ssh3SessionRequest::Shell
    } else {
        Ssh3SessionRequest::Exec(command.join(" "))
    };
    Ok(ClientPlan {
        config,
        request,
        no_session,
        transfer: None,
    })
}

/// Builds the plan of the transfer mode.
///
/// The mode takes exactly two operands: one in the `user@host:remote_path`
/// form and one local path. The remote operand is the source of a download
/// and the destination of an upload.
fn build_transfer_config(cli: Cli) -> Result<ClientPlan, clap::Error> {
    if cli.no_session {
        return Err(cli_error(
            ErrorKind::ArgumentConflict,
            "-N cannot be combined with --transfer",
        ));
    }
    let first = cli.url.clone().ok_or_else(|| {
        cli_error(
            ErrorKind::MissingRequiredArgument,
            "file transfer mode expects exactly two operands: one user@host:remote_path and one local path",
        )
    })?;
    if cli.command.len() != 1 {
        return Err(cli_error(
            ErrorKind::WrongNumberOfValues,
            "file transfer mode expects exactly two operands: one user@host:remote_path and one local path",
        ));
    }
    let second = cli.command[0].clone();

    // the remote operand decides the direction of the transfer
    let (remote_operand, local_operand, upload) = if is_remote_transfer_spec(&first)
        && !is_remote_transfer_spec(&second)
    {
        (first, second, false)
    } else if is_remote_transfer_spec(&second) && !is_remote_transfer_spec(&first) {
        (second, first, true)
    } else {
        return Err(cli_error(
            ErrorKind::ValueValidation,
            "file transfer mode expects exactly one remote operand in the user@host:remote_path form",
        ));
    };

    let default_url_path = cli
        .url_path
        .clone()
        .unwrap_or_else(|| DEFAULT_TRANSFER_URL_PATH.to_string());
    let default_port = cli.port.unwrap_or(DEFAULT_TRANSFER_PORT);
    let mut target = parse_remote_transfer_spec(&remote_operand, default_port, &default_url_path)
        .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))?;
    // the port of the command line wins over the port of the operand
    if let Some(port) = cli.port {
        target.port = port;
    }
    if target.url_path.is_empty() {
        target.url_path = "/".to_string();
    }

    let options = Ssh3TransferOptions {
        recursive: cli.recursive,
        resume: cli.resume,
        checksum: cli.checksum,
    };
    let transfer = Ssh3TransferPlan {
        target: target.clone(),
        local_path: PathBuf::from(&local_operand),
        upload,
        options,
    };

    // The URL of the connection carries the user of the operand in its
    // query, the way the Go client does: the server of the reference
    // implementation resolves the user of the session from the query.
    let mut url = url::Url::parse(&format!(
        "https://{}:{}{}",
        target.hostname, target.port, target.url_path
    ))
    .map_err(|err| {
        cli_error(
            ErrorKind::ValueValidation,
            format!("invalid transfer target {:?}: {err}", target.hostname),
        )
    })?;
    url.query_pairs_mut().append_pair("user", &target.username);
    let url = url.as_str().parse::<Uri>().map_err(|err| {
        cli_error(
            ErrorKind::ValueValidation,
            format!("invalid URL {url:?}: {err}"),
        )
    })?;
    // the user of the operand wins over the user of the command line
    let config = build_connection_config(cli, url, Some(target.username))?;

    Ok(ClientPlan {
        config,
        request: Ssh3SessionRequest::Shell,
        no_session: false,
        transfer: Some(transfer),
    })
}

/// Builds the configuration of the connection.
///
/// The username of the caller wins over the one of the configuration only
/// when the caller did not name one: the transfer mode carries the user of
/// its operand.
fn build_connection_config(
    cli: Cli,
    url: Uri,
    username: Option<String>,
) -> Result<Ssh3ClientConfig, clap::Error> {
    let mut config = Ssh3ClientConfig::new(url);
    config.server_name = cli.server_name;
    config.username = username.or(cli.user);
    config.identity_file = cli.identity;
    config.agent = if cli.agent {
        Some(Ssh3AgentSelection::First)
    } else {
        cli.agent_key.map(Ssh3AgentSelection::PublicKey)
    };
    config.agent_socket = cli.agent_socket;
    config.forward_agent = cli.forward_agent;
    config.password = match (cli.password, cli.password_file) {
        (Some(password), None) => Some(password),
        (None, Some(path)) => Some(read_secret_file(&path, "password file")?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces password conflicts"),
    };
    config.bearer_token = match (cli.bearer_token, cli.bearer_token_file) {
        (Some(token), None) => Some(token.trim().to_string()),
        (None, Some(path)) => Some(read_secret_file(&path, "bearer token file")?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces bearer token conflicts"),
    };
    config.oidc = match (cli.oidc_issuer_url, cli.oidc_client_id) {
        (Some(issuer_url), Some(client_id)) => Some(Ssh3OidcConfig {
            issuer_url,
            client_id,
            client_secret: match (cli.oidc_client_secret, cli.oidc_client_secret_file) {
                (Some(secret), None) => Some(secret),
                (None, Some(path)) => Some(read_secret_file(&path, "OIDC client secret file")?),
                (None, None) => None,
                (Some(_), Some(_)) => unreachable!("clap enforces OIDC secret conflicts"),
            },
            use_pkce: !cli.no_pkce,
        }),
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => unreachable!("clap enforces OIDC requirements"),
    };
    let overrides = parse_options(&cli.option)?;

    // The configuration file of the user. The `-F` option names another
    // file; the default one is read when it is not given.
    let ssh_config = load_user_ssh_config(cli.ssh_config.as_deref());
    let ssh_config_values = ssh_config_values(
        &ssh_config,
        config.target_url.host(),
        config.username.as_deref(),
    )?;

    // The certificate authorities the server chain may be verified against.
    let authorities = match cli.ca_cert.as_ref() {
        Some(path) => load_certificates(path).map_err(|err| {
            cli_error(
                ErrorKind::ValueValidation,
                format!("failed to load CA certificate: {err}"),
            )
        })?,
        None => Vec::new(),
    };

    // The StrictHostKeyChecking policy is resolved like OpenSSH does: the
    // flag wins over the `-o` option, which wins over the keyword of the
    // ssh_config file. The known_hosts check only runs when one of the
    // sources sets the policy, so that the default behaviour of the client
    // stays the one it had before.
    let policy = resolve_strict_host_key_checking(
        cli.strict_host_key_checking.as_deref(),
        overrides.strict_host_key_checking.as_deref(),
        ssh_config_values.strict_host_key_checking.as_deref(),
    )
    .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))?;
    let policy_is_set = cli.strict_host_key_checking.is_some()
        || overrides.strict_host_key_checking.is_some()
        || ssh_config_values.strict_host_key_checking.is_some();

    config.trust = if cli.insecure {
        Ssh3TrustStrategy::Insecure
    } else if policy_is_set {
        Ssh3TrustStrategy::KnownHosts(Ssh3KnownHostsTrust {
            policy,
            path: cli
                .known_hosts
                .clone()
                .or_else(default_known_hosts_path)
                .unwrap_or_else(|| PathBuf::from(".ssh3").join("known_hosts")),
            authorities,
        })
    } else if !authorities.is_empty() {
        Ssh3TrustStrategy::Certificates(authorities)
    } else {
        Ssh3TrustStrategy::WebPkiRoots
    };

    // The RequestTTY precedence follows OpenSSH: the `-T` and `-t` flags are
    // the absolutes, the `-o RequestTTY=` option comes next, the keyword of
    // the ssh_config file follows and `auto` is the default.
    config.pty_policy = overrides
        .request_tty
        .or(ssh_config_values.request_tty)
        .unwrap_or(Ssh3PtyPolicy::Auto);
    if cli.no_pty {
        config.pty_policy = Ssh3PtyPolicy::No;
    }
    if cli.force_pty {
        config.pty_policy = Ssh3PtyPolicy::Force;
    }
    config.term_type = overrides.term.or(ssh_config_values.term);
    if let Some(escape_char) = overrides.escape_char.or(ssh_config_values.escape_char) {
        config.escape_char = escape_char;
    }
    // The agent forwarding is enabled by the flag or by the keyword of the
    // ssh_config file.
    config.forward_agent = cli.forward_agent || ssh_config_values.forward_agent;
    // The agent socket is a unix domain socket: the Windows client cannot
    // forward an agent, and says so instead of opening a session that
    // cannot work.
    #[cfg(windows)]
    if config.forward_agent {
        return Err(cli_error(
            ErrorKind::ValueValidation,
            "the SSH agent forwarding is not available on Windows: the agent socket is a unix domain socket",
        ));
    }
    // The same socket carries the agent authentication.
    #[cfg(windows)]
    if config.agent.is_some() {
        return Err(cli_error(
            ErrorKind::ValueValidation,
            "the SSH agent authentication is not available on Windows: the agent socket is a unix domain socket",
        ));
    }
    // The keepalive period comes from the `-o` option first and from the
    // keyword of the ssh_config file next.
    if let Some(interval) = overrides
        .server_alive_interval
        .or(ssh_config_values.server_alive_interval)
    {
        config.keep_alive_interval = Some(interval);
    }
    // The proxy jump chain comes from the `-o` option first and from the
    // keyword of the ssh_config file next.
    // The proxy jump chain comes from the `-J` flag first, from its
    // deprecated `-proxy-jump` alias next, from the `-o` option after that
    // and from the keyword of the ssh_config file last.
    let jump_flag = cli
        .jump
        .as_deref()
        .or(cli.proxy_jump.as_deref())
        .map(str::to_string);
    if let Some(chain) = jump_flag {
        validate_proxy_jump(&chain).map_err(|err| cli_error(ErrorKind::ValueValidation, err))?;
        config.proxy_jump = Some(chain);
    } else {
        config.proxy_jump = overrides.proxy_jump.or(ssh_config_values.proxy_jump);
    }

    // The forwards follow the same precedence as the other options: the
    // command line wins over the `-o` options.
    config.local_forwards = if cli.local_forward.is_empty() {
        overrides.local_forwards
    } else {
        cli.local_forward
            .iter()
            .map(|spec| {
                parse_local_forward_spec(spec)
                    .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))
            })
            .collect::<Result<Vec<Ssh3LocalForwardSpec>, clap::Error>>()?
    };

    config.reverse_forwards = if cli.reverse_forward.is_empty() {
        overrides.reverse_forwards
    } else {
        cli.reverse_forward
            .iter()
            .map(|spec| {
                parse_reverse_forward_spec(spec)
                    .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))
            })
            .collect::<Result<Vec<Ssh3ReverseForwardSpec>, clap::Error>>()?
    };

    config.dynamic_forwards = if cli.dynamic_forward.is_empty() {
        overrides.dynamic_forwards
    } else {
        cli.dynamic_forward
            .iter()
            .map(|spec| {
                parse_dynamic_forward_spec(spec)
                    .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))
            })
            .collect::<Result<Vec<Ssh3DynamicForwardSpec>, clap::Error>>()?
    };

    config.handshake_idle_timeout = resolve_timeout(
        cli.handshake_idle_timeout.as_deref(),
        "SSH3_HANDSHAKE_IDLE_TIMEOUT",
        DEFAULT_HANDSHAKE_IDLE_TIMEOUT,
    )?;
    config.max_idle_timeout = resolve_timeout(
        cli.max_idle_timeout.as_deref(),
        "SSH3_MAX_IDLE_TIMEOUT",
        DEFAULT_MAX_IDLE_TIMEOUT,
    )?;

    // The `-N` flag holds the connection open for the forwards: no session is
    // opened, so a remote command makes no sense.
    if cli.no_session && !cli.command.is_empty() {
        return Err(cli_error(
            ErrorKind::ArgumentConflict,
            "-N does not accept a remote command",
        ));
    }
    Ok(config)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
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
    // The version string is printed on the standard output, like the Go
    // implementation does, and the connection is not opened.
    if cli.print_version {
        println!("{SSH3_CLIENT_VERSION_STRING}");
        return ExitCode::SUCCESS;
    }

    let plan = match build_config(cli) {
        Ok(parsed) => parsed,
        Err(err) => {
            let status = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            };
            err.print().ok();
            return status;
        }
    };

    // The transfer mode moves the files and opens no session.
    if let Some(transfer) = plan.transfer {
        return match run_file_transfer(&plan.config, &transfer).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("ssh3-rust-client: {err}");
                // the Go implementation leaves the process with the code -1,
                // which the shell sees as 255
                ExitCode::from(255)
            }
        };
    }

    if plan.no_session {
        return match run_forwards_only(&plan.config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("ssh3-rust-client failed: {err}");
                ExitCode::FAILURE
            }
        };
    }

    match run_session_stdio(&plan.config, plan.request).await {
        Ok(status) => ExitCode::from(status as u8),
        Err(Ssh3ClientError::ExitSignal(signal)) => {
            let name = String::from_utf8_lossy(&signal.signal_name_without_sig).to_string();
            let code = exit_code_for_exit_signal(name.strip_prefix("SIG").unwrap_or(&name));
            eprintln!("ssh3-rust-client: the remote process exited with signal {name}");
            ExitCode::from(code as u8)
        }
        Err(err) => {
            eprintln!("ssh3-rust-client failed: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, build_config};
    use clap::{Parser, error::ErrorKind};
    use ssh3_client::{
        SSH3_CLIENT_VERSION_STRING, Ssh3ForwardProtocol, Ssh3PtyPolicy, Ssh3ReverseForwardProtocol,
        Ssh3StrictHostKeyChecking, Ssh3TrustStrategy,
    };
    use std::time::Duration;

    fn config_of(arguments: &[&str]) -> ssh3_client::Ssh3ClientConfig {
        let mut argv = vec!["ssh3-rust-client"];
        argv.extend_from_slice(arguments);
        argv.push("https://localhost:4433/ssh3-term");
        let cli = Cli::try_parse_from(argv).unwrap();
        build_config(cli).unwrap().config
    }

    /// The three values the command line parsing produces.
    fn parsed_of(arguments: &[&str]) -> (ssh3_client::Ssh3ClientConfig, bool) {
        let mut argv = vec!["ssh3-rust-client"];
        argv.extend_from_slice(arguments);
        argv.push("https://localhost:4433/ssh3-term");
        let cli = Cli::try_parse_from(argv).unwrap();
        let plan = build_config(cli).unwrap();
        (plan.config, plan.no_session)
    }

    /// The policy of the known_hosts check of a configuration.
    fn policy_of(config: &ssh3_client::Ssh3ClientConfig) -> Option<Ssh3StrictHostKeyChecking> {
        match &config.trust {
            Ssh3TrustStrategy::KnownHosts(trust) => Some(trust.policy),
            _ => None,
        }
    }

    #[test]
    fn the_pty_flags_choose_the_pty_policy() {
        assert_eq!(config_of(&[]).pty_policy, Ssh3PtyPolicy::Auto);
        assert_eq!(config_of(&["-t"]).pty_policy, Ssh3PtyPolicy::Force);
        assert_eq!(config_of(&["-T"]).pty_policy, Ssh3PtyPolicy::No);
        assert_eq!(
            config_of(&["-o", "RequestTTY=yes"]).pty_policy,
            Ssh3PtyPolicy::Yes
        );
        assert_eq!(
            config_of(&["-o", "RequestTTY=force"]).pty_policy,
            Ssh3PtyPolicy::Force
        );
        assert_eq!(
            config_of(&["-o", "RequestTTY=no"]).pty_policy,
            Ssh3PtyPolicy::No
        );
    }

    #[test]
    fn the_pty_flags_win_over_the_request_tty_option() {
        assert_eq!(
            config_of(&["-T", "-o", "RequestTTY=yes"]).pty_policy,
            Ssh3PtyPolicy::No
        );
        assert_eq!(
            config_of(&["-t", "-o", "RequestTTY=no"]).pty_policy,
            Ssh3PtyPolicy::Force
        );
    }

    #[test]
    fn the_mutually_exclusive_pty_flags_are_refused() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "-t",
            "-T",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn an_invalid_request_tty_policy_is_refused() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "-o",
            "RequestTTY=maybe",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn the_local_forwards_are_parsed() {
        let config = config_of(&["-L", "8080:example.com:80", "-L", "udp://5353:127.0.0.1:53"]);
        assert_eq!(config.local_forwards.len(), 2);
        assert_eq!(config.local_forwards[0].bind_port, 8080);
        assert_eq!(config.local_forwards[0].target_host, "example.com");
        assert_eq!(config.local_forwards[0].target_port, 80);
        assert_eq!(config.local_forwards[0].protocol, Ssh3ForwardProtocol::Tcp);
        assert_eq!(config.local_forwards[1].protocol, Ssh3ForwardProtocol::Udp);
    }

    #[test]
    fn a_malformed_local_forward_is_refused() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "-L",
            "8080",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn the_reverse_forwards_are_parsed() {
        let config = config_of(&[
            "-R",
            "8080:example.com:80",
            "-R",
            "127.0.0.1:8081/udp:example.com:53",
            "-R",
            "*:0:[2001:db8::1]:443",
        ]);
        assert_eq!(config.reverse_forwards.len(), 3);
        assert_eq!(config.reverse_forwards[0].bind_port, 8080);
        assert_eq!(config.reverse_forwards[0].target_host, "example.com");
        assert_eq!(config.reverse_forwards[0].target_port, 80);
        assert_eq!(
            config.reverse_forwards[0].protocol,
            Ssh3ReverseForwardProtocol::Tcp
        );
        assert_eq!(
            config.reverse_forwards[1].bind_address.as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            config.reverse_forwards[1].protocol,
            Ssh3ReverseForwardProtocol::Udp
        );
        assert_eq!(
            config.reverse_forwards[2].bind_address.as_deref(),
            Some("*")
        );
        assert_eq!(config.reverse_forwards[2].target_host, "2001:db8::1");
    }

    #[test]
    fn a_malformed_reverse_forward_is_refused() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "-R",
            "8080",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn the_dynamic_forwards_are_parsed() {
        let config = config_of(&["-D", "1080", "-D", "*:1081", "-D", "[::1]:1082"]);
        assert_eq!(config.dynamic_forwards.len(), 3);
        assert_eq!(config.dynamic_forwards[0].bind_address, None);
        assert_eq!(config.dynamic_forwards[0].bind_port, 1080);
        assert_eq!(
            config.dynamic_forwards[1].bind_address.as_deref(),
            Some("*")
        );
        assert_eq!(
            config.dynamic_forwards[2].bind_address.as_deref(),
            Some("::1")
        );
        assert_eq!(config.dynamic_forwards[2].bind_port, 1082);
    }

    #[test]
    fn a_malformed_dynamic_forward_is_refused() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "-D",
            "::1:1080",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn the_timeouts_are_parsed_like_the_go_durations() {
        let config = config_of(&[
            "--handshake-idle-timeout",
            "30s",
            "--max-idle-timeout",
            "1h",
        ]);
        assert_eq!(config.handshake_idle_timeout, Duration::from_secs(30));
        assert_eq!(config.max_idle_timeout, Duration::from_secs(3600));

        let config = config_of(&["--handshake-idle-timeout", "2m30s"]);
        assert_eq!(config.handshake_idle_timeout, Duration::from_secs(150));
    }

    #[test]
    fn the_default_timeouts_follow_the_ssh_canon() {
        let config = config_of(&[]);
        assert_eq!(config.handshake_idle_timeout, Duration::from_secs(120));
        assert_eq!(config.max_idle_timeout, Duration::from_secs(24 * 60 * 60));
    }

    #[test]
    fn a_malformed_timeout_is_refused() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "--handshake-idle-timeout",
            "soon",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn the_term_and_escape_char_options_are_applied() {
        let config = config_of(&["-o", "Term=xterm-256color", "-o", "EscapeChar=none"]);
        assert_eq!(config.term_type.as_deref(), Some("xterm-256color"));
        assert_eq!(config.escape_char, 0);
    }

    #[test]
    fn password_file_is_loaded_and_trimmed() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let password_file = tempdir.path().join("password.txt");
        std::fs::write(&password_file, "secret-password\n").unwrap();

        let cli = Cli::try_parse_from([
            "ssh3-rust-client",
            "--user",
            "alice",
            "--password-file",
            password_file.to_str().unwrap(),
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let config = build_config(cli).unwrap().config;

        assert_eq!(config.password.as_deref(), Some("secret-password"));
    }

    #[test]
    fn oidc_client_secret_file_is_loaded_and_trimmed() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let secret_file = tempdir.path().join("oidc-secret.txt");
        std::fs::write(&secret_file, "client-secret\r\n").unwrap();

        let cli = Cli::try_parse_from([
            "ssh3-rust-client",
            "--use-oidc",
            "https://issuer.example",
            "--oidc-client-id",
            "client-id",
            "--oidc-client-secret-file",
            secret_file.to_str().unwrap(),
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let config = build_config(cli).unwrap().config;

        assert_eq!(
            config
                .oidc
                .as_ref()
                .and_then(|oidc| oidc.client_secret.as_deref()),
            Some("client-secret")
        );
    }

    #[test]
    fn clap_rejects_multiple_auth_methods() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "--identity",
            "/tmp/id",
            "--bearer-token-file",
            "/tmp/token",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn the_known_hosts_check_is_off_until_a_policy_is_set() {
        let config = config_of(&[]);
        assert!(matches!(config.trust, Ssh3TrustStrategy::WebPkiRoots));
        assert_eq!(policy_of(&config), None);
    }

    #[test]
    fn the_strict_host_key_checking_option_enables_the_known_hosts_check() {
        let config = config_of(&["-o", "StrictHostKeyChecking=accept-new"]);
        assert_eq!(
            policy_of(&config),
            Some(Ssh3StrictHostKeyChecking::AcceptNew)
        );
        match &config.trust {
            Ssh3TrustStrategy::KnownHosts(trust) => {
                assert!(trust.path.ends_with("known_hosts"));
            }
            other => panic!("the known_hosts check was expected, got {other:?}"),
        }
    }

    #[test]
    fn the_strict_host_key_checking_flag_wins_over_the_option() {
        let config = config_of(&[
            "--strict-host-key-checking",
            "yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
        ]);
        assert_eq!(policy_of(&config), Some(Ssh3StrictHostKeyChecking::Yes));
    }

    #[test]
    fn the_ssh_config_keyword_sets_the_policy() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(
            &path,
            "Host localhost\n  StrictHostKeyChecking accept-new\n",
        )
        .unwrap();

        let config = config_of(&["--ssh-config", path.to_str().unwrap()]);
        assert_eq!(
            policy_of(&config),
            Some(Ssh3StrictHostKeyChecking::AcceptNew)
        );
    }

    #[test]
    fn the_option_wins_over_the_ssh_config_keyword() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(
            &path,
            "Host localhost\n  StrictHostKeyChecking accept-new\n",
        )
        .unwrap();

        let config = config_of(&[
            "--ssh-config",
            path.to_str().unwrap(),
            "-o",
            "StrictHostKeyChecking=no",
        ]);
        assert_eq!(policy_of(&config), Some(Ssh3StrictHostKeyChecking::No));
    }

    #[test]
    fn an_invalid_strict_host_key_checking_value_is_refused() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "-o",
            "StrictHostKeyChecking=maybe",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn the_no_session_flag_is_parsed() {
        let (_, no_session) = parsed_of(&["-N"]);
        assert!(no_session);
        let (_, no_session) = parsed_of(&[]);
        assert!(!no_session);
    }

    #[test]
    fn the_no_session_flag_refuses_a_remote_command() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "-N",
            "ls",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn the_config_file_option_is_parsed() {
        let cli = Cli::try_parse_from([
            "ssh3-rust-client",
            "-F",
            "/tmp/ssh_config",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        assert_eq!(
            cli.ssh_config.as_deref(),
            Some(std::path::Path::new("/tmp/ssh_config"))
        );
    }

    #[test]
    fn an_unreadable_config_file_does_not_stop_the_client() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        // A directory cannot be read as a file: the client ignores the
        // configuration and goes on.
        std::fs::create_dir(&path).unwrap();

        let config = config_of(&["--ssh-config", path.to_str().unwrap()]);
        assert_eq!(config.pty_policy, Ssh3PtyPolicy::Auto);
    }

    #[test]
    fn the_local_forward_option_is_parsed() {
        let config = config_of(&["-o", "LocalForward=8080:example.com:80"]);
        assert_eq!(config.local_forwards.len(), 1);
        assert_eq!(config.local_forwards[0].bind_port, 8080);
        assert_eq!(config.local_forwards[0].target_host, "example.com");
    }

    #[test]
    fn the_remote_forward_option_is_parsed() {
        let config = config_of(&["-o", "RemoteForward=8081:example.com:81"]);
        assert_eq!(config.reverse_forwards.len(), 1);
        assert_eq!(config.reverse_forwards[0].bind_port, 8081);
    }

    #[test]
    fn the_dynamic_forward_option_is_parsed() {
        let config = config_of(&["-o", "DynamicForward=1080"]);
        assert_eq!(config.dynamic_forwards.len(), 1);
        assert_eq!(config.dynamic_forwards[0].bind_port, 1080);
    }

    #[test]
    fn a_malformed_forward_option_is_refused() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "-o",
            "LocalForward=8080",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn the_proxy_jump_option_is_parsed() {
        let config = config_of(&["-o", "ProxyJump=jump.example.org"]);
        assert_eq!(config.proxy_jump.as_deref(), Some("jump.example.org"));
    }

    #[test]
    fn a_malformed_proxy_jump_option_is_refused() {
        let err = Cli::try_parse_from([
            "ssh3-rust-client",
            "-o",
            "ProxyJump=jump one",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn the_server_alive_interval_option_is_parsed() {
        let config = config_of(&["-o", "ServerAliveInterval=30"]);
        assert_eq!(config.keep_alive_interval, Some(Duration::from_secs(30)));
    }

    #[test]
    fn the_command_line_wins_over_the_forward_options() {
        let config = config_of(&[
            "-L",
            "9090:example.com:90",
            "-o",
            "LocalForward=8080:example.com:80",
        ]);
        assert_eq!(config.local_forwards.len(), 1);
        assert_eq!(config.local_forwards[0].bind_port, 9090);
    }

    #[test]
    fn the_forward_options_are_used_when_the_command_line_is_silent() {
        let config = config_of(&["-o", "LocalForward=8080:example.com:80"]);
        assert_eq!(config.local_forwards.len(), 1);
        assert_eq!(config.local_forwards[0].bind_port, 8080);
    }

    // The keyword is parsed the same way on every platform, but the agent
    // forwarding itself is a unix feature: the validation of the Windows
    // command line rejects the resolved setting, so the check of the
    // resolved value runs on unix only.
    #[cfg(unix)]
    #[test]
    fn the_config_file_provides_the_forward_agent_keyword() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(&path, "Host localhost\n  ForwardAgent yes\n").unwrap();

        let config = config_of(&["--ssh-config", path.to_str().unwrap()]);
        assert!(config.forward_agent);
    }

    #[test]
    fn the_config_file_provides_the_server_alive_interval_keyword() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(&path, "Host localhost\n  ServerAliveInterval 45\n").unwrap();

        let config = config_of(&["--ssh-config", path.to_str().unwrap()]);
        assert_eq!(config.keep_alive_interval, Some(Duration::from_secs(45)));
    }

    #[test]
    fn the_forward_option_wins_over_the_config_file_keyword() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(&path, "Host localhost\n  ServerAliveInterval 45\n").unwrap();

        let config = config_of(&[
            "--ssh-config",
            path.to_str().unwrap(),
            "-o",
            "ServerAliveInterval=30",
        ]);
        assert_eq!(config.keep_alive_interval, Some(Duration::from_secs(30)));
    }

    #[test]
    fn the_config_file_provides_the_proxy_jump_keyword() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(&path, "Host localhost\n  ProxyJump jump.example.org\n").unwrap();

        let config = config_of(&["--ssh-config", path.to_str().unwrap()]);
        assert_eq!(config.proxy_jump.as_deref(), Some("jump.example.org"));
    }

    #[test]
    fn the_proxy_jump_option_wins_over_the_config_file_keyword() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(&path, "Host localhost\n  ProxyJump jump.example.org\n").unwrap();

        let config = config_of(&[
            "--ssh-config",
            path.to_str().unwrap(),
            "-o",
            "ProxyJump=other.example.org",
        ]);
        assert_eq!(config.proxy_jump.as_deref(), Some("other.example.org"));
    }

    #[test]
    fn the_config_file_provides_the_request_tty_keyword() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(&path, "Host localhost\n  RequestTTY force\n").unwrap();

        let config = config_of(&["--ssh-config", path.to_str().unwrap()]);
        assert_eq!(config.pty_policy, Ssh3PtyPolicy::Force);
    }

    #[test]
    fn the_version_flag_is_parsed_without_a_url() {
        let cli = Cli::try_parse_from(["ssh3-rust-client", "-V"]).unwrap();
        assert!(cli.print_version);
        let cli = Cli::try_parse_from(["ssh3-rust-client", "--version"]).unwrap();
        assert!(cli.print_version);
    }

    #[test]
    fn the_url_is_required_without_the_version_flag() {
        let err = Cli::try_parse_from(["ssh3-rust-client"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn the_version_string_has_the_format_of_the_go_implementation() {
        // The Go implementation announces the name of the protocol, the
        // version of the protocol, the name of the implementation and its
        // version, then the version of the experimental specification.
        let fields: Vec<&str> = SSH3_CLIENT_VERSION_STRING.split(' ').collect();
        assert_eq!(fields[0], "SSH");
        assert_eq!(fields[1], "3.0");
        assert_eq!(fields[2], "ssh3-rust");
        assert!(fields[3].starts_with("0."));
        assert_eq!(fields[4], "experimental_spec_version=alpha-00");
    }
}
