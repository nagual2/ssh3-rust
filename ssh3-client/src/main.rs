use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgGroup, CommandFactory, Parser, ValueHint, error::ErrorKind};
use http::Uri;
use ssh3_client::{
    DEFAULT_HANDSHAKE_IDLE_TIMEOUT, DEFAULT_MAX_IDLE_TIMEOUT, DEFAULT_TRANSFER_PORT,
    DEFAULT_TRANSFER_URL_PATH, SSH3_CLIENT_VERSION_STRING, Ssh3AgentSelection, Ssh3ClientConfig,
    Ssh3ClientError, Ssh3DynamicForwardSpec, Ssh3IpFamily, Ssh3KnownHostsTrust,
    Ssh3LocalForwardSpec, Ssh3OidcConfig, Ssh3PtyPolicy, Ssh3ReverseForwardSpec,
    Ssh3SessionRequest, Ssh3StrictHostKeyChecking, Ssh3TransferOptions, Ssh3TransferPlan,
    Ssh3TrustStrategy, SshConfig, default_known_hosts_path, default_ssh_config_path, diag_error,
    diag_info, exit_code_for_exit_signal, is_remote_transfer_spec, load_certificates,
    load_ssh_config, parse_duration, parse_dynamic_forward_spec, parse_escape_char,
    parse_local_forward_spec, parse_remote_transfer_spec, parse_reverse_forward_spec,
    read_config_text, resolve_strict_host_key_checking, run_file_transfer, run_forwards_only,
    run_session_stdio,
};

/// The body of the reference `--oidc-config` json file.
#[derive(serde::Deserialize)]
struct Ssh3OidcConfigFile {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Parser)]
#[command(
    name = "ssh3",
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

    #[arg(
        long,
        short = 'i',
        visible_alias = "privkey",
        value_name = "PATH",
        value_hint = ValueHint::FilePath
    )]
    identity: Option<PathBuf>,

    #[arg(long, requires = "user", conflicts_with = "agent_key")]
    agent: bool,

    #[arg(
        long,
        visible_alias = "pubkey-for-agent",
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        requires = "user",
        conflicts_with = "agent"
    )]
    agent_key: Option<PathBuf>,

    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    agent_socket: Option<PathBuf>,

    #[arg(long, short = 'A')]
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

    /// OpenID Connect json config file containing the client_id and the
    /// client_secret fields needed by the OIDC flow (the reference file
    /// name: ~/.ssh3/oidc_config.json).
    #[arg(
        long = "oidc-config",
        value_name = "PATH",
        value_hint = ValueHint::FilePath
    )]
    oidc_config: Option<PathBuf>,

    /// Use IPv4 addresses only (ssh2 -4).
    #[arg(short = '4', long, conflicts_with = "ipv6_only")]
    ipv4_only: bool,

    /// Use IPv6 addresses only (ssh2 -6).
    #[arg(short = '6', long, conflicts_with = "ipv4_only")]
    ipv6_only: bool,

    /// Write the QUIC TLS secrets in the NSS keylog format into the given
    /// file: only for debugging with a packet analyzer.
    #[arg(
        long = "keylog",
        value_name = "PATH",
        value_hint = ValueHint::FilePath
    )]
    keylog: Option<PathBuf>,

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

    /// Run as the control master: share one authenticated connection across
    /// the invocations through the control socket (-M).
    ///
    /// Unix only, and not compatible with the proxy jump chain.
    #[cfg(unix)]
    #[arg(short = 'M')]
    master_mode: bool,

    /// The control master unix socket path (-S).
    #[cfg(unix)]
    #[arg(short = 'S', value_name = "PATH", value_hint = ValueHint::FilePath)]
    control_socket: Option<PathBuf>,

    /// Run one control operation against the master (-O): check, stop or
    /// exit. check prints the status line on the standard output.
    #[cfg(unix)]
    #[arg(
        short = 'O',
        value_name = "OP",
        conflicts_with_all = ["no_session", "transfer", "master_mode" ]
    )]
    control_operation: Option<String>,

    /// The control master policy: no, yes or auto (-control-master).
    #[cfg(unix)]
    #[arg(long = "control-master", value_name = "VALUE")]
    control_master: Option<String>,

    /// The control master unix socket path (-control-path).
    #[cfg(unix)]
    #[arg(long = "control-path", value_name = "PATH", value_hint = ValueHint::FilePath)]
    control_path: Option<PathBuf>,

    /// How long an idle master persists: no, yes or a number of seconds
    /// (-control-persist).
    #[cfg(unix)]
    #[arg(long = "control-persist", value_name = "VALUE")]
    control_persist: Option<String>,

    /// Connect through the jump hosts of the chain, every destination in the
    /// `[user@]host[:port]` form separated by commas (-J). Each hop must run
    /// an SSH3 server.
    #[arg(short = 'J', long = "jump", value_name = "DESTINATION")]
    jump: Option<String>,

    /// The deprecated alias of `-J`.
    #[arg(long = "proxy-jump", value_name = "DESTINATION")]
    proxy_jump: Option<String>,

    /// Quiet mode: suppress the diagnostic messages, the errors stay
    /// (ssh2 -q).
    #[arg(short = 'q', long, conflicts_with = "verbose")]
    quiet: bool,

    /// Verbose mode: add the details of the connection to the
    /// diagnostics (ssh2 -v).
    #[arg(short = 'v', long)]
    verbose: bool,

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
    control_master: Option<String>,
    control_path: Option<String>,
    control_persist: Option<String>,
    verify_host_key_dns: Option<ssh3_client::sshfp::VerifyHostKeyDns>,
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
            "controlmaster" => {
                parse_control_master_policy(&value)
                    .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?;
                overrides.control_master = Some(value);
            }
            "controlpath" => {
                overrides.control_path = Some(value);
            }
            "controlpersist" => {
                parse_control_persist(&value)
                    .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?;
                overrides.control_persist = Some(value);
            }
            "verifyhostkeydns" => {
                overrides.verify_host_key_dns = Some(
                    ssh3_client::sshfp::VerifyHostKeyDns::parse(&value)
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
    // The secrets ride the byte-tolerant reader of the configuration
    // files: a PowerShell-created file carries a byte-order mark the
    // strict UTF-8 read would reject.
    read_config_text(path)
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
    control_master: Option<String>,
    control_path: Option<String>,
    control_persist: Option<String>,
    verify_host_key_dns: Option<String>,
    port: Option<u16>,
    identity_files: Vec<String>,
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
            crate::diag_info!(
                "ssh3: could not open {}: {err}, ignoring config",
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
        control_master: None,
        control_path: None,
        control_persist: None,
        verify_host_key_dns: None,
        port: None,
        identity_files: Vec::new(),
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
    if let Some(value) = get("ControlMaster") {
        parse_control_master_policy(&value)
            .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?;
        values.control_master = Some(value);
    }
    if let Some(value) = get("ControlPath") {
        values.control_path = Some(value);
    }
    if let Some(value) = get("ControlPersist") {
        parse_control_persist(&value).map_err(|err| cli_error(ErrorKind::ValueValidation, err))?;
        values.control_persist = Some(value);
    }
    if let Some(value) = get("VerifyHostKeyDNS") {
        // The value is checked right away: a typo must cost a process start
        // and nothing else.
        ssh3_client::sshfp::VerifyHostKeyDns::parse(&value)
            .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?;
        values.verify_host_key_dns = Some(value);
    }
    if let Some(value) = get("Port") {
        // The value is checked right away: a typo must cost a process start
        // and nothing else.
        values.port = Some(value.trim().parse::<u16>().map_err(|err| {
            cli_error(
                ErrorKind::ValueValidation,
                format!("invalid ssh_config Port {value:?}: {err}"),
            )
        })?);
    }
    // The IdentityFile keyword: every occurrence is a candidate, the first
    // one wins (the reference reads them in order).
    values.identity_files = configuration
        .values_for_user(host, user, "IdentityFile")
        .into_iter()
        .map(|value| value.to_string())
        .collect();
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
    /// The resolved control master settings of the command line.
    ///
    /// Read by the unix control modes only; the Windows build carries it
    /// unresolved by design.
    #[allow(dead_code)]
    control: ControlSettings,
}

/// The policy of the `-M`/`ControlMaster` flag: whether the invocations
/// share one authenticated connection through a control socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlMasterPolicy {
    /// Every invocation opens its own connection.
    No,
    /// The invocation reuses a live master or starts one.
    Yes,
    /// The invocation reuses a live master but never starts one.
    Auto,
}

/// The `-control-persist` semantics: how long a master stays alive without
/// any slave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlPersist {
    /// No master at all (the `no` value).
    No,
    /// The master persists until the exit op or a shutdown.
    Forever,
    /// The master idles out after that many seconds.
    Seconds(u64),
}

/// The resolved control master settings of the command line.
#[derive(Debug)]
#[allow(dead_code)]
struct ControlSettings {
    /// The `-O <op>` operation; `None` for a session invocation.
    operation: Option<String>,
    /// The reuse policy.
    master: ControlMasterPolicy,
    /// The unix socket path of the master.
    path: PathBuf,
    /// The persistence of a started master.
    persist: ControlPersist,
}

/// Parses the value of the `-control-master` keyword: `no`, `yes` or `auto`.
fn parse_control_master_policy(value: &str) -> Result<ControlMasterPolicy, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "no" => Ok(ControlMasterPolicy::No),
        "yes" => Ok(ControlMasterPolicy::Yes),
        "auto" => Ok(ControlMasterPolicy::Auto),
        other => Err(format!(
            "invalid ControlMaster value {other:?}: want no, yes or auto"
        )),
    }
}

/// Parses the value of the `-control-persist` keyword: `no`, `yes` or a
/// number of seconds.
fn parse_control_persist(value: &str) -> Result<ControlPersist, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "no" | "" => Ok(ControlPersist::No),
        "yes" => Ok(ControlPersist::Forever),
        other => other
            .parse::<u64>()
            .map(ControlPersist::Seconds)
            .map_err(|_| {
                format!(
                    "invalid ControlPersist value {other:?}: want no, yes or a number of seconds"
                )
            }),
    }
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
    // The operand of the reference rides the https prefix when the scheme
    // is absent (`max@host/ssh3-term` -> `https://max@host/ssh3-term`),
    // the way the Go client builds the URL from the ssh2-shaped operand.
    let url = if url.starts_with("https://") || url.starts_with("http://") {
        url
    } else {
        format!("https://{url}")
    };
    let url = url.parse::<Uri>().map_err(|err| {
        cli_error(
            ErrorKind::ValueValidation,
            format!("invalid URL {url:?}: {err}"),
        )
    })?;
    // The userinfo of the URL (`max@host`) is the session user of the
    // operand, the spelling of the reference; the `--user` option wins
    // over it.
    let url_user = url
        .authority()
        .and_then(|authority| authority.as_str().split_once('@'))
        .map(|(user, _)| user.to_string());
    let user = cli.user.clone().or(url_user);
    let (config, control) = build_connection_config(cli, url, user)?;
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
        control,
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
    let (config, control) = build_connection_config(cli, url, Some(target.username))?;

    Ok(ClientPlan {
        config,
        request: Ssh3SessionRequest::Shell,
        no_session: false,
        transfer: Some(transfer),
        control,
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
) -> Result<(Ssh3ClientConfig, ControlSettings), clap::Error> {
    // The reference config file of the OIDC flow: the json fields fill the
    // options the command line did not name (the file without the issuer
    // URL stays dormant, like in the Go implementation).
    let oidc_config_file: Option<Ssh3OidcConfigFile> = cli
        .oidc_config
        .as_ref()
        .map(|path| {
            let text = read_config_text(path).map_err(|err| {
                cli_error(ErrorKind::Io, format!("failed to read oidc config: {err}"))
            })?;
            serde_json::from_str(&text).map_err(|err| {
                cli_error(
                    ErrorKind::ValueValidation,
                    format!("invalid oidc config {}: {err}", path.display()),
                )
            })
        })
        .transpose()?;
    let mut cli = cli;
    if let Some(file) = &oidc_config_file {
        if cli.oidc_client_id.is_none() {
            cli.oidc_client_id = Some(file.client_id.clone());
        }
        if cli.oidc_client_secret.is_none() && cli.oidc_client_secret_file.is_none() {
            cli.oidc_client_secret = Some(file.client_secret.clone());
        }
    }
    // The url fields move into the config: the control settings resolve
    // from the copies taken here.
    // The session user rides the URL query (`?user=max`), the way the Go
    // client sends the CONNECT request: the reference server resolves the
    // user from the query, and the `x-ssh3-user` header alone is not read
    // by every implementation.
    let url = match &username {
        Some(user) => {
            let parsed = url::Url::parse(&url.to_string()).map_err(|err| {
                cli_error(
                    ErrorKind::ValueValidation,
                    format!("invalid URL {url}: {err}"),
                )
            })?;
            let already = parsed.query_pairs().any(|(key, _)| key == "user");
            let mut parsed = parsed;
            if !already {
                let mut pairs = parsed.query_pairs_mut();
                pairs.append_pair("user", user);
            }
            // The userinfo of the ssh2-shaped operand stays out of the wire.
            let _ = parsed.set_username("");
            parsed.as_str().parse::<Uri>().map_err(|err| {
                cli_error(
                    ErrorKind::ValueValidation,
                    format!("invalid URL {parsed}: {err}"),
                )
            })?
        }
        None => url,
    };
    let url_host = url.host().map(str::to_string);
    let url_port = url.port_u16().unwrap_or(443);
    let url_has_port = url.port_u16().is_some();
    let mut config = Ssh3ClientConfig::new(url);
    config.server_name = cli.server_name;
    config.username = username;
    config.identity_file = cli.identity;
    config.agent = if cli.agent {
        Some(Ssh3AgentSelection::First)
    } else {
        cli.agent_key.map(Ssh3AgentSelection::PublicKey)
    };
    config.agent_socket = cli.agent_socket;
    config.forward_agent = cli.forward_agent;
    // The `-4`/`-6` flags of the ssh2 canon filter the families of the
    // dial; the `-keylog` file rides the TLS layer of the connection.
    config.ip_family = if cli.ipv4_only {
        Ssh3IpFamily::Ipv4Only
    } else if cli.ipv6_only {
        Ssh3IpFamily::Ipv6Only
    } else {
        Ssh3IpFamily::Any
    };
    config.keylog = cli.keylog;
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
    // The control master fields of the CLI are snapshot before the values
    // of the command line move into the configuration: the unix-only struct
    // fields are gone by the time the control settings resolve.
    #[cfg(unix)]
    let control_cli = (
        cli.master_mode,
        cli.control_operation.clone(),
        cli.control_master.clone(),
        cli.control_socket.clone(),
        cli.control_path.clone(),
        cli.control_persist.clone(),
    );
    #[cfg(not(unix))]
    let control_cli = (
        false,
        None::<String>,
        None::<String>,
        None::<std::path::PathBuf>,
        None::<std::path::PathBuf>,
        None::<String>,
    );

    // The configuration file of the user. The `-F` option names another
    // file; the default one is read when it is not given.
    let ssh_config = load_user_ssh_config(cli.ssh_config.as_deref());
    let ssh_config_values = ssh_config_values(
        &ssh_config,
        config.target_url.host(),
        config.username.as_deref(),
    )?;

    // The IdentityFile keyword of the ssh_config file: the CLI wins over
    // the first candidate of the file (the reference reads them in order).
    if config.identity_file.is_none() {
        config.identity_file = ssh_config_values.identity_files.first().map(PathBuf::from);
    }

    // The `Port` keyword of the ssh_config file applies when the URL did
    // not name a port, like the Go implementation does (`cmd/ssh3.go:868`):
    // the keyword of the file is the last source of the connection port.
    if !url_has_port && let Some(port) = ssh_config_values.port {
        config.target_url = url_with_port(&config.target_url, port).map_err(|err| {
            cli_error(
                ErrorKind::ValueValidation,
                format!("invalid ssh_config Port: {err}"),
            )
        })?;
    }

    // The `-p` option of the ssh2 canon wins over the operand port and the
    // `Port` keyword (the transfer rides the same flag).
    if let Some(port) = cli.port {
        config.target_url = url_with_port(&config.target_url, port)
            .map_err(|err| cli_error(ErrorKind::ValueValidation, format!("invalid port: {err}")))?;
    }

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
    // ssh_config file. The known_hosts layer of the reference is always in
    // the game: the pinned certificate of a host accepts the self-signed
    // release, the public chains keep riding the webpki roots, and the
    // policy decides what happens to an unpinned self-signed one (the
    // default is ask, like in the reference).
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
    } else if !authorities.is_empty() && !policy_is_set {
        Ssh3TrustStrategy::Certificates(authorities)
    } else {
        Ssh3TrustStrategy::KnownHosts(Ssh3KnownHostsTrust {
            policy,
            path: cli
                .known_hosts
                .clone()
                .or_else(default_known_hosts_path)
                .unwrap_or_else(|| PathBuf::from(".ssh3").join("known_hosts")),
            authorities,
        })
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
    // The SSHFP policy comes from the `-o` option first and from the keyword
    // of the ssh_config file next; the parsed form of the winner lands in
    // the configuration (the values above were already validated).
    if let Some(value) = overrides
        .verify_host_key_dns
        .is_some()
        .then(|| overrides.verify_host_key_dns.clone())
        .flatten()
        .or_else(|| {
            ssh_config_values
                .verify_host_key_dns
                .as_deref()
                .map(ssh3_client::sshfp::VerifyHostKeyDns::parse)
                .and_then(Result::ok)
        })
    {
        config.verify_host_key_dns = Some(value);
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

    let control = resolve_control_settings(control_inputs_of(
        control_cli,
        (
            overrides.control_master.clone(),
            overrides.control_path.clone(),
            overrides.control_persist.clone(),
        ),
        (
            ssh_config_values.control_master.clone(),
            ssh_config_values.control_path.clone(),
            ssh_config_values.control_persist.clone(),
        ),
        config.proxy_jump.is_some(),
        config.username.clone(),
        url_host,
        url_port,
    ))?;
    Ok((config, control))
}

/// Rebuilds the URL of the connection with the given port.
///
/// The scheme, the host, the path and the query stay as they are; only the
/// authority carries the port.
fn url_with_port(uri: &Uri, port: u16) -> Result<Uri, String> {
    let host = uri
        .host()
        .ok_or_else(|| "the URL of the connection carries no host".to_string())?;
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    Uri::builder()
        .scheme("https")
        .authority(format!("{host}:{port}").as_str())
        .path_and_query(path_and_query)
        .build()
        .map_err(|err| format!("could not rebuild the URL of the connection: {err}"))
}

/// The raw control master inputs of the command line.
///
/// The `Cli` fields of the control master are unix-only (the struct hides
/// them on Windows), so the flags are read only on unix; the non-unix build
/// carries the empty inputs, and `resolve_control_settings` refuses any
/// control-master request through the keyword channels on its own.
/// The control master fields of the CLI, snapshotted before the values of
/// the command line move into the configuration.
type CliControlFields = (
    bool,
    Option<String>,
    Option<String>,
    Option<std::path::PathBuf>,
    Option<std::path::PathBuf>,
    Option<String>,
);

fn control_inputs_of(
    cli_fields: CliControlFields,
    option_copies: (Option<String>, Option<String>, Option<String>),
    config_copies: (Option<String>, Option<String>, Option<String>),
    proxy_jump_set: bool,
    user: Option<String>,
    host: Option<String>,
    port: u16,
) -> ControlInputs {
    let (master_flag, operation, flag_master, flag_socket, flag_path, flag_persist) = cli_fields;
    ControlInputs {
        master_flag,
        operation,
        flag_master,
        flag_socket,
        flag_path,
        flag_persist,
        option_master: option_copies.0,
        option_path: option_copies.1,
        option_persist: option_copies.2,
        config_master: config_copies.0,
        config_path: config_copies.1,
        config_persist: config_copies.2,
        proxy_jump_set,
        user,
        host,
        port,
    }
}

/// The raw control master inputs of the command line, taken before the
/// values move into the configuration: the flags win over the `-o` options,
/// which win over the ssh_config keywords.
#[allow(dead_code)]
struct ControlInputs {
    master_flag: bool,
    operation: Option<String>,
    flag_master: Option<String>,
    flag_socket: Option<PathBuf>,
    flag_path: Option<PathBuf>,
    flag_persist: Option<String>,
    option_master: Option<String>,
    option_path: Option<String>,
    option_persist: Option<String>,
    config_master: Option<String>,
    config_path: Option<String>,
    config_persist: Option<String>,
    proxy_jump_set: bool,
    user: Option<String>,
    host: Option<String>,
    port: u16,
}

/// Resolves the control master settings of the command line: the flags win
/// over the `-o` options, which win over the ssh_config keywords; the socket
/// path falls back to the default one of the target.
#[allow(unused_variables)]
fn resolve_control_settings(inputs: ControlInputs) -> Result<ControlSettings, clap::Error> {
    #[cfg(not(unix))]
    {
        // The control master is a unix-socket feature: a Windows invocation
        // that asks for it is refused before a packet is sent.
        let asked = inputs.operation.is_some()
            || inputs.flag_master.is_some()
            || inputs.flag_socket.is_some()
            || inputs.flag_path.is_some()
            || inputs.flag_persist.is_some()
            || inputs.option_master.is_some()
            || inputs.option_path.is_some()
            || inputs.option_persist.is_some()
            || inputs.config_master.is_some()
            || inputs.config_path.is_some()
            || inputs.config_persist.is_some();
        if asked {
            return Err(cli_error(
                ErrorKind::ValueValidation,
                "the control master is not available on Windows: the control socket is a unix domain socket",
            ));
        }
        Ok(ControlSettings {
            operation: None,
            master: ControlMasterPolicy::No,
            path: PathBuf::new(),
            persist: ControlPersist::No,
        })
    }
    #[cfg(unix)]
    {
        // The -M flag is the `yes` form of the policy, like in the reference.
        let master = if inputs.master_flag {
            ControlMasterPolicy::Yes
        } else if let Some(value) = inputs
            .flag_master
            .as_deref()
            .or(inputs.option_master.as_deref())
            .or(inputs.config_master.as_deref())
        {
            parse_control_master_policy(value)
                .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?
        } else {
            ControlMasterPolicy::No
        };
        // The reuse of a master through the proxy jump chain is not
        // supported, the way the reference refuses it (the chain dials the
        // hops itself, so there is nothing a control socket could share).
        if master != ControlMasterPolicy::No && inputs.proxy_jump_set {
            return Err(cli_error(
                ErrorKind::ArgumentConflict,
                "the control master is not compatible with the proxy jump chain",
            ));
        }
        let path = inputs
            .flag_socket
            .or(inputs.flag_path)
            .or_else(|| inputs.option_path.map(PathBuf::from))
            .or_else(|| inputs.config_path.map(PathBuf::from))
            .unwrap_or_else(|| {
                ssh3_client::control::default_control_path(
                    inputs.user.as_deref().unwrap_or(""),
                    inputs.host.as_deref().unwrap_or(""),
                    inputs.port,
                )
            });
        let persist = match inputs
            .flag_persist
            .as_deref()
            .or(inputs.option_persist.as_deref())
            .or(inputs.config_persist.as_deref())
        {
            Some(value) => parse_control_persist(value)
                .map_err(|err| cli_error(ErrorKind::ValueValidation, err))?,
            None => ControlPersist::No,
        };
        Ok(ControlSettings {
            operation: inputs.operation,
            master,
            path,
            persist,
        })
    }
}

/// The control master modes of the CLI: the `-O <op>` operations, the daemon
/// mode the master re-executes itself into (`SSH3_CM_DAEMON=1`), and the
/// reuse-or-start policy of the `-M`/`ControlMaster` family. Returns `None`
/// when the invocation goes the direct way, like the reference falls back to
/// a fresh connection.
#[cfg(unix)]
async fn run_control_mode(plan: &ClientPlan) -> Option<ExitCode> {
    use ssh3_client::control;
    use std::time::Duration;

    // The daemon mode: this process is the detached master the CLI
    // re-executed; it serves the socket until a slave sends EXIT or STOP or
    // the idle timeout fires, and never runs a session of its own.
    if std::env::var("SSH3_CM_DAEMON").as_deref() == Ok("1") {
        let client = match control::connect_shared(&plan.config).await {
            Ok(client) => client,
            Err(err) => {
                crate::diag_error!("ssh3 control master: {err}");
                return Some(ExitCode::from(255));
            }
        };
        let listener = match control::listen_control_master(&plan.control.path) {
            Ok(listener) => listener,
            Err(err) => {
                crate::diag_error!("ssh3 control master: {err}");
                return Some(ExitCode::from(255));
            }
        };
        let idle = match plan.control.persist {
            ControlPersist::Seconds(seconds) => Some(Duration::from_secs(seconds)),
            _ => None,
        };
        return Some(
            match control::serve_control_master(client, plan.control.path.clone(), listener, idle)
                .await
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    crate::diag_error!("ssh3 control master: {err}");
                    ExitCode::from(255)
                }
            },
        );
    }

    // The `-O <op>` operations run against a live master and end the process.
    if let Some(op) = plan.control.operation.as_deref() {
        return Some(
            match control::run_control_op(&plan.control.path, op).await {
                Ok(Some(status)) => {
                    println!("{}", status.status_line());
                    ExitCode::SUCCESS
                }
                Ok(None) => ExitCode::SUCCESS,
                Err(err) => {
                    crate::diag_error!("ssh3 control operation {op:?} failed: {err}");
                    ExitCode::from(255)
                }
            },
        );
    }

    match plan.control.master {
        ControlMasterPolicy::No => None,
        ControlMasterPolicy::Auto => {
            // Only the reuse: a live master carries the session, a missing
            // one sends the invocation the direct way.
            if control::ping_master(&plan.control.path).await {
                Some(run_slave(plan).await)
            } else {
                None
            }
        }
        ControlMasterPolicy::Yes => {
            if !control::ping_master(&plan.control.path).await {
                if let Err(err) = start_detached_master() {
                    crate::diag_info!("ssh3: could not start the control master: {err}");
                    return None;
                }
                if !wait_for_master(&plan.control.path).await {
                    crate::diag_info!(
                        "ssh3: the control master did not come up, connecting directly"
                    );
                    return None;
                }
            }
            Some(run_slave(plan).await)
        }
    }
}

/// Runs one session through the control master of the plan: the command line
/// of the request goes over the control socket, a shell request without a
/// local terminal stays a plain pipe session.
#[cfg(unix)]
async fn run_slave(plan: &ClientPlan) -> ExitCode {
    use ssh3_client::control;
    let (command, wants_pty) = match &plan.request {
        Ssh3SessionRequest::Shell => (Vec::new(), true),
        Ssh3SessionRequest::Exec(command) => (vec![command.clone()], false),
    };
    // A pty session drives the local console: the raw mode of the slave
    // matches the direct session, and the console events (a resize, the
    // interrupts of the session process) relay to the master.
    let terminal = if wants_pty {
        ssh3_client::detect_local_terminal().ok().flatten()
    } else {
        None
    };
    let pty = if wants_pty {
        control::local_console_pty(plan.config.term_type.as_deref())
    } else {
        None
    };
    match control::run_slave_session(
        &plan.control.path,
        command,
        pty,
        plan.config.forward_agent,
        terminal,
        tokio::io::stdin(),
        tokio::io::stdout(),
        tokio::io::stderr(),
    )
    .await
    {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            crate::diag_error!("ssh3 control-master session: {err}");
            ExitCode::from(255)
        }
    }
}

/// Re-executes this binary detached with the daemon marker, the way
/// `startDetached` does in the reference: no terminal, own process group.
#[cfg(unix)]
fn start_detached_master() -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    let current = std::env::current_exe()?;
    let child = std::process::Command::new(current)
        .args(std::env::args_os().skip(1))
        .env("SSH3_CM_DAEMON", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()?;
    drop(child);
    Ok(())
}

/// Polls the control socket until a master answers or the deadline passes,
/// the same 2 ms poll step the reference waits with.
#[cfg(unix)]
async fn wait_for_master(path: &Path) -> bool {
    use ssh3_client::control;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !control::ping_master(path).await {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    true
}

/// The long flags the reference writes with a single dash.
///
/// The flag package of the reference accepts `-privkey` and `--privkey`
/// alike, while this parser only accepts the double-dash spelling of the
/// long names: the arguments of the reference spelling are rewritten
/// before the parse, and the single-letter flags (`-i`, `-t`, ...) stay
/// untouched.
const GO_STYLE_LONG_FLAGS: &[&str] = &[
    "agent",
    "agent-key",
    "agent-socket",
    "bearer-token",
    "bearer-token-file",
    "ca-cert",
    "checksum",
    "continue",
    "control-master",
    "control-path",
    "control-persist",
    "forward-agent",
    "identity",
    "insecure",
    "known-hosts",
    "no-pkce",
    "oidc-client-id",
    "oidc-client-secret",
    "oidc-client-secret-file",
    "password",
    "password-file",
    "privkey",
    "proxy-jump",
    "server-name",
    "ssh-config",
    "strict-host-key-checking",
    "transfer",
    "url-path",
    "use-oidc",
    "user",
    "version",
];

/// Rewrites the single-dash long flags of the reference spelling into the
/// double-dash spelling the parser accepts. An argument the reference
/// does not define rides through unchanged, so the unknown-argument
/// error names it the way the user wrote it.
fn go_style_flags<I>(arguments: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    arguments
        .into_iter()
        .map(|argument| {
            let (name, value) = match argument.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (argument.as_str(), None),
            };
            if name.len() > 2
                && name.starts_with('-')
                && !name.starts_with("--")
                && GO_STYLE_LONG_FLAGS.contains(&&name[1..])
            {
                match value {
                    Some(value) => format!("--{}={value}", &name[1..]),
                    None => format!("--{}", &name[1..]),
                }
            } else {
                argument
            }
        })
        .collect()
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse_from(go_style_flags(
        std::env::args_os().map(|argument| argument.to_string_lossy().into_owned()),
    )) {
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
    // The diagnostic level of this invocation rides the `-q` / `-v` pair:
    // the errors stay in every mode, the quiet hides the diagnostics, the
    // verbose adds the connection details.
    ssh3_client::log::configure(cli.quiet, cli.verbose);
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
                crate::diag_error!("ssh3: {err}");
                // the Go implementation leaves the process with the code -1,
                // which the shell sees as 255
                ExitCode::from(255)
            }
        };
    }

    // The control master wiring: the control op, the daemon mode the master
    // re-executes itself into, and the slave sessions. Unix only; the plan
    // of a Windows build never carries control settings.
    #[cfg(unix)]
    if let Some(status) = run_control_mode(&plan).await {
        return status;
    }

    if plan.no_session {
        return match run_forwards_only(&plan.config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                crate::diag_error!("ssh3 failed: {err}");
                ExitCode::FAILURE
            }
        };
    }

    match run_session_stdio(&plan.config, plan.request).await {
        Ok(status) => ExitCode::from(status as u8),
        Err(Ssh3ClientError::ExitSignal(signal)) => {
            let name = String::from_utf8_lossy(&signal.signal_name_without_sig).to_string();
            let code = exit_code_for_exit_signal(name.strip_prefix("SIG").unwrap_or(&name));
            crate::diag_error!("ssh3: the remote process exited with signal {name}");
            ExitCode::from(code as u8)
        }
        Err(err) => {
            crate::diag_error!("ssh3 failed: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, build_config, go_style_flags};
    use clap::{Parser, error::ErrorKind};
    use ssh3_client::{
        SSH3_CLIENT_VERSION_STRING, Ssh3ForwardProtocol, Ssh3PtyPolicy, Ssh3ReverseForwardProtocol,
        Ssh3StrictHostKeyChecking, Ssh3TrustStrategy,
    };
    use std::time::Duration;

    fn config_of(arguments: &[&str]) -> ssh3_client::Ssh3ClientConfig {
        let mut argv = vec!["ssh3"];
        argv.extend_from_slice(arguments);
        argv.push("https://localhost:4433/ssh3-term");
        let cli = Cli::try_parse_from(argv).unwrap();
        build_config(cli).unwrap().config
    }

    /// The three values the command line parsing produces.
    fn parsed_of(arguments: &[&str]) -> (ssh3_client::Ssh3ClientConfig, bool) {
        let mut argv = vec!["ssh3"];
        argv.extend_from_slice(arguments);
        argv.push("https://localhost:4433/ssh3-term");
        let cli = Cli::try_parse_from(argv).unwrap();
        let plan = build_config(cli).unwrap();
        (plan.config, plan.no_session)
    }

    /// The reference writes its long flags with a single dash: the
    /// arguments of that spelling parse as if they were written with the
    /// double dash.
    #[test]
    fn the_reference_single_dash_flags_parse() {
        let cli = Cli::try_parse_from(go_style_flags(
            [
                "ssh3",
                "-privkey",
                "/tmp/id_ed25519",
                "-insecure",
                "-o",
                "ServerAliveInterval=30",
                "https://localhost:4433/ssh3-term",
            ]
            .map(String::from),
        ))
        .unwrap();
        assert_eq!(
            cli.identity.as_deref(),
            Some(std::path::Path::new("/tmp/id_ed25519"))
        );
        assert!(cli.insecure);
        assert!(
            cli.option
                .iter()
                .any(|value| value == "ServerAliveInterval=30")
        );
    }

    /// The single-letter flags stay single-letter: the rewrite touches
    /// only the long names of the reference list, and a glued short
    /// group (`-tT`) rides through untouched.
    #[test]
    fn the_single_letter_flags_stay_single_letter() {
        let cli = Cli::try_parse_from(go_style_flags(
            [
                "ssh3",
                "-t",
                "-N",
                "-L",
                "8080:example.org:80",
                "https://localhost:4433/ssh3-term",
            ]
            .map(String::from),
        ))
        .unwrap();
        assert!(cli.force_pty);
        assert!(cli.no_session);
        assert_eq!(cli.local_forward.len(), 1);
    }

    /// The inline value of a reference flag (`-privkey=path`) rides the
    /// same rewrite.
    #[test]
    fn the_reference_flag_with_an_inline_value_parses() {
        let cli = Cli::try_parse_from(go_style_flags(
            [
                "ssh3",
                "-privkey=/tmp/id_ed25519",
                "https://localhost:4433/ssh3-term",
            ]
            .map(String::from),
        ))
        .unwrap();
        assert_eq!(
            cli.identity.as_deref(),
            Some(std::path::Path::new("/tmp/id_ed25519"))
        );
    }

    /// The ssh2-shaped operand of the reference (`max@host/ssh3-term`)
    /// rides the https prefix of the Go client, and the userinfo of the
    /// operand is the session user.
    #[test]
    fn the_ssh2_shaped_operand_carries_the_user() {
        let cli = Cli::try_parse_from(go_style_flags(
            [
                "ssh3",
                "-privkey",
                "/tmp/id_ed25519",
                "max@example.org/ssh3-term",
            ]
            .map(String::from),
        ))
        .unwrap();
        let plan = build_config(cli).unwrap();
        assert_eq!(plan.config.username.as_deref(), Some("max"));
        assert_eq!(
            plan.config.target_url.host().map(str::to_string).as_deref(),
            Some("example.org")
        );
        // The session user rides the query of the CONNECT request: the
        // reference server resolves the user from it.
        assert_eq!(plan.config.target_url.query(), Some("user=max"));
    }

    /// The `--user` option wins over the user of the operand.
    #[test]
    fn the_user_option_wins_over_the_operand_user() {
        let cli = Cli::try_parse_from(go_style_flags(
            ["ssh3", "--user", "admin", "max@example.org/ssh3-term"].map(String::from),
        ))
        .unwrap();
        let plan = build_config(cli).unwrap();
        assert_eq!(plan.config.username.as_deref(), Some("admin"));
    }

    /// The diagnostic levels of the ssh2 canon: `-q` and `-v` parse
    /// alone and refuse each other.
    #[test]
    fn the_quiet_and_verbose_flags_parse_and_conflict() {
        let cli = Cli::try_parse_from(["ssh3", "-q", "https://localhost:4433/ssh3-term"]).unwrap();
        assert!(cli.quiet);
        assert!(!cli.verbose);

        let cli = Cli::try_parse_from(["ssh3", "-v", "https://localhost:4433/ssh3-term"]).unwrap();
        assert!(cli.verbose);
        assert!(!cli.quiet);

        let err = Cli::try_parse_from(["ssh3", "-q", "-v", "https://localhost:4433/ssh3-term"])
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
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
        let err = Cli::try_parse_from(["ssh3", "-t", "-T", "https://localhost:4433/ssh3-term"])
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn an_invalid_request_tty_policy_is_refused() {
        let err = Cli::try_parse_from([
            "ssh3",
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
        let err = Cli::try_parse_from(["ssh3", "-L", "8080", "https://localhost:4433/ssh3-term"])
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
        let err = Cli::try_parse_from(["ssh3", "-R", "8080", "https://localhost:4433/ssh3-term"])
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
        let err =
            Cli::try_parse_from(["ssh3", "-D", "::1:1080", "https://localhost:4433/ssh3-term"])
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
            "ssh3",
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
            "ssh3",
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
            "ssh3",
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
            "ssh3",
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
    fn the_known_hosts_layer_is_always_in_the_game() {
        let config = config_of(&[]);
        assert!(matches!(config.trust, Ssh3TrustStrategy::KnownHosts(_)));
        // The default policy of the reference is ask: the pinned
        // certificates accept the connection, the public chains keep
        // riding the webpki roots, and an unpinned self-signed one asks.
        assert!(matches!(
            policy_of(&config),
            Some(Ssh3StrictHostKeyChecking::Ask)
        ));
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
    fn the_ssh_config_port_applies_to_a_url_without_one() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(&path, "Host localhost\n  Port 1248\n").unwrap();

        let cli = Cli::try_parse_from([
            "ssh3",
            "--ssh-config",
            path.to_str().unwrap(),
            "https://localhost/ssh3-term",
        ])
        .unwrap();
        let plan = build_config(cli).unwrap();
        assert_eq!(plan.config.target_url.port_u16(), Some(1248));
    }

    #[test]
    fn the_url_port_wins_over_the_ssh_config_keyword() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");
        std::fs::write(&path, "Host localhost\n  Port 1248\n").unwrap();

        let config = config_of(&["--ssh-config", path.to_str().unwrap()]);
        assert_eq!(config.target_url.port_u16(), Some(4433));
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
            "ssh3",
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
        let err =
            Cli::try_parse_from(["ssh3", "-N", "ls", "https://localhost:4433/ssh3-term"]).unwrap();
        let err = build_config(err).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn the_config_file_option_is_parsed() {
        let cli = Cli::try_parse_from([
            "ssh3",
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
            "ssh3",
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
            "ssh3",
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
        let cli = Cli::try_parse_from(["ssh3", "-V"]).unwrap();
        assert!(cli.print_version);
        let cli = Cli::try_parse_from(["ssh3", "--version"]).unwrap();
        assert!(cli.print_version);
    }

    #[test]
    fn the_url_is_required_without_the_version_flag() {
        let err = Cli::try_parse_from(["ssh3"]).unwrap_err();
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

#[cfg(all(test, unix))]
mod control_tests {
    use super::{Cli, ControlMasterPolicy, ControlPersist, build_config};
    use clap::{Parser, error::ErrorKind};

    fn plan_of(arguments: &[&str]) -> super::ClientPlan {
        let mut argv = vec!["ssh3"];
        argv.extend_from_slice(arguments);
        argv.push("https://localhost:4433/ssh3-term");
        let cli = Cli::try_parse_from(argv).unwrap();
        build_config(cli).unwrap()
    }

    fn plan_error(arguments: &[&str]) -> ErrorKind {
        let mut argv = vec!["ssh3"];
        argv.extend_from_slice(arguments);
        argv.push("https://localhost:4433/ssh3-term");
        let cli = Cli::try_parse_from(argv).unwrap();
        build_config(cli).unwrap_err().kind()
    }

    /// The `-M` flag is the `yes` form of the policy and builds the default
    /// control path of the target.
    #[cfg(unix)]
    #[test]
    fn a_master_mode_builds_the_default_control_path() {
        let plan = plan_of(&["-M", "--user", "tester"]);
        assert_eq!(plan.control.master, ControlMasterPolicy::Yes);
        assert!(plan.control.operation.is_none());
        let path = plan.control.path.display().to_string();
        assert!(
            path.contains(".ssh3"),
            "the default path lives in ~/.ssh3: {path}"
        );
        assert!(path.contains("cm-tester@localhost:4433"), "{path}");
    }

    /// The `-o ControlMaster=` keyword follows the flag precedence: the flag
    /// of the command line wins over the `-o` option.
    #[cfg(unix)]
    #[test]
    fn the_control_master_keyword_loses_to_the_flag() {
        let plan = plan_of(&["-M", "-o", "ControlMaster=auto"]);
        assert_eq!(plan.control.master, ControlMasterPolicy::Yes);
        let plan = plan_of(&["-o", "ControlMaster=auto"]);
        assert_eq!(plan.control.master, ControlMasterPolicy::Auto);
        let plan = plan_of(&["-o", "ControlPersist=30"]);
        assert_eq!(plan.control.persist, ControlPersist::Seconds(30));
        let plan = plan_of(&["-o", "ControlPersist=yes"]);
        assert_eq!(plan.control.persist, ControlPersist::Forever);
    }

    /// The reuse of a master through the proxy jump chain is refused, the
    /// way the reference refuses it.
    #[cfg(unix)]
    #[test]
    fn a_master_mode_with_a_proxy_jump_is_refused() {
        assert_eq!(
            plan_error(&["-M", "-o", "ProxyJump=jump.example.org"]),
            ErrorKind::ArgumentConflict
        );
    }

    /// A broken value of the control keywords costs a process start and
    /// nothing else.
    #[test]
    fn an_invalid_control_value_is_refused() {
        assert_eq!(
            plan_error(&["-o", "ControlMaster=maybe"]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            plan_error(&["-o", "ControlPersist=maybe"]),
            ErrorKind::ValueValidation
        );
    }

    /// The `-O` operation and the `-M` mode are mutually exclusive, like the
    /// clap group enforces, and `-O` lands in the plan.
    #[cfg(unix)]
    #[test]
    fn a_control_operation_lands_in_the_plan() {
        let plan = plan_of(&["-O", "check", "--user", "tester"]);
        assert_eq!(plan.control.operation.as_deref(), Some("check"));
    }
}

#[cfg(test)]
mod sshfp_cli_tests {
    use super::{Cli, build_config};
    use clap::Parser;
    use ssh3_client::sshfp::VerifyHostKeyDnsMode;

    fn config_of(arguments: &[&str]) -> ssh3_client::Ssh3ClientConfig {
        let mut argv = vec!["ssh3"];
        argv.extend_from_slice(arguments);
        argv.push("https://localhost:4433/ssh3-term");
        let cli = Cli::try_parse_from(argv).unwrap();
        build_config(cli).unwrap().config
    }

    /// The `-o VerifyHostKeyDNS` option lands in the configuration; a value
    /// the parser refuses costs a process start and nothing else.
    #[test]
    fn the_verify_host_key_dns_option_lands_in_the_config() {
        let config = config_of(&["-o", "VerifyHostKeyDNS=yes"]);
        let setting = config
            .verify_host_key_dns
            .expect("the option sets the policy");
        assert_eq!(setting.mode, VerifyHostKeyDnsMode::Yes);
        assert!(setting.algorithms.is_empty());

        let config = config_of(&["-o", "VerifyHostKeyDNS=ask:ed25519,sha256"]);
        let setting = config
            .verify_host_key_dns
            .expect("the option sets the policy");
        assert_eq!(setting.mode, VerifyHostKeyDnsMode::Ask);
        assert_eq!(setting.algorithms, vec![4, 2]);

        // The default never runs the check.
        let config = config_of(&[]);
        assert!(config.verify_host_key_dns.is_none());

        // A broken value is refused before a packet is sent.
        let mut argv = vec!["ssh3".to_string()];
        argv.push("-o".to_string());
        argv.push("VerifyHostKeyDNS=maybe".to_string());
        argv.push("https://localhost:4433/ssh3-term".to_string());
        let cli = Cli::try_parse_from(argv).unwrap();
        assert!(build_config(cli).is_err());
    }
}
