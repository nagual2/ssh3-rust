use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgGroup, CommandFactory, Parser, ValueHint, error::ErrorKind};
use http::Uri;
use ssh3_client::{
    DEFAULT_HANDSHAKE_IDLE_TIMEOUT, DEFAULT_MAX_IDLE_TIMEOUT, Ssh3AgentSelection, Ssh3ClientConfig,
    Ssh3ClientError, Ssh3LocalForwardSpec, Ssh3OidcConfig, Ssh3PtyPolicy, Ssh3SessionRequest,
    Ssh3TrustStrategy, exit_code_for_exit_signal, load_certificates, parse_duration,
    parse_escape_char, parse_local_forward_spec, run_session_stdio,
};

#[derive(Debug, Parser)]
#[command(
    name = "ssh3-rust-client",
    version,
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

    #[arg(value_name = "URL")]
    url: Uri,

    /// Force the allocation of a pseudo-terminal.
    #[arg(short = 't', conflicts_with = "no_pty")]
    force_pty: bool,

    /// Never allocate a pseudo-terminal.
    #[arg(short = 'T', conflicts_with = "force_pty")]
    no_pty: bool,

    /// Set an option: RequestTTY=auto|yes|no|force, Term=<type>, EscapeChar=<char>.
    #[arg(short = 'o', value_name = "KEY=VALUE")]
    option: Vec<String>,

    /// Forward a local port to the remote host: [bind_address:]port:host:hostport.
    #[arg(short = 'L', value_name = "SPEC")]
    local_forward: Vec<String>,

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

fn build_config(cli: Cli) -> Result<(Ssh3ClientConfig, Ssh3SessionRequest), clap::Error> {
    let mut config = Ssh3ClientConfig::new(cli.url);
    config.server_name = cli.server_name;
    config.username = cli.user;
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
    config.trust = if cli.insecure {
        Ssh3TrustStrategy::Insecure
    } else if let Some(path) = cli.ca_cert {
        Ssh3TrustStrategy::Certificates(load_certificates(&path).map_err(|err| {
            cli_error(
                ErrorKind::ValueValidation,
                format!("failed to load CA certificate: {err}"),
            )
        })?)
    } else {
        Ssh3TrustStrategy::WebPkiRoots
    };

    let overrides = parse_options(&cli.option)?;

    // The RequestTTY precedence follows OpenSSH: the `-T` and `-t` flags are
    // the absolutes, the `-o RequestTTY=` option comes next and `auto` is the
    // default.
    config.pty_policy = overrides.request_tty.unwrap_or(Ssh3PtyPolicy::Auto);
    if cli.no_pty {
        config.pty_policy = Ssh3PtyPolicy::No;
    }
    if cli.force_pty {
        config.pty_policy = Ssh3PtyPolicy::Force;
    }
    config.term_type = overrides.term;
    if let Some(escape_char) = overrides.escape_char {
        config.escape_char = escape_char;
    }

    config.local_forwards = cli
        .local_forward
        .iter()
        .map(|spec| {
            parse_local_forward_spec(spec)
                .map_err(|err| cli_error(ErrorKind::ValueValidation, err.to_string()))
        })
        .collect::<Result<Vec<Ssh3LocalForwardSpec>, clap::Error>>()?;

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

    let request = if cli.command.is_empty() {
        Ssh3SessionRequest::Shell
    } else {
        Ssh3SessionRequest::Exec(cli.command.join(" "))
    };
    Ok((config, request))
}

fn parse_args() -> Result<(Ssh3ClientConfig, Ssh3SessionRequest), clap::Error> {
    build_config(Cli::try_parse()?)
}

#[tokio::main]
async fn main() -> ExitCode {
    let (config, request) = match parse_args() {
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

    match run_session_stdio(&config, request).await {
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
    use ssh3_client::{Ssh3ForwardProtocol, Ssh3PtyPolicy};
    use std::time::Duration;

    fn config_of(arguments: &[&str]) -> ssh3_client::Ssh3ClientConfig {
        let mut argv = vec!["ssh3-rust-client"];
        argv.extend_from_slice(arguments);
        argv.push("https://localhost:4433/ssh3-term");
        let cli = Cli::try_parse_from(argv).unwrap();
        build_config(cli).unwrap().0
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
        let (config, _) = build_config(cli).unwrap();

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
        let (config, _) = build_config(cli).unwrap();

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
}
