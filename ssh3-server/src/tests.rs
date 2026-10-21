//! Integration tests of the server: a real client talks to a real server
//! over a loopback QUIC connection.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use futures_util::future::poll_fn;
use http::header::HeaderValue;
use p256::SecretKey as P256SecretKey;
use rand_core::OsRng;
use rsa::RsaPrivateKey as JwtRsaPrivateKey;
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
use rsa::traits::PublicKeyParts;
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, RsaKeypair};
use ssh3_auth::{build_bearer_token, conversation_id_base64};
use ssh3_core::{Ssh3Channel, Ssh3Conversation};
use ssh3_h3::{
    SSH3_USER_HEADER, SSH3_VERSION_STRING, Ssh3ClientControlStream, Ssh3ClientConversationError,
    Ssh3SendRequest, build_connect_request, establish_client_conversation,
    generate_conversation_id, new_client,
};
use ssh3_proto::{
    SSH_EXTENDED_DATA_NONE, SSH_EXTENDED_DATA_STDERR, Ssh3ChannelRequest,
    Ssh3ChannelRequestMessage, Ssh3ExecRequest, Ssh3ExitStatusRequest, Ssh3Message, Ssh3PtyRequest,
    Ssh3SignalRequest, Ssh3WindowChangeRequest,
};
use ssh3_quinn::{client_config_for_certificate, open_channel, self_signed_server_config};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};

use crate::config::{Ssh3ServerConfig, current_username};
use crate::runtime::serve_connection;
use crate::session::{effective_shell, lookup_session_user};

struct TestHarness {
    client_endpoint: quinn::Endpoint,
    client_connection: quinn::Connection,
    conversation: Arc<Ssh3Conversation>,
    _control_stream: Ssh3ClientControlStream,
    _send_request: Ssh3SendRequest,
    driver_task: tokio::task::JoinHandle<()>,
    server_task: tokio::task::JoinHandle<()>,
}

struct SessionOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: u64,
}

impl TestHarness {
    async fn open_session_channel(&self) -> Arc<Ssh3Channel> {
        open_channel(
            self.conversation.as_ref(),
            &self.client_connection,
            b"session".to_vec(),
            1024,
            10,
        )
        .await
        .unwrap()
    }

    async fn shutdown(self) {
        self.client_connection.close(0u32.into(), b"done");
        let _ = timeout(Duration::from_secs(5), self.driver_task)
            .await
            .unwrap();
        self.client_endpoint.wait_idle().await;
        self.server_task.await.unwrap();
    }
}

async fn attempt_harness_with_headers(
    server_config: Ssh3ServerConfig,
    requested_user: Option<&str>,
    authorization: Option<&str>,
) -> Result<TestHarness, Ssh3ClientConversationError> {
    let (server_config_tls, server_certificate) =
        self_signed_server_config(vec!["localhost".to_string()]).unwrap();
    let server_endpoint = quinn::Endpoint::server(
        server_config_tls,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
    client_endpoint
        .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

    let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let connection = timeout(Duration::from_secs(5), incoming)
            .await
            .unwrap()
            .unwrap();
        timeout(
            Duration::from_secs(10),
            serve_connection(connection, server_config),
        )
        .await
        .unwrap()
        .unwrap();
    });
    let client_connection = timeout(Duration::from_secs(5), client_connecting)
        .await
        .unwrap()
        .unwrap();

    let (mut driver, mut send_request) = new_client(client_connection.clone()).await.unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut request = build_connect_request(
        "https://localhost/ssh3-term".parse().unwrap(),
        SSH3_VERSION_STRING,
    )
    .unwrap();
    if let Some(requested_user) = requested_user {
        request.headers_mut().insert(
            SSH3_USER_HEADER,
            HeaderValue::from_str(requested_user).unwrap(),
        );
    }
    if let Some(authorization) = authorization {
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(authorization).unwrap(),
        );
    }
    let established = timeout(
        Duration::from_secs(5),
        establish_client_conversation(
            &mut send_request,
            client_connection.clone(),
            request,
            30_000,
            10,
        ),
    )
    .await
    .unwrap();
    let established = match established {
        Ok(established) => established,
        Err(err) => {
            client_connection.close(0u32.into(), b"done");
            let _ = timeout(Duration::from_secs(5), driver_task).await.unwrap();
            client_endpoint.wait_idle().await;
            server_task.await.unwrap();
            return Err(err);
        }
    };

    Ok(TestHarness {
        client_endpoint,
        client_connection,
        conversation: established.conversation,
        _control_stream: established.control_stream,
        _send_request: send_request,
        driver_task,
        server_task,
    })
}

async fn attempt_oidc_harness(
    server_config: Ssh3ServerConfig,
    requested_user: Option<&str>,
    fixture: &OidcFixture,
) -> Result<TestHarness, Ssh3ClientConversationError> {
    let (server_config_tls, server_certificate) =
        self_signed_server_config(vec!["localhost".to_string()]).unwrap();
    let server_endpoint = quinn::Endpoint::server(
        server_config_tls,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
    client_endpoint
        .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

    let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let connection = timeout(Duration::from_secs(5), incoming)
            .await
            .unwrap()
            .unwrap();
        timeout(
            Duration::from_secs(10),
            serve_connection(connection, server_config),
        )
        .await
        .unwrap()
        .unwrap();
    });
    let client_connection = timeout(Duration::from_secs(5), client_connecting)
        .await
        .unwrap()
        .unwrap();

    let (mut driver, mut send_request) = new_client(client_connection.clone()).await.unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let conversation_id = generate_conversation_id(&client_connection).unwrap();
    let mut request = build_connect_request(
        "https://localhost/ssh3-term".parse().unwrap(),
        SSH3_VERSION_STRING,
    )
    .unwrap();
    if let Some(requested_user) = requested_user {
        request.headers_mut().insert(
            SSH3_USER_HEADER,
            HeaderValue::from_str(requested_user).unwrap(),
        );
    }
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&fixture.authorization_for_conversation(&conversation_id)).unwrap(),
    );
    let established = timeout(
        Duration::from_secs(5),
        establish_client_conversation(
            &mut send_request,
            client_connection.clone(),
            request,
            30_000,
            10,
        ),
    )
    .await
    .unwrap()?;

    driver_task.abort();
    Ok(TestHarness {
        client_endpoint,
        client_connection,
        conversation: established.conversation,
        _control_stream: established.control_stream,
        _send_request: send_request,
        driver_task,
        server_task,
    })
}

async fn attempt_harness(
    server_config: Ssh3ServerConfig,
    requested_user: Option<&str>,
) -> Result<TestHarness, Ssh3ClientConversationError> {
    attempt_harness_with_headers(server_config, requested_user, None).await
}

async fn attempt_authenticated_harness(
    server_config: Ssh3ServerConfig,
    requested_user: &str,
    private_key: &ssh_key::PrivateKey,
    username: &str,
) -> Result<TestHarness, Ssh3ClientConversationError> {
    let (server_config_tls, server_certificate) =
        self_signed_server_config(vec!["localhost".to_string()]).unwrap();
    let server_endpoint = quinn::Endpoint::server(
        server_config_tls,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
    client_endpoint
        .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

    let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let connection = timeout(Duration::from_secs(5), incoming)
            .await
            .unwrap()
            .unwrap();
        timeout(
            Duration::from_secs(10),
            serve_connection(connection, server_config),
        )
        .await
        .unwrap()
        .unwrap();
    });
    let client_connection = timeout(Duration::from_secs(5), client_connecting)
        .await
        .unwrap()
        .unwrap();

    let (mut driver, mut send_request) = new_client(client_connection.clone()).await.unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let conversation_id = generate_conversation_id(&client_connection).unwrap();
    let mut request = build_connect_request(
        "https://localhost/ssh3-term".parse().unwrap(),
        SSH3_VERSION_STRING,
    )
    .unwrap();
    request.headers_mut().insert(
        SSH3_USER_HEADER,
        HeaderValue::from_str(requested_user).unwrap(),
    );
    let token = build_bearer_token(private_key, username, &conversation_id).unwrap();
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );

    let established = timeout(
        Duration::from_secs(5),
        establish_client_conversation(
            &mut send_request,
            client_connection.clone(),
            request,
            30_000,
            10,
        ),
    )
    .await
    .unwrap();
    let established = match established {
        Ok(established) => established,
        Err(err) => {
            client_connection.close(0u32.into(), b"done");
            let _ = timeout(Duration::from_secs(5), driver_task).await.unwrap();
            client_endpoint.wait_idle().await;
            server_task.await.unwrap();
            return Err(err);
        }
    };

    Ok(TestHarness {
        client_endpoint,
        client_connection,
        conversation: established.conversation,
        _control_stream: established.control_stream,
        _send_request: send_request,
        driver_task,
        server_task,
    })
}

async fn setup_harness(server_config: Ssh3ServerConfig) -> TestHarness {
    attempt_harness(server_config, None).await.unwrap()
}

async fn collect_session_output(channel: Arc<Ssh3Channel>) -> SessionOutput {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        let message = timeout(Duration::from_secs(5), channel.next_message())
            .await
            .unwrap()
            .unwrap();
        match message {
            Ssh3Message::Data(data) => match data.data_type {
                SSH_EXTENDED_DATA_NONE => stdout.extend_from_slice(&data.data),
                SSH_EXTENDED_DATA_STDERR => stderr.extend_from_slice(&data.data),
                _ => {}
            },
            Ssh3Message::ChannelRequest(message) => {
                if let Ssh3ChannelRequest::ExitStatus(Ssh3ExitStatusRequest { exit_status }) =
                    message.request
                {
                    return SessionOutput {
                        stdout,
                        stderr,
                        exit_status,
                    };
                }
            }
            _ => {}
        }
    }
}

fn normalize_pty_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n")
}

fn basic_authorization(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{username}:{password}"))
    )
}

struct AuthFixture {
    _tempdir: TempDir,
    authorized_identities_path: PathBuf,
    private_key: ssh_key::PrivateKey,
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
            ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[21; 32]))
        }
        AuthKeyAlgorithm::NistP256 => {
            let secret_key = P256SecretKey::from_slice(&[23; 32]).unwrap();
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

fn create_auth_fixture(algorithm: AuthKeyAlgorithm) -> AuthFixture {
    let tempdir = TempDir::new().unwrap();
    let authorized_identities_path = tempdir.path().join("authorized_keys");
    let private_key = auth_private_key(algorithm);
    fs::write(
        &authorized_identities_path,
        format!("{}\n", private_key.public_key().to_openssh().unwrap()),
    )
    .unwrap();

    AuthFixture {
        _tempdir: tempdir,
        authorized_identities_path,
        private_key,
        username: current_username().unwrap(),
    }
}

struct OidcFixture {
    _tempdir: TempDir,
    authorized_identities_path: PathBuf,
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
    fn authorization_for_conversation(&self, conversation_id: &[u8; 32]) -> String {
        build_oidc_token(
            &self.issuer_url,
            &self.client_id,
            &self.email,
            Some(&conversation_id_base64(conversation_id)),
            &self.signing_key,
        )
    }
}

async fn read_http_request_path(
    stream: &mut tokio::net::TcpStream,
) -> Result<String, std::io::Error> {
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

    Ok(String::from_utf8_lossy(&buffer)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string())
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
    let signature: RsaSignature = Signer::try_sign(&signing_key, signing_input.as_bytes()).unwrap();
    format!(
        "Bearer {signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_vec())
    )
}

async fn create_oidc_fixture() -> OidcFixture {
    let tempdir = TempDir::new().unwrap();
    let authorized_identities_path = tempdir.path().join("authorized_identities");
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let issuer_url = format!("http://{}", listener.local_addr().unwrap());
    let client_id = "ssh3-client-id";
    let email = "alice@example.com";
    let signing_key = JwtRsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = signing_key.to_public_key();
    let discovery_body = format!(r#"{{"issuer":"{issuer_url}","jwks_uri":"{issuer_url}/keys"}}"#);
    let jwks_body = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"test-key","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
        URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
        URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
    );
    let provider_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let discovery_body = discovery_body.clone();
            let jwks_body = jwks_body.clone();
            tokio::spawn(async move {
                let path = read_http_request_path(&mut stream).await.unwrap();
                let (status_line, body) = match path.as_str() {
                    "/.well-known/openid-configuration" => ("HTTP/1.1 200 OK", discovery_body),
                    "/keys" => ("HTTP/1.1 200 OK", jwks_body),
                    _ => ("HTTP/1.1 404 Not Found", "{}".to_string()),
                };
                let response = format!(
                    "{status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
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
        client_id: client_id.to_string(),
        email: email.to_string(),
        signing_key,
        username: current_username().unwrap(),
        provider_task,
    }
}

#[tokio::test]
async fn exec_requests_run_commands_and_report_exit_status() {
    let harness = setup_harness(Ssh3ServerConfig::default()).await;
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"printf 'hello from rust\\n'".to_vec(),
            }),
        })
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    assert_eq!(output.stdout, b"hello from rust\n".to_vec());
    assert!(output.stderr.is_empty());
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn pty_requests_create_a_tty_and_apply_live_window_changes() {
    let harness = setup_harness(Ssh3ServerConfig::default()).await;
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Pty(Ssh3PtyRequest {
                term: b"vt100".to_vec(),
                char_width: 40,
                char_height: 12,
                pixel_width: 0,
                pixel_height: 0,
                encoded_terminal_modes: Vec::new(),
            }),
        })
        .await
        .unwrap();
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"sleep 0.2; if [ -t 0 ]; then printf 'pty:%s ' \"$TERM\"; stty size; else printf 'notty\\n'; fi".to_vec(),
            }),
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(50)).await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::WindowChange(Ssh3WindowChangeRequest {
                char_width: 61,
                char_height: 19,
                pixel_width: 0,
                pixel_height: 0,
            }),
        })
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    let stdout = normalize_pty_output(&output.stdout);
    assert!(stdout.starts_with("pty:vt100 "));
    assert!(
        stdout.contains("19 61"),
        "unexpected PTY output: {stdout:?}"
    );
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn signal_requests_are_forwarded_to_the_running_session() {
    let harness = setup_harness(Ssh3ServerConfig::default()).await;
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"trap 'printf trapped\\n; exit 0' TERM; while :; do sleep 1; done"
                    .to_vec(),
            }),
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(100)).await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::Signal(Ssh3SignalRequest {
                signal_name_without_sig: b"TERM".to_vec(),
            }),
        })
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    assert!(String::from_utf8_lossy(&output.stdout).contains("trapped"));
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn requested_user_header_selects_the_session_environment() {
    let username = current_username().expect("current user should resolve");
    let session_user = lookup_session_user(&username).unwrap();
    let config = Ssh3ServerConfig {
        default_user: Some("does-not-exist".to_string()),
        ..Default::default()
    };
    let expected_shell = effective_shell(&config, &session_user);

    let harness = attempt_harness(config.clone(), Some(&username))
        .await
        .unwrap();
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"printf '%s|%s|%s\\n' \"$HOME\" \"$USER\" \"$SHELL\"".to_vec(),
            }),
        })
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim_end(),
        format!(
            "{}|{}|{}",
            session_user.home_dir.display(),
            username,
            expected_shell.display()
        )
    );
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn bearer_tokens_authorize_session_startup() {
    let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
    let config = Ssh3ServerConfig {
        require_authentication: true,
        authorized_identity_paths: vec![fixture.authorized_identities_path.clone()],
        default_user: Some("does-not-exist".to_string()),
        ..Default::default()
    };

    let harness = attempt_authenticated_harness(
        config,
        &fixture.username,
        &fixture.private_key,
        &fixture.username,
    )
    .await
    .unwrap();
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"printf 'authenticated\\n'".to_vec(),
            }),
        })
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    assert_eq!(output.stdout, b"authenticated\n".to_vec());
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn missing_bearer_token_is_rejected_when_auth_is_required() {
    let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
    let config = Ssh3ServerConfig {
        require_authentication: true,
        authorized_identity_paths: vec![fixture.authorized_identities_path.clone()],
        default_user: Some("does-not-exist".to_string()),
        ..Default::default()
    };

    match attempt_harness(config, Some(&fixture.username)).await {
        Err(Ssh3ClientConversationError::UnexpectedStatus { status }) => {
            assert_eq!(status, http::StatusCode::UNAUTHORIZED);
        }
        Err(Ssh3ClientConversationError::Stream(err)) if err.is_h3_no_error() => {}
        Err(other) => panic!("expected auth rejection, got {other:?}"),
        Ok(_) => panic!("expected auth rejection"),
    }
}

#[tokio::test]
async fn oidc_identity_tokens_authorize_session_startup() {
    let fixture = create_oidc_fixture().await;
    let config = Ssh3ServerConfig {
        require_authentication: true,
        authorized_identity_paths: vec![fixture.authorized_identities_path.clone()],
        default_user: Some("does-not-exist".to_string()),
        ..Default::default()
    };

    let harness = attempt_oidc_harness(config, Some(&fixture.username), &fixture)
        .await
        .unwrap();
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"printf 'authenticated via oidc\\n'".to_vec(),
            }),
        })
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    assert_eq!(output.stdout, b"authenticated via oidc\n".to_vec());
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn basic_password_auth_authorizes_session_startup() {
    let username = current_username().unwrap();
    let password = "correct horse battery staple";
    let config = Ssh3ServerConfig {
        enable_password_login: true,
        default_user: Some("does-not-exist".to_string()),
        password_verifier: Some(Arc::new({
            let username = username.clone();
            move |candidate_username, candidate_password| {
                Ok(candidate_username == username && candidate_password == password)
            }
        })),
        ..Default::default()
    };

    let harness = attempt_harness_with_headers(
        config,
        None,
        Some(&basic_authorization(&username, password)),
    )
    .await
    .unwrap();
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"printf 'authenticated via password\\n'".to_vec(),
            }),
        })
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    assert_eq!(output.stdout, b"authenticated via password\n".to_vec());
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn missing_basic_auth_is_rejected_when_password_login_is_required() {
    let config = Ssh3ServerConfig {
        enable_password_login: true,
        default_user: Some(current_username().unwrap()),
        password_verifier: Some(Arc::new(|_, _| Ok(false))),
        ..Default::default()
    };

    match attempt_harness(config, None).await {
        Err(Ssh3ClientConversationError::UnexpectedStatus { status }) => {
            assert_eq!(status, http::StatusCode::UNAUTHORIZED);
        }
        Err(Ssh3ClientConversationError::Stream(err)) if err.is_h3_no_error() => {}
        Err(other) => panic!("expected auth rejection, got {other:?}"),
        Ok(_) => panic!("expected auth rejection"),
    }
}

#[tokio::test]
async fn nist_p256_bearer_tokens_authorize_session_startup() {
    let fixture = create_auth_fixture(AuthKeyAlgorithm::NistP256);
    let config = Ssh3ServerConfig {
        require_authentication: true,
        authorized_identity_paths: vec![fixture.authorized_identities_path.clone()],
        default_user: Some("does-not-exist".to_string()),
        ..Default::default()
    };

    let harness = attempt_authenticated_harness(
        config,
        &fixture.username,
        &fixture.private_key,
        &fixture.username,
    )
    .await
    .unwrap();
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"printf 'authenticated via p256\\n'".to_vec(),
            }),
        })
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    assert_eq!(output.stdout, b"authenticated via p256\n".to_vec());
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn rsa_bearer_tokens_authorize_session_startup() {
    let fixture = create_auth_fixture(AuthKeyAlgorithm::Rsa);
    let config = Ssh3ServerConfig {
        require_authentication: true,
        authorized_identity_paths: vec![fixture.authorized_identities_path.clone()],
        default_user: Some("does-not-exist".to_string()),
        ..Default::default()
    };

    let harness = attempt_authenticated_harness(
        config,
        &fixture.username,
        &fixture.private_key,
        &fixture.username,
    )
    .await
    .unwrap();
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"printf 'authenticated via rsa\\n'".to_vec(),
            }),
        })
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    assert_eq!(output.stdout, b"authenticated via rsa\n".to_vec());
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn shell_requests_start_a_login_shell() {
    let harness = setup_harness(Ssh3ServerConfig::default()).await;
    let channel = harness.open_session_channel().await;
    channel
        .send_request(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Shell,
        })
        .await
        .unwrap();
    channel
        .write_data(b"printf '%s\\n' \"$0\"\nexit\n", SSH_EXTENDED_DATA_NONE)
        .await
        .unwrap();

    let output = collect_session_output(channel).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.lines().any(|line| line.starts_with('-')),
        "expected a login shell argv[0], got {stdout:?}"
    );
    assert_eq!(output.exit_status, 0);

    harness.shutdown().await;
}

#[tokio::test]
async fn missing_requested_and_default_user_is_rejected() {
    let config = Ssh3ServerConfig {
        default_user: None,
        ..Default::default()
    };

    let (server_config_tls, server_certificate) =
        self_signed_server_config(vec!["localhost".to_string()]).unwrap();
    let server_endpoint = quinn::Endpoint::server(
        server_config_tls,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
    client_endpoint
        .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

    let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let connection = timeout(Duration::from_secs(5), incoming)
            .await
            .unwrap()
            .unwrap();
        timeout(
            Duration::from_secs(10),
            serve_connection(connection, config),
        )
        .await
        .unwrap()
        .unwrap();
    });

    let client_connection = timeout(Duration::from_secs(5), client_connecting)
        .await
        .unwrap()
        .unwrap();
    let (mut driver, mut send_request) = new_client(client_connection.clone()).await.unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let request = build_connect_request(
        "https://localhost/ssh3-term".parse().unwrap(),
        SSH3_VERSION_STRING,
    )
    .unwrap();
    let mut stream = send_request.send_request(request).await.unwrap();
    match timeout(Duration::from_secs(5), stream.recv_response())
        .await
        .unwrap()
    {
        Ok(response) => assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED),
        Err(err) if err.is_h3_no_error() => {}
        Err(other) => panic!("expected unauthorized response or clean close, got {other:?}"),
    }

    client_connection.close(0u32.into(), b"done");
    let _ = timeout(Duration::from_secs(5), driver_task).await.unwrap();
    client_endpoint.wait_idle().await;
    server_task.await.unwrap();
}
