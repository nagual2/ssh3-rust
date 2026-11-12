//! TLS bootstrap of the server.
//!
//! The server can either own its TLS material — generating a self-signed
//! certificate for the configured subject alternative names, or loading the
//! operator's PEM files (the `-cert`/`-key` pair of the reference) — or run
//! on top of an endpoint the caller has already configured.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;

use quinn::{Endpoint, ServerConfig};
use ssh3_quinn::{
    CertificateDer, PrivateKeyDer, self_signed_server_config, server_config_with_single_cert,
};

use crate::config::{Ssh3ServerConfig, validate_server_config};
use crate::error::Ssh3ServerError;
use crate::log_warn;
use crate::runtime::serve_endpoint_until_shutdown;
use crate::shutdown::{ShutdownSignal, shutdown_signal};

/// Applies the configured QUIC transport limits to a server configuration.
///
/// The idle timeout of the transport is the `max-idle-timeout` of the server;
/// the handshake timeout is enforced by the runtime, which gives up on a
/// connection that does not complete its handshake in time. The stream caps
/// are the `-max-incoming-streams` / `-max-incoming-uni-streams` options of
/// the audit of 2026-10-27 (K3): the peer cannot open more concurrent streams
/// per connection than the caps allow.
pub fn apply_transport_limits(server_config: &mut ServerConfig, config: &Ssh3ServerConfig) {
    server_config.transport = Arc::new(server_transport_config(config));
}

/// Builds the QUIC transport configuration of the server.
///
/// Split from [`apply_transport_limits`] so the tests can pin the transport
/// knobs of the reference (the disabled path MTU discovery) without binding
/// an endpoint.
fn server_transport_config(config: &Ssh3ServerConfig) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    // SSH3 carries its UDP forwarding over the raw QUIC datagram API: the
    // frame size parameter announces the ability to receive them. Without
    // it a peer that speaks only quinn (the Rust client of a proxy jump
    // chain, a local UDP forward) cannot send a single datagram.
    transport.datagram_receive_buffer_size(Some(65_535));
    transport.max_idle_timeout(match quinn::IdleTimeout::try_from(config.max_idle_timeout) {
        Ok(idle_timeout) => Some(idle_timeout),
        Err(_) => {
            log_warn!(
                "ssh3-rust-server the idle timeout of {}s does not fit into the QUIC transport parameters, the idle timeout is disabled",
                config.max_idle_timeout.as_secs()
            );
            None
        }
    });
    transport.max_concurrent_bidi_streams(config.max_incoming_streams.into());
    transport.max_concurrent_uni_streams(config.max_incoming_uni_streams.into());
    // The `-initial-packet-size` of the reference rides the transport: the
    // quinn builder floors the value at the QUIC minimum, the way the Go
    // reference ignores a size below it (`cmd/ssh3-server.go`).
    ssh3_quinn::apply_initial_packet_size(&mut transport, config.initial_packet_size);
    // The reference never grows the packets of its server past the initial
    // size (`cmd/ssh3-server.go`, `DisablePathMTUDiscovery: true`): the
    // discovery has nothing to learn.
    ssh3_quinn::disable_path_mtu_discovery(&mut transport);
    transport
}

/// Serves SSH3 with a freshly generated self-signed certificate.
///
/// A certificate is created for `config.cert_subject_alt_names`, the QUIC
/// endpoint is bound to `config.bind_addr` and connections are accepted until
/// the endpoint stops yielding incoming connections. On a shutdown signal
/// (`SIGINT`/`SIGTERM` on Unix, Ctrl-C on Windows) the endpoint stops
/// accepting new connections and the conversations being served drain up to
/// the `shutdown_drain` window of the configuration before the call returns.
///
/// Use [`run_with_certificates`] when the operator provides the certificate
/// and key files, [`serve_endpoint`](crate::serve_endpoint) when the caller
/// provides its own certificate or key, and
/// [`serve_endpoint_until_shutdown`](crate::serve_endpoint_until_shutdown)
/// when the caller owns the shutdown signal as well.
pub async fn run_with_self_signed(config: Ssh3ServerConfig) -> Result<(), Ssh3ServerError> {
    validate_server_config(&config)?;
    let (server_config, _certificate) =
        self_signed_server_config(config.cert_subject_alt_names.clone())?;
    run_server_config(config, server_config).await
}

/// Serves SSH3 with the operator's certificate and private key, the
/// `-cert`/`-key` pair of the reference (`cmd/ssh3-server.go:969-970`).
///
/// The PEM files are loaded once at startup with [`load_identity`]: a missing
/// or broken file refuses the start before any socket is bound, the way the
/// `tls.LoadX509KeyPair` failure of the reference does
/// (`cmd/ssh3-server.go:1286-1293`). The files are never re-read while the
/// server runs — the reference does not watch them either (its only renewal
/// is the ACME rotation of `-generate-public-cert`), so a new identity takes
/// a restart. Everything else — the bind, the accept loop and the graceful
/// shutdown — behaves like [`run_with_self_signed`].
pub async fn run_with_certificates(
    config: Ssh3ServerConfig,
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<(), Ssh3ServerError> {
    validate_server_config(&config)?;
    let (cert_chain, key) = load_identity(cert_path, key_path)?;
    let server_config =
        server_config_with_single_cert(cert_chain, key).map_err(Ssh3ServerError::Config)?;
    run_server_config(config, server_config).await
}

/// Binds the endpoint of a ready TLS server configuration and serves it with
/// the graceful shutdown wiring of the reference.
///
/// The shared tail of [`run_with_self_signed`] and [`run_with_certificates`]:
/// the transport limits of the configuration ride the server configuration,
/// the QUIC endpoint binds to `config.bind_addr`, and the operator's signal
/// asks the runtime to stop accepting and to drain the conversations.
async fn run_server_config(
    config: Ssh3ServerConfig,
    mut server_config: ServerConfig,
) -> Result<(), Ssh3ServerError> {
    apply_transport_limits(&mut server_config, &config);
    let endpoint = Endpoint::server(server_config, config.bind_addr)?;
    let shutdown = ShutdownSignal::new();
    let signal_task = shutdown.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        signal_task.trigger();
    });
    serve_endpoint_until_shutdown(endpoint, config, shutdown).await
}

/// Loads the certificate chain and the private key of the server from PEM
/// files, the `-cert`/`-key` pair of the reference.
///
/// The chain file may hold a single certificate or a fullchain, the way the
/// `LoadX509KeyPair` of the reference accepts one (`cmd/ssh3-server.go:969`).
/// The key file may hold any PEM spelling `rustls` understands (PKCS8, PKCS1
/// or SEC1). The errors mirror the readable refusals of the reference: a
/// missing file names the file (`cmd/ssh3-server.go:1191-1194`), a broken
/// one is reported as a pair-load failure (`cmd/ssh3-server.go:1289`).
pub fn load_identity(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Ssh3ServerError> {
    let cert_path = cert_path.as_ref();
    let key_path = key_path.as_ref();
    let cert_bytes = read_identity_file(cert_path, "certificate")?;
    let cert_chain = parse_certificates(cert_path, &cert_bytes)?;
    let key_bytes = read_identity_file(key_path, "certificate private key")?;
    let key = parse_private_key(key_path, &key_bytes)?;
    Ok((cert_chain, key))
}

/// Reads one of the identity files, naming it the way the reference names
/// the files of a half-configured pair (`cmd/ssh3-server.go:1191-1194`).
fn read_identity_file(path: &Path, what: &str) -> Result<Vec<u8>, Ssh3ServerError> {
    fs::read(path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("the \"{}\" {what} file does not exist", path.display()),
            )
        } else {
            io::Error::new(
                err.kind(),
                format!(
                    "could not load the -cert and -key pair: {}: {}",
                    path.display(),
                    err
                ),
            )
        }
        .into()
    })
}

/// Parses the certificate chain out of a PEM cert file.
///
/// PEM only, the `tls.LoadX509KeyPair` posture of the reference: an input
/// with no PEM data is a load failure, not a DER fallback
/// (`cmd/ssh3-server.go:1286-1293`).
fn parse_certificates(
    path: &Path,
    bytes: &[u8],
) -> Result<Vec<CertificateDer<'static>>, Ssh3ServerError> {
    let mut bytes = bytes;
    let certificates = rustls_pemfile::certs(&mut bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| pair_load_error(path, err))?;
    if certificates.is_empty() {
        return Err(pair_load_error(path, "no certificate in the file"));
    }
    Ok(certificates)
}

/// Parses the private key out of a PEM key file.
///
/// PEM only, like the reference: the key of the `LoadX509KeyPair` input
/// comes from a `PRIVATE KEY` block (`cmd/ssh3-server.go:1286-1293`).
fn parse_private_key(path: &Path, bytes: &[u8]) -> Result<PrivateKeyDer<'static>, Ssh3ServerError> {
    let mut bytes = bytes;
    let key = rustls_pemfile::private_key(&mut bytes).map_err(|err| pair_load_error(path, err))?;
    key.ok_or_else(|| pair_load_error(path, "no private key in the file"))
}

/// The readable refusal of a broken identity file, the "Could not load -cert
/// and -key pair" message of the reference (`cmd/ssh3-server.go:1289`).
fn pair_load_error(path: &Path, err: impl fmt::Display) -> Ssh3ServerError {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "could not load the -cert and -key pair: {}: {err}",
            path.display()
        ),
    )
    .into()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use futures_util::future::poll_fn;
    use ssh3_h3::{
        SSH3_VERSION_STRING, build_connect_request, establish_client_conversation, new_client,
    };
    use ssh3_quinn::{client_config_for_certificate, client_config_with_webpki_roots};
    use tokio::time::timeout;

    use crate::config::Ssh3ServerConfig;
    use crate::runtime::serve_endpoint;

    /// Writes a fresh self-signed identity into a directory of a test, the
    /// PEM pair an operator would hand to `-cert`/`-key`.
    fn write_identity_files(dir: &Path) -> (PathBuf, PathBuf) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        fs::write(&cert_path, cert.pem()).unwrap();
        fs::write(&key_path, key.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    /// Loads the certificates of a PEM file back, the `--ca-cert` shape of
    /// the client: the trust roots come from the file of the operator.
    fn certificates_of_file(path: &Path) -> Vec<ssh3_quinn::CertificateDer<'static>> {
        let bytes = fs::read(path).unwrap();
        rustls_pemfile::certs(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// The server keeps the path MTU discovery off, the posture of the
    /// reference (`cmd/ssh3-server.go`, `DisablePathMTUDiscovery: true`):
    /// the packets stay at the initial size instead of growing towards the
    /// path MTU.
    #[test]
    fn the_server_keeps_the_path_mtu_discovery_off() {
        let transport = super::server_transport_config(&Ssh3ServerConfig::default());
        assert!(
            format!("{transport:?}").contains("mtu_discovery_config: None"),
            "{transport:?}"
        );
    }

    /// The identity files of the reference load into a chain and a key: the
    /// `-cert` fullchain and the PEM private key
    /// (`cmd/ssh3-server.go:1286-1293`).
    #[test]
    fn the_identity_files_load_into_a_chain_and_a_key() {
        let directory = tempfile::TempDir::new().unwrap();
        let (cert_path, key_path) = write_identity_files(directory.path());
        let (chain, _key) = super::load_identity(&cert_path, &key_path).unwrap();
        assert_eq!(chain.len(), 1, "the single certificate of the test");
    }

    /// A missing file of the half-configured pair is named by the error, the
    /// readable refusal of the reference (`cmd/ssh3-server.go:1191-1194`).
    #[test]
    fn a_missing_identity_file_is_named_by_the_error() {
        let directory = tempfile::TempDir::new().unwrap();
        let (cert_path, key_path) = write_identity_files(directory.path());
        let err =
            super::load_identity(&cert_path, directory.path().join("absent.key")).unwrap_err();
        assert!(
            err.to_string()
                .contains("certificate private key file does not exist"),
            "{err}"
        );
        let err = super::load_identity(directory.path().join("absent.pem"), &key_path).unwrap_err();
        assert!(
            err.to_string().contains("certificate file does not exist"),
            "{err}"
        );
    }

    /// A broken or empty PEM refuses the start with the pair-load message of
    /// the reference (`cmd/ssh3-server.go:1289`).
    #[test]
    fn a_broken_identity_file_refuses_the_load() {
        let directory = tempfile::TempDir::new().unwrap();
        let (cert_path, key_path) = write_identity_files(directory.path());
        fs::write(&cert_path, "not a pem at all\n").unwrap();
        let err = super::load_identity(&cert_path, &key_path).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("could not load the -cert and -key pair:"),
            "{err}"
        );

        let (cert_path, key_path) = write_identity_files(directory.path());
        fs::write(&key_path, b"").unwrap();
        let err = super::load_identity(&cert_path, &key_path).unwrap_err();
        assert!(
            err.to_string().contains("no private key in the file"),
            "{err}"
        );

        // a garbage key refuses the same way: the reference reads PEM only
        let (cert_path, key_path) = write_identity_files(directory.path());
        fs::write(&key_path, "not a pem at all\n").unwrap();
        let err = super::load_identity(&cert_path, &key_path).unwrap_err();
        assert!(
            err.to_string().contains("no private key in the file"),
            "{err}"
        );
    }

    /// A server with its own certificate files accepts a client that trusts
    /// the certificate file — the `--ca-cert` shape of the client — and the
    /// conversation rides the loaded identity.
    #[tokio::test]
    async fn a_server_with_own_certificate_files_accepts_a_client_trusting_the_ca() {
        let directory = tempfile::TempDir::new().unwrap();
        let (cert_path, key_path) = write_identity_files(directory.path());
        let (cert_chain, key) = super::load_identity(&cert_path, &key_path).unwrap();
        let mut server_config =
            ssh3_quinn::server_config_with_single_cert(cert_chain, key).unwrap();
        super::apply_transport_limits(&mut server_config, &Ssh3ServerConfig::default());
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_task =
            tokio::spawn(serve_endpoint(server_endpoint, Ssh3ServerConfig::default()));

        // the client trusts the certificate file of the server, the way the
        // --ca-cert flag of the reference client loads it
        let certificate = certificates_of_file(&cert_path).remove(0);
        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(certificate).unwrap());
        let client_connection = timeout(
            Duration::from_secs(5),
            client_endpoint.connect(server_addr, "localhost").unwrap(),
        )
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
        timeout(
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
        .unwrap()
        .unwrap();

        client_connection.close(0u32.into(), b"done");
        let _ = timeout(Duration::from_secs(5), driver_task).await.unwrap();
        client_endpoint.wait_idle().await;
        server_task.abort();
    }

    /// The webpki (system) roots of the client refuse the self-signed
    /// identity of the server: without the `--ca-cert` trust the handshake
    /// dies, the TLS posture of the reference. The custom CA of the test is
    /// accepted by the companion test above.
    #[tokio::test]
    async fn the_webpki_roots_refuse_the_own_certificate_of_the_server() {
        let directory = tempfile::TempDir::new().unwrap();
        let (cert_path, key_path) = write_identity_files(directory.path());
        let (cert_chain, key) = super::load_identity(&cert_path, &key_path).unwrap();
        let mut server_config =
            ssh3_quinn::server_config_with_single_cert(cert_chain, key).unwrap();
        super::apply_transport_limits(&mut server_config, &Ssh3ServerConfig::default());
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_task =
            tokio::spawn(serve_endpoint(server_endpoint, Ssh3ServerConfig::default()));

        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        client_endpoint.set_default_client_config(client_config_with_webpki_roots(None).unwrap());
        let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        match timeout(Duration::from_secs(5), connecting).await {
            Ok(Ok(_)) => panic!("the webpki roots accepted the self-signed certificate"),
            Ok(Err(_)) => {}
            Err(_) => panic!("the webpki handshake did not finish in time"),
        }
        client_endpoint.wait_idle().await;
        server_task.abort();
    }

    /// `run_with_certificates` refuses the start on a broken identity file
    /// before any socket is bound, the `LoadX509KeyPair` posture of the
    /// reference (`cmd/ssh3-server.go:1286-1293`).
    #[tokio::test]
    async fn a_broken_identity_pair_refuses_the_start() {
        let directory = tempfile::TempDir::new().unwrap();
        let config = Ssh3ServerConfig::default();
        let err = super::run_with_certificates(
            config,
            directory.path().join("absent.pem"),
            directory.path().join("absent.key"),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("certificate file does not exist"),
            "{err}"
        );
    }

    /// `run_with_certificates` serves the loaded identity: the server keeps
    /// accepting instead of failing over the identity files of the operator.
    #[tokio::test]
    async fn the_server_with_own_identity_files_keeps_serving() {
        let directory = tempfile::TempDir::new().unwrap();
        let (cert_path, key_path) = write_identity_files(directory.path());
        let config = Ssh3ServerConfig {
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            ..Ssh3ServerConfig::default()
        };
        let mut task = tokio::spawn(super::run_with_certificates(config, cert_path, key_path));
        timeout(Duration::from_millis(500), &mut task)
            .await
            .expect_err("the server with its own identity keeps serving");
        task.abort();
    }

    /// The `-initial-packet-size` knob reaches the transport builder: the
    /// value lands in the initial MTU and a size below the QUIC minimum
    /// rides the 1200-byte floor, like in the reference.
    #[test]
    fn the_initial_packet_size_reaches_the_server_transport() {
        let config = Ssh3ServerConfig {
            initial_packet_size: 1400,
            ..Ssh3ServerConfig::default()
        };
        let transport = super::server_transport_config(&config);
        assert!(
            format!("{transport:?}").contains("initial_mtu: 1400"),
            "{transport:?}"
        );

        // Below the QUIC minimum the transport clamps to the 1200 default.
        let config = Ssh3ServerConfig {
            initial_packet_size: 900,
            ..Ssh3ServerConfig::default()
        };
        let transport = super::server_transport_config(&config);
        assert!(
            format!("{transport:?}").contains("initial_mtu: 1200"),
            "{transport:?}"
        );
    }
}
