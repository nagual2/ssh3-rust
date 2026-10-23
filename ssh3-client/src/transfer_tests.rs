//! The tests of the file transfer mode of the client.
//!
//! The tests run against a real server: the SFTP subsystem of the local Rust
//! server, jailed into a directory of the test, serves the files of the
//! transfer.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use russh_sftp::client::SftpSession;
use sha2::{Digest, Sha256};
use ssh3_quinn::self_signed_server_config;
use ssh3_server::{SftpJailMode, Ssh3ServerConfig, serve_connection};
use tempfile::TempDir;
use tokio::time::timeout;

use crate::transfer::verify_remote_checksum;
use crate::{
    Ssh3ClientConfig, Ssh3TransferError, Ssh3TransferFailure, Ssh3TransferOptions,
    Ssh3TransferPlan, Ssh3TransferTarget, Ssh3TrustStrategy, is_remote_transfer_spec,
    parse_remote_transfer_spec, run_file_transfer,
};

/// The time the tests wait for the server and for the transfers.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A server whose SFTP subsystem is jailed into a directory of a test.
struct TransferHarness {
    /// The home directory of the jail of the subsystem.
    home: TempDir,
    /// The address the server listens on.
    address: SocketAddr,
    /// The certificate the server presents.
    certificate: rustls::pki_types::CertificateDer<'static>,
    /// The task of the server.
    server_task: tokio::task::JoinHandle<()>,
}

impl TransferHarness {
    /// Starts a server whose jail is a directory of the test.
    async fn start() -> Self {
        let home = TempDir::new().unwrap();
        let (server_config, certificate) =
            self_signed_server_config(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let config = Ssh3ServerConfig {
            sftp_jail: SftpJailMode::Lexical,
            sftp_root: Some(home.path().to_path_buf()),
            ..Ssh3ServerConfig::default()
        };
        let server_task = tokio::spawn(async move {
            loop {
                let Ok(Some(incoming)) = timeout(Duration::from_secs(60), endpoint.accept()).await
                else {
                    break;
                };
                let Ok(Ok(connection)) = timeout(Duration::from_secs(5), incoming).await else {
                    break;
                };
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = serve_connection(connection, config).await;
                });
            }
        });
        Self {
            home,
            address,
            certificate,
            server_task,
        }
    }

    /// Returns the configuration of the client of the test.
    fn config(&self) -> Ssh3ClientConfig {
        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", self.address.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![self.certificate.clone()]);
        config
    }

    /// Returns the plan of a transfer of the test.
    fn plan(
        &self,
        remote_path: &str,
        local_path: &Path,
        upload: bool,
        options: Ssh3TransferOptions,
    ) -> Ssh3TransferPlan {
        Ssh3TransferPlan {
            target: Ssh3TransferTarget {
                username: "transfer-tester".to_string(),
                hostname: "127.0.0.1".to_string(),
                port: self.address.port(),
                url_path: "/ssh3-term".to_string(),
                remote_path: remote_path.to_string(),
            },
            local_path: local_path.to_path_buf(),
            upload,
            options,
        }
    }

    /// Returns the path of a file of the jail.
    fn remote(&self, relative: &str) -> PathBuf {
        self.home.path().join(relative)
    }

    /// Opens an SFTP session on the server of the test.
    ///
    /// The client is returned with the session: the connection of the client
    /// carries the session, and it dies with it.
    async fn session(&self) -> (crate::ActiveClient, SftpSession) {
        let client = crate::connect_client(&self.config()).await.unwrap();
        let channel = client.open_sftp_channel().await.unwrap();
        let stream = crate::sftp_stream::ChannelStream::new(channel);
        let session = SftpSession::new(stream).await.unwrap();
        (client, session)
    }
}

impl Drop for TransferHarness {
    fn drop(&mut self) {
        // the server of the test stops with the test
        self.server_task.abort();
    }
}

/// Stamps a file with a modification time.
fn set_mtime(path: &Path, time: SystemTime) {
    let file = std::fs::File::options().write(true).open(path).unwrap();
    let times = std::fs::FileTimes::new()
        .set_accessed(time)
        .set_modified(time);
    file.set_times(times).unwrap();
}

/// Returns the modification time of a file, in seconds since the epoch.
fn mtime_seconds(path: &Path) -> i64 {
    let modified = std::fs::metadata(path).unwrap().modified().unwrap();
    match modified.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(error) => -(error.duration().as_secs() as i64),
    }
}

/// The remote operand of the transfer mode is the `user@host:remote_path`
/// form, and the explicit form carries the port and the URL path of the
/// server.
#[test]
fn the_remote_operand_carries_the_user_the_host_and_the_remote_path() {
    let target =
        parse_remote_transfer_spec("max@example.org:docs/report.pdf", 443, "/ssh3-term").unwrap();
    assert_eq!(target.username, "max");
    assert_eq!(target.hostname, "example.org");
    assert_eq!(target.port, 443);
    assert_eq!(target.url_path, "/ssh3-term");
    assert_eq!(target.remote_path, "docs/report.pdf");
}

/// The explicit form of the operand carries the port and the URL path of the
/// server.
#[test]
fn the_explicit_operand_carries_the_port_and_the_url_path() {
    let target = parse_remote_transfer_spec(
        "max@example.org:8443/ssh3-other:docs/report.pdf",
        443,
        "/ssh3-term",
    )
    .unwrap();
    assert_eq!(target.username, "max");
    assert_eq!(target.hostname, "example.org");
    assert_eq!(target.port, 8443);
    assert_eq!(target.url_path, "/ssh3-other");
    assert_eq!(target.remote_path, "docs/report.pdf");
}

/// The port of the operand wins over the default port.
#[test]
fn the_operand_carries_a_port_of_its_own() {
    let target =
        parse_remote_transfer_spec("max@example.org:2222:report.pdf", 443, "/ssh3-term").unwrap();
    assert_eq!(target.port, 2222);
    assert_eq!(target.url_path, "/ssh3-term");
    assert_eq!(target.remote_path, "report.pdf");
}

/// The hybrid form of the operand carries the URL path of the server without
/// a port.
#[test]
fn the_hybrid_operand_carries_the_url_path_of_the_server() {
    let target =
        parse_remote_transfer_spec("max@example.org/ssh3-other:report.pdf", 443, "/ssh3-term")
            .unwrap();
    assert_eq!(target.hostname, "example.org");
    assert_eq!(target.port, 443);
    assert_eq!(target.url_path, "/ssh3-other");
    assert_eq!(target.remote_path, "report.pdf");
}

/// A malformed operand is refused.
#[test]
fn a_malformed_operand_is_refused() {
    assert!(parse_remote_transfer_spec("max@example.org", 443, "/ssh3-term").is_err());
    assert!(parse_remote_transfer_spec("max@example.org:", 443, "/ssh3-term").is_err());
    assert!(
        parse_remote_transfer_spec("max@example.org:port:report.pdf", 443, "/ssh3-term").is_err()
    );
    assert!(
        parse_remote_transfer_spec("max@example.org:1:2:report.pdf", 443, "/ssh3-term").is_err()
    );
}

/// The remote operand of the transfer mode is the one that carries a user
/// and a colon; the local paths stay local.
#[test]
fn the_remote_operand_is_the_one_that_carries_a_user_and_a_colon() {
    assert!(is_remote_transfer_spec("max@example.org:report.pdf"));
    assert!(is_remote_transfer_spec(
        "max@example.org:8443/ssh3-term:report.pdf"
    ));
    // a local path is never a remote operand
    assert!(!is_remote_transfer_spec("/home/max/report.pdf"));
    assert!(!is_remote_transfer_spec("report.pdf"));
    assert!(!is_remote_transfer_spec("max@example.org"));
    // a Windows path keeps the colon of its drive
    assert!(!is_remote_transfer_spec("C:\\Users\\max\\report.pdf"));
}

#[tokio::test]
async fn the_upload_moves_a_file_to_the_server() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("report.txt");
    std::fs::write(&source, b"the payload of the report").unwrap();

    let plan = harness.plan(
        "/docs/report.txt",
        &source,
        true,
        Ssh3TransferOptions::default(),
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    // the directories that are missing on the remote side are created
    assert_eq!(
        std::fs::read(harness.remote("docs/report.txt")).unwrap(),
        b"the payload of the report"
    );
}

#[tokio::test]
async fn the_upload_of_a_file_into_a_remote_directory_keeps_its_name() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("report.txt");
    std::fs::write(&source, b"the payload of the report").unwrap();
    std::fs::create_dir_all(harness.remote("inbox")).unwrap();

    let plan = harness.plan("/inbox", &source, true, Ssh3TransferOptions::default());
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        std::fs::read(harness.remote("inbox/report.txt")).unwrap(),
        b"the payload of the report"
    );
}

#[tokio::test]
async fn the_download_moves_a_file_from_the_server() {
    let harness = TransferHarness::start().await;
    std::fs::write(harness.remote("app.log"), b"the log of the app").unwrap();
    let local = TempDir::new().unwrap();
    let destination = local.path().join("app.log");

    let plan = harness.plan(
        "/app.log",
        &destination,
        false,
        Ssh3TransferOptions::default(),
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(std::fs::read(&destination).unwrap(), b"the log of the app");
}

#[tokio::test]
async fn the_recursive_upload_moves_a_tree() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let tree = local.path().join("tree");
    std::fs::create_dir_all(tree.join("nested")).unwrap();
    std::fs::create_dir_all(tree.join("empty")).unwrap();
    std::fs::write(tree.join("one.txt"), b"one").unwrap();
    std::fs::write(tree.join("nested/two.txt"), b"two").unwrap();

    let plan = harness.plan(
        "/backups",
        &tree,
        true,
        Ssh3TransferOptions {
            recursive: true,
            ..Ssh3TransferOptions::default()
        },
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        std::fs::read(harness.remote("backups/one.txt")).unwrap(),
        b"one"
    );
    assert_eq!(
        std::fs::read(harness.remote("backups/nested/two.txt")).unwrap(),
        b"two"
    );
    // an empty directory is created on the other side as well
    assert!(harness.remote("backups/empty").is_dir());
}

#[tokio::test]
async fn the_recursive_download_moves_a_tree() {
    let harness = TransferHarness::start().await;
    std::fs::create_dir_all(harness.remote("logs/nested")).unwrap();
    std::fs::create_dir_all(harness.remote("logs/empty")).unwrap();
    std::fs::write(harness.remote("logs/one.log"), b"one").unwrap();
    std::fs::write(harness.remote("logs/nested/two.log"), b"two").unwrap();
    let local = TempDir::new().unwrap();

    let plan = harness.plan(
        "/logs",
        local.path(),
        false,
        Ssh3TransferOptions {
            recursive: true,
            ..Ssh3TransferOptions::default()
        },
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(std::fs::read(local.path().join("one.log")).unwrap(), b"one");
    assert_eq!(
        std::fs::read(local.path().join("nested/two.log")).unwrap(),
        b"two"
    );
    assert!(local.path().join("empty").is_dir());
}

#[tokio::test]
async fn the_continue_mode_resumes_a_partial_file() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("big.bin");
    let payload: Vec<u8> = (0..4096u32).map(|index| (index % 251) as u8).collect();
    std::fs::write(&source, &payload).unwrap();
    // the remote side holds the first half of the file
    std::fs::write(harness.remote("big.bin"), &payload[..2048]).unwrap();

    let plan = harness.plan(
        "/big.bin",
        &source,
        true,
        Ssh3TransferOptions {
            resume: true,
            ..Ssh3TransferOptions::default()
        },
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(std::fs::read(harness.remote("big.bin")).unwrap(), payload);
}

#[tokio::test]
async fn the_continue_mode_transfers_a_file_whose_mtime_differs() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("same.bin");
    std::fs::write(&source, b"aaaa").unwrap();
    // the remote side holds a file of the same size, but with another
    // content and another modification time
    let remote = harness.remote("same.bin");
    std::fs::write(&remote, b"bbbb").unwrap();
    set_mtime(&remote, UNIX_EPOCH + Duration::from_secs(1_000_000));

    let plan = harness.plan(
        "/same.bin",
        &source,
        true,
        Ssh3TransferOptions {
            resume: true,
            ..Ssh3TransferOptions::default()
        },
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(std::fs::read(&remote).unwrap(), b"aaaa");
}

#[tokio::test]
async fn the_continue_mode_skips_a_file_that_is_up_to_date() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("same.bin");
    std::fs::write(&source, b"aaaa").unwrap();
    // the remote side holds a file of the same size and with the same
    // modification time, but with another content
    let remote = harness.remote("same.bin");
    std::fs::write(&remote, b"bbbb").unwrap();
    let modified = std::fs::metadata(&source).unwrap().modified().unwrap();
    set_mtime(&remote, modified);
    assert_eq!(mtime_seconds(&remote), mtime_seconds(&source));

    let plan = harness.plan(
        "/same.bin",
        &source,
        true,
        Ssh3TransferOptions {
            resume: true,
            ..Ssh3TransferOptions::default()
        },
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    // the file was skipped, so the content of the remote side did not change
    assert_eq!(std::fs::read(&remote).unwrap(), b"bbbb");
}

#[tokio::test]
async fn the_continue_mode_refuses_a_destination_that_is_larger() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("small.bin");
    std::fs::write(&source, b"aaaa").unwrap();
    std::fs::write(harness.remote("small.bin"), b"a longer content").unwrap();

    let plan = harness.plan(
        "/small.bin",
        &source,
        true,
        Ssh3TransferOptions {
            resume: true,
            ..Ssh3TransferOptions::default()
        },
    );
    let error = timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap_err();

    assert!(matches!(error, Ssh3TransferError::RemoteLarger { .. }));
    // the destination is left alone
    assert_eq!(
        std::fs::read(harness.remote("small.bin")).unwrap(),
        b"a longer content"
    );
}

#[tokio::test]
async fn the_checksum_mode_verifies_the_transfer() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("data.bin");
    std::fs::write(&source, b"the data of the file").unwrap();

    let plan = harness.plan(
        "/data.bin",
        &source,
        true,
        Ssh3TransferOptions {
            checksum: true,
            ..Ssh3TransferOptions::default()
        },
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        std::fs::read(harness.remote("data.bin")).unwrap(),
        b"the data of the file"
    );
}

#[tokio::test]
async fn the_checksum_of_a_file_that_differs_is_reported() {
    let harness = TransferHarness::start().await;
    std::fs::write(harness.remote("data.bin"), b"the data of the file").unwrap();
    let (_client, session) = harness.session().await;

    // the checksum of another content does not match the one of the file
    let mut hasher = Sha256::new();
    hasher.update(b"another content");
    let error = timeout(
        TEST_TIMEOUT,
        verify_remote_checksum(&session, "/data.bin", &hasher),
    )
    .await
    .unwrap()
    .unwrap_err();

    assert!(matches!(error, Ssh3TransferError::ChecksumMismatch { .. }));
    assert_eq!(error.failure(), Ssh3TransferFailure::Checksum);
}

#[tokio::test]
async fn the_upload_stamps_the_remote_file_with_the_mtime_of_the_source() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("stamped.bin");
    std::fs::write(&source, b"the content of the file").unwrap();
    let modified = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    set_mtime(&source, modified);

    let plan = harness.plan(
        "/stamped.bin",
        &source,
        true,
        Ssh3TransferOptions::default(),
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(mtime_seconds(&harness.remote("stamped.bin")), 1_600_000_000);
}

#[tokio::test]
async fn the_download_stamps_the_local_file_with_the_mtime_of_the_remote_file() {
    let harness = TransferHarness::start().await;
    let remote = harness.remote("stamped.bin");
    std::fs::write(&remote, b"the content of the file").unwrap();
    set_mtime(&remote, UNIX_EPOCH + Duration::from_secs(1_600_000_000));
    let local = TempDir::new().unwrap();
    let destination = local.path().join("stamped.bin");

    let plan = harness.plan(
        "/stamped.bin",
        &destination,
        false,
        Ssh3TransferOptions::default(),
    );
    timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(mtime_seconds(&destination), 1_600_000_000);
}

#[tokio::test]
async fn the_transfer_of_a_file_that_does_not_exist_fails() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("missing.bin");

    let plan = harness.plan(
        "/missing.bin",
        &source,
        true,
        Ssh3TransferOptions::default(),
    );
    let error = timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap_err();

    assert!(matches!(error, Ssh3TransferError::LocalStat { .. }));
    assert_eq!(error.failure(), Ssh3TransferFailure::LocalIo);
}

#[tokio::test]
async fn the_transfer_of_a_directory_without_the_recursive_flag_fails() {
    let harness = TransferHarness::start().await;
    let local = TempDir::new().unwrap();
    let source = local.path().join("tree");
    std::fs::create_dir_all(&source).unwrap();

    let plan = harness.plan("/tree", &source, true, Ssh3TransferOptions::default());
    let error = timeout(TEST_TIMEOUT, run_file_transfer(&harness.config(), &plan))
        .await
        .unwrap()
        .unwrap_err();

    assert!(matches!(error, Ssh3TransferError::LocalIsDirectory { .. }));
    assert_eq!(error.failure(), Ssh3TransferFailure::Operand);
}

/// The transfer round-trips against the Go server of the reference
/// implementation: its SFTP subsystem serves the files of the home directory
/// of the user, the way the subsystem of the Rust server does.
#[cfg(unix)]
#[tokio::test]
// The lock serialises the scenarios that open a Go-server agent socket: the
// socket path is derived from the process id and a timestamp, and two
// concurrent scenarios could collide on it. The guard is deliberately held
// across the awaits of the whole scenario.
#[allow(clippy::await_holding_lock)]
async fn the_transfer_round_trips_against_the_go_server() {
    let _guard = crate::tests::lock_go_binary_tests();
    let fixture = crate::tests::create_auth_fixture(crate::tests::AuthKeyAlgorithm::Ed25519);
    let tempdir = TempDir::new().unwrap();
    let home_dir = tempdir.path().join("home");
    std::fs::create_dir_all(home_dir.join(".ssh")).unwrap();
    std::fs::write(
        home_dir.join(".ssh").join("authorized_keys"),
        std::fs::read(&fixture.authorized_identities_path).unwrap(),
    )
    .unwrap();

    let bind_port = crate::tests::reserve_udp_port();
    let bind_addr = format!("127.0.0.1:{bind_port}");
    let cert_path = tempdir.path().join("cert.pem");
    let key_path = tempdir.path().join("key.pem");
    let log_path = tempdir.path().join("go-server.log");

    let Some(mut server) = crate::tests::spawn_go_cli_server(
        &bind_addr,
        &fixture.username,
        &home_dir,
        &cert_path,
        &key_path,
        &log_path,
    )
    .await
    else {
        crate::tests::skip_interop("the_transfer_round_trips_against_the_go_server");
        return;
    };

    // the server of the reference implementation resolves the user of the
    // session from the query of the URL, the way its own client does
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

    let local = TempDir::new().unwrap();
    let source = local.path().join("hello.txt");
    std::fs::write(&source, b"hello from rust to go").unwrap();

    // the upload moves the file into the home directory of the user
    let plan = Ssh3TransferPlan {
        target: Ssh3TransferTarget {
            username: fixture.username.clone(),
            hostname: "127.0.0.1".to_string(),
            port: bind_port,
            url_path: "/ssh3-term".to_string(),
            remote_path: "/hello.txt".to_string(),
        },
        local_path: source.clone(),
        upload: true,
        options: Ssh3TransferOptions::default(),
    };
    timeout(TEST_TIMEOUT, run_file_transfer(&config, &plan))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read(home_dir.join("hello.txt")).unwrap(),
        b"hello from rust to go"
    );

    // the download moves the file back to the local side
    let destination = local.path().join("downloaded.txt");
    let plan = Ssh3TransferPlan {
        target: Ssh3TransferTarget {
            username: fixture.username.clone(),
            hostname: "127.0.0.1".to_string(),
            port: bind_port,
            url_path: "/ssh3-term".to_string(),
            remote_path: "/hello.txt".to_string(),
        },
        local_path: destination.clone(),
        upload: false,
        options: Ssh3TransferOptions::default(),
    };
    timeout(TEST_TIMEOUT, run_file_transfer(&config, &plan))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"hello from rust to go"
    );

    let _ = server.kill().await;
    let _ = server.wait().await;
}
