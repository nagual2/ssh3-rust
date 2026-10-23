//! The tests of the command line of the transfer mode.
//!
//! The tests run the binary of the client against a real server: the SFTP
//! subsystem of the local Rust server, jailed into a directory of the test,
//! serves the files of the transfer.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread::JoinHandle;

use ssh3_quinn::self_signed_server_config;
use ssh3_server::{SftpJailMode, Ssh3ServerConfig, serve_connection};
use tempfile::TempDir;

/// A server whose SFTP subsystem is jailed into a directory of a test.
struct TransferServer {
    /// The home directory of the jail of the subsystem.
    home: TempDir,
    /// The address the server listens on.
    address: SocketAddr,
    /// The thread of the server; it ends with the process of the test.
    _server_thread: JoinHandle<()>,
}

impl TransferServer {
    /// Starts a server whose jail is a directory of the test.
    fn start() -> Self {
        let home = TempDir::new().unwrap();
        let config = Ssh3ServerConfig {
            sftp_jail: SftpJailMode::Lexical,
            sftp_root: Some(home.path().to_path_buf()),
            ..Ssh3ServerConfig::default()
        };
        // the endpoint of the server needs a runtime, so it is built inside
        // the thread that serves the connections
        let (sender, receiver) = std::sync::mpsc::channel();
        let server_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let (server_config, _certificate) = self_signed_server_config(vec![
                    "localhost".to_string(),
                    "127.0.0.1".to_string(),
                ])
                .unwrap();
                let endpoint = quinn::Endpoint::server(
                    server_config,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                )
                .unwrap();
                let _ = sender.send(endpoint.local_addr().unwrap());
                loop {
                    let Some(incoming) = endpoint.accept().await else {
                        break;
                    };
                    let Ok(connection) = incoming.await else {
                        break;
                    };
                    let config = config.clone();
                    tokio::spawn(async move {
                        let _ = serve_connection(connection, config).await;
                    });
                }
            });
        });
        let address = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the server of the test did not start");
        Self {
            home,
            address,
            _server_thread: server_thread,
        }
    }

    /// Returns the remote operand of a transfer of the test.
    fn remote_operand(&self, remote_path: &str) -> String {
        format!(
            "{}@127.0.0.1:{}/ssh3-term:{remote_path}",
            current_username(),
            self.address.port()
        )
    }

    /// Returns the path of a file of the jail.
    fn remote(&self, relative: &str) -> PathBuf {
        self.home.path().join(relative)
    }
}

/// Runs the client of the transfer mode.
fn run_transfer(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ssh3-rust-client"))
        .args(arguments)
        .output()
        .expect("the client of the test did not run")
}

/// Returns the name of the user of the process.
///
/// The server resolves the user of the session with the name the client
/// asks for, so the tests of the transfer mode use the name of the user
/// that runs them.
fn current_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default()
}

/// The upload of a file ends with the code of the success.
#[test]
fn the_upload_of_a_file_ends_with_the_code_of_the_success() {
    let server = TransferServer::start();
    let local = TempDir::new().unwrap();
    let source = local.path().join("report.txt");
    std::fs::write(&source, b"the payload of the report").unwrap();

    let output = run_transfer(&[
        "--transfer",
        "--insecure",
        source.to_str().unwrap(),
        &server.remote_operand("/report.txt"),
    ]);
    assert!(
        output.status.success(),
        "the upload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(server.remote("report.txt")).unwrap(),
        b"the payload of the report"
    );
}

/// A transfer that fails ends with a code that is not the code of the success.
///
/// The Go implementation leaves the process with the code -1, which the
/// shell sees as 255.
#[test]
fn a_transfer_that_fails_ends_with_a_code_that_is_not_the_success() {
    let server = TransferServer::start();
    let local = TempDir::new().unwrap();
    let source = local.path().join("missing.txt");

    let output = run_transfer(&[
        "--transfer",
        "--insecure",
        source.to_str().unwrap(),
        &server.remote_operand("/missing.txt"),
    ]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(255));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot stat"),
        "the failure was not reported: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The download of a file ends with the code of the success.
#[test]
fn the_download_of_a_file_ends_with_the_code_of_the_success() {
    let server = TransferServer::start();
    std::fs::write(server.remote("app.log"), b"the log of the app").unwrap();
    let local = TempDir::new().unwrap();
    let destination = local.path().join("app.log");

    let output = run_transfer(&[
        "--transfer",
        "--insecure",
        &server.remote_operand("/app.log"),
        destination.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "the download failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&destination).unwrap(), b"the log of the app");
}

/// The recursive upload of a tree ends with the code of the success.
#[test]
fn the_recursive_upload_of_a_tree_ends_with_the_code_of_the_success() {
    let server = TransferServer::start();
    let local = TempDir::new().unwrap();
    let tree = local.path().join("tree");
    std::fs::create_dir_all(tree.join("nested")).unwrap();
    std::fs::write(tree.join("one.txt"), b"one").unwrap();
    std::fs::write(tree.join("nested/two.txt"), b"two").unwrap();

    let output = run_transfer(&[
        "--transfer",
        "--recursive",
        "--insecure",
        tree.to_str().unwrap(),
        &server.remote_operand("/backups"),
    ]);
    assert!(
        output.status.success(),
        "the upload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(server.remote("backups/one.txt")).unwrap(),
        b"one"
    );
    assert_eq!(
        std::fs::read(server.remote("backups/nested/two.txt")).unwrap(),
        b"two"
    );
}

/// The mode refuses a command line that does not carry two operands.
#[test]
fn the_mode_refuses_a_single_operand() {
    let output = run_transfer(&["--transfer", "--insecure", "only-one-operand"]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exactly two operands"),
        "the refusal was not reported: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The mode refuses a command line whose two operands are remote.
#[test]
fn the_mode_refuses_two_remote_operands() {
    let output = run_transfer(&[
        "--transfer",
        "--insecure",
        "tester@127.0.0.1:443/ssh3-term:/one",
        "tester@127.0.0.1:443/ssh3-term:/two",
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exactly one remote operand"),
        "the refusal was not reported: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
