//! The tests of the `-s sftp` mode of the command line.
//!
//! The tests run the binary of the client against a real server: the
//! interactive client of the `sftp` subsystem talks to the local Rust
//! server over a piped stdin, the way an operator drives it from a script.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::JoinHandle;

use ssh3_quinn::self_signed_server_config;
use ssh3_server::{SftpJailMode, Ssh3ServerConfig, serve_connection};
use tempfile::TempDir;

/// A server whose SFTP subsystem is jailed into a directory of the test.
struct SftpServer {
    /// The home directory of the jail of the subsystem.
    home: TempDir,
    /// The address the server listens on.
    address: SocketAddr,
    /// The thread of the server; it ends with the process of the test.
    _server_thread: JoinHandle<()>,
}

impl SftpServer {
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

    /// Returns the URL operand of an interactive session of the test.
    fn url(&self) -> String {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default();
        format!("{}@127.0.0.1:{}/ssh3-term", user, self.address.port())
    }

    /// Returns the path of a file of the jail.
    fn remote(&self, relative: &str) -> PathBuf {
        self.home.path().join(relative)
    }
}

/// Runs the client in the interactive mode of the `sftp` subsystem with a
/// script of commands on the stdin.
fn run_sftp_script(url: &str, script: String) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ssh3"))
        .args(["-s", "sftp", "--insecure", url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the client of the test did not run");
    let mut stdin = child.stdin.take().expect("the stdin of the client");
    std::thread::spawn(move || {
        stdin.write_all(script.as_bytes()).unwrap();
    });
    child
        .wait_with_output()
        .expect("the client of the test did not end")
}

/// The interactive session of the `-s sftp` flag drives the SFTP subsystem:
/// the script of the stdin makes a directory, uploads, lists and downloads
/// a file, the payloads ride the jail byte for byte.
#[test]
fn the_sftp_flag_drives_the_interactive_client() {
    let server = SftpServer::start();
    let local = TempDir::new().unwrap();
    let source = local.path().join("payload.bin");
    let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &payload).unwrap();
    let download = local.path().join("downloaded.bin");

    let script = format!(
        "pwd\nmkdir testdir\nput {} testdir/payload.bin\nls testdir\nget testdir/payload.bin {}\nquit\n",
        source.to_str().unwrap(),
        download.to_str().unwrap(),
    );
    let output = run_sftp_script(&server.url(), script);
    assert!(
        output.status.success(),
        "the interactive session failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(server.remote("testdir/payload.bin")).unwrap(),
        payload
    );
    assert_eq!(std::fs::read(&download).unwrap(), payload);
}

/// The stdout of the interactive session carries the answers of the
/// commands: the `ls` of the uploaded directory names the file, the way an
/// operator sees it in a terminal.
#[test]
fn the_sftp_flag_prints_the_answers_of_the_commands() {
    let server = SftpServer::start();
    let local = TempDir::new().unwrap();
    let source = local.path().join("payload.bin");
    std::fs::write(&source, b"the payload").unwrap();

    let script = format!("put {} payload.bin\nls\nquit\n", source.to_str().unwrap(),);
    let output = run_sftp_script(&server.url(), script);
    assert!(
        output.status.success(),
        "the interactive session failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("payload.bin"),
        "the ls answer does not name the file: {stdout}"
    );
}
