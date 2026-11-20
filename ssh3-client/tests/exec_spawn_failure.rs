//! The client survives a spawn failure of the session process.
//!
//! The live Windows run of the T10.1 (2026-11-20) hit the bug: the server
//! failed to spawn the shell of the exec (`os error 3`), dropped the channel
//! without a close, and the client waited for an exit status that never came
//! — the verdict rode the server log alone (the ROADMAP follow-up 10.5).
//! The server tells the spawn failure through the stderr of the channel and
//! closes it explicitly; the client prints the verdict and exits non-zero.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::process::Stdio;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use ssh3_quinn::self_signed_server_config;
use ssh3_server::Ssh3ServerConfig;

/// A server whose session shell does not exist: every session spawn fails.
struct BrokenShellServer {
    /// The address the server listens on.
    address: SocketAddr,
    /// The thread of the server; it ends with the process of the test.
    _server_thread: JoinHandle<()>,
}

impl BrokenShellServer {
    /// Starts a server whose shell path cannot spawn.
    fn start() -> Self {
        let config = Ssh3ServerConfig {
            shell: Some("/nonexistent-sh-t10-5".to_string()),
            ..Ssh3ServerConfig::default()
        };
        // The endpoint of the server needs a runtime, so it is built inside
        // the thread that serves the connections.
        let (sender, receiver) = mpsc::channel();
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
                        let _ = ssh3_server::serve_connection(connection, config).await;
                    });
                }
            });
        });
        let address = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("the server of the test did not start");
        Self {
            address,
            _server_thread: server_thread,
        }
    }

    /// Returns the URL operand of the exec of the test.
    fn url(&self) -> String {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default();
        format!("{}@127.0.0.1:{}/ssh3-term", user, self.address.port())
    }
}

/// The spawn failure of the session process rides the stderr of the channel
/// and the explicit close: the client prints the verdict of the server and
/// exits non-zero instead of waiting forever.
#[tokio::test]
async fn a_spawn_failure_of_the_server_ends_the_client_with_an_error() {
    let server = BrokenShellServer::start();

    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ssh3"))
        .args(["--insecure", &server.url(), "true"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the client of the test did not run");

    // The deadline guards the test against the very bug of the live run: a
    // client that parks on the channel forever fails the test through the
    // timeout instead of wedging the suite.
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("the client hung on the channel error of the server (the T10.1 bug)")
        .expect("the client of the test did not end");

    assert!(
        !output.status.success(),
        "the client must exit non-zero on the spawn failure of the server"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ssh3:"),
        "the verdict of the server rides the stderr of the client: {stderr}"
    );
}
