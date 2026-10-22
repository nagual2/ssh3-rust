//! The tests of the SFTP subsystem.
//!
//! The tests cover the isolation of the paths of the user (the jail of the
//! subsystem) and the subsystem itself: a client opens a channel of the type
//! `sftp` and reads and writes the files of the home directory over it.

use std::path::PathBuf;
use std::time::Duration;

use russh_sftp::client::SftpSession;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use crate::config::{SftpJailMode, Ssh3ServerConfig};
use crate::sftp::{SftpJail, SftpSessionBudget};
use crate::sftp_stream::ChannelStream;
use crate::tests::setup_harness;

/// The time the tests wait for the subsystem to answer.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds the configuration of a server whose jail is a directory of a test.
fn jailed_config(home: &TempDir, mode: SftpJailMode) -> Ssh3ServerConfig {
    Ssh3ServerConfig {
        sftp_jail: mode,
        sftp_root: Some(home.path().to_path_buf()),
        ..Ssh3ServerConfig::default()
    }
}

#[test]
fn the_jail_maps_the_paths_of_the_client_into_the_home_directory() {
    let home = TempDir::new().unwrap();
    let root = home.path().to_path_buf();
    let jail = SftpJail::new(root.clone(), false).unwrap();

    // the jail-relative paths resolve under the home directory
    assert_eq!(jail.resolve("/docs/f").unwrap(), root.join("docs/f"));
    assert_eq!(jail.resolve("docs/f").unwrap(), root.join("docs/f"));
    assert_eq!(jail.resolve("/").unwrap(), root);
    assert_eq!(jail.resolve("").unwrap(), root);
    assert_eq!(jail.resolve("  ").unwrap(), root);

    // a ".." never leaves the jail
    assert_eq!(
        jail.resolve("/../etc/passwd").unwrap(),
        root.join("etc/passwd")
    );
    assert_eq!(
        jail.resolve("docs/../../etc/passwd").unwrap(),
        root.join("etc/passwd")
    );

    // the spelling of an interactive shell is honored inside the jail
    let absolute = root.join("docs/f");
    assert_eq!(jail.resolve(absolute.to_str().unwrap()).unwrap(), absolute);

    // a path outside of the jail is mapped into it
    assert_eq!(
        jail.resolve("/etc/passwd").unwrap(),
        root.join("etc/passwd")
    );
}

#[test]
fn the_jail_of_a_chrooted_process_keeps_the_paths_of_the_client() {
    let jail = SftpJail::new(PathBuf::from("/"), true).unwrap();
    assert_eq!(jail.resolve("/docs/f").unwrap(), PathBuf::from("/docs/f"));
    assert_eq!(jail.resolve("docs/f").unwrap(), PathBuf::from("/docs/f"));
    // the kernel confines the chroot, the ".." is resolved lexically
    assert_eq!(
        jail.resolve("/../etc/passwd").unwrap(),
        PathBuf::from("/etc/passwd")
    );
}

#[cfg(unix)]
#[test]
fn the_jail_refuses_the_symlink_that_leaves_the_home_directory() {
    let home = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
    std::os::unix::fs::symlink(outside.path(), home.path().join("link")).unwrap();

    let jail = SftpJail::new(home.path().to_path_buf(), false).unwrap();
    // the path of the link is inside the jail, its target is not: the link
    // is refused as well, the client cannot step through it
    assert!(jail.resolve("/link/secret.txt").is_err());
    assert!(jail.resolve("/link").is_err());
}

#[test]
fn the_budget_of_the_sftp_sessions_bounds_the_sessions_of_a_user() {
    let budget = SftpSessionBudget::new();
    let user = "sftp-budget-probe";
    while budget.current(user) > 0 {
        budget.release(user);
    }

    assert!(budget.try_acquire(user, 2));
    assert!(budget.try_acquire(user, 2));
    assert!(!budget.try_acquire(user, 2));
    assert_eq!(budget.current(user), 2);

    budget.release(user);
    assert_eq!(budget.current(user), 1);
    assert!(budget.try_acquire(user, 2));
    assert!(!budget.try_acquire(user, 2));

    while budget.current(user) > 0 {
        budget.release(user);
    }
    assert_eq!(budget.current(user), 0);

    // a limit of zero disables the budget
    assert!(budget.try_acquire(user, 0));
}

#[tokio::test]
async fn the_sftp_subsystem_serves_the_files_of_the_home_directory() {
    let home = TempDir::new().unwrap();
    let harness = setup_harness(jailed_config(&home, SftpJailMode::Lexical)).await;
    let channel = harness.open_channel(b"sftp").await;
    let (stream, _done) = ChannelStream::new(channel);
    let session = timeout(TEST_TIMEOUT, SftpSession::new(stream))
        .await
        .expect("the sftp session did not start in time")
        .expect("the sftp session failed to start");

    // a file is written and read back over the channel
    let mut file = session.create("/hello.txt").await.unwrap();
    file.write_all(b"hello sftp").await.unwrap();
    file.close().await.unwrap();
    assert_eq!(session.read("/hello.txt").await.unwrap(), b"hello sftp");
    assert_eq!(
        std::fs::read(home.path().join("hello.txt")).unwrap(),
        b"hello sftp"
    );

    // the directory of the home is listed
    let mut entries: Vec<String> = session
        .read_dir("/")
        .await
        .unwrap()
        .map(|entry| entry.file_name())
        .collect();
    entries.sort();
    assert_eq!(entries, vec!["hello.txt".to_string()]);

    // a directory is created and removed again
    session.create_dir("/sub").await.unwrap();
    assert!(home.path().join("sub").is_dir());
    session.remove_dir("/sub").await.unwrap();
    assert!(!home.path().join("sub").exists());

    // the file is renamed
    session.rename("/hello.txt", "/renamed.txt").await.unwrap();
    assert!(home.path().join("renamed.txt").exists());
    assert!(!home.path().join("hello.txt").exists());

    // the metadata of the file is reported
    let metadata = session.metadata("/renamed.txt").await.unwrap();
    assert_eq!(metadata.size, Some(10));

    harness.shutdown().await;
}

#[tokio::test]
async fn the_sftp_subsystem_keeps_the_paths_of_the_client_inside_the_home_directory() {
    let home = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let harness = setup_harness(jailed_config(&home, SftpJailMode::Lexical)).await;
    let channel = harness.open_channel(b"sftp").await;
    let (stream, _done) = ChannelStream::new(channel);
    let session = timeout(TEST_TIMEOUT, SftpSession::new(stream))
        .await
        .expect("the sftp session did not start in time")
        .expect("the sftp session failed to start");

    // a ".." is mapped into the jail, the file never leaves the home
    let mut file = session.create("/../escape.txt").await.unwrap();
    file.write_all(b"nope").await.unwrap();
    file.close().await.unwrap();
    assert!(home.path().join("escape.txt").exists());
    assert!(!outside.path().join("escape.txt").exists());

    // the path of another directory is mapped into the jail as well: the
    // file is never created outside of the home directory
    let escaped = outside.path().join("escape.txt");
    let _ = session.create(escaped.to_str().unwrap()).await;
    assert!(!outside.path().join("escape.txt").exists());
    assert!(home.path().join("escape.txt").exists());
    assert_eq!(
        std::fs::read(home.path().join("escape.txt")).unwrap(),
        b"nope"
    );

    harness.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn the_sftp_subsystem_refuses_the_symlink_that_leaves_the_home_directory() {
    let home = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
    std::os::unix::fs::symlink(outside.path(), home.path().join("link")).unwrap();

    let harness = setup_harness(jailed_config(&home, SftpJailMode::Lexical)).await;
    let channel = harness.open_channel(b"sftp").await;
    let (stream, _done) = ChannelStream::new(channel);
    let session = timeout(TEST_TIMEOUT, SftpSession::new(stream))
        .await
        .expect("the sftp session did not start in time")
        .expect("the sftp session failed to start");

    assert!(session.read("/link/secret.txt").await.is_err());

    harness.shutdown().await;
}

#[tokio::test]
async fn the_sftp_subsystem_serves_the_files_without_the_privileges_of_the_server() {
    // a server that does not run as root has no chroot to offer: the
    // subsystem is served in process, with the lexical jail
    #[cfg(unix)]
    if nix::unistd::Uid::effective().is_root() {
        // the chroot jail needs a child process, the test binary is not the
        // server binary
        return;
    }

    let home = TempDir::new().unwrap();
    let harness = setup_harness(jailed_config(&home, SftpJailMode::Chroot)).await;
    let channel = harness.open_channel(b"sftp").await;
    let (stream, _done) = ChannelStream::new(channel);
    let session = timeout(TEST_TIMEOUT, SftpSession::new(stream))
        .await
        .expect("the sftp session did not start in time")
        .expect("the sftp session failed to start");

    let mut file = session.create("/fallback.txt").await.unwrap();
    file.write_all(b"fallback").await.unwrap();
    file.close().await.unwrap();
    assert_eq!(session.read("/fallback.txt").await.unwrap(), b"fallback");

    harness.shutdown().await;
}

#[tokio::test]
async fn the_sftp_subsystem_refuses_the_session_over_the_budget_of_the_user() {
    let home = TempDir::new().unwrap();
    let config = Ssh3ServerConfig {
        // the budget of the user holds a single session
        max_sftp_sessions_per_user: 1,
        sftp_budget: std::sync::Arc::new(SftpSessionBudget::new()),
        ..jailed_config(&home, SftpJailMode::Lexical)
    };
    let harness = setup_harness(config).await;

    // the first session takes the slot of the user
    let channel = harness.open_channel(b"sftp").await;
    let (stream, _done) = ChannelStream::new(channel);
    let session = timeout(TEST_TIMEOUT, SftpSession::new(stream))
        .await
        .expect("the sftp session did not start in time")
        .expect("the sftp session failed to start");

    // the second session is refused: the channel is closed right away
    let channel = harness.open_channel(b"sftp").await;
    let (stream, _done) = ChannelStream::new(channel);
    let refused = timeout(TEST_TIMEOUT, SftpSession::new(stream)).await;
    assert!(
        refused.is_err() || refused.expect("the session started").is_err(),
        "the sftp session over the budget of the user was served"
    );

    // the first session still works
    let mut file = session.create("/budget.txt").await.unwrap();
    file.write_all(b"budget").await.unwrap();
    file.close().await.unwrap();
    assert_eq!(session.read("/budget.txt").await.unwrap(), b"budget");

    harness.shutdown().await;
}
