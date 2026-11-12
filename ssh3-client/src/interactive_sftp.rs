//! The interactive `-s sftp` client.
//!
//! The prompt-driven shell speaks the SFTP protocol over the channel of the
//! type `sftp`, as the reference implementation does (see
//! `cmd/subsystem.go`, `runSFTPSubsystem`). The command set stays reduced,
//! but every command names and behaves like the one of the reference.

use std::io;

use russh_sftp::client::SftpSession;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::Ssh3ClientError;
use crate::connect_client;
use crate::sftp_stream::ChannelStream;

/// The chunk buffer of the streaming copies: the files ride the sftp
/// handles in chunks, a whole file never sits in memory.
const COPY_BUFFER: usize = 64 * 1024;

/// Runs the interactive SFTP client over an established connection.
pub async fn run(config: &crate::Ssh3ClientConfig) -> Result<i32, Ssh3ClientError> {
    let client = connect_client(config).await?;
    let channel = client.open_sftp_channel().await?;
    let stream = ChannelStream::new(channel);
    let sftp = SftpSession::new(stream)
        .await
        .map_err(|error| Ssh3ClientError::Io(io::Error::other(error.to_string())))?;
    let mut cwd = sftp
        .canonicalize(".")
        .await
        .unwrap_or_else(|_| String::from("/"));
    println!("Connected to {}.", cwd);
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut writer = tokio::io::stdout();
    run_prompt(&sftp, &mut cwd, &mut reader, &mut writer).await;
    let _ = sftp.close().await;
    client.shutdown().await;
    Ok(0)
}

/// Runs the prompt loop of the interactive client.
///
/// The commands arrive through the reader line by line and the reports of
/// the session go through the writer, so a batched session (a script on the
/// stdin pipe, a test with an in-memory buffer) behaves like an interactive
/// one. The failures of a command go to the stderr of the process, as an
/// interactive session reports them.
pub(crate) async fn run_prompt<R, W>(
    sftp: &SftpSession,
    cwd: &mut String,
    reader: &mut R,
    writer: &mut W,
) where
    R: AsyncBufRead + ?Sized + Unpin,
    W: AsyncWrite + ?Sized + Unpin,
{
    loop {
        let _ = writer.write_all(b"sftp> ").await;
        let _ = writer.flush().await;
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => {
                let _ = writer.write_all(b"\n").await;
                break;
            }
            Ok(_) => {}
        }
        let fields = split_fields(line.trim_end_matches(['\r', '\n']));
        if fields.is_empty() {
            continue;
        }
        let command = fields[0].to_ascii_lowercase();
        let args = &fields[1..];
        match command.as_str() {
            "help" => print_help(writer).await,
            "pwd" => {
                let _ = writer.write_all(format!("{cwd}\n").as_bytes()).await;
            }
            "quit" | "exit" => break,
            "ls" => {
                let target = join_path(cwd, args.first().map(|s| s.as_str()));
                match sftp.read_dir(&target).await {
                    Ok(entries) => {
                        for entry in entries {
                            let name = entry.file_name();
                            let meta = entry.metadata();
                            if meta.is_dir() {
                                let _ = writer.write_all(format!("{name}/\n").as_bytes()).await;
                            } else {
                                let _ = writer.write_all(format!("{name}\n").as_bytes()).await;
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("could not list {}: {}", target, error);
                    }
                }
            }
            "cd" => {
                let target = join_path(cwd, args.first().map(|s| s.as_str()));
                match sftp.metadata(&target).await {
                    Ok(meta) if meta.is_dir() => {
                        if let Ok(real) = sftp.canonicalize(&target).await {
                            *cwd = real;
                        } else {
                            *cwd = target;
                        }
                    }
                    Ok(_) => eprintln!("{} is not a directory", target),
                    Err(error) => eprintln!("could not change directory to {}: {}", target, error),
                }
            }
            "mkdir" => {
                if args.len() != 1 {
                    eprintln!("mkdir expects 1 argument");
                    continue;
                }
                let target = join_path(cwd, Some(&args[0]));
                if let Err(error) = sftp.create_dir(&target).await {
                    eprintln!("could not create directory {}: {}", target, error);
                }
            }
            "rmdir" => {
                if args.len() != 1 {
                    eprintln!("rmdir expects 1 argument");
                    continue;
                }
                let target = join_path(cwd, Some(&args[0]));
                if let Err(error) = sftp.remove_dir(&target).await {
                    eprintln!("could not remove directory {}: {}", target, error);
                }
            }
            "rm" => {
                if args.len() != 1 {
                    eprintln!("rm expects 1 argument");
                    continue;
                }
                let target = join_path(cwd, Some(&args[0]));
                if let Err(error) = sftp.remove_file(&target).await {
                    eprintln!("could not remove {}: {}", target, error);
                }
            }
            "get" => {
                if args.is_empty() || args.len() > 2 {
                    eprintln!("get expects 1 or 2 arguments");
                    continue;
                }
                let remote = join_path(cwd, Some(&args[0]));
                let local = args.get(1).cloned().unwrap_or_else(|| {
                    std::path::PathBuf::from(&remote)
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_else(|| "remote-file".to_string())
                });
                match download_file(sftp, &remote, &local).await {
                    Ok(bytes) => {
                        let _ = writer
                            .write_all(format!("Downloaded {remote} ({bytes} bytes).\n").as_bytes())
                            .await;
                    }
                    Err(error) => eprintln!("could not download {}: {}", remote, error),
                }
            }
            "put" => {
                if args.len() != 2 {
                    eprintln!("put expects 2 arguments");
                    continue;
                }
                let (local, remote_name) = (&args[0], &args[1]);
                let remote = join_path(cwd, Some(remote_name));
                match upload_file(sftp, local, &remote).await {
                    Ok(bytes) => {
                        let _ = writer
                            .write_all(format!("Uploaded {remote} ({bytes} bytes).\n").as_bytes())
                            .await;
                    }
                    Err(error) => eprintln!("could not upload {}: {}", remote, error),
                }
            }
            other => eprintln!("unknown command {} (type \"help\")", other),
        }
    }
    let _ = writer.flush().await;
}

/// Streams a remote file into the local path: the data rides the sftp
/// file handle in chunks, the whole file never sits in memory.
async fn download_file(sftp: &SftpSession, remote: &str, local: &str) -> io::Result<u64> {
    let mut remote_file = sftp
        .open(remote)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut local_file = tokio::fs::File::create(local).await?;
    let copied = tokio::io::copy(
        &mut BufReader::with_capacity(COPY_BUFFER, &mut remote_file),
        &mut local_file,
    )
    .await?;
    local_file.flush().await?;
    Ok(copied)
}

/// Streams the local file into the remote path (the remote is truncated).
async fn upload_file(sftp: &SftpSession, local: &str, remote: &str) -> io::Result<u64> {
    let mut local_file = tokio::fs::File::open(local).await?;
    let mut remote_file = sftp
        .create(remote)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let copied = tokio::io::copy(
        &mut BufReader::with_capacity(COPY_BUFFER, &mut local_file),
        &mut remote_file,
    )
    .await?;
    remote_file.flush().await?;
    Ok(copied)
}

pub(crate) fn join_path(cwd: &str, requested: Option<&str>) -> String {
    match requested {
        None | Some(".") | Some("") => cwd.to_string(),
        Some(path) if path.starts_with('/') => path.to_string(),
        Some(path) => format!("{}/{}", cwd.trim_end_matches('/'), path).replace("//", "/"),
    }
}

pub(crate) fn split_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut started = false;
    let flush = |fields: &mut Vec<String>, current: &mut String, started: &mut bool| {
        if *started {
            fields.push(current.clone());
            current.clear();
            *started = false;
        }
    };
    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            ' ' | '\t' if !in_quotes => {
                flush(&mut fields, &mut current, &mut started);
            }
            _ => {
                current.push(ch);
                started = true;
            }
        }
    }
    if in_quotes {
        return fields;
    }
    flush(&mut fields, &mut current, &mut started);
    fields
}

async fn print_help<W>(writer: &mut W)
where
    W: AsyncWrite + ?Sized + Unpin,
{
    let _ = writer
        .write_all(
            b"Commands:\n  ls [path], cd <path>, pwd\n  get <remote> [local], put <local> <remote>\n  mkdir <path>, rmdir <path>, rm <path>\n  help, quit, exit\n",
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::{join_path, split_fields};

    #[test]
    fn split_fields_simple_args() {
        assert_eq!(split_fields("ls -la /tmp"), vec!["ls", "-la", "/tmp"]);
    }

    #[test]
    fn split_fields_handles_quotes() {
        assert_eq!(
            split_fields("get \"remote file.txt\" local.txt"),
            vec!["get", "remote file.txt", "local.txt"]
        );
    }

    #[test]
    fn split_fields_handles_quotes_with_spaces() {
        assert_eq!(split_fields("\"a b c\" d"), vec!["a b c", "d"]);
    }

    #[test]
    fn split_fields_handles_empty() {
        assert!(split_fields("").is_empty());
        assert!(split_fields("   \t  ").is_empty());
    }

    #[test]
    fn join_path_relative() {
        assert_eq!(
            join_path("/home/user", Some("docs/file.txt")),
            "/home/user/docs/file.txt"
        );
    }

    #[test]
    fn join_path_absolute() {
        assert_eq!(join_path("/home/user", Some("/etc/passwd")), "/etc/passwd");
    }

    #[test]
    fn join_path_missing_arg() {
        assert_eq!(join_path("/home/user", None), "/home/user");
    }

    #[test]
    fn join_path_dot_and_empty() {
        assert_eq!(join_path("/home/user", Some(".")), "/home/user");
        assert_eq!(join_path("/home/user", Some("")), "/home/user");
    }
}
