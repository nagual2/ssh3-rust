//! Session channels: process spawning, input/output pumping and agent forwarding.
//!
//! A "session" channel is the SSH3 equivalent of an SSH session: the client
//! asks for a shell or a command, optionally with a pseudo-terminal, and then
//! exchanges data with the spawned process until it exits.

use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

#[cfg(unix)]
use nix::sys::signal;
#[cfg(unix)]
use nix::unistd::{Gid, Pid, Uid, User};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{ChildStdin, Command};

use quinn::Connection;
use ssh3_core::Ssh3Channel;
use ssh3_proto::{
    SSH_EXTENDED_DATA_NONE, SSH_EXTENDED_DATA_STDERR, Ssh3ChannelRequest,
    Ssh3ChannelRequestMessage, Ssh3ExitStatusRequest, Ssh3Message, Ssh3SignalRequest,
};
use ssh3_quinn::open_channel;

use crate::auth::{RequestAuthorization, requested_username};
use crate::config::Ssh3ServerConfig;
use crate::error::{Ssh3ServerError, is_benign_server_error};
use crate::pty::SessionPtySize;
#[cfg(unix)]
use crate::pty::{PtyController, spawn_pty_session_process};

/// The operating-system account a session is executed as.
#[derive(Clone, Debug)]
pub(crate) struct SessionUser {
    /// Login name of the account.
    pub(crate) username: String,
    /// Home directory of the account; used as `HOME` and working directory.
    pub(crate) home_dir: PathBuf,
    /// Login shell of the account; used when the server has no override.
    pub(crate) shell: PathBuf,
    /// Numeric user id (Unix only).
    #[cfg(unix)]
    pub(crate) uid: u32,
    /// Numeric group id (Unix only).
    #[cfg(unix)]
    pub(crate) gid: u32,
}

/// The kind of program a session channel runs.
#[derive(Clone, Debug)]
pub(crate) enum SessionCommand {
    /// An interactive login shell.
    Shell,
    /// A single command executed through the login shell (`shell -c <command>`).
    Exec(String),
}

/// Looks up an operating-system account by name.
#[cfg(unix)]
pub(crate) fn lookup_session_user(username: &str) -> io::Result<SessionUser> {
    let Some(user) = User::from_name(username).map_err(io::Error::from)? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("unknown user: {username}"),
        ));
    };

    Ok(SessionUser {
        username: user.name,
        home_dir: user.dir,
        shell: if user.shell.as_os_str().is_empty() {
            PathBuf::from("/bin/sh")
        } else {
            user.shell
        },
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
    })
}

/// Looks up an operating-system account by name.
#[cfg(not(unix))]
pub(crate) fn lookup_session_user(username: &str) -> io::Result<SessionUser> {
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let home_dir = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Ok(SessionUser {
        username: username.to_string(),
        home_dir: PathBuf::from(home_dir),
        shell: PathBuf::from(shell),
    })
}

/// Determines the account a request should run as and looks it up.
///
/// A user name taken from HTTP basic authentication wins over the one
/// requested by the client, because it is the name the password belongs to.
pub(crate) fn resolve_session_user(
    request: &http::Request<()>,
    authorization: &RequestAuthorization,
    config: &Ssh3ServerConfig,
) -> io::Result<SessionUser> {
    let username = match authorization {
        RequestAuthorization::Basic { username, .. } if !username.is_empty() => {
            Some(username.clone())
        }
        _ => requested_username(request, config),
    }
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no SSH3 user was requested and no default server user is configured",
        )
    })?;
    lookup_session_user(&username)
}

/// Returns the shell used for a session.
///
/// The server-wide override wins; otherwise the login shell of the account is
/// used, falling back to `/bin/sh`.
pub(crate) fn effective_shell(config: &Ssh3ServerConfig, session_user: &SessionUser) -> PathBuf {
    config
        .shell
        .clone()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| {
            if session_user.shell.as_os_str().is_empty() {
                PathBuf::from("/bin/sh")
            } else {
                session_user.shell.clone()
            }
        })
}

/// Returns the `argv[0]` of a login shell (a name starting with `-`).
#[cfg(unix)]
fn login_shell_arg0(shell: &Path) -> String {
    let file_name = shell
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sh");
    format!("-{file_name}")
}

/// Applies the environment and credentials of the session user to a process.
pub(crate) fn configure_process(
    process: &mut Command,
    config: &Ssh3ServerConfig,
    session_user: &SessionUser,
    command: &SessionCommand,
    agent_socket_path: Option<&Path>,
) {
    let shell = effective_shell(config, session_user);
    process.kill_on_drop(true);
    process.env("HOME", &session_user.home_dir);
    process.env("USER", &session_user.username);
    process.env("LOGNAME", &session_user.username);
    process.env("SHELL", &shell);
    if let Some(agent_socket_path) = agent_socket_path {
        process.env("SSH_AUTH_SOCK", agent_socket_path);
    }
    process.env(
        "PATH",
        env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".to_string()),
    );
    if session_user.home_dir.is_dir() {
        process.current_dir(&session_user.home_dir);
    }

    #[cfg(unix)]
    {
        if session_user.uid != Uid::current().as_raw()
            || session_user.gid != Gid::current().as_raw()
        {
            process.uid(session_user.uid);
            process.gid(session_user.gid);
        }
        if matches!(command, SessionCommand::Shell) {
            process.arg0(login_shell_arg0(&shell));
        }
    }
}

/// The PTY request that was received before the session started.
#[derive(Clone, Debug)]
pub(crate) struct PendingPty {
    /// Value of the `TERM` environment variable requested by the client.
    pub(crate) term: Option<String>,
    /// Initial terminal size.
    pub(crate) size: SessionPtySize,
}

/// State of a forwarded SSH agent socket (Unix only).
#[cfg(unix)]
pub(crate) struct AgentForwarding {
    socket_path: PathBuf,
    socket_dir: PathBuf,
    listener_task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl AgentForwarding {
    fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

#[cfg(unix)]
impl Drop for AgentForwarding {
    fn drop(&mut self) {
        self.listener_task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_dir(&self.socket_dir);
    }
}

/// The input side of a running session: either a pipe or a pseudo-terminal.
pub(crate) enum SessionInput {
    /// Standard input of a process without a pseudo-terminal.
    Pipe(ChildStdin),
    /// Master side of a pseudo-terminal.
    Pty(TokioFile),
}

impl SessionInput {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), Ssh3ServerError> {
        match self {
            Self::Pipe(stdin) => {
                stdin.write_all(data).await?;
                stdin.flush().await?;
            }
            Self::Pty(pty) => {
                pty.write_all(data).await?;
                pty.flush().await?;
            }
        }
        Ok(())
    }
}

/// A session process that is currently running.
pub(crate) struct RunningSession {
    /// Where the input of the client is written to.
    pub(crate) input: SessionInput,
    /// Process id of the child, used to deliver signals.
    pub(crate) child_id: Option<u32>,
    /// Pseudo-terminal of the session, if one was requested.
    #[cfg(unix)]
    pub(crate) pty: Option<PtyController>,
}

impl RunningSession {
    async fn write_input(&mut self, data: &[u8]) -> Result<(), Ssh3ServerError> {
        self.input.write_all(data).await
    }

    fn apply_window_change(&self, size: SessionPtySize) -> Result<(), Ssh3ServerError> {
        #[cfg(unix)]
        {
            if let Some(pty) = &self.pty {
                pty.resize(size)?;
                return Ok(());
            }
        }
        Err(Ssh3ServerError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "window-change requires a PTY-backed session",
        )))
    }

    fn send_signal(&self, request: &Ssh3SignalRequest) -> Result<(), Ssh3ServerError> {
        #[cfg(not(unix))]
        {
            let _ = request;
            return Err(Ssh3ServerError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "signal forwarding is not supported on this platform",
            )));
        }

        #[cfg(unix)]
        let signal = crate::pty::parse_signal_request(request).ok_or_else(|| {
            Ssh3ServerError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unsupported signal: {}",
                    String::from_utf8_lossy(&request.signal_name_without_sig)
                ),
            ))
        })?;
        let Some(child_id) = self.child_id else {
            return Err(Ssh3ServerError::Io(io::Error::other(
                "running session does not have a child pid",
            )));
        };

        #[cfg(unix)]
        {
            let pid = child_id as i32;
            if self.pty.is_some() {
                signal::kill(Pid::from_raw(-pid), signal).map_err(io::Error::from)?;
            } else {
                signal::kill(Pid::from_raw(pid), signal).map_err(io::Error::from)?;
            }
            return Ok(());
        }

        #[allow(unreachable_code)]
        Err(Ssh3ServerError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "signal forwarding is not supported on this platform",
        )))
    }
}

/// Handles a channel that is not a session channel.
pub(crate) async fn handle_plain_channel(
    channel: Arc<Ssh3Channel>,
    conversation: Arc<ssh3_core::Ssh3Conversation>,
    connection: Connection,
    config: Ssh3ServerConfig,
    session_user: SessionUser,
) -> Result<(), Ssh3ServerError> {
    if channel.channel_type() == b"session" {
        handle_session_channel(channel, conversation, connection, config, session_user).await
    } else {
        write_stderr(
            channel.as_ref(),
            format!(
                "unsupported channel type: {}\n",
                String::from_utf8_lossy(channel.channel_type())
            )
            .as_bytes(),
        )
        .await?;
        channel.close().await?;
        Ok(())
    }
}

/// Runs the request loop of a session channel.
///
/// The loop dispatches the channel requests of the client (`pty-req`,
/// `shell`, `exec`, `signal`, `window-change`) and forwards channel data to
/// the running process. A PTY request is only accepted before the session
/// has started.
pub(crate) async fn handle_session_channel(
    channel: Arc<Ssh3Channel>,
    conversation: Arc<ssh3_core::Ssh3Conversation>,
    connection: Connection,
    config: Ssh3ServerConfig,
    session_user: SessionUser,
) -> Result<(), Ssh3ServerError> {
    let mut pending_pty: Option<PendingPty> = None;
    #[cfg(unix)]
    let mut agent_forwarding: Option<AgentForwarding> = None;
    let mut session: Option<RunningSession> = None;

    loop {
        let message = channel.next_message().await?;
        match message {
            Ssh3Message::ChannelRequest(request) => match request.request {
                Ssh3ChannelRequest::Pty(pty) => {
                    if session.is_some() {
                        write_stderr(
                            channel.as_ref(),
                            b"cannot request a PTY after the session has started\n",
                        )
                        .await?;
                    } else {
                        pending_pty = Some(PendingPty {
                            term: ssh_bytes_to_string(&pty.term),
                            size: SessionPtySize::from_pty_request(&pty),
                        });
                    }
                }
                Ssh3ChannelRequest::Shell => {
                    if session.is_none() {
                        session = Some(
                            spawn_session_process(
                                channel.clone(),
                                &config,
                                &session_user,
                                pending_pty.clone(),
                                {
                                    #[cfg(unix)]
                                    {
                                        agent_forwarding.as_ref().map(AgentForwarding::socket_path)
                                    }
                                    #[cfg(not(unix))]
                                    {
                                        None
                                    }
                                },
                                SessionCommand::Shell,
                            )
                            .await?,
                        );
                    } else {
                        write_stderr(channel.as_ref(), b"session is already running\n").await?;
                    }
                }
                Ssh3ChannelRequest::Exec(exec) => {
                    if session.is_none() {
                        session = Some(
                            spawn_session_process(
                                channel.clone(),
                                &config,
                                &session_user,
                                pending_pty.clone(),
                                {
                                    #[cfg(unix)]
                                    {
                                        agent_forwarding.as_ref().map(AgentForwarding::socket_path)
                                    }
                                    #[cfg(not(unix))]
                                    {
                                        None
                                    }
                                },
                                SessionCommand::Exec(
                                    ssh_bytes_to_string(&exec.command).unwrap_or_default(),
                                ),
                            )
                            .await?,
                        );
                    } else {
                        write_stderr(channel.as_ref(), b"session is already running\n").await?;
                    }
                }
                Ssh3ChannelRequest::Signal(signal) => {
                    if let Some(session) = session.as_ref() {
                        if let Err(err) = session.send_signal(&signal) {
                            write_stderr(channel.as_ref(), format!("{err}\n").as_bytes()).await?;
                        }
                    } else {
                        write_stderr(
                            channel.as_ref(),
                            b"cannot signal a session before it has started\n",
                        )
                        .await?;
                    }
                }
                Ssh3ChannelRequest::WindowChange(window_change) => {
                    let size = SessionPtySize::from_window_change(&window_change);
                    if let Some(session) = session.as_mut() {
                        if let Err(err) = session.apply_window_change(size) {
                            write_stderr(channel.as_ref(), format!("{err}\n").as_bytes()).await?;
                        }
                    } else if let Some(pending_pty) = pending_pty.as_mut() {
                        pending_pty.size = size;
                    } else {
                        write_stderr(
                            channel.as_ref(),
                            b"window-change requires a pending or running PTY session\n",
                        )
                        .await?;
                    }
                }
                other => {
                    write_stderr(
                        channel.as_ref(),
                        format!("unsupported session request: {other:?}\n").as_bytes(),
                    )
                    .await?;
                }
            },
            Ssh3Message::Data(message) => {
                if message.data_type != SSH_EXTENDED_DATA_NONE {
                    write_stderr(channel.as_ref(), b"unsupported extended data message\n").await?;
                    continue;
                }
                if let Some(session) = session.as_mut() {
                    session.write_input(&message.data).await?;
                } else if message.data == b"forward-agent" {
                    #[cfg(unix)]
                    {
                        if agent_forwarding.is_none() {
                            agent_forwarding = Some(
                                open_agent_socket_and_forward_agent(
                                    conversation.clone(),
                                    connection.clone(),
                                    &config,
                                    &session_user,
                                )
                                .await?,
                            );
                        }
                    }

                    #[cfg(not(unix))]
                    {
                        write_stderr(
                            channel.as_ref(),
                            b"agent forwarding is not supported on this platform\n",
                        )
                        .await?;
                    }
                } else {
                    write_stderr(
                        channel.as_ref(),
                        b"cannot send session data before the session has started\n",
                    )
                    .await?;
                }
            }
            _ => {}
        }
    }
}

/// Starts a session process, with or without a pseudo-terminal.
async fn spawn_session_process(
    channel: Arc<Ssh3Channel>,
    config: &Ssh3ServerConfig,
    session_user: &SessionUser,
    pending_pty: Option<PendingPty>,
    agent_socket_path: Option<&Path>,
    command: SessionCommand,
) -> Result<RunningSession, Ssh3ServerError> {
    #[cfg(unix)]
    if let Some(pending_pty) = pending_pty {
        return spawn_pty_session_process(
            channel,
            config,
            session_user,
            pending_pty,
            agent_socket_path,
            command,
        )
        .await;
    }

    #[cfg(not(unix))]
    if pending_pty.is_some() {
        return Err(Ssh3ServerError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "PTY requests are not supported on this platform",
        )));
    }

    spawn_pipe_session_process(channel, config, session_user, agent_socket_path, command).await
}

/// Starts a session process connected to the process pipes.
async fn spawn_pipe_session_process(
    channel: Arc<Ssh3Channel>,
    config: &Ssh3ServerConfig,
    session_user: &SessionUser,
    agent_socket_path: Option<&Path>,
    command: SessionCommand,
) -> Result<RunningSession, Ssh3ServerError> {
    let shell = effective_shell(config, session_user);
    let mut process = Command::new(&shell);
    if let SessionCommand::Exec(command) = &command {
        process.arg("-c").arg(command);
    }
    configure_process(
        &mut process,
        config,
        session_user,
        &command,
        agent_socket_path,
    );
    process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = process.spawn()?;
    let child_id = child.id();
    let stdin = child.stdin.take().ok_or_else(|| {
        Ssh3ServerError::Io(io::Error::other("spawned process did not expose stdin"))
    })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let stdout_task = tokio::spawn(pump_process_output(
        stdout,
        channel.clone(),
        SSH_EXTENDED_DATA_NONE,
    ));
    let stderr_task = tokio::spawn(pump_process_output(
        stderr,
        channel.clone(),
        SSH_EXTENDED_DATA_STDERR,
    ));

    tokio::spawn(async move {
        let status = child.wait().await;
        let _ = stdout_task.await;
        let _ = stderr_task.await;

        let exit_status = status
            .ok()
            .and_then(|status| status.code())
            .unwrap_or(1)
            .max(0) as u64;
        let _ = channel
            .send_request(Ssh3ChannelRequestMessage {
                want_reply: false,
                request: Ssh3ChannelRequest::ExitStatus(Ssh3ExitStatusRequest { exit_status }),
            })
            .await;
    });

    Ok(RunningSession {
        input: SessionInput::Pipe(stdin),
        child_id,
        #[cfg(unix)]
        pty: None,
    })
}

/// Creates the private directory and socket path of a forwarded agent socket.
#[cfg(unix)]
fn new_agent_socket_paths() -> io::Result<(PathBuf, PathBuf)> {
    let unique = format!(
        "ssh3-agent-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let socket_dir = env::temp_dir().join(unique);
    std::fs::create_dir(&socket_dir)?;
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700))?;
    let socket_path = socket_dir.join(format!("agent.{}", std::process::id()));
    Ok((socket_dir, socket_path))
}

/// Restricts the agent socket to the session user.
#[cfg(unix)]
fn prepare_agent_socket_permissions(
    socket_dir: &Path,
    socket_path: &Path,
    session_user: &SessionUser,
) -> io::Result<()> {
    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    if session_user.uid != Uid::current().as_raw() || session_user.gid != Gid::current().as_raw() {
        nix::unistd::chown(
            socket_dir,
            Some(Uid::from_raw(session_user.uid)),
            Some(Gid::from_raw(session_user.gid)),
        )
        .map_err(io::Error::from)?;
        nix::unistd::chown(
            socket_path,
            Some(Uid::from_raw(session_user.uid)),
            Some(Gid::from_raw(session_user.gid)),
        )
        .map_err(io::Error::from)?;
    }

    Ok(())
}

/// Bridges a local agent socket connection to an SSH3 channel.
#[cfg(unix)]
async fn handle_agent_socket_conn(
    stream: UnixStream,
    conversation: Arc<ssh3_core::Ssh3Conversation>,
    connection: Connection,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
) -> Result<(), Ssh3ServerError> {
    let channel = open_channel(
        conversation.as_ref(),
        &connection,
        b"agent-connection".to_vec(),
        max_packet_size,
        default_datagrams_queue_size,
    )
    .await?;
    channel.maybe_send_header().await?;
    channel.wait_for_confirmation().await?;
    let (mut reader, mut writer) = stream.into_split();

    let mut to_socket = tokio::spawn({
        let channel = channel.clone();
        async move {
            loop {
                let message = channel.next_message().await?;
                if let Ssh3Message::Data(data) = message
                    && data.data_type == SSH_EXTENDED_DATA_NONE
                {
                    writer.write_all(&data.data).await?;
                    writer.flush().await?;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), Ssh3ServerError>(())
        }
    });

    let mut from_socket = tokio::spawn({
        let channel = channel.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    let _ = channel.close().await;
                    return Ok::<(), Ssh3ServerError>(());
                }
                channel
                    .write_data(&buf[..n], SSH_EXTENDED_DATA_NONE)
                    .await?;
            }
        }
    });

    tokio::select! {
        result = &mut to_socket => {
            from_socket.abort();
            let _ = channel.close().await;
            result.map_err(|err| Ssh3ServerError::Io(io::Error::other(err.to_string())))?
        }
        result = &mut from_socket => {
            to_socket.abort();
            let _ = channel.close().await;
            result.map_err(|err| Ssh3ServerError::Io(io::Error::other(err.to_string())))?
        }
    }
}

/// Starts listening for local connections that shall be forwarded to the agent.
#[cfg(unix)]
async fn open_agent_socket_and_forward_agent(
    conversation: Arc<ssh3_core::Ssh3Conversation>,
    connection: Connection,
    config: &Ssh3ServerConfig,
    session_user: &SessionUser,
) -> Result<AgentForwarding, Ssh3ServerError> {
    let (socket_dir, socket_path) = new_agent_socket_paths()?;
    let listener = UnixListener::bind(&socket_path)?;
    prepare_agent_socket_permissions(&socket_dir, &socket_path, session_user)?;

    let listener_task = tokio::spawn({
        let conversation = conversation.clone();
        let connection = connection.clone();
        let max_packet_size = config.max_packet_size;
        let default_datagrams_queue_size = config.default_datagrams_queue_size;
        async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(stream) => stream,
                    Err(err) => {
                        eprintln!("ssh3-rust-server agent socket accept error: {err}");
                        return;
                    }
                };
                let conversation = conversation.clone();
                let connection = connection.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_agent_socket_conn(
                        stream,
                        conversation,
                        connection,
                        max_packet_size,
                        default_datagrams_queue_size,
                    )
                    .await
                    {
                        if !is_benign_server_error(&err) {
                            eprintln!("ssh3-rust-server agent forwarding error: {err}");
                        }
                    }
                });
            }
        }
    });

    Ok(AgentForwarding {
        socket_path,
        socket_dir,
        listener_task,
    })
}

/// Copies the output of a process into the channel as data messages.
pub(crate) async fn pump_process_output<R>(
    reader: Option<R>,
    channel: Arc<Ssh3Channel>,
    data_type: u64,
) -> Result<(), Ssh3ServerError>
where
    R: AsyncRead + Unpin,
{
    let Some(mut reader) = reader else {
        return Ok(());
    };

    let mut buf = vec![
        0;
        usize::try_from(channel.max_packet_size())
            .unwrap_or(30_000)
            .max(1)
    ];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        channel.write_data(&buf[..n], data_type).await?;
    }
}

/// Writes a diagnostic message to the extended data stream of a channel.
pub(crate) async fn write_stderr(
    channel: &Ssh3Channel,
    message: &[u8],
) -> Result<(), Ssh3ServerError> {
    channel
        .write_data(message, SSH_EXTENDED_DATA_STDERR)
        .await
        .map(|_| ())
        .map_err(Ssh3ServerError::from)
}

/// Decodes bytes received from the client into a string, lossily.
pub(crate) fn ssh_bytes_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}
