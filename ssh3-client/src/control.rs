//! The control master (the `-M`/`-S`/`-O` family): one authenticated
//! connection shared across client invocations.
//!
//! The master serves the control socket of the `client/cm` codec (see
//! [`crate::cm`]): a slave asks it for a session or a forward over the unix
//! socket, the master opens the channels on its own connection and bridges
//! the slave streams into them. The control op family (`-O check|stop|exit`)
//! rides on the same codec, so a master can grow new operations without
//! touching the framing.
//!
//! The socket, the session map and the bridges mirror `client/master.go` of
//! the reference implementation; the slave mirrors `client/slave.go`. The
//! wiring is unix-only, exactly like the reference.

// The library layer is complete; the CLI wiring lights the flags up in the
// next commit.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::forward::{Ssh3ForwardProtocol, Ssh3LocalForwardSpec};
use crate::{ActiveClient, PtySpec, Ssh3Channel, Ssh3SessionRequest};
use crate::{cm, cm::Attach};
use cm::{
    CM_PROTOCOL_VERSION, MSG_CONTROL_OP, MsgType, OpenForward, OpenSession, SessionToken, Signal,
    StreamKind, WindowChange, decode_exit_status, encode_exit_status,
};

/// The control operation names accepted by `ssh -O <op>`.
pub const CONTROL_OP_CHECK: &str = "check";
pub const CONTROL_OP_STOP: &str = "stop";
pub const CONTROL_OP_EXIT: &str = "exit";

/// Bounds one `-O <op>` operation: check returns as soon as the master
/// answers, stop additionally waits for the socket to be released.
const CONTROL_OP_TIMEOUT: Duration = Duration::from_secs(5);

/// The poll step while waiting for a master to release its socket, the same
/// small step the reference waits with.
const MASTER_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// The errors of the control master and of its slaves.
#[derive(Debug)]
pub enum ControlMasterError {
    /// The control socket cannot be served.
    Io(io::Error),
    /// The peer on the socket is not a control master, or the protocol
    /// exchange failed.
    Protocol(String),
    /// The master refused a request.
    Refused(String),
}

impl std::fmt::Display for ControlMasterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Protocol(reason) => write!(f, "control master: {reason}"),
            Self::Refused(reason) => write!(f, "the control master refused: {reason}"),
        }
    }
}

impl std::error::Error for ControlMasterError {}

impl From<io::Error> for ControlMasterError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<cm::CmError> for ControlMasterError {
    fn from(value: cm::CmError) -> Self {
        match value {
            cm::CmError::Refused(reason) => Self::Refused(reason),
            other => Self::Protocol(other.to_string()),
        }
    }
}

/// The snapshot a check op reports about a live master (`-O check`).
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct MasterStatus {
    /// The control socket path.
    pub path: String,
    /// The pid of the serving process.
    pub pid: u32,
    /// The control-channel protocol version.
    pub protocol: u8,
    /// Seconds since the master started serving.
    pub uptime_s: f64,
    /// The bridged sessions currently running.
    pub sessions: usize,
    /// The forwards opened through the master.
    pub forwards: u64,
}

impl MasterStatus {
    /// Renders the status as a single line for the CLI, the way the
    /// reference implementation prints it.
    pub fn status_line(&self) -> String {
        let uptime = Duration::from_secs_f64(self.uptime_s.max(0.0));
        format!(
            "Master running (pid={}), uptime {:?}, {} session(s), {} forward(s)",
            self.pid, uptime, self.sessions, self.forwards
        )
    }
}

/// Encodes one control operation name (uint32 length + bytes), the wire form
/// `encodeControlOp` of the reference carries.
pub fn encode_control_op(op: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + op.len());
    out.extend_from_slice(&(op.len() as u32).to_be_bytes());
    out.extend_from_slice(op.as_bytes());
    out
}

/// Decodes one control operation name; trailing bytes are ignored so a newer
/// client may extend the payload.
fn decode_control_op(payload: &[u8]) -> Result<String, ControlMasterError> {
    if payload.len() < 4 {
        return Err(ControlMasterError::Protocol(
            "truncated control operation".to_string(),
        ));
    }
    let (length, rest) = payload.split_at(4);
    let length = u32::from_be_bytes(length.try_into().expect("fixed size")) as usize;
    if rest.len() < length {
        return Err(ControlMasterError::Protocol(
            "truncated control operation".to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&rest[..length]).into_owned())
}

/// Returns the default control socket path of a target, the
/// `~/.ssh3/cm-<user>@<host>:<port>` form of the reference implementation.
pub fn default_control_path(user: &str, host: &str, port: u16) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    Path::new(&home)
        .join(".ssh3")
        .join(format!("cm-{user}@{host}:{port}"))
}

/// Reports whether anything listens on the control socket.
///
/// A successful dial (even before the master accepts it) proves a live
/// listener owns the path and the file must not be touched.
fn listener_alive(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

/// Creates and prepares the control-master unix listener with 0600
/// permissions.
///
/// A master killed with SIGKILL leaves its socket file behind; the bind then
/// fails with `AddressInUse` although nobody serves it, so the file is
/// unlinked and the bind retried once - but only after a dial confirms
/// nothing is listening (a live master always answers a connect).
pub fn listen_control_master(path: &Path) -> io::Result<StdUnixListener> {
    let listener = match StdUnixListener::bind(path) {
        Ok(listener) => listener,
        Err(err) if err.kind() == io::ErrorKind::AddrInUse && !listener_alive(path) => {
            std::fs::remove_file(path).ok();
            StdUnixListener::bind(path)?
        }
        Err(err) => return Err(err),
    };
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Reports whether a control master answers the version handshake on `path`.
pub async fn ping_master(path: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(path).await else {
        return false;
    };
    cm::hello(&mut stream).await.is_ok()
}

/// Performs the version handshake of a control socket.
async fn hello(stream: &mut UnixStream) -> Result<(), ControlMasterError> {
    Ok(cm::hello(stream).await?)
}

/// Sends one request and reads the reply.
async fn call(
    stream: &mut UnixStream,
    typ: MsgType,
    payload: &[u8],
) -> Result<Vec<u8>, ControlMasterError> {
    Ok(cm::call(stream, typ, payload).await?)
}

/// Waits until the master stopped serving on `path`, bounded by `timeout`.
async fn wait_master_released(path: &Path, timeout: Duration) -> Result<(), ControlMasterError> {
    let deadline = tokio::time::Instant::now() + timeout;
    while ping_master(path).await {
        if tokio::time::Instant::now() >= deadline {
            return Err(ControlMasterError::Protocol(format!(
                "the control master has not released {}",
                path.display()
            )));
        }
        tokio::time::sleep(MASTER_POLL_INTERVAL).await;
    }
    Ok(())
}

/// Runs one `ssh -O <op>` operation against the master listening on `path`.
///
/// `check` returns the status snapshot; `stop` and `exit` shut the master
/// down (stop also waits until the socket is released) and return `None`.
/// An unknown operation is passed to the master, which refuses it with a
/// clear error, the way `RunControlOp` of the reference does.
pub async fn run_control_op(
    path: &Path,
    op: &str,
) -> Result<Option<MasterStatus>, ControlMasterError> {
    let mut stream = UnixStream::connect(path).await.map_err(|err| {
        ControlMasterError::Protocol(format!(
            "no control master is listening on {}: {err}",
            path.display()
        ))
    })?;
    hello(&mut stream).await?;
    let reply = call(&mut stream, MsgType(MSG_CONTROL_OP), &encode_control_op(op))
        .await
        .map_err(|err| match err {
            ControlMasterError::Refused(reason) if reason.contains("unexpected message") => {
                ControlMasterError::Protocol(format!(
                    "the control master does not support the {op:?} control operation (it predates the -O check/stop extension)"
                ))
            }
            other => other,
        })?;
    if op == CONTROL_OP_CHECK {
        let status = serde_json::from_slice::<MasterStatus>(&reply).map_err(|err| {
            ControlMasterError::Protocol(format!(
                "malformed check reply from the control master: {err}"
            ))
        })?;
        return Ok(Some(status));
    }
    if op == CONTROL_OP_STOP {
        wait_master_released(path, CONTROL_OP_TIMEOUT).await?;
    }
    Ok(None)
}

/// One slave-requested session awaiting or running its bridge.
struct PendingSession {
    channel: Arc<Ssh3Channel>,
    pty_requested: bool,
    control: Option<UnixStream>,
    stderr: Option<UnixStream>,
    started: bool,
}

/// The mutable state of one serving master: the shutdown signal, the
/// bridged sessions and the bookkeeping a check op reports.
struct MasterState {
    path: PathBuf,
    started: Instant,
    sessions: Mutex<HashMap<SessionToken, PendingSession>>,
    forwards: AtomicU64,
    closing: AtomicBool,
    shutdown: watch::Sender<bool>,
}

impl MasterState {
    /// Reports whether the master is shutting down.
    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    /// Starts the shutdown: the accept loop ends and the socket file is
    /// removed on the way out. Idempotent, so the exit op, the idle timeout
    /// and a dropped context may all request it.
    fn shutdown(&self) {
        if self
            .closing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let _ = self.shutdown.send(true);
        }
    }

    /// Builds the status snapshot a check op reports.
    fn status(&self, sessions: usize) -> MasterStatus {
        MasterStatus {
            path: self.path.display().to_string(),
            pid: std::process::id(),
            protocol: CM_PROTOCOL_VERSION,
            uptime_s: self.started.elapsed().as_secs_f64(),
            sessions,
            forwards: self.forwards.load(Ordering::SeqCst),
        }
    }
}

/// Serves the control channel on `ln` until a slave sends EXIT or STOP or
/// the idle timeout fires.
///
/// `client` must be an authenticated connection; every slave session then
/// runs as a channel on it, the way `ServeControlMaster` of the reference
/// shares one connection across the CLI invocations. With an idle timeout
/// the master stops after that much inactivity (no running sessions and no
/// control connections), the `-control-persist=N` semantics. On return the
/// socket file is removed (clean teardown).
pub async fn serve_control_master(
    client: Arc<ActiveClient>,
    path: PathBuf,
    ln: StdUnixListener,
    idle_timeout: Option<Duration>,
) -> Result<(), ControlMasterError> {
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    let state = Arc::new(MasterState {
        path,
        started: Instant::now(),
        sessions: Mutex::new(HashMap::new()),
        forwards: AtomicU64::new(0),
        closing: AtomicBool::new(false),
        shutdown,
    });

    let listener = tokio::net::UnixListener::from_std(ln)?;
    let idle_task = idle_timeout.map(|timeout| {
        let state = state.clone();
        tokio::spawn(async move {
            // A quarter of the timeout, clamped to a sane range, the same
            // tick the reference idles out with.
            let tick = (timeout / 4).clamp(Duration::from_millis(50), Duration::from_secs(1));
            loop {
                tokio::time::sleep(tick).await;
                if *state.shutdown.subscribe().borrow() {
                    return;
                }
                let sessions = state.sessions.lock().unwrap().len();
                if sessions == 0 && state.started.elapsed() >= timeout {
                    state.shutdown();
                    return;
                }
            }
        })
    });

    let mut result = Ok(());
    loop {
        let (stream, _addr) = tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    result = Err(ControlMasterError::Io(err));
                    break;
                }
            },
        };
        if state.is_closing() {
            break;
        }
        let client = client.clone();
        let state = state.clone();
        tokio::spawn(async move {
            handle_control_conn(client, state, stream).await;
        });
    }

    if let Some(task) = idle_task {
        task.abort();
    }
    std::fs::remove_file(&state.path).ok();
    result
}

/// Sends an error frame to a control peer.
async fn send_error(stream: &mut UnixStream, message: &str) {
    let _ = cm::write_frame(stream, MsgType::ERROR, message.as_bytes()).await;
}

/// Drives one control or stream attachment connection.
///
/// Connections whose ownership moves to a session bridge (the stderr and io
/// attachments, and the control connection of a started session) are closed
/// by the bridge, not here, the way `handleMasterConn` moves them in the
/// reference.
async fn handle_control_conn(
    client: Arc<ActiveClient>,
    state: Arc<MasterState>,
    mut conn: UnixStream,
) {
    let (typ, _) = match cm::read_frame(&mut conn).await {
        Ok(Some(frame)) => frame,
        Ok(None) | Err(_) => return,
    };
    if typ != MsgType::HELLO {
        send_error(&mut conn, "expected HELLO").await;
        return;
    }
    if cm::write_frame(&mut conn, MsgType::OK, &[]).await.is_err() {
        return;
    }

    loop {
        let (typ, payload) = match cm::read_frame(&mut conn).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => return,
        };
        match typ {
            MsgType::OPEN_SESSION => {
                if state.is_closing() {
                    send_error(&mut conn, "the control master is shutting down").await;
                    continue;
                }
                let request = match OpenSession::decode(&payload) {
                    Ok(request) => request,
                    Err(err) => {
                        send_error(&mut conn, &format!("malformed OPEN_SESSION: {err}")).await;
                        continue;
                    }
                };
                let (token, mut session) = match master_open_session(&client, &request).await {
                    Ok(session) => session,
                    Err(err) => {
                        send_error(&mut conn, &err.to_string()).await;
                        continue;
                    }
                };
                // The OK reply goes on the control connection before the
                // session takes it over: the bridge reads its interaction
                // frames and writes the exit status into it, so no second
                // reader races it.
                if cm::write_frame(&mut conn, MsgType::OK, &token.0)
                    .await
                    .is_err()
                {
                    return;
                }
                session.control = Some(conn);
                state.sessions.lock().unwrap().insert(token, session);
                // This handler is done with the connection; the bridge takes
                // it over when the streams attach.
                return;
            }
            MsgType::ATTACH => {
                let attach = match Attach::decode(&payload) {
                    Ok(attach) => attach,
                    Err(err) => {
                        send_error(&mut conn, &format!("malformed ATTACH: {err}")).await;
                        return;
                    }
                };
                // The decision is taken inside one synchronous scope: the
                // mutex guard never crosses an await. The replies go out
                // after the lock is released.
                enum AttachOutcome {
                    Stderr,
                    Io {
                        channel: Arc<Ssh3Channel>,
                        control: UnixStream,
                        stderr: UnixStream,
                        token: SessionToken,
                    },
                    Reject(&'static str),
                }
                let outcome = {
                    let mut guard = state.sessions.lock().unwrap();
                    match guard.get_mut(&attach.token) {
                        None => AttachOutcome::Reject("unknown session token"),
                        Some(session) => match attach.stream {
                            StreamKind::Stderr => {
                                if session.started || session.stderr.is_some() {
                                    AttachOutcome::Reject("stderr stream already attached")
                                } else {
                                    AttachOutcome::Stderr
                                }
                            }
                            StreamKind::Io => {
                                if session.started {
                                    AttachOutcome::Reject("session already started")
                                } else {
                                    let stderr = session.stderr.take();
                                    let control = session.control.take();
                                    match (stderr, control) {
                                        (Some(stderr), Some(control)) => {
                                            session.started = true;
                                            AttachOutcome::Io {
                                                channel: session.channel.clone(),
                                                control,
                                                stderr,
                                                token: attach.token,
                                            }
                                        }
                                        (None, _) => AttachOutcome::Reject(
                                            "the stderr stream must attach before the io stream",
                                        ),
                                        (_, None) => AttachOutcome::Reject(
                                            "the session lost its control connection",
                                        ),
                                    }
                                }
                            }
                        },
                    }
                };
                match outcome {
                    AttachOutcome::Reject(reason) => {
                        send_error(&mut conn, reason).await;
                        return;
                    }
                    AttachOutcome::Stderr => {
                        if cm::write_frame(&mut conn, MsgType::OK, &[]).await.is_err() {
                            return;
                        }
                        state
                            .sessions
                            .lock()
                            .unwrap()
                            .get_mut(&attach.token)
                            .expect("the session outlives the attach decision")
                            .stderr = Some(conn);
                        // The bridge owns this connection now: it is stored
                        // in the session.
                        return;
                    }
                    AttachOutcome::Io {
                        channel,
                        control,
                        stderr,
                        token,
                    } => {
                        if cm::write_frame(&mut conn, MsgType::OK, &[]).await.is_err() {
                            return;
                        }
                        // The control connection also belongs to the bridge.
                        run_master_bridge(channel, control, conn, stderr, state.clone(), token)
                            .await;
                        return;
                    }
                }
            }
            MsgType(n) if n == MSG_CONTROL_OP => {
                let op = match decode_control_op(&payload) {
                    Ok(op) => op,
                    Err(err) => {
                        send_error(&mut conn, &err.to_string()).await;
                        continue;
                    }
                };
                match op.as_str() {
                    CONTROL_OP_CHECK => {
                        let sessions = state.sessions.lock().unwrap().len();
                        let status = state.status(sessions);
                        match serde_json::to_vec(&status) {
                            Ok(json) => {
                                if cm::write_frame(&mut conn, MsgType::OK, &json)
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            Err(err) => {
                                send_error(&mut conn, &err.to_string()).await;
                                continue;
                            }
                        }
                    }
                    CONTROL_OP_STOP | CONTROL_OP_EXIT => {
                        if cm::write_frame(&mut conn, MsgType::OK, &[]).await.is_err() {
                            return;
                        }
                        state.shutdown();
                        return;
                    }
                    unknown => {
                        // Refuse but keep the connection: the caller may retry
                        // with an operation this master does know.
                        send_error(&mut conn, &format!("unknown control operation {unknown:?}"))
                            .await;
                    }
                }
            }
            MsgType::EXIT => {
                let _ = cm::write_frame(&mut conn, MsgType::OK, &[]).await;
                state.shutdown();
                return;
            }
            other => {
                send_error(&mut conn, &format!("unexpected message {other:?}")).await;
                return;
            }
        }
    }
}

/// Opens the session channel of one slave request on the master connection.
///
/// Returns the fresh session token and the pending session; an empty command
/// list is a remote shell, otherwise the joined command line runs remotely,
/// the way `strings.Join(spec.Command, " ")` maps it in the reference.
async fn master_open_session(
    client: &ActiveClient,
    request: &OpenSession,
) -> Result<(SessionToken, PendingSession), ControlMasterError> {
    let channel = client
        .open_session_channel()
        .await
        .map_err(|err| ControlMasterError::Protocol(err.to_string()))?;
    let pty = request.pty.as_ref().map(|pty| PtySpec {
        term: pty.term.as_bytes().to_vec(),
        char_width: pty.columns.clamp(0, u16::MAX as u32) as u16,
        char_height: pty.rows.clamp(0, u16::MAX as u32) as u16,
        pixel_width: pty.pixel_width.clamp(0, u16::MAX as u32) as u16,
        pixel_height: pty.pixel_height.clamp(0, u16::MAX as u32) as u16,
    });
    if request.forward_agent {
        crate::send_forward_agent_request(channel.as_ref())
            .await
            .map_err(|err| ControlMasterError::Protocol(err.to_string()))?;
    }
    let session_request = if request.command.is_empty() {
        Ssh3SessionRequest::Shell
    } else {
        Ssh3SessionRequest::Exec(request.command.join(" "))
    };
    crate::send_initial_session_requests(channel.as_ref(), &session_request, pty.as_ref())
        .await
        .map_err(|err| ControlMasterError::Protocol(err.to_string()))?;
    Ok((
        SessionToken::new(),
        PendingSession {
            channel,
            pty_requested: pty.is_some(),
            control: None,
            stderr: None,
            started: false,
        },
    ))
}

/// Starts a local forward on the master: it listens on the requested local
/// address and relays connections or datagrams to the target through the
/// shared connection, the way `masterOpenForward` does.
async fn master_open_forward(
    client: &ActiveClient,
    typ: MsgType,
    forward: &OpenForward,
) -> Result<String, ControlMasterError> {
    if forward.listen_addr.is_empty() || forward.target_addr.is_empty() {
        return Err(ControlMasterError::Protocol(
            "listen and target addresses are required".to_string(),
        ));
    }
    let (bind_host, bind_port) = split_host_port(&forward.listen_addr)?;
    let (target_host, target_port) = split_host_port(&forward.target_addr)?;
    let protocol = match typ {
        MsgType::OPEN_FORWARD_TCP => Ssh3ForwardProtocol::Tcp,
        _ => Ssh3ForwardProtocol::Udp,
    };
    let spec = Ssh3LocalForwardSpec {
        bind_address: Some(bind_host),
        bind_port,
        target_host,
        target_port,
        protocol,
    };
    crate::forward::start_local_forward(
        client.conversation.clone(),
        client.connection.clone(),
        client.max_packet_size,
        client.default_datagrams_queue_size,
        &spec,
    )
    .await
    .map_err(|err| ControlMasterError::Protocol(err.to_string()))?;
    // The local listener runs in its own task; the requested address is what
    // the slave asked for and gets back.
    Ok(forward.listen_addr.clone())
}

/// Splits a `host:port` pair; IPv6 literals must be bracketed.
fn split_host_port(value: &str) -> Result<(String, u16), ControlMasterError> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| ControlMasterError::Protocol(format!("missing port in {value:?}")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ControlMasterError::Protocol(format!("invalid port in {value:?}")))?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    Ok((host, port))
}

/// Bridges one slave session: the io attachment carries the slave stdin
/// upstream and the session stdout downstream, the stderr attachment carries
/// the session stderr. The control connection carries the interaction frames
/// (window changes, signals) while the session runs and receives the final
/// exit status, the way `runMasterBridge` plus `relaySlaveInteractions` do.
async fn run_master_bridge(
    channel: Arc<Ssh3Channel>,
    mut control: UnixStream,
    io_conn: UnixStream,
    mut err_conn: UnixStream,
    state: Arc<MasterState>,
    token: SessionToken,
) {
    let (mut io_read, mut io_write) = tokio::io::split(io_conn);

    // The slave stdin upstream: a closed io attachment ends the pump without
    // tearing down the stdout direction.
    let stdin_task = {
        let channel = channel.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 32_768];
            loop {
                match io_read.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => {
                        if channel
                            .write_data(&buffer[..read], ssh3_proto::SSH_EXTENDED_DATA_NONE)
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        })
    };

    let mut code = 255u64;
    loop {
        tokio::select! {
            biased;
            message = channel.next_message() => match message {
                Ok(ssh3_proto::Ssh3Message::Data(data)) => {
                    let result = match data.data_type {
                        ssh3_proto::SSH_EXTENDED_DATA_NONE => io_write.write_all(&data.data).await,
                        ssh3_proto::SSH_EXTENDED_DATA_STDERR => err_conn.write_all(&data.data).await,
                        _ => Ok(()),
                    };
                    if result.is_err() {
                        break;
                    }
                }
                Ok(ssh3_proto::Ssh3Message::ChannelRequest(message)) => match message.request {
                    ssh3_proto::Ssh3ChannelRequest::ExitStatus(status) => {
                        code = status.exit_status;
                        break;
                    }
                    // A signal or an unknown request ends the session with
                    // the failure code, the way the reference pump reports a
                    // non-exit-status end.
                    _ => break,
                },
                Ok(_) => {}
                Err(_) => break,
            },
            frame = cm::read_frame(&mut control) => match frame {
                Ok(Some((MsgType::WINDOW_CHANGE, payload))) => {
                    if let Ok(change) = WindowChange::decode(&payload) {
                        let _ = channel
                            .send_request(ssh3_proto::Ssh3ChannelRequestMessage {
                                want_reply: false,
                                request: ssh3_proto::Ssh3ChannelRequest::WindowChange(
                                    ssh3_proto::Ssh3WindowChangeRequest {
                                        char_width: change.columns as u64,
                                        char_height: change.rows as u64,
                                        pixel_width: change.pixel_width as u64,
                                        pixel_height: change.pixel_height as u64,
                                    },
                                ),
                            })
                            .await;
                    }
                }
                Ok(Some((MsgType::SIGNAL, payload))) => {
                    if let Ok(signal) = Signal::decode(&payload) {
                        let _ = channel
                            .send_request(ssh3_proto::Ssh3ChannelRequestMessage {
                                want_reply: false,
                                request: ssh3_proto::Ssh3ChannelRequest::Signal(
                                    ssh3_proto::Ssh3SignalRequest {
                                        signal_name_without_sig: signal.name.into_bytes(),
                                    },
                                ),
                            })
                            .await;
                    }
                }
                Ok(Some(_)) => {
                    // Not an interaction frame (or from a newer protocol):
                    // ignore, like the reference relay does.
                }
                Ok(None) | Err(_) => {}
            },
        }
    }
    stdin_task.abort();
    channel.close().await.ok();
    // The exit status goes back on the control connection.
    let _ = cm::write_frame(
        &mut control,
        MsgType::EXIT_STATUS,
        &encode_exit_status(code),
    )
    .await;
    state.sessions.lock().unwrap().remove(&token);
}

/// Requests a session from the control master on `path` and bridges the
/// given local streams into it.
///
/// The control connection carries the session request and the final exit
/// status; two dedicated connections carry the session streams (stderr
/// attaches first, then the full-duplex io stream), the way
/// `RunSlaveSession` of the reference runs one session through the master.
/// The returned code is the remote exit status (255 for transport failures).
pub async fn run_slave_session<R, W1, W2>(
    control_path: &Path,
    command: Vec<String>,
    pty: Option<OpenSessionPty>,
    forward_agent: bool,
    mut stdin: R,
    mut stdout: W1,
    mut stderr: W2,
) -> Result<i32, ControlMasterError>
where
    R: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    W2: AsyncWrite + Unpin,
{
    let mut control = UnixStream::connect(control_path).await.map_err(|err| {
        ControlMasterError::Protocol(format!("could not reach the control master: {err}"))
    })?;
    hello(&mut control).await?;
    let request = OpenSession {
        command,
        env: Vec::new(),
        pty: pty.map(|pty| cm::PtySpec {
            term: pty.term,
            columns: pty.columns,
            rows: pty.rows,
            pixel_width: pty.pixel_width,
            pixel_height: pty.pixel_height,
        }),
        forward_agent,
    };
    let reply = call(&mut control, MsgType::OPEN_SESSION, &request.encode()).await?;
    let Ok(token) = <[u8; 16]>::try_from(reply.as_slice()) else {
        return Err(ControlMasterError::Protocol(format!(
            "cm: malformed session token reply ({} bytes)",
            reply.len()
        )));
    };
    let token = SessionToken(token);

    // The master starts the pump on the io attachment and needs the stderr
    // sink by then, so stderr must attach first.
    let mut err_conn = attach(control_path, &token, StreamKind::Stderr).await?;
    let io_conn = attach(control_path, &token, StreamKind::Io).await?;

    // The four directions of one session run in a single future: the slave
    // stdin upstream (a closed write half tells the master the input is
    // complete without tearing down the stdout direction), the stdout and
    // the stderr downstream, and the exit status on the control connection.
    let (mut io_read, mut io_write) = tokio::io::split(io_conn);
    let mut stdin_open = true;
    let code: u64;
    let mut got_exit_status = false;
    'session: loop {
        let mut stdin_buffer = [0u8; 16_384];
        let mut io_buffer = [0u8; 16_384];
        let mut err_buffer = [0u8; 16_384];
        tokio::select! {
            biased;
            frame = cm::read_frame(&mut control) => match frame {
                Ok(Some((MsgType::EXIT_STATUS, payload))) => {
                    code = decode_exit_status(&payload)
                        .map_err(|err| ControlMasterError::Protocol(err.to_string()))?;
                    got_exit_status = true;
                    break 'session;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    return Err(ControlMasterError::Protocol(
                        "control channel ended".to_string(),
                    ));
                }
            },
            read = stdin.read(&mut stdin_buffer), if stdin_open => match read {
                Ok(0) | Err(_) => {
                    // Dropping the write half closes the stdin direction of
                    // the io attachment without tearing down the stdout.
                    stdin_open = false;
                }
                Ok(read) => {
                    if io_write.write_all(&stdin_buffer[..read]).await.is_err() {
                        stdin_open = false;
                    }
                }
            },
            read = io_read.read(&mut io_buffer) => match read {
                Ok(0) | Err(_) => {
                    // The session stdout ended before the exit status: the
                    // control connection carries the verdict from here on.
                    code = 255;
                    break 'session;
                }
                Ok(read) => {
                    if stdout.write_all(&io_buffer[..read]).await.is_err() {
                        code = 255;
                        break 'session;
                    }
                }
            },
            read = err_conn.read(&mut err_buffer) => match read {
                Ok(0) | Err(_) => {}
                Ok(read) => {
                    if stderr.write_all(&err_buffer[..read]).await.is_err() {
                        code = 255;
                        break 'session;
                    }
                }
            },
        }
    }

    // The exit status implies the output tail is already sent: the master
    // writes it after its pump ends. The outputs drain what is still in
    // flight until the master closes the attachments.
    if got_exit_status {
        let mut io_buffer = [0u8; 16_384];
        let mut err_buffer = [0u8; 16_384];
        while let Ok(read) = io_read.read(&mut io_buffer).await {
            if read == 0 || stdout.write_all(&io_buffer[..read]).await.is_err() {
                break;
            }
        }
        while let Ok(read) = err_conn.read(&mut err_buffer).await {
            if read == 0 || stderr.write_all(&err_buffer[..read]).await.is_err() {
                break;
            }
        }
    }
    Ok(i32::try_from(code).unwrap_or(255))
}

/// The pty parameters a slave carries in its session request.
///
/// The local console of the slave fills it; the master translates it into
/// the pty request of the session channel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenSessionPty {
    /// The terminal type of the slave environment.
    pub term: String,
    /// The console geometry in character cells.
    pub columns: u32,
    /// The console geometry in character cells.
    pub rows: u32,
    /// The console geometry in pixels.
    pub pixel_width: u32,
    /// The console geometry in pixels.
    pub pixel_height: u32,
}

/// Attaches one dedicated stream connection to a bridged session, the way
/// `attachCM` does: one fresh connection, one handshake, one ATTACH.
async fn attach(
    control_path: &Path,
    token: &SessionToken,
    stream: StreamKind,
) -> Result<UnixStream, ControlMasterError> {
    let mut conn = UnixStream::connect(control_path).await.map_err(|err| {
        ControlMasterError::Protocol(format!("could not reach the control master: {err}"))
    })?;
    hello(&mut conn).await?;
    call(
        &mut conn,
        MsgType::ATTACH,
        &Attach {
            token: *token,
            stream,
        }
        .encode(),
    )
    .await?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::{
        CONTROL_OP_CHECK, CONTROL_OP_EXIT, ControlMasterError, MasterStatus, ping_master,
        run_control_op, run_slave_session,
    };
    use crate::{Ssh3ClientConfig, Ssh3TrustStrategy, connect_client};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::Duration;

    /// Spawns the Rust server and an authenticated client of it: the server
    /// accepts exactly one connection, so a second session that succeeds
    /// proves it went through the master and not through a fresh dial.
    async fn connected_client() -> (
        tokio::task::JoinHandle<()>,
        Arc<crate::ActiveClient>,
        tempfile::TempDir,
    ) {
        let (server_config, server_certificate) = ssh3_quinn::self_signed_server_config(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let _ = tokio::time::timeout(
                Duration::from_secs(30),
                ssh3_server::serve_connection(connection, ssh3_server::Ssh3ServerConfig::default()),
            )
            .await;
        });

        let mut config = Ssh3ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = Ssh3TrustStrategy::Certificates(vec![server_certificate]);
        let client = Arc::new(connect_client(&config).await.unwrap());
        let temp = tempfile::TempDir::new().unwrap();
        (server_task, client, temp)
    }

    /// Two slaves run through one master: the server accepts exactly one
    /// connection, so the second session proves the reuse.
    #[tokio::test]
    async fn two_slaves_share_one_connection_through_the_master() {
        let (server_task, client, temp) = connected_client().await;
        let control_path = temp.path().join("cm-test");

        let listener = super::listen_control_master(&control_path).unwrap();
        let serve_task = tokio::spawn(super::serve_control_master(
            client.clone(),
            control_path.clone(),
            listener,
            None,
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !ping_master(&control_path).await {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();

        for round in 1..=2u32 {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let command = format!("printf 'round {round} via master\\n'");
            let code = tokio::time::timeout(
                Duration::from_secs(10),
                run_slave_session(
                    &control_path,
                    vec![command],
                    None,
                    false,
                    tokio::io::empty(),
                    &mut stdout,
                    &mut stderr,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            let want = format!("round {round} via master\n").into_bytes();
            assert_eq!(code, 0, "round {round}");
            assert_eq!(stdout, want, "round {round}");
            assert!(stderr.is_empty(), "round {round}");
        }

        // The check op answers with the status of the live master.
        let status = tokio::time::timeout(
            Duration::from_secs(5),
            run_control_op(&control_path, CONTROL_OP_CHECK),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("the check op returns the status");
        assert_eq!(status.pid, std::process::id());
        assert_eq!(status.protocol, crate::cm::CM_PROTOCOL_VERSION);

        // The exit op shuts the master down and releases the socket.
        let stopped = tokio::time::timeout(
            Duration::from_secs(5),
            run_control_op(&control_path, CONTROL_OP_EXIT),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(stopped.is_none());
        tokio::time::timeout(Duration::from_secs(5), async {
            while ping_master(&control_path).await {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(!control_path.exists(), "the socket file is removed on exit");

        serve_task.abort();
        // The client is shared with the aborted serve task: the connection
        // closes when the last Arc drops with the task.
        drop(client);
        server_task.abort();
    }

    /// A control op without a live master fails with the explicit message.
    #[tokio::test]
    async fn a_control_op_without_a_master_fails_fast() {
        let temp = tempfile::TempDir::new().unwrap();
        let control_path = temp.path().join("no-master");
        let err = run_control_op(&control_path, CONTROL_OP_CHECK)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ControlMasterError::Protocol(ref reason) if reason.contains("no control master")),
            "unexpected error: {err:?}"
        );
    }

    /// A status renders as the single line the CLI prints.
    #[test]
    fn a_status_renders_one_line() {
        let status = MasterStatus {
            path: "/tmp/cm".to_string(),
            pid: 42,
            protocol: 1,
            uptime_s: 1.5,
            sessions: 2,
            forwards: 3,
        };
        let line = status.status_line();
        assert!(line.contains("pid=42"), "{line}");
        assert!(line.contains("2 session(s)"), "{line}");
        assert!(line.contains("3 forward(s)"), "{line}");
    }
}
