//! Direct port forwarding: TCP and UDP channels opened by the client.
//!
//! SSH3 carries forwarded connections as regular channels: a `direct-tcp`
//! channel is a byte stream to a remote TCP endpoint, a `direct-udp` channel
//! is a datagram channel to a remote UDP endpoint. The target address is
//! negotiated in the channel header and is delivered with the channel.
//!
//! Every server-side dial is gated by a [`ForwardPolicy`] — the
//! `PermitOpen` analog of the sshd canon. Without a policy the historical
//! unrestricted behavior is kept; with a policy the server refuses to dial
//! the targets the policy does not allow, so an authenticated account cannot
//! turn the server into an SSRF or port-scanning pivot.

use std::collections::HashMap;
use std::io::{self, Cursor};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

use quinn::Connection;
use ssh3_core::{Ssh3Channel, Ssh3Conversation};
use ssh3_proto::{
    SSH_EXTENDED_DATA_NONE, Ssh3Message, build_forwarding_additional_bytes, read_var_int,
};
use ssh3_quinn::{Ssh3QuinnReceiveStream, Ssh3QuinnSendStream};

use crate::error::Ssh3ServerError;

/// Maximum number of forwarded channels one conversation may keep open at the
/// same time.
///
/// The limit is a denial-of-service guard: a peer that opens a reverse
/// forward must not be able to make the server open an unbounded number of
/// channels towards it.
pub(crate) const MAX_FORWARDED_CHANNELS_PER_CONVERSATION: i64 = 64;

/// Maximum number of connections one dynamic forwarding session may bridge at
/// the same time.
pub(crate) const MAX_DYNAMIC_FORWARD_CONNECTIONS: i64 = 64;

/// How long the server waits for the client to confirm a channel it opened
/// towards it.
const FORWARDED_CHANNEL_CONFIRMATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);

/// A single entry of a [`ForwardPolicy`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct ForwardTarget {
    /// Lower-cased host pattern the entry matches.
    host: String,
    /// Decimal port or `"*"` for every port.
    port: String,
    /// `true` when the entry was negated with a leading `!`.
    negated: bool,
}

/// A parsed `PermitOpen` / `PermitListen` policy.
///
/// The syntax follows the `PermitOpen` directive of `sshd_config`:
///
/// ```text
/// host:port          exact host (or IP) and port
/// *.example.org:443  wildcard host, exact port
/// host:*             any port
/// !host:port         negated entry: always denied
/// ```
///
/// Entries are separated by commas or whitespace. A policy that holds at
/// least one allow entry denies everything that is not explicitly allowed; a
/// policy that holds only negated entries allows everything that is not
/// explicitly denied.
///
/// The forwarded target reaches the server as a resolved socket address, so
/// the host of an entry is matched against the IP address the server is
/// about to dial, not against a host name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardPolicy {
    entries: Vec<ForwardTarget>,
}

impl ForwardPolicy {
    /// Parses a comma/space-separated `PermitOpen` style specification.
    ///
    /// An empty specification yields `None`, which keeps the unrestricted
    /// behavior of the historical server.
    pub fn parse(spec: &str) -> Result<Option<Self>, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Ok(None);
        }

        let mut entries = Vec::new();
        for field in spec
            .split(|character: char| character == ',' || character.is_whitespace())
            .filter(|field| !field.is_empty())
        {
            let (negated, rest) = match field.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, field),
            };
            let Some((host, port)) = rest.split_once(':') else {
                return Err(format!(
                    "invalid permit entry {field:?}: want host:port (for example \"*.example.org:443\")"
                ));
            };
            if host.is_empty() || port.is_empty() {
                return Err(format!(
                    "invalid permit entry {field:?}: want host:port (for example \"*.example.org:443\")"
                ));
            }
            if port != "*" && port.parse::<u16>().is_err() {
                return Err(format!(
                    "invalid permit entry {field:?}: {port:?} is not a valid port"
                ));
            }
            entries.push(ForwardTarget {
                host: host.to_ascii_lowercase(),
                port: port.to_string(),
                negated,
            });
        }

        Ok(Some(Self { entries }))
    }

    /// Reports whether a dial to `host:port` is allowed by the policy.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        let port = port.to_string();

        let mut allowed = false;
        let mut matched = false;
        for entry in &self.entries {
            if !matches_forward_host(&host, &entry.host) {
                continue;
            }
            if entry.port != "*" && entry.port != port {
                continue;
            }
            matched = true;
            if entry.negated {
                return false;
            }
            allowed = true;
        }

        if !matched {
            // a policy that only holds negated entries allows everything
            // that is not explicitly denied
            allowed = !self.entries.iter().any(|entry| !entry.negated);
        }

        allowed
    }

    /// Reports whether a dial to the given socket address is allowed.
    pub fn allows_addr(&self, address: SocketAddr) -> bool {
        self.allows(&address.ip().to_string(), address.port())
    }
}

/// Matches a host against a policy pattern.
///
/// The pattern `*` matches every host, an exact pattern matches the equal
/// host and a leading `*.` matches every sub-domain, but not the domain
/// itself.
fn matches_forward_host(host: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.len() > suffix.len() + 1
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    false
}

/// Returns `true` when the policy permits a dial to the given address.
pub(crate) fn check_forward_target(
    kind: &str,
    address: SocketAddr,
    policy: Option<&ForwardPolicy>,
) -> Result<(), Ssh3ServerError> {
    check_forward_target_host(kind, &address.ip().to_string(), address.port(), policy)
}

/// Returns `true` when the policy permits a dial to the given host.
///
/// The host is matched as it was spelled by the peer, not as it was
/// resolved: a name that resolves outside the policy stays denied even when
/// its addresses would individually match.
pub(crate) fn check_forward_target_host(
    kind: &str,
    host: &str,
    port: u16,
    policy: Option<&ForwardPolicy>,
) -> Result<(), Ssh3ServerError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if policy.allows(host, port) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{kind} forwarding to {host}:{port} denied by the permit-open policy"),
    )
    .into())
}

/// Returns `true` when the policy permits a bind to the given address.
///
/// The server does not open reverse-forward listeners itself; the check is
/// part of the public surface for callers that implement them.
pub fn check_listen_target(
    kind: &str,
    address: SocketAddr,
    policy: Option<&ForwardPolicy>,
) -> Result<(), Ssh3ServerError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if policy.allows_addr(address) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{kind} listen on {address} denied by the permit-listen policy"),
    )
    .into())
}

/// Forwards a UDP datagram channel to the requested remote endpoint.
///
/// A local socket is connected to the remote address and both directions are
/// pumped until the connection is closed. The dial is gated by the
/// `permit-open` policy.
pub(crate) async fn handle_udp_forwarding(
    channel: Arc<Ssh3Channel>,
    remote_addr: SocketAddr,
    connection: Connection,
    policy: Option<&ForwardPolicy>,
) -> Result<(), Ssh3ServerError> {
    check_forward_target("udp", remote_addr, policy)?;
    let bind_addr = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    };
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    socket.connect(remote_addr).await?;

    let to_socket = tokio::spawn({
        let channel = channel.clone();
        let socket = socket.clone();
        let connection = connection.clone();
        async move {
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    datagram = channel.receive_datagram() => {
                        socket.send(&datagram).await?;
                    }
                }
            }
        }
    });

    let from_socket = tokio::spawn({
        let channel = channel.clone();
        let socket = socket.clone();
        let connection = connection.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    result = socket.recv(&mut buf) => {
                        let n = result?;
                        channel.send_datagram(buf[..n].to_vec()).await?;
                    }
                }
            }
        }
    });

    let _ = to_socket.await;
    let _ = from_socket.await;
    Ok(())
}

/// Forwards a TCP stream channel to the requested remote endpoint.
///
/// The remote socket is connected once and both directions are pumped until
/// the connection is closed. The dial is gated by the `permit-open` policy.
pub(crate) async fn handle_tcp_forwarding(
    channel: Arc<Ssh3Channel>,
    remote_addr: SocketAddr,
    connection: Connection,
    policy: Option<&ForwardPolicy>,
) -> Result<(), Ssh3ServerError> {
    check_forward_target("tcp", remote_addr, policy)?;
    let stream = TcpStream::connect(remote_addr).await?;
    let (mut reader, mut writer) = stream.into_split();

    let to_socket = tokio::spawn({
        let channel = channel.clone();
        let connection = connection.clone();
        async move {
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    message = channel.next_message() => {
                        let message = message?;
                        if let Ssh3Message::Data(data) = message
                            && data.data_type == SSH_EXTENDED_DATA_NONE
                        {
                            writer.write_all(&data.data).await?;
                            writer.flush().await?;
                        }
                    }
                }
            }
        }
    });

    let from_socket = tokio::spawn({
        let channel = channel.clone();
        let connection = connection.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    read = reader.read(&mut buf) => {
                        let n = read?;
                        if n == 0 {
                            return Ok(());
                        }
                        channel.write_data(&buf[..n], SSH_EXTENDED_DATA_NONE).await?;
                    }
                }
            }
        }
    });

    let _ = to_socket.await;
    let _ = from_socket.await;
    Ok(())
}

/// The dynamic forwarding session of one conversation.
///
/// The session exists as long as the client keeps its `dynamic-forward`
/// control channel open; every connection the session bridges dies with it.
pub(crate) struct DynamicForwardSession {
    closed: watch::Sender<bool>,
    connections: AtomicI64,
}

impl DynamicForwardSession {
    /// Creates an open session.
    pub(crate) fn new() -> Self {
        let (closed, _) = watch::channel(false);
        Self {
            closed,
            connections: AtomicI64::new(0),
        }
    }

    /// Closes the session; every bridged connection is released.
    pub(crate) fn close(&self) {
        self.closed.send_replace(true);
    }

    /// Waits until the session is closed.
    pub(crate) async fn wait_closed(&self) {
        let mut closed = self.closed.subscribe();
        if *closed.borrow() {
            return;
        }
        let _ = closed.changed().await;
    }

    /// Registers a freshly bridged connection.
    ///
    /// Returns `false` when the session already bridges the maximum number of
    /// connections, which is the denial-of-service guard of the session.
    pub(crate) fn acquire_connection(&self) -> bool {
        let mut count = self.connections.load(Ordering::SeqCst);
        loop {
            if count >= MAX_DYNAMIC_FORWARD_CONNECTIONS {
                return false;
            }
            match self.connections.compare_exchange(
                count,
                count + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(current) => count = current,
            }
        }
    }

    /// Releases a bridged connection.
    pub(crate) fn release_connection(&self) {
        self.connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The forwarding state of one conversation.
///
/// The state holds the guards the reverse and dynamic forwarding share: the
/// number of forwarded channels the conversation keeps open and the dynamic
/// forwarding session the client announced.
#[derive(Default)]
pub(crate) struct ForwardingState {
    open_forwarded_channels: AtomicI64,
    dynamic_session: std::sync::Mutex<Option<Arc<DynamicForwardSession>>>,
    datagram_channels: std::sync::Mutex<HashMap<u64, Arc<Ssh3Channel>>>,
}

impl ForwardingState {
    /// Creates an empty state.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Registers a forwarded channel the server opens towards the client.
    ///
    /// Returns `false` when the conversation already holds the maximum number
    /// of forwarded channels.
    pub(crate) fn acquire_forwarded_channel(&self) -> bool {
        let mut count = self.open_forwarded_channels.load(Ordering::SeqCst);
        loop {
            if count >= MAX_FORWARDED_CHANNELS_PER_CONVERSATION {
                return false;
            }
            match self.open_forwarded_channels.compare_exchange(
                count,
                count + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(current) => count = current,
            }
        }
    }

    /// Releases a forwarded channel.
    pub(crate) fn release_forwarded_channel(&self) {
        self.open_forwarded_channels.fetch_sub(1, Ordering::SeqCst);
    }

    /// Returns the dynamic forwarding session of the conversation, if the
    /// client announced one.
    pub(crate) fn dynamic_session(&self) -> Option<Arc<DynamicForwardSession>> {
        self.dynamic_session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    /// Announces a dynamic forwarding session and returns it.
    pub(crate) fn open_dynamic_session(&self) -> Arc<DynamicForwardSession> {
        let session = Arc::new(DynamicForwardSession::new());
        let mut guard = self
            .dynamic_session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(previous) = guard.replace(session.clone()) {
            previous.close();
        }
        session
    }

    /// Retires the dynamic forwarding session of the conversation.
    pub(crate) fn close_dynamic_session(&self) {
        let session = self
            .dynamic_session
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(session) = session {
            session.close();
        }
    }

    /// Registers a channel the server opened towards the client that carries
    /// datagrams.
    ///
    /// The channels the server opens are not registered in the conversation
    /// of the peer, so the datagrams the peer sends for them are routed by
    /// the state of the conversation.
    pub(crate) fn register_datagram_channel(&self, channel: Arc<Ssh3Channel>) {
        self.datagram_channels
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(channel.channel_id(), channel);
    }

    /// Routes a datagram the peer sent to the channel it is addressed to.
    ///
    /// Returns `true` when the datagram was routed to a channel the server
    /// opened towards the peer; a datagram of another channel is left to the
    /// conversation of the peer.
    pub(crate) async fn route_datagram(&self, datagram: &[u8]) -> bool {
        let mut cursor = Cursor::new(datagram);
        let Ok(_control_stream_id) = read_var_int(&mut cursor) else {
            return false;
        };
        let Ok(channel_id) = read_var_int(&mut cursor) else {
            return false;
        };
        let channel = self
            .datagram_channels
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&channel_id)
            .cloned();
        let Some(channel) = channel else {
            return false;
        };
        let offset = cursor.position() as usize;
        let Some(payload) = datagram.get(offset..) else {
            return false;
        };
        channel.wait_add_datagram(payload.to_vec()).await;
        true
    }
}

/// Opens a channel towards the client that carries the target of a forwarded
/// connection in its additional header bytes.
///
/// The channel type is `forwarded-tcp` or `forwarded-udp`; the additional
/// bytes hold the address family, the address octets and the port of the
/// client-side target, the layout the reference implementation uses for the
/// direct forwarding channels.
pub(crate) async fn open_forwarded_channel(
    conversation: &Ssh3Conversation,
    connection: &Connection,
    channel_type: &[u8],
    target: SocketAddr,
    max_packet_size: u64,
    datagrams_queue_size: usize,
    with_datagrams: bool,
) -> Result<Arc<Ssh3Channel>, Ssh3ServerError> {
    let (send, recv) = connection.open_bi().await.map_err(|error| {
        Ssh3ServerError::Io(io::Error::other(format!(
            "could not open the {channel_type:?} channel: {error}"
        )))
    })?;
    let stream_id: u64 = send.id().into();
    let datagram_sender =
        with_datagrams.then(|| conversation.datagram_sender_for_channel(stream_id));
    let additional_bytes = build_forwarding_additional_bytes(target.ip(), target.port());
    let channel = Arc::new(Ssh3Channel::new(
        conversation.control_stream_id(),
        conversation.conversation_id(),
        stream_id,
        channel_type.to_vec(),
        max_packet_size,
        Ssh3QuinnReceiveStream::new(recv),
        Ssh3QuinnSendStream::new(send),
        datagram_sender,
        true,
        true,
        false,
        datagrams_queue_size,
        Some(&additional_bytes),
    ));
    channel.maybe_send_header().await?;
    // The client confirms the channel: a peer that never does must not hold
    // the server forever, so the wait is bounded.
    match tokio::time::timeout(
        FORWARDED_CHANNEL_CONFIRMATION_TIMEOUT,
        channel.wait_for_confirmation(),
    )
    .await
    {
        Ok(Ok(())) => Ok(channel),
        Ok(Err(err)) => Err(Ssh3ServerError::Channel(err)),
        Err(_) => Err(Ssh3ServerError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the client did not confirm the {channel_type:?} channel in time"),
        ))),
    }
}

/// Bridges a channel and a TCP connection in both directions.
///
/// The bridge ends when either side is done; the caller releases the
/// resources it owns.
pub(crate) async fn bridge_tcp_channel(
    channel: Arc<Ssh3Channel>,
    stream: TcpStream,
    connection: Connection,
) -> Result<(), Ssh3ServerError> {
    bridge_tcp_channel_until(channel, stream, connection, None).await
}

/// Bridges a channel and a TCP connection in both directions.
///
/// When a session is given, the bridge also ends as soon as the session is
/// closed: the bridges of a dynamic forwarding session die with it.
pub(crate) async fn bridge_tcp_channel_until(
    channel: Arc<Ssh3Channel>,
    stream: TcpStream,
    connection: Connection,
    session: Option<Arc<DynamicForwardSession>>,
) -> Result<(), Ssh3ServerError> {
    let (mut reader, mut writer) = stream.into_split();

    let to_socket = tokio::spawn({
        let channel = channel.clone();
        let connection = connection.clone();
        let session = session.clone();
        async move {
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    _ = wait_for_session(session.clone()) => return Ok::<(), Ssh3ServerError>(()),
                    message = channel.next_message() => {
                        let message = message?;
                        if let Ssh3Message::Data(data) = message
                            && data.data_type == SSH_EXTENDED_DATA_NONE
                        {
                            writer.write_all(&data.data).await?;
                            writer.flush().await?;
                        }
                    }
                }
            }
        }
    });

    let from_socket = tokio::spawn({
        let channel = channel.clone();
        let connection = connection.clone();
        let session = session.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    _ = wait_for_session(session.clone()) => return Ok::<(), Ssh3ServerError>(()),
                    read = reader.read(&mut buf) => {
                        let n = read?;
                        if n == 0 {
                            return Ok(());
                        }
                        channel.write_data(&buf[..n], SSH_EXTENDED_DATA_NONE).await?;
                    }
                }
            }
        }
    });

    let _ = to_socket.await;
    let _ = from_socket.await;
    Ok(())
}

/// Waits for the closing of a dynamic forwarding session.
///
/// Without a session the future never completes, which keeps the bridge
/// alive until the connection ends.
async fn wait_for_session(session: Option<Arc<DynamicForwardSession>>) {
    match session {
        Some(session) => session.wait_closed().await,
        None => std::future::pending().await,
    }
}
