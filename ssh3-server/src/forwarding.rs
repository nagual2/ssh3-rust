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

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use quinn::Connection;
use ssh3_core::Ssh3Channel;
use ssh3_proto::{SSH_EXTENDED_DATA_NONE, Ssh3Message};

use crate::error::Ssh3ServerError;

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
    let Some(policy) = policy else {
        return Ok(());
    };
    if policy.allows_addr(address) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{kind} forwarding to {address} denied by the permit-open policy"),
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
