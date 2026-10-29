//! The local forwarding (`-L`) of the client.
//!
//! A local forward is a local listener that hands every accepted connection
//! (or datagram) to the server over a `direct-tcp` (or `direct-udp`) channel;
//! the server dials the target on the client behalf. The syntax of the
//! specification is the ssh(1) one: `[bind_address:]port:host:hostport`, with
//! an optional `udp://` prefix for the datagram extension of ssh3.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use ssh3_core::{Ssh3Channel, Ssh3Conversation};
use ssh3_proto::{SSH_EXTENDED_DATA_NONE, Ssh3Message};
use ssh3_quinn::{open_tcp_forwarding_channel, open_udp_forwarding_channel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::Ssh3ClientError;

/// The protocol of a local forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ssh3ForwardProtocol {
    /// A byte stream forward (`direct-tcp`).
    Tcp,
    /// A datagram forward (`direct-udp`).
    Udp,
}

/// One parsed `-L` value: the local listener plus the remote target the
/// server dials for every accepted connection (or datagram).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3LocalForwardSpec {
    /// The local address to listen on.
    ///
    /// `None` binds the loopback of the target family (the OpenSSH default)
    /// and `Some("*")` binds every interface.
    pub bind_address: Option<String>,
    /// The local port to listen on; zero allocates an ephemeral port.
    pub bind_port: u16,
    /// The host the server dials on the client behalf.
    pub target_host: String,
    /// The port the server dials on the client behalf.
    pub target_port: u16,
    /// The protocol of the forward.
    pub protocol: Ssh3ForwardProtocol,
}

impl Ssh3LocalForwardSpec {
    /// Renders the forward back into its `-L` form.
    pub fn spec_string(&self) -> String {
        let protocol = match self.protocol {
            Ssh3ForwardProtocol::Tcp => "",
            Ssh3ForwardProtocol::Udp => "udp://",
        };
        let bind = match &self.bind_address {
            Some(address) => format!("{address}:"),
            None => String::new(),
        };
        format!(
            "{protocol}{bind}{}:{}:{}",
            self.bind_port, self.target_host, self.target_port
        )
    }
}

/// The error of a `-L` value the ssh(1) syntax does not accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ForwardParseError {
    spec: String,
    reason: String,
}

impl std::fmt::Display for Ssh3ForwardParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid -L specification {:?}: {}",
            self.spec, self.reason
        )
    }
}

impl std::error::Error for Ssh3ForwardParseError {}

/// Parses the ssh(1) `-L [bind_address:]port:host:hostport` syntax.
///
/// The syntax is extended with an optional `udp://` prefix for the datagram
/// forward (the ssh(1) canon has none) and accepts a `tcp://` prefix for
/// symmetry. IPv6 literals must be bracketed.
pub fn parse_local_forward_spec(spec: &str) -> Result<Ssh3LocalForwardSpec, Ssh3ForwardParseError> {
    let mut value = spec.trim();
    let mut protocol = Ssh3ForwardProtocol::Tcp;
    if let Some(rest) = value.strip_prefix("udp://") {
        protocol = Ssh3ForwardProtocol::Udp;
        value = rest;
    } else if let Some(rest) = value.strip_prefix("tcp://") {
        value = rest;
    }

    let parts = split_outside_brackets(value, ':');
    if parts.len() != 3 && parts.len() != 4 {
        return Err(Ssh3ForwardParseError {
            spec: spec.to_string(),
            reason: "expected [bind_address:]port:host:hostport, IPv6 addresses must be bracketed"
                .to_string(),
        });
    }

    let mut bind_address = None;
    let port_part = if parts.len() == 4 {
        let address = unbracket(&parts[0]);
        if address.contains([' ', '\t']) {
            return Err(Ssh3ForwardParseError {
                spec: spec.to_string(),
                reason: format!("invalid bind address {address:?}"),
            });
        }
        if !address.is_empty() {
            bind_address = Some(address);
        }
        parts[1].clone()
    } else {
        parts[0].clone()
    };

    let target_host = unbracket(&parts[parts.len() - 2]);
    if target_host.is_empty() {
        return Err(Ssh3ForwardParseError {
            spec: spec.to_string(),
            reason: "the target host cannot be empty".to_string(),
        });
    }

    let bind_port = parse_port(&port_part).ok_or_else(|| Ssh3ForwardParseError {
        spec: spec.to_string(),
        reason: format!("invalid bind port {port_part:?}"),
    })?;
    let target_port = parse_port(&parts[parts.len() - 1]).ok_or_else(|| Ssh3ForwardParseError {
        spec: spec.to_string(),
        reason: format!("invalid target port {:?}", parts[parts.len() - 1]),
    })?;
    if target_port == 0 {
        return Err(Ssh3ForwardParseError {
            spec: spec.to_string(),
            reason: "the target port cannot be 0".to_string(),
        });
    }

    Ok(Ssh3LocalForwardSpec {
        bind_address,
        bind_port,
        target_host,
        target_port,
        protocol,
    })
}

/// Parses a TCP/UDP port number; zero is allowed on a bind port (an ephemeral
/// bind) and refused for a target port by the caller.
fn parse_port(port: &str) -> Option<u16> {
    port.parse::<u16>().ok()
}

/// Splits on the separator, ignoring the separators inside brackets, so that
/// an IPv6 literal like `[::1]:8080` stays in one part.
fn split_outside_brackets(value: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut in_brackets = false;
    let mut start = 0usize;
    for (index, character) in value.char_indices() {
        match character {
            '[' => in_brackets = true,
            ']' => in_brackets = false,
            character if character == separator && !in_brackets => {
                parts.push(value[start..index].to_string());
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].to_string());
    parts
}

/// Strips the brackets around an IPv6 literal.
fn unbracket(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('[') && value.ends_with(']') {
        return value[1..value.len() - 1].to_string();
    }
    value.to_string()
}

/// Resolves the local address the forward listens on.
///
/// An explicit address wins, "*" binds every interface and the OpenSSH
/// default binds the loopback of the target family, so a forward without a
/// bind address never exposes the listener to the network.
async fn resolve_bind_address(
    spec: &Ssh3LocalForwardSpec,
    target: SocketAddr,
) -> Result<SocketAddr, Ssh3ClientError> {
    match spec.bind_address.as_deref() {
        Some("*") => Ok(SocketAddr::new(
            match target.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            spec.bind_port,
        )),
        Some(address) => {
            let address = unbracket(address);
            let mut resolved = tokio::net::lookup_host((address.as_str(), spec.bind_port))
                .await
                .map_err(Ssh3ClientError::Io)?;
            resolved.next().ok_or_else(|| {
                Ssh3ClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    format!("could not resolve the bind address {address:?}"),
                ))
            })
        }
        None => Ok(SocketAddr::new(
            match target.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            spec.bind_port,
        )),
    }
}

/// Resolves the target the server dials on the client behalf.
async fn resolve_target(spec: &Ssh3LocalForwardSpec) -> Result<SocketAddr, Ssh3ClientError> {
    let host = unbracket(&spec.target_host);
    let mut resolved = tokio::net::lookup_host((host.as_str(), spec.target_port))
        .await
        .map_err(Ssh3ClientError::Io)?;
    resolved.next().ok_or_else(|| {
        Ssh3ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!(
                "could not resolve the -L target {}:{}",
                spec.target_host, spec.target_port
            ),
        ))
    })
}

/// Opens the local listener of a forward and spawns the task that serves it.
///
/// The returned task runs until the client shuts down; the caller aborts it
/// with the rest of the background tasks of the session.
pub(crate) async fn start_local_forward(
    conversation: Arc<Ssh3Conversation>,
    connection: quinn::Connection,
    max_packet_size: u64,
    datagrams_queue_size: usize,
    spec: &Ssh3LocalForwardSpec,
) -> Result<tokio::task::JoinHandle<()>, Ssh3ClientError> {
    let target = resolve_target(spec).await?;
    let bind = resolve_bind_address(spec, target).await?;

    match spec.protocol {
        Ssh3ForwardProtocol::Tcp => {
            let listener = TcpListener::bind(bind).await.map_err(Ssh3ClientError::Io)?;
            Ok(tokio::spawn(async move {
                loop {
                    let (stream, _peer) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(_) => return,
                    };
                    let conversation = conversation.clone();
                    let connection = connection.clone();
                    tokio::spawn(async move {
                        let result = forward_tcp_connection(
                            conversation.as_ref(),
                            &connection,
                            stream,
                            target,
                            max_packet_size,
                            datagrams_queue_size,
                        )
                        .await;
                        if let Err(err) = result
                            && !crate::is_benign_client_error(&err)
                        {
                            eprintln!("ssh3 local TCP forwarding error: {err}");
                        }
                    });
                }
            }))
        }
        Ssh3ForwardProtocol::Udp => {
            let socket = Arc::new(UdpSocket::bind(bind).await.map_err(Ssh3ClientError::Io)?);
            Ok(tokio::spawn(async move {
                forward_udp_socket(
                    conversation.as_ref(),
                    &connection,
                    socket,
                    target,
                    max_packet_size,
                    datagrams_queue_size,
                )
                .await;
            }))
        }
    }
}

/// Bridges one accepted TCP connection to a `direct-tcp` channel.
async fn forward_tcp_connection(
    conversation: &Ssh3Conversation,
    connection: &quinn::Connection,
    stream: TcpStream,
    target: SocketAddr,
    max_packet_size: u64,
    datagrams_queue_size: usize,
) -> Result<(), Ssh3ClientError> {
    let channel = open_tcp_forwarding_channel(
        conversation,
        connection,
        max_packet_size,
        datagrams_queue_size,
        target,
    )
    .await
    .map_err(Ssh3ClientError::from)?;

    let (mut reader, mut writer) = stream.into_split();

    let to_remote = tokio::spawn({
        let channel = channel.clone();
        async move {
            let mut buffer = vec![0u8; buffer_size(channel.max_packet_size())];
            loop {
                let read = reader.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                channel
                    .write_data(&buffer[..read], SSH_EXTENDED_DATA_NONE)
                    .await?;
            }
            let _ = channel.close().await;
            Ok::<(), Ssh3ClientError>(())
        }
    });

    let from_remote = tokio::spawn({
        let channel = channel.clone();
        async move {
            loop {
                if let Ssh3Message::Data(data) = channel.next_message().await?
                    && data.data_type == SSH_EXTENDED_DATA_NONE
                {
                    writer.write_all(&data.data).await?;
                    writer.flush().await?;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), Ssh3ClientError>(())
        }
    });

    let _ = to_remote.await;
    let _ = from_remote.await;
    Ok(())
}

/// The size of the buffer of a forwarding pump.
fn buffer_size(max_packet_size: u64) -> usize {
    usize::try_from(max_packet_size.min(30_000))
        .unwrap_or(30_000)
        .max(1)
}

/// Bridges a local UDP socket to the `direct-udp` channels of the server.
///
/// Every source address gets its own channel, like the Go implementation does:
/// the server forwards the datagrams of a channel to a single target, so the
/// source of a datagram must not be mixed with the source of another one.
async fn forward_udp_socket(
    conversation: &Ssh3Conversation,
    connection: &quinn::Connection,
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    max_packet_size: u64,
    datagrams_queue_size: usize,
) {
    let mut channels: HashMap<SocketAddr, Arc<Ssh3Channel>> = HashMap::new();
    let mut buffer = vec![0u8; 1500];
    loop {
        let (read, source) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(_) => return,
        };
        if read == 0 {
            continue;
        }

        let channel = match channels.entry(source) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let channel = match open_udp_forwarding_channel(
                    conversation,
                    connection,
                    max_packet_size,
                    datagrams_queue_size,
                    target,
                )
                .await
                {
                    Ok(channel) => channel,
                    Err(err) => {
                        eprintln!(
                            "ssh3 could not open the UDP forwarding channel: {err}"
                        );
                        return;
                    }
                };

                let socket = socket.clone();
                let receive_channel = channel.clone();
                tokio::spawn(async move {
                    loop {
                        let datagram = receive_channel.receive_datagram().await;
                        if socket.send_to(&datagram, source).await.is_err() {
                            return;
                        }
                    }
                });

                entry.insert(channel)
            }
        };

        if let Err(error) = channel.send_datagram(buffer[..read].to_vec()).await {
            // A packet past the datagram budget of the tunnel drops the way
            // an oversized packet drops on a UDP path: the MTU discovery of
            // the tunneled connection never learns to exceed the budget,
            // and the packets that fit keep flowing.
            if matches!(
                error,
                ssh3_core::Ssh3ChannelError::Io(ref io_error)
                    if io_error.kind() == io::ErrorKind::InvalidData
            ) {
                continue;
            }
            return;
        }
    }
}

/// Opens a UDP forward bridge of one proxy-jump hop: a local UDP listener
/// whose datagrams travel to `target` through the SSH3 UDP forwarding
/// channel of the connection, and whose answers travel back.
///
/// This is the `ForwardUDP` of the reference implementation: the QUIC
/// packets of the next hop of the chain are dialed against the returned
/// local address, so they ride the datagrams of this connection. The task
/// of the bridge runs until the connection ends; the caller keeps the
/// returned handle alive for as long as the tunnel is needed.
pub(crate) async fn open_udp_forward_bridge(
    conversation: Arc<Ssh3Conversation>,
    connection: quinn::Connection,
    max_packet_size: u64,
    datagrams_queue_size: usize,
    target: SocketAddr,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Ssh3ClientError> {
    let socket = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(Ssh3ClientError::Io)?,
    );
    let local = socket.local_addr().map_err(Ssh3ClientError::Io)?;
    let task = tokio::spawn(async move {
        forward_udp_socket(
            conversation.as_ref(),
            &connection,
            socket,
            target,
            max_packet_size,
            datagrams_queue_size,
        )
        .await;
    });
    Ok((local, task))
}

#[cfg(test)]
mod tests {
    use super::{Ssh3ForwardProtocol, Ssh3LocalForwardSpec, parse_local_forward_spec};

    #[test]
    fn parses_the_ssh_local_forward_syntax() {
        let spec = parse_local_forward_spec("8080:example.com:80").unwrap();
        assert_eq!(spec.bind_address, None);
        assert_eq!(spec.bind_port, 8080);
        assert_eq!(spec.target_host, "example.com");
        assert_eq!(spec.target_port, 80);
        assert_eq!(spec.protocol, Ssh3ForwardProtocol::Tcp);
    }

    #[test]
    fn parses_the_bind_address_of_a_local_forward() {
        let spec = parse_local_forward_spec("127.0.0.1:8080:example.com:80").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(spec.bind_port, 8080);
        assert_eq!(spec.target_host, "example.com");
        assert_eq!(spec.target_port, 80);
    }

    #[test]
    fn parses_the_udp_prefix_of_a_local_forward() {
        let spec = parse_local_forward_spec("udp://5353:example.com:53").unwrap();
        assert_eq!(spec.protocol, Ssh3ForwardProtocol::Udp);
        assert_eq!(spec.bind_port, 5353);
        assert_eq!(spec.target_host, "example.com");
        assert_eq!(spec.target_port, 53);
    }

    #[test]
    fn parses_the_bracketed_ipv6_literals_of_a_local_forward() {
        let spec = parse_local_forward_spec("[::1]:8080:[2001:db8::1]:80").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("::1"));
        assert_eq!(spec.target_host, "2001:db8::1");
        assert_eq!(spec.target_port, 80);
    }

    #[test]
    fn refuses_the_malformed_local_forwards() {
        assert!(parse_local_forward_spec("").is_err());
        assert!(parse_local_forward_spec("8080").is_err());
        assert!(parse_local_forward_spec("8080:example.com").is_err());
        assert!(parse_local_forward_spec("8080::80").is_err());
        assert!(parse_local_forward_spec("8080:example.com:0").is_err());
        assert!(parse_local_forward_spec("http://8080:example.com:80").is_err());
    }

    #[test]
    fn renders_a_local_forward_back_into_its_specification() {
        let spec = Ssh3LocalForwardSpec {
            bind_address: Some("127.0.0.1".to_string()),
            bind_port: 8080,
            target_host: "example.com".to_string(),
            target_port: 80,
            protocol: Ssh3ForwardProtocol::Udp,
        };
        assert_eq!(spec.spec_string(), "udp://127.0.0.1:8080:example.com:80");
    }
}
