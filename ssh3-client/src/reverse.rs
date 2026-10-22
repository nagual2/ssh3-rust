//! Reverse port forwarding (`-R`): the client half.
//!
//! A reverse forward asks the server to bind a listener on its side; every
//! connection (or datagram) the server accepts there is mirrored back as a
//! server-initiated `forwarded-tcp` (or `forwarded-udp`) channel whose
//! additional header bytes carry the local target. The client requests the
//! bind over a `reverse-forward` control channel and bridges the incoming
//! channels to the target it asked for.
//!
//! The reference implementation of this behavior lives in
//! `nagual2/ssh3-go`, files `client/reverse_forward.go` and
//! `cmd/reverse_forward_server.go`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ssh3_core::{Ssh3Channel, Ssh3Conversation};
use ssh3_proto::{SSH_EXTENDED_DATA_NONE, Ssh3Message};
use ssh3_quinn::open_channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::Ssh3ClientError;
use crate::forwarding_wire::{
    FORWARDING_PROTOCOL_TCP, FORWARDING_PROTOCOL_UDP, ReverseForwardReply, ReverseForwardRequest,
};

/// Channel type of the control channel a client opens to request a reverse
/// forward.
pub(crate) const CHANNEL_TYPE_REVERSE_FORWARD: &[u8] = b"reverse-forward";

/// The transport protocol of a reverse forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ssh3ReverseForwardProtocol {
    /// A byte stream forward.
    Tcp,
    /// A datagram forward.
    Udp,
}

impl Ssh3ReverseForwardProtocol {
    /// The protocol number of the wire format.
    fn wire_value(self) -> u64 {
        match self {
            Self::Tcp => FORWARDING_PROTOCOL_TCP,
            Self::Udp => FORWARDING_PROTOCOL_UDP,
        }
    }
}

/// One parsed `-R` value: the listener the server binds and the local target
/// every accepted connection (or datagram) is bridged to.
///
/// The target is resolved on the client, like OpenSSH resolves the `-R`
/// target on the machine where the client runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ReverseForwardSpec {
    /// The address the server binds the listener on.
    ///
    /// `None` asks for the default of the server (the loopback only) and
    /// `Some("*")` asks for every interface.
    pub bind_address: Option<String>,
    /// The port the server binds the listener on; zero asks for an ephemeral
    /// port.
    pub bind_port: u16,
    /// The host the client connects to on behalf of the server.
    pub target_host: String,
    /// The port the client connects to on behalf of the server.
    pub target_port: u16,
    /// The protocol of the forward.
    pub protocol: Ssh3ReverseForwardProtocol,
}

impl Ssh3ReverseForwardSpec {
    /// Renders the forward back into its `-R` form.
    pub fn spec_string(&self) -> String {
        let protocol = match self.protocol {
            Ssh3ReverseForwardProtocol::Tcp => "",
            Ssh3ReverseForwardProtocol::Udp => "/udp",
        };
        let bind = match &self.bind_address {
            Some(address) => format!("{address}:"),
            None => String::new(),
        };
        format!(
            "{bind}{}{}:{}:{}",
            self.bind_port, protocol, self.target_host, self.target_port
        )
    }

    /// The bind address the request carries on the wire.
    ///
    /// The wildcard marker of OpenSSH is sent as the unspecified IPv6
    /// address: it is the form the reference implementation uses and the one
    /// every server understands.
    fn wire_bind_address(&self) -> String {
        match self.bind_address.as_deref() {
            None => String::new(),
            Some("*") => "::".to_string(),
            Some(address) => address.to_string(),
        }
    }
}

/// The error of a `-R` value the ssh(1) syntax does not accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ReverseForwardParseError {
    spec: String,
    reason: String,
}

impl std::fmt::Display for Ssh3ReverseForwardParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid -R specification {:?}: {}",
            self.spec, self.reason
        )
    }
}

impl std::error::Error for Ssh3ReverseForwardParseError {}

/// Parses the ssh(1) `-R [bind_address:]bind_port[/udp]:host:hostport` syntax.
///
/// The syntax is the one of the reference implementation: the bind port may
/// carry an explicit `/tcp` or `/udp` marker (TCP is the default) and the
/// IPv6 literals must be bracketed.
pub fn parse_reverse_forward_spec(
    spec: &str,
) -> Result<Ssh3ReverseForwardSpec, Ssh3ReverseForwardParseError> {
    let parts = split_outside_brackets(spec, ':');
    if parts.len() != 3 && parts.len() != 4 {
        return Err(Ssh3ReverseForwardParseError {
            spec: spec.to_string(),
            reason:
                "expected [bind_address:]bind_port[/udp]:target_host:target_port, IPv6 addresses must be bracketed"
                    .to_string(),
        });
    }

    let (bind_address, bind_port_part) = if parts.len() == 4 {
        let address = unbracket(&parts[0]);
        if address.contains([' ', '\t']) {
            return Err(Ssh3ReverseForwardParseError {
                spec: spec.to_string(),
                reason: format!("invalid bind address {address:?}"),
            });
        }
        (Some(address), parts[1].clone())
    } else {
        (None, parts[0].clone())
    };

    let target_host = unbracket(&parts[parts.len() - 2]);
    let target_port_part = parts[parts.len() - 1].clone();

    let mut protocol = Ssh3ReverseForwardProtocol::Tcp;
    let bind_port_part = match bind_port_part.split_once('/') {
        Some((port, "udp")) => {
            protocol = Ssh3ReverseForwardProtocol::Udp;
            port.to_string()
        }
        Some((port, "tcp")) => port.to_string(),
        Some((_, suffix)) => {
            return Err(Ssh3ReverseForwardParseError {
                spec: spec.to_string(),
                reason: format!("unknown protocol suffix {suffix:?} (expected /tcp or /udp)"),
            });
        }
        None => bind_port_part,
    };

    let bind_port = parse_port(&bind_port_part).ok_or_else(|| Ssh3ReverseForwardParseError {
        spec: spec.to_string(),
        reason: format!("invalid bind port {bind_port_part:?}"),
    })?;
    let target_port =
        parse_port(&target_port_part).ok_or_else(|| Ssh3ReverseForwardParseError {
            spec: spec.to_string(),
            reason: format!("invalid target port {target_port_part:?}"),
        })?;
    if target_port == 0 {
        return Err(Ssh3ReverseForwardParseError {
            spec: spec.to_string(),
            reason: "the target port cannot be 0".to_string(),
        });
    }
    if target_host.is_empty() {
        return Err(Ssh3ReverseForwardParseError {
            spec: spec.to_string(),
            reason: "the target host cannot be empty".to_string(),
        });
    }

    Ok(Ssh3ReverseForwardSpec {
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

/// A reverse forward whose target the client resolved.
///
/// The resolved target is the one the client bridges the forwarded channels
/// to, and the one a forwarded channel is checked against: a server that
/// asks the client to connect somewhere else is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ResolvedReverseForward {
    /// The specification the forward was requested with.
    pub spec: Ssh3ReverseForwardSpec,
    /// The local target the forwarded connections are bridged to.
    pub target: SocketAddr,
}

/// Resolves the target of a reverse forward on the client.
pub(crate) async fn resolve_reverse_forward(
    spec: &Ssh3ReverseForwardSpec,
) -> Result<Ssh3ResolvedReverseForward, Ssh3ClientError> {
    let host = unbracket(&spec.target_host);
    let mut resolved = tokio::net::lookup_host((host.as_str(), spec.target_port))
        .await
        .map_err(Ssh3ClientError::Io)?;
    let target = resolved.next().ok_or_else(|| {
        Ssh3ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!(
                "could not resolve the -R target {}:{}",
                spec.target_host, spec.target_port
            ),
        ))
    })?;
    Ok(Ssh3ResolvedReverseForward {
        spec: spec.clone(),
        target,
    })
}

/// A reverse forward the server bound.
///
/// The handle carries the port the listener was actually bound to, which
/// differs from the requested one when the client asked for port zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ReverseForwardHandle {
    /// The forward the client requested.
    pub forward: Ssh3ResolvedReverseForward,
    /// The port the server bound the listener to.
    pub bound_port: u16,
}

/// Tells whether a forwarded channel may be bridged to its target.
///
/// Only the targets the client asked for with `-R` are bridged: a
/// compromised or buggy server must not be able to make the client connect
/// to an arbitrary local endpoint.
pub(crate) fn authorize_forwarded_target(
    forwards: &[Ssh3ResolvedReverseForward],
    protocol: Ssh3ReverseForwardProtocol,
    target: SocketAddr,
) -> bool {
    let target = canonical_target(target);
    forwards.iter().any(|forward| {
        forward.spec.protocol == protocol && canonical_target(forward.target) == target
    })
}

/// Normalizes an address so that the IPv4-mapped IPv6 form of an IPv4
/// address designates the same endpoint as the IPv4 address itself.
///
/// The server echoes the target it received: a peer that parses an IPv4
/// literal into an IPv4-mapped IPv6 address sends that form back, and the
/// two forms are the same endpoint.
pub(crate) fn canonical_target(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V6(address) => match address.ip().to_ipv4_mapped() {
            Some(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), address.port()),
            None => target,
        },
        SocketAddr::V4(_) => target,
    }
}

/// Asks the server to bind a listener for a reverse forward.
///
/// The returned value is the port the listener was actually bound to, which
/// differs from the requested one when the client asked for port zero. The
/// control channel is returned as well: it stays open for the whole session,
/// because the lifetime of a forward is the lifetime of its control channel.
pub(crate) async fn request_reverse_forward(
    conversation: &Ssh3Conversation,
    connection: &quinn::Connection,
    forward: &Ssh3ResolvedReverseForward,
    max_packet_size: u64,
    datagrams_queue_size: usize,
) -> Result<(u16, Arc<Ssh3Channel>), Ssh3ClientError> {
    let channel = open_channel(
        conversation,
        connection,
        CHANNEL_TYPE_REVERSE_FORWARD,
        max_packet_size,
        datagrams_queue_size,
    )
    .await
    .map_err(Ssh3ClientError::from)?;

    let request = ReverseForwardRequest {
        protocol: forward.spec.protocol.wire_value(),
        bind_address: forward.spec.wire_bind_address(),
        bind_port: forward.spec.bind_port,
        target_address: forward.target.ip().to_string(),
        target_port: forward.target.port(),
    };
    channel
        .write_data(&request.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .map_err(Ssh3ClientError::from)?;

    let reply = read_reverse_forward_reply(channel.as_ref()).await?;
    if !reply.error.is_empty() {
        let _ = channel.close().await;
        return Err(Ssh3ClientError::ReverseForwardRefused {
            spec: forward.spec.spec_string(),
            reason: reply.error,
        });
    }
    Ok((reply.bound_port, channel))
}

/// Reads the bind result the server sends on a `reverse-forward` channel.
async fn read_reverse_forward_reply(
    channel: &Ssh3Channel,
) -> Result<ReverseForwardReply, Ssh3ClientError> {
    let message = channel
        .next_message()
        .await
        .map_err(Ssh3ClientError::from)?;
    let Ssh3Message::Data(data) = message else {
        return Err(Ssh3ClientError::ForwardingProtocol(
            "the reverse forwarding reply is not a data message".to_string(),
        ));
    };
    if data.data_type != SSH_EXTENDED_DATA_NONE {
        return Err(Ssh3ClientError::ForwardingProtocol(
            "the reverse forwarding reply carries unexpected data".to_string(),
        ));
    }
    ReverseForwardReply::decode(&data.data).map_err(|err| {
        Ssh3ClientError::ForwardingProtocol(format!(
            "could not parse the reverse forwarding reply: {err}"
        ))
    })
}

/// Bridges a `forwarded-tcp` channel to the local target of the forward.
pub(crate) async fn bridge_forwarded_tcp(
    channel: Arc<Ssh3Channel>,
    target: SocketAddr,
) -> Result<(), Ssh3ClientError> {
    let stream = TcpStream::connect(target)
        .await
        .map_err(Ssh3ClientError::Io)?;
    let (mut reader, mut writer) = stream.into_split();

    let to_target = tokio::spawn({
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
            Ok::<(), Ssh3ClientError>(())
        }
    });

    let from_target = tokio::spawn({
        let channel = channel.clone();
        async move {
            let mut buffer = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                let read = reader.read(&mut buffer).await?;
                if read == 0 {
                    let _ = channel.close().await;
                    return Ok::<(), Ssh3ClientError>(());
                }
                channel
                    .write_data(&buffer[..read], SSH_EXTENDED_DATA_NONE)
                    .await?;
            }
        }
    });

    let _ = to_target.await;
    let _ = from_target.await;
    Ok(())
}

/// Bridges a `forwarded-udp` channel to the local target of the forward.
///
/// The datagrams of the channel travel over the datagram transport of the
/// conversation, like the ones of a local forward.
pub(crate) async fn bridge_forwarded_udp(
    connection: &quinn::Connection,
    channel: Arc<Ssh3Channel>,
    target: SocketAddr,
) -> Result<(), Ssh3ClientError> {
    let socket = Arc::new(
        UdpSocket::bind(match target {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })
        .await
        .map_err(Ssh3ClientError::Io)?,
    );
    socket.connect(target).await.map_err(Ssh3ClientError::Io)?;

    let to_target = tokio::spawn({
        let channel = channel.clone();
        let socket = socket.clone();
        let connection = connection.clone();
        async move {
            loop {
                // The datagram queue of a closed channel never wakes up: the
                // bridge ends with the connection.
                let datagram = tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ClientError>(()),
                    datagram = channel.receive_datagram() => datagram,
                };
                if socket.send(&datagram).await.is_err() {
                    return Ok::<(), Ssh3ClientError>(());
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), Ssh3ClientError>(())
        }
    });

    let from_target = tokio::spawn({
        let channel = channel.clone();
        let socket = socket.clone();
        let connection = connection.clone();
        async move {
            let mut buffer = vec![0u8; 1500];
            loop {
                let read = tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ClientError>(()),
                    read = socket.recv(&mut buffer) => match read {
                        Ok(read) => read,
                        Err(_) => return Ok::<(), Ssh3ClientError>(()),
                    },
                };
                if channel
                    .send_datagram(buffer[..read].to_vec())
                    .await
                    .is_err()
                {
                    return Ok::<(), Ssh3ClientError>(());
                }
            }
        }
    });

    let _ = to_target.await;
    let _ = from_target.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Ssh3ReverseForwardProtocol, Ssh3ReverseForwardSpec, authorize_forwarded_target,
        parse_reverse_forward_spec,
    };
    use crate::Ssh3ResolvedReverseForward;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn parses_the_ssh_reverse_forward_syntax() {
        let spec = parse_reverse_forward_spec("8080:example.com:80").unwrap();
        assert_eq!(spec.bind_address, None);
        assert_eq!(spec.bind_port, 8080);
        assert_eq!(spec.target_host, "example.com");
        assert_eq!(spec.target_port, 80);
        assert_eq!(spec.protocol, Ssh3ReverseForwardProtocol::Tcp);
    }

    #[test]
    fn parses_the_bind_address_of_a_reverse_forward() {
        let spec = parse_reverse_forward_spec("127.0.0.1:8080:example.com:80").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(spec.bind_port, 8080);
    }

    #[test]
    fn parses_the_wildcard_bind_address_of_a_reverse_forward() {
        let spec = parse_reverse_forward_spec("*:8080:example.com:80").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("*"));
    }

    #[test]
    fn parses_the_udp_marker_of_a_reverse_forward() {
        let spec = parse_reverse_forward_spec("5353/udp:example.com:53").unwrap();
        assert_eq!(spec.protocol, Ssh3ReverseForwardProtocol::Udp);
        assert_eq!(spec.bind_port, 5353);

        let spec = parse_reverse_forward_spec("5353/tcp:example.com:53").unwrap();
        assert_eq!(spec.protocol, Ssh3ReverseForwardProtocol::Tcp);
    }

    #[test]
    fn parses_the_bracketed_ipv6_literals_of_a_reverse_forward() {
        let spec = parse_reverse_forward_spec("[::1]:8080:[2001:db8::1]:80").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("::1"));
        assert_eq!(spec.target_host, "2001:db8::1");
        assert_eq!(spec.target_port, 80);
    }

    #[test]
    fn refuses_the_malformed_reverse_forwards() {
        assert!(parse_reverse_forward_spec("").is_err());
        assert!(parse_reverse_forward_spec("8080").is_err());
        assert!(parse_reverse_forward_spec("8080:example.com").is_err());
        assert!(parse_reverse_forward_spec("8080::80").is_err());
        assert!(parse_reverse_forward_spec("8080:example.com:0").is_err());
        assert!(parse_reverse_forward_spec("8080:example.com:http").is_err());
        assert!(parse_reverse_forward_spec("8080/sctp:example.com:80").is_err());
        assert!(parse_reverse_forward_spec("8080::80").is_err());
    }

    #[test]
    fn renders_a_reverse_forward_back_into_its_specification() {
        let spec = Ssh3ReverseForwardSpec {
            bind_address: Some("127.0.0.1".to_string()),
            bind_port: 8080,
            target_host: "example.com".to_string(),
            target_port: 80,
            protocol: Ssh3ReverseForwardProtocol::Udp,
        };
        assert_eq!(spec.spec_string(), "127.0.0.1:8080/udp:example.com:80");
    }

    #[test]
    fn only_the_requested_targets_are_authorized() {
        let forward = Ssh3ResolvedReverseForward {
            spec: Ssh3ReverseForwardSpec {
                bind_address: None,
                bind_port: 8080,
                target_host: "example.com".to_string(),
                target_port: 80,
                protocol: Ssh3ReverseForwardProtocol::Tcp,
            },
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
        };
        let forwards = vec![forward];

        assert!(authorize_forwarded_target(
            &forwards,
            Ssh3ReverseForwardProtocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
        ));
        // another port of the same host is another endpoint.
        assert!(!authorize_forwarded_target(
            &forwards,
            Ssh3ReverseForwardProtocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        ));
        // another protocol is another endpoint.
        assert!(!authorize_forwarded_target(
            &forwards,
            Ssh3ReverseForwardProtocol::Udp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
        ));
        // an endpoint the client never asked for.
        assert!(!authorize_forwarded_target(
            &forwards,
            Ssh3ReverseForwardProtocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22),
        ));
    }
}
