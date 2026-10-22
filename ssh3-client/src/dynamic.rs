//! Dynamic port forwarding (`-D`): the client half.
//!
//! A dynamic forward is a local SOCKS5 proxy whose connections are dialed by
//! the remote peer. The client announces the local bind on a
//! `dynamic-forward` control channel and opens one `dynamic-forward-tcp`
//! channel per accepted connection, carrying the address of the target the
//! server must dial.
//!
//! The reference implementation of this behavior lives in `nagual2/ssh3-go`,
//! files `cmd/dynamic_forward.go` and `cmd/dynamic_forward_server.go`.

use std::net::SocketAddr;
use std::sync::Arc;

use ssh3_core::{Ssh3Channel, Ssh3Conversation};
use ssh3_proto::{SSH_EXTENDED_DATA_NONE, Ssh3Message};
use ssh3_quinn::open_channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::Ssh3ClientError;
use crate::forwarding_wire::{
    DynamicForwardReply, DynamicForwardRequest, DynamicForwardTarget, DynamicForwardTargetReply,
};

/// Channel type of the control channel a client opens to announce a dynamic
/// forward.
pub(crate) const CHANNEL_TYPE_DYNAMIC_FORWARD: &[u8] = b"dynamic-forward";

/// Channel type of the data channels a client opens for every connection its
/// SOCKS listener accepts.
pub(crate) const CHANNEL_TYPE_DYNAMIC_FORWARD_TCP: &[u8] = b"dynamic-forward-tcp";

/// The version of the SOCKS5 protocol the proxy speaks.
const SOCKS5_VERSION: u8 = 0x05;

/// The only authentication method the proxy offers.
const SOCKS5_METHOD_NO_AUTH: u8 = 0x00;

/// The only SOCKS5 command the proxy serves.
const SOCKS5_COMMAND_CONNECT: u8 = 0x01;

/// The address type of an IPv4 address.
const SOCKS5_ADDRESS_IPV4: u8 = 0x01;

/// The address type of a domain name.
const SOCKS5_ADDRESS_DOMAIN: u8 = 0x03;

/// The address type of an IPv6 address.
const SOCKS5_ADDRESS_IPV6: u8 = 0x04;

/// The reply code of a successful request.
const SOCKS5_REPLY_SUCCESS: u8 = 0x00;

/// The reply code of a failure the proxy cannot describe better.
const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;

/// The reply code of a request the proxy refuses to serve.
const SOCKS5_REPLY_NOT_ALLOWED: u8 = 0x02;

/// The reply code of an unreachable network.
const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;

/// The reply code of an unreachable host.
const SOCKS5_REPLY_HOST_UNREACHABLE: u8 = 0x04;

/// The reply code of a refused connection.
const SOCKS5_REPLY_CONNECTION_REFUSED: u8 = 0x05;

/// The reply code of an expired time to live.
const SOCKS5_REPLY_TTL_EXPIRED: u8 = 0x06;

/// The reply code of an unsupported command.
const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// The reply code of an unsupported address type.
const SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

/// The timeout of the SOCKS5 prologue of a connection.
const SOCKS5_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// One parsed `-D` value: the local SOCKS listener to open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3DynamicForwardSpec {
    /// The address the SOCKS listener binds.
    ///
    /// `None` binds the loopback (the OpenSSH default) and `Some("*")` binds
    /// every interface.
    pub bind_address: Option<String>,
    /// The port the SOCKS listener binds; zero allocates an ephemeral port.
    pub bind_port: u16,
}

impl Ssh3DynamicForwardSpec {
    /// Renders the forward back into its `-D` form.
    pub fn spec_string(&self) -> String {
        let address = self.bind_address.as_deref().unwrap_or("127.0.0.1");
        format!("{address}:{}", self.bind_port)
    }

    /// The bind address the announcement carries on the wire.
    ///
    /// The wildcard marker of OpenSSH is sent as it is: the server only
    /// echoes it back, it never binds it.
    fn wire_bind_address(&self) -> String {
        match self.bind_address.as_deref() {
            None => String::new(),
            Some(address) => address.to_string(),
        }
    }
}

/// A dynamic forward the client opened.
///
/// The handle carries the address the SOCKS listener really listens on, which
/// differs from the requested one when the client asked for port zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3DynamicForwardHandle {
    /// The forward the client requested.
    pub spec: Ssh3DynamicForwardSpec,
    /// The address the SOCKS listener listens on.
    pub listen_addr: SocketAddr,
}

/// The dynamic forwards a client opened, with the tasks that serve them.
pub(crate) struct Ssh3DynamicForwards {
    /// The handle of every forward.
    ///
    /// The handles carry the address the SOCKS listener really listens on:
    /// the callers that need it read them, the session itself only needs the
    /// tasks.
    #[allow(dead_code)]
    pub handles: Vec<Ssh3DynamicForwardHandle>,
    /// The tasks that serve the SOCKS listeners.
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// The error of a `-D` value the ssh(1) syntax does not accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3DynamicForwardParseError {
    spec: String,
    reason: String,
}

impl std::fmt::Display for Ssh3DynamicForwardParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid -D specification {:?}: {}",
            self.spec, self.reason
        )
    }
}

impl std::error::Error for Ssh3DynamicForwardParseError {}

/// Parses the OpenSSH `-D [bind_address:]port` syntax.
///
/// The IPv6 literals must be bracketed: a bare `::1:1080` is refused instead
/// of being silently read as the address `::` and the port `1`.
pub fn parse_dynamic_forward_spec(
    spec: &str,
) -> Result<Ssh3DynamicForwardSpec, Ssh3DynamicForwardParseError> {
    let value = spec.trim();
    if value.is_empty() {
        return Err(Ssh3DynamicForwardParseError {
            spec: spec.to_string(),
            reason: "expected [bind_address:]port".to_string(),
        });
    }

    let parts = split_outside_brackets(value, ':');
    let (bind_address, port_part) = match parts.len() {
        1 => (None, parts[0].clone()),
        2 => {
            let address = unbracket(&parts[0]);
            if address != "*" && address.contains([' ', '\t']) {
                return Err(Ssh3DynamicForwardParseError {
                    spec: spec.to_string(),
                    reason: format!("invalid bind address {address:?}"),
                });
            }
            (Some(address), parts[1].clone())
        }
        _ => {
            return Err(Ssh3DynamicForwardParseError {
                spec: spec.to_string(),
                reason: "expected [bind_address:]port, IPv6 addresses must be bracketed"
                    .to_string(),
            });
        }
    };

    let bind_port = port_part
        .parse::<u16>()
        .map_err(|_| Ssh3DynamicForwardParseError {
            spec: spec.to_string(),
            reason: format!("invalid bind port {port_part:?}"),
        })?;

    Ok(Ssh3DynamicForwardSpec {
        bind_address,
        bind_port,
    })
}

/// Splits on the separator, ignoring the separators inside brackets, so that
/// an IPv6 literal like `[::1]:1080` stays in one part.
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

/// A SOCKS5 failure and the reply code that describes it best.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Socks5Error {
    /// The SOCKS5 reply code of the failure.
    pub code: u8,
    /// The human-readable reason of the failure.
    pub message: String,
}

impl Socks5Error {
    /// Builds a failure with its reply code.
    fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Socks5Error {}

/// A decoded SOCKS5 CONNECT request.
///
/// The address holds an IP literal for the IPv4 and IPv6 address types and
/// the name as it was sent for the domain type: it is never resolved on this
/// side, the server resolves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Socks5Request {
    /// The address the server must dial.
    pub address: String,
    /// The port the server must dial.
    pub port: u16,
}

/// Decodes a SOCKS5 CONNECT request.
///
/// The buffer must hold the whole request, the header included.
pub(crate) fn parse_socks5_request(buffer: &[u8]) -> Result<Socks5Request, Socks5Error> {
    if buffer.len() < 4 {
        return Err(Socks5Error::new(
            SOCKS5_REPLY_GENERAL_FAILURE,
            format!("truncated SOCKS5 request: {} bytes", buffer.len()),
        ));
    }
    if buffer[0] != SOCKS5_VERSION {
        return Err(Socks5Error::new(
            SOCKS5_REPLY_GENERAL_FAILURE,
            format!("unsupported SOCKS version 0x{:02x}", buffer[0]),
        ));
    }
    let command = buffer[1];
    if buffer[2] != 0 {
        return Err(Socks5Error::new(
            SOCKS5_REPLY_GENERAL_FAILURE,
            format!("invalid SOCKS5 reserved byte 0x{:02x}", buffer[2]),
        ));
    }

    let mut consumed = 4usize;
    let address = match buffer[3] {
        SOCKS5_ADDRESS_IPV4 => {
            if buffer.len() < consumed + 4 {
                return Err(Socks5Error::new(
                    SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED,
                    "truncated SOCKS5 IPv4 address",
                ));
            }
            let address = std::net::Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
            consumed += 4;
            address.to_string()
        }
        SOCKS5_ADDRESS_IPV6 => {
            if buffer.len() < consumed + 16 {
                return Err(Socks5Error::new(
                    SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED,
                    "truncated SOCKS5 IPv6 address",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buffer[4..20]);
            let address = std::net::Ipv6Addr::from(octets);
            consumed += 16;
            address.to_string()
        }
        SOCKS5_ADDRESS_DOMAIN => {
            if buffer.len() < consumed + 1 {
                return Err(Socks5Error::new(
                    SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED,
                    "truncated SOCKS5 domain name length",
                ));
            }
            let length = usize::from(buffer[4]);
            if length == 0 {
                return Err(Socks5Error::new(
                    SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED,
                    "empty SOCKS5 domain name",
                ));
            }
            if buffer.len() < consumed + 1 + length {
                return Err(Socks5Error::new(
                    SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED,
                    "truncated SOCKS5 domain name",
                ));
            }
            let name = String::from_utf8_lossy(&buffer[5..5 + length]).to_string();
            consumed += 1 + length;
            name
        }
        address_type => {
            return Err(Socks5Error::new(
                SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED,
                format!("unsupported SOCKS5 address type 0x{address_type:02x}"),
            ));
        }
    };

    if buffer.len() < consumed + 2 {
        return Err(Socks5Error::new(
            SOCKS5_REPLY_GENERAL_FAILURE,
            "truncated SOCKS5 port",
        ));
    }
    let port = u16::from_be_bytes([buffer[consumed], buffer[consumed + 1]]);

    if command != SOCKS5_COMMAND_CONNECT {
        return Err(Socks5Error::new(
            SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            format!("unsupported SOCKS5 command 0x{command:02x}"),
        ));
    }
    if port == 0 {
        return Err(Socks5Error::new(
            SOCKS5_REPLY_HOST_UNREACHABLE,
            "invalid SOCKS5 target port 0",
        ));
    }
    if address.is_empty() {
        return Err(Socks5Error::new(
            SOCKS5_REPLY_HOST_UNREACHABLE,
            "empty SOCKS5 target address",
        ));
    }

    Ok(Socks5Request { address, port })
}

/// Maps the textual reason of a failed dial onto a SOCKS5 reply code.
///
/// The reason comes from the server, so "connection refused" must not reach
/// the SOCKS client as "host unreachable".
pub(crate) fn socks5_reply_code_for_server_error(message: &str) -> u8 {
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("refused") {
        SOCKS5_REPLY_CONNECTION_REFUSED
    } else if lowered.contains("no such host")
        || lowered.contains("unknown host")
        || lowered.contains("unreachable")
    {
        SOCKS5_REPLY_HOST_UNREACHABLE
    } else if lowered.contains("timeout") || lowered.contains("expired") {
        SOCKS5_REPLY_TTL_EXPIRED
    } else if lowered.contains("network") {
        SOCKS5_REPLY_NETWORK_UNREACHABLE
    } else {
        SOCKS5_REPLY_GENERAL_FAILURE
    }
}

/// Builds the reply of the proxy.
///
/// The bound address is always the unspecified one: the proxy has no listener
/// of its own to advertise.
fn socks5_reply(code: u8) -> [u8; 10] {
    let mut reply = [0u8; 10];
    reply[0] = SOCKS5_VERSION;
    reply[1] = code;
    reply[3] = SOCKS5_ADDRESS_IPV4;
    reply
}

/// Reads the method list of the SOCKS client and checks that the proxy may
/// answer with the only method it supports.
async fn read_method_selection(stream: &mut TcpStream) -> Result<(), Socks5Error> {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|err| Socks5Error::new(SOCKS5_REPLY_GENERAL_FAILURE, err.to_string()))?;
    if header[0] != SOCKS5_VERSION {
        return Err(Socks5Error::new(
            SOCKS5_REPLY_GENERAL_FAILURE,
            format!("unsupported SOCKS version 0x{:02x}", header[0]),
        ));
    }
    let count = usize::from(header[1]);
    if count == 0 {
        return Err(Socks5Error::new(
            SOCKS5_REPLY_GENERAL_FAILURE,
            "empty SOCKS5 method list",
        ));
    }
    let mut methods = vec![0u8; count];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|err| Socks5Error::new(SOCKS5_REPLY_GENERAL_FAILURE, err.to_string()))?;
    if methods.contains(&SOCKS5_METHOD_NO_AUTH) {
        return Ok(());
    }
    Err(Socks5Error::new(
        SOCKS5_REPLY_NOT_ALLOWED,
        "the SOCKS5 proxy only supports \"no authentication required\"",
    ))
}

/// Reads a whole SOCKS5 request from the stream.
async fn read_socks5_request(stream: &mut TcpStream) -> Result<Socks5Request, Socks5Error> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|err| Socks5Error::new(SOCKS5_REPLY_GENERAL_FAILURE, err.to_string()))?;

    // The length of the request depends on its address type: the header is
    // read first, then exactly the bytes of the address and of the port.
    let length = match header[3] {
        SOCKS5_ADDRESS_IPV4 => 4 + 4 + 2,
        SOCKS5_ADDRESS_IPV6 => 4 + 16 + 2,
        SOCKS5_ADDRESS_DOMAIN => {
            let mut length_byte = [0u8; 1];
            stream
                .read_exact(&mut length_byte)
                .await
                .map_err(|err| Socks5Error::new(SOCKS5_REPLY_GENERAL_FAILURE, err.to_string()))?;
            5 + usize::from(length_byte[0]) + 2
        }
        _ => {
            return Err(Socks5Error::new(
                SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED,
                format!("unsupported SOCKS5 address type 0x{:02x}", header[3]),
            ));
        }
    };

    let mut buffer = Vec::with_capacity(length);
    buffer.extend_from_slice(&header);
    if length > 4 {
        let mut rest = vec![0u8; length - 4];
        stream
            .read_exact(&mut rest)
            .await
            .map_err(|err| Socks5Error::new(SOCKS5_REPLY_GENERAL_FAILURE, err.to_string()))?;
        buffer.extend_from_slice(&rest);
    }
    parse_socks5_request(&buffer)
}

/// Announces a dynamic forward to the server and opens the local SOCKS
/// listener.
///
/// The returned control channel stays open for the whole session: closing it
/// is how the server learns that the forward is gone, so the caller must
/// keep it alive.
pub(crate) async fn start_dynamic_forward(
    conversation: &Ssh3Conversation,
    connection: &quinn::Connection,
    spec: &Ssh3DynamicForwardSpec,
    max_packet_size: u64,
    datagrams_queue_size: usize,
) -> Result<(TcpListener, Arc<Ssh3Channel>), Ssh3ClientError> {
    let control_channel = open_channel(
        conversation,
        connection,
        CHANNEL_TYPE_DYNAMIC_FORWARD,
        max_packet_size,
        datagrams_queue_size,
    )
    .await
    .map_err(Ssh3ClientError::from)?;

    let request = DynamicForwardRequest {
        bind_address: spec.wire_bind_address(),
        bind_port: spec.bind_port,
    };
    control_channel
        .write_data(&request.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .map_err(Ssh3ClientError::from)?;

    let reply = read_dynamic_forward_reply(control_channel.as_ref()).await?;
    if !reply.error.is_empty() {
        let _ = control_channel.close().await;
        return Err(Ssh3ClientError::DynamicForwardRefused {
            spec: spec.spec_string(),
            reason: reply.error,
        });
    }

    let listener = TcpListener::bind(resolve_bind_address(spec).await?)
        .await
        .map_err(Ssh3ClientError::Io)?;

    Ok((listener, control_channel))
}

/// Resolves the address the SOCKS listener binds.
async fn resolve_bind_address(
    spec: &Ssh3DynamicForwardSpec,
) -> Result<SocketAddr, Ssh3ClientError> {
    match spec.bind_address.as_deref() {
        // The OpenSSH wildcard: every interface of the family.
        Some("*") => Ok(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
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
        // The OpenSSH default: the loopback only, so the proxy is never
        // reachable from the network.
        None => Ok(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            spec.bind_port,
        )),
    }
}

/// Reads the acknowledgement the server sends on a `dynamic-forward` channel.
async fn read_dynamic_forward_reply(
    channel: &Ssh3Channel,
) -> Result<DynamicForwardReply, Ssh3ClientError> {
    let message = channel
        .next_message()
        .await
        .map_err(Ssh3ClientError::from)?;
    let Ssh3Message::Data(data) = message else {
        return Err(Ssh3ClientError::ForwardingProtocol(
            "the dynamic forwarding reply is not a data message".to_string(),
        ));
    };
    if data.data_type != SSH_EXTENDED_DATA_NONE {
        return Err(Ssh3ClientError::ForwardingProtocol(
            "the dynamic forwarding reply carries unexpected data".to_string(),
        ));
    }
    DynamicForwardReply::decode(&data.data).map_err(|err| {
        Ssh3ClientError::ForwardingProtocol(format!(
            "could not parse the dynamic forwarding reply: {err}"
        ))
    })
}

/// Reads the result of the dial the server performed for a SOCKS connection.
async fn read_dynamic_forward_target_reply(
    channel: &Ssh3Channel,
) -> Result<DynamicForwardTargetReply, Ssh3ClientError> {
    let message = channel
        .next_message()
        .await
        .map_err(Ssh3ClientError::from)?;
    let Ssh3Message::Data(data) = message else {
        return Err(Ssh3ClientError::ForwardingProtocol(
            "the dynamic forwarding target reply is not a data message".to_string(),
        ));
    };
    if data.data_type != SSH_EXTENDED_DATA_NONE {
        return Err(Ssh3ClientError::ForwardingProtocol(
            "the dynamic forwarding target reply carries unexpected data".to_string(),
        ));
    }
    DynamicForwardTargetReply::decode(&data.data).map_err(|err| {
        Ssh3ClientError::ForwardingProtocol(format!(
            "could not parse the dynamic forwarding target reply: {err}"
        ))
    })
}

/// Opens the data channel of one SOCKS connection and asks the server to
/// dial the target.
///
/// The channel is returned only once the server confirmed it reached the
/// target.
pub(crate) async fn open_dynamic_forward_stream(
    conversation: &Ssh3Conversation,
    connection: &quinn::Connection,
    request: &Socks5Request,
) -> Result<Arc<Ssh3Channel>, Ssh3ClientError> {
    let channel = open_channel(
        conversation,
        connection,
        CHANNEL_TYPE_DYNAMIC_FORWARD_TCP,
        30_000,
        0,
    )
    .await
    .map_err(Ssh3ClientError::from)?;

    let target = DynamicForwardTarget {
        address: request.address.clone(),
        port: request.port,
    };
    channel
        .write_data(&target.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .map_err(Ssh3ClientError::from)?;

    let reply = read_dynamic_forward_target_reply(channel.as_ref()).await?;
    if !reply.error.is_empty() {
        let _ = channel.close().await;
        return Err(Ssh3ClientError::DynamicForwardDial {
            target: format!("{}:{}", request.address, request.port),
            reason: reply.error,
        });
    }
    Ok(channel)
}

/// Serves one SOCKS5 connection: the handshake, then the tunnel.
pub(crate) async fn serve_socks5_connection(
    conversation: &Ssh3Conversation,
    connection: &quinn::Connection,
    mut stream: TcpStream,
) {
    let handshake = tokio::time::timeout(
        SOCKS5_HANDSHAKE_TIMEOUT,
        serve_socks5_handshake(conversation, connection, &mut stream),
    )
    .await;

    match handshake {
        Ok(Ok(channel)) => {
            if let Err(err) = bridge_dynamic_forward(channel, stream).await {
                if !crate::is_benign_client_error(&err) {
                    eprintln!("ssh3-rust-client dynamic forwarding error: {err}");
                }
            }
        }
        Ok(Err(err)) => {
            // The failure is reported to the SOCKS client with the reply
            // code that describes it best.
            let _ = stream.write_all(&socks5_reply(err.code)).await;
            let _ = stream.flush().await;
        }
        Err(_) => {
            // A client that opens a connection and then says nothing must not
            // hold a channel open.
        }
    }
}

/// Runs the SOCKS5 prologue of a connection and opens the tunnel.
async fn serve_socks5_handshake(
    conversation: &Ssh3Conversation,
    connection: &quinn::Connection,
    stream: &mut TcpStream,
) -> Result<Arc<Ssh3Channel>, Socks5Error> {
    read_method_selection(stream).await?;
    // The proxy speaks one method only: the credentials of the SOCKS client
    // never travel over the local connection.
    stream
        .write_all(&[SOCKS5_VERSION, SOCKS5_METHOD_NO_AUTH])
        .await
        .map_err(|err| Socks5Error::new(SOCKS5_REPLY_GENERAL_FAILURE, err.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|err| Socks5Error::new(SOCKS5_REPLY_GENERAL_FAILURE, err.to_string()))?;

    let request = read_socks5_request(stream).await?;
    let channel = open_dynamic_forward_stream(conversation, connection, &request)
        .await
        .map_err(|err| {
            Socks5Error::new(
                socks5_reply_code_for_server_error(&err.to_string()),
                err.to_string(),
            )
        })?;

    // The handshake is over: the connection is now an opaque tunnel.
    stream
        .write_all(&socks5_reply(SOCKS5_REPLY_SUCCESS))
        .await
        .map_err(|err| Socks5Error::new(SOCKS5_REPLY_GENERAL_FAILURE, err.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|err| Socks5Error::new(SOCKS5_REPLY_GENERAL_FAILURE, err.to_string()))?;
    Ok(channel)
}

/// Bridges the local connection and the remote channel in both directions.
async fn bridge_dynamic_forward(
    channel: Arc<Ssh3Channel>,
    stream: TcpStream,
) -> Result<(), Ssh3ClientError> {
    let (mut reader, mut writer) = stream.into_split();

    let to_remote = tokio::spawn({
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

    let from_remote = tokio::spawn({
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

    let _ = to_remote.await;
    let _ = from_remote.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        SOCKS5_ADDRESS_DOMAIN, SOCKS5_ADDRESS_IPV4, SOCKS5_ADDRESS_IPV6,
        SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
        SOCKS5_REPLY_CONNECTION_REFUSED, SOCKS5_REPLY_GENERAL_FAILURE,
        SOCKS5_REPLY_HOST_UNREACHABLE, SOCKS5_REPLY_NETWORK_UNREACHABLE, SOCKS5_REPLY_TTL_EXPIRED,
        Socks5Error, parse_dynamic_forward_spec, parse_socks5_request,
        socks5_reply_code_for_server_error,
    };

    #[test]
    fn parses_the_ssh_dynamic_forward_syntax() {
        let spec = parse_dynamic_forward_spec("1080").unwrap();
        assert_eq!(spec.bind_address, None);
        assert_eq!(spec.bind_port, 1080);

        let spec = parse_dynamic_forward_spec("127.0.0.1:1080").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(spec.bind_port, 1080);

        let spec = parse_dynamic_forward_spec("*:1080").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("*"));

        let spec = parse_dynamic_forward_spec("[::1]:1080").unwrap();
        assert_eq!(spec.bind_address.as_deref(), Some("::1"));
        assert_eq!(spec.bind_port, 1080);
    }

    #[test]
    fn refuses_the_malformed_dynamic_forwards() {
        assert!(parse_dynamic_forward_spec("").is_err());
        assert!(parse_dynamic_forward_spec("http").is_err());
        assert!(parse_dynamic_forward_spec("::1:1080").is_err());
        assert!(parse_dynamic_forward_spec("127.0.0.1:1080:1").is_err());
        assert!(parse_dynamic_forward_spec("127.0.0.1:70000").is_err());
    }

    #[test]
    fn parses_a_socks5_connect_request_with_an_ipv4_address() {
        let request = parse_socks5_request(&[
            0x05,
            0x01,
            0x00,
            SOCKS5_ADDRESS_IPV4,
            192,
            0,
            2,
            10,
            0x01,
            0xbb,
        ])
        .unwrap();
        assert_eq!(request.address, "192.0.2.10");
        assert_eq!(request.port, 443);
    }

    #[test]
    fn parses_a_socks5_connect_request_with_an_ipv6_address() {
        let mut buffer = vec![0x05, 0x01, 0x00, SOCKS5_ADDRESS_IPV6];
        buffer.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        buffer.extend_from_slice(&[0x20, 0xfb]);
        let request = parse_socks5_request(&buffer).unwrap();
        assert_eq!(request.address, "2001:db8::1");
        assert_eq!(request.port, 8443);
    }

    #[test]
    fn parses_a_socks5_connect_request_with_a_domain_name() {
        let request = parse_socks5_request(&[
            0x05,
            0x01,
            0x00,
            SOCKS5_ADDRESS_DOMAIN,
            11,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            b'.',
            b'c',
            b'o',
            b'm',
            0x01,
            0xbb,
        ])
        .unwrap();
        assert_eq!(request.address, "example.com");
        assert_eq!(request.port, 443);
    }

    #[test]
    fn refuses_the_malformed_socks5_requests() {
        // a truncated request
        assert_eq!(
            parse_socks5_request(&[0x05, 0x01]).unwrap_err().code,
            SOCKS5_REPLY_GENERAL_FAILURE
        );
        // an unsupported version
        assert_eq!(
            parse_socks5_request(&[0x04, 0x01, 0x00, SOCKS5_ADDRESS_IPV4])
                .unwrap_err()
                .code,
            SOCKS5_REPLY_GENERAL_FAILURE
        );
        // a non-zero reserved byte
        assert_eq!(
            parse_socks5_request(&[0x05, 0x01, 0x01, SOCKS5_ADDRESS_IPV4])
                .unwrap_err()
                .code,
            SOCKS5_REPLY_GENERAL_FAILURE
        );
        // an unsupported address type
        assert_eq!(
            parse_socks5_request(&[0x05, 0x01, 0x00, 0x02])
                .unwrap_err()
                .code,
            SOCKS5_REPLY_ADDRESS_NOT_SUPPORTED
        );
        // an unsupported command
        assert_eq!(
            parse_socks5_request(&[0x05, 0x02, 0x00, SOCKS5_ADDRESS_IPV4, 1, 2, 3, 4, 0, 80])
                .unwrap_err()
                .code,
            SOCKS5_REPLY_COMMAND_NOT_SUPPORTED
        );
        // a null port
        assert_eq!(
            parse_socks5_request(&[0x05, 0x01, 0x00, SOCKS5_ADDRESS_IPV4, 1, 2, 3, 4, 0, 0])
                .unwrap_err()
                .code,
            SOCKS5_REPLY_HOST_UNREACHABLE
        );
    }

    #[test]
    fn maps_the_reason_of_a_failed_dial_onto_a_reply_code() {
        assert_eq!(
            socks5_reply_code_for_server_error(
                "dial tcp 192.0.2.10:80: connect: connection refused"
            ),
            SOCKS5_REPLY_CONNECTION_REFUSED
        );
        assert_eq!(
            socks5_reply_code_for_server_error("could not resolve \"example.com\": no such host"),
            SOCKS5_REPLY_HOST_UNREACHABLE
        );
        // The unreachable check comes before the network one, like in the
        // reference implementation.
        assert_eq!(
            socks5_reply_code_for_server_error("network is unreachable"),
            SOCKS5_REPLY_HOST_UNREACHABLE
        );
        assert_eq!(
            socks5_reply_code_for_server_error("network error"),
            SOCKS5_REPLY_NETWORK_UNREACHABLE
        );
        assert_eq!(
            socks5_reply_code_for_server_error("i/o timeout"),
            SOCKS5_REPLY_TTL_EXPIRED
        );
        assert_eq!(
            socks5_reply_code_for_server_error("something else"),
            SOCKS5_REPLY_GENERAL_FAILURE
        );
    }

    #[test]
    fn the_socks5_error_carries_its_reply_code() {
        let error = Socks5Error {
            code: SOCKS5_REPLY_GENERAL_FAILURE,
            message: "broken".to_string(),
        };
        assert_eq!(error.to_string(), "broken");
    }
}
