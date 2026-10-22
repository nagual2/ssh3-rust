//! Wire payloads of the reverse and dynamic port forwarding channels.
//!
//! Both forwarding families carry their payloads as channel data instead of
//! as new message-type ids: an older peer refuses the channel type by its
//! name instead of crashing on an unknown message-type id.
//!
//! The layouts are byte-for-byte compatible with the reference
//! implementation (`nagual2/ssh3-go`, packages `message/reverse_forward.go`
//! and `message/dynamic_forward.go`):
//!
//! | Payload | Layout |
//! |---|---|
//! | reverse forward request | protocol, bind address, bind port, target address, target port |
//! | reverse forward reply | bound port, error |
//! | dynamic forward request | version, kind, bind address, bind port |
//! | dynamic forward reply | version, kind, bound port, error |
//! | dynamic forward target | version, kind, address, port |
//! | dynamic forward target reply | version, kind, error |
//!
//! Strings are length-prefixed (the length is a variable-length integer) and
//! ports are two bytes in network byte order.

use std::fmt;
use std::io::{Cursor, Read};

use ssh3_proto::{append_ssh_bytes, append_var_int, read_ssh_bytes, read_var_int};

/// Transport protocol of a reverse forwarding request: datagrams.
pub(crate) const FORWARDING_PROTOCOL_UDP: u64 = 0;

/// Transport protocol of a reverse forwarding request: byte streams.
pub(crate) const FORWARDING_PROTOCOL_TCP: u64 = 1;

/// Version of the dynamic forwarding payloads.
///
/// The version travels as the first variable-length integer of every
/// dynamic forwarding payload, so a future revision of the codec is refused
/// instead of being misinterpreted.
pub(crate) const DYNAMIC_FORWARD_VERSION: u64 = 1;

/// Kind of a dynamic forwarding payload sent by the client on a
/// `dynamic-forward` control channel.
pub(crate) const DYNAMIC_FORWARD_KIND_REQUEST: u64 = 1;

/// Kind of a dynamic forwarding payload sent by the server in answer to a
/// [`DYNAMIC_FORWARD_KIND_REQUEST`] payload.
pub(crate) const DYNAMIC_FORWARD_KIND_REQUEST_REPLY: u64 = 2;

/// Kind of a dynamic forwarding payload sent by the client on a
/// `dynamic-forward-tcp` channel.
pub(crate) const DYNAMIC_FORWARD_KIND_TARGET: u64 = 3;

/// Kind of a dynamic forwarding payload sent by the server in answer to a
/// [`DYNAMIC_FORWARD_KIND_TARGET`] payload.
pub(crate) const DYNAMIC_FORWARD_KIND_TARGET_REPLY: u64 = 4;

/// Everything that can go wrong while decoding a forwarding payload.
///
/// The payloads travel as channel data, so a malformed one is a peer error
/// and never a reason to abort the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ssh3ForwardingWireError {
    /// The payload ended before the expected number of bytes.
    Truncated,
    /// The payload holds a string that is not valid UTF-8.
    InvalidUtf8,
    /// The protocol of a reverse forwarding request is neither UDP nor TCP.
    UnsupportedProtocol(u64),
    /// The version of a dynamic forwarding payload is not supported.
    UnsupportedVersion(u64),
    /// The kind of a dynamic forwarding payload is not the expected one.
    UnexpectedKind {
        /// The kind the server expected.
        expected: u64,
        /// The kind the client sent.
        found: u64,
    },
    /// The address of a dynamic forwarding target is empty.
    EmptyTargetAddress,
    /// The port of a dynamic forwarding target is zero.
    NullTargetPort,
}

impl fmt::Display for Ssh3ForwardingWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "the forwarding payload is truncated"),
            Self::InvalidUtf8 => write!(f, "the forwarding payload holds a non-UTF-8 string"),
            Self::UnsupportedProtocol(protocol) => {
                write!(f, "invalid reverse forwarding protocol number: {protocol}")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "unsupported dynamic forwarding protocol version: {version}"
                )
            }
            Self::UnexpectedKind { expected, found } => write!(
                f,
                "unexpected dynamic forwarding message kind: {found} instead of expected {expected}"
            ),
            Self::EmptyTargetAddress => write!(f, "empty dynamic forwarding target address"),
            Self::NullTargetPort => write!(f, "null dynamic forwarding target port"),
        }
    }
}

impl std::error::Error for Ssh3ForwardingWireError {}

/// Reads a length-prefixed string from `reader`.
fn read_string(reader: &mut impl Read) -> Result<String, Ssh3ForwardingWireError> {
    let bytes = read_ssh_bytes(reader).map_err(|_| Ssh3ForwardingWireError::Truncated)?;
    String::from_utf8(bytes).map_err(|_| Ssh3ForwardingWireError::InvalidUtf8)
}

/// Reads a port (two bytes in network byte order) from `reader`.
fn read_port(reader: &mut impl Read) -> Result<u16, Ssh3ForwardingWireError> {
    let mut bytes = [0u8; 2];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| Ssh3ForwardingWireError::Truncated)?;
    Ok(u16::from_be_bytes(bytes))
}

/// Writes a port (two bytes in network byte order) into `out`.
fn write_port(out: &mut Vec<u8>, port: u16) {
    out.extend_from_slice(&port.to_be_bytes());
}

/// Reads the versioned prefix shared by every dynamic forwarding payload.
fn read_dynamic_forward_header(
    reader: &mut impl Read,
    expected_kind: u64,
) -> Result<(), Ssh3ForwardingWireError> {
    let version = read_var_int(reader).map_err(|_| Ssh3ForwardingWireError::Truncated)?;
    if version != DYNAMIC_FORWARD_VERSION {
        return Err(Ssh3ForwardingWireError::UnsupportedVersion(version));
    }
    let kind = read_var_int(reader).map_err(|_| Ssh3ForwardingWireError::Truncated)?;
    if kind != expected_kind {
        return Err(Ssh3ForwardingWireError::UnexpectedKind {
            expected: expected_kind,
            found: kind,
        });
    }
    Ok(())
}

/// Writes the versioned prefix shared by every dynamic forwarding payload.
fn write_dynamic_forward_header(out: &mut Vec<u8>, kind: u64) {
    append_var_int(out, DYNAMIC_FORWARD_VERSION);
    append_var_int(out, kind);
}

/// The payload a client sends as channel data on a `reverse-forward` channel
/// to ask the server to bind a listener for it.
///
/// The bind address is an IP literal, `"*"` (wildcard) or empty (the server
/// default: loopback only). The target address is always an IP literal: the
/// client resolves the target locally, like OpenSSH resolves the `-R` target
/// on the machine where the client runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReverseForwardRequest {
    /// Transport protocol of the listener: TCP or UDP.
    pub protocol: u64,
    /// Address the listener is requested on.
    pub bind_address: String,
    /// Port the listener is requested on; zero asks for an ephemeral port.
    pub bind_port: u16,
    /// Address of the client-side target the connections are bridged to.
    pub target_address: String,
    /// Port of the client-side target.
    pub target_port: u16,
}

impl ReverseForwardRequest {
    /// Encodes the payload.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        append_var_int(&mut out, self.protocol);
        append_ssh_bytes(&mut out, self.bind_address.as_bytes());
        write_port(&mut out, self.bind_port);
        append_ssh_bytes(&mut out, self.target_address.as_bytes());
        write_port(&mut out, self.target_port);
        out
    }

    /// Decodes the payload.
    pub fn decode(payload: &[u8]) -> Result<Self, Ssh3ForwardingWireError> {
        let mut reader = Cursor::new(payload);
        let protocol = read_var_int(&mut reader).map_err(|_| Ssh3ForwardingWireError::Truncated)?;
        if protocol != FORWARDING_PROTOCOL_TCP && protocol != FORWARDING_PROTOCOL_UDP {
            return Err(Ssh3ForwardingWireError::UnsupportedProtocol(protocol));
        }
        let bind_address = read_string(&mut reader)?;
        let bind_port = read_port(&mut reader)?;
        let target_address = read_string(&mut reader)?;
        let target_port = read_port(&mut reader)?;
        Ok(Self {
            protocol,
            bind_address,
            bind_port,
            target_address,
            target_port,
        })
    }
}

/// The payload the server sends back as channel data on a
/// `reverse-forward` control channel.
///
/// An empty error means the bind succeeded; `bound_port` is the port that was
/// actually bound, which differs from the requested one when the client asked
/// for port zero. Otherwise the error carries a human-readable reason (port
/// busy, permission denied, ...).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReverseForwardReply {
    /// The port the listener was bound to.
    pub bound_port: u16,
    /// The reason the bind was refused; empty when it succeeded.
    pub error: String,
}

impl ReverseForwardReply {
    /// Encodes the payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_port(&mut out, self.bound_port);
        append_ssh_bytes(&mut out, self.error.as_bytes());
        out
    }

    /// Decodes the payload.
    #[cfg(test)]
    pub fn decode(payload: &[u8]) -> Result<Self, Ssh3ForwardingWireError> {
        let mut reader = Cursor::new(payload);
        let bound_port = read_port(&mut reader)?;
        let error = read_string(&mut reader)?;
        Ok(Self { bound_port, error })
    }
}

/// The payload a client sends as channel data on a `dynamic-forward` control
/// channel to announce that it wants the server to serve dynamic forwarding.
///
/// The bind address and port describe the SOCKS listener on the *client*
/// side: the server never binds anything for a dynamic forward, it only
/// echoes the values back so the client can confirm the request was
/// accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DynamicForwardRequest {
    /// Address of the SOCKS listener on the client side.
    pub bind_address: String,
    /// Port of the SOCKS listener on the client side.
    pub bind_port: u16,
}

impl DynamicForwardRequest {
    /// Encodes the payload.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_dynamic_forward_header(&mut out, DYNAMIC_FORWARD_KIND_REQUEST);
        append_ssh_bytes(&mut out, self.bind_address.as_bytes());
        write_port(&mut out, self.bind_port);
        out
    }

    /// Decodes the payload.
    pub fn decode(payload: &[u8]) -> Result<Self, Ssh3ForwardingWireError> {
        let mut reader = Cursor::new(payload);
        read_dynamic_forward_header(&mut reader, DYNAMIC_FORWARD_KIND_REQUEST)?;
        let bind_address = read_string(&mut reader)?;
        let bind_port = read_port(&mut reader)?;
        Ok(Self {
            bind_address,
            bind_port,
        })
    }
}

/// The payload the server sends back as channel data on a
/// `dynamic-forward` control channel.
///
/// An empty error means the request was accepted; the bound port echoes the
/// client-side bind port the server was asked to serve.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DynamicForwardReply {
    /// The client-side bind port the server was asked to serve.
    pub bound_port: u16,
    /// The reason the request was refused; empty when it was accepted.
    pub error: String,
}

impl DynamicForwardReply {
    /// Encodes the payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_dynamic_forward_header(&mut out, DYNAMIC_FORWARD_KIND_REQUEST_REPLY);
        write_port(&mut out, self.bound_port);
        append_ssh_bytes(&mut out, self.error.as_bytes());
        out
    }

    /// Decodes the payload.
    #[cfg(test)]
    pub fn decode(payload: &[u8]) -> Result<Self, Ssh3ForwardingWireError> {
        let mut reader = Cursor::new(payload);
        read_dynamic_forward_header(&mut reader, DYNAMIC_FORWARD_KIND_REQUEST_REPLY)?;
        let bound_port = read_port(&mut reader)?;
        let error = read_string(&mut reader)?;
        Ok(Self { bound_port, error })
    }
}

/// The payload a client sends as the first channel data on a
/// `dynamic-forward-tcp` channel: the address the server must dial on behalf
/// of the SOCKS client.
///
/// Unlike the reverse forwarding targets, the address may be a host name: the
/// server resolves it, as a SOCKS client may only know a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DynamicForwardTarget {
    /// The address the server must dial.
    pub address: String,
    /// The port the server must dial.
    pub port: u16,
}

impl DynamicForwardTarget {
    /// Encodes the payload.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_dynamic_forward_header(&mut out, DYNAMIC_FORWARD_KIND_TARGET);
        append_ssh_bytes(&mut out, self.address.as_bytes());
        write_port(&mut out, self.port);
        out
    }

    /// Decodes the payload.
    ///
    /// An empty address or a null port is refused: there is nothing to dial.
    pub fn decode(payload: &[u8]) -> Result<Self, Ssh3ForwardingWireError> {
        let mut reader = Cursor::new(payload);
        read_dynamic_forward_header(&mut reader, DYNAMIC_FORWARD_KIND_TARGET)?;
        let address = read_string(&mut reader)?;
        let port = read_port(&mut reader)?;
        if address.is_empty() {
            return Err(Ssh3ForwardingWireError::EmptyTargetAddress);
        }
        if port == 0 {
            return Err(Ssh3ForwardingWireError::NullTargetPort);
        }
        Ok(Self { address, port })
    }
}

/// The payload the server sends as channel data on a `dynamic-forward-tcp`
/// channel, right after the target.
///
/// An empty error means the connection to the target was established and the
/// channel is now a live bridge; otherwise the error carries the reason the
/// dial failed (unreachable host, connection refused, ...) so the client can
/// report it to the SOCKS client.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DynamicForwardTargetReply {
    /// The reason the dial failed; empty when it succeeded.
    pub error: String,
}

impl DynamicForwardTargetReply {
    /// Encodes the payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_dynamic_forward_header(&mut out, DYNAMIC_FORWARD_KIND_TARGET_REPLY);
        append_ssh_bytes(&mut out, self.error.as_bytes());
        out
    }

    /// Decodes the payload.
    #[cfg(test)]
    pub fn decode(payload: &[u8]) -> Result<Self, Ssh3ForwardingWireError> {
        let mut reader = Cursor::new(payload);
        read_dynamic_forward_header(&mut reader, DYNAMIC_FORWARD_KIND_TARGET_REPLY)?;
        let error = read_string(&mut reader)?;
        Ok(Self { error })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden vectors of the reference implementation, taken from
    /// `ssh3-proto/tests/data/wire_vectors.txt`.
    const REVERSE_FORWARD_REQUEST_TCP: &str =
        "01093132372e302e302e311f900a3139322e302e322e31300050";
    const REVERSE_FORWARD_REQUEST_UDP_WILDCARD: &str = "00012a00350b323030313a6462383a3a310035";
    const REVERSE_FORWARD_REPLY_OK: &str = "1f9000";
    const REVERSE_FORWARD_REPLY_ERROR: &str =
        "00001c62696e643a206164647265737320616c726561647920696e20757365";
    const DYNAMIC_FORWARD_REQUEST: &str = "0101093132372e302e302e310438";
    const DYNAMIC_FORWARD_REQUEST_WILDCARD: &str = "0101012a0000";
    const DYNAMIC_FORWARD_REPLY_OK: &str = "0102043800";
    const DYNAMIC_FORWARD_REPLY_ERROR: &str =
        "010200002064796e616d696320666f7277617264696e67206e6f7420726571756573746564";
    const DYNAMIC_FORWARD_TARGET_HOSTNAME: &str = "01030b6578616d706c652e636f6d01bb";
    const DYNAMIC_FORWARD_TARGET_IPV4: &str = "01030a3139322e302e322e31300050";
    const DYNAMIC_FORWARD_TARGET_REPLY_OK: &str = "010400";
    const DYNAMIC_FORWARD_TARGET_REPLY_ERROR: &str = "0104336469616c20746370203139322e302e322e31303a38303a20636f6e6e6563743a20636f6e6e656374696f6e2072656675736564";

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0, "the vector is not a byte string");
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn reverse_forward_request_matches_the_golden_vectors() {
        let request = ReverseForwardRequest {
            protocol: FORWARDING_PROTOCOL_TCP,
            bind_address: "127.0.0.1".to_string(),
            bind_port: 8080,
            target_address: "192.0.2.10".to_string(),
            target_port: 80,
        };
        assert_eq!(
            encode_hex(&request.encode()),
            REVERSE_FORWARD_REQUEST_TCP.to_string()
        );
        assert_eq!(
            ReverseForwardRequest::decode(&decode_hex(REVERSE_FORWARD_REQUEST_TCP)).unwrap(),
            request
        );

        let request = ReverseForwardRequest {
            protocol: FORWARDING_PROTOCOL_UDP,
            bind_address: "*".to_string(),
            bind_port: 53,
            target_address: "2001:db8::1".to_string(),
            target_port: 53,
        };
        assert_eq!(
            encode_hex(&request.encode()),
            REVERSE_FORWARD_REQUEST_UDP_WILDCARD.to_string()
        );
        assert_eq!(
            ReverseForwardRequest::decode(&decode_hex(REVERSE_FORWARD_REQUEST_UDP_WILDCARD))
                .unwrap(),
            request
        );
    }

    #[test]
    fn reverse_forward_reply_matches_the_golden_vectors() {
        let reply = ReverseForwardReply {
            bound_port: 8080,
            error: String::new(),
        };
        assert_eq!(
            encode_hex(&reply.encode()),
            REVERSE_FORWARD_REPLY_OK.to_string()
        );
        assert_eq!(
            ReverseForwardReply::decode(&decode_hex(REVERSE_FORWARD_REPLY_OK)).unwrap(),
            reply
        );

        let reply = ReverseForwardReply {
            bound_port: 0,
            error: "bind: address already in use".to_string(),
        };
        assert_eq!(
            encode_hex(&reply.encode()),
            REVERSE_FORWARD_REPLY_ERROR.to_string()
        );
        assert_eq!(
            ReverseForwardReply::decode(&decode_hex(REVERSE_FORWARD_REPLY_ERROR)).unwrap(),
            reply
        );
    }

    #[test]
    fn dynamic_forward_payloads_match_the_golden_vectors() {
        let request = DynamicForwardRequest {
            bind_address: "127.0.0.1".to_string(),
            bind_port: 1080,
        };
        assert_eq!(
            encode_hex(&request.encode()),
            DYNAMIC_FORWARD_REQUEST.to_string()
        );
        assert_eq!(
            DynamicForwardRequest::decode(&decode_hex(DYNAMIC_FORWARD_REQUEST)).unwrap(),
            request
        );

        let request = DynamicForwardRequest {
            bind_address: "*".to_string(),
            bind_port: 0,
        };
        assert_eq!(
            encode_hex(&request.encode()),
            DYNAMIC_FORWARD_REQUEST_WILDCARD.to_string()
        );

        let reply = DynamicForwardReply {
            bound_port: 1080,
            error: String::new(),
        };
        assert_eq!(
            encode_hex(&reply.encode()),
            DYNAMIC_FORWARD_REPLY_OK.to_string()
        );
        assert_eq!(
            DynamicForwardReply::decode(&decode_hex(DYNAMIC_FORWARD_REPLY_OK)).unwrap(),
            reply
        );

        let reply = DynamicForwardReply {
            bound_port: 0,
            error: "dynamic forwarding not requested".to_string(),
        };
        assert_eq!(
            encode_hex(&reply.encode()),
            DYNAMIC_FORWARD_REPLY_ERROR.to_string()
        );

        let target = DynamicForwardTarget {
            address: "example.com".to_string(),
            port: 443,
        };
        assert_eq!(
            encode_hex(&target.encode()),
            DYNAMIC_FORWARD_TARGET_HOSTNAME.to_string()
        );
        assert_eq!(
            DynamicForwardTarget::decode(&decode_hex(DYNAMIC_FORWARD_TARGET_HOSTNAME)).unwrap(),
            target
        );

        let target = DynamicForwardTarget {
            address: "192.0.2.10".to_string(),
            port: 80,
        };
        assert_eq!(
            encode_hex(&target.encode()),
            DYNAMIC_FORWARD_TARGET_IPV4.to_string()
        );

        let reply = DynamicForwardTargetReply {
            error: String::new(),
        };
        assert_eq!(
            encode_hex(&reply.encode()),
            DYNAMIC_FORWARD_TARGET_REPLY_OK.to_string()
        );

        let reply = DynamicForwardTargetReply {
            error: "dial tcp 192.0.2.10:80: connect: connection refused".to_string(),
        };
        assert_eq!(
            encode_hex(&reply.encode()),
            DYNAMIC_FORWARD_TARGET_REPLY_ERROR.to_string()
        );
        assert_eq!(
            DynamicForwardTargetReply::decode(&decode_hex(DYNAMIC_FORWARD_TARGET_REPLY_ERROR))
                .unwrap(),
            reply
        );
    }

    #[test]
    fn malformed_payloads_are_refused() {
        assert_eq!(
            ReverseForwardRequest::decode(&[2]),
            Err(Ssh3ForwardingWireError::UnsupportedProtocol(2))
        );
        assert_eq!(
            ReverseForwardRequest::decode(&[FORWARDING_PROTOCOL_TCP as u8]),
            Err(Ssh3ForwardingWireError::Truncated)
        );
        assert_eq!(
            DynamicForwardTarget::decode(&[2, DYNAMIC_FORWARD_KIND_TARGET as u8]),
            Err(Ssh3ForwardingWireError::UnsupportedVersion(2))
        );
        assert_eq!(
            DynamicForwardTarget::decode(&decode_hex(DYNAMIC_FORWARD_TARGET_HOSTNAME)[..2]),
            Err(Ssh3ForwardingWireError::Truncated)
        );
        assert_eq!(
            DynamicForwardRequest::decode(&decode_hex(DYNAMIC_FORWARD_TARGET_HOSTNAME)),
            Err(Ssh3ForwardingWireError::UnexpectedKind {
                expected: DYNAMIC_FORWARD_KIND_REQUEST,
                found: DYNAMIC_FORWARD_KIND_TARGET,
            })
        );
    }
}
