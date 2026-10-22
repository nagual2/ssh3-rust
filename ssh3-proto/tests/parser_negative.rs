//! Negative tests of the parsers of the SSH3 wire format.
//!
//! Every test feeds the parser an input a hostile or broken peer could send
//! and checks that the parser refuses it with an error instead of panicking,
//! allocating an unbounded buffer or accepting a value the protocol does not
//! define.
//!
//! The expectations follow the reference implementation (`nagual2/ssh3-go`,
//! package `message/` and `util/wire.go`).

use std::io::{self, Cursor};

use ssh3_proto::{
    MAX_SSH_STRING_LEN, MAX_VARINT, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_REQUEST,
    Ssh3Error, Ssh3Message, append_ssh_bytes, append_var_int, read_bool, read_ssh_bytes,
    read_var_int,
};

/// Parses a message and returns the error it reported.
fn parse_error(bytes: &[u8]) -> Ssh3Error {
    match Ssh3Message::parse(&mut Cursor::new(bytes)) {
        Ok(message) => panic!("the input must be refused, got {message:?}"),
        Err(err) => err,
    }
}

/// Builds the prefix of a channel request: the type, the request type name
/// and the `want_reply` flag.
fn channel_request_prefix(request_type: &[u8], want_reply: u8) -> Vec<u8> {
    let mut out = Vec::new();
    append_var_int(&mut out, SSH_MSG_CHANNEL_REQUEST);
    append_ssh_bytes(&mut out, request_type);
    out.push(want_reply);
    out
}

/// Builds the payload of a `forward-port` request.
fn forwarding_payload(protocol: u64, family: u64, address: &[u8], port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    append_var_int(&mut out, protocol);
    append_var_int(&mut out, family);
    out.extend_from_slice(address);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

fn is_io_error(err: &Ssh3Error) -> bool {
    matches!(err, Ssh3Error::Io(io_err) if io_err.kind() == io::ErrorKind::UnexpectedEof)
}

// --- truncated input -------------------------------------------------------

#[test]
fn an_empty_input_is_refused() {
    assert!(is_io_error(&parse_error(&[])));
}

#[test]
fn a_truncated_varint_is_refused() {
    // A two byte varint announced, one byte delivered.
    assert!(is_io_error(&parse_error(&[0x40])));
    // A four byte varint announced, three bytes delivered.
    assert!(is_io_error(&parse_error(&[0x80, 0x00, 0x00])));
    // An eight byte varint announced, seven bytes delivered.
    assert!(is_io_error(&parse_error(&[
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])));
}

#[test]
fn a_channel_request_without_a_request_type_is_refused() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, SSH_MSG_CHANNEL_REQUEST);
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_channel_request_without_the_want_reply_flag_is_refused() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, SSH_MSG_CHANNEL_REQUEST);
    append_ssh_bytes(&mut bytes, b"shell");
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_exec_request_is_refused() {
    let mut bytes = channel_request_prefix(b"exec", 0);
    // The command is announced as five bytes, three are delivered.
    append_ssh_bytes(&mut bytes, b"abc");
    bytes.truncate(bytes.len() - 2);
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_pty_request_is_refused() {
    let mut bytes = channel_request_prefix(b"pty-req", 0);
    append_ssh_bytes(&mut bytes, b"vt100");
    // The four sizes are missing.
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_x11_request_is_refused() {
    let mut bytes = channel_request_prefix(b"x11-req", 0);
    bytes.push(0);
    append_ssh_bytes(&mut bytes, b"MIT-MAGIC-COOKIE-1");
    // The cookie and the screen number are missing.
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_exit_signal_request_is_refused() {
    let mut bytes = channel_request_prefix(b"exit-signal", 0);
    append_ssh_bytes(&mut bytes, b"TERM");
    bytes.push(0);
    // The error message and the language tag are missing.
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_window_change_request_is_refused() {
    let mut bytes = channel_request_prefix(b"window-change", 0);
    append_var_int(&mut bytes, 80);
    append_var_int(&mut bytes, 24);
    // The pixel sizes are missing.
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_forward_port_request_is_refused() {
    let mut bytes = channel_request_prefix(b"forward-port", 0);
    bytes.extend_from_slice(&forwarding_payload(1, 4, &[192, 0, 2, 10], 443));
    // The port is missing.
    bytes.truncate(bytes.len() - 1);
    assert!(is_io_error(&parse_error(&bytes)));

    let mut bytes = channel_request_prefix(b"forward-port", 0);
    bytes.extend_from_slice(&forwarding_payload(1, 4, &[192, 0, 2, 10], 443));
    // Two address octets are missing.
    bytes.truncate(bytes.len() - 3);
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_channel_open_confirmation_is_refused() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    // The maximum packet size is missing.
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_channel_open_failure_is_refused() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, SSH_MSG_CHANNEL_OPEN_FAILURE);
    append_var_int(&mut bytes, 2);
    append_ssh_bytes(&mut bytes, b"connection refused");
    // The language tag is missing.
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_data_message_is_refused() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, SSH_MSG_CHANNEL_DATA);
    append_ssh_bytes(&mut bytes, b"hello");
    bytes.truncate(bytes.len() - 2);
    assert!(is_io_error(&parse_error(&bytes)));
}

#[test]
fn a_truncated_extended_data_message_is_refused() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, SSH_MSG_CHANNEL_EXTENDED_DATA);
    append_var_int(&mut bytes, 1);
    // The payload is missing.
    assert!(is_io_error(&parse_error(&bytes)));
}

// --- oversized lengths -----------------------------------------------------

#[test]
fn an_oversized_data_payload_is_refused_before_the_allocation() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, SSH_MSG_CHANNEL_DATA);
    append_var_int(&mut bytes, MAX_SSH_STRING_LEN + 1);
    match parse_error(&bytes) {
        Ssh3Error::StringTooLong { length, limit } => {
            assert_eq!(length, MAX_SSH_STRING_LEN + 1);
            assert_eq!(limit, MAX_SSH_STRING_LEN);
        }
        other => panic!("expected the length to be refused, got {other:?}"),
    }
}

#[test]
fn an_oversized_request_type_name_is_refused_before_the_allocation() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, SSH_MSG_CHANNEL_REQUEST);
    append_var_int(&mut bytes, MAX_SSH_STRING_LEN + 1);
    match parse_error(&bytes) {
        Ssh3Error::StringTooLong { length, limit } => {
            assert_eq!(length, MAX_SSH_STRING_LEN + 1);
            assert_eq!(limit, MAX_SSH_STRING_LEN);
        }
        other => panic!("expected the length to be refused, got {other:?}"),
    }
}

#[test]
fn an_oversized_command_is_refused_before_the_allocation() {
    let mut bytes = channel_request_prefix(b"exec", 0);
    append_var_int(&mut bytes, MAX_SSH_STRING_LEN + 1);
    match parse_error(&bytes) {
        Ssh3Error::StringTooLong { length, limit } => {
            assert_eq!(length, MAX_SSH_STRING_LEN + 1);
            assert_eq!(limit, MAX_SSH_STRING_LEN);
        }
        other => panic!("expected the length to be refused, got {other:?}"),
    }
}

#[test]
fn the_largest_varint_is_refused_as_a_string_length() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, SSH_MSG_CHANNEL_DATA);
    append_var_int(&mut bytes, MAX_VARINT);
    match parse_error(&bytes) {
        Ssh3Error::StringTooLong { length, limit } => {
            assert_eq!(length, MAX_VARINT);
            assert_eq!(limit, MAX_SSH_STRING_LEN);
        }
        other => panic!("expected the length to be refused, got {other:?}"),
    }
}

// --- unknown identifiers ---------------------------------------------------

#[test]
fn an_unknown_message_type_is_refused() {
    for kind in [0, 7, 42, 89, 101, u64::from(u8::MAX)] {
        let mut bytes = Vec::new();
        append_var_int(&mut bytes, kind);
        match parse_error(&bytes) {
            Ssh3Error::UnknownMessageType(reported) => assert_eq!(reported, kind),
            other => panic!("expected the type to be refused, got {other:?}"),
        }
    }
}

#[test]
fn an_unknown_channel_request_type_is_refused() {
    let bytes = channel_request_prefix(b"no-such-request", 0);
    match parse_error(&bytes) {
        Ssh3Error::UnknownRequestType(reported) => assert_eq!(reported, b"no-such-request"),
        other => panic!("expected the request type to be refused, got {other:?}"),
    }
}

#[test]
fn a_request_type_name_that_is_not_utf8_is_refused() {
    let bytes = channel_request_prefix(&[0xff, 0xfe], 0);
    match parse_error(&bytes) {
        Ssh3Error::UnknownRequestType(reported) => assert_eq!(reported, vec![0xff, 0xfe]),
        other => panic!("expected the request type to be refused, got {other:?}"),
    }
}

// --- invalid values of the forwarding request ------------------------------

#[test]
fn an_invalid_forwarding_protocol_is_refused() {
    let mut bytes = channel_request_prefix(b"forward-port", 0);
    bytes.extend_from_slice(&forwarding_payload(2, 4, &[192, 0, 2, 10], 443));
    match parse_error(&bytes) {
        Ssh3Error::InvalidForwardingProtocol(reported) => assert_eq!(reported, 2),
        other => panic!("expected the protocol to be refused, got {other:?}"),
    }
}

#[test]
fn an_invalid_forwarding_protocol_in_the_family_first_order_is_refused() {
    let mut bytes = channel_request_prefix(b"forward-port", 0);
    // The address family comes first, the protocol is invalid.
    bytes.extend_from_slice(&forwarding_payload(4, 7, &[192, 0, 2, 10], 443));
    match parse_error(&bytes) {
        Ssh3Error::InvalidForwardingProtocol(reported) => assert_eq!(reported, 7),
        other => panic!("expected the protocol to be refused, got {other:?}"),
    }
}

#[test]
fn an_invalid_address_family_is_refused() {
    let mut bytes = channel_request_prefix(b"forward-port", 0);
    bytes.extend_from_slice(&forwarding_payload(1, 5, &[192, 0, 2, 10], 443));
    match parse_error(&bytes) {
        Ssh3Error::InvalidAddressFamily(reported) => assert_eq!(reported, 5),
        other => panic!("expected the address family to be refused, got {other:?}"),
    }
}

#[test]
fn a_forwarding_request_with_an_unknown_first_field_is_refused() {
    let mut bytes = channel_request_prefix(b"forward-port", 0);
    bytes.extend_from_slice(&forwarding_payload(9, 4, &[192, 0, 2, 10], 443));
    match parse_error(&bytes) {
        Ssh3Error::InvalidForwardingProtocol(reported) => assert_eq!(reported, 9),
        other => panic!("expected the protocol to be refused, got {other:?}"),
    }
}

// --- boundaries of the primitives ------------------------------------------

#[test]
fn the_largest_varint_is_decoded() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, MAX_VARINT);
    let value = read_var_int(&mut Cursor::new(bytes)).unwrap();
    assert_eq!(value, MAX_VARINT);
}

#[test]
fn a_varint_of_every_width_is_decoded() {
    for value in [
        0,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        MAX_VARINT,
    ] {
        let mut bytes = Vec::new();
        append_var_int(&mut bytes, value);
        let decoded = read_var_int(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(decoded, value, "value {value}");
    }
}

#[test]
fn a_string_of_the_largest_allowed_length_is_refused_when_it_is_truncated() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, MAX_SSH_STRING_LEN);
    match read_ssh_bytes(&mut Cursor::new(bytes)) {
        Err(Ssh3Error::Io(err)) => assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof),
        other => panic!("expected the missing payload to be reported, got {other:?}"),
    }
}

#[test]
fn a_string_longer_than_the_limit_is_refused() {
    let mut bytes = Vec::new();
    append_var_int(&mut bytes, MAX_SSH_STRING_LEN + 1);
    match read_ssh_bytes(&mut Cursor::new(bytes)) {
        Err(Ssh3Error::StringTooLong { length, limit }) => {
            assert_eq!(length, MAX_SSH_STRING_LEN + 1);
            assert_eq!(limit, MAX_SSH_STRING_LEN);
        }
        other => panic!("expected the length to be refused, got {other:?}"),
    }
}

#[test]
fn a_boolean_that_is_not_zero_is_true() {
    // The reference implementation decodes the byte into a number and
    // compares it against zero, so every byte other than `0` is true.
    for byte in [0x01, 0x02, 0x7f, 0x80, 0xff] {
        let value = read_bool(&mut Cursor::new([byte])).unwrap();
        assert!(value, "byte {byte:#04x} must be true");
    }
    let value = read_bool(&mut Cursor::new([0x00])).unwrap();
    assert!(!value, "the byte 0x00 must be false");
}

#[test]
fn a_boolean_without_a_byte_is_refused() {
    assert!(is_io_error(&read_bool(&mut Cursor::new([])).unwrap_err()));
}
