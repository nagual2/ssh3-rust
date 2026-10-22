//! Deterministic replay of the fuzz targets of the `fuzz/` crate.
//!
//! The fuzz targets of the crate need the nightly toolchain and are run out
//! of band. This file replays the same code paths with pseudo-random inputs
//! and a fixed seed, so the continuous integration of the project checks the
//! invariants of the parsers on every commit.

use std::io::Cursor;

use ssh3_proto::{
    MAX_SSH_STRING_LEN, MAX_VARINT, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_REQUEST,
    Ssh3ChannelHeader, Ssh3Message, append_ssh_bytes, append_var_int, read_bool, read_ssh_bytes,
    read_var_int,
};

/// Number of pseudo-random inputs every target replays.
const ROUNDS: usize = 2_000;

/// The largest input the replay feeds to the parsers, in bytes.
const MAX_INPUT_LEN: usize = 512;

/// A deterministic generator of pseudo-random bytes.
///
/// The generator is a xorshift64: the same seed always produces the same
/// bytes, so a failure can be reproduced exactly.
struct PseudoRandom {
    state: u64,
}

impl PseudoRandom {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut state = self.state;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.state = state;
        state
    }

    fn next_byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    fn next_len(&mut self) -> usize {
        (self.next_u64() % (MAX_INPUT_LEN as u64 + 1)) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_byte()).collect()
    }
}

/// The message types the parser of the implementation knows.
const KNOWN_MESSAGE_TYPES: [u64; 5] = [
    SSH_MSG_CHANNEL_REQUEST,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
    SSH_MSG_CHANNEL_OPEN_FAILURE,
    SSH_MSG_CHANNEL_DATA,
    SSH_MSG_CHANNEL_EXTENDED_DATA,
];

/// The request types the parser of the implementation knows.
const KNOWN_REQUEST_TYPES: [&[u8]; 10] = [
    b"pty-req",
    b"x11-req",
    b"shell",
    b"exec",
    b"subsystem",
    b"window-change",
    b"signal",
    b"exit-status",
    b"exit-signal",
    b"forward-port",
];

#[test]
fn the_varint_parser_never_panics_on_random_input() {
    let mut random = PseudoRandom::new(0x5eed_0000_0000_0001);
    for _ in 0..ROUNDS {
        let len = random.next_len();
        let input = random.bytes(len);
        if let Ok(value) = read_var_int(&mut Cursor::new(&input)) {
            assert!(
                value <= MAX_VARINT,
                "the value {value} does not fit into 62 bits"
            );
        }
    }
}

#[test]
fn the_string_parser_never_panics_on_random_input() {
    let mut random = PseudoRandom::new(0x5eed_0000_0000_0002);
    for _ in 0..ROUNDS {
        let len = random.next_len();
        let input = random.bytes(len);
        if let Ok(payload) = read_ssh_bytes(&mut Cursor::new(&input)) {
            assert!(payload.len() as u64 <= MAX_SSH_STRING_LEN);
        }
    }
}

#[test]
fn the_boolean_parser_never_panics_on_random_input() {
    let mut random = PseudoRandom::new(0x5eed_0000_0000_0003);
    for _ in 0..ROUNDS {
        let len = random.next_len();
        let input = random.bytes(len);
        if let Ok(value) = read_bool(&mut Cursor::new(&input)) {
            // Every byte other than zero is true, like in the reference
            // implementation.
            assert_eq!(value, input[0] != 0);
        }
    }
}

#[test]
fn the_message_parser_never_panics_on_random_input() {
    let mut random = PseudoRandom::new(0x5eed_0000_0000_0004);
    for _ in 0..ROUNDS {
        let len = random.next_len();
        let input = random.bytes(len);
        if let Ok(message) = Ssh3Message::parse(&mut Cursor::new(&input)) {
            let encoded = message.to_vec();
            assert_eq!(encoded.len(), message.encoded_len());
        }
    }
}

#[test]
fn the_message_parser_never_panics_on_random_payloads_of_known_types() {
    let mut random = PseudoRandom::new(0x5eed_0000_0000_0005);
    for _ in 0..ROUNDS {
        let mut input = Vec::new();
        append_var_int(
            &mut input,
            KNOWN_MESSAGE_TYPES[random.next_u64() as usize % KNOWN_MESSAGE_TYPES.len()],
        );
        let len = random.next_len();
        input.extend_from_slice(&random.bytes(len));
        if let Ok(message) = Ssh3Message::parse(&mut Cursor::new(&input)) {
            assert_eq!(message.to_vec().len(), message.encoded_len());
        }
    }
}

#[test]
fn the_request_parser_never_panics_on_random_payloads_of_known_types() {
    let mut random = PseudoRandom::new(0x5eed_0000_0000_0006);
    for _ in 0..ROUNDS {
        let mut input = Vec::new();
        append_var_int(&mut input, SSH_MSG_CHANNEL_REQUEST);
        append_ssh_bytes(
            &mut input,
            KNOWN_REQUEST_TYPES[random.next_u64() as usize % KNOWN_REQUEST_TYPES.len()],
        );
        input.push(random.next_byte());
        let len = random.next_len();
        input.extend_from_slice(&random.bytes(len));

        let Ok(Ssh3Message::ChannelRequest(request)) = Ssh3Message::parse(&mut Cursor::new(&input))
        else {
            continue;
        };

        // A request that is read is encoded back into itself.
        let message = Ssh3Message::ChannelRequest(request.clone());
        let encoded = message.to_vec();
        assert_eq!(encoded.len(), message.encoded_len());
        match Ssh3Message::parse(&mut Cursor::new(&encoded)) {
            Ok(Ssh3Message::ChannelRequest(decoded)) => assert_eq!(decoded, request),
            other => panic!("the round trip returned another message: {other:?}"),
        }
    }
}

#[test]
fn the_channel_header_parser_never_panics_on_random_input() {
    let mut random = PseudoRandom::new(0x5eed_0000_0000_0007);
    for _ in 0..ROUNDS {
        let mut input = Vec::new();
        append_var_int(&mut input, ssh3_proto::SSH_FRAME_TYPE);
        let len = random.next_len();
        input.extend_from_slice(&random.bytes(len));
        let mut reader = Cursor::new(input);
        let frame_type = read_var_int(&mut reader).unwrap();
        assert_eq!(frame_type, ssh3_proto::SSH_FRAME_TYPE);
        let _ = Ssh3ChannelHeader::parse_payload(&mut reader);
    }
}
