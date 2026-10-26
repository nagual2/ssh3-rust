//! Golden vectors of the SSH3 wire format, shared with the Go implementation.
//!
//! The vectors live in `tests/data/wire_vectors.txt` and use the format of
//! the dumper of the reference implementation (`nagual2/ssh3-go`,
//! `wire_vectors_test.go`):
//!
//! ```text
//! VECTOR <name> = <hex>
//! ```
//!
//! The file is the verbatim output of
//!
//! ```text
//! go test -run TestDumpWireVectors -v ./
//! ```
//!
//! run in the root package of the Go implementation, so both implementations
//! read the same bytes. Every vector the Rust implementation covers is
//! re-encoded here and compared byte for byte, and the vectors the Go
//! implementation covers alone are listed explicitly, so a change of the
//! reference dumper fails the test instead of silently drifting.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use ssh3_proto::{
    SSH_EXTENDED_DATA_NONE, SSH_EXTENDED_DATA_STDERR, Ssh3ChannelHeader, Ssh3ChannelRequest,
    Ssh3ChannelRequestMessage, Ssh3DataOrExtendedDataMessage, Ssh3ExecRequest, Ssh3Message,
    append_ssh_bytes, append_var_int, build_forwarding_additional_bytes,
};

/// Vectors of the reference implementation that the Rust implementation does
/// not cover.
///
/// The payloads of the reverse (`-R`) and dynamic (`-D`) forwarding are Go
/// extensions carried as channel data; the Rust implementation has no codec
/// for them, so it cannot reproduce their bytes. They are kept in the shared
/// file, because the file must stay the verbatim output of the Go dumper.
const GO_ONLY_VECTORS: &[&str] = &[
    "reverse_forward_request_tcp",
    "reverse_forward_request_udp_wildcard",
    "reverse_forward_reply_ok",
    "reverse_forward_reply_error",
    "dynamic_forward_request",
    "dynamic_forward_request_wildcard",
    "dynamic_forward_reply_ok",
    "dynamic_forward_reply_error",
    "dynamic_forward_target_hostname",
    "dynamic_forward_target_ipv4",
    "dynamic_forward_target_reply_ok",
    "dynamic_forward_target_reply_error",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/wire_vectors.txt")
}

/// Reads the shared vector file and decodes the hexadecimal payloads.
fn load_vectors() -> BTreeMap<String, Vec<u8>> {
    let raw = std::fs::read_to_string(vectors_path())
        .unwrap_or_else(|err| panic!("cannot read the vector file: {err}"));
    let mut vectors = BTreeMap::new();
    for (number, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let body = line
            .strip_prefix("VECTOR ")
            .unwrap_or_else(|| panic!("line {} is not a vector: {line}", number + 1));
        let (name, hex) = body
            .split_once(" = ")
            .unwrap_or_else(|| panic!("line {} is not a vector: {line}", number + 1));
        let bytes = decode_hex(hex);
        assert!(
            vectors.insert(name.to_string(), bytes).is_none(),
            "duplicate vector {name}"
        );
    }
    assert!(!vectors.is_empty(), "the vector file is empty");
    vectors
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "odd length hexadecimal payload");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("invalid hexadecimal"))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The 140 byte payload of the `sshstring_140` vector: the letters of the
/// alphabet, repeated.
fn strings_140() -> Vec<u8> {
    (0..140).map(|index| b'a' + (index % 26) as u8).collect()
}

fn header(stream_id: u64, channel_type: &str, max_packet_size: u64) -> Ssh3ChannelHeader {
    Ssh3ChannelHeader {
        conversation_stream_id: stream_id,
        channel_type: channel_type.as_bytes().to_vec(),
        max_packet_size,
    }
}

fn ip_v4(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(octets))
}

fn ip_v6(octets: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(octets))
}

/// Checks that the Rust encoder produces the bytes of the reference vector.
#[test]
fn rust_encoders_match_the_reference_vectors() {
    let vectors = load_vectors();

    let mut varints: Vec<(u64, &str)> = vec![
        (0, "varint_0"),
        (1, "varint_1"),
        (63, "varint_63"),
        (64, "varint_64"),
        (16_383, "varint_16383"),
        (16_384, "varint_16384"),
        (1_073_741_823, "varint_1073741823"),
        (1_073_741_824, "varint_1073741824"),
        (4_611_686_018_427_387_903, "varint_4611686018427387903"),
    ];
    varints.sort_by_key(|(_, name)| (*name).to_string());
    for (value, name) in varints {
        let mut encoded = Vec::new();
        append_var_int(&mut encoded, value);
        assert_eq!(
            encode_hex(&encoded),
            encode_hex(
                vectors
                    .get(name)
                    .unwrap_or_else(|| panic!("missing {name}"))
            ),
            "vector {name}"
        );
    }

    let mut strings: Vec<(Vec<u8>, &str)> = vec![
        (Vec::new(), "sshstring_empty"),
        (b"direct-tcp".to_vec(), "sshstring_direct_tcp"),
        (b"exec".to_vec(), "sshstring_exec"),
        (strings_140(), "sshstring_140"),
    ];
    strings.sort_by_key(|(_, name)| (*name).to_string());
    for (payload, name) in strings {
        let mut encoded = Vec::new();
        append_ssh_bytes(&mut encoded, &payload);
        assert_eq!(
            encode_hex(&encoded),
            encode_hex(
                vectors
                    .get(name)
                    .unwrap_or_else(|| panic!("missing {name}"))
            ),
            "vector {name}"
        );
    }

    let tcp_ipv4 = header(4, "direct-tcp", 30_000).encode(Some(
        &build_forwarding_additional_bytes(ip_v4([192, 0, 2, 10]), 443),
    ));
    let tcp_ipv6 =
        header(64, "direct-tcp", 65_536).encode(Some(&build_forwarding_additional_bytes(
            ip_v6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            8443,
        )));
    let udp_ipv4 = header(8, "direct-udp", 30_000).encode(Some(
        &build_forwarding_additional_bytes(ip_v4([192, 0, 2, 10]), 53),
    ));
    let session = header(0, "session", 30_000).encode(None);
    let forwarded_tcp = header(4, "forwarded-tcp", 30_000).encode(Some(
        &build_forwarding_additional_bytes(ip_v4([127, 0, 0, 1]), 8080),
    ));
    let dynamic_control = header(4, "dynamic-forward", 30_000).encode(None);
    let dynamic_tcp = header(4, "dynamic-forward-tcp", 30_000).encode(None);

    let open_confirmation =
        Ssh3Message::ChannelOpenConfirmation(ssh3_proto::Ssh3ChannelOpenConfirmationMessage {
            max_packet_size: 30_000,
        })
        .to_vec();
    let open_failure = Ssh3Message::ChannelOpenFailure(ssh3_proto::Ssh3ChannelOpenFailureMessage {
        reason_code: 2,
        error_message_utf8: b"connection refused".to_vec(),
        language_tag: Vec::new(),
    })
    .to_vec();
    let channel_data = Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
        data_type: SSH_EXTENDED_DATA_NONE,
        data: b"hello".to_vec(),
    })
    .to_vec();
    let channel_extended_data = Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
        data_type: SSH_EXTENDED_DATA_STDERR,
        data: b"err".to_vec(),
    })
    .to_vec();
    let channel_request_exec = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
        want_reply: false,
        request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
            command: b"uptime".to_vec(),
        }),
    })
    .to_vec();

    // The compressed data frame of the channel body compression: the
    // framing (the type-192 varints of the type, the algorithm id and the
    // compressed size) is built here; the payload stays the verbatim bytes
    // of the reference deflate, so the golden file pins both.
    let go_compressed = vectors["channel_data_compressed_deflate"].clone();
    // The frame is the three varints of the header (the type, the algorithm,
    // the payload size) followed by the raw payload bytes: the size varint
    // doubles as the length prefix the SSH string reader consumes.
    let header_len = ssh3_proto::compressed_data_header(1, 0).len();
    let payload = &go_compressed[header_len..];
    let mut channel_data_compressed = ssh3_proto::compressed_data_header(1, payload.len() as u64);
    channel_data_compressed.extend_from_slice(payload);

    let mut produced: Vec<(&str, Vec<u8>)> = vec![
        ("channel_data_compressed_deflate", channel_data_compressed),
        ("channel_header_tcp_ipv4", tcp_ipv4),
        ("channel_header_tcp_ipv6", tcp_ipv6),
        ("channel_header_udp_ipv4", udp_ipv4),
        ("channel_header_session", session),
        ("channel_header_forwarded_tcp", forwarded_tcp),
        ("channel_header_dynamic_forward_control", dynamic_control),
        ("channel_header_dynamic_forward_tcp", dynamic_tcp),
        ("open_confirmation_30000", open_confirmation),
        ("open_failure", open_failure),
        ("channel_data", channel_data.clone()),
        ("channel_extended_data", channel_extended_data),
        ("channel_request_exec", channel_request_exec),
    ];
    produced.sort_by_key(|(name, _)| (*name).to_string());
    for (name, encoded) in produced {
        assert_eq!(
            encode_hex(&encoded),
            encode_hex(
                vectors
                    .get(name)
                    .unwrap_or_else(|| panic!("missing {name}"))
            ),
            "vector {name}"
        );
    }

    // The zero-copy header of a data message is the prefix of the encoded
    // message: the header of a five byte payload plus the payload itself is
    // the encoded message.
    let data_header = vectors
        .get("channel_data_header_5")
        .unwrap_or_else(|| panic!("missing channel_data_header_5"));
    assert_eq!(data_header, &channel_data[..data_header.len()]);
    assert_eq!(&channel_data[data_header.len()..], b"hello");
}

/// Checks that the Rust parser reads back the messages of the reference
/// vectors.
#[test]
fn rust_parsers_match_the_reference_vectors() {
    let vectors = load_vectors();

    let confirmation = Ssh3Message::parse(&mut vectors["open_confirmation_30000"].as_slice())
        .expect("the open confirmation must be parsed");
    assert_eq!(
        confirmation,
        Ssh3Message::ChannelOpenConfirmation(ssh3_proto::Ssh3ChannelOpenConfirmationMessage {
            max_packet_size: 30_000,
        })
    );

    let failure = Ssh3Message::parse(&mut vectors["open_failure"].as_slice())
        .expect("the open failure must be parsed");
    assert_eq!(
        failure,
        Ssh3Message::ChannelOpenFailure(ssh3_proto::Ssh3ChannelOpenFailureMessage {
            reason_code: 2,
            error_message_utf8: b"connection refused".to_vec(),
            language_tag: Vec::new(),
        })
    );

    let data = Ssh3Message::parse(&mut vectors["channel_data"].as_slice())
        .expect("the data message must be parsed");
    assert_eq!(
        data,
        Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
            data_type: SSH_EXTENDED_DATA_NONE,
            data: b"hello".to_vec(),
        })
    );

    let extended = Ssh3Message::parse(&mut vectors["channel_extended_data"].as_slice())
        .expect("the extended data message must be parsed");
    assert_eq!(
        extended,
        Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
            data_type: SSH_EXTENDED_DATA_STDERR,
            data: b"err".to_vec(),
        })
    );

    let request = Ssh3Message::parse(&mut vectors["channel_request_exec"].as_slice())
        .expect("the channel request must be parsed");
    assert_eq!(
        request,
        Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: b"uptime".to_vec(),
            }),
        })
    );

    let mut session_bytes = vectors["channel_header_session"].as_slice();
    let frame_type =
        ssh3_proto::read_var_int(&mut session_bytes).expect("the frame type must be read");
    assert_eq!(frame_type, ssh3_proto::SSH_FRAME_TYPE);
    let header = Ssh3ChannelHeader::parse_payload(&mut session_bytes)
        .expect("the channel header must be parsed");
    assert_eq!(
        header,
        Ssh3ChannelHeader {
            conversation_stream_id: 0,
            channel_type: b"session".to_vec(),
            max_packet_size: 30_000,
        }
    );
}

/// Checks that the shared vector file still holds exactly the vectors of the
/// reference dumper, so a change of the reference is noticed.
#[test]
fn the_vector_file_holds_the_vectors_of_the_reference_dumper() {
    let vectors = load_vectors();
    let names: Vec<&str> = vectors.keys().map(String::as_str).collect();

    let mut expected: Vec<&str> = vec![
        "varint_0",
        "varint_1",
        "varint_63",
        "varint_64",
        "varint_16383",
        "varint_16384",
        "varint_1073741823",
        "varint_1073741824",
        "varint_4611686018427387903",
        "sshstring_empty",
        "sshstring_direct_tcp",
        "sshstring_exec",
        "sshstring_140",
        "channel_header_tcp_ipv4",
        "channel_header_tcp_ipv6",
        "channel_header_udp_ipv4",
        "channel_header_session",
        "open_confirmation_30000",
        "open_failure",
        "channel_data",
        "channel_data_compressed_deflate",
        "channel_extended_data",
        "channel_data_header_5",
        "channel_request_exec",
        "channel_header_forwarded_tcp",
        "reverse_forward_request_tcp",
        "reverse_forward_request_udp_wildcard",
        "reverse_forward_reply_ok",
        "reverse_forward_reply_error",
        "channel_header_dynamic_forward_control",
        "channel_header_dynamic_forward_tcp",
        "dynamic_forward_request",
        "dynamic_forward_request_wildcard",
        "dynamic_forward_reply_ok",
        "dynamic_forward_reply_error",
        "dynamic_forward_target_hostname",
        "dynamic_forward_target_ipv4",
        "dynamic_forward_target_reply_ok",
        "dynamic_forward_target_reply_error",
    ];
    expected.sort_unstable();

    assert_eq!(names, expected);

    for name in GO_ONLY_VECTORS {
        assert!(
            vectors.contains_key(*name),
            "the vector {name} disappeared from the shared file"
        );
    }
}
