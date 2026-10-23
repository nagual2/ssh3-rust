//! Primitive encoding and decoding of the SSH3 wire format.
//!
//! The two building blocks are the QUIC variable-length integer and the
//! length-prefixed byte string ("SSH string"). Both are byte-compatible with
//! the reference implementation `nagual2/ssh3-go` (`util/wire.go`).

use std::fmt;
use std::io::{self, Read};

/// Smallest value that can be encoded as a variable-length integer.
pub const MIN_VARINT: u64 = 0;
/// Largest value that can be encoded as a variable-length integer (2^62 - 1).
pub const MAX_VARINT: u64 = MAX_VARINT_8;

const MAX_VARINT_1: u64 = 63;
const MAX_VARINT_2: u64 = 16_383;
const MAX_VARINT_4: u64 = 1_073_741_823;
const MAX_VARINT_8: u64 = 4_611_686_018_427_387_903;

/// Upper bound of the length of an SSH string, in bytes (16 MiB).
///
/// The length of an SSH string is a variable-length integer chosen by the
/// peer, so it can carry any value up to 2^62 - 1. Allocating a buffer of
/// that size from a handful of attacker-controlled bytes is a remote denial
/// of service, so the length is checked before the allocation happens.
///
/// The bound is the one of the reference implementation
/// (`nagual2/ssh3-go`, `util.MaxSSHStringLen`): it stays above any legitimate
/// use — the largest data chunks are bounded by the negotiated maximum
/// packet size, which is itself refused above this bound, and commands and
/// paths are bounded by `PATH_MAX` — while keeping the worst-case allocation
/// bounded.
pub const MAX_SSH_STRING_LEN: u64 = 1 << 24;

/// Result of a decoding operation on the wire format.
pub type Ssh3Result<T> = std::result::Result<T, Ssh3Error>;

/// Everything that can go wrong while decoding a wire message.
#[derive(Debug)]
pub enum Ssh3Error {
    /// The underlying reader failed.
    Io(io::Error),
    /// A string length did not fit into the address space of the process.
    InvalidLength(u64),
    /// A string length exceeded [`MAX_SSH_STRING_LEN`].
    StringTooLong {
        /// The length the peer announced.
        length: u64,
        /// The largest length that is accepted.
        limit: u64,
    },
    /// The message type is not known to this implementation.
    UnknownMessageType(u64),
    /// The channel request type is not known to this implementation.
    UnknownRequestType(Vec<u8>),
    /// The forwarding protocol was neither `0` (UDP) nor `1` (TCP).
    InvalidForwardingProtocol(u64),
    /// The address family was neither `4` (IPv4) nor `6` (IPv6).
    InvalidAddressFamily(u64),
    /// A compressed data frame did not decode: the payload is not a frame of
    /// the algorithm the frame names, or it crosses the bomb limit.
    Compression(String),
}

impl fmt::Display for Ssh3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::InvalidLength(length) => {
                write!(f, "SSH string length does not fit in memory: {length}")
            }
            Self::StringTooLong { length, limit } => {
                write!(
                    f,
                    "SSH string length {length} exceeds the limit of {limit} bytes"
                )
            }
            Self::UnknownMessageType(kind) => write!(f, "unknown SSH message type: {kind}"),
            Self::UnknownRequestType(kind) => {
                write!(f, "unknown channel request type: {:?}", kind)
            }
            Self::InvalidForwardingProtocol(protocol) => {
                write!(f, "invalid forwarding protocol: {protocol}")
            }
            Self::InvalidAddressFamily(family) => write!(f, "invalid address family: {family}"),
            Self::Compression(reason) => write!(f, "compressed data frame: {reason}"),
        }
    }
}

impl std::error::Error for Ssh3Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Ssh3Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Reads a variable-length integer from `reader`.
///
/// The first two bits of the first byte select the width of the encoding
/// (1, 2, 4 or 8 bytes); the remaining bits carry the value, most significant
/// byte first.
pub fn read_var_int<R: Read>(reader: &mut R) -> Ssh3Result<u64> {
    let first_byte = read_byte(reader)?;
    let len = 1 << ((first_byte & 0xc0) >> 6);
    let b1 = first_byte & 0x3f;
    if len == 1 {
        return Ok(u64::from(b1));
    }

    let b2 = read_byte(reader)?;
    if len == 2 {
        return Ok(u64::from(b2) + (u64::from(b1) << 8));
    }

    let b3 = read_byte(reader)?;
    let b4 = read_byte(reader)?;
    if len == 4 {
        return Ok(u64::from(b4)
            + (u64::from(b3) << 8)
            + (u64::from(b2) << 16)
            + (u64::from(b1) << 24));
    }

    let b5 = read_byte(reader)?;
    let b6 = read_byte(reader)?;
    let b7 = read_byte(reader)?;
    let b8 = read_byte(reader)?;
    Ok(u64::from(b8)
        + (u64::from(b7) << 8)
        + (u64::from(b6) << 16)
        + (u64::from(b5) << 24)
        + (u64::from(b4) << 32)
        + (u64::from(b3) << 40)
        + (u64::from(b2) << 48)
        + (u64::from(b1) << 56))
}

/// Appends `value` to `out` using the shortest variable-length encoding.
///
/// # Panics
///
/// Panics when `value` exceeds [`MAX_VARINT`].
pub fn append_var_int(out: &mut Vec<u8>, value: u64) {
    if value <= MAX_VARINT_1 {
        out.push(value as u8);
    } else if value <= MAX_VARINT_2 {
        out.extend_from_slice(&[((value >> 8) as u8) | 0x40, value as u8]);
    } else if value <= MAX_VARINT_4 {
        out.extend_from_slice(&[
            ((value >> 24) as u8) | 0x80,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]);
    } else if value <= MAX_VARINT_8 {
        out.extend_from_slice(&[
            ((value >> 56) as u8) | 0xc0,
            (value >> 48) as u8,
            (value >> 40) as u8,
            (value >> 32) as u8,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]);
    } else {
        panic!("{value:#x} doesn't fit into 62 bits");
    }
}

/// Appends `value` to `out` using exactly `length` bytes.
///
/// The value is padded with leading zero bytes, so the encoded number keeps
/// the width the peer expects. Used where the protocol fixes the width of a
/// field, for example inside a fixed-size frame.
///
/// # Panics
///
/// Panics when `length` is not 1, 2, 4 or 8, or when `value` does not fit
/// into `length` bytes.
pub fn append_var_int_with_len(out: &mut Vec<u8>, value: u64, length: usize) {
    if !matches!(length, 1 | 2 | 4 | 8) {
        panic!("invalid varint length");
    }

    let actual_len = var_int_len(value);
    if actual_len > length {
        panic!("cannot encode {value} in {length} bytes");
    }
    if actual_len == length {
        append_var_int(out, value);
        return;
    }

    match length {
        2 => out.push(0b0100_0000),
        4 => out.push(0b1000_0000),
        8 => out.push(0b1100_0000),
        _ => {}
    }

    for _ in 1..(length - actual_len) {
        out.push(0);
    }

    for shift_index in (0..actual_len).rev() {
        out.push((value >> (shift_index * 8)) as u8);
    }
}

/// Returns the number of bytes [`append_var_int`] writes for `value`.
///
/// # Panics
///
/// Panics when `value` exceeds [`MAX_VARINT`].
pub fn var_int_len(value: u64) -> usize {
    if value <= MAX_VARINT_1 {
        1
    } else if value <= MAX_VARINT_2 {
        2
    } else if value <= MAX_VARINT_4 {
        4
    } else if value <= MAX_VARINT_8 {
        8
    } else {
        panic!("value doesn't fit into 62 bits: {value}");
    }
}

/// Reads a length-prefixed byte string ("SSH string") from `reader`.
///
/// The length is a variable-length integer followed by exactly that many
/// bytes. The length is bounded by [`MAX_SSH_STRING_LEN`]: a length above
/// that bound is reported as [`Ssh3Error::StringTooLong`] *before* any buffer
/// is allocated, so a peer cannot make the process allocate an arbitrary
/// amount of memory. A length that does not fit into the address space of the
/// process is reported as [`Ssh3Error::InvalidLength`].
pub fn read_ssh_bytes<R: Read>(reader: &mut R) -> Ssh3Result<Vec<u8>> {
    let length = read_var_int(reader)?;
    if length > MAX_SSH_STRING_LEN {
        return Err(Ssh3Error::StringTooLong {
            length,
            limit: MAX_SSH_STRING_LEN,
        });
    }
    let length = usize::try_from(length).map_err(|_| Ssh3Error::InvalidLength(length))?;
    let mut out = vec![0; length];
    reader.read_exact(&mut out)?;
    Ok(out)
}

/// Appends `bytes` to `out` as a length-prefixed byte string.
pub fn append_ssh_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    append_var_int(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Returns the number of bytes [`append_ssh_bytes`] writes for `bytes`.
pub fn ssh_string_len(bytes: &[u8]) -> usize {
    var_int_len(bytes.len() as u64) + bytes.len()
}

/// Reads a boolean field from `reader`.
///
/// A boolean is encoded as a single byte: `0` is false and **every** other
/// byte is true.
///
/// This is the semantics of the reference implementation
/// (`nagual2/ssh3-go`), where the field is decoded with `encoding/binary`
/// into a `bool`: the byte is read as a number and compared against zero, so
/// `0xff` is true there. Refusing such a byte would tear down a channel that
/// the reference implementation keeps running.
pub fn read_bool<R: Read>(reader: &mut R) -> Ssh3Result<bool> {
    let value = read_byte(reader)?;
    Ok(value != 0)
}

/// Writes a boolean field to `out` as a single byte (`0` or `1`).
pub fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

/// Returns the smaller of the two values.
pub fn min_u64(a: u64, b: u64) -> u64 {
    if a <= b { a } else { b }
}

fn read_byte<R: Read>(reader: &mut R) -> Ssh3Result<u8> {
    let mut byte = [0; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read};

    use super::{
        MAX_SSH_STRING_LEN, MAX_VARINT, Ssh3Error, append_ssh_bytes, append_var_int,
        append_var_int_with_len, min_u64, read_bool, read_ssh_bytes, read_var_int, ssh_string_len,
        var_int_len,
    };

    #[test]
    fn var_int_round_trips_at_boundaries() {
        let cases = [
            (0, vec![0x00]),
            (63, vec![0x3f]),
            (64, vec![0x40, 0x40]),
            (16_383, vec![0x7f, 0xff]),
            (16_384, vec![0x80, 0x00, 0x40, 0x00]),
            (1_073_741_823, vec![0xbf, 0xff, 0xff, 0xff]),
            (
                1_073_741_824,
                vec![0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
            ),
            (
                MAX_VARINT,
                vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        for (value, expected) in cases {
            let mut encoded = Vec::new();
            append_var_int(&mut encoded, value);
            assert_eq!(encoded, expected);
            assert_eq!(var_int_len(value), expected.len());

            let mut cursor = Cursor::new(encoded);
            let decoded = read_var_int(&mut cursor).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn append_var_int_with_explicit_length_uses_requested_size() {
        let mut encoded = Vec::new();
        append_var_int_with_len(&mut encoded, 63, 2);
        assert_eq!(encoded, vec![0x40, 0x3f]);
    }

    /// A boolean is a single byte: `0` is false and every other byte is
    /// true, the semantics of the reference implementation.
    #[test]
    fn booleans_are_read_like_the_reference_implementation() {
        for byte in [0x01, 0x02, 0x7f, 0x80, 0xff] {
            assert!(
                read_bool(&mut Cursor::new([byte])).unwrap(),
                "byte {byte:#04x}"
            );
        }
        assert!(!read_bool(&mut Cursor::new([0x00])).unwrap());
    }

    #[test]
    fn ssh_bytes_round_trip() {
        let value = b"ssh3-bytes".to_vec();
        let mut encoded = Vec::new();
        append_ssh_bytes(&mut encoded, &value);
        assert_eq!(encoded.len(), ssh_string_len(&value));

        let mut cursor = Cursor::new(encoded);
        let decoded = read_ssh_bytes(&mut cursor).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn min_u64_returns_the_smaller_value() {
        assert_eq!(min_u64(4, 9), 4);
        assert_eq!(min_u64(9, 4), 4);
    }

    /// Reader that hands out the bytes of a buffer and counts them.
    struct CountingReader<'a> {
        data: &'a [u8],
        consumed: usize,
    }

    impl Read for CountingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let available = self.data.len() - self.consumed;
            let count = buf.len().min(available);
            buf[..count].copy_from_slice(&self.data[self.consumed..self.consumed + count]);
            self.consumed += count;
            Ok(count)
        }
    }

    #[test]
    fn ssh_bytes_above_the_limit_are_refused_before_the_allocation() {
        for length in [MAX_SSH_STRING_LEN + 1, MAX_VARINT] {
            let mut encoded = Vec::new();
            append_var_int(&mut encoded, length);
            let mut reader = CountingReader {
                data: &encoded,
                consumed: 0,
            };

            match read_ssh_bytes(&mut reader) {
                Err(Ssh3Error::StringTooLong {
                    length: reported,
                    limit,
                }) => {
                    assert_eq!(reported, length);
                    assert_eq!(limit, MAX_SSH_STRING_LEN);
                }
                other => panic!("expected a length error, got {other:?}"),
            }

            // Only the length prefix was consumed: the payload was never
            // requested, so no buffer of the announced size was allocated.
            assert_eq!(reader.consumed, encoded.len());
        }
    }

    #[test]
    fn ssh_bytes_at_the_limit_are_accepted() {
        let mut encoded = Vec::new();
        append_var_int(&mut encoded, MAX_SSH_STRING_LEN);
        let mut reader = CountingReader {
            data: &encoded,
            consumed: 0,
        };

        // The length itself is accepted: what fails is the missing payload.
        match read_ssh_bytes(&mut reader) {
            Err(Ssh3Error::Io(err)) => assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("expected the missing payload to be reported, got {other:?}"),
        }
    }
}
