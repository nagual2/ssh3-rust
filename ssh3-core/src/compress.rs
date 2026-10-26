//! The compression of the channel body: the capability field of the version
//! string, the algorithm negotiation and the one-shot codec of a single data
//! frame.
//!
//! The wire contract is shared with the reference implementation
//! (`nagual2/ssh3-go`, package `compress`) and is written down in the
//! protocol specification, section 15:
//!
//! - the version string carries a `compress=<list>` field with the
//!   algorithms the endpoint can decode; the list is comma separated and the
//!   field is optional (an endpoint without it supports no compression at
//!   all);
//! - a compressed data frame is the message type 192 (the private range of
//!   RFC 4253), its body is the algorithm id and the compressed payload as
//!   an SSH string;
//! - the frame unit is one data message: the payload is compressed
//!   independently, so a plain frame and a compressed frame may share the
//!   channel in any order and a lost frame never desynchronizes the decoder;
//! - the cutoff follows the "fast" levels of ZFS: a frame whose compressed
//!   form is not smaller travels as it is, so already compressed data is not
//!   compressed twice.
//!
//! The algorithm ids are the same in both implementations:
//!
//! `0` = none, `1` = deflate, `2` = lz4, `3` = zstd
//!
//! The three formats have their own quirks, and the bytes on the wire must
//! match the C port:
//!
//! - deflate is the raw DEFLATE stream (the window-less zlib wrapper, the
//!   same bytes the C port produces with its window-less zlib wrapper with a
//!   window of -15), at the middle level of the zlib range (`6`, the gzip-6
//!   of ZFS);
//! - lz4 is the LZ4 *block* format (the bytes of `LZ4_compress_default`),
//!   not the LZ4 frame format: the block carries no size, so the decoder
//!   must be given a buffer big enough, and the compressor must leave room
//!   for the worst case (`LZ4_compressBound`);
//! - zstd is the zstd frame of the reference library at the level of the
//!   ZFS default (level `3`), and the frame must carry the size of the plain
//!   payload: the decoder refuses a frame whose size is unknown, so the
//!   encoder always emits the size (the one-shot encoder knows it). The
//!   frames of the reference implementation carry no checksum and use a
//!   2 MiB window; the frames below 256 bytes use the single-segment form,
//!   because a windowed frame of that size would carry no size field at all.
//!
//! A compressed frame may not expand beyond [`MAX_OUTPUT`] (the channel
//! packet limit of 16 MiB): the decoder refuses it, whatever the frame
//! claims.

use std::fmt;

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use std::io::Read;
use std::io::Write;

/// The algorithm id of the wire that means "no compression".
///
/// The id never names a compressed frame: a peer that announced nothing
/// gets the plain frames, and a frame that carries `0` is refused.
pub const ALGORITHM_NONE: u64 = 0;
/// The algorithm id of the raw DEFLATE stream.
pub const ALGORITHM_DEFLATE: u64 = 1;
/// The algorithm id of the LZ4 block format.
pub const ALGORITHM_LZ4: u64 = 2;
/// The algorithm id of the zstd frame format.
pub const ALGORITHM_ZSTD: u64 = 3;

/// The capability mask bit of deflate.
pub const MASK_DEFLATE: u64 = 1 << 0;
/// The capability mask bit of lz4.
pub const MASK_LZ4: u64 = 1 << 1;
/// The capability mask bit of zstd.
pub const MASK_ZSTD: u64 = 1 << 2;

/// The bomb limit of the decoder: a compressed frame may not expand beyond
/// the channel packet limit (16 MiB), the same ceiling the reference
/// implementation uses.
pub const MAX_OUTPUT: usize = 16 << 20;

/// The level of the deflate codec: the middle of the zlib range, the same
/// level the reference implementation uses (the gzip-6 of ZFS).
const DEFLATE_LEVEL: u32 = 6;

/// The level of the zstd codec: the ZFS default, the level `3` of the
/// reference library.
const ZSTD_LEVEL: i32 = 3;

/// The sizes of the buffer the lz4 decoder is given, in the order they are
/// tried: the LZ4 block format carries no size, so the decoder must be given
/// a buffer big enough. The first size covers the usual channel chunk, the
/// last one is the bomb limit.
const LZ4_DECODE_SIZES: [usize; 3] = [64 << 10, 1 << 20, MAX_OUTPUT];

/// The codecs of the wire, in the preference order of the negotiation: the
/// same order in both implementations, so that the two sides pick the same
/// algorithm out of the announced intersection. The tuple is
/// `(algorithm id, capability name, capability mask bit)`.
const CODECS: [(u64, &str, u64); 3] = [
    (ALGORITHM_ZSTD, "zstd", MASK_ZSTD),
    (ALGORITHM_DEFLATE, "deflate", MASK_DEFLATE),
    (ALGORITHM_LZ4, "lz4", MASK_LZ4),
];

/// The mask of the codecs this build can decode.
const LOCAL_MASK: u64 = MASK_DEFLATE | MASK_LZ4 | MASK_ZSTD;

/// Returns the capability list of this build: the names of the codecs, in
/// the order of the negotiation.
pub fn available() -> String {
    CODECS
        .iter()
        .map(|(_, name, _)| *name)
        .collect::<Vec<_>>()
        .join(",")
}

/// Returns the capability mask bit of an algorithm id, or `0` for an
/// algorithm no build knows.
#[must_use]
pub fn mask_of(algorithm: u64) -> u64 {
    CODECS
        .iter()
        .find(|(id, _, _)| *id == algorithm)
        .map_or(0, |(_, _, mask)| *mask)
}

/// Returns the name of an algorithm id, or `None` for an algorithm no build
/// knows.
#[must_use]
pub fn name_of(algorithm: u64) -> Option<&'static str> {
    CODECS
        .iter()
        .find(|(id, _, _)| *id == algorithm)
        .map(|(_, name, _)| *name)
}

/// Parses the value of the `compress=` field of a version string into a
/// capability mask.
///
/// An unknown name is skipped: a newer peer may announce more than this
/// build knows.
#[must_use]
pub fn parse_capability(value: &str) -> u64 {
    value
        .split(',')
        .filter_map(|name| {
            CODECS
                .iter()
                .find(|(_, known, _)| *known == name.trim())
                .map(|(id, _, _)| *id)
        })
        .fold(0, |mask, id| mask | mask_of(id))
}

/// Returns the algorithm of the intersection of the peer's capability and
/// the local codecs, or [`ALGORITHM_NONE`] when the intersection is empty.
///
/// The order is the shared preference order, so that both sides end up with
/// the same algorithm.
#[must_use]
pub fn choose(peer_mask: u64) -> u64 {
    let common = peer_mask & LOCAL_MASK;
    CODECS
        .iter()
        .find(|(_, _, mask)| common & mask != 0)
        .map_or(ALGORITHM_NONE, |(id, _, _)| *id)
}

/// Extracts the capability mask announced in the `compress=` field of a
/// version string.
///
/// The field is the one the endpoints announce in their version string; a
/// version string without it announces no compression at all. Unknown
/// fields are skipped, and a field with more than one `=` is skipped the
/// way the reference implementation skips it. When the string carries the
/// field twice, the last one wins, like in the reference implementation.
#[must_use]
pub fn parse_version_capability(version_string: &str) -> u64 {
    let mut mask = 0;
    for field in version_string.split_whitespace() {
        let mut parts = field.split('=');
        let (Some(key), Some(value), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if key == "compress" {
            mask = parse_capability(value);
        }
    }
    mask
}

/// Returns the algorithm negotiated with a peer that announced its
/// capability in the given version string: the algorithm of the
/// intersection of the peer's mask and the local codecs, or
/// [`ALGORITHM_NONE`] when the peer announced nothing usable.
#[must_use]
pub fn negotiate_with_version_string(version_string: &str) -> u64 {
    choose(parse_version_capability(version_string))
}

/// Everything that can fail while a compressed frame is decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressError {
    /// The frame names an algorithm this build does not know.
    UnknownAlgorithm(u64),
    /// The frame expands beyond [`MAX_OUTPUT`].
    TooLarge,
    /// The frame does not carry the size of its plain payload: the decoder
    /// cannot bound it, so it refuses the frame.
    UnknownContentSize,
    /// The payload does not decode: the bytes are not a frame of the
    /// algorithm the frame names, or the frame is truncated.
    DoesNotDecode {
        /// The algorithm id the frame named.
        algorithm: u64,
        /// What the codec refused.
        reason: String,
    },
}

impl fmt::Display for CompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAlgorithm(algorithm) => {
                write!(f, "unknown compression algorithm: {algorithm}")
            }
            Self::TooLarge => write!(f, "the compressed frame expands beyond the limit"),
            Self::UnknownContentSize => {
                write!(f, "the compressed frame does not carry its size")
            }
            Self::DoesNotDecode { algorithm, reason } => {
                let name = name_of(*algorithm).unwrap_or("unknown");
                write!(f, "the {name} frame does not decode: {reason}")
            }
        }
    }
}

impl std::error::Error for CompressError {}

/// Compresses one frame payload with the given algorithm.
///
/// The result is `None` when the algorithm is not available in this build or
/// when the codec refuses the payload (an empty one, for the lz4 and zstd
/// codecs); the caller then sends the plain frame. The compressed bytes may
/// be bigger than the payload (an incompressible one): the cutoff of the
/// ZFS fast levels belongs to the frame layer, which sends a frame that
/// does not shrink as it is.
#[must_use]
pub fn compress(algorithm: u64, data: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        ALGORITHM_DEFLATE => compress_deflate(data),
        ALGORITHM_LZ4 => compress_lz4(data),
        ALGORITHM_ZSTD => compress_zstd(data),
        _ => None,
    }
}

/// Expands one frame payload.
///
/// The output never crosses [`MAX_OUTPUT`], so a hostile peer cannot make
/// the receiver allocate more than one channel packet.
///
/// # Errors
///
/// [`CompressError::UnknownAlgorithm`] when the frame names an algorithm
/// this build does not know (including [`ALGORITHM_NONE`], which never
/// names a frame), [`CompressError::TooLarge`] when the frame expands
/// beyond the bomb limit, [`CompressError::UnknownContentSize`] when a
/// zstd frame carries no size, and [`CompressError::DoesNotDecode`] when
/// the payload is not a frame of the named algorithm.
pub fn decompress(algorithm: u64, data: &[u8]) -> Result<Vec<u8>, CompressError> {
    match algorithm {
        ALGORITHM_DEFLATE => decompress_deflate(data),
        ALGORITHM_LZ4 => decompress_lz4(data),
        ALGORITHM_ZSTD => decompress_zstd(data),
        _ => Err(CompressError::UnknownAlgorithm(algorithm)),
    }
}

/// Compresses one payload into a raw DEFLATE stream at the level of the
/// ZFS gzip-6.
fn compress_deflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(DEFLATE_LEVEL));
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

/// Expands a raw DEFLATE stream, never beyond the bomb limit: the decoder
/// reads at most one byte more than the limit, so a hostile frame cannot
/// make the receiver allocate more than one channel packet.
fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>, CompressError> {
    let decoder = DeflateDecoder::new(data);
    let mut limited = decoder.take((MAX_OUTPUT as u64) + 1);
    let mut out = Vec::new();
    limited
        .read_to_end(&mut out)
        .map_err(|err| CompressError::DoesNotDecode {
            algorithm: ALGORITHM_DEFLATE,
            reason: err.to_string(),
        })?;
    if out.len() > MAX_OUTPUT {
        return Err(CompressError::TooLarge);
    }
    Ok(out)
}

/// Compresses one payload into an LZ4 block, the bytes of
/// `LZ4_compress_default`. The buffer must hold the worst case, the bound
/// of the block format. An empty payload is refused: the block format has
/// no representation of it, and the plain frame travels instead.
fn compress_lz4(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let packed = lz4_flex::block::compress(data);
    (!packed.is_empty()).then_some(packed)
}

/// Expands an LZ4 block. The block format carries no size, so the decoder
/// is given a buffer of a growing size until the block fits; the last size
/// is the bomb limit, and a block that does not fit it is refused.
fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>, CompressError> {
    let mut last_reason = String::from("the block does not fit the bomb limit");
    for size in LZ4_DECODE_SIZES {
        match lz4_flex::block::decompress(data, size) {
            Ok(out) => return Ok(out),
            // the last buffer is the bomb limit: a block that does not fit
            // it decodes into more than the channel packet allows
            Err(lz4_flex::block::DecompressError::OutputTooSmall { .. }) if size == MAX_OUTPUT => {
                return Err(CompressError::TooLarge);
            }
            Err(err) => {
                last_reason = err.to_string();
            }
        }
    }
    Err(CompressError::DoesNotDecode {
        algorithm: ALGORITHM_LZ4,
        reason: last_reason,
    })
}

/// Compresses one payload into a zstd frame. The frame must carry the size
/// of the plain payload, because the decoder refuses a frame whose size is
/// unknown; the one-shot encoder knows it, and the frame is checked after
/// the compression, the way the reference implementation checks its own.
fn compress_zstd(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        // the reference implementation emits no frame at all for an empty
        // payload
        return None;
    }
    // the one-shot encoder knows the payload size, so the frame always
    // carries it; the streaming encoder would emit a sizeless frame
    let packed = zstd::bulk::compress(data, ZSTD_LEVEL).ok()?;
    // the 7.x API answers Ok(None) for a frame whose header carries no size
    let size_is_known = matches!(
        zstd_safe::get_frame_content_size(&packed),
        Ok(Some(size)) if size != zstd_safe::CONTENTSIZE_UNKNOWN
    );
    size_is_known.then_some(packed)
}

/// Expands a zstd frame. The frame must carry the size of its plain
/// payload: the size is the bound of the decoder, and the decoder refuses a
/// frame without it.
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, CompressError> {
    let Some(announced) =
        zstd_safe::get_frame_content_size(data).map_err(|err| CompressError::DoesNotDecode {
            algorithm: ALGORITHM_ZSTD,
            reason: format!("the frame header does not parse: {err}"),
        })?
    else {
        return Err(CompressError::UnknownContentSize);
    };
    if announced > MAX_OUTPUT as u64 {
        return Err(CompressError::TooLarge);
    }
    // The capacity of the buffer is the announced size: the codec refuses
    // a frame whose content crosses it, whatever the frame claims.
    let out = zstd::bulk::decompress(data, announced as usize).map_err(|err| {
        CompressError::DoesNotDecode {
            algorithm: ALGORITHM_ZSTD,
            reason: err.to_string(),
        }
    })?;
    if out.len() > MAX_OUTPUT {
        return Err(CompressError::TooLarge);
    }
    Ok(out)
}

/// The payload no codec can shrink: the LCG of the seed of the tests of the
/// reference implementation is enough for the codecs, the bytes are not the
/// output of a cryptographic generator. The generator is part of the wire
/// contract of the golden vectors: the same bytes feed both the dump of the
/// reference implementation and the tests of this crate.
#[cfg(any(test, feature = "test-util"))]
pub fn pseudo_random_bytes(size: usize) -> Vec<u8> {
    let mut payload = vec![0; size];
    let mut seed: u32 = 0x1234_5678;
    for byte in &mut payload {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *byte = (seed >> 16) as u8;
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::{
        ALGORITHM_DEFLATE, ALGORITHM_LZ4, ALGORITHM_NONE, ALGORITHM_ZSTD, CompressError,
        MASK_DEFLATE, MASK_LZ4, MASK_ZSTD, MAX_OUTPUT, available, choose, compress, decompress,
        mask_of, name_of, parse_capability, parse_version_capability, pseudo_random_bytes,
    };

    const UNKNOWN_ALGORITHM: u64 = 42;

    /// The capability list announces the codecs of the build, in the order
    /// of the negotiation: the C port writes them in the same order, so the
    /// two sides read the same list (`TestCapabilityAnnouncesEveryCodec` of
    /// the reference).
    #[test]
    fn capability_announces_every_codec() {
        let available = available();
        assert_eq!(available, "zstd,deflate,lz4");
        for name in ["deflate", "lz4", "zstd"] {
            assert!(
                available.contains(name),
                "the capability list {available} does not announce {name}"
            );
        }
        let mask = parse_capability(&available);
        assert_ne!(mask & MASK_DEFLATE, 0);
        assert_ne!(mask & MASK_LZ4, 0);
        assert_ne!(mask & MASK_ZSTD, 0);
        assert_ne!(choose(mask), ALGORITHM_NONE);
    }

    /// The round trip of the capability list
    /// (`TestCapabilityRoundTrip` of the reference).
    #[test]
    fn capability_round_trip() {
        let available = available();
        assert!(!available.is_empty());
        let mask = parse_capability(&available);
        assert_ne!(mask, 0);
        assert_ne!(choose(mask), ALGORITHM_NONE);
        for name in available.split(',') {
            assert_ne!(
                parse_capability(name),
                0,
                "the name {name} of the list does not parse"
            );
        }
    }

    /// An unknown name is skipped, an empty list is an empty mask
    /// (`TestParseCapabilitySkipsUnknown` of the reference).
    #[test]
    fn parse_capability_skips_unknown() {
        let mask = parse_capability("deflate,nosuch,zstd");
        assert_ne!(mask & MASK_DEFLATE, 0, "the known name was skipped");
        assert_ne!(mask & MASK_ZSTD, 0, "the known name was skipped");
        assert_eq!(parse_capability(""), 0);
        assert_eq!(parse_capability("nosuch"), 0);
    }

    /// An empty peer mask yields no algorithm, and the unknown bits of a
    /// peer are ignored (`TestChooseIsEmptyWithoutCommon` of the
    /// reference).
    #[test]
    fn choose_is_empty_without_common() {
        assert_eq!(choose(0), ALGORITHM_NONE);
        let unknown_bit = 1_u64 << 63;
        assert_eq!(choose(unknown_bit), ALGORITHM_NONE);
    }

    /// The preference order is the one of the C port (zstd, deflate, lz4):
    /// both sides pick the same algorithm out of the announced intersection
    /// (`TestChooseFollowsThePreferenceOrder` of the reference).
    #[test]
    fn choose_follows_the_preference_order() {
        let cases = [
            (MASK_ZSTD | MASK_DEFLATE | MASK_LZ4, ALGORITHM_ZSTD),
            (MASK_DEFLATE | MASK_LZ4, ALGORITHM_DEFLATE),
            (MASK_LZ4 | MASK_ZSTD, ALGORITHM_ZSTD),
            (MASK_DEFLATE | MASK_ZSTD, ALGORITHM_ZSTD),
            (MASK_LZ4, ALGORITHM_LZ4),
            (MASK_DEFLATE, ALGORITHM_DEFLATE),
            (MASK_ZSTD, ALGORITHM_ZSTD),
        ];
        for (mask, want) in cases {
            assert_eq!(choose(mask), want, "choose({mask}) picked the wrong codec");
        }
    }

    /// The mask of an algorithm id, and the name of it.
    #[test]
    fn mask_and_name_of_the_algorithms() {
        assert_eq!(mask_of(ALGORITHM_DEFLATE), MASK_DEFLATE);
        assert_eq!(mask_of(ALGORITHM_LZ4), MASK_LZ4);
        assert_eq!(mask_of(ALGORITHM_ZSTD), MASK_ZSTD);
        assert_eq!(mask_of(ALGORITHM_NONE), 0);
        assert_eq!(mask_of(UNKNOWN_ALGORITHM), 0);
        assert_eq!(name_of(ALGORITHM_ZSTD), Some("zstd"));
        assert_eq!(name_of(UNKNOWN_ALGORITHM), None);
    }

    /// The `compress=` field of a version string is parsed the way the
    /// reference implementation parses it: unknown fields are skipped, the
    /// field is optional, and the last field wins.
    #[test]
    fn version_capability_is_parsed() {
        let version =
            "SSH 3.0 ssh3-rust 0.1.0 experimental_spec_version=alpha-00 compress=zstd,deflate,lz4";
        assert_eq!(
            parse_version_capability(version),
            MASK_ZSTD | MASK_DEFLATE | MASK_LZ4
        );
        assert_eq!(parse_version_capability("SSH 3.0 impl 1.0.0"), 0);
        assert_eq!(
            parse_version_capability("SSH 3.0 impl 1.0.0 experimental_spec_version=alpha-00"),
            0
        );
        // An unknown codec inside the field is skipped, the known ones stay.
        assert_eq!(
            parse_version_capability("SSH 3.0 impl 1.0.0 compress=nosuch,deflate"),
            MASK_DEFLATE
        );
        // A field with more than one `=` is skipped, like in the reference.
        assert_eq!(
            parse_version_capability("SSH 3.0 impl 1.0.0 compress=deflate=extra"),
            0
        );
        // The last field wins.
        assert_eq!(
            parse_version_capability("SSH 3.0 impl 1.0.0 compress=lz4 compress=zstd"),
            MASK_ZSTD
        );
        // The negotiated algorithm of a version string is the best common
        // codec.
        assert_eq!(
            super::negotiate_with_version_string(
                "SSH 3.0 ssh3 0.1.37 experimental_spec_version=alpha-00 compress=zstd,deflate,lz4"
            ),
            ALGORITHM_ZSTD
        );
        assert_eq!(
            super::negotiate_with_version_string(
                "SSH 3.0 ssh3 0.1.37 experimental_spec_version=alpha-00"
            ),
            ALGORITHM_NONE
        );
    }

    /// The round trip of every codec over a compressible payload
    /// (`TestRoundTrip` of the reference).
    #[test]
    fn round_trip() {
        let payload = b"ssh3 compression payload ".repeat(500);
        for algorithm in [ALGORITHM_DEFLATE, ALGORITHM_LZ4, ALGORITHM_ZSTD] {
            let packed = compress(algorithm, &payload).unwrap_or_else(|| {
                panic!(
                    "the {} codec refused the payload",
                    name_of(algorithm).unwrap_or("?")
                )
            });
            assert!(
                packed.len() < payload.len(),
                "the compressed form of {} ({}) is not smaller than the payload ({})",
                name_of(algorithm).unwrap_or("?"),
                packed.len(),
                payload.len()
            );
            let out = decompress(algorithm, &packed).unwrap_or_else(|err| {
                panic!(
                    "the {} decompression failed: {err}",
                    name_of(algorithm).unwrap_or("?")
                )
            });
            assert_eq!(out, payload, "the round trip changed the payload");
        }
    }

    /// The cutoff of the ZFS fast levels: a payload that does not shrink
    /// travels as it is, so already compressed data is not compressed
    /// twice. The codec returns the compressed bytes whatever their size -
    /// the frame layer applies the cutoff - so the test pins the size
    /// relation the frame layer relies on
    /// (`TestTheCutoffOfAnIncompressiblePayload` of the reference).
    #[test]
    fn the_cutoff_of_an_incompressible_payload() {
        let payload = pseudo_random_bytes(4096);
        for algorithm in [ALGORITHM_DEFLATE, ALGORITHM_LZ4, ALGORITHM_ZSTD] {
            let Some(packed) = compress(algorithm, &payload) else {
                // the codec refused the payload: the frame travels as it is
                continue;
            };
            assert!(
                packed.len() >= payload.len(),
                "the {} codec shrank a pseudo random payload ({} -> {})",
                name_of(algorithm).unwrap_or("?"),
                payload.len(),
                packed.len()
            );
        }
    }

    /// An unknown algorithm is refused on both paths
    /// (`TestCompressRefusesUnknownAlgorithm` of the reference). The id `0`
    /// never names a frame either: it means "no compression".
    #[test]
    fn compress_refuses_unknown_algorithm() {
        assert_eq!(compress(UNKNOWN_ALGORITHM, b"x"), None);
        assert_eq!(compress(ALGORITHM_NONE, b"x"), None);
        assert_eq!(
            decompress(UNKNOWN_ALGORITHM, b"x"),
            Err(CompressError::UnknownAlgorithm(42))
        );
        assert_eq!(
            decompress(ALGORITHM_NONE, b"x"),
            Err(CompressError::UnknownAlgorithm(0))
        );
    }

    /// The lz4 and zstd codecs refuse an empty payload: the plain frame
    /// travels instead.
    #[test]
    fn an_empty_payload_is_refused_by_lz4_and_zstd() {
        assert_eq!(compress(ALGORITHM_LZ4, b""), None);
        assert_eq!(compress(ALGORITHM_ZSTD, b""), None);
        // The deflate codec has a representation of the empty payload.
        let packed =
            compress(ALGORITHM_DEFLATE, b"").expect("the deflate codec refused an empty payload");
        assert_eq!(decompress(ALGORITHM_DEFLATE, &packed), Ok(Vec::new()));
    }

    /// A payload of zeros expands by a factor of more than a thousand, so
    /// a legitimate payload below the limit must decode
    /// (`TestDecompressAcceptsTheOutputBelowTheLimit` of the reference).
    #[test]
    fn decompress_accepts_the_output_below_the_limit() {
        let payload = vec![0_u8; 1 << 20];
        let packed =
            compress(ALGORITHM_DEFLATE, &payload).expect("the deflate codec refused the payload");
        let out = decompress(ALGORITHM_DEFLATE, &packed)
            .expect("the decompression of a legitimate payload failed");
        assert_eq!(out, payload);
    }

    /// The bomb limit of the decoder: a frame that expands beyond the
    /// channel packet limit is refused, whatever the codec
    /// (`TestDecompressRefusesAFrameBeyondTheLimit` of the reference).
    #[test]
    fn decompress_refuses_a_frame_beyond_the_limit() {
        let payload = vec![0_u8; MAX_OUTPUT + 1];
        for algorithm in [ALGORITHM_DEFLATE, ALGORITHM_LZ4, ALGORITHM_ZSTD] {
            let packed = compress(algorithm, &payload).unwrap_or_else(|| {
                panic!(
                    "the {} codec refused the payload",
                    name_of(algorithm).unwrap_or("?")
                )
            });
            let out = decompress(algorithm, &packed);
            assert!(
                matches!(out, Err(CompressError::TooLarge)),
                "the {} decoder accepted a frame beyond the limit: {out:?}",
                name_of(algorithm).unwrap_or("?")
            );
        }
    }

    /// The zstd frame must carry the size of the plain payload: the
    /// decoder refuses a frame whose size is unknown, so the encoder must
    /// always emit it (`TestTheZstdFrameCarriesItsSize` of the reference).
    #[test]
    fn the_zstd_frame_carries_its_size() {
        for size in [1, 100, 255, 256, 1000, 30000] {
            let payload = b"zstd frame size ".repeat(size / 16 + 1)[..size].to_vec();
            let packed =
                compress(ALGORITHM_ZSTD, &payload).expect("the zstd codec refused the payload");
            let announced = zstd_safe::get_frame_content_size(&packed)
                .expect("the zstd frame does not parse")
                .expect("the zstd frame carries no size");
            assert_eq!(
                announced, size as u64,
                "the zstd frame of {size} bytes announces {announced} bytes"
            );
        }
    }

    /// A frame without the size is refused, as the C port refuses it
    /// (`TestDecompressRefusesAFrameWithoutItsSize` of the reference): the
    /// windowed form whose header declares neither the size nor the single
    /// segment form.
    #[test]
    fn decompress_refuses_a_frame_without_its_size() {
        let payload = b"the payload of a frame without its size";
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00];
        // the block header: the size in the upper bits, the raw block type
        // and the flag of the last block
        let block_header = (payload.len() as u32) << 3 | 1;
        frame.extend_from_slice(&block_header.to_le_bytes()[..3]);
        frame.extend_from_slice(payload);

        let out = decompress(ALGORITHM_ZSTD, &frame);
        assert_eq!(out, Err(CompressError::UnknownContentSize));
    }

    /// The frames the reference libraries produce for the payload below -
    /// the very bytes the C port puts on the wire (`interop_test.go` of the
    /// reference): the lz4 block of `LZ4_compress_default` and the zstd
    /// frame of `ZSTD_compress` at the level 3. They are the fixtures of
    /// the wire contract: a drift of the codecs would decode them into
    /// something else.
    #[test]
    fn the_reference_frames_are_decoded() {
        let payload: Vec<u8> = (0..512).map(|i| b'a' + (i % 26) as u8).collect();
        let cases = [
            (
                ALGORITHM_LZ4,
                "ff0b6162636465666768696a6b6c6d6e6f7071727374757677\
                 78797a1a00ffcf506e6f707172",
            ),
            (
                ALGORITHM_ZSTD,
                "28b52ffd6000010d0100d06162636465666768696a6b6c6d6e\
                 6f707172737475767778797a01008eb73ac7",
            ),
        ];
        for (algorithm, frame) in cases {
            let frame = decode_hex(frame);
            let out = decompress(algorithm, &frame).unwrap_or_else(|err| {
                panic!(
                    "the {} frame of the reference library does not decode: {err}",
                    name_of(algorithm).unwrap_or("?")
                )
            });
            assert_eq!(
                out,
                payload,
                "the {} frame of the reference library decodes into something else",
                name_of(algorithm).unwrap_or("?")
            );
        }
    }

    /// The lz4 codec is the block format (the bytes of
    /// `LZ4_compress_default`), not the frame format: the frames of the
    /// stream format start with their own magic number
    /// (`TestTheLZ4CodecEmitsABlockAndNotAFrame` of the reference).
    #[test]
    fn the_lz4_codec_emits_a_block_and_not_a_frame() {
        let payload = b"ssh3 compression payload ".repeat(500);
        let packed = compress(ALGORITHM_LZ4, &payload).expect("the lz4 codec refused the payload");
        let frame_magic = [0x04, 0x22, 0x4d, 0x18];
        assert!(
            !packed.starts_with(&frame_magic),
            "the lz4 codec emitted a frame of the stream format, not a block"
        );
    }

    /// The zstd codec is the frame format of the reference library: the
    /// frame starts with its magic number (`TestTheZstdCodecEmitsAFrame`
    /// of the reference).
    #[test]
    fn the_zstd_codec_emits_a_frame() {
        let payload = b"ssh3 compression payload ".repeat(500);
        let packed =
            compress(ALGORITHM_ZSTD, &payload).expect("the zstd codec refused the payload");
        let frame_magic = [0x28, 0xb5, 0x2f, 0xfd];
        assert!(
            packed.starts_with(&frame_magic),
            "the zstd codec did not emit a frame of the reference library"
        );
    }

    /// The bomb limit bites on a truncated deflate stream too: a frame
    /// that claims to expand beyond the limit is refused before the
    /// decoder allocates beyond one channel packet.
    #[test]
    fn a_truncated_deflate_stream_is_refused() {
        let payload = vec![7_u8; 1 << 20];
        let packed =
            compress(ALGORITHM_DEFLATE, &payload).expect("the deflate codec refused the payload");
        let out = decompress(ALGORITHM_DEFLATE, &packed[..packed.len() - 1]);
        assert!(
            matches!(out, Err(CompressError::DoesNotDecode { .. })),
            "a truncated deflate stream must not decode: {out:?}"
        );
    }

    /// Decodes a hexadecimal string, with the spaces and the line breaks
    /// the fixtures are written with.
    fn decode_hex(value: &str) -> Vec<u8> {
        let cleaned: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..cleaned.len() / 2)
            .map(|i| {
                u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
                    .expect("the fixture is not valid hex")
            })
            .collect()
    }
}
