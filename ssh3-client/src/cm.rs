//! The codec of the control master channel (the `client/cm` package of the
//! Go implementation): a minimal versioned framing plus the slave-to-master
//! message set.
//!
//! The format is deliberately not the OpenSSH mux wire format: both ends are
//! ours, so it optimizes for a small auditable codec over the unix socket of
//! the control master. The encoding follows the Go implementation byte for
//! byte, so a Go client and a Rust client may share one control socket.
//!
//! Frame layout: magic `S3CM` (4 bytes), protocol version (1 byte), message
//! type (1 byte), payload length (4 bytes, big endian), then the payload.
//! Session and forward descriptors are tiny; bulk data travels outside this
//! codec over the bridged streams.

// The codec lands before the daemon wiring: the protocol surface mirrors the
// Go message set byte for byte, and the still-unused items light up as the
// master and slave integration progresses.
#![allow(dead_code)]

use std::fmt;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The mux protocol version carried by every frame header; a HELLO with a
/// mismatching version is refused by the peer.
pub const CM_PROTOCOL_VERSION: u8 = 1;

/// The type of the frame that carries one `-O` control operation.
///
/// The constant lives in `client/control.go` of the Go implementation, not in
/// the `cm` package: it is an extension of the base message set that keeps the
/// framing untouched.
pub const MSG_CONTROL_OP: u8 = 12;

/// Tags every frame so a garbage dialer (an HTTP probe, a stray client) fails
/// fast instead of being misparsed as a control message.
const MAGIC: [u8; 4] = *b"S3CM";

/// Bounds one control payload. Session and forward descriptors are tiny; bulk
/// data travels over the bridged streams.
pub const MAX_FRAME: u32 = 1 << 20;

/// The length of the frame header: magic(4) version(1) type(1) payload
/// length(4, big endian).
pub const HEADER_LEN: usize = 10;

/// The type of a control frame.
///
/// Slave to master: Hello, OpenSession, OpenForwardTCP, OpenForwardUDP, Exit,
/// WindowChange, Signal. Master to slave: OK, Error, ExitStatus. The values
/// are the ones of the Go implementation; an unknown value is refused by the
/// peers with an "unexpected message" error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgType(pub u8);

impl MsgType {
    pub const HELLO: MsgType = MsgType(1);
    pub const OPEN_SESSION: MsgType = MsgType(2);
    pub const OPEN_FORWARD_TCP: MsgType = MsgType(3);
    pub const OPEN_FORWARD_UDP: MsgType = MsgType(4);
    pub const EXIT: MsgType = MsgType(5);
    pub const OK: MsgType = MsgType(6);
    pub const ERROR: MsgType = MsgType(7);
    pub const ATTACH: MsgType = MsgType(8);
    pub const EXIT_STATUS: MsgType = MsgType(9);
    pub const WINDOW_CHANGE: MsgType = MsgType(10);
    pub const SIGNAL: MsgType = MsgType(11);
}

/// The errors of the control channel codec.
#[derive(Debug)]
pub enum CmError {
    /// The peer is not a control master (a garbage dialer).
    BadMagic,
    /// The peer speaks another version of the protocol.
    Version { got: u8, want: u8 },
    /// A frame payload exceeds the maximum size.
    FrameSize,
    /// A frame started but ended before it was complete: a partial write is a
    /// protocol violation, not an orderly end.
    Truncated,
    /// A message payload ended before the decoder was done.
    Short,
    /// A message payload carries bytes the decoder did not consume.
    Trailing,
    /// The reply of a request is not OK or Error.
    UnexpectedReply(u8),
    /// The master refused a request (the payload of the Error frame).
    Refused(String),
    /// The underlying stream failed.
    Io(io::Error),
}

impl fmt::Display for CmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "cm: not a control-master stream (bad magic)"),
            Self::Version { got, want } => {
                write!(f, "cm: protocol version mismatch: got {got}, want {want}")
            }
            Self::FrameSize => write!(f, "cm: frame payload too large"),
            Self::Truncated => write!(f, "cm: truncated frame"),
            Self::Short => write!(f, "cm: truncated message payload"),
            Self::Trailing => write!(f, "cm: trailing bytes after message"),
            Self::UnexpectedReply(typ) => write!(f, "cm: unexpected reply {typ}"),
            Self::Refused(message) => write!(f, "cm: master refused: {message}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for CmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for CmError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Tells whether an I/O error is a premature end of stream.
fn is_premature_eof(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::UnexpectedEof)
}

/// Writes one frame with the current protocol version.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    typ: MsgType,
    payload: &[u8],
) -> Result<(), CmError> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| CmError::FrameSize)?;
    if payload_len > MAX_FRAME {
        return Err(CmError::FrameSize);
    }
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4] = CM_PROTOCOL_VERSION;
    header[5] = typ.0;
    header[6..].copy_from_slice(&payload_len.to_be_bytes());
    writer.write_all(&header).await?;
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    Ok(())
}

/// Reads one frame. A clean peer close surfaces as `Ok(None)`; a started but
/// incomplete header or payload is [`CmError::Truncated`].
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<(MsgType, Vec<u8>)>, CmError> {
    let mut header = [0u8; HEADER_LEN];
    // A read of the first byte distinguishes the orderly end of the stream
    // from a partial header.
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await.map_err(|err| {
        if is_premature_eof(&err) {
            CmError::Truncated
        } else {
            CmError::Io(err)
        }
    })?;
    if header[..4] != MAGIC {
        return Err(CmError::BadMagic);
    }
    if header[4] != CM_PROTOCOL_VERSION {
        return Err(CmError::Version {
            got: header[4],
            want: CM_PROTOCOL_VERSION,
        });
    }
    let payload_len = u32::from_be_bytes(header[6..].try_into().expect("fixed size"));
    if payload_len > MAX_FRAME {
        return Err(CmError::FrameSize);
    }
    let mut payload = vec![0u8; usize::try_from(payload_len).expect("bounded by MAX_FRAME")];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await.map_err(|err| {
            if is_premature_eof(&err) {
                CmError::Truncated
            } else {
                CmError::Io(err)
            }
        })?;
    }
    Ok(Some((MsgType(header[5]), payload)))
}

/// Performs the version handshake: sends HELLO and expects OK.
pub async fn hello<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<(), CmError> {
    write_frame(stream, MsgType::HELLO, &[]).await?;
    match read_frame(stream).await? {
        None => Err(CmError::Truncated),
        Some((typ, _)) if typ == MsgType::OK => Ok(()),
        Some((typ, _)) => Err(CmError::UnexpectedReply(typ.0)),
    }
}

/// Sends one request frame and reads the reply. OK returns the reply payload;
/// Error returns it as [`CmError::Refused`]; anything else is a protocol
/// violation.
pub async fn call<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    typ: MsgType,
    payload: &[u8],
) -> Result<Vec<u8>, CmError> {
    write_frame(stream, typ, payload).await?;
    match read_frame(stream).await? {
        None => Err(CmError::Truncated),
        Some((MsgType::OK, reply)) => Ok(reply),
        Some((MsgType::ERROR, reply)) => Err(CmError::Refused(
            String::from_utf8_lossy(&reply).into_owned(),
        )),
        Some((typ, _)) => Err(CmError::UnexpectedReply(typ.0)),
    }
}

/// Appends a big-endian length-prefixed string to a buffer.
fn append_str(mut buffer: Vec<u8>, value: &str) -> Vec<u8> {
    buffer.extend_from_slice(
        &u32::try_from(value.len())
            .expect("string length")
            .to_be_bytes(),
    );
    buffer.extend_from_slice(value.as_bytes());
    buffer
}

/// Reads a big-endian length-prefixed string from the front of a buffer.
fn read_str(buffer: &[u8]) -> Result<(&str, &[u8]), CmError> {
    if buffer.len() < 4 {
        return Err(CmError::Short);
    }
    let length = u32::from_be_bytes(buffer[..4].try_into().expect("fixed size"));
    let rest = &buffer[4..];
    let length = usize::try_from(length).map_err(|_| CmError::Short)?;
    if rest.len() < length {
        return Err(CmError::Short);
    }
    let value = std::str::from_utf8(&rest[..length]).map_err(|_| CmError::Short)?;
    Ok((value, &rest[length..]))
}

/// Reads a big-endian item count whose items cost at least `min_bytes_per_item`
/// bytes: a count above the remaining length is already malformed.
fn read_count(buffer: &[u8], min_bytes_per_item: usize) -> Result<(usize, &[u8]), CmError> {
    if buffer.len() < 4 {
        return Err(CmError::Short);
    }
    let count = u32::from_be_bytes(buffer[..4].try_into().expect("fixed size"));
    let rest = &buffer[4..];
    let count = usize::try_from(count).map_err(|_| CmError::Short)?;
    if count > rest.len() / min_bytes_per_item {
        return Err(CmError::Short);
    }
    Ok((count, rest))
}

/// Requests a remote pty; `None` in an open-session request means no pty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PtySpec {
    pub term: String,
    pub columns: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

/// Asks the master to open a session channel. The command is the remote
/// command line; an empty list means a remote shell.
///
/// The environment list is carried for the wire compatibility with the Go
/// implementation, which encodes it but does not apply it on the master.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenSession {
    pub command: Vec<String>,
    pub env: Vec<String>,
    pub pty: Option<PtySpec>,
    pub forward_agent: bool,
}

impl OpenSession {
    /// Marshals the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(64);
        buffer.extend_from_slice(
            &u32::try_from(self.command.len())
                .expect("list length")
                .to_be_bytes(),
        );
        for item in &self.command {
            buffer = append_str(buffer, item);
        }
        buffer.extend_from_slice(
            &u32::try_from(self.env.len())
                .expect("list length")
                .to_be_bytes(),
        );
        for item in &self.env {
            buffer = append_str(buffer, item);
        }
        match &self.pty {
            None => buffer.push(0),
            Some(pty) => {
                buffer.push(1);
                buffer = append_str(buffer, &pty.term);
                buffer.extend_from_slice(&pty.columns.to_be_bytes());
                buffer.extend_from_slice(&pty.rows.to_be_bytes());
                buffer.extend_from_slice(&pty.pixel_width.to_be_bytes());
                buffer.extend_from_slice(&pty.pixel_height.to_be_bytes());
            }
        }
        buffer.push(u8::from(self.forward_agent));
        buffer
    }

    /// Unmarshals the message; malformed or trailing input is an error.
    pub fn decode(payload: &[u8]) -> Result<Self, CmError> {
        let (command_count, mut rest) = read_count(payload, 4)?;
        let mut command = Vec::new();
        for _ in 0..command_count {
            let (item, remainder) = read_str(rest)?;
            command.push(item.to_string());
            rest = remainder;
        }
        let (env_count, mut rest) = read_count(rest, 4)?;
        let mut env = Vec::new();
        for _ in 0..env_count {
            let (item, remainder) = read_str(rest)?;
            env.push(item.to_string());
            rest = remainder;
        }
        let (&has_pty, remainder) = rest.split_first().ok_or(CmError::Short)?;
        rest = remainder;
        let pty = if has_pty == 0 {
            None
        } else {
            let (term, remainder) = read_str(rest)?;
            rest = remainder;
            if rest.len() < 16 {
                return Err(CmError::Short);
            }
            let (columns, rows, pixel_width, pixel_height) = (
                u32::from_be_bytes(rest[0..4].try_into().expect("fixed size")),
                u32::from_be_bytes(rest[4..8].try_into().expect("fixed size")),
                u32::from_be_bytes(rest[8..12].try_into().expect("fixed size")),
                u32::from_be_bytes(rest[12..16].try_into().expect("fixed size")),
            );
            rest = &rest[16..];
            Some(PtySpec {
                term: term.to_string(),
                columns,
                rows,
                pixel_width,
                pixel_height,
            })
        };
        let (&agent, remainder) = rest.split_first().ok_or(CmError::Short)?;
        if !remainder.is_empty() {
            return Err(CmError::Trailing);
        }
        Ok(Self {
            command,
            env,
            pty,
            forward_agent: agent == 1,
        })
    }
}

/// Asks the master to open a forwarding channel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenForward {
    /// The local side; empty lets the master pick one.
    pub listen_addr: String,
    /// The remote side the master connects or forwards to.
    pub target_addr: String,
}

impl OpenForward {
    /// Marshals the message.
    pub fn encode(&self) -> Vec<u8> {
        let buffer = append_str(Vec::new(), &self.listen_addr);
        append_str(buffer, &self.target_addr)
    }

    /// Unmarshals the message; malformed or trailing input is an error.
    pub fn decode(payload: &[u8]) -> Result<Self, CmError> {
        let (listen_addr, rest) = read_str(payload)?;
        let (target_addr, rest) = read_str(rest)?;
        if !rest.is_empty() {
            return Err(CmError::Trailing);
        }
        Ok(Self {
            listen_addr: listen_addr.to_string(),
            target_addr: target_addr.to_string(),
        })
    }
}

/// Identifies one bridged session between the control connection and the
/// stream attachments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionToken(pub [u8; 16]);

impl SessionToken {
    /// Generates a fresh session token.
    pub fn new() -> Self {
        let mut token = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
        Self(token)
    }
}

impl Default for SessionToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Selects which data stream an attachment carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    /// Full duplex: slave stdin up, session stdout down.
    Io,
    /// Master to slave only.
    Stderr,
}

impl StreamKind {
    const IO: u8 = 0;
    const STDERR: u8 = 1;

    fn from_byte(value: u8) -> Option<Self> {
        match value {
            Self::IO => Some(Self::Io),
            Self::STDERR => Some(Self::Stderr),
            _ => None,
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Self::Io => Self::IO,
            Self::Stderr => Self::STDERR,
        }
    }
}

/// Binds a dedicated stream connection to a bridged session. The stderr
/// stream must attach before the io stream: the master starts the session
/// pump on the io attachment and needs the stderr sink by then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attach {
    pub token: SessionToken,
    pub stream: StreamKind,
}

impl Attach {
    /// Marshals the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(17);
        buffer.extend_from_slice(&self.token.0);
        buffer.push(self.stream.to_byte());
        buffer
    }

    /// Unmarshals the message; malformed input is an error.
    pub fn decode(payload: &[u8]) -> Result<Self, CmError> {
        if payload.len() != 17 {
            return Err(CmError::Short);
        }
        let token = SessionToken(payload[..16].try_into().expect("fixed size"));
        let stream = StreamKind::from_byte(payload[16]).ok_or(CmError::Trailing)?;
        Ok(Self { token, stream })
    }
}

/// Marshals a session exit status (8 bytes, big endian).
pub fn encode_exit_status(code: u64) -> Vec<u8> {
    code.to_be_bytes().to_vec()
}

/// Unmarshals a session exit status.
pub fn decode_exit_status(payload: &[u8]) -> Result<u64, CmError> {
    if payload.len() != 8 {
        return Err(CmError::Short);
    }
    Ok(u64::from_be_bytes(payload.try_into().expect("fixed size")))
}

/// Relays a slave terminal resize for a bridged session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowChange {
    pub columns: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

impl WindowChange {
    /// Marshals the message (4 big-endian u32s).
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(16);
        buffer.extend_from_slice(&self.columns.to_be_bytes());
        buffer.extend_from_slice(&self.rows.to_be_bytes());
        buffer.extend_from_slice(&self.pixel_width.to_be_bytes());
        buffer.extend_from_slice(&self.pixel_height.to_be_bytes());
        buffer
    }

    /// Unmarshals the message; malformed or trailing input is an error.
    pub fn decode(payload: &[u8]) -> Result<Self, CmError> {
        if payload.len() != 16 {
            return Err(CmError::Short);
        }
        Ok(Self {
            columns: u32::from_be_bytes(payload[0..4].try_into().expect("fixed size")),
            rows: u32::from_be_bytes(payload[4..8].try_into().expect("fixed size")),
            pixel_width: u32::from_be_bytes(payload[8..12].try_into().expect("fixed size")),
            pixel_height: u32::from_be_bytes(payload[12..16].try_into().expect("fixed size")),
        })
    }
}

/// Relays a slave-side signal for a bridged session. The name is the bare
/// signal name without the SIG prefix ("INT", "TERM", ...), like SSH2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signal {
    pub name: String,
}

impl Signal {
    /// Marshals the message.
    pub fn encode(&self) -> Vec<u8> {
        append_str(Vec::new(), &self.name)
    }

    /// Unmarshals the message; malformed or trailing input is an error.
    pub fn decode(payload: &[u8]) -> Result<Self, CmError> {
        let (name, rest) = read_str(payload)?;
        if !rest.is_empty() {
            return Err(CmError::Trailing);
        }
        Ok(Self {
            name: name.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Attach, CM_PROTOCOL_VERSION, CmError, HEADER_LEN, MAX_FRAME, MSG_CONTROL_OP, MsgType,
        OpenForward, OpenSession, PtySpec, SessionToken, Signal, StreamKind, WindowChange,
        decode_exit_status, encode_exit_status, read_frame, write_frame,
    };

    fn frame_bytes(typ: u8, payload: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"S3CM");
        buffer.push(CM_PROTOCOL_VERSION);
        buffer.push(typ);
        buffer.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        buffer.extend_from_slice(payload);
        buffer
    }

    #[tokio::test]
    async fn a_frame_round_trips() {
        let payload = b"hello control master";
        let mut written = Vec::new();
        write_frame(&mut written, MsgType::OPEN_SESSION, payload)
            .await
            .unwrap();
        assert_eq!(written, frame_bytes(MsgType::OPEN_SESSION.0, payload));
        let (typ, got) = read_frame(&mut written.as_slice()).await.unwrap().unwrap();
        assert_eq!(typ, MsgType::OPEN_SESSION);
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn an_empty_payload_round_trips() {
        for typ in [MsgType::HELLO, MsgType::EXIT, MsgType::OK] {
            let mut written = Vec::new();
            write_frame(&mut written, typ, &[]).await.unwrap();
            // the header carries a zero length and no payload bytes follow
            assert_eq!(written.len(), HEADER_LEN);
            let (got, payload) = read_frame(&mut written.as_slice()).await.unwrap().unwrap();
            assert_eq!(got, typ);
            assert!(payload.is_empty());
        }
    }

    #[tokio::test]
    async fn the_maximum_payload_is_accepted() {
        let payload = vec![0u8; MAX_FRAME as usize];
        let mut written = Vec::new();
        write_frame(&mut written, MsgType::ERROR, &payload)
            .await
            .unwrap();
        let (_, got) = read_frame(&mut written.as_slice()).await.unwrap().unwrap();
        assert_eq!(got.len(), MAX_FRAME as usize);
    }

    #[tokio::test]
    async fn an_oversize_write_is_rejected() {
        let payload = vec![0u8; MAX_FRAME as usize + 1];
        let mut written = Vec::new();
        let err = write_frame(&mut written, MsgType::ERROR, &payload)
            .await
            .unwrap_err();
        assert!(matches!(err, CmError::FrameSize));
    }

    #[tokio::test]
    async fn a_garbage_dialer_is_refused_by_the_magic() {
        // a stray HTTP probe is the realistic garbage dialer
        let mut garbage = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        garbage.extend_from_slice(&[0u8; 10]);
        let err = read_frame(&mut garbage.as_slice()).await.unwrap_err();
        assert!(matches!(err, CmError::BadMagic));
    }

    #[tokio::test]
    async fn a_version_mismatch_is_refused() {
        let mut frame = frame_bytes(MsgType::HELLO.0, &[]);
        frame[4] = CM_PROTOCOL_VERSION + 1;
        let err = read_frame(&mut frame.as_slice()).await.unwrap_err();
        assert!(matches!(err, CmError::Version { got: 2, want: 1 }));
    }

    #[tokio::test]
    async fn an_oversize_read_is_refused() {
        let mut frame = frame_bytes(MsgType::HELLO.0, &[]);
        let length = (MAX_FRAME + 1).to_be_bytes();
        frame[6..].copy_from_slice(&length);
        let err = read_frame(&mut frame.as_slice()).await.unwrap_err();
        assert!(matches!(err, CmError::FrameSize));
    }

    #[tokio::test]
    async fn a_clean_end_of_stream_is_not_an_error() {
        let mut written = Vec::new();
        write_frame(&mut written, MsgType::EXIT, &[]).await.unwrap();
        let mut cursor: &[u8] = &written;
        read_frame(&mut cursor).await.unwrap().unwrap();
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_truncated_frame_is_not_a_clean_end() {
        let mut written = Vec::new();
        write_frame(&mut written, MsgType::ERROR, b"abcde")
            .await
            .unwrap();
        for cut in [HEADER_LEN / 2, HEADER_LEN + 2] {
            let mut cursor: &[u8] = &written[..cut];
            let err = read_frame(&mut cursor).await.unwrap_err();
            assert!(matches!(err, CmError::Truncated), "cut {cut}: {err:?}");
        }
    }

    #[tokio::test]
    async fn the_handshake_and_the_call_follow_the_go_protocol() {
        use super::{call, hello};
        use tokio::io::duplex;

        // A fake master that answers OK to every request: the slave side of
        // the exchange runs through the public helpers.
        let (mut master, mut slave) = duplex(1024);
        let master_task = tokio::spawn(async move {
            let (typ, _) = read_frame(&mut master).await.unwrap().unwrap();
            assert_eq!(typ, MsgType::HELLO);
            write_frame(&mut master, MsgType::OK, &[]).await.unwrap();

            let (typ, payload) = read_frame(&mut master).await.unwrap().unwrap();
            assert_eq!(typ.0, MSG_CONTROL_OP);
            // the payload of a control op is the length-prefixed name
            assert_eq!(payload, b"\x00\x00\x00\x05check");
            write_frame(&mut master, MsgType::OK, b"status")
                .await
                .unwrap();

            let (typ, _) = read_frame(&mut master).await.unwrap().unwrap();
            assert_eq!(typ, MsgType::EXIT);
            write_frame(&mut master, MsgType::ERROR, b"no")
                .await
                .unwrap();
        });

        hello(&mut slave).await.unwrap();
        let reply = call(
            &mut slave,
            MsgType(MSG_CONTROL_OP),
            b"\x00\x00\x00\x05check",
        )
        .await
        .unwrap();
        assert_eq!(reply, b"status");
        let err = call(&mut slave, MsgType::EXIT, &[]).await.unwrap_err();
        assert!(matches!(err, CmError::Refused(ref message) if message == "no"));
        master_task.await.unwrap();
    }

    #[test]
    fn an_open_session_round_trips() {
        let request = OpenSession {
            command: vec!["ls".to_string(), "-l".to_string()],
            env: vec!["PATH=/bin".to_string()],
            pty: Some(PtySpec {
                term: "xterm-256color".to_string(),
                columns: 80,
                rows: 24,
                pixel_width: 640,
                pixel_height: 480,
            }),
            forward_agent: true,
        };
        let encoded = request.encode();
        assert_eq!(OpenSession::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn an_open_session_without_pty_round_trips() {
        let request = OpenSession::default();
        let encoded = request.encode();
        assert_eq!(OpenSession::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn an_open_session_decode_refuses_trailing_bytes() {
        let mut encoded = OpenSession::default().encode();
        encoded.push(0);
        assert!(matches!(
            OpenSession::decode(&encoded),
            Err(CmError::Trailing)
        ));
    }

    #[test]
    fn an_open_session_decode_refuses_truncation() {
        let encoded = OpenSession::default().encode();
        assert!(matches!(
            OpenSession::decode(&encoded[..3]),
            Err(CmError::Short)
        ));
    }

    #[test]
    fn an_open_session_decode_refuses_an_oversize_count() {
        // a count of two commands without any string bytes is malformed
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&2u32.to_be_bytes());
        assert!(matches!(OpenSession::decode(&encoded), Err(CmError::Short)));
    }

    #[test]
    fn an_open_forward_round_trips() {
        let forward = OpenForward {
            listen_addr: "127.0.0.1:8080".to_string(),
            target_addr: "example.com:80".to_string(),
        };
        let encoded = forward.encode();
        assert_eq!(OpenForward::decode(&encoded).unwrap(), forward);
    }

    #[test]
    fn an_attach_round_trips_and_refuses_unknown_streams() {
        let attach = Attach {
            token: SessionToken([7u8; 16]),
            stream: StreamKind::Stderr,
        };
        let encoded = attach.encode();
        assert_eq!(encoded.len(), 17);
        assert_eq!(Attach::decode(&encoded).unwrap(), attach);

        let mut garbage = attach.encode();
        garbage[16] = 9;
        assert!(matches!(Attach::decode(&garbage), Err(CmError::Trailing)));
        assert!(matches!(Attach::decode(&garbage[..8]), Err(CmError::Short)));
    }

    #[test]
    fn an_exit_status_round_trips() {
        assert_eq!(encode_exit_status(42).len(), 8);
        assert_eq!(decode_exit_status(&encode_exit_status(42)).unwrap(), 42);
        assert!(matches!(decode_exit_status(&[0u8; 7]), Err(CmError::Short)));
    }

    #[test]
    fn a_window_change_round_trips() {
        let change = WindowChange {
            columns: 120,
            rows: 40,
            pixel_width: 960,
            pixel_height: 640,
        };
        let encoded = change.encode();
        assert_eq!(encoded.len(), 16);
        assert_eq!(WindowChange::decode(&encoded).unwrap(), change);
        assert!(matches!(
            WindowChange::decode(&encoded[..12]),
            Err(CmError::Short)
        ));
    }

    #[test]
    fn a_signal_round_trips() {
        let signal = Signal {
            name: "INT".to_string(),
        };
        let encoded = signal.encode();
        assert_eq!(Signal::decode(&encoded).unwrap(), signal);
        let mut trailing = encoded.clone();
        trailing.push(b'x');
        assert!(matches!(Signal::decode(&trailing), Err(CmError::Trailing)));
        assert!(matches!(Signal::decode(&[]), Err(CmError::Short)));
    }
}
