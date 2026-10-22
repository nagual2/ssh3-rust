//! SSH messages and channel requests.
//!
//! Every message starts with a variable-length integer holding the message
//! type, followed by the fields of the message in a fixed order. The set of
//! messages and their layout is inherited from SSH and is byte-for-byte
//! compatible with the reference implementation `nagual2/ssh3-go`
//! (package `message/`).

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::wire::{
    Ssh3Error, Ssh3Result, append_ssh_bytes, append_var_int, read_bool, read_ssh_bytes,
    read_var_int, ssh_string_len, var_int_len, write_bool,
};

/// Message type of a disconnect notification.
pub const SSH_MSG_DISCONNECT: u64 = 1;
/// Message type of a message that must be ignored.
pub const SSH_MSG_IGNORE: u64 = 2;
/// Message type of an "unimplemented message" notification.
pub const SSH_MSG_UNIMPLEMENTED: u64 = 3;
/// Message type of a debug message.
pub const SSH_MSG_DEBUG: u64 = 4;
/// Message type of a service request.
pub const SSH_MSG_SERVICE_REQUEST: u64 = 5;
/// Message type of a service acceptance.
pub const SSH_MSG_SERVICE_ACCEPT: u64 = 6;
/// Message type of a key exchange initialisation.
pub const SSH_MSG_KEXINIT: u64 = 20;
/// Message type of a "new keys" notification.
pub const SSH_MSG_NEWKEYS: u64 = 21;
/// Message type of a user authentication request.
pub const SSH_MSG_USERAUTH_REQUEST: u64 = 50;
/// Message type of a failed user authentication.
pub const SSH_MSG_USERAUTH_FAILURE: u64 = 51;
/// Message type of a successful user authentication.
pub const SSH_MSG_USERAUTH_SUCCESS: u64 = 52;
/// Message type of an authentication banner.
pub const SSH_MSG_USERAUTH_BANNER: u64 = 53;
/// Message type of a global request.
pub const SSH_MSG_GLOBAL_REQUEST: u64 = 80;
/// Message type of a successful global request.
pub const SSH_MSG_REQUEST_SUCCESS: u64 = 81;
/// Message type of a failed global request.
pub const SSH_MSG_REQUEST_FAILURE: u64 = 82;
/// Message type of a channel open request.
pub const SSH_MSG_CHANNEL_OPEN: u64 = 90;
/// Message type of a channel open confirmation.
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u64 = 91;
/// Message type of a channel open failure.
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u64 = 92;
/// Message type of a window adjustment.
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u64 = 93;
/// Message type of channel data.
pub const SSH_MSG_CHANNEL_DATA: u64 = 94;
/// Message type of channel extended data.
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u64 = 95;
/// Message type of an end-of-file notification.
pub const SSH_MSG_CHANNEL_EOF: u64 = 96;
/// Message type of a channel close notification.
pub const SSH_MSG_CHANNEL_CLOSE: u64 = 97;
/// Message type of a channel request.
pub const SSH_MSG_CHANNEL_REQUEST: u64 = 98;
/// Message type of a successful channel request.
pub const SSH_MSG_CHANNEL_SUCCESS: u64 = 99;
/// Message type of a failed channel request.
pub const SSH_MSG_CHANNEL_FAILURE: u64 = 100;

/// Discriminator of the payload of a data message.
///
/// `0` marks standard data, `1` marks standard error; other values are
/// reserved for additional data streams.
pub type Ssh3DataType = u64;

/// Data type of the standard data stream of a session.
pub const SSH_EXTENDED_DATA_NONE: Ssh3DataType = 0;
/// Data type of the standard error stream of a session.
pub const SSH_EXTENDED_DATA_STDERR: Ssh3DataType = 1;

/// A message that can be exchanged on a channel stream.
///
/// The variants cover the messages that SSH3 sends inside a channel; the
/// remaining SSH message types are negotiated out of band or are not used by
/// SSH3 at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ssh3Message {
    /// A request sent by the client on a channel.
    ChannelRequest(Ssh3ChannelRequestMessage),
    /// The answer of the peer to a channel open request.
    ChannelOpenConfirmation(Ssh3ChannelOpenConfirmationMessage),
    /// The refusal of the peer to a channel open request.
    ChannelOpenFailure(Ssh3ChannelOpenFailureMessage),
    /// Payload data, either standard data or extended data.
    Data(Ssh3DataOrExtendedDataMessage),
}

impl Ssh3Message {
    /// Decodes a message from `reader`.
    ///
    /// The message type is read first; unknown types are rejected with
    /// [`Ssh3Error::UnknownMessageType`].
    pub fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        match read_var_int(reader)? {
            SSH_MSG_CHANNEL_REQUEST => Ok(Self::ChannelRequest(
                Ssh3ChannelRequestMessage::parse_payload(reader)?,
            )),
            SSH_MSG_CHANNEL_OPEN_CONFIRMATION => Ok(Self::ChannelOpenConfirmation(
                Ssh3ChannelOpenConfirmationMessage::parse_payload(reader)?,
            )),
            SSH_MSG_CHANNEL_OPEN_FAILURE => Ok(Self::ChannelOpenFailure(
                Ssh3ChannelOpenFailureMessage::parse_payload(reader)?,
            )),
            SSH_MSG_CHANNEL_DATA => Ok(Self::Data(
                Ssh3DataOrExtendedDataMessage::parse_data_payload(reader)?,
            )),
            SSH_MSG_CHANNEL_EXTENDED_DATA => Ok(Self::Data(
                Ssh3DataOrExtendedDataMessage::parse_extended_payload(reader)?,
            )),
            kind => Err(Ssh3Error::UnknownMessageType(kind)),
        }
    }

    /// Returns the number of bytes [`Ssh3Message::encode`] writes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::ChannelRequest(message) => message.encoded_len(),
            Self::ChannelOpenConfirmation(message) => message.encoded_len(),
            Self::ChannelOpenFailure(message) => message.encoded_len(),
            Self::Data(message) => message.encoded_len(),
        }
    }

    /// Appends the encoded message to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::ChannelRequest(message) => message.encode(out),
            Self::ChannelOpenConfirmation(message) => message.encode(out),
            Self::ChannelOpenFailure(message) => message.encode(out),
            Self::Data(message) => message.encode(out),
        }
    }

    /// Encodes the message into a freshly allocated buffer.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out);
        out
    }
}

/// Confirmation of a channel open request.
///
/// Wire layout: message type `91`, then the maximum packet size the sender is
/// willing to receive, as a variable-length integer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ChannelOpenConfirmationMessage {
    /// Maximum payload size, in bytes, the peer accepts on this channel.
    pub max_packet_size: u64,
}

impl Ssh3ChannelOpenConfirmationMessage {
    fn parse_payload<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            max_packet_size: read_var_int(reader)?,
        })
    }

    /// Returns the number of bytes [`Ssh3ChannelOpenConfirmationMessage::encode`]
    /// writes.
    pub fn encoded_len(&self) -> usize {
        var_int_len(SSH_MSG_CHANNEL_OPEN_CONFIRMATION) + var_int_len(self.max_packet_size)
    }

    /// Appends the encoded message to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        append_var_int(out, self.max_packet_size);
    }
}

/// Refusal of a channel open request.
///
/// Wire layout: message type `92`, then the reason code, the human readable
/// error message and the language tag, each as a variable-length integer or a
/// length-prefixed string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ChannelOpenFailureMessage {
    /// Protocol-specific reason of the refusal.
    pub reason_code: u64,
    /// Human readable description of the refusal, in UTF-8.
    pub error_message_utf8: Vec<u8>,
    /// RFC 1766 language tag of the error message, empty when not set.
    pub language_tag: Vec<u8>,
}

impl Ssh3ChannelOpenFailureMessage {
    fn parse_payload<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            reason_code: read_var_int(reader)?,
            error_message_utf8: read_ssh_bytes(reader)?,
            language_tag: read_ssh_bytes(reader)?,
        })
    }

    /// Returns the number of bytes [`Ssh3ChannelOpenFailureMessage::encode`]
    /// writes.
    pub fn encoded_len(&self) -> usize {
        var_int_len(SSH_MSG_CHANNEL_OPEN_FAILURE)
            + var_int_len(self.reason_code)
            + ssh_string_len(&self.error_message_utf8)
            + ssh_string_len(&self.language_tag)
    }

    /// Appends the encoded message to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, SSH_MSG_CHANNEL_OPEN_FAILURE);
        append_var_int(out, self.reason_code);
        append_ssh_bytes(out, &self.error_message_utf8);
        append_ssh_bytes(out, &self.language_tag);
    }
}

/// Payload of a channel: standard data or extended data.
///
/// Standard data (message type `94`) carries only the payload, extended data
/// (message type `95`) additionally carries the data type before the
/// payload. Both variants are represented by this single type: the data type
/// is [`SSH_EXTENDED_DATA_NONE`] for standard data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3DataOrExtendedDataMessage {
    /// Stream the payload belongs to.
    pub data_type: Ssh3DataType,
    /// Raw payload bytes.
    pub data: Vec<u8>,
}

impl Ssh3DataOrExtendedDataMessage {
    fn parse_data_payload<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            data_type: SSH_EXTENDED_DATA_NONE,
            data: read_ssh_bytes(reader)?,
        })
    }

    fn parse_extended_payload<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            data_type: read_var_int(reader)?,
            data: read_ssh_bytes(reader)?,
        })
    }

    /// Returns the number of bytes [`Ssh3DataOrExtendedDataMessage::encode`]
    /// writes.
    pub fn encoded_len(&self) -> usize {
        if self.data_type == SSH_EXTENDED_DATA_NONE {
            var_int_len(SSH_MSG_CHANNEL_DATA) + ssh_string_len(&self.data)
        } else {
            var_int_len(SSH_MSG_CHANNEL_EXTENDED_DATA)
                + var_int_len(self.data_type)
                + ssh_string_len(&self.data)
        }
    }

    /// Appends the encoded message to `out`.
    ///
    /// The message type is derived from the data type: standard data is
    /// encoded as `94`, every other data type as `95`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        if self.data_type == SSH_EXTENDED_DATA_NONE {
            append_var_int(out, SSH_MSG_CHANNEL_DATA);
        } else {
            append_var_int(out, SSH_MSG_CHANNEL_EXTENDED_DATA);
            append_var_int(out, self.data_type);
        }
        append_ssh_bytes(out, &self.data);
    }
}

/// A request sent by the client on an open channel.
///
/// Wire layout: message type `98`, the request type as a length-prefixed
/// string, the `want_reply` flag as a single byte, then the payload of the
/// request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ChannelRequestMessage {
    /// Whether the peer must answer with a success or failure message.
    pub want_reply: bool,
    /// The request itself.
    pub request: Ssh3ChannelRequest,
}

impl Ssh3ChannelRequestMessage {
    fn parse_payload<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        let request_type = read_ssh_bytes(reader)?;
        let want_reply = read_bool(reader)?;
        let request = Ssh3ChannelRequest::parse(&request_type, reader)?;
        Ok(Self {
            want_reply,
            request,
        })
    }

    /// Returns the number of bytes [`Ssh3ChannelRequestMessage::encode`] writes.
    pub fn encoded_len(&self) -> usize {
        var_int_len(SSH_MSG_CHANNEL_REQUEST)
            + ssh_string_len(self.request.request_type())
            + 1
            + self.request.encoded_payload_len()
    }

    /// Appends the encoded message to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, SSH_MSG_CHANNEL_REQUEST);
        append_ssh_bytes(out, self.request.request_type());
        write_bool(out, self.want_reply);
        self.request.encode_payload(out);
    }
}

/// The request types a client can send on a channel.
///
/// Each variant maps to a fixed request type string; the payload layout of
/// every variant is the one defined by SSH and reproduced by the reference
/// implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ssh3ChannelRequest {
    /// Request a pseudo-terminal (`pty-req`).
    Pty(Ssh3PtyRequest),
    /// Request X11 forwarding (`x11-req`).
    X11(Ssh3X11Request),
    /// Request an interactive shell (`shell`).
    Shell,
    /// Request the execution of a single command (`exec`).
    Exec(Ssh3ExecRequest),
    /// Request a subsystem (`subsystem`).
    Subsystem(Ssh3SubsystemRequest),
    /// Notify the peer about a new terminal size (`window-change`).
    WindowChange(Ssh3WindowChangeRequest),
    /// Deliver a signal to the running process (`signal`).
    Signal(Ssh3SignalRequest),
    /// Report the exit status of a process (`exit-status`).
    ExitStatus(Ssh3ExitStatusRequest),
    /// Report that a process died from a signal (`exit-signal`).
    ExitSignal(Ssh3ExitSignalRequest),
    /// Request a forwarded port (`forward-port`).
    ForwardPort(Ssh3ForwardingRequest),
}

impl Ssh3ChannelRequest {
    fn parse<R: Read>(request_type: &[u8], reader: &mut R) -> Ssh3Result<Self> {
        match request_type {
            b"pty-req" => Ok(Self::Pty(Ssh3PtyRequest::parse(reader)?)),
            b"x11-req" => Ok(Self::X11(Ssh3X11Request::parse(reader)?)),
            b"shell" => Ok(Self::Shell),
            b"exec" => Ok(Self::Exec(Ssh3ExecRequest::parse(reader)?)),
            b"subsystem" => Ok(Self::Subsystem(Ssh3SubsystemRequest::parse(reader)?)),
            b"window-change" => Ok(Self::WindowChange(Ssh3WindowChangeRequest::parse(reader)?)),
            b"signal" => Ok(Self::Signal(Ssh3SignalRequest::parse(reader)?)),
            b"exit-status" => Ok(Self::ExitStatus(Ssh3ExitStatusRequest::parse(reader)?)),
            b"exit-signal" => Ok(Self::ExitSignal(Ssh3ExitSignalRequest::parse(reader)?)),
            b"forward-port" => Ok(Self::ForwardPort(Ssh3ForwardingRequest::parse(reader)?)),
            _ => Err(Ssh3Error::UnknownRequestType(request_type.to_vec())),
        }
    }

    fn request_type(&self) -> &'static [u8] {
        match self {
            Self::Pty(_) => b"pty-req",
            Self::X11(_) => b"x11-req",
            Self::Shell => b"shell",
            Self::Exec(_) => b"exec",
            Self::Subsystem(_) => b"subsystem",
            Self::WindowChange(_) => b"window-change",
            Self::Signal(_) => b"signal",
            Self::ExitStatus(_) => b"exit-status",
            Self::ExitSignal(_) => b"exit-signal",
            Self::ForwardPort(_) => b"forward-port",
        }
    }

    fn encoded_payload_len(&self) -> usize {
        match self {
            Self::Pty(request) => request.encoded_len(),
            Self::X11(request) => request.encoded_len(),
            Self::Shell => 0,
            Self::Exec(request) => request.encoded_len(),
            Self::Subsystem(request) => request.encoded_len(),
            Self::WindowChange(request) => request.encoded_len(),
            Self::Signal(request) => request.encoded_len(),
            Self::ExitStatus(request) => request.encoded_len(),
            Self::ExitSignal(request) => request.encoded_len(),
            Self::ForwardPort(request) => request.encoded_len(),
        }
    }

    fn encode_payload(&self, out: &mut Vec<u8>) {
        match self {
            Self::Pty(request) => request.encode(out),
            Self::X11(request) => request.encode(out),
            Self::Shell => {}
            Self::Exec(request) => request.encode(out),
            Self::Subsystem(request) => request.encode(out),
            Self::WindowChange(request) => request.encode(out),
            Self::Signal(request) => request.encode(out),
            Self::ExitStatus(request) => request.encode(out),
            Self::ExitSignal(request) => request.encode(out),
            Self::ForwardPort(request) => request.encode(out),
        }
    }
}

/// Request of a pseudo-terminal for a session (`pty-req`).
///
/// Wire layout: the terminal type, the character and pixel size of the
/// terminal and the encoded terminal modes, in that order. Sizes are
/// transmitted as variable-length integers and are truncated to 16 bit by the
/// receivers that talk to a real terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3PtyRequest {
    /// Value of the `TERM` environment variable, for example `vt100`.
    pub term: Vec<u8>,
    /// Width of the terminal, in characters.
    pub char_width: u64,
    /// Height of the terminal, in characters.
    pub char_height: u64,
    /// Width of the terminal, in pixels.
    pub pixel_width: u64,
    /// Height of the terminal, in pixels.
    pub pixel_height: u64,
    /// Terminal modes, encoded as in SSH.
    pub encoded_terminal_modes: Vec<u8>,
}

impl Ssh3PtyRequest {
    fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            term: read_ssh_bytes(reader)?,
            char_width: read_var_int(reader)?,
            char_height: read_var_int(reader)?,
            pixel_width: read_var_int(reader)?,
            pixel_height: read_var_int(reader)?,
            encoded_terminal_modes: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.term)
            + var_int_len(self.char_width)
            + var_int_len(self.char_height)
            + var_int_len(self.pixel_width)
            + var_int_len(self.pixel_height)
            + ssh_string_len(&self.encoded_terminal_modes)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.term);
        append_var_int(out, self.char_width);
        append_var_int(out, self.char_height);
        append_var_int(out, self.pixel_width);
        append_var_int(out, self.pixel_height);
        append_ssh_bytes(out, &self.encoded_terminal_modes);
    }
}

/// Request of X11 forwarding for a session (`x11-req`).
///
/// Wire layout: the "single connection" flag as a single byte, the
/// authentication protocol, the authentication cookie and the screen number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3X11Request {
    /// Whether only a single X11 connection is forwarded.
    pub single_connection: bool,
    /// Name of the X11 authentication protocol, for example `MIT-MAGIC-COOKIE-1`.
    pub x11_authentication_protocol: Vec<u8>,
    /// Cookie the peer must present to the X11 server.
    pub x11_authentication_cookie: Vec<u8>,
    /// Screen of the X11 display that is forwarded.
    pub x11_screen_number: u64,
}

impl Ssh3X11Request {
    fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            single_connection: read_bool(reader)?,
            x11_authentication_protocol: read_ssh_bytes(reader)?,
            x11_authentication_cookie: read_ssh_bytes(reader)?,
            x11_screen_number: read_var_int(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        1 + ssh_string_len(&self.x11_authentication_protocol)
            + ssh_string_len(&self.x11_authentication_cookie)
            + var_int_len(self.x11_screen_number)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        write_bool(out, self.single_connection);
        append_ssh_bytes(out, &self.x11_authentication_protocol);
        append_ssh_bytes(out, &self.x11_authentication_cookie);
        append_var_int(out, self.x11_screen_number);
    }
}

/// Request to run a single command instead of a shell (`exec`).
///
/// Wire layout: the command line as a length-prefixed string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ExecRequest {
    /// The command line to execute.
    pub command: Vec<u8>,
}

impl Ssh3ExecRequest {
    fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            command: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.command)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.command);
    }
}

/// Request to run a subsystem instead of a shell (`subsystem`).
///
/// Wire layout: the name of the subsystem as a length-prefixed string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3SubsystemRequest {
    /// Name of the subsystem, for example `sftp`.
    pub subsystem_name: Vec<u8>,
}

impl Ssh3SubsystemRequest {
    fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            subsystem_name: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.subsystem_name)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.subsystem_name);
    }
}

/// Notification about a new terminal size (`window-change`).
///
/// Wire layout: the character and pixel size of the terminal, in that order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3WindowChangeRequest {
    /// New width of the terminal, in characters.
    pub char_width: u64,
    /// New height of the terminal, in characters.
    pub char_height: u64,
    /// New width of the terminal, in pixels.
    pub pixel_width: u64,
    /// New height of the terminal, in pixels.
    pub pixel_height: u64,
}

impl Ssh3WindowChangeRequest {
    fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            char_width: read_var_int(reader)?,
            char_height: read_var_int(reader)?,
            pixel_width: read_var_int(reader)?,
            pixel_height: read_var_int(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        var_int_len(self.char_width)
            + var_int_len(self.char_height)
            + var_int_len(self.pixel_width)
            + var_int_len(self.pixel_height)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, self.char_width);
        append_var_int(out, self.char_height);
        append_var_int(out, self.pixel_width);
        append_var_int(out, self.pixel_height);
    }
}

/// Delivery of a signal to the running process (`signal`).
///
/// Wire layout: the name of the signal as a length-prefixed string, without
/// the `SIG` prefix, for example `TERM`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3SignalRequest {
    /// Name of the signal, with or without the `SIG` prefix.
    pub signal_name_without_sig: Vec<u8>,
}

impl Ssh3SignalRequest {
    fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            signal_name_without_sig: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.signal_name_without_sig)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.signal_name_without_sig);
    }
}

/// Report of the exit status of a process (`exit-status`).
///
/// Wire layout: the exit code as a variable-length integer. A process that
/// died from a signal is reported with `exit-signal` instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ExitStatusRequest {
    /// Exit code of the process.
    pub exit_status: u64,
}

impl Ssh3ExitStatusRequest {
    fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            exit_status: read_var_int(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        var_int_len(self.exit_status)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_var_int(out, self.exit_status);
    }
}

/// Report that a process was killed by a signal (`exit-signal`).
///
/// Wire layout: the name of the signal, the "core dumped" flag, the error
/// message and the language tag, in that order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ExitSignalRequest {
    /// Name of the signal, with or without the `SIG` prefix.
    pub signal_name_without_sig: Vec<u8>,
    /// Whether the process dumped core.
    pub core_dumped: bool,
    /// Human readable description, in UTF-8.
    pub error_message_utf8: Vec<u8>,
    /// RFC 1766 language tag of the error message, empty when not set.
    pub language_tag: Vec<u8>,
}

impl Ssh3ExitSignalRequest {
    fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        Ok(Self {
            signal_name_without_sig: read_ssh_bytes(reader)?,
            core_dumped: read_bool(reader)?,
            error_message_utf8: read_ssh_bytes(reader)?,
            language_tag: read_ssh_bytes(reader)?,
        })
    }

    fn encoded_len(&self) -> usize {
        ssh_string_len(&self.signal_name_without_sig)
            + 1
            + ssh_string_len(&self.error_message_utf8)
            + ssh_string_len(&self.language_tag)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        append_ssh_bytes(out, &self.signal_name_without_sig);
        write_bool(out, self.core_dumped);
        append_ssh_bytes(out, &self.error_message_utf8);
        append_ssh_bytes(out, &self.language_tag);
    }
}

/// Protocol of a forwarded port.
///
/// The discriminant is the value used on the wire, so the numbering is fixed
/// by the reference implementation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Ssh3ForwardingProtocol {
    /// UDP forwarding.
    Udp = 0,
    /// TCP forwarding.
    Tcp = 1,
}

impl Ssh3ForwardingProtocol {
    pub(crate) fn as_u64(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for Ssh3ForwardingProtocol {
    type Error = Ssh3Error;

    fn try_from(value: u64) -> Ssh3Result<Self> {
        match value {
            0 => Ok(Self::Udp),
            1 => Ok(Self::Tcp),
            _ => Err(Ssh3Error::InvalidForwardingProtocol(value)),
        }
    }
}

/// Address family of a forwarded port.
///
/// The discriminant is the value used on the wire and determines how many
/// address octets follow it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Ssh3ForwardingAddressFamily {
    /// IPv4, followed by 4 address octets.
    Ipv4 = 4,
    /// IPv6, followed by 16 address octets.
    Ipv6 = 6,
}

impl Ssh3ForwardingAddressFamily {
    pub(crate) fn octet_len(self) -> usize {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 16,
        }
    }

    pub(crate) fn as_u64(self) -> u64 {
        self as u64
    }

    pub(crate) fn from_ip(ip_address: IpAddr) -> Self {
        match ip_address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

impl TryFrom<u64> for Ssh3ForwardingAddressFamily {
    type Error = Ssh3Error;

    fn try_from(value: u64) -> Ssh3Result<Self> {
        match value {
            4 => Ok(Self::Ipv4),
            6 => Ok(Self::Ipv6),
            _ => Err(Ssh3Error::InvalidAddressFamily(value)),
        }
    }
}

/// Request to forward a port of the server (`forward-port`).
///
/// Wire layout: the address family, the protocol, the address octets and the
/// port in network byte order.
///
/// The reference implementation writes the address family before the protocol
/// (`nagual2/ssh3-go`, `message/channel_request.go`, `ForwardingRequest.Write`)
/// and reads the protocol before the address family (`ParseForwardingRequest`).
/// The encoder follows the order of the reference encoder, and the decoder
/// accepts both orders: the protocol is `0` or `1` and the address family is
/// `4` or `6`, so the two values never collide and the order of the first
/// field tells which one comes next.
///
/// The request type is an extension of the Rust implementation: the reference
/// implementation has no `forward-port` entry in its map of the channel
/// request types, so a reference peer refuses the request by its type name
/// before it looks at the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ForwardingRequest {
    /// Transport protocol of the forwarded port.
    pub protocol: Ssh3ForwardingProtocol,
    /// Address the server shall connect to.
    pub ip_address: IpAddr,
    /// Port the server shall connect to, in host byte order.
    pub port: u16,
}

impl Ssh3ForwardingRequest {
    fn parse<R: Read>(reader: &mut R) -> Ssh3Result<Self> {
        let (protocol, family) = Self::parse_protocol_and_family(reader)?;
        let mut octets = vec![0; family.octet_len()];
        reader.read_exact(&mut octets)?;
        let ip_address = match family {
            Ssh3ForwardingAddressFamily::Ipv4 => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap()))
            }
            Ssh3ForwardingAddressFamily::Ipv6 => {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap()))
            }
        };

        let mut port = [0; 2];
        reader.read_exact(&mut port)?;
        Ok(Self {
            protocol,
            ip_address,
            port: u16::from_be_bytes(port),
        })
    }

    /// Reads the protocol and the address family of a forwarding request.
    ///
    /// The first field tells which one comes first: the protocol is `0`
    /// (UDP) or `1` (TCP), the address family is `4` (IPv4) or `6` (IPv6).
    /// Both orders are accepted, so a payload written by the encoder of the
    /// reference implementation and a payload written by its parser are both
    /// read back correctly.
    fn parse_protocol_and_family<R: Read>(
        reader: &mut R,
    ) -> Ssh3Result<(Ssh3ForwardingProtocol, Ssh3ForwardingAddressFamily)> {
        let first = read_var_int(reader)?;
        match first {
            0 | 1 => {
                let protocol = Ssh3ForwardingProtocol::try_from(first)?;
                let family = Ssh3ForwardingAddressFamily::try_from(read_var_int(reader)?)?;
                Ok((protocol, family))
            }
            4 | 6 => {
                let family = Ssh3ForwardingAddressFamily::try_from(first)?;
                let protocol = Ssh3ForwardingProtocol::try_from(read_var_int(reader)?)?;
                Ok((protocol, family))
            }
            other => Err(Ssh3Error::InvalidForwardingProtocol(other)),
        }
    }

    fn encoded_len(&self) -> usize {
        let family = Ssh3ForwardingAddressFamily::from_ip(self.ip_address);
        var_int_len(self.protocol.as_u64()) + var_int_len(family.as_u64()) + family.octet_len() + 2
    }

    fn encode(&self, out: &mut Vec<u8>) {
        let family = Ssh3ForwardingAddressFamily::from_ip(self.ip_address);
        append_var_int(out, family.as_u64());
        append_var_int(out, self.protocol.as_u64());
        match self.ip_address {
            IpAddr::V4(address) => out.extend_from_slice(&address.octets()),
            IpAddr::V6(address) => out.extend_from_slice(&address.octets()),
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        SSH_EXTENDED_DATA_NONE, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA,
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_REQUEST,
        Ssh3ChannelOpenConfirmationMessage, Ssh3ChannelOpenFailureMessage, Ssh3ChannelRequest,
        Ssh3ChannelRequestMessage, Ssh3DataOrExtendedDataMessage, Ssh3ExecRequest,
        Ssh3ExitSignalRequest, Ssh3ExitStatusRequest, Ssh3ForwardingProtocol,
        Ssh3ForwardingRequest, Ssh3Message, Ssh3PtyRequest, Ssh3SignalRequest,
        Ssh3SubsystemRequest, Ssh3WindowChangeRequest, Ssh3X11Request,
    };
    use crate::wire::{append_ssh_bytes, append_var_int, write_bool};

    const EXTENDED_DATA_TYPE: u64 = 10_000_000;

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn parse_message(bytes: &[u8]) -> Ssh3Message {
        Ssh3Message::parse(&mut Cursor::new(bytes)).unwrap()
    }

    fn encode_request_bytes(request_type: &[u8], want_reply: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        append_var_int(&mut out, SSH_MSG_CHANNEL_REQUEST);
        append_ssh_bytes(&mut out, request_type);
        write_bool(&mut out, want_reply);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_and_writes_data_messages() {
        let large_data = patterned_bytes(128 * 1024);
        let cases = [
            Vec::from(b"hello, world!".as_slice()),
            Vec::new(),
            large_data,
        ];

        for data in cases {
            let message = Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
                data_type: SSH_EXTENDED_DATA_NONE,
                data: data.clone(),
            });
            let mut expected = Vec::new();
            append_var_int(&mut expected, SSH_MSG_CHANNEL_DATA);
            append_ssh_bytes(&mut expected, &data);

            assert_eq!(message.encoded_len(), expected.len());
            assert_eq!(message.to_vec(), expected);
            assert_eq!(parse_message(&expected), message);
        }
    }

    #[test]
    fn parses_and_writes_extended_data_messages() {
        let large_data = patterned_bytes(128 * 1024);
        let cases = [
            Vec::from(b"hello, world!".as_slice()),
            Vec::new(),
            large_data,
        ];

        for data in cases {
            let message = Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
                data_type: EXTENDED_DATA_TYPE,
                data: data.clone(),
            });
            let mut expected = Vec::new();
            append_var_int(&mut expected, SSH_MSG_CHANNEL_EXTENDED_DATA);
            append_var_int(&mut expected, EXTENDED_DATA_TYPE);
            append_ssh_bytes(&mut expected, &data);

            assert_eq!(message.encoded_len(), expected.len());
            assert_eq!(message.to_vec(), expected);
            assert_eq!(parse_message(&expected), message);
        }
    }

    #[test]
    fn parses_and_writes_channel_request_messages() {
        let large_bytes = patterned_bytes(1024);
        let term = large_bytes[..100].to_vec();
        let encoded_modes = large_bytes[100..600].to_vec();
        let x11_protocol = large_bytes[..100].to_vec();
        let x11_cookie = large_bytes[100..500].to_vec();
        let exec_command = large_bytes.clone();
        let subsystem_name = large_bytes.clone();
        let signal_name = large_bytes.clone();
        let exit_signal_name = large_bytes[..100].to_vec();
        let error_message = large_bytes[100..500].to_vec();
        let language_tag = large_bytes[500..700].to_vec();

        let pty_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &term);
            append_var_int(&mut payload, 9_001);
            append_var_int(&mut payload, 9_002);
            append_var_int(&mut payload, 9_003);
            append_var_int(&mut payload, 9_004);
            append_ssh_bytes(&mut payload, &encoded_modes);
            payload
        };
        let pty_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Pty(Ssh3PtyRequest {
                term,
                char_width: 9_001,
                char_height: 9_002,
                pixel_width: 9_003,
                pixel_height: 9_004,
                encoded_terminal_modes: encoded_modes,
            }),
        });
        let pty_bytes = encode_request_bytes(b"pty-req", true, &pty_payload);

        let x11_payload = {
            let mut payload = Vec::new();
            write_bool(&mut payload, false);
            append_ssh_bytes(&mut payload, &x11_protocol);
            append_ssh_bytes(&mut payload, &x11_cookie);
            append_var_int(&mut payload, 4_096);
            payload
        };
        let x11_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::X11(Ssh3X11Request {
                single_connection: false,
                x11_authentication_protocol: x11_protocol,
                x11_authentication_cookie: x11_cookie,
                x11_screen_number: 4_096,
            }),
        });
        let x11_bytes = encode_request_bytes(b"x11-req", false, &x11_payload);

        let shell_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Shell,
        });
        let shell_bytes = encode_request_bytes(b"shell", true, &[]);

        let exec_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &exec_command);
            payload
        };
        let exec_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::Exec(Ssh3ExecRequest {
                command: exec_command,
            }),
        });
        let exec_bytes = encode_request_bytes(b"exec", false, &exec_payload);

        let subsystem_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &subsystem_name);
            payload
        };
        let subsystem_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Subsystem(Ssh3SubsystemRequest { subsystem_name }),
        });
        let subsystem_bytes = encode_request_bytes(b"subsystem", true, &subsystem_payload);

        let window_change_payload = {
            let mut payload = Vec::new();
            append_var_int(&mut payload, 80);
            append_var_int(&mut payload, 24);
            append_var_int(&mut payload, 1_280);
            append_var_int(&mut payload, 720);
            payload
        };
        let window_change_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::WindowChange(Ssh3WindowChangeRequest {
                char_width: 80,
                char_height: 24,
                pixel_width: 1_280,
                pixel_height: 720,
            }),
        });
        let window_change_bytes =
            encode_request_bytes(b"window-change", false, &window_change_payload);

        let signal_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &signal_name);
            payload
        };
        let signal_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Signal(Ssh3SignalRequest {
                signal_name_without_sig: signal_name,
            }),
        });
        let signal_bytes = encode_request_bytes(b"signal", true, &signal_payload);

        let exit_status_payload = {
            let mut payload = Vec::new();
            append_var_int(&mut payload, 255);
            payload
        };
        let exit_status_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::ExitStatus(Ssh3ExitStatusRequest { exit_status: 255 }),
        });
        let exit_status_bytes = encode_request_bytes(b"exit-status", false, &exit_status_payload);

        let exit_signal_payload = {
            let mut payload = Vec::new();
            append_ssh_bytes(&mut payload, &exit_signal_name);
            write_bool(&mut payload, true);
            append_ssh_bytes(&mut payload, &error_message);
            append_ssh_bytes(&mut payload, &language_tag);
            payload
        };
        let exit_signal_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::ExitSignal(Ssh3ExitSignalRequest {
                signal_name_without_sig: exit_signal_name,
                core_dumped: true,
                error_message_utf8: error_message,
                language_tag,
            }),
        });
        let exit_signal_bytes = encode_request_bytes(b"exit-signal", true, &exit_signal_payload);

        let forwarding_payload = {
            let mut payload = Vec::new();
            append_var_int(&mut payload, 4);
            append_var_int(&mut payload, Ssh3ForwardingProtocol::Tcp as u64);
            payload.extend_from_slice(&[192, 0, 2, 10]);
            payload.extend_from_slice(&443u16.to_be_bytes());
            payload
        };
        let forwarding_message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::ForwardPort(Ssh3ForwardingRequest {
                protocol: Ssh3ForwardingProtocol::Tcp,
                ip_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 443,
            }),
        });
        let forwarding_bytes = encode_request_bytes(b"forward-port", false, &forwarding_payload);

        let cases = [
            (pty_message, pty_bytes),
            (x11_message, x11_bytes),
            (shell_message, shell_bytes),
            (exec_message, exec_bytes),
            (subsystem_message, subsystem_bytes),
            (window_change_message, window_change_bytes),
            (signal_message, signal_bytes),
            (exit_status_message, exit_status_bytes),
            (exit_signal_message, exit_signal_bytes),
            (forwarding_message, forwarding_bytes),
        ];

        for (message, expected_bytes) in cases {
            assert_eq!(message.encoded_len(), expected_bytes.len());
            assert_eq!(message.to_vec(), expected_bytes);
            assert_eq!(parse_message(&expected_bytes), message);
        }
    }

    #[test]
    fn parses_and_writes_channel_open_confirmation_messages() {
        let message = Ssh3Message::ChannelOpenConfirmation(Ssh3ChannelOpenConfirmationMessage {
            max_packet_size: 32_768,
        });
        let mut expected = Vec::new();
        append_var_int(&mut expected, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        append_var_int(&mut expected, 32_768);

        assert_eq!(message.encoded_len(), expected.len());
        assert_eq!(message.to_vec(), expected);
        assert_eq!(parse_message(&expected), message);
    }

    #[test]
    fn parses_and_writes_channel_open_failure_messages() {
        let error_message = patterned_bytes(100);
        let language_tag = patterned_bytes(32);
        let message = Ssh3Message::ChannelOpenFailure(Ssh3ChannelOpenFailureMessage {
            reason_code: 4_096,
            error_message_utf8: error_message.clone(),
            language_tag: language_tag.clone(),
        });
        let mut expected = Vec::new();
        append_var_int(&mut expected, SSH_MSG_CHANNEL_OPEN_FAILURE);
        append_var_int(&mut expected, 4_096);
        append_ssh_bytes(&mut expected, &error_message);
        append_ssh_bytes(&mut expected, &language_tag);

        assert_eq!(message.encoded_len(), expected.len());
        assert_eq!(message.to_vec(), expected);
        assert_eq!(parse_message(&expected), message);
    }

    /// The encoder of the reference implementation writes the address family
    /// before the protocol (`message/channel_request.go`,
    /// `ForwardingRequest.Write`).
    #[test]
    fn writes_the_forwarding_request_in_the_order_of_the_reference_encoder() {
        let message = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::ForwardPort(Ssh3ForwardingRequest {
                protocol: Ssh3ForwardingProtocol::Tcp,
                ip_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 443,
            }),
        });

        let mut expected = Vec::new();
        append_var_int(&mut expected, SSH_MSG_CHANNEL_REQUEST);
        append_ssh_bytes(&mut expected, b"forward-port");
        write_bool(&mut expected, false);
        // The address family comes first, then the protocol.
        append_var_int(&mut expected, 4);
        append_var_int(&mut expected, 1);
        expected.extend_from_slice(&[192, 0, 2, 10]);
        expected.extend_from_slice(&443u16.to_be_bytes());

        assert_eq!(message.encoded_len(), expected.len());
        assert_eq!(message.to_vec(), expected);
        assert_eq!(parse_message(&expected), message);
    }

    /// The parser of the reference implementation reads the protocol before
    /// the address family (`message/channel_request.go`,
    /// `ParseForwardingRequest`): a payload written in that order must still
    /// be read back correctly.
    #[test]
    fn reads_the_forwarding_request_in_the_order_of_the_reference_parser() {
        let mut payload = Vec::new();
        append_var_int(&mut payload, 1);
        append_var_int(&mut payload, 4);
        payload.extend_from_slice(&[192, 0, 2, 10]);
        payload.extend_from_slice(&443u16.to_be_bytes());

        let bytes = encode_request_bytes(b"forward-port", false, &payload);
        let expected = Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
            want_reply: false,
            request: Ssh3ChannelRequest::ForwardPort(Ssh3ForwardingRequest {
                protocol: Ssh3ForwardingProtocol::Tcp,
                ip_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 443,
            }),
        });
        assert_eq!(parse_message(&bytes), expected);
    }
}
