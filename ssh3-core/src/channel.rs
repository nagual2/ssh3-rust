//! Channels of a conversation: the framing of the SSH messages they carry.
//!
//! A channel multiplexes three kinds of traffic over a pair of streams: SSH
//! messages (requests, data, confirmations), datagrams and the channel
//! header that identifies the channel inside its conversation.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ssh3_proto::{
    SSH_EXTENDED_DATA_NONE, Ssh3ChannelHeader, Ssh3ChannelOpenConfirmationMessage,
    Ssh3ChannelOpenFailureMessage, Ssh3ChannelRequestMessage, Ssh3DataOrExtendedDataMessage,
    Ssh3DataType, Ssh3Message,
};
use tokio::sync::Mutex as AsyncMutex;

use crate::conversation::{Ssh3ConversationDatagramSender, Ssh3ConversationId};
use crate::queue::Ssh3DatagramQueue;
use crate::transport::{Ssh3ReceiveStream, Ssh3SendStream};

/// Static description of a channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ChannelInfo {
    /// Maximum payload size, in bytes, the peer accepts on this channel.
    pub max_packet_size: u64,
    /// Id of the stream the channel belongs to.
    pub conversation_stream_id: u64,
    /// Id of the conversation the channel belongs to.
    pub conversation_id: Ssh3ConversationId,
    /// Id of the channel inside its conversation.
    pub channel_id: u64,
    /// Type of the channel, for example `session` or `direct-tcp`.
    pub channel_type: Vec<u8>,
}

/// A channel that the peer opened and that was accepted by the local side.
///
/// Forwarding channels carry the address the peer asked the server to
/// connect to; plain channels do not.
#[derive(Clone)]
pub enum Ssh3AcceptedChannel {
    /// A plain channel, for example a `session` channel.
    Channel(Arc<Ssh3Channel>),
    /// A channel that forwards datagrams to a remote UDP endpoint.
    UdpForwarding {
        /// The underlying channel.
        channel: Arc<Ssh3Channel>,
        /// Address the server shall forward the datagrams to.
        remote_addr: SocketAddr,
    },
    /// A channel that forwards a byte stream to a remote TCP endpoint.
    TcpForwarding {
        /// The underlying channel.
        channel: Arc<Ssh3Channel>,
        /// Address the server shall forward the stream to.
        remote_addr: SocketAddr,
    },
}

impl Ssh3AcceptedChannel {
    /// Returns the underlying channel.
    pub fn channel(&self) -> &Arc<Ssh3Channel> {
        match self {
            Self::Channel(channel)
            | Self::UdpForwarding { channel, .. }
            | Self::TcpForwarding { channel, .. } => channel,
        }
    }

    /// Consumes the value and returns the underlying channel.
    pub fn into_channel(self) -> Arc<Ssh3Channel> {
        match self {
            Self::Channel(channel)
            | Self::UdpForwarding { channel, .. }
            | Self::TcpForwarding { channel, .. } => channel,
        }
    }

    /// Returns the forwarding target, or `None` for a plain channel.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Channel(_) => None,
            Self::UdpForwarding { remote_addr, .. } | Self::TcpForwarding { remote_addr, .. } => {
                Some(*remote_addr)
            }
        }
    }
}

impl From<Arc<Ssh3Channel>> for Ssh3AcceptedChannel {
    fn from(value: Arc<Ssh3Channel>) -> Self {
        Self::Channel(value)
    }
}

/// The refusal of the peer to open a channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3ChannelOpenFailure {
    /// Protocol-specific reason of the refusal.
    pub reason_code: u64,
    /// Human readable description of the refusal, in UTF-8.
    pub error_message_utf8: Vec<u8>,
}

impl fmt::Display for Ssh3ChannelOpenFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "channel open failure: reason {}: {}",
            self.reason_code,
            String::from_utf8_lossy(&self.error_message_utf8)
        )
    }
}

impl std::error::Error for Ssh3ChannelOpenFailure {}

/// A message that arrived before the channel was confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3MessageOnNonConfirmedChannel {
    /// The message that was received too early.
    pub message: Ssh3Message,
}

impl fmt::Display for Ssh3MessageOnNonConfirmedChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "message {:?} received on a non-confirmed channel",
            self.message
        )
    }
}

impl std::error::Error for Ssh3MessageOnNonConfirmedChannel {}

/// A datagram that was sent on a channel that has no datagram transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3SentDatagramOnNonDatagramChannel {
    /// Id of the offending channel.
    pub channel_id: u64,
}

impl fmt::Display for Ssh3SentDatagramOnNonDatagramChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "datagram sent on non-datagram channel {}",
            self.channel_id
        )
    }
}

impl std::error::Error for Ssh3SentDatagramOnNonDatagramChannel {}

/// Everything that can fail while a channel is used.
#[derive(Debug)]
pub enum Ssh3ChannelError {
    /// The underlying stream failed.
    Io(io::Error),
    /// The peer sent a message that could not be decoded.
    Proto(ssh3_proto::Ssh3Error),
    /// The peer refused to open the channel.
    OpenFailure(Ssh3ChannelOpenFailure),
    /// A message arrived before the channel was confirmed.
    NonConfirmed(Ssh3MessageOnNonConfirmedChannel),
    /// A datagram was sent on a channel without a datagram transport.
    DatagramSenderMissing(Ssh3SentDatagramOnNonDatagramChannel),
    /// The negotiated maximum packet size leaves no room for the payload.
    MaxPacketSizeTooSmall {
        /// The negotiated maximum packet size, in bytes.
        max_packet_size: u64,
        /// Size of the message overhead, in bytes.
        message_overhead: usize,
    },
}

impl fmt::Display for Ssh3ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Proto(err) => write!(f, "{err}"),
            Self::OpenFailure(err) => write!(f, "{err}"),
            Self::NonConfirmed(err) => write!(f, "{err}"),
            Self::DatagramSenderMissing(err) => write!(f, "{err}"),
            Self::MaxPacketSizeTooSmall {
                max_packet_size,
                message_overhead,
            } => write!(
                f,
                "max packet size {} is too small for message overhead {}",
                max_packet_size, message_overhead
            ),
        }
    }
}

impl std::error::Error for Ssh3ChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Proto(err) => Some(err),
            Self::OpenFailure(err) => Some(err),
            Self::NonConfirmed(err) => Some(err),
            Self::DatagramSenderMissing(err) => Some(err),
            Self::MaxPacketSizeTooSmall { .. } => None,
        }
    }
}

impl From<io::Error> for Ssh3ChannelError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ssh3_proto::Ssh3Error> for Ssh3ChannelError {
    fn from(value: ssh3_proto::Ssh3Error) -> Self {
        Self::Proto(value)
    }
}

/// A channel inside a conversation.
///
/// The channel owns the pair of streams that carry its SSH messages, keeps
/// track of the confirmation handshake and, for datagram channels, holds the
/// queue of datagrams that were not consumed yet.
pub struct Ssh3Channel {
    info: Ssh3ChannelInfo,
    confirm_sent: AtomicBool,
    confirm_received: AtomicBool,
    header: Mutex<Option<Vec<u8>>>,
    datagram_sender: RwLock<Option<Arc<Ssh3ConversationDatagramSender>>>,
    recv: AsyncMutex<Box<dyn Ssh3ReceiveStream>>,
    send: AsyncMutex<Box<dyn Ssh3SendStream>>,
    datagrams_queue: RwLock<Arc<Ssh3DatagramQueue>>,
}

impl Ssh3Channel {
    /// Creates a channel.
    ///
    /// `send_header` decides whether the channel header is written before the
    /// first message, `confirm_sent` and `confirm_received` record the state
    /// of the confirmation handshake, and `additional_header_bytes` carries
    /// the target address of a forwarded channel.
    #[allow(clippy::too_many_arguments)]
    pub fn new<R, W>(
        conversation_stream_id: u64,
        conversation_id: Ssh3ConversationId,
        channel_id: u64,
        channel_type: impl Into<Vec<u8>>,
        max_packet_size: u64,
        recv: R,
        send: W,
        datagram_sender: Option<Arc<Ssh3ConversationDatagramSender>>,
        send_header: bool,
        confirm_sent: bool,
        confirm_received: bool,
        datagrams_queue_size: usize,
        additional_header_bytes: Option<&[u8]>,
    ) -> Self
    where
        R: Ssh3ReceiveStream + 'static,
        W: Ssh3SendStream + 'static,
    {
        let channel_type = channel_type.into();
        let header = send_header.then(|| {
            Ssh3ChannelHeader {
                conversation_stream_id,
                channel_type: channel_type.clone(),
                max_packet_size,
            }
            .encode(additional_header_bytes)
        });

        Self {
            info: Ssh3ChannelInfo {
                max_packet_size,
                conversation_stream_id,
                conversation_id,
                channel_id,
                channel_type,
            },
            confirm_sent: AtomicBool::new(confirm_sent),
            confirm_received: AtomicBool::new(confirm_received),
            header: Mutex::new(header),
            datagram_sender: RwLock::new(datagram_sender),
            recv: AsyncMutex::new(Box::new(recv)),
            send: AsyncMutex::new(Box::new(send)),
            datagrams_queue: RwLock::new(Arc::new(Ssh3DatagramQueue::new(datagrams_queue_size))),
        }
    }

    /// Returns the static description of the channel.
    pub fn info(&self) -> &Ssh3ChannelInfo {
        &self.info
    }

    /// Returns the id of the channel inside its conversation.
    pub fn channel_id(&self) -> u64 {
        self.info.channel_id
    }

    /// Returns the id of the conversation the channel belongs to.
    pub fn conversation_id(&self) -> Ssh3ConversationId {
        self.info.conversation_id
    }

    /// Returns the id of the stream the channel belongs to.
    pub fn conversation_stream_id(&self) -> u64 {
        self.info.conversation_stream_id
    }

    /// Returns the maximum payload size, in bytes, accepted on the channel.
    pub fn max_packet_size(&self) -> u64 {
        self.info.max_packet_size
    }

    /// Returns the type of the channel, for example `session`.
    pub fn channel_type(&self) -> &[u8] {
        &self.info.channel_type
    }

    /// Returns `true` once the peer confirmed the channel.
    pub fn confirm_received(&self) -> bool {
        self.confirm_received.load(Ordering::SeqCst)
    }

    /// Waits until the peer confirms the channel.
    ///
    /// Fails with [`Ssh3ChannelError::OpenFailure`] when the peer refuses the
    /// channel and with [`Ssh3ChannelError::NonConfirmed`] when it sends an
    /// unexpected message instead of a confirmation.
    pub async fn wait_for_confirmation(&self) -> Result<(), Ssh3ChannelError> {
        if self.confirm_received() {
            return Ok(());
        }

        let message = {
            let mut recv = self.recv.lock().await;
            parse_message(recv.as_mut()).await?
        };

        match message {
            Ssh3Message::ChannelOpenConfirmation(_) => {
                self.confirm_received.store(true, Ordering::SeqCst);
                Ok(())
            }
            Ssh3Message::ChannelOpenFailure(message) => {
                Err(Ssh3ChannelError::OpenFailure(Ssh3ChannelOpenFailure {
                    reason_code: message.reason_code,
                    error_message_utf8: message.error_message_utf8,
                }))
            }
            other => Err(Ssh3ChannelError::NonConfirmed(
                Ssh3MessageOnNonConfirmedChannel { message: other },
            )),
        }
    }

    /// Reads the next message from the channel.
    ///
    /// A confirmation message is consumed silently: it only updates the
    /// confirmation state. Any other message is returned to the caller.
    pub async fn next_message(&self) -> Result<Ssh3Message, Ssh3ChannelError> {
        loop {
            let message = {
                let mut recv = self.recv.lock().await;
                parse_message(recv.as_mut()).await?
            };

            match message {
                Ssh3Message::ChannelOpenConfirmation(_) => {
                    self.confirm_received.store(true, Ordering::SeqCst);
                    continue;
                }
                Ssh3Message::ChannelOpenFailure(message) => {
                    return Err(Ssh3ChannelError::OpenFailure(Ssh3ChannelOpenFailure {
                        reason_code: message.reason_code,
                        error_message_utf8: message.error_message_utf8,
                    }));
                }
                other => {
                    if !self.confirm_sent.load(Ordering::SeqCst) {
                        return Err(Ssh3ChannelError::NonConfirmed(
                            Ssh3MessageOnNonConfirmedChannel { message: other },
                        ));
                    }
                    return Ok(other);
                }
            }
        }
    }

    /// Writes the channel header, unless it was already written.
    ///
    /// The header is sent at most once per channel, before the first message.
    pub async fn maybe_send_header(&self) -> Result<(), Ssh3ChannelError> {
        let header = self.header.lock().unwrap().take();
        if let Some(header) = header {
            let mut send = self.send.lock().await;
            send.write_all(&header).await?;
        }
        Ok(())
    }

    /// Writes payload data to the channel.
    ///
    /// The payload is split into chunks that fit into the negotiated maximum
    /// packet size. Returns the number of bytes written, including the
    /// framing of the data messages.
    pub async fn write_data(
        &self,
        data_buf: &[u8],
        data_type: Ssh3DataType,
    ) -> Result<usize, Ssh3ChannelError> {
        self.maybe_send_header().await?;

        let empty = Ssh3DataOrExtendedDataMessage {
            data_type,
            data: Vec::new(),
        };
        let overhead = empty.encoded_len();
        let max_payload = self
            .info
            .max_packet_size
            .checked_sub(overhead as u64)
            .ok_or(Ssh3ChannelError::MaxPacketSizeTooSmall {
                max_packet_size: self.info.max_packet_size,
                message_overhead: overhead,
            })? as usize;

        let mut written = 0;
        let mut send = self.send.lock().await;
        for chunk in data_buf.chunks(max_payload.max(1)) {
            let message = Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
                data_type,
                data: chunk.to_vec(),
            });
            let encoded = message.to_vec();
            send.write_all(&encoded).await?;
            written += encoded.len();
        }
        Ok(written)
    }

    /// Confirms the channel to the peer with the given maximum packet size.
    pub async fn confirm_channel(&self, max_packet_size: u64) -> Result<(), Ssh3ChannelError> {
        self.send_message(Ssh3Message::ChannelOpenConfirmation(
            Ssh3ChannelOpenConfirmationMessage { max_packet_size },
        ))
        .await?;
        self.confirm_sent.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Sends a message to the peer.
    pub async fn send_message(&self, message: Ssh3Message) -> Result<(), Ssh3ChannelError> {
        self.maybe_send_header().await?;
        let mut send = self.send.lock().await;
        send.write_all(&message.to_vec()).await?;
        Ok(())
    }

    /// Appends a datagram to the queue, waiting until the queue has room.
    pub async fn wait_add_datagram(&self, datagram: Vec<u8>) {
        let queue = self.datagrams_queue.read().unwrap().clone();
        queue.wait_add(datagram).await;
    }

    /// Appends a datagram to the queue without waiting.
    ///
    /// Returns `false` when the queue is full and the datagram was dropped.
    pub fn add_datagram(&self, datagram: Vec<u8>) -> bool {
        self.datagrams_queue.read().unwrap().add(datagram)
    }

    /// Waits for the next datagram of the channel.
    pub async fn receive_datagram(&self) -> Vec<u8> {
        let queue = self.datagrams_queue.read().unwrap().clone();
        queue.wait_next().await
    }

    /// Sends a datagram to the peer.
    ///
    /// Fails with [`Ssh3ChannelError::DatagramSenderMissing`] when the channel
    /// was opened without a datagram transport.
    pub async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Ssh3ChannelError> {
        self.maybe_send_header().await?;
        let sender = self.datagram_sender.read().unwrap().clone().ok_or(
            Ssh3ChannelError::DatagramSenderMissing(Ssh3SentDatagramOnNonDatagramChannel {
                channel_id: self.channel_id(),
            }),
        )?;
        sender.send(datagram).await?;
        Ok(())
    }

    /// Sends a channel request to the peer.
    pub async fn send_request(
        &self,
        request: Ssh3ChannelRequestMessage,
    ) -> Result<(), Ssh3ChannelError> {
        self.send_message(Ssh3Message::ChannelRequest(request))
            .await
    }

    /// Aborts a pending read on the channel.
    pub async fn cancel_read(&self) {
        self.recv.lock().await.cancel_read(42);
    }

    /// Closes the write side of the channel.
    pub async fn close(&self) -> Result<(), Ssh3ChannelError> {
        self.send.lock().await.close().await?;
        Ok(())
    }

    /// Attaches the datagram transport of the conversation to the channel.
    pub fn set_datagram_sender(&self, datagram_sender: Arc<Ssh3ConversationDatagramSender>) {
        *self.datagram_sender.write().unwrap() = Some(datagram_sender);
    }

    /// Replaces the datagram queue of the channel.
    ///
    /// Used to hand over the datagrams that arrived before the channel was
    /// registered.
    pub fn set_datagram_queue(&self, queue: Arc<Ssh3DatagramQueue>) {
        *self.datagrams_queue.write().unwrap() = queue;
    }
}

async fn parse_message(recv: &mut dyn Ssh3ReceiveStream) -> Result<Ssh3Message, Ssh3ChannelError> {
    let message_type = read_var_int(recv).await?;
    Ok(match message_type {
        ssh3_proto::SSH_MSG_CHANNEL_REQUEST => {
            Ssh3Message::ChannelRequest(read_channel_request(recv).await?)
        }
        ssh3_proto::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
            Ssh3Message::ChannelOpenConfirmation(Ssh3ChannelOpenConfirmationMessage {
                max_packet_size: read_var_int(recv).await?,
            })
        }
        ssh3_proto::SSH_MSG_CHANNEL_OPEN_FAILURE => {
            Ssh3Message::ChannelOpenFailure(Ssh3ChannelOpenFailureMessage {
                reason_code: read_var_int(recv).await?,
                error_message_utf8: read_ssh_bytes(recv).await?,
                language_tag: read_ssh_bytes(recv).await?,
            })
        }
        ssh3_proto::SSH_MSG_CHANNEL_DATA => Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
            data_type: SSH_EXTENDED_DATA_NONE,
            data: read_ssh_bytes(recv).await?,
        }),
        ssh3_proto::SSH_MSG_CHANNEL_EXTENDED_DATA => {
            Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
                data_type: read_var_int(recv).await?,
                data: read_ssh_bytes(recv).await?,
            })
        }
        kind => {
            return Err(Ssh3ChannelError::Proto(
                ssh3_proto::Ssh3Error::UnknownMessageType(kind),
            ));
        }
    })
}

async fn read_channel_request(
    recv: &mut dyn Ssh3ReceiveStream,
) -> Result<Ssh3ChannelRequestMessage, Ssh3ChannelError> {
    let request_type = read_ssh_bytes(recv).await?;
    let want_reply = read_bool(recv).await?;
    let request = match request_type.as_slice() {
        b"pty-req" => ssh3_proto::Ssh3ChannelRequest::Pty(ssh3_proto::Ssh3PtyRequest {
            term: read_ssh_bytes(recv).await?,
            char_width: read_var_int(recv).await?,
            char_height: read_var_int(recv).await?,
            pixel_width: read_var_int(recv).await?,
            pixel_height: read_var_int(recv).await?,
            encoded_terminal_modes: read_ssh_bytes(recv).await?,
        }),
        b"x11-req" => ssh3_proto::Ssh3ChannelRequest::X11(ssh3_proto::Ssh3X11Request {
            single_connection: read_bool(recv).await?,
            x11_authentication_protocol: read_ssh_bytes(recv).await?,
            x11_authentication_cookie: read_ssh_bytes(recv).await?,
            x11_screen_number: read_var_int(recv).await?,
        }),
        b"shell" => ssh3_proto::Ssh3ChannelRequest::Shell,
        b"exec" => ssh3_proto::Ssh3ChannelRequest::Exec(ssh3_proto::Ssh3ExecRequest {
            command: read_ssh_bytes(recv).await?,
        }),
        b"subsystem" => {
            ssh3_proto::Ssh3ChannelRequest::Subsystem(ssh3_proto::Ssh3SubsystemRequest {
                subsystem_name: read_ssh_bytes(recv).await?,
            })
        }
        b"window-change" => {
            ssh3_proto::Ssh3ChannelRequest::WindowChange(ssh3_proto::Ssh3WindowChangeRequest {
                char_width: read_var_int(recv).await?,
                char_height: read_var_int(recv).await?,
                pixel_width: read_var_int(recv).await?,
                pixel_height: read_var_int(recv).await?,
            })
        }
        b"signal" => ssh3_proto::Ssh3ChannelRequest::Signal(ssh3_proto::Ssh3SignalRequest {
            signal_name_without_sig: read_ssh_bytes(recv).await?,
        }),
        b"exit-status" => {
            ssh3_proto::Ssh3ChannelRequest::ExitStatus(ssh3_proto::Ssh3ExitStatusRequest {
                exit_status: read_var_int(recv).await?,
            })
        }
        b"exit-signal" => {
            ssh3_proto::Ssh3ChannelRequest::ExitSignal(ssh3_proto::Ssh3ExitSignalRequest {
                signal_name_without_sig: read_ssh_bytes(recv).await?,
                core_dumped: read_bool(recv).await?,
                error_message_utf8: read_ssh_bytes(recv).await?,
                language_tag: read_ssh_bytes(recv).await?,
            })
        }
        b"forward-port" => {
            let protocol = ssh3_proto::Ssh3ForwardingProtocol::try_from(read_var_int(recv).await?)?;
            let family =
                ssh3_proto::Ssh3ForwardingAddressFamily::try_from(read_var_int(recv).await?)?;
            let mut octets = vec![
                0;
                match family {
                    ssh3_proto::Ssh3ForwardingAddressFamily::Ipv4 => 4,
                    ssh3_proto::Ssh3ForwardingAddressFamily::Ipv6 => 16,
                }
            ];
            recv.read_exact(&mut octets).await?;
            let mut port = [0; 2];
            recv.read_exact(&mut port).await?;
            ssh3_proto::Ssh3ChannelRequest::ForwardPort(ssh3_proto::Ssh3ForwardingRequest {
                protocol,
                ip_address: match family {
                    ssh3_proto::Ssh3ForwardingAddressFamily::Ipv4 => std::net::IpAddr::V4(
                        std::net::Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap()),
                    ),
                    ssh3_proto::Ssh3ForwardingAddressFamily::Ipv6 => std::net::IpAddr::V6(
                        std::net::Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap()),
                    ),
                },
                port: u16::from_be_bytes(port),
            })
        }
        _ => {
            return Err(Ssh3ChannelError::Proto(
                ssh3_proto::Ssh3Error::UnknownRequestType(request_type),
            ));
        }
    };
    Ok(Ssh3ChannelRequestMessage {
        want_reply,
        request,
    })
}

async fn read_var_int(recv: &mut dyn Ssh3ReceiveStream) -> Result<u64, Ssh3ChannelError> {
    let first_byte = read_byte(recv).await?;
    let len = 1 << ((first_byte & 0xc0) >> 6);
    let b1 = first_byte & 0x3f;
    if len == 1 {
        return Ok(u64::from(b1));
    }

    let b2 = read_byte(recv).await?;
    if len == 2 {
        return Ok(u64::from(b2) + (u64::from(b1) << 8));
    }

    let b3 = read_byte(recv).await?;
    let b4 = read_byte(recv).await?;
    if len == 4 {
        return Ok(u64::from(b4)
            + (u64::from(b3) << 8)
            + (u64::from(b2) << 16)
            + (u64::from(b1) << 24));
    }

    let b5 = read_byte(recv).await?;
    let b6 = read_byte(recv).await?;
    let b7 = read_byte(recv).await?;
    let b8 = read_byte(recv).await?;
    Ok(u64::from(b8)
        + (u64::from(b7) << 8)
        + (u64::from(b6) << 16)
        + (u64::from(b5) << 24)
        + (u64::from(b4) << 32)
        + (u64::from(b3) << 40)
        + (u64::from(b2) << 48)
        + (u64::from(b1) << 56))
}

async fn read_ssh_bytes(recv: &mut dyn Ssh3ReceiveStream) -> Result<Vec<u8>, Ssh3ChannelError> {
    let len = read_var_int(recv).await?;
    let len = usize::try_from(len)
        .map_err(|_| Ssh3ChannelError::Proto(ssh3_proto::Ssh3Error::InvalidLength(len)))?;
    let mut out = vec![0; len];
    recv.read_exact(&mut out).await?;
    Ok(out)
}

async fn read_bool(recv: &mut dyn Ssh3ReceiveStream) -> Result<bool, Ssh3ChannelError> {
    match read_byte(recv).await? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(Ssh3ChannelError::Proto(ssh3_proto::Ssh3Error::InvalidBool(
            value,
        ))),
    }
}

async fn read_byte(recv: &mut dyn Ssh3ReceiveStream) -> Result<u8, Ssh3ChannelError> {
    let mut byte = [0; 1];
    recv.read_exact(&mut byte).await?;
    Ok(byte[0])
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ssh3_proto::{
        Ssh3ChannelHeader, Ssh3ChannelRequest, Ssh3ChannelRequestMessage, Ssh3Message,
        Ssh3SignalRequest, append_var_int,
    };

    use super::{Ssh3Channel, Ssh3ChannelError};
    use crate::conversation::Ssh3ConversationDatagramSender;
    use crate::transport::testutil::{
        BytesReceiveStream, RecordingDatagramSender, RecordingSendStream,
    };

    fn conversation_id() -> [u8; 32] {
        [7; 32]
    }

    #[tokio::test]
    async fn write_data_sends_header_once_and_chunks_payload() {
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();
        let channel = Ssh3Channel::new(
            11,
            conversation_id(),
            22,
            b"session".to_vec(),
            5,
            recv,
            send,
            None,
            true,
            true,
            true,
            4,
            None,
        );

        let written = channel
            .write_data(b"abcdefg", ssh3_proto::SSH_EXTENDED_DATA_NONE)
            .await
            .unwrap();
        let mut expected = Ssh3ChannelHeader {
            conversation_stream_id: 11,
            channel_type: b"session".to_vec(),
            max_packet_size: 5,
        }
        .encode(None);
        let header_len = expected.len();
        for chunk in [
            b"ab".as_slice(),
            b"cd".as_slice(),
            b"ef".as_slice(),
            b"g".as_slice(),
        ] {
            expected.extend_from_slice(
                &Ssh3Message::Data(ssh3_proto::Ssh3DataOrExtendedDataMessage {
                    data_type: ssh3_proto::SSH_EXTENDED_DATA_NONE,
                    data: chunk.to_vec(),
                })
                .to_vec(),
            );
        }

        assert_eq!(written, expected.len() - header_len);
        assert_eq!(handle.bytes(), expected);
    }

    #[tokio::test]
    async fn next_message_handles_confirmation_then_returns_message() {
        let mut recv_bytes =
            Ssh3Message::ChannelOpenConfirmation(ssh3_proto::Ssh3ChannelOpenConfirmationMessage {
                max_packet_size: 4096,
            })
            .to_vec();
        recv_bytes.extend_from_slice(
            &Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
                want_reply: true,
                request: Ssh3ChannelRequest::Signal(Ssh3SignalRequest {
                    signal_name_without_sig: b"TERM".to_vec(),
                }),
            })
            .to_vec(),
        );

        let (recv, _) = BytesReceiveStream::new(recv_bytes);
        let (send, _) = RecordingSendStream::new();
        let channel = Ssh3Channel::new(
            1,
            conversation_id(),
            2,
            b"session".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            true,
            false,
            4,
            None,
        );

        let message = channel.next_message().await.unwrap();
        assert!(channel.confirm_received());
        assert_eq!(
            message,
            Ssh3Message::ChannelRequest(Ssh3ChannelRequestMessage {
                want_reply: true,
                request: Ssh3ChannelRequest::Signal(Ssh3SignalRequest {
                    signal_name_without_sig: b"TERM".to_vec(),
                }),
            })
        );
    }

    #[tokio::test]
    async fn next_message_returns_non_confirmed_error() {
        let recv_bytes = Ssh3Message::Data(ssh3_proto::Ssh3DataOrExtendedDataMessage {
            data_type: ssh3_proto::SSH_EXTENDED_DATA_NONE,
            data: b"hello".to_vec(),
        })
        .to_vec();
        let (recv, _) = BytesReceiveStream::new(recv_bytes);
        let (send, _) = RecordingSendStream::new();
        let channel = Ssh3Channel::new(
            1,
            conversation_id(),
            2,
            b"session".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            false,
            true,
            4,
            None,
        );

        match channel.next_message().await {
            Err(Ssh3ChannelError::NonConfirmed(_)) => {}
            other => panic!("expected non-confirmed error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_datagram_uses_conversation_sender() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, _) = RecordingSendStream::new();
        let channel = Ssh3Channel::new(
            11,
            conversation_id(),
            22,
            b"direct-udp".to_vec(),
            1024,
            recv,
            send,
            Some(Arc::new(Ssh3ConversationDatagramSender::new(
                11,
                22,
                sender.clone(),
            ))),
            false,
            true,
            true,
            4,
            None,
        );

        channel.send_datagram(vec![9, 8, 7]).await.unwrap();

        let mut expected = Vec::new();
        append_var_int(&mut expected, 11);
        append_var_int(&mut expected, 22);
        expected.extend_from_slice(&[9, 8, 7]);
        assert_eq!(sender.datagrams(), vec![expected]);
    }
}
