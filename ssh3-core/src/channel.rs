//! Channels of a conversation: the framing of the SSH messages they carry.
//!
//! A channel multiplexes three kinds of traffic over a pair of streams: SSH
//! messages (requests, data, confirmations), datagrams and the channel
//! header that identifies the channel inside its conversation.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use ssh3_proto::{
    SSH_EXTENDED_DATA_NONE, Ssh3ChannelHeader, Ssh3ChannelOpenConfirmationMessage,
    Ssh3ChannelOpenFailureMessage, Ssh3ChannelRequestMessage, Ssh3DataOrExtendedDataMessage,
    Ssh3DataType, Ssh3Message,
};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

use crate::conversation::{Ssh3ConversationDatagramSender, Ssh3ConversationId};
use crate::queue::Ssh3DatagramQueue;
use crate::transport::{Ssh3ReceiveStream, Ssh3SendStream};

/// Smallest maximum packet size a channel may negotiate, in bytes.
///
/// Below this value the outbound chunk size (the maximum packet size minus
/// the length of the data frame header) underflows and the write loop stops
/// making progress, and a read buffer of that size would starve the channel
/// anyway.
pub const MIN_MAX_PACKET_SIZE: u64 = 4096;

/// Largest maximum packet size a peer may announce, in bytes.
///
/// The value is bounded by the maximum length of an SSH string, the largest
/// payload a channel may carry.
pub const MAX_MAX_PACKET_SIZE: u64 = ssh3_proto::MAX_SSH_STRING_LEN;

/// Capacity of the queue of messages the reader task fills.
const MESSAGE_QUEUE_CAPACITY: usize = 32;

/// Error code sent to the peer when a read is cancelled.
const CANCEL_READ_ERROR_CODE: u64 = 42;

/// Floors the maximum packet size a local endpoint announces.
///
/// The floor is applied where the channel is built, so the invariant that
/// the maximum packet size exceeds the length of the data frame header holds
/// for every caller instead of depending on the call sites.
pub fn clamp_local_max_packet_size(local: u64) -> u64 {
    local.max(MIN_MAX_PACKET_SIZE)
}

/// Bounds the maximum packet size a peer announces.
///
/// The value of the peer is floored at [`MIN_MAX_PACKET_SIZE`] and capped by
/// the value the local endpoint announces: the peer must not pick the size
/// of the buffers of the local endpoint, and the channel would starve with a
/// packet size below the floor.
pub fn clamp_peer_max_packet_size(peer: u64, local: u64) -> u64 {
    peer.max(MIN_MAX_PACKET_SIZE).min(local)
}

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
    /// Maximum packet size the peer announced, once it is known.
    peer_max_packet_size: AtomicU64,
    header: Mutex<Option<Vec<u8>>>,
    datagram_sender: RwLock<Option<Arc<Ssh3ConversationDatagramSender>>>,
    recv: Ssh3Recv,
    send: AsyncMutex<Box<dyn Ssh3SendStream>>,
    datagrams_queue: RwLock<Arc<Ssh3DatagramQueue>>,
}

/// The receive side of a channel.
///
/// The stream is read by a dedicated task that owns it and hands the parsed
/// messages over a queue. The task never holds a lock of the channel while it
/// waits for the peer, so a pending read can always be cancelled and the
/// writers of the channel are never blocked by a silent peer.
struct Ssh3Recv {
    /// State shared with the reader task.
    shared: Arc<Ssh3RecvShared>,
    /// Queue of the messages the reader task parsed.
    queue: AsyncMutex<mpsc::Receiver<Result<Ssh3Message, Ssh3ChannelError>>>,
    /// The stream, moved into the reader task when it starts.
    stream: Mutex<Option<Box<dyn Ssh3ReceiveStream>>>,
    /// Whether the reader task was already started.
    started: AtomicBool,
}

/// The state the reader task shares with the channel.
struct Ssh3RecvShared {
    /// Sender of the queue of parsed messages.
    sender: mpsc::Sender<Result<Ssh3Message, Ssh3ChannelError>>,
    /// Set when the caller cancelled the read.
    cancelled: AtomicBool,
    /// Set when the channel is being dropped.
    closing: AtomicBool,
    /// Set when the reader task ended.
    finished: AtomicBool,
    /// Wakes the reader task when the read is cancelled.
    notify: Notify,
}

impl Ssh3RecvShared {
    /// Returns `true` when the reader task must stop.
    fn stop_requested(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst) || self.closing.load(Ordering::SeqCst)
    }
}

impl Ssh3Recv {
    /// Creates the receive side of a channel.
    fn new(recv: Box<dyn Ssh3ReceiveStream>) -> Self {
        let (sender, queue) = mpsc::channel(MESSAGE_QUEUE_CAPACITY);
        Self {
            shared: Arc::new(Ssh3RecvShared {
                sender,
                cancelled: AtomicBool::new(false),
                closing: AtomicBool::new(false),
                finished: AtomicBool::new(false),
                notify: Notify::new(),
            }),
            queue: AsyncMutex::new(queue),
            stream: Mutex::new(Some(recv)),
            started: AtomicBool::new(false),
        }
    }

    /// Cancels the pending read.
    ///
    /// The reader task is woken up so it can abort the read of the transport,
    /// and the waiters are woken up with an error.
    fn cancel(&self) {
        self.shared.cancelled.store(true, Ordering::SeqCst);
        self.shared.notify.notify_waiters();
        let _ = self.shared.sender.try_send(Err(cancelled_error()));
    }

    /// Stops the reader task without reporting an error to the waiters.
    fn close(&self) {
        self.shared.closing.store(true, Ordering::SeqCst);
        self.shared.notify.notify_waiters();
    }
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
        // The floor is applied where the channel is built, so the value that
        // reaches the header and the channel info is always usable.
        let max_packet_size = clamp_local_max_packet_size(max_packet_size);
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
            peer_max_packet_size: AtomicU64::new(MAX_MAX_PACKET_SIZE),
            header: Mutex::new(header),
            datagram_sender: RwLock::new(datagram_sender),
            recv: Ssh3Recv::new(Box::new(recv)),
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
        self.start_reader()?;

        let message = self.next_queued_message().await?;

        match message {
            Ssh3Message::ChannelOpenConfirmation(confirmation) => {
                self.confirm_received.store(true, Ordering::SeqCst);
                self.apply_peer_max_packet_size(confirmation.max_packet_size);
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
        self.start_reader()?;

        loop {
            let message = self.next_queued_message().await?;

            match message {
                Ssh3Message::ChannelOpenConfirmation(confirmation) => {
                    self.confirm_received.store(true, Ordering::SeqCst);
                    self.apply_peer_max_packet_size(confirmation.max_packet_size);
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

    /// Starts the task that reads the stream of the channel.
    ///
    /// The task owns the stream, so it can be cancelled while it waits for
    /// the peer. It is started once, when the first message is requested.
    fn start_reader(&self) -> Result<(), Ssh3ChannelError> {
        // The lock of the stream serializes the start: the task that owns
        // the stream is started exactly once.
        let mut stream = self.recv.stream.lock().unwrap();
        if self.recv.started.load(Ordering::SeqCst) {
            return Ok(());
        }

        let Some(taken) = stream.take() else {
            return Err(Ssh3ChannelError::Io(io::Error::other(
                "the stream of the channel is already gone",
            )));
        };
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle,
            Err(_) => {
                // The stream is given back: the reader can be started later.
                *stream = Some(taken);
                return Err(Ssh3ChannelError::Io(io::Error::other(
                    "a tokio runtime is needed to read the channel",
                )));
            }
        };

        self.recv.started.store(true, Ordering::SeqCst);
        let shared = Arc::downgrade(&self.recv.shared);
        let sender = self.recv.shared.sender.clone();
        handle.spawn(read_messages(shared, taken, sender));
        Ok(())
    }

    /// Returns the next message the reader task parsed.
    async fn next_queued_message(&self) -> Result<Ssh3Message, Ssh3ChannelError> {
        let mut queue = self.recv.queue.lock().await;
        loop {
            if self.recv.shared.cancelled.load(Ordering::SeqCst) {
                return Err(cancelled_error());
            }
            match queue.try_recv() {
                Ok(message) => return message,
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => return Err(finished_error()),
            }
            if self.recv.shared.finished.load(Ordering::SeqCst) {
                return Err(finished_error());
            }

            // The notification is registered before the state is checked
            // again, so an end of the stream that happens in between is not
            // missed.
            let notified = self.recv.shared.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match queue.try_recv() {
                Ok(message) => return message,
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => return Err(finished_error()),
            }
            if self.recv.shared.cancelled.load(Ordering::SeqCst) {
                return Err(cancelled_error());
            }
            if self.recv.shared.finished.load(Ordering::SeqCst) {
                return Err(finished_error());
            }

            tokio::select! {
                biased;
                _ = &mut notified => continue,
                message = queue.recv() => {
                    return match message {
                        Some(message) => message,
                        None => Err(finished_error()),
                    };
                }
            }
        }
    }

    /// Records the maximum packet size the peer announced.
    fn apply_peer_max_packet_size(&self, peer: u64) {
        let clamped = clamp_peer_max_packet_size(peer, self.info.max_packet_size);
        self.peer_max_packet_size.store(clamped, Ordering::SeqCst);
    }

    /// Returns the maximum packet size the channel may use for its frames.
    ///
    /// It is the smallest of the value the local endpoint announced and the
    /// value the peer announced, so a frame never exceeds what the peer
    /// accepts.
    fn negotiated_max_packet_size(&self) -> u64 {
        self.peer_max_packet_size
            .load(Ordering::SeqCst)
            .min(self.info.max_packet_size)
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
    /// packet size, so a frame never exceeds what the peer accepts. Returns
    /// the number of bytes written, including the framing of the data
    /// messages.
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
        let max_packet_size = self.negotiated_max_packet_size();
        let max_payload = max_packet_size.checked_sub(overhead as u64).ok_or(
            Ssh3ChannelError::MaxPacketSizeTooSmall {
                max_packet_size,
                message_overhead: overhead,
            },
        )? as usize;

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
    ///
    /// The call returns as soon as the cancellation is signalled: the read of
    /// the transport is aborted by the task that owns the stream, and the
    /// pending call that waits for a message returns an error.
    pub async fn cancel_read(&self) {
        self.recv.cancel();
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

impl Drop for Ssh3Channel {
    fn drop(&mut self) {
        // Stop the task that reads the stream: it holds the stream of the
        // channel and would otherwise wait for a peer that is gone.
        self.recv.close();
    }
}

/// Reads the messages of a channel and hands them over to the waiters.
///
/// The task owns the stream of the channel, so it can abort the read of the
/// transport when the read is cancelled. It never holds a lock of the channel
/// while it waits for the peer.
async fn read_messages(
    shared: Weak<Ssh3RecvShared>,
    mut stream: Box<dyn Ssh3ReceiveStream>,
    sender: mpsc::Sender<Result<Ssh3Message, Ssh3ChannelError>>,
) {
    let mut cancelled = false;

    loop {
        let Some(state) = shared.upgrade() else {
            break;
        };
        if state.stop_requested() {
            break;
        }

        // The notification is registered before the state is checked again,
        // so a cancellation that happens in between is not missed.
        let notified = state.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if state.stop_requested() {
            break;
        }

        let message = tokio::select! {
            biased;
            _ = &mut notified => {
                cancelled = true;
                break;
            }
            result = parse_message(stream.as_mut()) => result,
        };

        match message {
            Ok(message) => {
                let notified = state.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let sent = tokio::select! {
                    biased;
                    _ = &mut notified => {
                        cancelled = true;
                        break;
                    }
                    result = sender.send(Ok(message)) => result.is_ok(),
                };
                if !sent {
                    break;
                }
            }
            Err(err) => {
                let _ = sender.try_send(Err(err));
                break;
            }
        }
    }

    if cancelled {
        // The peer is told that the read was aborted instead of waiting for
        // a message that will never arrive.
        stream.cancel_read(CANCEL_READ_ERROR_CODE);
    }

    if let Some(state) = shared.upgrade() {
        state.finished.store(true, Ordering::SeqCst);
        // The waiters that are still waiting for a message are woken up: the
        // stream of the channel is over.
        state.notify.notify_waiters();
    }
}

/// Returns the error reported when a read was cancelled.
fn cancelled_error() -> Ssh3ChannelError {
    Ssh3ChannelError::Io(io::Error::new(
        io::ErrorKind::Interrupted,
        "the read of the channel was cancelled",
    ))
}

/// Returns the error reported when the stream of the channel ended.
fn finished_error() -> Ssh3ChannelError {
    Ssh3ChannelError::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the stream of the channel ended",
    ))
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
        ssh3_proto::SSH_MSG_CHANNEL_DATA_COMPRESSED => {
            // the frame carries its algorithm, so the decode needs no
            // negotiation of its own, exactly like the reference
            // implementation (message.ParseCompressedDataMessage)
            let algorithm = read_var_int(recv).await?;
            let packed = read_ssh_bytes(recv).await?;
            let data = crate::compress::decompress(algorithm, &packed).map_err(|err| {
                Ssh3ChannelError::Proto(ssh3_proto::Ssh3Error::Compression(err.to_string()))
            })?;
            Ssh3Message::Data(Ssh3DataOrExtendedDataMessage {
                data_type: SSH_EXTENDED_DATA_NONE,
                data,
            })
        }
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
            // The protocol is `0` or `1` and the address family is `4` or
            // `6`, so the first field tells which one comes first: both the
            // order of the encoder and the order of the parser of the
            // reference implementation are accepted.
            let first = read_var_int(recv).await?;
            let (protocol, family) = match first {
                0 | 1 => (
                    ssh3_proto::Ssh3ForwardingProtocol::try_from(first)?,
                    ssh3_proto::Ssh3ForwardingAddressFamily::try_from(read_var_int(recv).await?)?,
                ),
                4 | 6 => (
                    ssh3_proto::Ssh3ForwardingProtocol::try_from(read_var_int(recv).await?)?,
                    ssh3_proto::Ssh3ForwardingAddressFamily::try_from(first)?,
                ),
                other => {
                    return Err(Ssh3ChannelError::Proto(
                        ssh3_proto::Ssh3Error::InvalidForwardingProtocol(other),
                    ));
                }
            };
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
    // The length is chosen by the peer: refuse it before allocating, so a
    // hostile peer cannot make the process allocate an arbitrary buffer.
    if len > ssh3_proto::MAX_SSH_STRING_LEN {
        return Err(Ssh3ChannelError::Proto(
            ssh3_proto::Ssh3Error::StringTooLong {
                length: len,
                limit: ssh3_proto::MAX_SSH_STRING_LEN,
            },
        ));
    }
    let len = usize::try_from(len)
        .map_err(|_| Ssh3ChannelError::Proto(ssh3_proto::Ssh3Error::InvalidLength(len)))?;
    let mut out = vec![0; len];
    recv.read_exact(&mut out).await?;
    Ok(out)
}

/// Reads a boolean field of a message.
///
/// A boolean is encoded as a single byte: `0` is false and every other byte
/// is true, the semantics of the reference implementation
/// (`nagual2/ssh3-go`), where the field is decoded with `encoding/binary`
/// into a `bool`.
async fn read_bool(recv: &mut dyn Ssh3ReceiveStream) -> Result<bool, Ssh3ChannelError> {
    let value = read_byte(recv).await?;
    Ok(value != 0)
}

async fn read_byte(recv: &mut dyn Ssh3ReceiveStream) -> Result<u8, Ssh3ChannelError> {
    let mut byte = [0; 1];
    recv.read_exact(&mut byte).await?;
    Ok(byte[0])
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use ssh3_proto::{
        SSH_MSG_CHANNEL_DATA, Ssh3ChannelHeader, Ssh3ChannelRequest, Ssh3ChannelRequestMessage,
        Ssh3Message, Ssh3SignalRequest, append_var_int,
    };

    use super::{
        MIN_MAX_PACKET_SIZE, Ssh3Channel, Ssh3ChannelError, clamp_local_max_packet_size,
        clamp_peer_max_packet_size, parse_message,
    };
    use crate::conversation::Ssh3ConversationDatagramSender;
    use crate::transport::Ssh3ReceiveStream;
    use crate::transport::testutil::{
        BytesReceiveStream, RecordingDatagramSender, RecordingSendStream,
    };

    fn conversation_id() -> [u8; 32] {
        [7; 32]
    }

    /// A receive stream that never delivers a byte until it is cancelled.
    struct BlockingReceiveStream {
        cancelled: Arc<AtomicBool>,
        codes: Arc<Mutex<Vec<u64>>>,
    }

    impl BlockingReceiveStream {
        fn new() -> (Self, Arc<Mutex<Vec<u64>>>) {
            let codes = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    cancelled: Arc::new(AtomicBool::new(false)),
                    codes: codes.clone(),
                },
                codes,
            )
        }
    }

    #[async_trait]
    impl Ssh3ReceiveStream for BlockingReceiveStream {
        async fn read_exact(&mut self, _buf: &mut [u8]) -> io::Result<()> {
            while !self.cancelled.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(io::Error::new(io::ErrorKind::Interrupted, "read cancelled"))
        }

        fn cancel_read(&mut self, error_code: u64) {
            self.codes.lock().unwrap().push(error_code);
            self.cancelled.store(true, Ordering::SeqCst);
        }
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
            MIN_MAX_PACKET_SIZE,
            recv,
            send,
            None,
            true,
            true,
            true,
            4,
            None,
        );

        // The payload is split into chunks that fit into the negotiated
        // maximum packet size.
        let overhead = ssh3_proto::Ssh3DataOrExtendedDataMessage {
            data_type: ssh3_proto::SSH_EXTENDED_DATA_NONE,
            data: Vec::new(),
        }
        .encoded_len() as u64;
        let chunk_size = (MIN_MAX_PACKET_SIZE - overhead) as usize;
        let payload: Vec<u8> = (0..chunk_size * 2 + 5).map(|i| i as u8).collect();

        let written = channel
            .write_data(&payload, ssh3_proto::SSH_EXTENDED_DATA_NONE)
            .await
            .unwrap();
        let mut expected = Ssh3ChannelHeader {
            conversation_stream_id: 11,
            channel_type: b"session".to_vec(),
            max_packet_size: MIN_MAX_PACKET_SIZE,
        }
        .encode(None);
        let header_len = expected.len();
        for chunk in payload.chunks(chunk_size) {
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
    async fn local_max_packet_size_is_floored_at_construction() {
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

        assert_eq!(channel.max_packet_size(), MIN_MAX_PACKET_SIZE);
        let header = Ssh3ChannelHeader {
            conversation_stream_id: 11,
            channel_type: b"session".to_vec(),
            max_packet_size: MIN_MAX_PACKET_SIZE,
        }
        .encode(None);
        channel.maybe_send_header().await.unwrap();
        assert_eq!(handle.bytes(), header);
    }

    #[test]
    fn peer_max_packet_size_is_bounded_by_the_local_value() {
        let local = 30_000;
        let cases = [
            (0, MIN_MAX_PACKET_SIZE),
            (1, MIN_MAX_PACKET_SIZE),
            (MIN_MAX_PACKET_SIZE - 1, MIN_MAX_PACKET_SIZE),
            (MIN_MAX_PACKET_SIZE, MIN_MAX_PACKET_SIZE),
            (29_999, 29_999),
            (30_000, 30_000),
            (30_001, 30_000),
            (1 << 24, 30_000),
            (1 << 62, 30_000),
        ];
        for (peer, expected) in cases {
            assert_eq!(
                clamp_peer_max_packet_size(peer, local),
                expected,
                "peer {peer} must be clamped to {expected}"
            );
        }

        // A local value under the floor is not raised by the clamp: the clamp
        // bounds the peer by what the local endpoint announces.
        assert_eq!(clamp_peer_max_packet_size(0, 2048), 2048);
        // The floor of the local value is applied where the channel is built.
        assert_eq!(clamp_local_max_packet_size(0), MIN_MAX_PACKET_SIZE);
        assert_eq!(clamp_local_max_packet_size(2048), MIN_MAX_PACKET_SIZE);
        assert_eq!(clamp_local_max_packet_size(30_000), 30_000);
    }

    /// Builds the bytes of a channel request with the given request type and
    /// `want_reply` flag.
    fn channel_request_bytes(request_type: &[u8], want_reply: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        append_var_int(&mut out, ssh3_proto::SSH_MSG_CHANNEL_REQUEST);
        ssh3_proto::append_ssh_bytes(&mut out, request_type);
        out.push(want_reply);
        out.extend_from_slice(payload);
        out
    }

    /// The reference implementation decodes a boolean into a number and
    /// compares it against zero, so every byte other than `0` is true.
    #[tokio::test]
    async fn a_boolean_that_is_not_zero_is_true() {
        for byte in [0x01, 0x02, 0x7f, 0x80, 0xff] {
            let bytes = channel_request_bytes(b"shell", byte, &[]);
            let (mut recv, _) = BytesReceiveStream::new(bytes);
            let message = parse_message(&mut recv).await.unwrap();
            match message {
                Ssh3Message::ChannelRequest(request) => assert!(
                    request.want_reply,
                    "the byte {byte:#04x} must be read as true"
                ),
                other => panic!("expected a channel request, got {other:?}"),
            }
        }
    }

    /// The `forward-port` request is read in the order of the encoder and in
    /// the order of the parser of the reference implementation.
    #[tokio::test]
    async fn the_forwarding_request_is_read_in_both_orders() {
        let mut protocol_first = Vec::new();
        append_var_int(&mut protocol_first, 1);
        append_var_int(&mut protocol_first, 4);
        protocol_first.extend_from_slice(&[192, 0, 2, 10]);
        protocol_first.extend_from_slice(&443u16.to_be_bytes());

        let mut family_first = Vec::new();
        append_var_int(&mut family_first, 4);
        append_var_int(&mut family_first, 1);
        family_first.extend_from_slice(&[192, 0, 2, 10]);
        family_first.extend_from_slice(&443u16.to_be_bytes());

        for payload in [protocol_first, family_first] {
            let bytes = channel_request_bytes(b"forward-port", 0, &payload);
            let (mut recv, _) = BytesReceiveStream::new(bytes);
            let message = parse_message(&mut recv).await.unwrap();
            match message {
                Ssh3Message::ChannelRequest(request) => {
                    assert_eq!(
                        request.request,
                        Ssh3ChannelRequest::ForwardPort(ssh3_proto::Ssh3ForwardingRequest {
                            protocol: ssh3_proto::Ssh3ForwardingProtocol::Tcp,
                            ip_address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                192, 0, 2, 10
                            ),),
                            port: 443,
                        })
                    );
                }
                other => panic!("expected a channel request, got {other:?}"),
            }
        }
    }

    /// A request type the implementation does not know is refused with an
    /// error, without a panic and without an allocation of the payload.
    #[tokio::test]
    async fn an_unknown_request_type_is_refused() {
        let bytes = channel_request_bytes(b"no-such-request", 0, &[]);
        let (mut recv, _) = BytesReceiveStream::new(bytes);
        match parse_message(&mut recv).await {
            Err(Ssh3ChannelError::Proto(ssh3_proto::Ssh3Error::UnknownRequestType(reported))) => {
                assert_eq!(reported, b"no-such-request")
            }
            other => panic!("expected the request type to be refused, got {other:?}"),
        }
    }

    /// Builds the bytes of a compressed data frame: the message type, the
    /// algorithm and the compressed payload as an SSH string.
    fn compressed_data_frame_bytes(algorithm: u64, packed: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        append_var_int(&mut out, ssh3_proto::SSH_MSG_CHANNEL_DATA_COMPRESSED);
        append_var_int(&mut out, algorithm);
        ssh3_proto::append_ssh_bytes(&mut out, packed);
        out
    }

    /// A compressed data frame decodes into its plain payload: the frame
    /// carries its algorithm, so the parser needs no state of its own, the
    /// way `ParseCompressedDataMessage` of the reference works.
    #[tokio::test]
    async fn a_compressed_data_frame_decodes_into_its_plain_payload() {
        let payload = b"a compressed channel body ".repeat(64);
        let packed = crate::compress::compress(crate::compress::ALGORITHM_DEFLATE, &payload)
            .expect("the deflate codec refused the payload");
        let bytes = compressed_data_frame_bytes(crate::compress::ALGORITHM_DEFLATE, &packed);
        let (mut recv, _) = BytesReceiveStream::new(bytes);
        let message = parse_message(&mut recv).await.unwrap();
        match message {
            Ssh3Message::Data(data) => {
                assert_eq!(data.data_type, ssh3_proto::SSH_EXTENDED_DATA_NONE);
                assert_eq!(data.data, payload);
            }
            other => panic!("expected a data message, got {other:?}"),
        }
    }

    /// A frame whose payload does not decode is a protocol error: the
    /// channel dies, the way the reference implementation drops the channel
    /// of a frame that does not parse.
    #[tokio::test]
    async fn a_compressed_data_frame_that_does_not_decode_is_a_protocol_error() {
        let bytes = compressed_data_frame_bytes(
            crate::compress::ALGORITHM_DEFLATE,
            b"not a deflate stream",
        );
        let (mut recv, _) = BytesReceiveStream::new(bytes);
        match parse_message(&mut recv).await {
            Err(Ssh3ChannelError::Proto(ssh3_proto::Ssh3Error::Compression(_))) => {}
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    /// An algorithm no implementation knows is refused the same way.
    #[tokio::test]
    async fn a_compressed_data_frame_of_an_unknown_algorithm_is_refused() {
        let bytes = compressed_data_frame_bytes(42, b"whatever");
        let (mut recv, _) = BytesReceiveStream::new(bytes);
        match parse_message(&mut recv).await {
            Err(Ssh3ChannelError::Proto(ssh3_proto::Ssh3Error::Compression(_))) => {}
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_data_never_exceeds_the_size_agreed_with_the_peer() {
        // The peer confirms the channel with a smaller packet size.
        let mut confirmation = Vec::new();
        append_var_int(
            &mut confirmation,
            ssh3_proto::SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
        );
        append_var_int(&mut confirmation, 4096);
        let (recv, _) = BytesReceiveStream::new(confirmation);
        let (send, handle) = RecordingSendStream::new();
        let channel = Ssh3Channel::new(
            11,
            conversation_id(),
            22,
            b"session".to_vec(),
            30_000,
            recv,
            send,
            None,
            true,
            true,
            false,
            4,
            None,
        );
        channel.wait_for_confirmation().await.unwrap();

        let payload = vec![7; 20_000];
        channel
            .write_data(&payload, ssh3_proto::SSH_EXTENDED_DATA_NONE)
            .await
            .unwrap();

        // Every data frame carries at most the payload that fits into the
        // size the peer accepted.
        let overhead = ssh3_proto::Ssh3DataOrExtendedDataMessage {
            data_type: ssh3_proto::SSH_EXTENDED_DATA_NONE,
            data: Vec::new(),
        }
        .encoded_len() as u64;
        let bytes = handle.bytes();
        let header = Ssh3ChannelHeader {
            conversation_stream_id: 11,
            channel_type: b"session".to_vec(),
            max_packet_size: 30_000,
        }
        .encode(None);
        assert_eq!(&bytes[..header.len()], &header[..]);
        let mut cursor = std::io::Cursor::new(&bytes[header.len()..]);
        let mut frames = 0;
        while (cursor.position() as usize) < cursor.get_ref().len() {
            let message_type = ssh3_proto::read_var_int(&mut cursor).unwrap();
            assert_eq!(message_type, SSH_MSG_CHANNEL_DATA);
            let length = ssh3_proto::read_var_int(&mut cursor).unwrap();
            assert!(
                length + overhead <= 4096,
                "frame of {length} bytes exceeds the size the peer accepted"
            );
            cursor.set_position(cursor.position() + length);
            frames += 1;
        }
        assert!(frames > 1, "the payload must be split into several frames");
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

    #[tokio::test]
    async fn oversized_strings_in_a_message_are_refused() {
        let mut recv_bytes = Vec::new();
        append_var_int(&mut recv_bytes, SSH_MSG_CHANNEL_DATA);
        append_var_int(&mut recv_bytes, ssh3_proto::MAX_SSH_STRING_LEN + 1);
        let (recv, _) = BytesReceiveStream::new(recv_bytes);
        let (send, _) = RecordingSendStream::new();
        let channel = Ssh3Channel::new(
            1,
            conversation_id(),
            2,
            b"session".to_vec(),
            MIN_MAX_PACKET_SIZE,
            recv,
            send,
            None,
            false,
            true,
            true,
            4,
            None,
        );

        match channel.next_message().await {
            Err(Ssh3ChannelError::Proto(ssh3_proto::Ssh3Error::StringTooLong {
                length,
                limit,
            })) => {
                assert_eq!(length, ssh3_proto::MAX_SSH_STRING_LEN + 1);
                assert_eq!(limit, ssh3_proto::MAX_SSH_STRING_LEN);
            }
            other => panic!("expected a length error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cancel_read_interrupts_a_blocked_read() {
        let (recv, codes) = BlockingReceiveStream::new();
        let (send, _) = RecordingSendStream::new();
        let channel = Arc::new(Ssh3Channel::new(
            1,
            conversation_id(),
            2,
            b"session".to_vec(),
            MIN_MAX_PACKET_SIZE,
            recv,
            send,
            None,
            false,
            true,
            true,
            4,
            None,
        ));

        // The reader blocks on the stream of the channel.
        let reader = channel.clone();
        let pending = tokio::spawn(async move { reader.next_message().await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The cancellation returns at once, even though the read is pending.
        tokio::time::timeout(Duration::from_secs(2), channel.cancel_read())
            .await
            .expect("cancel_read must not wait for the pending read");

        // The pending read gives up instead of waiting for the peer.
        let result = tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .expect("the pending read must return")
            .expect("the reader task must not panic");
        assert!(result.is_err(), "the pending read must report an error");

        // The read of the transport was aborted, so the peer is not left
        // waiting for a message that will never arrive.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while codes.lock().unwrap().is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the read of the transport was not aborted"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(*codes.lock().unwrap(), vec![super::CANCEL_READ_ERROR_CODE]);
    }
}
