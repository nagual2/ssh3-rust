//! The conversation: the registry of the channels of one SSH3 session.
//!
//! A conversation owns the channels that were opened on it, confirms the
//! channels the peer opens and routes the datagrams to the channel they
//! belong to.

use std::collections::HashMap;
use std::fmt;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ssh3_proto::{append_var_int, build_forwarding_additional_bytes, read_var_int};

use crate::channel::{Ssh3AcceptedChannel, Ssh3Channel, Ssh3ChannelError};
use crate::queue::{Ssh3AcceptQueue, Ssh3DatagramQueue};
use crate::transport::{Ssh3DatagramSender, Ssh3ReceiveStream, Ssh3SendStream};

/// Identifier of a conversation: 32 bytes chosen by the client.
pub type Ssh3ConversationId = [u8; 32];

const DANGLING_DATAGRAM_QUEUE_SIZE: usize = 10;

/// Everything that can fail while a conversation is used.
#[derive(Debug)]
pub enum Ssh3ConversationError {
    /// The channel failed.
    Channel(Ssh3ChannelError),
    /// The peer sent a message that could not be decoded.
    Proto(ssh3_proto::Ssh3Error),
    /// A datagram arrived for a channel that does not exist.
    ChannelNotFound {
        /// Id of the channel the datagram was addressed to.
        channel_id: u64,
    },
}

impl fmt::Display for Ssh3ConversationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(err) => write!(f, "{err}"),
            Self::Proto(err) => write!(f, "{err}"),
            Self::ChannelNotFound { channel_id } => write!(f, "channel not found: {channel_id}"),
        }
    }
}

impl std::error::Error for Ssh3ConversationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Channel(err) => Some(err),
            Self::Proto(err) => Some(err),
            Self::ChannelNotFound { .. } => None,
        }
    }
}

impl From<Ssh3ChannelError> for Ssh3ConversationError {
    fn from(value: Ssh3ChannelError) -> Self {
        Self::Channel(value)
    }
}

impl From<ssh3_proto::Ssh3Error> for Ssh3ConversationError {
    fn from(value: ssh3_proto::Ssh3Error) -> Self {
        Self::Proto(value)
    }
}

/// Sends the datagrams of a single channel of a conversation.
///
/// Every datagram is prefixed with the id of the conversation stream and the
/// id of the channel, so that the peer can route it to the right channel.
#[derive(Clone)]
pub struct Ssh3ConversationDatagramSender {
    control_stream_id: u64,
    channel_id: u64,
    message_sender: Arc<dyn Ssh3DatagramSender>,
}

impl Ssh3ConversationDatagramSender {
    /// Creates a sender for the channel `channel_id` of the conversation
    /// `control_stream_id`.
    pub fn new(
        control_stream_id: u64,
        channel_id: u64,
        message_sender: Arc<dyn Ssh3DatagramSender>,
    ) -> Self {
        Self {
            control_stream_id,
            channel_id,
            message_sender,
        }
    }

    /// Sends one datagram, prefixed with the addresses of the channel.
    pub async fn send(&self, datagram: Vec<u8>) -> std::io::Result<()> {
        let mut buf = Vec::new();
        append_var_int(&mut buf, self.control_stream_id);
        append_var_int(&mut buf, self.channel_id);
        buf.extend_from_slice(&datagram);
        self.message_sender.send_datagram(buf).await
    }
}

/// The set of channels that belong to one SSH3 session.
///
/// The conversation opens the channels of the local side, accepts and
/// confirms the channels opened by the peer, and dispatches the datagrams
/// to the channel they are addressed to.
pub struct Ssh3Conversation {
    control_stream_id: u64,
    conversation_id: Ssh3ConversationId,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
    message_sender: Arc<dyn Ssh3DatagramSender>,
    channels_manager: ChannelsManager,
    channels_accept_queue: Ssh3AcceptQueue<Ssh3AcceptedChannel>,
}

impl Ssh3Conversation {
    /// Creates a conversation.
    ///
    /// `max_packet_size` is the size announced to the peer when a channel is
    /// confirmed, `default_datagrams_queue_size` the capacity of the datagram
    /// queue of a channel that does not request one.
    pub fn new(
        control_stream_id: u64,
        conversation_id: Ssh3ConversationId,
        max_packet_size: u64,
        default_datagrams_queue_size: usize,
        message_sender: Arc<dyn Ssh3DatagramSender>,
    ) -> Self {
        Self {
            control_stream_id,
            conversation_id,
            max_packet_size,
            default_datagrams_queue_size,
            message_sender,
            channels_manager: ChannelsManager::new(),
            channels_accept_queue: Ssh3AcceptQueue::new(),
        }
    }

    /// Opens a channel of the local side.
    ///
    /// The channel is registered immediately and is not confirmed: the
    /// confirmation is sent by the caller.
    pub fn open_channel<R, W>(
        &self,
        stream_id: u64,
        channel_type: impl Into<Vec<u8>>,
        max_packet_size: u64,
        datagrams_queue_size: usize,
        recv: R,
        send: W,
    ) -> Arc<Ssh3Channel>
    where
        R: Ssh3ReceiveStream + 'static,
        W: Ssh3SendStream + 'static,
    {
        let channel = Arc::new(Ssh3Channel::new(
            self.control_stream_id,
            self.conversation_id,
            stream_id,
            channel_type,
            max_packet_size,
            recv,
            send,
            None,
            true,
            true,
            false,
            datagrams_queue_size,
            None,
        ));
        self.channels_manager.add_channel(channel.clone());
        channel
    }

    /// Returns the datagram sender of the channel `channel_id`.
    pub fn datagram_sender_for_channel(
        &self,
        channel_id: u64,
    ) -> Arc<Ssh3ConversationDatagramSender> {
        Arc::new(Ssh3ConversationDatagramSender::new(
            self.control_stream_id,
            channel_id,
            self.message_sender.clone(),
        ))
    }

    /// Opens a channel that forwards datagrams to `remote_addr`.
    ///
    /// The target address is written into the channel header and the header is
    /// sent immediately.
    pub async fn open_udp_forwarding_channel<R, W>(
        &self,
        stream_id: u64,
        max_packet_size: u64,
        datagrams_queue_size: usize,
        remote_addr: SocketAddr,
        recv: R,
        send: W,
    ) -> Result<Arc<Ssh3Channel>, Ssh3ConversationError>
    where
        R: Ssh3ReceiveStream + 'static,
        W: Ssh3SendStream + 'static,
    {
        let channel = Arc::new(Ssh3Channel::new(
            self.control_stream_id,
            self.conversation_id,
            stream_id,
            b"direct-udp".to_vec(),
            max_packet_size,
            recv,
            send,
            Some(self.datagram_sender_for_channel(stream_id)),
            true,
            true,
            false,
            datagrams_queue_size,
            Some(&build_forwarding_additional_bytes(
                remote_addr.ip(),
                remote_addr.port(),
            )),
        ));
        channel.maybe_send_header().await?;
        self.channels_manager.add_channel(channel.clone());
        Ok(channel)
    }

    /// Opens a channel that forwards a byte stream to `remote_addr`.
    ///
    /// The target address is written into the channel header and the header is
    /// sent immediately.
    pub async fn open_tcp_forwarding_channel<R, W>(
        &self,
        stream_id: u64,
        max_packet_size: u64,
        datagrams_queue_size: usize,
        remote_addr: SocketAddr,
        recv: R,
        send: W,
    ) -> Result<Arc<Ssh3Channel>, Ssh3ConversationError>
    where
        R: Ssh3ReceiveStream + 'static,
        W: Ssh3SendStream + 'static,
    {
        let channel = Arc::new(Ssh3Channel::new(
            self.control_stream_id,
            self.conversation_id,
            stream_id,
            b"direct-tcp".to_vec(),
            max_packet_size,
            recv,
            send,
            None,
            true,
            true,
            false,
            datagrams_queue_size,
            Some(&build_forwarding_additional_bytes(
                remote_addr.ip(),
                remote_addr.port(),
            )),
        ));
        channel.maybe_send_header().await?;
        self.channels_manager.add_channel(channel.clone());
        Ok(channel)
    }

    /// Queues a channel that the peer opened, without metadata.
    pub fn queue_incoming_channel(&self, channel: Arc<Ssh3Channel>) {
        self.queue_incoming_accepted_channel(channel.into());
    }

    /// Queues a channel that the peer opened.
    ///
    /// The channel is confirmed when it is accepted.
    pub fn queue_incoming_accepted_channel(&self, channel: Ssh3AcceptedChannel) {
        self.channels_accept_queue.add(channel);
    }

    /// Waits for a channel opened by the peer and confirms it.
    pub async fn accept_channel(&self) -> Result<Arc<Ssh3Channel>, Ssh3ConversationError> {
        Ok(self.accept_channel_with_metadata().await?.into_channel())
    }

    /// Waits for a channel opened by the peer, confirms it and returns the
    /// metadata of the channel.
    pub async fn accept_channel_with_metadata(
        &self,
    ) -> Result<Ssh3AcceptedChannel, Ssh3ConversationError> {
        if let Some(channel) = self.channels_accept_queue.next() {
            return self.confirm_and_register_channel(channel).await;
        }
        let channel = self.channels_accept_queue.wait_next().await;
        self.confirm_and_register_channel(channel).await
    }

    /// Routes a datagram to the channel it is addressed to.
    ///
    /// The datagram starts with the id of the channel. When the channel is
    /// not known yet, the datagram is parked in a dangling queue and handed
    /// over as soon as the channel appears; the error
    /// [`Ssh3ConversationError::ChannelNotFound`] is returned in that case.
    pub async fn add_datagram(&self, datagram: &[u8]) -> Result<(), Ssh3ConversationError> {
        let mut cursor = Cursor::new(datagram);
        let channel_id = read_var_int(&mut cursor)?;
        let offset = cursor.position() as usize;
        let payload = datagram[offset..].to_vec();

        if let Some(channel) = self.channels_manager.get_channel(channel_id) {
            channel.wait_add_datagram(payload).await;
            return Ok(());
        }

        let queue = Arc::new(Ssh3DatagramQueue::new(DANGLING_DATAGRAM_QUEUE_SIZE));
        let _ = queue.add(payload);
        self.channels_manager
            .add_dangling_datagrams_queue(channel_id, queue);
        Err(Ssh3ConversationError::ChannelNotFound { channel_id })
    }

    /// Returns the id of the stream the conversation runs on.
    pub fn control_stream_id(&self) -> u64 {
        self.control_stream_id
    }

    /// Returns the id of the conversation.
    pub fn conversation_id(&self) -> Ssh3ConversationId {
        self.conversation_id
    }

    /// Returns the capacity of the datagram queue used for new channels.
    pub fn default_datagrams_queue_size(&self) -> usize {
        self.default_datagrams_queue_size
    }

    /// Returns the maximum packet size the conversation announces.
    ///
    /// It is the value sent in the confirmation of a channel and the upper
    /// bound of the maximum packet size a peer may announce.
    pub fn max_packet_size(&self) -> u64 {
        self.max_packet_size
    }

    async fn confirm_and_register_channel(
        &self,
        channel: Ssh3AcceptedChannel,
    ) -> Result<Ssh3AcceptedChannel, Ssh3ConversationError> {
        let inner = channel.channel().clone();
        inner.confirm_channel(self.max_packet_size).await?;
        self.channels_manager.add_channel(inner);
        Ok(channel)
    }
}

#[derive(Default)]
struct ChannelsState {
    channels: HashMap<u64, Arc<Ssh3Channel>>,
    dangling_datagram_queues: HashMap<u64, Arc<Ssh3DatagramQueue>>,
}

struct ChannelsManager {
    state: Mutex<ChannelsState>,
}

impl ChannelsManager {
    fn new() -> Self {
        Self {
            state: Mutex::new(ChannelsState::default()),
        }
    }

    fn add_channel(&self, channel: Arc<Ssh3Channel>) {
        let pending_queue = {
            let mut state = self.state.lock().unwrap();
            let pending_queue = state.dangling_datagram_queues.remove(&channel.channel_id());
            state.channels.insert(channel.channel_id(), channel.clone());
            pending_queue
        };

        if let Some(queue) = pending_queue {
            channel.set_datagram_queue(queue);
        }
    }

    fn add_dangling_datagrams_queue(&self, channel_id: u64, queue: Arc<Ssh3DatagramQueue>) {
        let existing_channel = {
            let mut state = self.state.lock().unwrap();
            if let Some(channel) = state.channels.get(&channel_id) {
                Some(channel.clone())
            } else {
                state
                    .dangling_datagram_queues
                    .insert(channel_id, queue.clone());
                None
            }
        };

        if let Some(channel) = existing_channel {
            while let Some(datagram) = queue.next() {
                channel.add_datagram(datagram);
            }
        }
    }

    fn get_channel(&self, channel_id: u64) -> Option<Arc<Ssh3Channel>> {
        self.state
            .lock()
            .unwrap()
            .channels
            .get(&channel_id)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use ssh3_proto::{Ssh3ChannelOpenConfirmationMessage, Ssh3Message};

    use super::{Ssh3Conversation, Ssh3ConversationError};
    use crate::channel::{Ssh3AcceptedChannel, Ssh3Channel};
    use crate::transport::testutil::{
        BytesReceiveStream, RecordingDatagramSender, RecordingSendStream,
    };

    fn conversation_id() -> [u8; 32] {
        [9; 32]
    }

    #[tokio::test]
    async fn accept_channel_confirms_and_registers_channel() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Ssh3Conversation::new(10, conversation_id(), 2048, 8, sender);
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();
        let incoming = Arc::new(Ssh3Channel::new(
            10,
            conversation_id(),
            42,
            b"session".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            false,
            true,
            8,
            None,
        ));

        conversation.queue_incoming_channel(incoming.clone());
        let accepted = conversation.accept_channel().await.unwrap();

        assert!(Arc::ptr_eq(&accepted, &incoming));
        assert_eq!(
            handle.bytes(),
            Ssh3Message::ChannelOpenConfirmation(Ssh3ChannelOpenConfirmationMessage {
                max_packet_size: 2048,
            })
            .to_vec()
        );
    }

    #[tokio::test]
    async fn accept_channel_with_metadata_preserves_udp_forwarding_target() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Ssh3Conversation::new(10, conversation_id(), 2048, 8, sender);
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();
        let incoming = Arc::new(Ssh3Channel::new(
            10,
            conversation_id(),
            42,
            b"direct-udp".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            false,
            true,
            8,
            None,
        ));
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 443));

        conversation.queue_incoming_accepted_channel(Ssh3AcceptedChannel::UdpForwarding {
            channel: incoming.clone(),
            remote_addr,
        });
        let accepted = conversation.accept_channel_with_metadata().await.unwrap();

        match accepted {
            Ssh3AcceptedChannel::UdpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert!(Arc::ptr_eq(&channel, &incoming));
                assert_eq!(accepted_remote_addr, remote_addr);
            }
            _ => panic!("expected UDP forwarding channel"),
        }
        assert_eq!(
            handle.bytes(),
            Ssh3Message::ChannelOpenConfirmation(Ssh3ChannelOpenConfirmationMessage {
                max_packet_size: 2048,
            })
            .to_vec()
        );
    }

    #[tokio::test]
    async fn accept_channel_with_metadata_preserves_tcp_forwarding_target() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Ssh3Conversation::new(10, conversation_id(), 2048, 8, sender);
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();
        let incoming = Arc::new(Ssh3Channel::new(
            10,
            conversation_id(),
            42,
            b"direct-tcp".to_vec(),
            1024,
            recv,
            send,
            None,
            false,
            false,
            true,
            8,
            None,
        ));
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25)), 22);

        conversation.queue_incoming_accepted_channel(Ssh3AcceptedChannel::TcpForwarding {
            channel: incoming.clone(),
            remote_addr,
        });
        let accepted = conversation.accept_channel_with_metadata().await.unwrap();

        match accepted {
            Ssh3AcceptedChannel::TcpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert!(Arc::ptr_eq(&channel, &incoming));
                assert_eq!(accepted_remote_addr, remote_addr);
            }
            _ => panic!("expected TCP forwarding channel"),
        }
        assert_eq!(
            handle.bytes(),
            Ssh3Message::ChannelOpenConfirmation(Ssh3ChannelOpenConfirmationMessage {
                max_packet_size: 2048,
            })
            .to_vec()
        );
    }

    #[tokio::test]
    async fn dangling_datagrams_are_delivered_when_channel_is_added() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Ssh3Conversation::new(10, conversation_id(), 2048, 8, sender);

        let mut datagram = Vec::new();
        ssh3_proto::append_var_int(&mut datagram, 42);
        datagram.extend_from_slice(&[1, 2, 3]);

        match conversation.add_datagram(&datagram).await {
            Err(Ssh3ConversationError::ChannelNotFound { channel_id }) => {
                assert_eq!(channel_id, 42)
            }
            other => panic!("expected missing channel error, got {other:?}"),
        }

        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, _) = RecordingSendStream::new();
        let channel = conversation.open_channel(42, b"session".to_vec(), 1024, 8, recv, send);

        assert_eq!(channel.receive_datagram().await, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn udp_forwarding_channels_send_prefixed_datagrams() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Ssh3Conversation::new(10, conversation_id(), 2048, 8, sender.clone());
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, _) = RecordingSendStream::new();

        let channel = conversation
            .open_udp_forwarding_channel(
                77,
                1024,
                8,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 8), 443)),
                recv,
                send,
            )
            .await
            .unwrap();

        channel.send_datagram(vec![5, 4, 3]).await.unwrap();

        let mut expected = Vec::new();
        ssh3_proto::append_var_int(&mut expected, 10);
        ssh3_proto::append_var_int(&mut expected, 77);
        expected.extend_from_slice(&[5, 4, 3]);
        assert_eq!(sender.datagrams(), vec![expected]);
    }

    #[tokio::test]
    async fn tcp_forwarding_channels_write_forwarding_headers_immediately() {
        let sender = Arc::new(RecordingDatagramSender::default());
        let conversation = Ssh3Conversation::new(10, conversation_id(), 2048, 8, sender);
        let (recv, _) = BytesReceiveStream::new(Vec::new());
        let (send, handle) = RecordingSendStream::new();

        let _channel = conversation
            .open_tcp_forwarding_channel(
                77,
                1024,
                8,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 22),
                recv,
                send,
            )
            .await
            .unwrap();

        let expected = ssh3_proto::Ssh3ChannelHeader {
            conversation_stream_id: 10,
            channel_type: b"direct-tcp".to_vec(),
            // The announced packet size is floored at the construction of the
            // channel, so it never drops below the minimum sane value.
            max_packet_size: crate::channel::MIN_MAX_PACKET_SIZE,
        }
        .encode(Some(&ssh3_proto::build_forwarding_additional_bytes(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            22,
        )));
        assert_eq!(handle.bytes(), expected);
    }
}
