use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::Mutex;

use quinn::{Connection, ConnectionError, RecvStream};
use ssh3_core::{
    MAX_MAX_PACKET_SIZE, Ssh3AcceptedChannel, Ssh3Channel, Ssh3Conversation,
    Ssh3ConversationDatagramSender, Ssh3ConversationError, Ssh3ConversationId,
    clamp_peer_max_packet_size,
};
use ssh3_proto::{SSH_FRAME_TYPE, Ssh3ChannelHeader, Ssh3ForwardingAddressFamily};

use crate::{Ssh3QuinnReceiveStream, Ssh3QuinnSendStream, read_exact_error_to_io};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3IncomingChannel {
    pub stream_id: u64,
    pub header: Ssh3ChannelHeader,
    pub forwarding_target: Option<SocketAddr>,
}

impl Ssh3IncomingChannel {
    pub fn into_accepted_channel(
        self,
        conversation_id: Ssh3ConversationId,
        recv: quinn::RecvStream,
        send: quinn::SendStream,
        datagram_sender: Option<Arc<Ssh3ConversationDatagramSender>>,
        datagrams_queue_size: usize,
    ) -> Ssh3AcceptedChannel {
        // Without a conversation the value this endpoint announces is
        // unknown: the value of the peer is only bounded by the protocol
        // limit.
        let max_packet_size =
            clamp_peer_max_packet_size(self.header.max_packet_size, MAX_MAX_PACKET_SIZE);
        self.build(
            max_packet_size,
            conversation_id,
            recv,
            send,
            datagram_sender,
            datagrams_queue_size,
        )
    }

    pub fn into_accepted_channel_for_conversation(
        self,
        conversation: &Ssh3Conversation,
        recv: quinn::RecvStream,
        send: quinn::SendStream,
    ) -> Ssh3AcceptedChannel {
        let datagram_sender = (self.header.channel_type.as_slice() == b"direct-udp")
            .then(|| conversation.datagram_sender_for_channel(self.stream_id));
        // The peer must not pick the size of the buffers of this endpoint:
        // its value is bounded by the value this endpoint announces.
        let max_packet_size =
            clamp_peer_max_packet_size(self.header.max_packet_size, conversation.max_packet_size());
        self.build(
            max_packet_size,
            conversation.conversation_id(),
            recv,
            send,
            datagram_sender,
            conversation.default_datagrams_queue_size(),
        )
    }

    /// Builds the channel of an incoming channel with the maximum packet
    /// size this endpoint uses on it.
    #[allow(clippy::too_many_arguments)]
    fn build(
        &self,
        max_packet_size: u64,
        conversation_id: Ssh3ConversationId,
        recv: quinn::RecvStream,
        send: quinn::SendStream,
        datagram_sender: Option<Arc<Ssh3ConversationDatagramSender>>,
        datagrams_queue_size: usize,
    ) -> Ssh3AcceptedChannel {
        let stream_id = self.stream_id;
        let forwarding_target = self.forwarding_target;
        let channel_type = self.header.channel_type.clone();
        let datagram_sender = if channel_type.as_slice() == b"direct-udp" {
            datagram_sender
        } else {
            None
        };
        let channel = Arc::new(Ssh3Channel::new(
            self.header.conversation_stream_id,
            conversation_id,
            stream_id,
            self.header.channel_type.clone(),
            max_packet_size,
            Ssh3QuinnReceiveStream::new(recv),
            Ssh3QuinnSendStream::new(send),
            datagram_sender,
            false,
            false,
            true,
            datagrams_queue_size,
            None,
        ));

        match (channel_type.as_slice(), forwarding_target) {
            (b"direct-udp", Some(remote_addr)) => Ssh3AcceptedChannel::UdpForwarding {
                channel,
                remote_addr,
            },
            (b"direct-tcp", Some(remote_addr)) => Ssh3AcceptedChannel::TcpForwarding {
                channel,
                remote_addr,
            },
            _ => Ssh3AcceptedChannel::Channel(channel),
        }
    }

    pub fn into_channel(
        self,
        conversation_id: Ssh3ConversationId,
        recv: quinn::RecvStream,
        send: quinn::SendStream,
        datagram_sender: Option<Arc<Ssh3ConversationDatagramSender>>,
        datagrams_queue_size: usize,
    ) -> Arc<Ssh3Channel> {
        self.into_accepted_channel(
            conversation_id,
            recv,
            send,
            datagram_sender,
            datagrams_queue_size,
        )
        .into_channel()
    }
}

#[derive(Default)]
pub struct Ssh3IncomingChannelRouter {
    conversations: Mutex<std::collections::HashMap<u64, Arc<Ssh3Conversation>>>,
}

impl Ssh3IncomingChannelRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_conversation(&self, conversation: Arc<Ssh3Conversation>) {
        self.conversations
            .lock()
            .unwrap()
            .insert(conversation.control_stream_id(), conversation);
    }

    pub fn unregister_conversation(&self, control_stream_id: u64) -> Option<Arc<Ssh3Conversation>> {
        self.conversations
            .lock()
            .unwrap()
            .remove(&control_stream_id)
    }

    pub fn conversation(&self, control_stream_id: u64) -> Option<Arc<Ssh3Conversation>> {
        self.conversations
            .lock()
            .unwrap()
            .get(&control_stream_id)
            .cloned()
    }

    pub fn route_incoming_channel(
        &self,
        incoming: Ssh3IncomingChannel,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Result<Arc<Ssh3Conversation>, Ssh3RouteIncomingChannelError> {
        let control_stream_id = incoming.header.conversation_stream_id;
        let channel_id = incoming.stream_id;
        let Some(conversation) = self.conversation(control_stream_id) else {
            return Err(Ssh3RouteIncomingChannelError::UnknownConversation {
                control_stream_id,
                channel_id,
            });
        };

        conversation.queue_incoming_accepted_channel(
            incoming.into_accepted_channel_for_conversation(conversation.as_ref(), recv, send),
        );
        Ok(conversation)
    }

    pub async fn accept_and_route_channel(
        &self,
        connection: &Connection,
    ) -> Result<Arc<Ssh3Conversation>, Ssh3RouteAcceptedChannelError> {
        let (incoming, send, recv) = accept_bi_channel(connection).await?;
        self.route_incoming_channel(incoming, send, recv)
            .map_err(Ssh3RouteAcceptedChannelError::Route)
    }

    pub async fn accept_and_route_channels_forever(
        self: Arc<Self>,
        connection: Connection,
    ) -> Result<(), Ssh3RouteAcceptedChannelError> {
        loop {
            self.accept_and_route_channel(&connection).await?;
        }
    }
}

#[derive(Debug)]
pub enum Ssh3ChannelSetupError {
    Io(io::Error),
    Proto(ssh3_proto::Ssh3Error),
    UnexpectedFrameType { frame_type: u64 },
}

impl fmt::Display for Ssh3ChannelSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Proto(err) => write!(f, "{err}"),
            Self::UnexpectedFrameType { frame_type } => {
                write!(f, "unexpected SSH3 frame type: {frame_type}")
            }
        }
    }
}

impl std::error::Error for Ssh3ChannelSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Proto(err) => Some(err),
            Self::UnexpectedFrameType { .. } => None,
        }
    }
}

impl From<io::Error> for Ssh3ChannelSetupError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ssh3_proto::Ssh3Error> for Ssh3ChannelSetupError {
    fn from(value: ssh3_proto::Ssh3Error) -> Self {
        Self::Proto(value)
    }
}

#[derive(Debug)]
pub enum Ssh3AcceptChannelError {
    Connection(ConnectionError),
    Setup(Ssh3ChannelSetupError),
}

impl fmt::Display for Ssh3AcceptChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "{err}"),
            Self::Setup(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Ssh3AcceptChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::Setup(err) => Some(err),
        }
    }
}

impl From<ConnectionError> for Ssh3AcceptChannelError {
    fn from(value: ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<Ssh3ChannelSetupError> for Ssh3AcceptChannelError {
    fn from(value: Ssh3ChannelSetupError) -> Self {
        Self::Setup(value)
    }
}

#[derive(Debug)]
pub enum Ssh3OpenChannelError {
    Connection(ConnectionError),
    Conversation(Ssh3ConversationError),
}

impl fmt::Display for Ssh3OpenChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "{err}"),
            Self::Conversation(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Ssh3OpenChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::Conversation(err) => Some(err),
        }
    }
}

impl From<ConnectionError> for Ssh3OpenChannelError {
    fn from(value: ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<Ssh3ConversationError> for Ssh3OpenChannelError {
    fn from(value: Ssh3ConversationError) -> Self {
        Self::Conversation(value)
    }
}

#[derive(Debug)]
pub enum Ssh3RouteIncomingChannelError {
    UnknownConversation {
        control_stream_id: u64,
        channel_id: u64,
    },
}

impl fmt::Display for Ssh3RouteIncomingChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownConversation {
                control_stream_id,
                channel_id,
            } => write!(
                f,
                "no registered conversation for control stream {} while routing channel {}",
                control_stream_id, channel_id
            ),
        }
    }
}

impl std::error::Error for Ssh3RouteIncomingChannelError {}

#[derive(Debug)]
pub enum Ssh3RouteAcceptedChannelError {
    Accept(Ssh3AcceptChannelError),
    Route(Ssh3RouteIncomingChannelError),
}

impl fmt::Display for Ssh3RouteAcceptedChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept(err) => write!(f, "{err}"),
            Self::Route(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Ssh3RouteAcceptedChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Accept(err) => Some(err),
            Self::Route(err) => Some(err),
        }
    }
}

impl From<Ssh3AcceptChannelError> for Ssh3RouteAcceptedChannelError {
    fn from(value: Ssh3AcceptChannelError) -> Self {
        Self::Accept(value)
    }
}

pub async fn accept_bi_channel(
    connection: &Connection,
) -> Result<(Ssh3IncomingChannel, quinn::SendStream, quinn::RecvStream), Ssh3AcceptChannelError> {
    let (send, mut recv) = connection.accept_bi().await?;
    let incoming = read_incoming_channel(&mut recv).await?;
    Ok((incoming, send, recv))
}

pub async fn read_incoming_channel(
    recv: &mut RecvStream,
) -> Result<Ssh3IncomingChannel, Ssh3ChannelSetupError> {
    let frame_type = read_var_int(recv).await?;
    if frame_type != SSH_FRAME_TYPE {
        return Err(Ssh3ChannelSetupError::UnexpectedFrameType { frame_type });
    }

    let header = Ssh3ChannelHeader {
        conversation_stream_id: read_var_int(recv).await?,
        channel_type: read_ssh_bytes(recv).await?,
        max_packet_size: read_var_int(recv).await?,
    };

    // The value the peer announces bounds the data messages it may send on
    // the channel: left unbounded it is a second unvalidated allocation
    // knob, because the data messages are parsed as SSH strings.
    if header.max_packet_size > MAX_MAX_PACKET_SIZE {
        return Err(Ssh3ChannelSetupError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "peer max packet size {} exceeds the limit of {MAX_MAX_PACKET_SIZE}",
                header.max_packet_size
            ),
        )));
    }

    let forwarding_target = match header.channel_type.as_slice() {
        b"direct-udp" | b"direct-tcp" => Some(read_forwarding_target(recv).await?),
        _ => None,
    };

    Ok(Ssh3IncomingChannel {
        stream_id: recv.id().into(),
        header,
        forwarding_target,
    })
}

pub async fn open_channel(
    conversation: &Ssh3Conversation,
    connection: &Connection,
    channel_type: impl Into<Vec<u8>>,
    max_packet_size: u64,
    datagrams_queue_size: usize,
) -> Result<Arc<Ssh3Channel>, Ssh3OpenChannelError> {
    let (send, recv) = connection.open_bi().await?;
    Ok(conversation.open_channel(
        send.id().into(),
        channel_type,
        max_packet_size,
        datagrams_queue_size,
        Ssh3QuinnReceiveStream::new(recv),
        Ssh3QuinnSendStream::new(send),
    ))
}

pub async fn open_udp_forwarding_channel(
    conversation: &Ssh3Conversation,
    connection: &Connection,
    max_packet_size: u64,
    datagrams_queue_size: usize,
    remote_addr: SocketAddr,
) -> Result<Arc<Ssh3Channel>, Ssh3OpenChannelError> {
    let (send, recv) = connection.open_bi().await?;
    conversation
        .open_udp_forwarding_channel(
            send.id().into(),
            max_packet_size,
            datagrams_queue_size,
            remote_addr,
            Ssh3QuinnReceiveStream::new(recv),
            Ssh3QuinnSendStream::new(send),
        )
        .await
        .map_err(Ssh3OpenChannelError::from)
}

pub async fn open_tcp_forwarding_channel(
    conversation: &Ssh3Conversation,
    connection: &Connection,
    max_packet_size: u64,
    datagrams_queue_size: usize,
    remote_addr: SocketAddr,
) -> Result<Arc<Ssh3Channel>, Ssh3OpenChannelError> {
    let (send, recv) = connection.open_bi().await?;
    conversation
        .open_tcp_forwarding_channel(
            send.id().into(),
            max_packet_size,
            datagrams_queue_size,
            remote_addr,
            Ssh3QuinnReceiveStream::new(recv),
            Ssh3QuinnSendStream::new(send),
        )
        .await
        .map_err(Ssh3OpenChannelError::from)
}

async fn read_forwarding_target(
    recv: &mut RecvStream,
) -> Result<SocketAddr, Ssh3ChannelSetupError> {
    let family = Ssh3ForwardingAddressFamily::try_from(read_var_int(recv).await?)?;
    let mut octets = match family {
        Ssh3ForwardingAddressFamily::Ipv4 => vec![0; 4],
        Ssh3ForwardingAddressFamily::Ipv6 => vec![0; 16],
    };
    read_exact(recv, &mut octets).await?;

    let mut port = [0; 2];
    read_exact(recv, &mut port).await?;
    let port = u16::from_be_bytes(port);

    match family {
        Ssh3ForwardingAddressFamily::Ipv4 => {
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap());
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        Ssh3ForwardingAddressFamily::Ipv6 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap());
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
    }
}

async fn read_var_int(recv: &mut RecvStream) -> Result<u64, Ssh3ChannelSetupError> {
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

async fn read_ssh_bytes(recv: &mut RecvStream) -> Result<Vec<u8>, Ssh3ChannelSetupError> {
    let len = read_var_int(recv).await?;
    // The length is chosen by the peer: refuse it before allocating, so a
    // hostile peer cannot make the process allocate an arbitrary buffer.
    if len > ssh3_proto::MAX_SSH_STRING_LEN {
        return Err(Ssh3ChannelSetupError::Proto(
            ssh3_proto::Ssh3Error::StringTooLong {
                length: len,
                limit: ssh3_proto::MAX_SSH_STRING_LEN,
            },
        ));
    }
    let len = usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SSH string too large"))?;
    let mut out = vec![0; len];
    read_exact(recv, &mut out).await?;
    Ok(out)
}

async fn read_byte(recv: &mut RecvStream) -> Result<u8, Ssh3ChannelSetupError> {
    let mut byte = [0; 1];
    read_exact(recv, &mut byte).await?;
    Ok(byte[0])
}

async fn read_exact(recv: &mut RecvStream, buf: &mut [u8]) -> Result<(), Ssh3ChannelSetupError> {
    recv.read_exact(buf)
        .await
        .map_err(read_exact_error_to_io)
        .map_err(Ssh3ChannelSetupError::from)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::Duration;

    use ssh3_core::{MAX_MAX_PACKET_SIZE, Ssh3AcceptedChannel, Ssh3Conversation};
    use ssh3_proto::{
        Ssh3ChannelHeader, Ssh3ChannelRequest, Ssh3ChannelRequestMessage, Ssh3Message,
        append_var_int,
    };

    use super::{
        Ssh3IncomingChannelRouter, Ssh3RouteAcceptedChannelError, accept_bi_channel, open_channel,
        open_tcp_forwarding_channel, open_udp_forwarding_channel,
    };
    use crate::{
        Ssh3QuinnDatagramSender, client_config_for_certificate, self_signed_server_config,
    };

    fn conversation_id() -> [u8; 32] {
        [7; 32]
    }

    async fn loopback() -> (
        quinn::Endpoint,
        quinn::Endpoint,
        quinn::Connection,
        quinn::Connection,
    ) {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_connection, server_connection) = tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(5), client_connecting)
                    .await
                    .unwrap()
                    .unwrap()
            },
            async {
                let incoming =
                    tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                        .await
                        .unwrap()
                        .unwrap();
                tokio::time::timeout(Duration::from_secs(5), incoming)
                    .await
                    .unwrap()
                    .unwrap()
            },
        );
        (
            client_endpoint,
            server_endpoint,
            client_connection,
            server_connection,
        )
    }

    #[tokio::test]
    async fn incoming_channels_round_trip_with_core_messages() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let conversation = Ssh3Conversation::new(
            5,
            conversation_id(),
            4096,
            8,
            Arc::new(Ssh3QuinnDatagramSender::new(client_connection.clone())),
        );
        let client_channel = open_channel(
            &conversation,
            &client_connection,
            b"session".to_vec(),
            1024,
            8,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), client_channel.maybe_send_header())
            .await
            .unwrap()
            .unwrap();

        let (incoming, send, recv) = tokio::time::timeout(
            Duration::from_secs(5),
            accept_bi_channel(&server_connection),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(incoming.header.conversation_stream_id, 5);
        assert_eq!(incoming.header.channel_type, b"session".to_vec());
        assert_eq!(incoming.forwarding_target, None);

        let server_channel = incoming.into_channel(conversation_id(), recv, send, None, 8);
        tokio::time::timeout(Duration::from_secs(5), server_channel.confirm_channel(2048))
            .await
            .unwrap()
            .unwrap();

        let request = Ssh3ChannelRequestMessage {
            want_reply: true,
            request: Ssh3ChannelRequest::Shell,
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            client_channel.send_request(request.clone()),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), server_channel.next_message())
                .await
                .unwrap()
                .unwrap(),
            Ssh3Message::ChannelRequest(request)
        );
    }

    #[tokio::test]
    async fn udp_forwarding_channels_send_quic_datagrams() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let client_conversation = Ssh3Conversation::new(
            11,
            conversation_id(),
            4096,
            8,
            Arc::new(Ssh3QuinnDatagramSender::new(client_connection.clone())),
        );
        let server_conversation = Ssh3Conversation::new(
            11,
            conversation_id(),
            4096,
            8,
            Arc::new(Ssh3QuinnDatagramSender::new(server_connection.clone())),
        );
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 443));
        let client_channel = open_udp_forwarding_channel(
            &client_conversation,
            &client_connection,
            1024,
            8,
            remote_addr,
        )
        .await
        .unwrap();

        let (incoming, send, recv) = tokio::time::timeout(
            Duration::from_secs(5),
            accept_bi_channel(&server_connection),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(incoming.header.channel_type, b"direct-udp".to_vec());
        assert_eq!(incoming.forwarding_target, Some(remote_addr));

        server_conversation.queue_incoming_accepted_channel(
            incoming.into_accepted_channel_for_conversation(&server_conversation, recv, send),
        );
        let accepted = tokio::time::timeout(
            Duration::from_secs(5),
            server_conversation.accept_channel_with_metadata(),
        )
        .await
        .unwrap()
        .unwrap();
        let server_channel = match accepted {
            Ssh3AcceptedChannel::UdpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert_eq!(accepted_remote_addr, remote_addr);
                channel
            }
            _ => panic!("expected UDP forwarding channel"),
        };

        tokio::time::timeout(
            Duration::from_secs(5),
            client_channel.send_datagram(vec![1, 2, 3, 4]),
        )
        .await
        .unwrap()
        .unwrap();
        let client_to_server_datagram =
            tokio::time::timeout(Duration::from_secs(5), server_connection.read_datagram())
                .await
                .unwrap()
                .unwrap();

        let mut expected = Vec::new();
        append_var_int(&mut expected, 11);
        append_var_int(&mut expected, client_channel.channel_id());
        expected.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(client_to_server_datagram.as_ref(), expected);

        tokio::time::timeout(
            Duration::from_secs(5),
            server_channel.send_datagram(vec![9, 8, 7]),
        )
        .await
        .unwrap()
        .unwrap();
        let server_to_client_datagram =
            tokio::time::timeout(Duration::from_secs(5), client_connection.read_datagram())
                .await
                .unwrap()
                .unwrap();

        let mut expected = Vec::new();
        append_var_int(&mut expected, 11);
        append_var_int(&mut expected, server_channel.channel_id());
        expected.extend_from_slice(&[9, 8, 7]);
        assert_eq!(server_to_client_datagram.as_ref(), expected);
    }

    #[tokio::test]
    async fn tcp_forwarding_channels_accept_as_typed_forwarding_channels() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let conversation = Ssh3Conversation::new(
            12,
            conversation_id(),
            4096,
            8,
            Arc::new(Ssh3QuinnDatagramSender::new(server_connection.clone())),
        );
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 22));
        let _channel =
            open_tcp_forwarding_channel(&conversation, &client_connection, 1024, 8, remote_addr)
                .await
                .unwrap();

        let (incoming, send, recv) = tokio::time::timeout(
            Duration::from_secs(5),
            accept_bi_channel(&server_connection),
        )
        .await
        .unwrap()
        .unwrap();

        let accepted = incoming.into_accepted_channel_for_conversation(&conversation, recv, send);
        match accepted {
            Ssh3AcceptedChannel::TcpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert_eq!(channel.channel_type(), b"direct-tcp");
                assert_eq!(accepted_remote_addr, remote_addr);
            }
            _ => panic!("expected TCP forwarding channel"),
        }
    }

    #[tokio::test]
    async fn router_queues_channels_for_registered_conversations() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let control_stream_id = 21;
        let client_conversation = Ssh3Conversation::new(
            control_stream_id,
            conversation_id(),
            4096,
            8,
            Arc::new(Ssh3QuinnDatagramSender::new(client_connection.clone())),
        );
        let server_conversation = Arc::new(Ssh3Conversation::new(
            control_stream_id,
            conversation_id(),
            4096,
            8,
            Arc::new(Ssh3QuinnDatagramSender::new(server_connection.clone())),
        ));
        let router = Ssh3IncomingChannelRouter::new();
        router.register_conversation(server_conversation.clone());

        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 15), 5353));
        let client_channel = open_udp_forwarding_channel(
            &client_conversation,
            &client_connection,
            1024,
            8,
            remote_addr,
        )
        .await
        .unwrap();

        let routed_conversation = tokio::time::timeout(
            Duration::from_secs(5),
            router.accept_and_route_channel(&server_connection),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(Arc::ptr_eq(&routed_conversation, &server_conversation));

        let accepted = tokio::time::timeout(
            Duration::from_secs(5),
            server_conversation.accept_channel_with_metadata(),
        )
        .await
        .unwrap()
        .unwrap();
        let server_channel = match accepted {
            Ssh3AcceptedChannel::UdpForwarding {
                channel,
                remote_addr: accepted_remote_addr,
            } => {
                assert_eq!(accepted_remote_addr, remote_addr);
                channel
            }
            _ => panic!("expected UDP forwarding channel"),
        };

        tokio::time::timeout(
            Duration::from_secs(5),
            client_channel.send_datagram(vec![6, 5, 4]),
        )
        .await
        .unwrap()
        .unwrap();
        let mut expected = Vec::new();
        append_var_int(&mut expected, control_stream_id);
        append_var_int(&mut expected, client_channel.channel_id());
        expected.extend_from_slice(&[6, 5, 4]);
        let datagram =
            tokio::time::timeout(Duration::from_secs(5), server_connection.read_datagram())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(datagram.as_ref(), expected);

        tokio::time::timeout(
            Duration::from_secs(5),
            server_channel.send_datagram(vec![1, 1, 2, 3]),
        )
        .await
        .unwrap()
        .unwrap();
        let mut expected = Vec::new();
        append_var_int(&mut expected, control_stream_id);
        append_var_int(&mut expected, server_channel.channel_id());
        expected.extend_from_slice(&[1, 1, 2, 3]);
        let datagram =
            tokio::time::timeout(Duration::from_secs(5), client_connection.read_datagram())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(datagram.as_ref(), expected);
    }

    #[tokio::test]
    async fn router_rejects_unknown_conversations() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let client_conversation = Ssh3Conversation::new(
            33,
            conversation_id(),
            4096,
            8,
            Arc::new(Ssh3QuinnDatagramSender::new(client_connection.clone())),
        );
        let router = Ssh3IncomingChannelRouter::new();

        let channel = open_channel(
            &client_conversation,
            &client_connection,
            b"session".to_vec(),
            1024,
            8,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), channel.maybe_send_header())
            .await
            .unwrap()
            .unwrap();

        match tokio::time::timeout(
            Duration::from_secs(5),
            router.accept_and_route_channel(&server_connection),
        )
        .await
        .unwrap()
        {
            Err(Ssh3RouteAcceptedChannelError::Route(
                super::Ssh3RouteIncomingChannelError::UnknownConversation {
                    control_stream_id,
                    channel_id,
                },
            )) => {
                assert_eq!(control_stream_id, 33);
                assert_eq!(channel_id % 4, 0);
            }
            _ => panic!("expected routing error"),
        }
    }

    /// Opens a stream and writes a channel header with the given maximum
    /// packet size, the way a peer that announces a value of its own would.
    async fn open_raw_channel(
        connection: &quinn::Connection,
        conversation_stream_id: u64,
        max_packet_size: u64,
    ) -> (quinn::SendStream, quinn::RecvStream) {
        let (mut send, recv) = connection.open_bi().await.unwrap();
        let header = Ssh3ChannelHeader {
            conversation_stream_id,
            channel_type: b"session".to_vec(),
            max_packet_size,
        };
        send.write_all(&header.encode(None)).await.unwrap();
        (send, recv)
    }

    #[tokio::test]
    async fn incoming_channels_reject_an_oversized_max_packet_size() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;
        let _raw = open_raw_channel(&client_connection, 5, MAX_MAX_PACKET_SIZE + 1).await;

        match tokio::time::timeout(
            Duration::from_secs(5),
            accept_bi_channel(&server_connection),
        )
        .await
        .unwrap()
        {
            Err(super::Ssh3AcceptChannelError::Setup(super::Ssh3ChannelSetupError::Io(err))) => {
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            }
            other => panic!("expected the channel to be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn incoming_channels_bound_the_max_packet_size_of_the_peer() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let local_max_packet_size = 4096;
        let conversation = Ssh3Conversation::new(
            5,
            conversation_id(),
            local_max_packet_size,
            8,
            Arc::new(Ssh3QuinnDatagramSender::new(client_connection.clone())),
        );
        let router = Ssh3IncomingChannelRouter::new();
        router.register_conversation(Arc::new(conversation));

        // The peer announces a value above the one this endpoint announces.
        let _raw = open_raw_channel(&client_connection, 5, 1 << 20).await;

        let conversation = router
            .accept_and_route_channel(&server_connection)
            .await
            .unwrap();
        let accepted = conversation.accept_channel_with_metadata().await.unwrap();
        let channel = accepted.channel();
        assert_eq!(channel.max_packet_size(), local_max_packet_size);
    }

    /// A peer that announces a maximum packet size below the floor does not
    /// starve the channel: the value is raised to the floor, and the channel
    /// still works.
    #[tokio::test]
    async fn incoming_channels_floor_the_max_packet_size_of_the_peer() {
        let (_client_endpoint, _server_endpoint, client_connection, server_connection) =
            loopback().await;

        let local_max_packet_size = 30_000;
        let conversation = Ssh3Conversation::new(
            5,
            conversation_id(),
            local_max_packet_size,
            8,
            Arc::new(Ssh3QuinnDatagramSender::new(client_connection.clone())),
        );
        let router = Ssh3IncomingChannelRouter::new();
        router.register_conversation(Arc::new(conversation));

        // The peer announces a value below the floor of the protocol.
        let _raw = open_raw_channel(&client_connection, 5, 0).await;

        let conversation = router
            .accept_and_route_channel(&server_connection)
            .await
            .unwrap();
        let accepted = conversation.accept_channel_with_metadata().await.unwrap();
        let channel = accepted.channel();
        assert_eq!(channel.max_packet_size(), ssh3_core::MIN_MAX_PACKET_SIZE);
    }
}
