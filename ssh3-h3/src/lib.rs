use std::{fmt, io::Cursor, sync::Arc};

use bytes::Bytes;
use h3::ext::Protocol;
use http::{
    HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{SERVER, USER_AGENT},
};
use ssh3_core::{
    Ssh3Conversation, Ssh3ConversationError, Ssh3ConversationId, negotiate_with_version_string,
};
use ssh3_proto::read_var_int;
use ssh3_quinn::{
    Ssh3IncomingChannelRouter, Ssh3QuinnDatagramSender, Ssh3RouteAcceptedChannelError,
};

pub const SSH3_PROTOCOL_NAME: &str = "ssh3";
pub const SSH3_EXPORTER_LABEL: &[u8] = b"EXPORTER-SSH3";
pub const SSH3_CONVERSATION_ID_LEN: usize = 32;
pub const SSH3_USER_HEADER: &str = "x-ssh3-user";
/// The version string of this build.
///
/// The `compress=` field announces the codecs this build can decode, in the
/// same order the reference implementation announces them (the capability
/// mask of the channel body compression). The field is optional on the wire:
/// a peer without it simply never sends compressed frames.
pub const SSH3_VERSION_STRING: &str =
    "SSH 3.0 ssh3-rust 0.1.0 experimental_spec_version=alpha-00 compress=zstd,deflate,lz4";
/// The maximum size of the HEADERS field section an endpoint accepts.
///
/// The HTTP/3 layer buffers the whole compressed field section of a HEADERS
/// frame before it decodes it, and the library default lets that buffer grow
/// up to `VarInt::MAX`: without this limit a peer grows the receive buffers
/// of the connection with oversized HEADERS before any authentication
/// happens. 16 KiB holds the SSH3 CONNECT request (the method, the
/// `:protocol` pseudo-header, the path, the `Authorization` and the user
/// agent headers) with room to spare (audit 2026-10-27, finding 3.5.1).
pub const MAX_FIELD_SECTION_SIZE: u64 = 16 * 1024;

pub type Ssh3QuinnConnection = h3_quinn::Connection;
pub type Ssh3ClientConnection = h3::client::Connection<Ssh3QuinnConnection, Bytes>;
pub type Ssh3ServerConnection = h3::server::Connection<Ssh3QuinnConnection, Bytes>;
pub type Ssh3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
pub type Ssh3ClientControlStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub type Ssh3ServerControlStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Debug)]
pub enum Ssh3BuildConnectRequestError {
    InvalidUserAgent(http::header::InvalidHeaderValue),
    Http(http::Error),
}

impl fmt::Display for Ssh3BuildConnectRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUserAgent(err) => write!(f, "{err}"),
            Self::Http(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Ssh3BuildConnectRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUserAgent(err) => Some(err),
            Self::Http(err) => Some(err),
        }
    }
}

impl From<http::header::InvalidHeaderValue> for Ssh3BuildConnectRequestError {
    fn from(value: http::header::InvalidHeaderValue) -> Self {
        Self::InvalidUserAgent(value)
    }
}

impl From<http::Error> for Ssh3BuildConnectRequestError {
    fn from(value: http::Error) -> Self {
        Self::Http(value)
    }
}

#[derive(Debug)]
pub struct Ssh3ConversationIdError {
    inner: h3_quinn::quinn::crypto::ExportKeyingMaterialError,
}

impl fmt::Display for Ssh3ConversationIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to export conversation keying material: {:?}",
            self.inner
        )
    }
}

impl std::error::Error for Ssh3ConversationIdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<h3_quinn::quinn::crypto::ExportKeyingMaterialError> for Ssh3ConversationIdError {
    fn from(value: h3_quinn::quinn::crypto::ExportKeyingMaterialError) -> Self {
        Self { inner: value }
    }
}

#[derive(Debug)]
pub enum Ssh3ClientConversationError {
    ConversationId(Ssh3ConversationIdError),
    Stream(h3::error::StreamError),
    UnexpectedStatus { status: StatusCode },
}

impl fmt::Display for Ssh3ClientConversationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConversationId(err) => write!(f, "{err}"),
            Self::Stream(err) => write!(f, "{err}"),
            Self::UnexpectedStatus { status } => write!(f, "unexpected HTTP status: {status}"),
        }
    }
}

impl std::error::Error for Ssh3ClientConversationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConversationId(err) => Some(err),
            Self::Stream(err) => Some(err),
            Self::UnexpectedStatus { .. } => None,
        }
    }
}

impl From<Ssh3ConversationIdError> for Ssh3ClientConversationError {
    fn from(value: Ssh3ConversationIdError) -> Self {
        Self::ConversationId(value)
    }
}

impl From<h3::error::StreamError> for Ssh3ClientConversationError {
    fn from(value: h3::error::StreamError) -> Self {
        Self::Stream(value)
    }
}

#[derive(Debug)]
pub enum Ssh3ServerConversationError {
    Connection(h3::error::ConnectionError),
    Stream(h3::error::StreamError),
    ConversationId(Ssh3ConversationIdError),
}

impl fmt::Display for Ssh3ServerConversationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "{err}"),
            Self::Stream(err) => write!(f, "{err}"),
            Self::ConversationId(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Ssh3ServerConversationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::Stream(err) => Some(err),
            Self::ConversationId(err) => Some(err),
        }
    }
}

impl From<h3::error::ConnectionError> for Ssh3ServerConversationError {
    fn from(value: h3::error::ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<h3::error::StreamError> for Ssh3ServerConversationError {
    fn from(value: h3::error::StreamError) -> Self {
        Self::Stream(value)
    }
}

impl From<Ssh3ConversationIdError> for Ssh3ServerConversationError {
    fn from(value: Ssh3ConversationIdError) -> Self {
        Self::ConversationId(value)
    }
}

#[derive(Debug)]
pub enum Ssh3DatagramDispatchError {
    Connection(h3_quinn::quinn::ConnectionError),
    Proto(ssh3_proto::Ssh3Error),
    Conversation(Ssh3ConversationError),
}

impl fmt::Display for Ssh3DatagramDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "{err}"),
            Self::Proto(err) => write!(f, "{err}"),
            Self::Conversation(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Ssh3DatagramDispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(err) => Some(err),
            Self::Proto(err) => Some(err),
            Self::Conversation(err) => Some(err),
        }
    }
}

impl From<h3_quinn::quinn::ConnectionError> for Ssh3DatagramDispatchError {
    fn from(value: h3_quinn::quinn::ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<ssh3_proto::Ssh3Error> for Ssh3DatagramDispatchError {
    fn from(value: ssh3_proto::Ssh3Error) -> Self {
        Self::Proto(value)
    }
}

impl From<Ssh3ConversationError> for Ssh3DatagramDispatchError {
    fn from(value: Ssh3ConversationError) -> Self {
        Self::Conversation(value)
    }
}

pub struct Ssh3EstablishedClientConversation {
    pub conversation: Arc<Ssh3Conversation>,
    pub connection: h3_quinn::quinn::Connection,
    pub control_stream: Ssh3ClientControlStream,
    pub response: Response<()>,
}

pub struct Ssh3AcceptedServerConversation {
    pub conversation: Arc<Ssh3Conversation>,
    pub connection: h3_quinn::quinn::Connection,
    pub control_stream: Ssh3ServerControlStream,
    pub request: Request<()>,
}

pub struct Ssh3ServerConnectionDriver {
    connection: h3_quinn::quinn::Connection,
    server: Ssh3ServerConnection,
    channel_router: Arc<Ssh3IncomingChannelRouter>,
}

impl Ssh3ServerConnectionDriver {
    pub async fn new(
        connection: h3_quinn::quinn::Connection,
    ) -> Result<Self, h3::error::ConnectionError> {
        let server = new_server(connection.clone()).await?;
        Ok(Self {
            connection,
            server,
            channel_router: Arc::new(Ssh3IncomingChannelRouter::new()),
        })
    }

    pub fn connection(&self) -> &h3_quinn::quinn::Connection {
        &self.connection
    }

    pub fn channel_router(&self) -> &Arc<Ssh3IncomingChannelRouter> {
        &self.channel_router
    }

    pub async fn accept_conversation(
        &mut self,
        max_packet_size: u64,
        default_datagrams_queue_size: usize,
    ) -> Result<Option<Ssh3AcceptedServerConversation>, Ssh3ServerConversationError> {
        let accepted = accept_server_conversation(
            &mut self.server,
            self.connection.clone(),
            max_packet_size,
            default_datagrams_queue_size,
        )
        .await?;
        if let Some(conversation) = accepted
            .as_ref()
            .map(|accepted| accepted.conversation.clone())
        {
            self.channel_router.register_conversation(conversation);
        }
        Ok(accepted)
    }

    pub fn unregister_conversation(&self, control_stream_id: u64) -> Option<Arc<Ssh3Conversation>> {
        self.channel_router
            .unregister_conversation(control_stream_id)
    }

    pub async fn route_datagram(
        &self,
        datagram: &[u8],
    ) -> Result<Option<Arc<Ssh3Conversation>>, Ssh3DatagramDispatchError> {
        route_registered_datagram(self.channel_router.as_ref(), datagram).await
    }

    pub async fn accept_and_route_datagram(
        &self,
    ) -> Result<Option<Arc<Ssh3Conversation>>, Ssh3DatagramDispatchError> {
        let datagram = self.connection.read_datagram().await?;
        self.route_datagram(&datagram).await
    }

    pub async fn accept_and_route_datagrams_forever(
        &self,
    ) -> Result<(), Ssh3DatagramDispatchError> {
        loop {
            self.accept_and_route_datagram().await?;
        }
    }

    pub async fn accept_and_route_channel(
        &self,
    ) -> Result<Arc<Ssh3Conversation>, Ssh3RouteAcceptedChannelError> {
        self.channel_router
            .accept_and_route_channel(&self.connection)
            .await
    }

    pub async fn accept_and_route_channels_forever(
        &self,
    ) -> Result<(), Ssh3RouteAcceptedChannelError> {
        self.channel_router
            .clone()
            .accept_and_route_channels_forever(self.connection.clone())
            .await
    }
}

pub fn ssh3_protocol() -> Protocol {
    Protocol::new(SSH3_PROTOCOL_NAME)
}

/// Configures the HTTP/3 layer of the client.
///
/// The extended CONNECT is required: SSH3 tunnels its conversation over a
/// CONNECT request with the `:protocol` pseudo-header set to `ssh3`.
///
/// The HEADERS field sections the peer sends stay bounded by
/// [`MAX_FIELD_SECTION_SIZE`]: the HTTP/3 layer buffers a whole field
/// section before it decodes it, and the client applies the limit to the
/// response headers of the server before any conversation is established.
///
/// The HTTP/3 datagram setting stays disabled on purpose. SSH3 carries its
/// own datagrams (the UDP forwarding) directly over the QUIC datagram API,
/// and the HTTP/3 datagram layer of the peer would open a second reader on
/// the same connection-wide datagram queue and steal the SSH3 datagrams.
/// A peer that implements the HTTP/3 datagram extension starts that reader
/// as soon as the SETTINGS frame of its peer announces the datagram
/// support (quic-go does it in `http3/conn.go`, `handleControlStream`), so
/// the setting must not be announced at all.
pub fn configure_client_builder(builder: &mut h3::client::Builder) -> &mut h3::client::Builder {
    builder
        .enable_extended_connect(true)
        .enable_datagram(false)
        .max_field_section_size(MAX_FIELD_SECTION_SIZE)
}

/// Configures the HTTP/3 layer of the server.
///
/// See [`configure_client_builder`] for the reason why the HTTP/3 datagram
/// setting stays disabled, and for the reason why the HEADERS field
/// sections of the peer stay bounded by [`MAX_FIELD_SECTION_SIZE`]. On the
/// server the limit applies to the request headers of the client, before
/// any authentication happens.
pub fn configure_server_builder(builder: &mut h3::server::Builder) -> &mut h3::server::Builder {
    builder
        .enable_extended_connect(true)
        .enable_datagram(false)
        .max_field_section_size(MAX_FIELD_SECTION_SIZE)
}

pub async fn new_client(
    connection: h3_quinn::quinn::Connection,
) -> Result<(Ssh3ClientConnection, Ssh3SendRequest), h3::error::ConnectionError> {
    let mut builder = h3::client::builder();
    configure_client_builder(&mut builder);
    builder.build(Ssh3QuinnConnection::new(connection)).await
}

pub async fn new_server(
    connection: h3_quinn::quinn::Connection,
) -> Result<Ssh3ServerConnection, h3::error::ConnectionError> {
    let mut builder = h3::server::builder();
    configure_server_builder(&mut builder);
    builder.build(Ssh3QuinnConnection::new(connection)).await
}

pub fn build_connect_request(
    uri: Uri,
    user_agent: impl AsRef<str>,
) -> Result<Request<()>, Ssh3BuildConnectRequestError> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())?;
    request
        .headers_mut()
        .insert(USER_AGENT, HeaderValue::from_str(user_agent.as_ref())?);
    request.extensions_mut().insert(ssh3_protocol());
    Ok(request)
}

pub fn generate_conversation_id(
    connection: &h3_quinn::quinn::Connection,
) -> Result<Ssh3ConversationId, Ssh3ConversationIdError> {
    let mut conversation_id = [0; SSH3_CONVERSATION_ID_LEN];
    connection.export_keying_material(&mut conversation_id, SSH3_EXPORTER_LABEL, &[])?;
    Ok(conversation_id)
}

pub async fn establish_client_conversation(
    send_request: &mut Ssh3SendRequest,
    connection: h3_quinn::quinn::Connection,
    request: Request<()>,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
) -> Result<Ssh3EstablishedClientConversation, Ssh3ClientConversationError> {
    let conversation_id = generate_conversation_id(&connection)?;
    let mut control_stream = send_request.send_request(request).await?;
    let response = control_stream.recv_response().await?;
    if response.status() != StatusCode::OK {
        return Err(Ssh3ClientConversationError::UnexpectedStatus {
            status: response.status(),
        });
    }

    let conversation = Arc::new(Ssh3Conversation::new(
        control_stream.id().into_inner(),
        conversation_id,
        max_packet_size,
        default_datagrams_queue_size,
        Arc::new(Ssh3QuinnDatagramSender::new(connection.clone())),
    ));
    // The compression of the channel body: the codec both sides derive from
    // the capability the peer announced in its version string, the same way
    // the reference implementation derives it from its peerVersion. A peer
    // that announced nothing keeps the plain frames.
    conversation.set_compression_algorithm(
        response_server_header(&response)
            .map(negotiate_with_version_string)
            .unwrap_or(ssh3_core::ALGORITHM_NONE),
    );

    Ok(Ssh3EstablishedClientConversation {
        conversation,
        connection,
        control_stream,
        response,
    })
}

pub async fn accept_server_conversation(
    server: &mut Ssh3ServerConnection,
    connection: h3_quinn::quinn::Connection,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
) -> Result<Option<Ssh3AcceptedServerConversation>, Ssh3ServerConversationError> {
    let Some(resolver) = server.accept().await? else {
        return Ok(None);
    };
    let (request, control_stream) = resolver.resolve_request().await?;
    let conversation_id = generate_conversation_id(&connection)?;
    let conversation = Arc::new(Ssh3Conversation::new(
        control_stream.id().into_inner(),
        conversation_id,
        max_packet_size,
        default_datagrams_queue_size,
        Arc::new(Ssh3QuinnDatagramSender::new(connection.clone())),
    ));
    // The compression of the channel body: the codec both sides derive from
    // the capability the client announced in its User-Agent, the same way the
    // reference implementation derives it from its peerVersion. A client that
    // announced nothing keeps the plain frames.
    if let Some(user_agent) = request_user_agent(&request) {
        conversation.set_compression_algorithm(negotiate_with_version_string(user_agent));
    }

    Ok(Some(Ssh3AcceptedServerConversation {
        conversation,
        connection,
        control_stream,
        request,
    }))
}

pub fn request_protocol(request: &Request<()>) -> Option<&Protocol> {
    request.extensions().get::<Protocol>()
}

pub fn is_ssh3_connect(request: &Request<()>) -> bool {
    request.method() == Method::CONNECT
        && request_protocol(request).is_some_and(|protocol| protocol.as_str() == SSH3_PROTOCOL_NAME)
}

pub fn response_server_header(response: &Response<()>) -> Option<&str> {
    response
        .headers()
        .get(SERVER)
        .and_then(|value| value.to_str().ok())
}

pub fn request_user_agent(request: &Request<()>) -> Option<&str> {
    request
        .headers()
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
}

pub fn response_with_server_header(
    status: StatusCode,
    server_version: impl AsRef<str>,
) -> Result<Response<()>, Ssh3BuildConnectRequestError> {
    Ok(Response::builder()
        .status(status)
        .header(SERVER, HeaderValue::from_str(server_version.as_ref())?)
        .body(())?)
}

pub async fn dispatch_datagram(
    conversation: &Ssh3Conversation,
    datagram: &[u8],
) -> Result<(), Ssh3DatagramDispatchError> {
    let mut cursor = Cursor::new(datagram);
    let control_stream_id = read_var_int(&mut cursor)?;
    if control_stream_id != conversation.control_stream_id() {
        return Ok(());
    }

    let offset = cursor.position() as usize;
    match conversation.add_datagram(&datagram[offset..]).await {
        Ok(()) | Err(Ssh3ConversationError::ChannelNotFound { .. }) => Ok(()),
        Err(err) => Err(Ssh3DatagramDispatchError::Conversation(err)),
    }
}

pub async fn route_registered_datagram(
    channel_router: &Ssh3IncomingChannelRouter,
    datagram: &[u8],
) -> Result<Option<Arc<Ssh3Conversation>>, Ssh3DatagramDispatchError> {
    let mut cursor = Cursor::new(datagram);
    let control_stream_id = read_var_int(&mut cursor)?;
    let Some(conversation) = channel_router.conversation(control_stream_id) else {
        return Ok(None);
    };

    let offset = cursor.position() as usize;
    match conversation.add_datagram(&datagram[offset..]).await {
        Ok(()) | Err(Ssh3ConversationError::ChannelNotFound { .. }) => Ok(Some(conversation)),
        Err(err) => Err(Ssh3DatagramDispatchError::Conversation(err)),
    }
}

pub async fn dispatch_one_datagram(
    conversation: &Ssh3Conversation,
    connection: &h3_quinn::quinn::Connection,
) -> Result<(), Ssh3DatagramDispatchError> {
    let datagram = connection.read_datagram().await?;
    dispatch_datagram(conversation, &datagram).await
}

pub async fn dispatch_datagrams_forever(
    conversation: Arc<Ssh3Conversation>,
    connection: h3_quinn::quinn::Connection,
) -> Result<(), Ssh3DatagramDispatchError> {
    loop {
        dispatch_one_datagram(conversation.as_ref(), &connection).await?;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;

    use futures_util::future;
    use http::{StatusCode, Version};
    use ssh3_core::Ssh3AcceptedChannel;
    use ssh3_quinn::{
        client_config_for_certificate, open_udp_forwarding_channel, self_signed_server_config,
    };
    use tokio::sync::oneshot;

    use super::{
        MAX_FIELD_SECTION_SIZE, SSH3_PROTOCOL_NAME, SSH3_VERSION_STRING,
        Ssh3ServerConnectionDriver, Ssh3ServerConversationError, accept_server_conversation,
        build_connect_request, establish_client_conversation, is_ssh3_connect, new_client,
        new_server, request_protocol, request_user_agent, response_server_header,
        response_with_server_header,
    };

    #[test]
    fn build_connect_request_sets_ssh3_protocol_and_user_agent() {
        let request = build_connect_request(
            "https://localhost/ssh3-term".parse().unwrap(),
            SSH3_VERSION_STRING,
        )
        .unwrap();

        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(
            request_protocol(&request).map(|protocol| protocol.as_str()),
            Some(SSH3_PROTOCOL_NAME)
        );
        assert_eq!(request_user_agent(&request), Some(SSH3_VERSION_STRING));
    }

    /// The stream type of the HTTP/3 control stream.
    const CONTROL_STREAM_TYPE: u64 = 0x00;
    /// The type of the HTTP/3 SETTINGS frame.
    const SETTINGS_FRAME_TYPE: u64 = 0x04;
    /// The HTTP/3 setting that announces the HTTP/3 datagram support.
    const SETTING_H3_DATAGRAM: u64 = 0x33;

    /// Reads a QUIC variable-length integer from a receive stream.
    async fn read_stream_var_int(stream: &mut h3_quinn::quinn::RecvStream) -> u64 {
        let mut first = [0u8; 1];
        stream.read_exact(&mut first).await.unwrap();
        let length = 1usize << ((first[0] & 0xc0) >> 6);
        let mut value = u64::from(first[0] & 0x3f);
        for _ in 1..length {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            value = (value << 8) | u64::from(byte[0]);
        }
        value
    }

    /// Reads a QUIC variable-length integer from a buffer.
    fn read_buffer_var_int(buffer: &[u8], offset: &mut usize) -> u64 {
        let first = buffer[*offset];
        *offset += 1;
        let length = 1usize << ((first & 0xc0) >> 6);
        let mut value = u64::from(first & 0x3f);
        for _ in 1..length {
            let byte = buffer[*offset];
            *offset += 1;
            value = (value << 8) | u64::from(byte);
        }
        value
    }

    /// Reads the SETTINGS frame of a peer and returns the announced settings.
    ///
    /// The settings are read at the QUIC level, below the HTTP/3 layer: the
    /// test needs to see what the peer puts on the wire, not what the HTTP/3
    /// library made of it.
    async fn read_peer_settings(connection: &h3_quinn::quinn::Connection) -> Vec<(u64, u64)> {
        let mut stream = connection.accept_uni().await.unwrap();
        assert_eq!(read_stream_var_int(&mut stream).await, CONTROL_STREAM_TYPE);
        assert_eq!(read_stream_var_int(&mut stream).await, SETTINGS_FRAME_TYPE);
        let length = read_stream_var_int(&mut stream).await as usize;
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).await.unwrap();

        let mut settings = Vec::new();
        let mut offset = 0usize;
        while offset < payload.len() {
            let id = read_buffer_var_int(&payload, &mut offset);
            let value = read_buffer_var_int(&payload, &mut offset);
            settings.push((id, value));
        }
        settings
    }

    /// The SSH3 datagrams travel over the QUIC datagram API, not over the
    /// HTTP/3 datagram extension. A peer that announces the HTTP/3 datagram
    /// support opens a second reader on the connection-wide datagram queue
    /// and steals the SSH3 datagrams (quic-go does it in the HTTP/3 layer of
    /// the connection, `handleControlStream`).
    #[tokio::test]
    async fn the_client_does_not_announce_the_http3_datagram_support() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = h3_quinn::quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = h3_quinn::quinn::Endpoint::client(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ))
        .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_quinn, server_quinn) =
            tokio::join!(async { client_connecting.await.unwrap() }, async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            },);

        let client_task = tokio::spawn(async move {
            let _client = new_client(client_quinn).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let settings = read_peer_settings(&server_quinn).await;
        client_task.abort();

        assert!(
            !settings
                .iter()
                .any(|(id, value)| *id == SETTING_H3_DATAGRAM && *value != 0),
            "the HTTP/3 datagram support must not be announced: {settings:?}"
        );
    }

    #[tokio::test]
    async fn bootstrap_creates_matching_client_and_server_conversations() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = h3_quinn::quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = h3_quinn::quinn::Endpoint::client(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ))
        .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_quinn, server_quinn) =
            tokio::join!(async { client_connecting.await.unwrap() }, async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            },);
        let (server_info_tx, server_info_rx) = oneshot::channel();
        let (response_seen_tx, response_seen_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut server = new_server(server_quinn.clone()).await.unwrap();
            let mut accepted = tokio::time::timeout(
                Duration::from_secs(5),
                accept_server_conversation(&mut server, server_quinn, 30_000, 10),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();

            assert!(is_ssh3_connect(&accepted.request));
            assert_eq!(accepted.request.version(), Version::HTTP_3);
            assert_eq!(
                request_user_agent(&accepted.request),
                Some(SSH3_VERSION_STRING)
            );
            assert_eq!(
                request_protocol(&accepted.request).map(|protocol| protocol.as_str()),
                Some(SSH3_PROTOCOL_NAME)
            );
            let _ = server_info_tx.send((
                accepted.conversation.conversation_id(),
                accepted.conversation.control_stream_id(),
            ));

            accepted
                .control_stream
                .send_response(
                    response_with_server_header(StatusCode::OK, SSH3_VERSION_STRING).unwrap(),
                )
                .await
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), response_seen_rx).await;
        });

        let client_task = tokio::spawn(async move {
            let client_quinn_for_close = client_quinn.clone();
            let (mut driver, mut send_request) = new_client(client_quinn.clone()).await.unwrap();
            let driver_task =
                tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

            let established = tokio::time::timeout(
                Duration::from_secs(5),
                establish_client_conversation(
                    &mut send_request,
                    client_quinn,
                    build_connect_request(
                        "https://localhost/ssh3-term?user=tester".parse().unwrap(),
                        SSH3_VERSION_STRING,
                    )
                    .unwrap(),
                    30_000,
                    10,
                ),
            )
            .await
            .unwrap()
            .unwrap();

            let (server_conversation_id, server_control_stream_id) = server_info_rx.await.unwrap();
            assert_eq!(
                established.conversation.conversation_id(),
                server_conversation_id
            );
            assert_eq!(
                established.conversation.control_stream_id(),
                server_control_stream_id
            );
            assert_eq!(
                response_server_header(&established.response),
                Some(SSH3_VERSION_STRING)
            );

            let _ = response_seen_tx.send(());
            client_quinn_for_close.close(0u32.into(), b"done");
            let _ = tokio::time::timeout(Duration::from_secs(5), driver_task)
                .await
                .unwrap();
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.unwrap();
        client_result.unwrap();
    }

    #[tokio::test]
    async fn server_driver_routes_follow_up_channels_into_the_accepted_conversation() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = h3_quinn::quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = h3_quinn::quinn::Endpoint::client(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ))
        .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_quinn, server_quinn) =
            tokio::join!(async { client_connecting.await.unwrap() }, async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            },);
        let (datagram_seen_tx, datagram_seen_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut driver = Ssh3ServerConnectionDriver::new(server_quinn).await.unwrap();
            let mut accepted = tokio::time::timeout(
                Duration::from_secs(5),
                driver.accept_conversation(30_000, 10),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();

            accepted
                .control_stream
                .send_response(
                    response_with_server_header(StatusCode::OK, SSH3_VERSION_STRING).unwrap(),
                )
                .await
                .unwrap();

            let routed_conversation =
                tokio::time::timeout(Duration::from_secs(5), driver.accept_and_route_channel())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(
                routed_conversation.control_stream_id(),
                accepted.conversation.control_stream_id()
            );

            let accepted_channel = tokio::time::timeout(
                Duration::from_secs(5),
                accepted.conversation.accept_channel_with_metadata(),
            )
            .await
            .unwrap()
            .unwrap();
            match accepted_channel {
                Ssh3AcceptedChannel::UdpForwarding {
                    channel,
                    remote_addr,
                } => {
                    assert_eq!(
                        remote_addr,
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 44), 443))
                    );
                    channel.send_datagram(vec![9, 7, 5]).await.unwrap();
                    let _ = tokio::time::timeout(Duration::from_secs(5), datagram_seen_rx).await;
                }
                _ => panic!("expected UDP forwarding channel"),
            }
        });

        let client_task = tokio::spawn(async move {
            let client_quinn_for_close = client_quinn.clone();
            let (mut driver, mut send_request) = new_client(client_quinn.clone()).await.unwrap();
            let driver_task =
                tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

            let established = tokio::time::timeout(
                Duration::from_secs(5),
                establish_client_conversation(
                    &mut send_request,
                    client_quinn.clone(),
                    build_connect_request(
                        "https://localhost/ssh3-term?user=tester".parse().unwrap(),
                        SSH3_VERSION_STRING,
                    )
                    .unwrap(),
                    30_000,
                    10,
                ),
            )
            .await
            .unwrap()
            .unwrap();

            let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 44), 443));
            let channel = open_udp_forwarding_channel(
                established.conversation.as_ref(),
                &client_quinn,
                1024,
                10,
                remote_addr,
            )
            .await
            .unwrap();

            let datagram =
                tokio::time::timeout(Duration::from_secs(5), client_quinn.read_datagram())
                    .await
                    .unwrap()
                    .unwrap();
            let mut expected = Vec::new();
            ssh3_proto::append_var_int(&mut expected, established.conversation.control_stream_id());
            ssh3_proto::append_var_int(&mut expected, channel.channel_id());
            expected.extend_from_slice(&[9, 7, 5]);
            assert_eq!(datagram.as_ref(), expected);
            let _ = datagram_seen_tx.send(());

            client_quinn_for_close.close(0u32.into(), b"done");
            let _ = tokio::time::timeout(Duration::from_secs(5), driver_task)
                .await
                .unwrap();
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.unwrap();
        client_result.unwrap();
    }

    #[tokio::test]
    async fn server_driver_routes_datagrams_into_the_registered_conversation() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = h3_quinn::quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = h3_quinn::quinn::Endpoint::client(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ))
        .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_quinn, server_quinn) =
            tokio::join!(async { client_connecting.await.unwrap() }, async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            },);
        let (channel_ready_tx, channel_ready_rx) = oneshot::channel::<()>();
        let (datagram_seen_tx, datagram_seen_rx) = oneshot::channel::<()>();

        let server_task = async move {
            let mut driver = Ssh3ServerConnectionDriver::new(server_quinn).await.unwrap();
            let mut accepted = tokio::time::timeout(
                Duration::from_secs(5),
                driver.accept_conversation(30_000, 10),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();

            accepted
                .control_stream
                .send_response(
                    response_with_server_header(StatusCode::OK, SSH3_VERSION_STRING).unwrap(),
                )
                .await
                .unwrap();

            let _ = tokio::time::timeout(Duration::from_secs(5), driver.accept_and_route_channel())
                .await
                .unwrap()
                .unwrap();
            let accepted_channel = tokio::time::timeout(
                Duration::from_secs(5),
                accepted.conversation.accept_channel_with_metadata(),
            )
            .await
            .unwrap()
            .unwrap();
            let server_channel = match accepted_channel {
                Ssh3AcceptedChannel::UdpForwarding {
                    channel,
                    remote_addr,
                } => {
                    assert_eq!(
                        remote_addr,
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 55), 9000))
                    );
                    channel
                }
                _ => panic!("expected UDP forwarding channel"),
            };
            let _ = channel_ready_tx.send(());

            let routed_conversation =
                tokio::time::timeout(Duration::from_secs(5), driver.accept_and_route_datagram())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(
                routed_conversation.control_stream_id(),
                accepted.conversation.control_stream_id()
            );
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), server_channel.receive_datagram())
                    .await
                    .unwrap(),
                vec![4, 3, 2, 1]
            );
            let _ = datagram_seen_tx.send(());
        };

        let client_task = async move {
            let client_quinn_for_close = client_quinn.clone();
            let (mut driver, mut send_request) = new_client(client_quinn.clone()).await.unwrap();
            let driver_task =
                tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

            let established = tokio::time::timeout(
                Duration::from_secs(5),
                establish_client_conversation(
                    &mut send_request,
                    client_quinn.clone(),
                    build_connect_request(
                        "https://localhost/ssh3-term?user=tester".parse().unwrap(),
                        SSH3_VERSION_STRING,
                    )
                    .unwrap(),
                    30_000,
                    10,
                ),
            )
            .await
            .unwrap()
            .unwrap();

            let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 55), 9000));
            let channel = open_udp_forwarding_channel(
                established.conversation.as_ref(),
                &client_quinn,
                1024,
                10,
                remote_addr,
            )
            .await
            .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), channel_ready_rx).await;
            channel.send_datagram(vec![4, 3, 2, 1]).await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), datagram_seen_rx).await;

            client_quinn_for_close.close(0u32.into(), b"done");
            let _ = tokio::time::timeout(Duration::from_secs(5), driver_task)
                .await
                .unwrap();
        };

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        let _ = (server_result, client_result);
    }

    /// The type of the HTTP/3 HEADERS frame.
    const HEADERS_FRAME_TYPE: u64 = 0x01;
    /// The HTTP/3 setting that announces the maximum field section size.
    const SETTING_MAX_HEADER_LIST_SIZE: u64 = 0x06;

    /// The limit stays at the pre-auth bound the endpoints are built for:
    /// the number is pinned so a casual edit does not silently widen it.
    #[test]
    fn the_field_section_limit_is_16_kib() {
        assert_eq!(MAX_FIELD_SECTION_SIZE, 16384);
    }

    /// Each endpoint announces its field section limit in the SETTINGS frame
    /// of its control stream: the peer uses the announced value as the bound
    /// of the HEADERS it sends back, so the limit only protects the endpoint
    /// if the setting is actually on the wire.
    #[tokio::test]
    async fn the_endpoints_announce_their_max_field_section_size() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = h3_quinn::quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = h3_quinn::quinn::Endpoint::client(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ))
        .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_quinn, server_quinn) =
            tokio::join!(async { client_connecting.await.unwrap() }, async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            },);

        let client_quinn_for_settings = client_quinn.clone();
        let client_task = tokio::spawn(async move {
            let _client = new_client(client_quinn_for_settings).await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let server_quinn_for_settings = server_quinn.clone();
        let server_task = tokio::spawn(async move {
            let _server = new_server(server_quinn_for_settings).await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        // The settings of the client, read on the server endpoint.
        let client_settings = read_peer_settings(&server_quinn).await;
        // The settings of the server, read on the client endpoint.
        let server_settings = read_peer_settings(&client_quinn).await;
        client_task.abort();
        server_task.abort();

        for (who, settings) in [("client", client_settings), ("server", server_settings)] {
            assert!(
                settings.iter().any(|(id, value)| {
                    *id == SETTING_MAX_HEADER_LIST_SIZE && *value == MAX_FIELD_SECTION_SIZE
                }),
                "the {who} must announce the field section limit: {settings:?}"
            );
        }
    }

    /// Builds a QPACK stateless field section with one literal header field
    /// without name reference whose decoded size exceeds
    /// [`MAX_FIELD_SECTION_SIZE`].
    ///
    /// The wire format is written by hand: a rogue peer ignores the limit
    /// announced by the SETTINGS frame of its peer and does not go through
    /// the HTTP/3 layer of the client, which would refuse to send the
    /// request. The prefix integers of QPACK continue in little endian
    /// 7-bit groups.
    fn oversized_field_section(value_len: usize) -> Vec<u8> {
        let mut block = vec![
            0x00, // the required insert count: 0
            0x00, // the delta base: 0
            0x21, // a literal field without name reference, name length 1
            b'a',
        ];
        let mut remaining = value_len as u64 - 127;
        block.push(0x7f); // the value length: the 7 inline bits are exhausted
        while remaining >= 128 {
            block.push((remaining % 128) as u8 + 128);
            remaining /= 128;
        }
        block.push(remaining as u8);
        block.extend(std::iter::repeat_n(b'x', value_len));
        block
    }

    /// Opens a raw QUIC stream and sends one HEADERS frame with the given
    /// field section, without any HTTP/3 client layer.
    ///
    /// The receive side stays with the caller: the server answers the
    /// oversized request on it, and a dropped receive side would carry the
    /// `STOP_SENDING` that turns the answer into a remote-terminate error
    /// before the headers rejection comes through.
    async fn send_raw_headers_frame(
        connection: &h3_quinn::quinn::Connection,
        field_section: Vec<u8>,
    ) -> h3_quinn::quinn::RecvStream {
        let (mut send, recv) = connection.open_bi().await.unwrap();
        let mut frame = Vec::new();
        ssh3_proto::append_var_int(&mut frame, HEADERS_FRAME_TYPE);
        ssh3_proto::append_var_int(&mut frame, field_section.len() as u64);
        frame.extend_from_slice(&field_section);
        send.write_all(&frame).await.unwrap();
        send.finish().unwrap();
        recv
    }

    /// The field section limit holds before any authentication: a rogue peer
    /// that sends request headers above the announced limit gets its request
    /// rejected instead of having its headers buffered by the HTTP/3 layer.
    #[tokio::test]
    async fn the_server_rejects_request_headers_above_the_field_section_limit() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = h3_quinn::quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = h3_quinn::quinn::Endpoint::client(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ))
        .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let (client_quinn, server_quinn) =
            tokio::join!(async { client_connecting.await.unwrap() }, async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            },);
        let (server_done_tx, server_done_rx) = oneshot::channel();

        let _server_task = tokio::spawn(async move {
            let mut server = new_server(server_quinn.clone()).await.unwrap();
            let accepted = tokio::time::timeout(
                Duration::from_secs(5),
                accept_server_conversation(&mut server, server_quinn, 30_000, 10),
            )
            .await
            .unwrap();
            let _ = server_done_tx.send(accepted);
        });

        let client_task = tokio::spawn(async move {
            // The unidirectional streams of a real HTTP/3 client go first:
            // the control stream carries the (empty) SETTINGS, and the QPACK
            // encoder and decoder streams complete the connection preamble
            // the server waits for before it reads the request streams.
            let mut control = client_quinn.open_uni().await.unwrap();
            let mut settings = Vec::new();
            ssh3_proto::append_var_int(&mut settings, CONTROL_STREAM_TYPE);
            ssh3_proto::append_var_int(&mut settings, SETTINGS_FRAME_TYPE);
            ssh3_proto::append_var_int(&mut settings, 0);
            control.write_all(&settings).await.unwrap();
            let mut encoder_header = Vec::new();
            ssh3_proto::append_var_int(&mut encoder_header, 0x02);
            let mut encoder = client_quinn.open_uni().await.unwrap();
            encoder.write_all(&encoder_header).await.unwrap();
            let mut decoder_header = Vec::new();
            ssh3_proto::append_var_int(&mut decoder_header, 0x03);
            let mut decoder = client_quinn.open_uni().await.unwrap();
            decoder.write_all(&decoder_header).await.unwrap();
            let _answer_recv =
                send_raw_headers_frame(&client_quinn, oversized_field_section(17_000)).await;
            // The connection stays alive while the server rejects the request.
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let accepted = tokio::time::timeout(Duration::from_secs(5), server_done_rx)
            .await
            .unwrap()
            .unwrap();
        client_task.abort();

        match accepted {
            Err(Ssh3ServerConversationError::Stream(err)) => assert!(
                matches!(err, h3::error::StreamError::HeaderTooBig { .. }),
                "expected a too big headers error, got {err:?}"
            ),
            Err(err) => panic!("expected a too big headers error, got {err:?}"),
            Ok(accepted) => panic!(
                "expected the oversized request to be rejected, got a conversation on stream {}",
                accepted.unwrap().conversation.control_stream_id()
            ),
        }
    }
}
