//! Runtime of the server: accepting connections and routing their channels.
//!
//! The runtime turns a QUIC connection into an SSH3 conversation: it accepts
//! the HTTP/3 CONNECT request, authorizes it, and then dispatches every
//! channel the client opens to the matching handler (session, TCP forwarding
//! or UDP forwarding).

use std::sync::Arc;

use http::{Response, StatusCode};
use quinn::{Connection, Endpoint};
use ssh3_core::Ssh3AcceptedChannel;
use ssh3_h3::{
    Ssh3AcceptedServerConversation, Ssh3DatagramDispatchError, Ssh3ServerConnectionDriver,
    Ssh3ServerConversationError, is_ssh3_connect, response_with_server_header,
    route_registered_datagram,
};
use ssh3_quinn::Ssh3IncomingChannelRouter;

use crate::auth::{authorize_request, parse_request_authorization};
use crate::config::{Ssh3ServerConfig, validate_server_config};
use crate::error::{
    Ssh3ServerError, is_benign_connection_error, is_benign_datagram_error, is_benign_route_error,
    is_benign_server_error,
};
use crate::forwarding::{handle_tcp_forwarding, handle_udp_forwarding};
use crate::session::{SessionUser, handle_plain_channel, resolve_session_user};

/// Serves an endpoint until it stops accepting connections.
///
/// Every accepted connection is handled in its own task, so a slow or broken
/// peer never blocks the others.
pub async fn serve_endpoint(
    endpoint: Endpoint,
    config: Ssh3ServerConfig,
) -> Result<(), Ssh3ServerError> {
    validate_server_config(&config)?;
    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = serve_connection(connection, config).await {
                        if !is_benign_server_error(&err) {
                            eprintln!("ssh3-rust-server connection error: {err}");
                        }
                    }
                }
                Err(err) => {
                    if !is_benign_connection_error(&err) {
                        eprintln!("ssh3-rust-server accept error: {err}");
                    }
                }
            }
        });
    }
    Ok(())
}

/// Serves a single accepted QUIC connection.
///
/// The connection is upgraded to an SSH3 conversation; the call returns when
/// the conversation ends.
pub async fn serve_connection(
    connection: Connection,
    config: Ssh3ServerConfig,
) -> Result<(), Ssh3ServerError> {
    validate_server_config(&config)?;
    let mut driver = Ssh3ServerConnectionDriver::new(connection.clone()).await?;
    let Some(accepted) = driver
        .accept_conversation(config.max_packet_size, config.default_datagrams_queue_size)
        .await?
    else {
        return Ok(());
    };

    handle_conversation(
        accepted,
        connection,
        driver.channel_router().clone(),
        config,
    )
    .await
}

/// Dispatches the datagrams of a connection to the channels that wait for them.
async fn route_datagrams(
    connection: Connection,
    channel_router: Arc<Ssh3IncomingChannelRouter>,
) -> Result<(), Ssh3DatagramDispatchError> {
    loop {
        let datagram = connection.read_datagram().await?;
        let _ = route_registered_datagram(channel_router.as_ref(), &datagram).await?;
    }
}

/// Runs an accepted conversation: authorize, then serve its channels.
async fn handle_conversation(
    mut accepted: Ssh3AcceptedServerConversation,
    connection: Connection,
    channel_router: Arc<Ssh3IncomingChannelRouter>,
    config: Ssh3ServerConfig,
) -> Result<(), Ssh3ServerError> {
    let control_stream_id = accepted.conversation.control_stream_id();
    let result = async {
        if !is_ssh3_connect(&accepted.request) {
            accepted
                .control_stream
                .send_response(Response::builder().status(StatusCode::NOT_FOUND).body(())?)
                .await
                .map_err(Ssh3ServerConversationError::from)?;
            accepted
                .control_stream
                .finish()
                .await
                .map_err(Ssh3ServerConversationError::from)?;
            return Ok(());
        }

        let authorization = parse_request_authorization(&accepted.request);
        let session_user = match resolve_session_user(&accepted.request, &authorization, &config) {
            Ok(session_user) => session_user,
            Err(_) => {
                accepted
                    .control_stream
                    .send_response(
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .body(())?,
                    )
                    .await
                    .map_err(Ssh3ServerConversationError::from)?;
                accepted
                    .control_stream
                    .finish()
                    .await
                    .map_err(Ssh3ServerConversationError::from)?;
                return Ok(());
            }
        };
        if !authorize_request(
            &authorization,
            &session_user,
            &accepted.conversation.conversation_id(),
            &config,
        )
        .await?
        {
            accepted
                .control_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(())?,
                )
                .await
                .map_err(Ssh3ServerConversationError::from)?;
            accepted
                .control_stream
                .finish()
                .await
                .map_err(Ssh3ServerConversationError::from)?;
            return Ok(());
        }

        accepted
            .control_stream
            .send_response(response_with_server_header(
                StatusCode::OK,
                &config.server_header,
            )?)
            .await
            .map_err(Ssh3ServerConversationError::from)?;

        let channels_task = tokio::spawn({
            let channel_router = channel_router.clone();
            let connection = connection.clone();
            async move {
                match channel_router
                    .accept_and_route_channels_forever(connection)
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(err) if is_benign_route_error(&err) => Ok(()),
                    Err(err) => Err(Ssh3ServerError::RouteAcceptedChannel(err)),
                }
            }
        });

        let datagrams_task = tokio::spawn({
            let channel_router = channel_router.clone();
            let connection = connection.clone();
            async move {
                match route_datagrams(connection, channel_router).await {
                    Ok(()) => Ok(()),
                    Err(err) if is_benign_datagram_error(&err) => Ok(()),
                    Err(err) => Err(Ssh3ServerError::DatagramDispatch(err)),
                }
            }
        });

        loop {
            tokio::select! {
                _ = connection.closed() => break,
                accepted_channel = accepted.conversation.accept_channel_with_metadata() => {
                    let accepted_channel = accepted_channel?;
                    let config = config.clone();
                    let connection = connection.clone();
                    let conversation = accepted.conversation.clone();
                    let session_user = session_user.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_accepted_channel(
                            accepted_channel,
                            conversation,
                            connection,
                            config,
                            session_user,
                        )
                        .await
                        {
                            if !is_benign_server_error(&err) {
                                eprintln!("ssh3-rust-server channel error: {err}");
                            }
                        }
                    });
                }
            }
        }

        let _ = channels_task.await;
        let _ = datagrams_task.await;

        Ok(())
    }
    .await;

    channel_router.unregister_conversation(control_stream_id);
    result
}

/// Dispatches an accepted channel to the handler of its channel type.
async fn handle_accepted_channel(
    accepted_channel: Ssh3AcceptedChannel,
    conversation: Arc<ssh3_core::Ssh3Conversation>,
    connection: Connection,
    config: Ssh3ServerConfig,
    session_user: SessionUser,
) -> Result<(), Ssh3ServerError> {
    match accepted_channel {
        Ssh3AcceptedChannel::Channel(channel) => {
            handle_plain_channel(channel, conversation, connection, config, session_user).await
        }
        Ssh3AcceptedChannel::UdpForwarding {
            channel,
            remote_addr,
        } => handle_udp_forwarding(channel, remote_addr, connection).await,
        Ssh3AcceptedChannel::TcpForwarding {
            channel,
            remote_addr,
        } => handle_tcp_forwarding(channel, remote_addr, connection).await,
    }
}
