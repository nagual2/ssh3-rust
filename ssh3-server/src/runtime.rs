//! Runtime of the server: accepting connections and routing their channels.
//!
//! The runtime turns a QUIC connection into an SSH3 conversation: it accepts
//! the HTTP/3 CONNECT request, authorizes it, and then dispatches every
//! channel the client opens to the matching handler (session, TCP forwarding
//! or UDP forwarding).

use std::sync::Arc;
use std::time::Duration;

use http::{Response, StatusCode};
use quinn::{Connection, Endpoint};
use ssh3_core::Ssh3AcceptedChannel;
use ssh3_h3::{
    Ssh3AcceptedServerConversation, Ssh3DatagramDispatchError, Ssh3ServerConnectionDriver,
    Ssh3ServerControlStream, Ssh3ServerConversationError, is_ssh3_connect,
    response_with_server_header, route_registered_datagram,
};
use ssh3_quinn::Ssh3IncomingChannelRouter;

use crate::auth::{AuthOutcome, authorize_request, parse_request_authorization};
use crate::config::{Ssh3ServerConfig, validate_server_config};
use crate::dynamic_forward::{
    CHANNEL_TYPE_DYNAMIC_FORWARD, CHANNEL_TYPE_DYNAMIC_FORWARD_TCP, handle_dynamic_forward_channel,
    handle_dynamic_forward_data_channel,
};
use crate::error::{
    Ssh3ServerError, is_benign_connection_error, is_benign_datagram_error, is_benign_route_error,
    is_benign_server_error,
};
use crate::forwarding::{ForwardingState, handle_tcp_forwarding, handle_udp_forwarding};
use crate::reverse_forward::{CHANNEL_TYPE_REVERSE_FORWARD, handle_reverse_forward_channel};
use crate::session::{
    AgentForwardingSlot, SessionUser, handle_plain_channel, resolve_session_user,
};

/// Serves an endpoint until it stops accepting connections.
///
/// Every accepted connection is handled in its own task, so a slow or broken
/// peer never blocks the others.
pub async fn serve_endpoint(
    endpoint: Endpoint,
    config: Ssh3ServerConfig,
) -> Result<(), Ssh3ServerError> {
    validate_server_config(&config)?;
    let handshake_idle_timeout = config.handshake_idle_timeout;
    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            // the handshake timeout: a peer that opens a connection and
            // never finishes the handshake must not hold a slot forever
            match tokio::time::timeout(handshake_idle_timeout, incoming).await {
                Ok(Ok(connection)) => {
                    if let Err(err) = serve_connection(connection, config).await {
                        if !is_benign_server_error(&err) {
                            eprintln!("ssh3-rust-server connection error: {err}");
                        }
                    }
                }
                Ok(Err(err)) => {
                    if !is_benign_connection_error(&err) {
                        eprintln!("ssh3-rust-server accept error: {err}");
                    }
                }
                Err(_) => {
                    eprintln!(
                        "ssh3-rust-server handshake timed out after {}s",
                        handshake_idle_timeout.as_secs()
                    );
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
    forwarding_state: Arc<ForwardingState>,
) -> Result<(), Ssh3DatagramDispatchError> {
    loop {
        let datagram = connection.read_datagram().await?;
        // The channels the server opens towards the client are not registered
        // in the conversation of the peer, so their datagrams are routed by
        // the state of the conversation.
        if forwarding_state.route_datagram(&datagram).await {
            continue;
        }
        let _ = route_registered_datagram(channel_router.as_ref(), &datagram).await?;
    }
}

/// Reports whether the request was sent to the secret URL path of the server.
///
/// The path of the request is compared without its query string, so the
/// `user` query parameter of the SSH3 protocol keeps working.
fn request_path_matches(request: &http::Request<()>, url_path: &str) -> bool {
    request.uri().path() == url_path
}

/// The grace period a refusal response gets before the connection is closed.
///
/// The connection is closed right after the conversation ends, and a QUIC
/// connection close can overtake the response on the wire: the pause gives
/// the peer the chance to read the status of the refusal.
const REFUSAL_GRACE: Duration = Duration::from_millis(100);

/// Answers a request with a refusal status and lets the peer read it.
async fn refuse(
    control_stream: &mut Ssh3ServerControlStream,
    status: StatusCode,
) -> Result<(), Ssh3ServerError> {
    control_stream
        .send_response(Response::builder().status(status).body(())?)
        .await
        .map_err(Ssh3ServerConversationError::from)?;
    control_stream
        .finish()
        .await
        .map_err(Ssh3ServerConversationError::from)?;
    tokio::time::sleep(REFUSAL_GRACE).await;
    Ok(())
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
        // the secret URL path: a CONNECT on any other path is not an SSH3
        // conversation at all and is answered like an unknown route
        if !request_path_matches(&accepted.request, &config.url_path) {
            refuse(&mut accepted.control_stream, StatusCode::NOT_FOUND).await?;
            return Ok(());
        }

        if !is_ssh3_connect(&accepted.request) {
            refuse(&mut accepted.control_stream, StatusCode::NOT_FOUND).await?;
            return Ok(());
        }

        // the unauthenticated phase holds a DoS slot (the MaxStartups
        // analog): the slot is taken before any per-request work worth
        // protecting and is given back whatever the verdict is, so a
        // successful authentication never keeps the slot
        if !config
            .auth_guard
            .try_acquire_unauthenticated(config.max_unauthenticated_conversations)
        {
            eprintln!(
                "ssh3-rust-server too many unauthenticated conversations ({} active), refusing the request",
                config.max_unauthenticated_conversations
            );
            refuse(&mut accepted.control_stream, StatusCode::SERVICE_UNAVAILABLE).await?;
            return Ok(());
        }

        let authorization = parse_request_authorization(&accepted.request);
        let session_user = match resolve_session_user(&accepted.request, &authorization, &config) {
            Ok(session_user) => session_user,
            Err(_) => {
                config.auth_guard.release_unauthenticated();
                refuse(&mut accepted.control_stream, StatusCode::UNAUTHORIZED).await?;
                return Ok(());
            }
        };
        let outcome = match authorize_request(
            &authorization,
            &session_user,
            &accepted.conversation.conversation_id(),
            &config,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                config.auth_guard.release_unauthenticated();
                return Err(err.into());
            }
        };
        config.auth_guard.release_unauthenticated();
        if outcome != AuthOutcome::Authorized {
            let status = match outcome {
                AuthOutcome::Authorized => StatusCode::OK,
                AuthOutcome::Unauthorized => StatusCode::UNAUTHORIZED,
                AuthOutcome::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            };
            refuse(&mut accepted.control_stream, status).await?;
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

        // the forwarded agent socket outlives the session channel that
        // requested it: a client may close the session and connect to the
        // agent socket afterwards, so the socket is owned by the
        // conversation and removed when the conversation ends
        let agent_forwarding = AgentForwardingSlot::new();

        // the reverse and dynamic forwards of a conversation share their
        // guards, so they are owned by the conversation as well
        let forwarding_state = Arc::new(ForwardingState::new());

        let datagrams_task = tokio::spawn({
            let channel_router = channel_router.clone();
            let connection = connection.clone();
            let forwarding_state = forwarding_state.clone();
            async move {
                match route_datagrams(connection, channel_router, forwarding_state).await {
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
                    let agent_forwarding = agent_forwarding.clone();
                    let forwarding_state = forwarding_state.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_accepted_channel(
                            accepted_channel,
                            conversation,
                            connection,
                            config,
                            session_user,
                            agent_forwarding,
                            forwarding_state,
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
    agent_forwarding: AgentForwardingSlot,
    forwarding_state: Arc<ForwardingState>,
) -> Result<(), Ssh3ServerError> {
    match accepted_channel {
        Ssh3AcceptedChannel::Channel(channel) => match channel.channel_type() {
            CHANNEL_TYPE_REVERSE_FORWARD => {
                handle_reverse_forward_channel(
                    channel,
                    conversation,
                    connection,
                    config,
                    session_user,
                    forwarding_state,
                )
                .await
            }
            CHANNEL_TYPE_DYNAMIC_FORWARD => {
                handle_dynamic_forward_channel(channel, connection, forwarding_state).await
            }
            CHANNEL_TYPE_DYNAMIC_FORWARD_TCP => {
                handle_dynamic_forward_data_channel(channel, connection, config, forwarding_state)
                    .await
            }
            _ => {
                handle_plain_channel(
                    channel,
                    conversation,
                    connection,
                    config,
                    session_user,
                    agent_forwarding,
                )
                .await
            }
        },
        Ssh3AcceptedChannel::UdpForwarding {
            channel,
            remote_addr,
        } => {
            let permit_open = config.permit_open.clone();
            handle_udp_forwarding(channel, remote_addr, connection, permit_open.as_ref()).await
        }
        Ssh3AcceptedChannel::TcpForwarding {
            channel,
            remote_addr,
        } => {
            let permit_open = config.permit_open.clone();
            handle_tcp_forwarding(channel, remote_addr, connection, permit_open.as_ref()).await
        }
    }
}
