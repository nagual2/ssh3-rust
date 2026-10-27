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
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::auth::{
    AuthOutcome, UnauthenticatedSlot, authorize_request, parse_request_authorization,
};
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
use crate::sftp::{CHANNEL_TYPE_SFTP, handle_sftp_channel};

/// Converts a resource cap into the number of semaphore permits.
///
/// The `0` of the `-max-connections` and `-max-channels-per-conversation`
/// options means "no limit", which the semaphores express with the maximum
/// number of permits they can hold.
fn cap_permits(cap: usize) -> usize {
    if cap == 0 {
        Semaphore::MAX_PERMITS
    } else {
        cap
    }
}

/// Serves an endpoint until it stops accepting connections.
///
/// Every accepted connection is handled in its own task, so a slow or broken
/// peer never blocks the others. The `max_connections` configuration bounds
/// the number of tasks: an incoming connection over the cap is refused right
/// after the QUIC accept, without a handshake.
pub async fn serve_endpoint(
    endpoint: Endpoint,
    config: Ssh3ServerConfig,
) -> Result<(), Ssh3ServerError> {
    validate_server_config(&config)?;
    let handshake_idle_timeout = config.handshake_idle_timeout;
    // the connection cap (`-max-connections`): the permit of a connection is
    // owned by its task below and is given back whatever the connection dies
    // of, the pre-auth timeout included
    let connection_slots = Arc::new(Semaphore::new(cap_permits(config.max_connections)));
    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
            eprintln!(
                "ssh3-rust-server too many connections ({} active), refusing the incoming connection",
                config.max_connections
            );
            incoming.refuse();
            continue;
        };
        tokio::spawn(async move {
            // the permit of the connection cap is owned by the task, so the
            // slot is held for the whole life of the connection
            let _connection_permit = permit;
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
///
/// The whole pre-auth phase — the HTTP/3 accept of the CONNECT request, the
/// secret-path checks, the unauthenticated-slot acquisition and the
/// credential verification (a slow OIDC provider included) — runs under
/// `handshake_idle_timeout` (the audit of 2026-10-27, risk 3.5.2): without
/// the cap a peer that trickled its request held a task, a conversation and
/// the idle timeout of the transport (24 h by default, renewed by traffic)
/// for as long as it kept dribbling bytes, without ever consuming a DoS
/// slot. The value is the `LoginGraceTime` of the server: the time a
/// connection may spend before it is authenticated.
pub async fn serve_connection(
    connection: Connection,
    config: Ssh3ServerConfig,
) -> Result<(), Ssh3ServerError> {
    validate_server_config(&config)?;
    let established = match tokio::time::timeout(
        config.handshake_idle_timeout,
        pre_auth_phase(&connection, &config),
    )
    .await
    {
        Ok(established) => established?,
        Err(_) => {
            // no refusal response is sent: at every point this can fire the
            // control stream of the conversation is not at hand (it lives in
            // the aborted phase), so the connection is closed the quiet way
            // of the refusal path, without a status the peer could mistake
            // for a credential verdict
            eprintln!(
                "ssh3-rust-server the pre-auth phase timed out after {}s, closing the connection",
                config.handshake_idle_timeout.as_secs()
            );
            connection.close(0u32.into(), b"pre-auth phase timed out");
            return Ok(());
        }
    };
    let Some((driver, accepted, session_user)) = established else {
        return Ok(());
    };

    handle_conversation(
        accepted,
        connection,
        driver.channel_router().clone(),
        config,
        session_user,
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

/// Runs the unauthenticated phase of an accepted connection.
///
/// The phase turns the QUIC connection into an authorized conversation: it
/// accepts the HTTP/3 CONNECT request, checks it and verifies the credentials
/// of the peer. `None` means the conversation was refused or never arrived;
/// `Some` carries the pieces the serving phase continues with — the driver
/// included, which owns the channel router and must outlive the conversation.
async fn pre_auth_phase(
    connection: &Connection,
    config: &Ssh3ServerConfig,
) -> Result<
    Option<(
        Ssh3ServerConnectionDriver,
        Ssh3AcceptedServerConversation,
        SessionUser,
    )>,
    Ssh3ServerError,
> {
    let mut driver = Ssh3ServerConnectionDriver::new(connection.clone()).await?;
    let Some(mut accepted) = driver
        .accept_conversation(config.max_packet_size, config.default_datagrams_queue_size)
        .await?
    else {
        return Ok(None);
    };
    let Some(session_user) = authorize_conversation(&mut accepted, config).await? else {
        return Ok(None);
    };
    Ok(Some((driver, accepted, session_user)))
}

/// Authorizes the CONNECT request of an accepted conversation.
///
/// The function runs the whole unauthenticated phase: the secret-path and
/// method checks, the `MaxStartups` analog of the DoS guard and the
/// credential verification. A refused conversation is answered here (`404`,
/// `503`, `401` or `429`); the caller only serves the conversations the
/// function authorizes.
///
/// The unauthenticated slot of the DoS guard is owned by an
/// [`UnauthenticatedSlot`]: the slot is given back when the phase ends,
/// whatever its verdict is — a successful authentication never keeps the
/// slot, and a phase aborted by the pre-auth timeout cannot leak it.
async fn authorize_conversation(
    accepted: &mut Ssh3AcceptedServerConversation,
    config: &Ssh3ServerConfig,
) -> Result<Option<SessionUser>, Ssh3ServerError> {
    // the secret URL path: a CONNECT on any other path is not an SSH3
    // conversation at all and is answered like an unknown route
    if !request_path_matches(&accepted.request, &config.url_path) {
        refuse(&mut accepted.control_stream, StatusCode::NOT_FOUND).await?;
        return Ok(None);
    }

    if !is_ssh3_connect(&accepted.request) {
        refuse(&mut accepted.control_stream, StatusCode::NOT_FOUND).await?;
        return Ok(None);
    }

    let Some(_unauthenticated_slot) = UnauthenticatedSlot::try_acquire(config) else {
        eprintln!(
            "ssh3-rust-server too many unauthenticated conversations ({} active), refusing the request",
            config.max_unauthenticated_conversations
        );
        refuse(
            &mut accepted.control_stream,
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await?;
        return Ok(None);
    };

    let authorization = parse_request_authorization(&accepted.request);
    let Ok(session_user) = resolve_session_user(&accepted.request, &authorization, config) else {
        refuse(&mut accepted.control_stream, StatusCode::UNAUTHORIZED).await?;
        return Ok(None);
    };

    let outcome = authorize_request(
        &authorization,
        &session_user,
        &accepted.conversation.conversation_id(),
        config,
    )
    .await?;

    if outcome != AuthOutcome::Authorized {
        let status = match outcome {
            AuthOutcome::Authorized => StatusCode::OK,
            AuthOutcome::Unauthorized => StatusCode::UNAUTHORIZED,
            AuthOutcome::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        };
        refuse(&mut accepted.control_stream, status).await?;
        return Ok(None);
    }

    Ok(Some(session_user))
}

/// Runs an authorized conversation: serve its channels.
async fn handle_conversation(
    mut accepted: Ssh3AcceptedServerConversation,
    connection: Connection,
    channel_router: Arc<Ssh3IncomingChannelRouter>,
    config: Ssh3ServerConfig,
    session_user: SessionUser,
) -> Result<(), Ssh3ServerError> {
    let control_stream_id = accepted.conversation.control_stream_id();
    let result = async {
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

        // the channel budget of the conversation (the Go server's
        // `-max-channels-per-conversation`): every served channel holds a
        // permit for its handler's lifetime, so a channel over the cap is
        // torn down instead of being served and one account cannot grow the
        // task count of its conversation without bounds. A budget of `0`
        // disables the cap.
        let channel_budget = Arc::new(Semaphore::new(cap_permits(
            config.max_channels_per_conversation,
        )));

        loop {
            tokio::select! {
                _ = connection.closed() => break,
                accepted_channel = accepted.conversation.accept_channel_with_metadata() => {
                    let accepted_channel = accepted_channel?;
                    // the Go refusal: the confirmed channel is torn down
                    // rather than served, so the peer sees the refusal
                    // instead of a silently dead channel
                    let Ok(permit) = channel_budget.clone().try_acquire_owned() else {
                        let channel = accepted_channel.channel().clone();
                        eprintln!(
                            "ssh3-rust-server refusing channel {} of the conversation: the {}-channel budget is exhausted",
                            channel.channel_id(),
                            config.max_channels_per_conversation
                        );
                        channel.cancel_read().await;
                        let _ = channel.close().await;
                        continue;
                    };
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
                            permit,
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
///
/// The permit of the conversation's channel budget travels with the call: it
/// is held for the handler's lifetime and given back when it ends.
#[allow(clippy::too_many_arguments)]
async fn handle_accepted_channel(
    accepted_channel: Ssh3AcceptedChannel,
    conversation: Arc<ssh3_core::Ssh3Conversation>,
    connection: Connection,
    config: Ssh3ServerConfig,
    session_user: SessionUser,
    agent_forwarding: AgentForwardingSlot,
    forwarding_state: Arc<ForwardingState>,
    _channel_budget_permit: OwnedSemaphorePermit,
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
            CHANNEL_TYPE_SFTP => {
                // the file transfer has its own lifetime: closing the
                // transfer channel ends the transfer, not the conversation
                handle_sftp_channel(channel, &config, &session_user).await
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
