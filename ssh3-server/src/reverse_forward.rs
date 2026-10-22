//! Reverse port forwarding (`-R`): the server side of the control channel.
//!
//! A client opens a `reverse-forward` channel and sends its bind request as
//! channel data. The server binds the requested listener, answers with the
//! port it actually bound and then mirrors every connection (or datagram) it
//! accepts there back to the client as a `forwarded-tcp` (or `forwarded-udp`)
//! channel whose additional header bytes carry the client-side target.
//!
//! The reference implementation of this behavior lives in
//! `nagual2/ssh3-go`, file `cmd/reverse_forward_server.go`.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::net::{TcpListener, UdpSocket};

use quinn::Connection;
use ssh3_core::{Ssh3Channel, Ssh3Conversation};
use ssh3_proto::SSH_EXTENDED_DATA_NONE;

use crate::config::{GatewayPortsPolicy, Ssh3ServerConfig};
use crate::error::{Ssh3ServerError, is_benign_server_error};
use crate::forwarding::{
    ForwardingState, bridge_tcp_channel, check_listen_target, open_forwarded_channel,
};
use crate::forwarding_wire::{
    FORWARDING_PROTOCOL_TCP, FORWARDING_PROTOCOL_UDP, ReverseForwardReply, ReverseForwardRequest,
    Ssh3ForwardingWireError,
};
use crate::session::SessionUser;

/// Channel type of the control channel a client opens to request a reverse
/// forward.
pub(crate) const CHANNEL_TYPE_REVERSE_FORWARD: &[u8] = b"reverse-forward";

/// Channel type of the connection channels the server opens towards the
/// client for a reverse forward.
pub(crate) const CHANNEL_TYPE_FORWARDED_TCP: &[u8] = b"forwarded-tcp";

/// Channel type of the datagram channels the server opens towards the client
/// for a reverse forward.
pub(crate) const CHANNEL_TYPE_FORWARDED_UDP: &[u8] = b"forwarded-udp";

/// The address a reverse forward listener is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
enum BindAddress {
    /// A concrete IP address.
    Ip(IpAddr),
    /// The wildcard address.
    Wildcard,
    /// A host name that has to be resolved.
    Host(String),
}

/// The bind address the `GatewayPorts` policy resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedBind {
    /// The address the listener is bound to.
    address: BindAddress,
    /// `true` when the policy rewrote the client-requested address.
    restricted: bool,
}

/// Applies the `GatewayPorts` policy to the client-requested bind address.
///
/// The policy follows the `sshd_config` semantics: `no` (the default) forces
/// every client-requested bind back to the loopback, `clientspecified` honors
/// the bind address the client asked for and `yes` binds the wildcard
/// address regardless of the request.
fn resolve_reverse_forward_bind(policy: GatewayPortsPolicy, requested: &str) -> ResolvedBind {
    match policy {
        GatewayPortsPolicy::No => {
            if requested.is_empty() {
                return ResolvedBind {
                    address: BindAddress::Ip(Ipv4Addr::LOCALHOST.into()),
                    restricted: true,
                };
            }
            // An address that is neither an IP nor provably loopback is
            // treated as non-loopback: under "no" it is forced back to the
            // loopback.
            match requested.parse::<IpAddr>() {
                Ok(address) if address.is_loopback() => ResolvedBind {
                    address: BindAddress::Ip(address),
                    restricted: false,
                },
                _ => ResolvedBind {
                    address: BindAddress::Ip(Ipv4Addr::LOCALHOST.into()),
                    restricted: true,
                },
            }
        }
        GatewayPortsPolicy::ClientSpecified => {
            if requested.is_empty() {
                return ResolvedBind {
                    address: BindAddress::Ip(Ipv4Addr::LOCALHOST.into()),
                    restricted: true,
                };
            }
            if requested == "*" {
                return ResolvedBind {
                    address: BindAddress::Wildcard,
                    restricted: false,
                };
            }
            match requested.parse::<IpAddr>() {
                Ok(address) => ResolvedBind {
                    address: BindAddress::Ip(address),
                    restricted: false,
                },
                Err(_) => ResolvedBind {
                    address: BindAddress::Host(requested.to_string()),
                    restricted: false,
                },
            }
        }
        GatewayPortsPolicy::Yes => ResolvedBind {
            address: BindAddress::Wildcard,
            restricted: true,
        },
    }
}

/// Resolves the bind address into the socket address the listener uses.
async fn bind_socket_address(bind: &BindAddress, port: u16) -> io::Result<SocketAddr> {
    match bind {
        BindAddress::Ip(address) => Ok(SocketAddr::new(*address, port)),
        BindAddress::Wildcard => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)),
        BindAddress::Host(host) => {
            let mut addresses = tokio::net::lookup_host((host.as_str(), port)).await?;
            addresses.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("could not resolve the bind address {host:?}"),
                )
            })
        }
    }
}

/// The number of active reverse forward listeners of every user.
///
/// The budget bounds the number of server ports a single account may occupy;
/// it is released when the listener of a forward goes away.
fn reverse_forward_binds() -> &'static Mutex<HashMap<String, usize>> {
    static BINDS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
    BINDS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Admits one more active listener of the user while it stays under the
/// limit.
fn acquire_reverse_forward_bind(user: &str, limit: usize) -> bool {
    let mut binds = reverse_forward_binds()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let count = binds.entry(user.to_string()).or_insert(0);
    if *count >= limit {
        return false;
    }
    *count += 1;
    true
}

/// Releases one listener of the user from the budget.
fn release_reverse_forward_bind(user: &str) {
    let mut binds = reverse_forward_binds()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(count) = binds.get_mut(user) {
        *count = count.saturating_sub(1);
    }
}

/// The listener budget slot of a reverse forward.
///
/// The slot is given back when the forward ends, whatever the reason the
/// forward ended.
struct ReverseForwardBind {
    user: String,
}

impl Drop for ReverseForwardBind {
    fn drop(&mut self) {
        release_reverse_forward_bind(&self.user);
    }
}

/// Reads the bind request the client sends as channel data.
async fn read_reverse_forward_request(
    channel: &Ssh3Channel,
) -> Result<ReverseForwardRequest, Ssh3ForwardingWireError> {
    let message = channel
        .next_message()
        .await
        .map_err(|_| Ssh3ForwardingWireError::Truncated)?;
    let ssh3_proto::Ssh3Message::Data(data) = message else {
        return Err(Ssh3ForwardingWireError::Truncated);
    };
    if data.data_type != SSH_EXTENDED_DATA_NONE {
        return Err(Ssh3ForwardingWireError::Truncated);
    }
    ReverseForwardRequest::decode(&data.data)
}

/// Sends the bind result to the client.
async fn write_reverse_forward_reply(
    channel: &Ssh3Channel,
    reply: &ReverseForwardReply,
) -> Result<(), Ssh3ServerError> {
    channel
        .write_data(&reply.encode(), SSH_EXTENDED_DATA_NONE)
        .await?;
    Ok(())
}

/// Serves one client `reverse-forward` control channel.
///
/// The handler reads the bind request, answers with the bind result and then
/// serves the bound listener until the conversation ends.
pub(crate) async fn handle_reverse_forward_channel(
    channel: Arc<Ssh3Channel>,
    conversation: Arc<Ssh3Conversation>,
    connection: Connection,
    config: Ssh3ServerConfig,
    session_user: SessionUser,
    state: Arc<ForwardingState>,
) -> Result<(), Ssh3ServerError> {
    let request = match read_reverse_forward_request(&channel).await {
        Ok(request) => request,
        Err(err) => {
            eprintln!("ssh3-rust-server invalid reverse-forwarding request: {err}");
            let _ = channel.close().await;
            return Ok(());
        }
    };

    let bind = resolve_reverse_forward_bind(config.gateway_ports, &request.bind_address);
    if bind.restricted {
        eprintln!(
            "ssh3-rust-server the GatewayPorts={:?} policy restricted the client-requested bind {:?} to {:?}",
            config.gateway_ports, request.bind_address, bind.address
        );
    }
    let bind_address = bind.address;

    // The bind budget is taken before the target is validated, like the
    // reference implementation does.
    if !acquire_reverse_forward_bind(&session_user.username, config.max_reverse_forwards_per_user) {
        let reason = format!(
            "too many reverse forwards for user {} (limit {})",
            session_user.username, config.max_reverse_forwards_per_user
        );
        eprintln!("ssh3-rust-server {reason}");
        write_reverse_forward_reply(
            &channel,
            &ReverseForwardReply {
                bound_port: 0,
                error: reason,
            },
        )
        .await?;
        let _ = channel.close().await;
        return Ok(());
    }
    let _bind_guard = ReverseForwardBind {
        user: session_user.username.clone(),
    };

    // The client resolves the target locally, so only literals are accepted.
    let Ok(target_address) = request.target_address.parse::<IpAddr>() else {
        let reason = format!("invalid target address {:?}", request.target_address);
        write_reverse_forward_reply(
            &channel,
            &ReverseForwardReply {
                bound_port: 0,
                error: reason,
            },
        )
        .await?;
        let _ = channel.close().await;
        return Ok(());
    };
    let target = SocketAddr::new(target_address, request.target_port);

    let listen_kind = if request.protocol == FORWARDING_PROTOCOL_UDP {
        "udp"
    } else {
        "tcp"
    };
    let socket_address = match bind_socket_address(&bind_address, request.bind_port).await {
        Ok(address) => address,
        Err(err) => {
            let reason = err.to_string();
            write_reverse_forward_reply(
                &channel,
                &ReverseForwardReply {
                    bound_port: 0,
                    error: reason,
                },
            )
            .await?;
            let _ = channel.close().await;
            return Ok(());
        }
    };

    // The permit-listen gate runs on the post-GatewayPorts address, the one
    // that is actually bound.
    if let Err(err) =
        check_listen_target(listen_kind, socket_address, config.permit_listen.as_ref())
    {
        eprintln!("ssh3-rust-server refusing the reverse-forward bind: {err}");
        let reason = err.to_string();
        write_reverse_forward_reply(
            &channel,
            &ReverseForwardReply {
                bound_port: 0,
                error: reason,
            },
        )
        .await?;
        let _ = channel.close().await;
        return Ok(());
    }

    match request.protocol {
        FORWARDING_PROTOCOL_TCP => {
            let listener = match TcpListener::bind(socket_address).await {
                Ok(listener) => listener,
                Err(err) => {
                    let reason = err.to_string();
                    write_reverse_forward_reply(
                        &channel,
                        &ReverseForwardReply {
                            bound_port: 0,
                            error: reason,
                        },
                    )
                    .await?;
                    let _ = channel.close().await;
                    return Ok(());
                }
            };
            let bound_address = listener.local_addr().unwrap_or(socket_address);
            let bound_port = bound_address.port();
            if !bound_address.ip().is_loopback() {
                eprintln!(
                    "ssh3-rust-server the reverse forward binds a non-loopback address ({bound_address}): the port is reachable from other hosts"
                );
            }
            eprintln!(
                "ssh3-rust-server reverse forwarding TCP {bound_address} towards the client target {target}"
            );
            write_reverse_forward_reply(
                &channel,
                &ReverseForwardReply {
                    bound_port,
                    error: String::new(),
                },
            )
            .await?;
            serve_reverse_tcp(listener, target, conversation, connection, &config, state).await
        }
        FORWARDING_PROTOCOL_UDP => {
            let socket = match UdpSocket::bind(socket_address).await {
                Ok(socket) => Arc::new(socket),
                Err(err) => {
                    let reason = err.to_string();
                    write_reverse_forward_reply(
                        &channel,
                        &ReverseForwardReply {
                            bound_port: 0,
                            error: reason,
                        },
                    )
                    .await?;
                    let _ = channel.close().await;
                    return Ok(());
                }
            };
            let bound_address = socket.local_addr().unwrap_or(socket_address);
            let bound_port = bound_address.port();
            eprintln!(
                "ssh3-rust-server reverse forwarding UDP {bound_address} towards the client target {target}"
            );
            write_reverse_forward_reply(
                &channel,
                &ReverseForwardReply {
                    bound_port,
                    error: String::new(),
                },
            )
            .await?;
            serve_reverse_udp(socket, target, conversation, connection, &config, state).await
        }
        _ => {
            let reason = format!("unsupported forwarding protocol {}", request.protocol);
            write_reverse_forward_reply(
                &channel,
                &ReverseForwardReply {
                    bound_port: 0,
                    error: reason,
                },
            )
            .await?;
            let _ = channel.close().await;
            Ok(())
        }
    }
}

/// Accepts the connections of a reverse forward listener and mirrors them to
/// the client.
async fn serve_reverse_tcp(
    listener: TcpListener,
    target: SocketAddr,
    conversation: Arc<Ssh3Conversation>,
    connection: Connection,
    config: &Ssh3ServerConfig,
    state: Arc<ForwardingState>,
) -> Result<(), Ssh3ServerError> {
    loop {
        let (stream, peer) = tokio::select! {
            _ = connection.closed() => return Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    eprintln!("ssh3-rust-server error while accepting on the reverse-forwarded listener: {err}");
                    return Ok(());
                }
            },
        };

        if !state.acquire_forwarded_channel() {
            eprintln!(
                "ssh3-rust-server too many open forwarded channels, dropping the connection from {peer}"
            );
            drop(stream);
            continue;
        }

        // The channel is opened in its own task: a client that never
        // confirms it must not hold the accept loop.
        let conversation = conversation.clone();
        let connection = connection.clone();
        let config = config.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let channel = match open_forwarded_channel(
                conversation.as_ref(),
                &connection,
                CHANNEL_TYPE_FORWARDED_TCP,
                target,
                config.max_packet_size,
                config.default_datagrams_queue_size,
                false,
            )
            .await
            {
                Ok(channel) => channel,
                Err(err) => {
                    eprintln!(
                        "ssh3-rust-server could not open the forwarded-tcp channel for the connection from {peer}: {err}"
                    );
                    state.release_forwarded_channel();
                    return;
                }
            };
            let result = bridge_tcp_channel(channel, stream, connection).await;
            state.release_forwarded_channel();
            if let Err(err) = result
                && !is_benign_server_error(&err)
            {
                eprintln!("ssh3-rust-server reverse-forwarded connection error: {err}");
            }
        });
    }
}

/// Reads the datagrams of a reverse forward listener and mirrors them to the
/// client, one channel per remote peer.
async fn serve_reverse_udp(
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    conversation: Arc<Ssh3Conversation>,
    connection: Connection,
    config: &Ssh3ServerConfig,
    state: Arc<ForwardingState>,
) -> Result<(), Ssh3ServerError> {
    let mut channels: HashMap<SocketAddr, Arc<Ssh3Channel>> = HashMap::new();
    let mut buffer = vec![0u8; 65_535];
    loop {
        let (length, peer) = tokio::select! {
            _ = connection.closed() => return Ok(()),
            received = socket.recv_from(&mut buffer) => match received {
                Ok(received) => received,
                Err(err) => {
                    eprintln!("ssh3-rust-server error while reading on the reverse-forwarded socket: {err}");
                    return Ok(());
                }
            },
        };

        let channel = match channels.entry(peer) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                if !state.acquire_forwarded_channel() {
                    eprintln!(
                        "ssh3-rust-server too many open forwarded channels, dropping the datagram from {peer}"
                    );
                    continue;
                }
                let channel = match open_forwarded_channel(
                    conversation.as_ref(),
                    &connection,
                    CHANNEL_TYPE_FORWARDED_UDP,
                    target,
                    config.max_packet_size,
                    config.default_datagrams_queue_size,
                    true,
                )
                .await
                {
                    Ok(channel) => channel,
                    Err(err) => {
                        eprintln!(
                            "ssh3-rust-server could not open the forwarded-udp channel for the peer {peer}: {err}"
                        );
                        state.release_forwarded_channel();
                        continue;
                    }
                };
                state.register_datagram_channel(channel.clone());
                spawn_udp_bridge(socket.clone(), peer, channel.clone(), connection.clone());
                entry.insert(channel.clone());
                channel
            }
        };

        if let Err(err) = channel.send_datagram(buffer[..length].to_vec()).await {
            eprintln!(
                "ssh3-rust-server could not send the datagram on the forwarded-udp channel: {err}"
            );
        }
    }
}

/// Copies the datagrams the client sends back to the remote peer.
fn spawn_udp_bridge(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    channel: Arc<Ssh3Channel>,
    connection: Connection,
) {
    tokio::spawn(async move {
        loop {
            let datagram = tokio::select! {
                _ = connection.closed() => return,
                datagram = channel.receive_datagram() => datagram,
            };
            if socket.send_to(&datagram, peer).await.is_err() {
                return;
            }
        }
    });
}
