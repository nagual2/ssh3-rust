//! Dynamic (SOCKS) port forwarding (`-D`): the server side.
//!
//! A client opens one `dynamic-forward` control channel and announces its
//! local SOCKS bind as channel data. The server confirms that it will serve
//! the forward and binds nothing itself. Every connection the SOCKS listener
//! of the client accepts is then mirrored to the server as a
//! client-initiated `dynamic-forward-tcp` channel that carries the target
//! address as channel data: the server resolves that address, dials it and
//! bridges the channel with the TCP connection.
//!
//! The reference implementation of this behavior lives in
//! `nagual2/ssh3-go`, file `cmd/dynamic_forward_server.go`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::TcpStream;

use quinn::Connection;
use ssh3_core::Ssh3Channel;
use ssh3_proto::SSH_EXTENDED_DATA_NONE;

use crate::config::Ssh3ServerConfig;
use crate::error::{Ssh3ServerError, is_benign_server_error};
use crate::forwarding::{ForwardingState, bridge_tcp_channel_until, check_forward_target_host};
use crate::forwarding_wire::{
    DynamicForwardReply, DynamicForwardRequest, DynamicForwardTarget, DynamicForwardTargetReply,
    Ssh3ForwardingWireError,
};

/// Channel type of the control channel a client opens to announce a dynamic
/// forward.
pub(crate) const CHANNEL_TYPE_DYNAMIC_FORWARD: &[u8] = b"dynamic-forward";

/// Channel type of the data channels a client opens for every connection its
/// SOCKS listener accepts.
pub(crate) const CHANNEL_TYPE_DYNAMIC_FORWARD_TCP: &[u8] = b"dynamic-forward-tcp";

/// Normalizes the client-announced bind address.
///
/// The server never binds anything for a dynamic forward: the address only
/// describes the SOCKS listener of the client.
fn dynamic_forward_bind_address(bind_address: &str) -> String {
    match bind_address {
        // the loopback-only default, like OpenSSH binding localhost when no
        // bind address is given
        "" => "127.0.0.1".to_string(),
        "*" => "0.0.0.0".to_string(),
        other => other.to_string(),
    }
}

/// Reports whether the announced bind address stays on the loopback.
fn is_loopback_bind(bind_address: &str) -> bool {
    match bind_address.parse::<IpAddr>() {
        Ok(address) => address.is_loopback() || address.is_unspecified(),
        Err(_) => false,
    }
}

/// Reads the announcement the client sends as channel data.
async fn read_dynamic_forward_request(
    channel: &Ssh3Channel,
) -> Result<DynamicForwardRequest, Ssh3ForwardingWireError> {
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
    DynamicForwardRequest::decode(&data.data)
}

/// Reads the target the client sends as the first channel data of a
/// `dynamic-forward-tcp` channel.
async fn read_dynamic_forward_target(
    channel: &Ssh3Channel,
) -> Result<DynamicForwardTarget, Ssh3ForwardingWireError> {
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
    DynamicForwardTarget::decode(&data.data)
}

/// Sends a payload as channel data.
async fn write_payload(channel: &Ssh3Channel, payload: &[u8]) -> Result<(), Ssh3ServerError> {
    channel.write_data(payload, SSH_EXTENDED_DATA_NONE).await?;
    Ok(())
}

/// Serves one client `dynamic-forward` control channel.
///
/// The handler reads the announcement, answers with the acknowledgement and
/// then keeps the dynamic forwarding session alive until the client closes
/// the channel or the conversation ends.
pub(crate) async fn handle_dynamic_forward_channel(
    channel: Arc<Ssh3Channel>,
    connection: Connection,
    state: Arc<ForwardingState>,
) -> Result<(), Ssh3ServerError> {
    let request = match read_dynamic_forward_request(&channel).await {
        Ok(request) => request,
        Err(err) => {
            eprintln!("ssh3-rust-server invalid dynamic forwarding request: {err}");
            let _ = channel.close().await;
            return Ok(());
        }
    };

    let bind_address = dynamic_forward_bind_address(&request.bind_address);
    if !is_loopback_bind(&bind_address) {
        eprintln!(
            "ssh3-rust-server dynamic forwarding announced for a non-loopback client bind ({bind_address}:{}): the SOCKS listener is reachable from other hosts",
            request.bind_port
        );
    }

    // The server binds nothing for a dynamic forward: it only confirms that
    // it will serve the SOCKS listener of the client.
    let session = state.open_dynamic_session();
    let reply = DynamicForwardReply {
        bound_port: request.bind_port,
        error: String::new(),
    };
    if let Err(err) = write_payload(&channel, &reply.encode()).await {
        eprintln!("ssh3-rust-server could not send the dynamic forwarding reply: {err}");
        let _ = channel.close().await;
        return Ok(());
    }
    eprintln!(
        "ssh3-rust-server dynamic forwarding (-D) enabled for the client bind {bind_address}:{}",
        request.bind_port
    );

    // The control channel is the lifetime of the dynamic forwarding session:
    // when the client closes it, every bridged connection is released.
    loop {
        tokio::select! {
            _ = connection.closed() => break,
            message = channel.next_message() => {
                match message {
                    Ok(ssh3_proto::Ssh3Message::Data(data)) if !data.data.is_empty() => {
                        eprintln!(
                            "ssh3-rust-server ignoring {} unexpected data bytes on the dynamic forwarding control channel",
                            data.data.len()
                        );
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }

    session.close();
    state.close_dynamic_session();
    let _ = channel.close().await;
    Ok(())
}

/// Resolves the target of a dynamic forward.
///
/// Unlike the targets of a reverse forward, the address may be a host name:
/// a SOCKS client often only knows a name.
async fn resolve_dynamic_target(address: &str, port: u16) -> io::Result<SocketAddr> {
    match address.parse::<IpAddr>() {
        Ok(ip_address) => Ok(SocketAddr::new(ip_address, port)),
        Err(_) => {
            let mut addresses = tokio::net::lookup_host((address, port))
                .await
                .map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("could not resolve {address:?}: no such host ({err})"),
                    )
                })?;
            addresses.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("could not resolve {address:?}: no such host"),
                )
            })
        }
    }
}

/// Serves one client `dynamic-forward-tcp` channel.
///
/// The handler reads the target, dials it and bridges the channel with the
/// TCP connection. The client learns whether the dial succeeded from the
/// answer the server sends right after the target.
pub(crate) async fn handle_dynamic_forward_data_channel(
    channel: Arc<Ssh3Channel>,
    connection: Connection,
    config: Ssh3ServerConfig,
    state: Arc<ForwardingState>,
) -> Result<(), Ssh3ServerError> {
    let target = match read_dynamic_forward_target(&channel).await {
        Ok(target) => target,
        Err(err) => {
            eprintln!("ssh3-rust-server invalid dynamic forwarding target: {err}");
            let _ = channel.close().await;
            return Ok(());
        }
    };

    let Some(session) = state.dynamic_session() else {
        eprintln!(
            "ssh3-rust-server refusing the dynamic forwarding target {}:{}: no dynamic forwarding session",
            target.address, target.port
        );
        let reply = DynamicForwardTargetReply {
            error: "no dynamic forwarding session on this connection".to_string(),
        };
        let _ = write_payload(&channel, &reply.encode()).await;
        let _ = channel.close().await;
        return Ok(());
    };

    // The policy matches the name as the SOCKS client spelled it: a name
    // that resolves outside the policy stays denied even when its addresses
    // would individually match.
    if let Err(err) = check_forward_target_host(
        "dynamic tcp",
        &target.address,
        target.port,
        config.permit_open.as_ref(),
    ) {
        eprintln!(
            "ssh3-rust-server refusing the dynamic forwarding target {}:{}: {err}",
            target.address, target.port
        );
        let reply = DynamicForwardTargetReply {
            error: err.to_string(),
        };
        let _ = write_payload(&channel, &reply.encode()).await;
        let _ = channel.close().await;
        return Ok(());
    }

    let address = match resolve_dynamic_target(&target.address, target.port).await {
        Ok(address) => address,
        Err(err) => {
            eprintln!(
                "ssh3-rust-server could not resolve the dynamic forwarding target {}:{}: {err}",
                target.address, target.port
            );
            let reply = DynamicForwardTargetReply {
                error: err.to_string(),
            };
            let _ = write_payload(&channel, &reply.encode()).await;
            let _ = channel.close().await;
            return Ok(());
        }
    };

    let stream = match TcpStream::connect(address).await {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!(
                "ssh3-rust-server could not dial the dynamic forwarding target {address}: {err}"
            );
            let reply = DynamicForwardTargetReply {
                error: format!("dial tcp {address}: connect: {err}"),
            };
            let _ = write_payload(&channel, &reply.encode()).await;
            let _ = channel.close().await;
            return Ok(());
        }
    };

    if !session.acquire_connection() {
        let reason = format!(
            "too many open dynamic forwarding connections ({})",
            crate::forwarding::MAX_DYNAMIC_FORWARD_CONNECTIONS
        );
        eprintln!(
            "ssh3-rust-server not bridging the dynamic forwarding target {address}: {reason}"
        );
        let reply = DynamicForwardTargetReply { error: reason };
        let _ = write_payload(&channel, &reply.encode()).await;
        drop(stream);
        let _ = channel.close().await;
        return Ok(());
    }

    let reply = DynamicForwardTargetReply {
        error: String::new(),
    };
    if let Err(err) = write_payload(&channel, &reply.encode()).await {
        eprintln!("ssh3-rust-server could not acknowledge the dynamic forwarding target: {err}");
        session.release_connection();
        drop(stream);
        let _ = channel.close().await;
        return Ok(());
    }

    let result = bridge_tcp_channel_until(channel, stream, connection, Some(session.clone())).await;
    session.release_connection();
    if let Err(err) = result
        && !is_benign_server_error(&err)
    {
        eprintln!("ssh3-rust-server dynamic forwarding bridge error: {err}");
    }
    Ok(())
}
