//! The dispatcher of the channels the server opens towards the client.
//!
//! A server may open a channel towards the client at any moment: the
//! reverse forwarding bridges (`forwarded-tcp` and `forwarded-udp`) and the
//! agent connections. The dispatcher is the single consumer of the channels
//! the peer opened, so no channel is stolen by another task.
//!
//! The channels arrive as raw QUIC streams: the HTTP/3 driver of the client
//! is stopped once the conversation is established, exactly like the server
//! does, because a server-initiated stream is not an HTTP/3 request and the
//! driver would refuse the connection (RFC 9114, section 6.1).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::reverse::{
    Ssh3ResolvedReverseForward, Ssh3ReverseForwardProtocol, authorize_forwarded_target,
    bridge_forwarded_tcp, bridge_forwarded_udp, canonical_target,
};
use quinn::Connection;
use ssh3_core::{Ssh3AcceptedChannel, Ssh3Channel, Ssh3Conversation};

/// The maximum number of forwarded channels that may be bridged at the same
/// time.
///
/// The limit is the one of the reference implementation: it bounds the
/// number of local connections a peer may make the client open.
pub(crate) const MAX_FORWARDED_CHANNELS: usize = 64;

/// The state the dispatcher needs to serve the channels of the peer.
pub(crate) struct IncomingChannels {
    /// The conversation the channels belong to.
    conversation: Arc<Ssh3Conversation>,
    /// The connection the channels ride.
    ///
    /// The dispatcher ends when the connection is closed: the queue of the
    /// conversation never wakes up on its own.
    connection: Connection,
    /// The reverse forwards the client requested.
    ///
    /// Only the targets of these forwards may be bridged: a peer that asks
    /// for another endpoint is refused.
    reverse_forwards: Arc<RwLock<Vec<Ssh3ResolvedReverseForward>>>,
    /// The socket of the SSH agent, when the agent forwarding is on.
    agent_socket: Option<PathBuf>,
    /// The number of forwarded channels that are bridged at the same time.
    open_forwarded_channels: Arc<AtomicUsize>,
}

impl IncomingChannels {
    /// Creates the dispatcher of the channels of a conversation.
    pub(crate) fn new(
        conversation: Arc<Ssh3Conversation>,
        connection: Connection,
        reverse_forwards: Arc<RwLock<Vec<Ssh3ResolvedReverseForward>>>,
        agent_socket: Option<PathBuf>,
    ) -> Self {
        Self {
            conversation,
            connection,
            reverse_forwards,
            agent_socket,
            open_forwarded_channels: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Serves the channels the peer opens until the conversation ends.
    pub(crate) async fn run(self) {
        loop {
            let accepted = tokio::select! {
                _ = self.connection.closed() => return,
                accepted = self.conversation.accept_channel_with_metadata() => {
                    match accepted {
                        Ok(accepted) => accepted,
                        Err(_) => return,
                    }
                }
            };
            match accepted {
                Ssh3AcceptedChannel::TcpForwarding {
                    channel,
                    remote_addr,
                } if channel.channel_type() == b"forwarded-tcp" => {
                    self.serve_forwarded_tcp(channel, remote_addr).await;
                }
                Ssh3AcceptedChannel::UdpForwarding {
                    channel,
                    remote_addr,
                } if channel.channel_type() == b"forwarded-udp" => {
                    self.serve_forwarded_udp(channel, remote_addr).await;
                }
                Ssh3AcceptedChannel::Channel(channel)
                    if channel.channel_type() == b"agent-connection" =>
                {
                    self.serve_agent_connection(channel).await;
                }
                other => {
                    let channel = other.channel();
                    eprintln!(
                        "ssh3 rejecting unexpected server-initiated channel {} of type {}",
                        channel.channel_id(),
                        String::from_utf8_lossy(channel.channel_type())
                    );
                    let _ = channel.close().await;
                }
            }
        }
    }

    /// Bridges a `forwarded-tcp` channel to the local target of its forward.
    async fn serve_forwarded_tcp(&self, channel: Arc<Ssh3Channel>, target: SocketAddr) {
        if !self.is_authorized(Ssh3ReverseForwardProtocol::Tcp, target) {
            eprintln!(
                "ssh3 rejecting a forwarded-tcp channel towards {target}: the target was not requested with -R"
            );
            let _ = channel.close().await;
            return;
        }
        let Some(guard) = ForwardedChannelGuard::acquire(&self.open_forwarded_channels) else {
            eprintln!(
                "ssh3 too many open forwarded channels (limit {MAX_FORWARDED_CHANNELS}), closing the channel towards {target}"
            );
            let _ = channel.close().await;
            return;
        };
        // The peer may echo the target in the IPv4-mapped IPv6 form: the
        // bridge always uses the canonical form of the endpoint.
        let target = canonical_target(target);

        tokio::spawn(async move {
            let _guard = guard;
            if let Err(err) = bridge_forwarded_tcp(channel, target).await
                && !crate::is_benign_client_error(&err)
            {
                eprintln!("ssh3 reverse forwarding error: {err}");
            }
        });
    }

    /// Bridges a `forwarded-udp` channel to the local target of its forward.
    async fn serve_forwarded_udp(&self, channel: Arc<Ssh3Channel>, target: SocketAddr) {
        if !self.is_authorized(Ssh3ReverseForwardProtocol::Udp, target) {
            eprintln!(
                "ssh3 rejecting a forwarded-udp channel towards {target}: the target was not requested with -R"
            );
            let _ = channel.close().await;
            return;
        }
        let Some(guard) = ForwardedChannelGuard::acquire(&self.open_forwarded_channels) else {
            eprintln!(
                "ssh3 too many open forwarded channels (limit {MAX_FORWARDED_CHANNELS}), closing the channel towards {target}"
            );
            let _ = channel.close().await;
            return;
        };
        // The peer may echo the target in the IPv4-mapped IPv6 form: the
        // bridge always uses the canonical form of the endpoint.
        let target = canonical_target(target);

        let connection = self.connection.clone();
        tokio::spawn(async move {
            let _guard = guard;
            if let Err(err) = bridge_forwarded_udp(&connection, channel, target).await
                && !crate::is_benign_client_error(&err)
            {
                eprintln!("ssh3 reverse forwarding error: {err}");
            }
        });
    }

    /// Forwards an agent connection to the local SSH agent.
    async fn serve_agent_connection(&self, channel: Arc<Ssh3Channel>) {
        let Some(agent_socket) = self.agent_socket.clone() else {
            eprintln!("ssh3 rejecting an agent connection: the agent forwarding is not enabled");
            let _ = channel.close().await;
            return;
        };

        #[cfg(unix)]
        tokio::spawn(async move {
            if let Err(err) = forward_agent_channel(channel, &agent_socket).await
                && !crate::is_benign_client_error(&err)
            {
                eprintln!("ssh3 agent forwarding error: {err}");
            }
        });
        #[cfg(not(unix))]
        {
            // The local SSH agent is a Unix socket, so there is nothing to
            // forward a connection to on the other platforms.
            let _ = agent_socket;
            eprintln!("ssh3 rejecting an agent connection: the agent forwarding is unix-only");
            let _ = channel.close().await;
        }
    }

    /// Tells whether the target of a forwarded channel was requested.
    fn is_authorized(&self, protocol: Ssh3ReverseForwardProtocol, target: SocketAddr) -> bool {
        let forwards = match self.reverse_forwards.read() {
            Ok(forwards) => forwards.clone(),
            // A poisoned lock holds a consistent list of forwards: the panic
            // of a writer must not open the door to an unauthorized target.
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        authorize_forwarded_target(&forwards, protocol, target)
    }
}

/// A guard that gives the slot of a forwarded channel back when it ends.
pub(crate) struct ForwardedChannelGuard {
    counter: Arc<AtomicUsize>,
}

impl ForwardedChannelGuard {
    /// Takes a slot of the forwarded channel budget.
    pub(crate) fn acquire(counter: &Arc<AtomicUsize>) -> Option<Self> {
        let mut count = counter.load(Ordering::SeqCst);
        loop {
            if count >= MAX_FORWARDED_CHANNELS {
                return None;
            }
            match counter.compare_exchange(count, count + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => {
                    return Some(Self {
                        counter: counter.clone(),
                    });
                }
                Err(current) => count = current,
            }
        }
    }
}

impl Drop for ForwardedChannelGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Forwards an agent connection to the local SSH agent.
#[cfg(unix)]
pub(crate) async fn forward_agent_channel(
    channel: Arc<Ssh3Channel>,
    agent_socket: &std::path::Path,
) -> Result<(), crate::Ssh3ClientError> {
    use ssh3_proto::{SSH_EXTENDED_DATA_NONE, Ssh3Message};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(agent_socket).await?;
    let (mut reader, mut writer) = stream.into_split();

    let mut to_agent = tokio::spawn({
        let channel = channel.clone();
        async move {
            loop {
                let message = channel.next_message().await?;
                if let Ssh3Message::Data(data) = message
                    && data.data_type == SSH_EXTENDED_DATA_NONE
                {
                    writer.write_all(&data.data).await?;
                    writer.flush().await?;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), crate::Ssh3ClientError>(())
        }
    });

    let mut from_agent = tokio::spawn({
        let channel = channel.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    let _ = channel.close().await;
                    return Ok::<(), crate::Ssh3ClientError>(());
                }
                channel
                    .write_data(&buf[..n], SSH_EXTENDED_DATA_NONE)
                    .await?;
            }
        }
    });

    tokio::select! {
        result = &mut to_agent => {
            from_agent.abort();
            let _ = channel.close().await;
            result.map_err(|err| crate::Ssh3ClientError::Io(std::io::Error::other(err.to_string())))?
        }
        result = &mut from_agent => {
            to_agent.abort();
            let _ = channel.close().await;
            result.map_err(|err| crate::Ssh3ClientError::Io(std::io::Error::other(err.to_string())))?
        }
    }
}
