//! Direct port forwarding: TCP and UDP channels opened by the client.
//!
//! SSH3 carries forwarded connections as regular channels: a `direct-tcp`
//! channel is a byte stream to a remote TCP endpoint, a `direct-udp` channel
//! is a datagram channel to a remote UDP endpoint. The target address is
//! negotiated in the channel header and is delivered with the channel.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use quinn::Connection;
use ssh3_core::Ssh3Channel;
use ssh3_proto::{SSH_EXTENDED_DATA_NONE, Ssh3Message};

use crate::error::Ssh3ServerError;

/// Forwards a UDP datagram channel to the requested remote endpoint.
///
/// A local socket is connected to the remote address and both directions are
/// pumped until the connection is closed.
pub(crate) async fn handle_udp_forwarding(
    channel: Arc<Ssh3Channel>,
    remote_addr: SocketAddr,
    connection: Connection,
) -> Result<(), Ssh3ServerError> {
    let bind_addr = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    };
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    socket.connect(remote_addr).await?;

    let to_socket = tokio::spawn({
        let channel = channel.clone();
        let socket = socket.clone();
        let connection = connection.clone();
        async move {
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    datagram = channel.receive_datagram() => {
                        socket.send(&datagram).await?;
                    }
                }
            }
        }
    });

    let from_socket = tokio::spawn({
        let channel = channel.clone();
        let socket = socket.clone();
        let connection = connection.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    result = socket.recv(&mut buf) => {
                        let n = result?;
                        channel.send_datagram(buf[..n].to_vec()).await?;
                    }
                }
            }
        }
    });

    let _ = to_socket.await;
    let _ = from_socket.await;
    Ok(())
}

/// Forwards a TCP stream channel to the requested remote endpoint.
///
/// The remote socket is connected once and both directions are pumped until
/// the connection is closed.
pub(crate) async fn handle_tcp_forwarding(
    channel: Arc<Ssh3Channel>,
    remote_addr: SocketAddr,
    connection: Connection,
) -> Result<(), Ssh3ServerError> {
    let stream = TcpStream::connect(remote_addr).await?;
    let (mut reader, mut writer) = stream.into_split();

    let to_socket = tokio::spawn({
        let channel = channel.clone();
        let connection = connection.clone();
        async move {
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    message = channel.next_message() => {
                        let message = message?;
                        if let Ssh3Message::Data(data) = message
                            && data.data_type == SSH_EXTENDED_DATA_NONE
                        {
                            writer.write_all(&data.data).await?;
                            writer.flush().await?;
                        }
                    }
                }
            }
        }
    });

    let from_socket = tokio::spawn({
        let channel = channel.clone();
        let connection = connection.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), Ssh3ServerError>(()),
                    read = reader.read(&mut buf) => {
                        let n = read?;
                        if n == 0 {
                            return Ok(());
                        }
                        channel.write_data(&buf[..n], SSH_EXTENDED_DATA_NONE).await?;
                    }
                }
            }
        }
    });

    let _ = to_socket.await;
    let _ = from_socket.await;
    Ok(())
}
