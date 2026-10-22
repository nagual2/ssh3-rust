//! Integration tests of the reverse and dynamic port forwarding.
//!
//! The tests speak the protocol of the reference implementation: the client
//! opens the control channels itself, encodes the payloads with the codec of
//! the crate and reads the channels the server opens towards it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use ssh3_core::{Ssh3Channel, Ssh3Conversation};
use ssh3_proto::{SSH_EXTENDED_DATA_NONE, SSH_FRAME_TYPE, Ssh3Message};
use ssh3_quinn::{Ssh3QuinnReceiveStream, Ssh3QuinnSendStream, open_channel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::config::Ssh3ServerConfig;
use crate::forwarding::ForwardPolicy;
use crate::forwarding_wire::{
    DynamicForwardReply, DynamicForwardRequest, DynamicForwardTarget, DynamicForwardTargetReply,
    FORWARDING_PROTOCOL_TCP, FORWARDING_PROTOCOL_UDP, ReverseForwardReply, ReverseForwardRequest,
};
use crate::tests::{TestHarness, setup_forwarding_harness};

/// A channel the server opened towards the client.
struct ServerOpenedChannel {
    /// The channel itself.
    channel: Arc<Ssh3Channel>,
    /// The type the server announced for the channel.
    channel_type: Vec<u8>,
    /// The target the additional header bytes carried, if any.
    target: Option<SocketAddr>,
}

/// Reads a variable-length integer from a QUIC stream.
async fn read_var_int_stream(recv: &mut quinn::RecvStream) -> std::io::Result<u64> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let length = 1usize << ((first[0] & 0xc0) >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    if length > 1 {
        let mut rest = [0u8; 8];
        let rest = &mut rest[..length - 1];
        recv.read_exact(rest)
            .await
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        for byte in rest.iter() {
            value = (value << 8) | u64::from(*byte);
        }
    }
    Ok(value)
}

/// Reads a length-prefixed byte string from a QUIC stream.
async fn read_ssh_bytes_stream(recv: &mut quinn::RecvStream) -> std::io::Result<Vec<u8>> {
    let length = read_var_int_stream(recv).await?;
    let length =
        usize::try_from(length).map_err(|_| std::io::Error::other("the length is too big"))?;
    let mut bytes = vec![0u8; length];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    Ok(bytes)
}

/// Reads the target address a forwarded channel carries in its additional
/// header bytes.
async fn read_forwarding_target_stream(
    recv: &mut quinn::RecvStream,
) -> std::io::Result<SocketAddr> {
    let family = read_var_int_stream(recv).await?;
    let octets = match family {
        4 => 4,
        6 => 16,
        other => {
            return Err(std::io::Error::other(format!(
                "invalid address family: {other}"
            )));
        }
    };
    let mut address = vec![0u8; octets];
    recv.read_exact(&mut address)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let mut port = [0u8; 2];
    recv.read_exact(&mut port)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let port = u16::from_be_bytes(port);
    match octets {
        4 => {
            let octets: [u8; 4] = address
                .try_into()
                .map_err(|_| std::io::Error::other("invalid IPv4 address"))?;
            Ok(SocketAddr::new(Ipv4Addr::from(octets).into(), port))
        }
        _ => {
            let octets: [u8; 16] = address
                .try_into()
                .map_err(|_| std::io::Error::other("invalid IPv6 address"))?;
            Ok(SocketAddr::new(Ipv6Addr::from(octets).into(), port))
        }
    }
}

/// Accepts a channel the server opened towards the client.
///
/// The header of a forwarded channel carries the target address in its
/// additional bytes, so the header is read here instead of being parsed by
/// the generic helper of the transport, which only knows the direct
/// forwarding channels.
async fn accept_server_opened_channel(
    connection: &quinn::Connection,
    conversation: &Ssh3Conversation,
) -> std::io::Result<ServerOpenedChannel> {
    let (send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let frame_type = read_var_int_stream(&mut recv).await?;
    if frame_type != SSH_FRAME_TYPE {
        return Err(std::io::Error::other("unexpected channel frame type"));
    }
    let _conversation_stream_id = read_var_int_stream(&mut recv).await?;
    let channel_type = read_ssh_bytes_stream(&mut recv).await?;
    let max_packet_size = read_var_int_stream(&mut recv).await?;
    let target = match channel_type.as_slice() {
        b"forwarded-tcp" | b"forwarded-udp" => {
            Some(read_forwarding_target_stream(&mut recv).await?)
        }
        _ => None,
    };
    let stream_id: u64 = recv.id().into();
    let channel = Arc::new(Ssh3Channel::new(
        conversation.control_stream_id(),
        conversation.conversation_id(),
        stream_id,
        channel_type.clone(),
        max_packet_size,
        Ssh3QuinnReceiveStream::new(recv),
        Ssh3QuinnSendStream::new(send),
        None,
        false,
        false,
        true,
        10,
        None,
    ));
    channel
        .confirm_channel(conversation.max_packet_size())
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    Ok(ServerOpenedChannel {
        channel,
        channel_type,
        target,
    })
}

/// Reads the payload of the first data message of a channel.
async fn read_channel_payload(channel: &Ssh3Channel) -> Vec<u8> {
    let message = timeout(Duration::from_secs(5), channel.next_message())
        .await
        .expect("the peer did not answer in time")
        .expect("the channel failed");
    match message {
        Ssh3Message::Data(data) => data.data,
        other => panic!("unexpected message: {other:?}"),
    }
}

/// Opens a channel of the given type towards the server.
async fn open_client_channel(harness: &TestHarness, channel_type: &[u8]) -> Arc<Ssh3Channel> {
    open_channel(
        harness.conversation.as_ref(),
        &harness.client_connection,
        channel_type.to_vec(),
        1024,
        10,
    )
    .await
    .expect("the channel could not be opened")
}

/// Starts an echo server that answers every payload it receives.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                if let Ok(read) = stream.read(&mut buffer).await {
                    let _ = stream.write_all(&buffer[..read]).await;
                }
            });
        }
    });
    address
}

/// A reverse forward request for the loopback interface.
fn loopback_reverse_request(bind_port: u16) -> ReverseForwardRequest {
    ReverseForwardRequest {
        protocol: FORWARDING_PROTOCOL_TCP,
        bind_address: "127.0.0.1".to_string(),
        bind_port,
        target_address: "127.0.0.1".to_string(),
        target_port: 9,
    }
}

#[tokio::test]
async fn the_reverse_forward_binds_an_ephemeral_port_and_mirrors_the_connections() {
    let harness = setup_forwarding_harness(Ssh3ServerConfig::default()).await;
    let control = open_client_channel(&harness, b"reverse-forward").await;

    let request = loopback_reverse_request(0);
    control
        .write_data(&request.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .unwrap();

    let reply = ReverseForwardReply::decode(&read_channel_payload(&control).await).unwrap();
    assert!(
        reply.error.is_empty(),
        "the bind was refused: {}",
        reply.error
    );
    assert_ne!(
        reply.bound_port, 0,
        "the server did not bind an ephemeral port"
    );

    // a connection to the bound port reaches the client as a forwarded-tcp
    // channel that carries the client-side target
    let mut stream = TcpStream::connect(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        reply.bound_port,
    ))
    .await
    .unwrap();
    let accepted = timeout(
        Duration::from_secs(10),
        accept_server_opened_channel(&harness.client_connection, &harness.conversation),
    )
    .await
    .expect("the server did not open a forwarded-tcp channel in time")
    .expect("the forwarded-tcp channel could not be read");
    assert_eq!(accepted.channel_type, b"forwarded-tcp");
    assert_eq!(
        accepted.target,
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)),
        "the forwarded-tcp channel does not carry the client-side target"
    );

    // the payload of the connection reaches the client
    stream.write_all(b"ping").await.unwrap();
    assert_eq!(read_channel_payload(&accepted.channel).await, b"ping");

    harness.shutdown().await;
}

#[tokio::test]
async fn the_reverse_forward_mirrors_the_datagrams_of_a_udp_listener() {
    // a UDP echo server
    let socket =
        tokio::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
    let echo_address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let _ = socket.send_to(&buffer[..length], peer).await;
        }
    });

    let harness = setup_forwarding_harness(Ssh3ServerConfig::default()).await;
    let control = open_client_channel(&harness, b"reverse-forward").await;

    let request = ReverseForwardRequest {
        protocol: FORWARDING_PROTOCOL_UDP,
        bind_address: "127.0.0.1".to_string(),
        bind_port: 0,
        target_address: "127.0.0.1".to_string(),
        target_port: echo_address.port(),
    };
    control
        .write_data(&request.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .unwrap();
    let reply = ReverseForwardReply::decode(&read_channel_payload(&control).await).unwrap();
    assert!(
        reply.error.is_empty(),
        "the bind was refused: {}",
        reply.error
    );
    let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), reply.bound_port);

    // the server mirrors the datagrams of the listener to the client
    let client_socket =
        tokio::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
    client_socket.send_to(b"ping", bound).await.unwrap();

    let accepted = timeout(
        Duration::from_secs(10),
        accept_server_opened_channel(&harness.client_connection, &harness.conversation),
    )
    .await
    .expect("the server did not open a forwarded-udp channel in time")
    .expect("the forwarded-udp channel could not be read");
    assert_eq!(accepted.channel_type, b"forwarded-udp");
    assert_eq!(
        accepted.target,
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            echo_address.port()
        )),
        "the forwarded-udp channel does not carry the client-side target"
    );

    // the datagram reaches the client as a QUIC datagram of the channel
    let datagram = timeout(
        Duration::from_secs(10),
        harness.client_connection.read_datagram(),
    )
    .await
    .expect("the datagram did not reach the client in time")
    .expect("the datagram could not be read");
    let mut cursor = std::io::Cursor::new(datagram.as_ref());
    let _control_stream_id = ssh3_proto::read_var_int(&mut cursor).unwrap();
    let channel_id = ssh3_proto::read_var_int(&mut cursor).unwrap();
    assert_eq!(channel_id, accepted.channel.channel_id());
    let payload = &datagram[cursor.position() as usize..];
    assert_eq!(payload, b"ping");

    harness.shutdown().await;
}

#[tokio::test]
async fn the_reverse_forward_bind_is_denied_by_the_permit_listen_policy() {
    let config = Ssh3ServerConfig {
        permit_listen: ForwardPolicy::parse("203.0.113.7:443").unwrap(),
        ..Default::default()
    };
    let harness = setup_forwarding_harness(config).await;
    let control = open_client_channel(&harness, b"reverse-forward").await;

    let request = loopback_reverse_request(8080);
    control
        .write_data(&request.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .unwrap();

    let reply = ReverseForwardReply::decode(&read_channel_payload(&control).await).unwrap();
    assert!(!reply.error.is_empty(), "the denied bind was accepted");
    assert_eq!(reply.bound_port, 0);
    assert!(
        reply.error.contains("permit-listen"),
        "the reason is not readable: {}",
        reply.error
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn the_sixty_fifth_forwarded_channel_is_refused() {
    let harness = setup_forwarding_harness(Ssh3ServerConfig::default()).await;
    let control = open_client_channel(&harness, b"reverse-forward").await;

    let request = loopback_reverse_request(0);
    control
        .write_data(&request.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .unwrap();
    let reply = ReverseForwardReply::decode(&read_channel_payload(&control).await).unwrap();
    assert!(
        reply.error.is_empty(),
        "the bind was refused: {}",
        reply.error
    );
    let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), reply.bound_port);

    // the first sixty-four connections get a forwarded channel each
    let mut connections = Vec::new();
    for _ in 0..64 {
        connections.push(TcpStream::connect(bound).await.unwrap());
    }
    let mut channels = Vec::new();
    for _ in 0..64 {
        let accepted = timeout(
            Duration::from_secs(10),
            accept_server_opened_channel(&harness.client_connection, &harness.conversation),
        )
        .await
        .expect("the server did not open a forwarded-tcp channel in time")
        .expect("the forwarded-tcp channel could not be read");
        assert_eq!(accepted.channel_type, b"forwarded-tcp");
        channels.push(accepted.channel);
    }

    // the sixty-fifth connection is refused: the server closes it instead of
    // opening a forwarded channel
    let mut refused = TcpStream::connect(bound).await.unwrap();
    let mut buffer = [0u8; 1];
    let read = timeout(Duration::from_secs(10), refused.read(&mut buffer))
        .await
        .expect("the refused connection was not closed in time");
    assert!(
        matches!(read, Ok(0)),
        "the sixty-fifth connection was not refused: {read:?}"
    );
    assert!(
        timeout(
            Duration::from_secs(1),
            accept_server_opened_channel(&harness.client_connection, &harness.conversation)
        )
        .await
        .is_err(),
        "the server opened a sixty-fifth forwarded channel"
    );

    drop(connections);
    drop(channels);
    harness.shutdown().await;
}

#[tokio::test]
async fn the_dynamic_forward_dials_the_target_and_reports_the_failures() {
    let echo_address = start_echo_server().await;
    let harness = setup_forwarding_harness(Ssh3ServerConfig::default()).await;

    // the client announces its SOCKS listener
    let control = open_client_channel(&harness, b"dynamic-forward").await;
    let request = DynamicForwardRequest {
        bind_address: "127.0.0.1".to_string(),
        bind_port: 1080,
    };
    control
        .write_data(&request.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .unwrap();
    let reply = DynamicForwardReply::decode(&read_channel_payload(&control).await).unwrap();
    assert!(
        reply.error.is_empty(),
        "the dynamic forward was refused: {}",
        reply.error
    );
    assert_eq!(reply.bound_port, 1080);

    // a target the server can dial is bridged
    let data = open_client_channel(&harness, b"dynamic-forward-tcp").await;
    let target = DynamicForwardTarget {
        address: "127.0.0.1".to_string(),
        port: echo_address.port(),
    };
    data.write_data(&target.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .unwrap();
    let reply = DynamicForwardTargetReply::decode(&read_channel_payload(&data).await).unwrap();
    assert!(
        reply.error.is_empty(),
        "the dial was refused: {}",
        reply.error
    );
    data.write_data(b"ping", SSH_EXTENDED_DATA_NONE)
        .await
        .unwrap();
    assert_eq!(read_channel_payload(&data).await, b"ping");

    // a target that does not resolve is reported with a readable reason
    let data = open_client_channel(&harness, b"dynamic-forward-tcp").await;
    let target = DynamicForwardTarget {
        address: "host-that-does-not-exist.invalid".to_string(),
        port: 80,
    };
    data.write_data(&target.encode(), SSH_EXTENDED_DATA_NONE)
        .await
        .unwrap();
    let reply = DynamicForwardTargetReply::decode(&read_channel_payload(&data).await).unwrap();
    assert!(!reply.error.is_empty(), "the failing dial was not reported");
    assert!(
        reply.error.contains("could not resolve"),
        "the reason is not readable: {}",
        reply.error
    );

    harness.shutdown().await;
}
