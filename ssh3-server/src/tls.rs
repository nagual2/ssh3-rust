//! TLS bootstrap of the server.
//!
//! The server can either own its TLS material — generating a self-signed
//! certificate for the configured subject alternative names — or run on top
//! of an endpoint the caller has already configured.

use std::sync::Arc;

use quinn::{Endpoint, ServerConfig};
use ssh3_quinn::self_signed_server_config;

use crate::config::{Ssh3ServerConfig, validate_server_config};
use crate::error::Ssh3ServerError;
use crate::runtime::serve_endpoint_until_shutdown;
use crate::shutdown::{ShutdownSignal, shutdown_signal};

/// Applies the configured QUIC transport limits to a server configuration.
///
/// The idle timeout of the transport is the `max-idle-timeout` of the server;
/// the handshake timeout is enforced by the runtime, which gives up on a
/// connection that does not complete its handshake in time. The stream caps
/// are the `-max-incoming-streams` / `-max-incoming-uni-streams` options of
/// the audit of 2026-10-27 (K3): the peer cannot open more concurrent streams
/// per connection than the caps allow.
pub fn apply_transport_limits(server_config: &mut ServerConfig, config: &Ssh3ServerConfig) {
    server_config.transport = Arc::new(server_transport_config(config));
}

/// Builds the QUIC transport configuration of the server.
///
/// Split from [`apply_transport_limits`] so the tests can pin the transport
/// knobs of the reference (the disabled path MTU discovery) without binding
/// an endpoint.
fn server_transport_config(config: &Ssh3ServerConfig) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    // SSH3 carries its UDP forwarding over the raw QUIC datagram API: the
    // frame size parameter announces the ability to receive them. Without
    // it a peer that speaks only quinn (the Rust client of a proxy jump
    // chain, a local UDP forward) cannot send a single datagram.
    transport.datagram_receive_buffer_size(Some(65_535));
    transport.max_idle_timeout(match quinn::IdleTimeout::try_from(config.max_idle_timeout) {
        Ok(idle_timeout) => Some(idle_timeout),
        Err(_) => {
            eprintln!(
                "ssh3-rust-server the idle timeout of {}s does not fit into the QUIC transport parameters, the idle timeout is disabled",
                config.max_idle_timeout.as_secs()
            );
            None
        }
    });
    transport.max_concurrent_bidi_streams(config.max_incoming_streams.into());
    transport.max_concurrent_uni_streams(config.max_incoming_uni_streams.into());
    // The `-initial-packet-size` of the reference rides the transport: the
    // quinn builder floors the value at the QUIC minimum, the way the Go
    // reference ignores a size below it (`cmd/ssh3-server.go`).
    ssh3_quinn::apply_initial_packet_size(&mut transport, config.initial_packet_size);
    // The reference never grows the packets of its server past the initial
    // size (`cmd/ssh3-server.go`, `DisablePathMTUDiscovery: true`): the
    // discovery has nothing to learn.
    ssh3_quinn::disable_path_mtu_discovery(&mut transport);
    transport
}

/// Serves SSH3 with a freshly generated self-signed certificate.
///
/// A certificate is created for `config.cert_subject_alt_names`, the QUIC
/// endpoint is bound to `config.bind_addr` and connections are accepted until
/// the endpoint stops yielding incoming connections. On a shutdown signal
/// (`SIGINT`/`SIGTERM` on Unix, Ctrl-C on Windows) the endpoint stops
/// accepting new connections and the conversations being served drain up to
/// the `shutdown_drain` window of the configuration before the call returns.
///
/// Use [`serve_endpoint`](crate::serve_endpoint) instead when the caller
/// provides its own certificate or key, and
/// [`serve_endpoint_until_shutdown`](crate::serve_endpoint_until_shutdown)
/// when the caller owns the shutdown signal as well.
pub async fn run_with_self_signed(config: Ssh3ServerConfig) -> Result<(), Ssh3ServerError> {
    validate_server_config(&config)?;
    let (mut server_config, _certificate) =
        self_signed_server_config(config.cert_subject_alt_names.clone())?;
    apply_transport_limits(&mut server_config, &config);
    let endpoint = Endpoint::server(server_config, config.bind_addr)?;
    // the graceful shutdown of the Go reference: the operator's signal asks
    // the runtime to stop accepting and to drain the conversations
    let shutdown = ShutdownSignal::new();
    let signal_task = shutdown.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        signal_task.trigger();
    });
    serve_endpoint_until_shutdown(endpoint, config, shutdown).await
}

#[cfg(test)]
mod tests {
    use crate::config::Ssh3ServerConfig;

    /// The server keeps the path MTU discovery off, the posture of the
    /// reference (`cmd/ssh3-server.go`, `DisablePathMTUDiscovery: true`):
    /// the packets stay at the initial size instead of growing towards the
    /// path MTU.
    #[test]
    fn the_server_keeps_the_path_mtu_discovery_off() {
        let transport = super::server_transport_config(&Ssh3ServerConfig::default());
        assert!(
            format!("{transport:?}").contains("mtu_discovery_config: None"),
            "{transport:?}"
        );
    }

    /// The `-initial-packet-size` knob reaches the transport builder: the
    /// value lands in the initial MTU and a size below the QUIC minimum
    /// rides the 1200-byte floor, like in the reference.
    #[test]
    fn the_initial_packet_size_reaches_the_server_transport() {
        let config = Ssh3ServerConfig {
            initial_packet_size: 1400,
            ..Ssh3ServerConfig::default()
        };
        let transport = super::server_transport_config(&config);
        assert!(
            format!("{transport:?}").contains("initial_mtu: 1400"),
            "{transport:?}"
        );

        // Below the QUIC minimum the transport clamps to the 1200 default.
        let config = Ssh3ServerConfig {
            initial_packet_size: 900,
            ..Ssh3ServerConfig::default()
        };
        let transport = super::server_transport_config(&config);
        assert!(
            format!("{transport:?}").contains("initial_mtu: 1200"),
            "{transport:?}"
        );
    }
}
