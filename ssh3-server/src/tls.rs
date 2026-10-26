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
use crate::runtime::serve_endpoint;

/// Applies the configured QUIC timeouts to a server configuration.
///
/// The idle timeout of the transport is the `max-idle-timeout` of the
/// server; the handshake timeout is enforced by the runtime, which gives up
/// on a connection that does not complete its handshake in time.
pub fn apply_transport_timeouts(server_config: &mut ServerConfig, config: &Ssh3ServerConfig) {
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
    server_config.transport = Arc::new(transport);
}

/// Serves SSH3 with a freshly generated self-signed certificate.
///
/// A certificate is created for `config.cert_subject_alt_names`, the QUIC
/// endpoint is bound to `config.bind_addr` and connections are accepted until
/// the endpoint stops yielding incoming connections.
///
/// Use [`serve_endpoint`](crate::serve_endpoint) instead when the caller
/// provides its own certificate or key.
pub async fn run_with_self_signed(config: Ssh3ServerConfig) -> Result<(), Ssh3ServerError> {
    validate_server_config(&config)?;
    let (mut server_config, _certificate) =
        self_signed_server_config(config.cert_subject_alt_names.clone())?;
    apply_transport_timeouts(&mut server_config, &config);
    let endpoint = Endpoint::server(server_config, config.bind_addr)?;
    serve_endpoint(endpoint, config).await
}
