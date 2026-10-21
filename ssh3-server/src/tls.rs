//! TLS bootstrap of the server.
//!
//! The server can either own its TLS material — generating a self-signed
//! certificate for the configured subject alternative names — or run on top
//! of an endpoint the caller has already configured.

use quinn::Endpoint;
use ssh3_quinn::self_signed_server_config;

use crate::config::{Ssh3ServerConfig, validate_server_config};
use crate::error::Ssh3ServerError;
use crate::runtime::serve_endpoint;

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
    let (server_config, _certificate) =
        self_signed_server_config(config.cert_subject_alt_names.clone())?;
    let endpoint = Endpoint::server(server_config, config.bind_addr)?;
    serve_endpoint(endpoint, config).await
}
