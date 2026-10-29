//! SSH3 server runtime.
//!
//! This crate implements the server half of SSH3 (SSH tunnelled over
//! QUIC/HTTP3) on top of [`quinn`]. The public surface is intentionally
//! small:
//!
//! * [`Ssh3ServerConfig`] — how the server binds, which identities it trusts and
//!   which user sessions run as.
//! * [`run_with_self_signed`] — convenience entry point that generates a
//!   self-signed certificate and serves until the endpoint dies.
//! * [`serve_endpoint`] / [`serve_connection`] — building blocks for callers
//!   that own the TLS configuration or the QUIC endpoint themselves.
//! * [`Ssh3ServerError`] — the error type returned by all of the above.
//!
//! Internally the crate is split into focused modules:
//!
//! | Module | Responsibility |
//! |---|---|
//! | `config` | [`Ssh3ServerConfig`] and the defaults it is built from |
//! | `auth` | request authorization: bearer tokens, OIDC identities, passwords, DoS guards |
//! | `session` | session channels, process spawning, agent forwarding |
//! | `pty` | pseudo-terminal allocation, sizing and signal delivery |
//! | `forwarding` | direct TCP/UDP port forwarding and the `PermitOpen` policy |
//! | `forwarding_wire` | wire payloads of the reverse and dynamic forwarding channels |
//! | `reverse_forward` | the server side of the reverse port forwarding (`-R`) |
//! | `dynamic_forward` | the server side of the dynamic SOCKS forwarding (`-D`) |
//! | `sftp` | the server side of the SFTP subsystem (the file transfer) |
//! | `sftp_child` | the internal child of the chroot jail of the SFTP subsystem |
//! | `sftp_stream` | the byte streams of the SFTP subsystem |
//! | `tls` | self-signed TLS entry point |
//! | `runtime` | endpoint/connection acceptance and channel routing |
//! | `error` | [`Ssh3ServerError`] and benign-error classification |

mod auth;
mod config;
mod dynamic_forward;
mod error;
mod forwarding;
mod forwarding_wire;
mod pty;
mod reverse_forward;
mod runtime;
mod session;
mod sftp;
mod sftp_child;
mod sftp_stream;
mod tls;

#[cfg(test)]
mod forwarding_tests;
#[cfg(test)]
mod sftp_tests;
#[cfg(test)]
mod tests;

pub use auth::Ssh3AuthGuard;
pub use config::{
    GatewayPortsPolicy, SftpJailMode, Ssh3PasswordVerifier, Ssh3ServerConfig, parse_duration,
};
pub use error::Ssh3ServerError;
pub use forwarding::{ForwardPolicy, check_listen_target};
pub use forwarding_wire::Ssh3ForwardingWireError;
pub use runtime::{serve_connection, serve_endpoint};
pub use sftp::SftpSessionBudget;
pub use sftp_child::{InternalSftpOptions, run_internal_sftp_server};
pub use tls::{apply_transport_limits, run_with_self_signed};
