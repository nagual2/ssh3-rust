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
//! | `tls` | self-signed TLS entry point |
//! | `runtime` | endpoint/connection acceptance and channel routing |
//! | `error` | [`Ssh3ServerError`] and benign-error classification |

mod auth;
mod config;
mod error;
mod forwarding;
mod pty;
mod runtime;
mod session;
mod tls;

#[cfg(test)]
mod tests;

pub use auth::Ssh3AuthGuard;
pub use config::{Ssh3PasswordVerifier, Ssh3ServerConfig, parse_duration};
pub use error::Ssh3ServerError;
pub use forwarding::{ForwardPolicy, check_listen_target};
pub use runtime::{serve_connection, serve_endpoint};
pub use tls::{apply_transport_timeouts, run_with_self_signed};
