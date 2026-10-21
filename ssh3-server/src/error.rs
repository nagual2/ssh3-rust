//! Error type of the server and the classification of "benign" failures.
//!
//! A large part of the server's error handling is about deciding whether a
//! failure is worth reporting: when a peer simply disconnects, the QUIC
//! stack reports a connection error, and every spawned task would otherwise
//! print a scary message on stderr. [`is_benign_server_error`] and its
//! siblings implement that policy.

use std::fmt;
use std::io;

use quinn::ConnectionError;
use ssh3_auth::Ssh3AuthError;
use ssh3_core::{Ssh3ChannelError, Ssh3ConversationError};
use ssh3_h3::{
    Ssh3BuildConnectRequestError, Ssh3DatagramDispatchError, Ssh3ServerConversationError,
};
use ssh3_quinn::{
    Ssh3AcceptChannelError, Ssh3ConfigError, Ssh3OpenChannelError, Ssh3RouteAcceptedChannelError,
};

/// Every failure that the server can surface to its caller.
///
/// The variants mirror the layer that produced the failure (configuration,
/// authentication, I/O, HTTP/3, QUIC, protocol), so callers can match on the
/// origin without inspecting nested error types.
#[derive(Debug)]
pub enum Ssh3ServerError {
    /// The TLS/QUIC server configuration was rejected.
    Config(Ssh3ConfigError),
    /// The request could not be authorized.
    Auth(Ssh3AuthError),
    /// An I/O operation failed.
    Io(io::Error),
    /// Building or sending an HTTP response failed.
    Http(http::Error),
    /// The HTTP/3 connection failed.
    H3Connection(h3::error::ConnectionError),
    /// The CONNECT response could not be constructed.
    BuildResponse(Ssh3BuildConnectRequestError),
    /// The QUIC connection failed.
    Connection(ConnectionError),
    /// Opening a channel failed.
    OpenChannel(Ssh3OpenChannelError),
    /// Accepting a channel failed.
    AcceptChannel(Ssh3AcceptChannelError),
    /// Routing an accepted channel failed.
    RouteAcceptedChannel(Ssh3RouteAcceptedChannelError),
    /// The server-side conversation failed.
    ServerConversation(Ssh3ServerConversationError),
    /// Dispatching a datagram failed.
    DatagramDispatch(Ssh3DatagramDispatchError),
    /// The conversation failed.
    Conversation(Ssh3ConversationError),
    /// The channel failed.
    Channel(Ssh3ChannelError),
}

impl fmt::Display for Ssh3ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "{err}"),
            Self::Auth(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Http(err) => write!(f, "{err}"),
            Self::H3Connection(err) => write!(f, "{err}"),
            Self::BuildResponse(err) => write!(f, "{err}"),
            Self::Connection(err) => write!(f, "{err}"),
            Self::OpenChannel(err) => write!(f, "{err}"),
            Self::AcceptChannel(err) => write!(f, "{err}"),
            Self::RouteAcceptedChannel(err) => write!(f, "{err}"),
            Self::ServerConversation(err) => write!(f, "{err}"),
            Self::DatagramDispatch(err) => write!(f, "{err}"),
            Self::Conversation(err) => write!(f, "{err}"),
            Self::Channel(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Ssh3ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(err) => Some(err),
            Self::Auth(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::Http(err) => Some(err),
            Self::H3Connection(err) => Some(err),
            Self::BuildResponse(err) => Some(err),
            Self::Connection(err) => Some(err),
            Self::OpenChannel(err) => Some(err),
            Self::AcceptChannel(err) => Some(err),
            Self::RouteAcceptedChannel(err) => Some(err),
            Self::ServerConversation(err) => Some(err),
            Self::DatagramDispatch(err) => Some(err),
            Self::Conversation(err) => Some(err),
            Self::Channel(err) => Some(err),
        }
    }
}

impl From<Ssh3ConfigError> for Ssh3ServerError {
    fn from(value: Ssh3ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<io::Error> for Ssh3ServerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<Ssh3AuthError> for Ssh3ServerError {
    fn from(value: Ssh3AuthError) -> Self {
        Self::Auth(value)
    }
}

impl From<http::Error> for Ssh3ServerError {
    fn from(value: http::Error) -> Self {
        Self::Http(value)
    }
}

impl From<h3::error::ConnectionError> for Ssh3ServerError {
    fn from(value: h3::error::ConnectionError) -> Self {
        Self::H3Connection(value)
    }
}

impl From<Ssh3BuildConnectRequestError> for Ssh3ServerError {
    fn from(value: Ssh3BuildConnectRequestError) -> Self {
        Self::BuildResponse(value)
    }
}

impl From<ConnectionError> for Ssh3ServerError {
    fn from(value: ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<Ssh3OpenChannelError> for Ssh3ServerError {
    fn from(value: Ssh3OpenChannelError) -> Self {
        Self::OpenChannel(value)
    }
}

impl From<Ssh3AcceptChannelError> for Ssh3ServerError {
    fn from(value: Ssh3AcceptChannelError) -> Self {
        Self::AcceptChannel(value)
    }
}

impl From<Ssh3RouteAcceptedChannelError> for Ssh3ServerError {
    fn from(value: Ssh3RouteAcceptedChannelError) -> Self {
        Self::RouteAcceptedChannel(value)
    }
}

impl From<Ssh3ServerConversationError> for Ssh3ServerError {
    fn from(value: Ssh3ServerConversationError) -> Self {
        Self::ServerConversation(value)
    }
}

impl From<Ssh3DatagramDispatchError> for Ssh3ServerError {
    fn from(value: Ssh3DatagramDispatchError) -> Self {
        Self::DatagramDispatch(value)
    }
}

impl From<Ssh3ConversationError> for Ssh3ServerError {
    fn from(value: Ssh3ConversationError) -> Self {
        Self::Conversation(value)
    }
}

impl From<Ssh3ChannelError> for Ssh3ServerError {
    fn from(value: Ssh3ChannelError) -> Self {
        Self::Channel(value)
    }
}

/// Returns `true` for QUIC errors that only mean "the peer went away".
pub(crate) fn is_benign_connection_error(error: &ConnectionError) -> bool {
    matches!(
        error,
        ConnectionError::ApplicationClosed(..)
            | ConnectionError::ConnectionClosed(..)
            | ConnectionError::LocallyClosed
            | ConnectionError::TimedOut
    )
}

/// Returns `true` for I/O errors caused by a closed or reset connection.
pub(crate) fn is_benign_io_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    ) {
        return true;
    }

    if error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ConnectionError>())
        .is_some_and(is_benign_connection_error)
    {
        return true;
    }

    let message = error.to_string().to_ascii_lowercase();
    message.contains("connection lost")
        || message.contains("closed stream")
        || message.contains("connection closed")
}

/// Returns `true` for channel errors that only mean "the peer went away".
pub(crate) fn is_benign_channel_error(error: &Ssh3ChannelError) -> bool {
    matches!(error, Ssh3ChannelError::Io(error) if is_benign_io_error(error))
}

/// Returns `true` for conversation errors that only mean "the peer went away".
pub(crate) fn is_benign_conversation_error(error: &Ssh3ConversationError) -> bool {
    matches!(error, Ssh3ConversationError::Channel(error) if is_benign_channel_error(error))
}

/// Returns `true` for open-channel errors that only mean "the peer went away".
pub(crate) fn is_benign_open_channel_error(error: &Ssh3OpenChannelError) -> bool {
    match error {
        Ssh3OpenChannelError::Connection(error) => is_benign_connection_error(error),
        Ssh3OpenChannelError::Conversation(error) => is_benign_conversation_error(error),
    }
}

/// Returns `true` for accept-channel errors that only mean "the peer went away".
pub(crate) fn is_benign_accept_channel_error(error: &Ssh3AcceptChannelError) -> bool {
    matches!(error, Ssh3AcceptChannelError::Connection(error) if is_benign_connection_error(error))
}

/// Returns `true` for channel-routing errors that only mean "the peer went away".
pub(crate) fn is_benign_route_error(error: &Ssh3RouteAcceptedChannelError) -> bool {
    matches!(
        error,
        Ssh3RouteAcceptedChannelError::Accept(Ssh3AcceptChannelError::Connection(error))
            if is_benign_connection_error(error)
    )
}

/// Returns `true` for datagram-dispatch errors that only mean "the peer went away".
pub(crate) fn is_benign_datagram_error(error: &Ssh3DatagramDispatchError) -> bool {
    matches!(
        error,
        Ssh3DatagramDispatchError::Connection(error) if is_benign_connection_error(error)
    )
}

/// Returns `true` when a server error is only the result of a peer disconnecting.
///
/// Such errors are not logged: they are the normal end of a session.
pub(crate) fn is_benign_server_error(error: &Ssh3ServerError) -> bool {
    match error {
        Ssh3ServerError::Connection(error) => is_benign_connection_error(error),
        Ssh3ServerError::OpenChannel(error) => is_benign_open_channel_error(error),
        Ssh3ServerError::AcceptChannel(error) => is_benign_accept_channel_error(error),
        Ssh3ServerError::RouteAcceptedChannel(error) => is_benign_route_error(error),
        Ssh3ServerError::DatagramDispatch(error) => is_benign_datagram_error(error),
        Ssh3ServerError::Conversation(error) => is_benign_conversation_error(error),
        Ssh3ServerError::Channel(error) => is_benign_channel_error(error),
        Ssh3ServerError::Io(error) => is_benign_io_error(error),
        _ => false,
    }
}
