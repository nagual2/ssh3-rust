//! Conversation and channel runtime of SSH3.
//!
//! This crate implements the stateful part of SSH3 that both peers share: a
//! [`Ssh3Conversation`] owns the channels of one SSH3 session, each [`Ssh3Channel`]
//! multiplexes the SSH messages and the datagrams that flow over it, and the
//! [`transport`] traits abstract away the QUIC streams the messages travel on.
//!
//! The crate is transport agnostic: it knows nothing about QUIC, HTTP/3 or
//! TLS. A transport only has to provide a byte stream for the control
//! channel, one stream per channel, and a way to send datagrams.
//!
//! # Modules
//!
//! | Module | Contents |
//! |---|---|
//! | [`compress`] | the codec of the compressed channel data frames |
//! | [`conversation`] | the conversation and the registry of its channels |
//! | [`channel`] | a single channel and the framing of its messages |
//! | [`queue`] | the accept queue and the datagram queue |
//! | [`transport`] | the stream and datagram traits a transport implements |
//!
//! The items of the five modules are re-exported at the crate root.

pub mod channel;
pub mod compress;
pub mod conversation;
pub mod queue;
pub mod transport;

pub use channel::{
    MAX_MAX_PACKET_SIZE, MIN_MAX_PACKET_SIZE, Ssh3AcceptedChannel, Ssh3Channel, Ssh3ChannelError,
    Ssh3ChannelInfo, Ssh3ChannelOpenFailure, Ssh3MessageOnNonConfirmedChannel,
    Ssh3SentDatagramOnNonDatagramChannel, clamp_local_max_packet_size, clamp_peer_max_packet_size,
};
pub use compress::{
    ALGORITHM_DEFLATE, ALGORITHM_LZ4, ALGORITHM_NONE, ALGORITHM_ZSTD, CompressError,
    negotiate_with_version_string, parse_version_capability,
};
pub use conversation::{
    Ssh3Conversation, Ssh3ConversationDatagramSender, Ssh3ConversationError, Ssh3ConversationId,
};
pub use queue::{Ssh3AcceptQueue, Ssh3DatagramQueue};
pub use transport::{Ssh3DatagramSender, Ssh3ReceiveStream, Ssh3SendStream};
