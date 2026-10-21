//! Wire-format primitives of the SSH3 protocol.
//!
//! SSH3 reuses the SSH message framing on top of QUIC streams: every message
//! starts with a QUIC variable-length integer holding the message type,
//! followed by the payload of that message. Integers that are not lengths use
//! the same variable-length encoding as QUIC, and byte strings are prefixed
//! with their length encoded the same way.
//!
//! The layout of every message is fixed and byte-for-byte compatible with the
//! reference implementation (`nagual2/ssh3-go`, package `message/` and
//! `util/wire.go`). Changing the order or the type of a field breaks
//! interoperability, so the encoders and decoders of this crate are written
//! to reproduce the reference implementation exactly.
//!
//! # Modules
//!
//! | Module | Contents |
//! |---|---|
//! | [`wire`] | primitives: variable-length integers, SSH strings, booleans |
//! | [`message`] | SSH messages and channel requests |
//! | [`channel`] | channel header and the payload of forwarded channels |
//!
//! All items of the three modules are re-exported at the crate root, so
//! `use ssh3_proto::Ssh3Message;` and `use ssh3_proto::message::Ssh3Message;` are
//! equivalent.

pub mod channel;
pub mod message;
pub mod wire;

pub use channel::*;
pub use message::*;
pub use wire::*;
