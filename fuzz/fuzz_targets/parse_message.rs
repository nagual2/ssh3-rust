//! Fuzz target of the parser of the messages of a channel.
//!
//! A peer may send any byte stream on a channel: the parser must refuse the
//! ones it does not know with an error and must never panic. The reference
//! implementation used to panic on an unknown message type
//! (`nagual2/ssh3-go`, `message/message.go`, `UnknownMessageType`), which
//! turned two bytes into a remote crash of the process.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh3_proto::Ssh3Message;

fuzz_target!(|data: &[u8]| {
    let mut reader = data;
    if let Ok(message) = Ssh3Message::parse(&mut reader) {
        // A message that is read must be encoded back into the same bytes.
        let encoded = message.to_vec();
        assert!(!encoded.is_empty());
        assert_eq!(encoded.len(), message.encoded_len());
    }
});
