//! Fuzz target of the parser of the channel requests.
//!
//! A peer may ask for any request on a channel: the parser must refuse the
//! ones it does not know with an error and must never panic, and the payload
//! of a request that is read must survive a round trip through the encoder.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh3_proto::Ssh3Message;

fuzz_target!(|data: &[u8]| {
    let mut reader = data;
    let Ok(Ssh3Message::ChannelRequest(request)) = Ssh3Message::parse(&mut reader) else {
        return;
    };

    // The encoder and the parser of the Rust implementation agree on the
    // layout of every request, so a request that is read is encoded back
    // into the request itself.
    let message = Ssh3Message::ChannelRequest(request.clone());
    let encoded = message.to_vec();
    assert_eq!(encoded.len(), message.encoded_len());

    let mut round_trip = std::io::Cursor::new(encoded);
    match Ssh3Message::parse(&mut round_trip) {
        Ok(Ssh3Message::ChannelRequest(decoded)) => {
            assert_eq!(decoded, request);
        }
        Ok(other) => panic!("the round trip returned another message: {other:?}"),
        Err(err) => panic!("the round trip failed: {err:?}"),
    }
});
