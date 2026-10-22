//! Fuzz target of the parser of the length-prefixed byte strings.
//!
//! The parser of the reference implementation (`nagual2/ssh3-go`,
//! `util/fuzz_test.go`, `FuzzParseSSHString`) must never panic and must never
//! allocate more than the limit of the length of a string: the length is
//! chosen by the peer, so a handful of bytes would otherwise make the
//! process allocate an arbitrary buffer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh3_proto::{read_ssh_bytes, MAX_SSH_STRING_LEN};

fuzz_target!(|data: &[u8]| {
    let mut reader = data;
    if let Ok(payload) = read_ssh_bytes(&mut reader) {
        // A string that is read must fit into the limit of the protocol.
        assert!(payload.len() as u64 <= MAX_SSH_STRING_LEN);
    }
});
