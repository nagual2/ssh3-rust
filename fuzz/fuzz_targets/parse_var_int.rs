//! Fuzz target of the parser of the variable-length integers.
//!
//! The parser of the reference implementation (`nagual2/ssh3-go`,
//! `util/fuzz_test.go`, `FuzzReadVarInt`) must never panic: any byte stream
//! must come back as a value or as an error.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh3_proto::{read_var_int, MAX_VARINT};

fuzz_target!(|data: &[u8]| {
    let mut reader = data;
    if let Ok(value) = read_var_int(&mut reader) {
        // A value that is read must fit into 62 bits.
        assert!(value <= MAX_VARINT);
    }
});
