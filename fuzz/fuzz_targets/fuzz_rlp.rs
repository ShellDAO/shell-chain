//! Fuzz target: RLP decode of block headers and transactions.
//!
//! Attempts to decode arbitrary bytes as:
//!   1. A `BlockHeader` via RLP
//!   2. A `SignedTransaction` via RLP
//!
//! Neither should panic; both must return an error on invalid input.

#![no_main]

use alloy_rlp::Decodable;
use libfuzzer_sys::fuzz_target;
use shell_core::{BlockHeader, SignedTransaction};

fuzz_target!(|data: &[u8]| {
    // BlockHeader decode — must not panic on any input.
    let _ = BlockHeader::decode(&mut &data[..]);

    // SignedTransaction decode — must not panic on any input.
    let _ = SignedTransaction::decode(&mut &data[..]);
});
