//! Fuzz the bootstrap segment parser with random 64-byte inputs.
//! Must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use cbc_core::bootstrap::{BootstrapSegment, BOOTSTRAP_SIZE};

fuzz_target!(|data: &[u8]| {
    // Only try if we have enough bytes
    if data.len() >= BOOTSTRAP_SIZE {
        let mut buf = [0u8; BOOTSTRAP_SIZE];
        buf.copy_from_slice(&data[..BOOTSTRAP_SIZE]);
        let _ = BootstrapSegment::decode(&buf);
    }
});
