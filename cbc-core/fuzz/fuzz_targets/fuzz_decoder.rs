//! Fuzz the decoder with completely random bytes.
//! This must NEVER panic — every input must produce Ok or Err.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic. Ok or Err, both are fine.
    let _ = cbc_core::decoder::decode(data);
});
