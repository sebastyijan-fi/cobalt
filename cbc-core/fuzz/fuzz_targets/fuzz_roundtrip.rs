//! Fuzz encode → decode roundtrip.
//! For any valid encoder config + payload, decode(encode(payload)) must == payload.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    payload: Vec<u8>,
    hash_suite_byte: u8,
    commitment_mode_byte: u8,
    block_size_exp: u8, // 9..24 maps to 512..16MiB
    nonce: [u8; 16],
}

fuzz_target!(|input: FuzzInput| {
    // Derive valid hash suite
    let hash_suite = if input.hash_suite_byte % 2 == 0 {
        cbc_core::HashSuite::Blake3
    } else {
        cbc_core::HashSuite::Sha256
    };

    // Derive valid commitment mode (bit 0 always set)
    let commitment_mode = (input.commitment_mode_byte & 0x07) | 0x01;

    // Derive valid block size (power of 2, 512..=16MiB)
    let exp = 9 + (input.block_size_exp % 16); // 9..24
    let block_payload_size = 1u32 << exp;

    // Cap payload to avoid OOM (max 1 MiB for fuzzing)
    let payload = if input.payload.len() > 1024 * 1024 {
        &input.payload[..1024 * 1024]
    } else {
        &input.payload
    };

    let config = cbc_core::EncoderConfig {
        hash_suite,
        commitment_mode,
        block_payload_size,
        flags: 0,
    };

    let artifact = cbc_core::encoder::encode(&config, payload, input.nonce, &[]);
    let decoded = cbc_core::decoder::decode(&artifact)
        .expect("decode of freshly encoded artifact must succeed");

    assert_eq!(&decoded.payload, payload, "roundtrip payload mismatch");
});
