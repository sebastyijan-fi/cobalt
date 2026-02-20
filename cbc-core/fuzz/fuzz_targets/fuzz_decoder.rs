//! Fuzz the decoder with a mix of random bytes and mutated valid artifacts.
//! This ensures we bypass initial checks and test deep into the validation logic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use cbc_core::{encoder, decoder, EncoderConfig, HashSuite};
use cbc_core::bootstrap::FAMILY_A_BIT;

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    // Strategy 1: Random bytes (from fuzzer directly)
    let _ = decoder::decode(data, None);

    // Strategy 2: Mutate a valid artifact
    // Use first few bytes of fuzz data to determine config
    let suite = if data[0] % 2 == 0 { HashSuite::Blake3 } else { HashSuite::Sha256 };
    let block_size = 64 + (data[1] as u32 % 1024).next_power_of_two().max(512);
    
    let config = EncoderConfig {
        hash_suite: suite,
        commitment_mode: FAMILY_A_BIT,
        block_payload_size: block_size,
        flags: 0,
        encryption_key: None,
    };

    let payload = &data[2..];
    if let Ok(artifact) = encoder::encode_random_nonce(&config, payload, &[]) {
        let mut mutated = artifact.clone();
        
        // Apply some mutations based on the rest of the 'data'
        if data.len() > 10 {
            let mut_idx = (data[3] as usize) % mutated.len();
            let mut_val = data[4];
            mutated[mut_idx] = mut_val;

            // Maybe bit flip
            let bit_idx = (data[5] as usize) % mutated.len();
            mutated[bit_idx] ^= 1 << (data[6] % 8);
        }

        let _ = decoder::decode(&mutated, None);
    }
});
