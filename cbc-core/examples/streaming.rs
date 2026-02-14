//! Example: Low-Memory Streaming Processing
//!
//! This example shows how to use the `StreamingEncoder` and `StreamingDecoder`
//! to process data in constant memory. This is essential for large files
//! that cannot fit in RAM.

use cbc_core::bootstrap::FAMILY_A_BIT;
use cbc_core::streaming::{StreamingDecoder, StreamingEncoder};
use cbc_core::{EncoderConfig, HashSuite};

fn main() {
    let chunk_1 = b"This is the first chunk of a very large file. ";
    let chunk_2 = b"And this is the second chunk of that same file. ";
    let chunk_3 = b"Processing this in chunks saves memory!";

    // 1. Configure for streaming
    let config = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT,
        block_payload_size: 512, // 512 bytes is the minimum allowed
        flags: 0,
        encryption_key: None,
    };

    println!("--- Step 1: Streaming Encoding ---");
    let nonce = [0u8; 16]; // Use a fixed nonce for deterministic output
    let mut encoder = StreamingEncoder::new(&config, nonce);

    // Emulating writing chunks
    encoder.write_payload(chunk_1).unwrap();
    encoder.write_payload(chunk_2).unwrap();
    encoder.write_payload(chunk_3).unwrap();
    
    // Add more data to ensure we actually have multiple 512-byte blocks
    let large_data = vec![0x42u8; 1000];
    encoder.write_payload(&large_data).unwrap();

    let artifact = encoder.finalize(&[]).unwrap();
    println!("Encoded {} bytes into artifact of {} bytes", 
             chunk_1.len() + chunk_2.len() + chunk_3.len() + large_data.len(), 
             artifact.len());

    // 2. Streaming Decoding
    println!("\n--- Step 2: Streaming Decoding ---");
    let mut decoder = StreamingDecoder::new(None);
    
    // In a real scenario, we would read the bootstrap header (first 64 bytes) first
    let bootstrap_bytes = &artifact[..64];
    decoder.feed_bootstrap(bootstrap_bytes).unwrap();

    // Now feed blocks one by one
    // Blocks 0..N-1 are full size: 16 (header) + 512 (payload) + 32 (commitment) = 560
    let full_block_size = 16 + 512 + 32;
    let mut offset = 64;
    let mut recovered_payload = Vec::new();

    let block_count = decoder.bootstrap().unwrap().block_count;
    println!("Total blocks to decode: {}", block_count);

    for i in 0..block_count {
        let is_last = i == block_count - 1;
        
        let current_block_size = full_block_size;
        let block_bytes = &artifact[offset..offset + current_block_size];
        
        // feed_block returns the plaintext chunk of this specific block
        let chunk = decoder.feed_block(block_bytes, is_last).unwrap();
        recovered_payload.extend_from_slice(&chunk);
        
        offset += current_block_size;
        println!("  Decoded block {} at offset {}, size {}", i, offset, current_block_size);
    }

    // Finally, feed the footer
    let footer_bytes = &artifact[offset..];
    let full_payload = decoder.finalize(footer_bytes).unwrap();

    println!("\n✓ Recovered payload length: {} bytes", full_payload.len());
    println!("Payload string: {}", String::from_utf8_lossy(&full_payload));
    
    let expected = [chunk_1.to_vec(), chunk_2.to_vec(), chunk_3.to_vec(), large_data].concat();
    assert_eq!(full_payload, expected);
}
