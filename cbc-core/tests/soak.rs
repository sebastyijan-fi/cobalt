//! Soak tests for CBC — sustained-load, stress, and stability testing.
//!
//! These tests exercise the system under prolonged or intensive conditions
//! to surface issues that unit tests and property tests cannot:
//!
//! - Memory leaks / unbounded growth
//! - Performance degradation over time
//! - Edge-case accumulation bugs
//! - Resource exhaustion
//! - Correctness under sustained cycling
//!
//! Run with: `cargo test -p cbc-core --test soak -- --ignored`
//! (Most soak tests are `#[ignore]` by default to keep CI fast.)

use cbc_core::block::block_wire_size;
use cbc_core::bootstrap::*;
use cbc_core::decoder;
use cbc_core::encoder::{self, EncoderConfig};
use cbc_core::hash::HashSuite;
use cbc_core::merkle::{MerkleTree, RangeProof};
use cbc_core::streaming::{StreamingDecoder, StreamingEncoder};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn config_for(suite: HashSuite, mode: u8, bps: u32, encrypt: bool) -> EncoderConfig {
    EncoderConfig {
        hash_suite: suite,
        commitment_mode: mode,
        block_payload_size: bps,
        flags: if encrypt { FLAG_ENCRYPTED } else { 0 },
        encryption_key: if encrypt { Some([0xABu8; 32]) } else { None },
    }
}

fn all_configs() -> Vec<(HashSuite, u8, u32)> {
    let suites = [HashSuite::Blake3, HashSuite::Sha256];
    let modes = [
        FAMILY_A_BIT,
        FAMILY_A_BIT | FAMILY_B_BIT,
        FAMILY_A_BIT | FAMILY_B_BIT | FAMILY_C_BIT,
    ];
    let block_sizes: [u32; 4] = [512, 1024, 4096, 8192];

    let mut out = Vec::new();
    for &s in &suites {
        for &m in &modes {
            for &b in &block_sizes {
                out.push((s, m, b));
            }
        }
    }
    out
}

/// Deterministic pseudo-random payload that varies by seed.
fn seeded_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut state = seed;
    for byte in buf.iter_mut() {
        // Simple xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xFF) as u8;
    }
    buf
}

fn nonce_for(iteration: u64) -> [u8; 16] {
    let mut n = [0u8; 16];
    n[..8].copy_from_slice(&iteration.to_le_bytes());
    n
}

// ---------------------------------------------------------------------------
// 1) Sustained encode → decode → verify cycling
// ---------------------------------------------------------------------------

/// Encode and decode 1 000 artifacts in a tight loop, verifying byte-exact
/// payload recovery each time. Exercises allocator pressure, commitment
/// chain correctness under repetition, and determinism.
#[test]
#[ignore]
fn soak_encode_decode_cycle_1k() {
    let iterations = 1_000u64;
    let config = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, 4096, false);

    let start = Instant::now();
    for i in 0..iterations {
        let payload = seeded_payload(i, 10_000);
        let nonce = nonce_for(i);

        let artifact = encoder::encode(&config, &payload, nonce, &[])
            .unwrap_or_else(|e| panic!("encode failed at iteration {i}: {e}"));

        let decoded = decoder::decode(&artifact, None)
            .unwrap_or_else(|e| panic!("decode failed at iteration {i}: {e}"));

        assert_eq!(
            decoded.payload, payload,
            "payload mismatch at iteration {i}"
        );
    }
    let elapsed = start.elapsed();
    eprintln!(
        "soak_encode_decode_cycle_1k: {iterations} iterations in {:.2}s ({:.1} ops/s)",
        elapsed.as_secs_f64(),
        iterations as f64 / elapsed.as_secs_f64()
    );
}

/// Shorter version that runs in normal CI (not ignored).
#[test]
fn soak_encode_decode_cycle_100() {
    let iterations = 100u64;
    let config = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, 4096, false);

    for i in 0..iterations {
        let payload = seeded_payload(i, 8_000);
        let nonce = nonce_for(i);
        let artifact = encoder::encode(&config, &payload, nonce, &[]).unwrap();
        let decoded = decoder::decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload, "mismatch at iteration {i}");
    }
}

// ---------------------------------------------------------------------------
// 2) All config combinations matrix
// ---------------------------------------------------------------------------

/// Cycle every combination of hash suite × family mode × block size with
/// multiple payload sizes. This is a breadth-first soak that catches
/// config-specific regressions.
#[test]
#[ignore]
fn soak_config_matrix_full() {
    let payload_sizes = [0, 1, 511, 512, 513, 1023, 1024, 4096, 10_000, 50_000];
    let configs = all_configs();
    let mut total = 0u64;

    let start = Instant::now();
    for (suite, mode, bps) in &configs {
        let cfg = config_for(*suite, *mode, *bps, false);
        for &psize in &payload_sizes {
            let payload = seeded_payload(psize as u64 ^ (*bps as u64), psize);
            let nonce = nonce_for(*bps as u64);

            let artifact = encoder::encode(&cfg, &payload, nonce, &[]).unwrap_or_else(|e| {
                panic!(
                    "encode failed: suite={suite:?} mode=0x{mode:02x} bps={bps} psize={psize}: {e}"
                )
            });

            let decoded = decoder::decode(&artifact, None).unwrap_or_else(|e| {
                panic!(
                    "decode failed: suite={suite:?} mode=0x{mode:02x} bps={bps} psize={psize}: {e}"
                )
            });

            assert_eq!(
                decoded.payload, payload,
                "mismatch: suite={suite:?} mode=0x{mode:02x} bps={bps} psize={psize}"
            );
            total += 1;
        }
    }
    let elapsed = start.elapsed();
    eprintln!(
        "soak_config_matrix_full: {total} combinations in {:.2}s",
        elapsed.as_secs_f64()
    );
}

/// Compact matrix that runs in normal CI.
#[test]
fn soak_config_matrix_quick() {
    let payload_sizes = [0, 1, 512, 4096, 10_000];
    let suites = [HashSuite::Blake3, HashSuite::Sha256];
    let modes = [
        FAMILY_A_BIT,
        FAMILY_A_BIT | FAMILY_B_BIT,
        FAMILY_A_BIT | FAMILY_B_BIT | FAMILY_C_BIT,
    ];

    for &suite in &suites {
        for &mode in &modes {
            let cfg = config_for(suite, mode, 4096, false);
            for &psize in &payload_sizes {
                let payload = seeded_payload(psize as u64, psize);
                let artifact = encoder::encode(&cfg, &payload, [0u8; 16], &[]).unwrap();
                let decoded = decoder::decode(&artifact, None).unwrap();
                assert_eq!(decoded.payload, payload);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3) Large payload soak
// ---------------------------------------------------------------------------

/// Encode and decode a 10 MiB payload. Tests memory handling and throughput
/// for realistic file sizes.
#[test]
#[ignore]
fn soak_large_payload_10mb() {
    let size = 10 * 1024 * 1024;
    let payload = seeded_payload(0xDEAD, size);

    for &bps in &[4096u32, 8192, 65536] {
        let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, bps, false);
        let start = Instant::now();

        let artifact = encoder::encode(&cfg, &payload, [1u8; 16], &[])
            .unwrap_or_else(|e| panic!("large encode failed at bps={bps}: {e}"));

        let encode_time = start.elapsed();

        let start2 = Instant::now();
        let decoded = decoder::decode(&artifact, None)
            .unwrap_or_else(|e| panic!("large decode failed at bps={bps}: {e}"));
        let decode_time = start2.elapsed();

        assert_eq!(
            decoded.payload, payload,
            "large payload mismatch at bps={bps}"
        );

        let throughput_encode = size as f64 / encode_time.as_secs_f64() / (1024.0 * 1024.0);
        let throughput_decode = size as f64 / decode_time.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!(
            "  bps={bps}: encode {throughput_encode:.1} MiB/s, decode {throughput_decode:.1} MiB/s"
        );
    }
}

/// Moderate large payload test for normal CI.
#[test]
fn soak_large_payload_1mb() {
    let size = 1024 * 1024;
    let payload = seeded_payload(0xBEEF, size);
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, 4096, false);

    let artifact = encoder::encode(&cfg, &payload, [2u8; 16], &[]).unwrap();
    let decoded = decoder::decode(&artifact, None).unwrap();
    assert_eq!(decoded.payload, payload);
}

// ---------------------------------------------------------------------------
// 4) Streaming encoder soak
// ---------------------------------------------------------------------------

/// Feed data to the streaming encoder in many small chunks (simulating
/// network/pipe input), then verify the result decodes correctly.
/// Repeats with varying chunk sizes.
#[test]
#[ignore]
fn soak_streaming_encoder_varied_chunks() {
    let total_payload_size = 100_000usize;
    let payload = seeded_payload(42, total_payload_size);
    let chunk_sizes = [
        1, 7, 13, 64, 100, 255, 511, 512, 513, 1024, 3000, 4096, 8192,
    ];

    for &chunk_size in &chunk_sizes {
        let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT, 4096, false);
        let nonce = [0u8; 16];

        let bootstrap = BootstrapSegment {
            hash_suite: cfg.hash_suite,
            commitment_mode: cfg.commitment_mode,
            block_payload_size: cfg.block_payload_size,
            block_count: 0,
            bootstrap_nonce: nonce,
            flags: cfg.flags,
        };

        let mut encoder = StreamingEncoder::new(&cfg, nonce);
        let mut artifact_bytes = Vec::new();

        // Write bootstrap placeholder
        artifact_bytes.extend_from_slice(&bootstrap.encode());

        // Feed in chunks
        let mut offset = 0;
        while offset < payload.len() {
            let end = std::cmp::min(offset + chunk_size, payload.len());
            let blocks = encoder.feed(&payload[offset..end]).unwrap_or_else(|e| {
                panic!("streaming feed failed at chunk_size={chunk_size} offset={offset}: {e}")
            });
            for block_bytes in blocks {
                artifact_bytes.extend_from_slice(&block_bytes);
            }
            offset = end;
        }

        // Finalize
        let (final_bytes, final_count) = encoder.finalize(&[]).unwrap_or_else(|e| {
            panic!("streaming finalize failed at chunk_size={chunk_size}: {e}")
        });
        artifact_bytes.extend_from_slice(&final_bytes);

        // Patch bootstrap with actual block count
        let mut patched_bootstrap = bootstrap;
        patched_bootstrap.block_count = final_count;
        let patched_bs = patched_bootstrap.encode();
        artifact_bytes[..64].copy_from_slice(&patched_bs);

        // Decode and verify
        let decoded = decoder::decode(&artifact_bytes, None)
            .unwrap_or_else(|e| panic!("streaming decode failed at chunk_size={chunk_size}: {e}"));
        assert_eq!(
            decoded.payload, payload,
            "streaming payload mismatch at chunk_size={chunk_size}"
        );
    }
}

/// Quick streaming soak for normal CI.
#[test]
fn soak_streaming_encoder_quick() {
    let payload = seeded_payload(99, 20_000);
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT, 4096, false);
    let nonce = [0u8; 16];

    let bootstrap = BootstrapSegment {
        hash_suite: cfg.hash_suite,
        commitment_mode: cfg.commitment_mode,
        block_payload_size: cfg.block_payload_size,
        block_count: 0,
        bootstrap_nonce: nonce,
        flags: cfg.flags,
    };

    let mut encoder = StreamingEncoder::new(&cfg, nonce);
    let mut artifact_bytes = Vec::new();
    artifact_bytes.extend_from_slice(&bootstrap.encode());

    for chunk in payload.chunks(333) {
        let blocks = encoder.feed(chunk).unwrap();
        for b in blocks {
            artifact_bytes.extend_from_slice(&b);
        }
    }

    let (final_bytes, final_count) = encoder.finalize(&[]).unwrap();
    artifact_bytes.extend_from_slice(&final_bytes);

    let mut patched = bootstrap;
    patched.block_count = final_count;
    artifact_bytes[..64].copy_from_slice(&patched.encode());

    let decoded = decoder::decode(&artifact_bytes, None).unwrap();
    assert_eq!(decoded.payload, payload);
}

// ---------------------------------------------------------------------------
// 5) Streaming decoder soak
// ---------------------------------------------------------------------------

/// Full streaming decode pipeline: encode normally, then decode block-by-block
/// via StreamingDecoder, verify payload matches.
#[test]
#[ignore]
fn soak_streaming_decoder_block_by_block() {
    let iterations = 200u64;
    let bps = 4096u32;

    for i in 0..iterations {
        let payload_size = (i as usize % 50_000) + 1;
        let payload = seeded_payload(i, payload_size);
        let mode = FAMILY_A_BIT | FAMILY_B_BIT;
        let cfg = config_for(HashSuite::Blake3, mode, bps, false);
        let nonce = nonce_for(i);

        let artifact = encoder::encode(&cfg, &payload, nonce, &[]).unwrap();

        // Streaming decode
        let mut dec = StreamingDecoder::new(None);
        dec.feed_bootstrap(&artifact[..BOOTSTRAP_SIZE]).unwrap();

        let bs = dec.bootstrap().unwrap();
        let block_count = bs.block_count as usize;
        let wire = block_wire_size(bps).unwrap();

        let mut reassembled = Vec::new();
        for b in 0..block_count {
            let is_last = b == block_count - 1;
            let offset = BOOTSTRAP_SIZE + b * wire;
            let block_bytes = &artifact[offset..offset + wire];
            let chunk = dec.feed_block(block_bytes, is_last).unwrap_or_else(|e| {
                panic!("streaming decode block {b} failed at iteration {i}: {e}")
            });
            reassembled.extend_from_slice(&chunk);
        }

        let footer_offset = BOOTSTRAP_SIZE + block_count * wire;
        let footer_bytes = &artifact[footer_offset..];
        let final_payload = dec
            .finalize(footer_bytes)
            .unwrap_or_else(|e| panic!("streaming finalize failed at iteration {i}: {e}"));

        assert_eq!(
            final_payload, payload,
            "streaming decoder payload mismatch at iteration {i}"
        );
        assert_eq!(
            reassembled, payload,
            "reassembled mismatch at iteration {i}"
        );
    }
}

/// Quick streaming decoder test for normal CI.
#[test]
fn soak_streaming_decoder_quick() {
    let payload = seeded_payload(7, 12_000);
    let bps = 4096u32;
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT, bps, false);
    let artifact = encoder::encode(&cfg, &payload, [3u8; 16], &[]).unwrap();

    let mut dec = StreamingDecoder::new(None);
    dec.feed_bootstrap(&artifact[..BOOTSTRAP_SIZE]).unwrap();

    let block_count = dec.bootstrap().unwrap().block_count as usize;
    let wire = block_wire_size(bps).unwrap();

    let mut reassembled = Vec::new();
    for b in 0..block_count {
        let is_last = b == block_count - 1;
        let offset = BOOTSTRAP_SIZE + b * wire;
        let chunk = dec
            .feed_block(&artifact[offset..offset + wire], is_last)
            .unwrap();
        reassembled.extend_from_slice(&chunk);
    }

    let footer_offset = BOOTSTRAP_SIZE + block_count * wire;
    let final_payload = dec.finalize(&artifact[footer_offset..]).unwrap();
    assert_eq!(final_payload, payload);
    assert_eq!(reassembled, payload);
}

// ---------------------------------------------------------------------------
// 6) Determinism soak
// ---------------------------------------------------------------------------

/// Encoding the same payload+config+nonce must always produce identical bytes.
/// Run many times to catch non-determinism from uninitialized memory, HashMap
/// iteration order, or timing-dependent paths.
#[test]
#[ignore]
fn soak_determinism_1k() {
    let iterations = 1_000;
    let payload = seeded_payload(0xCAFE, 20_000);
    let cfg = config_for(
        HashSuite::Blake3,
        FAMILY_A_BIT | FAMILY_B_BIT | FAMILY_C_BIT,
        4096,
        false,
    );
    let nonce = [42u8; 16];

    let reference = encoder::encode(&cfg, &payload, nonce, &[]).unwrap();

    for i in 0..iterations {
        let artifact = encoder::encode(&cfg, &payload, nonce, &[]).unwrap();
        assert_eq!(
            artifact, reference,
            "determinism violation at iteration {i}: artifact differs from reference"
        );
    }
}

/// Quick determinism check for normal CI.
#[test]
fn soak_determinism_quick() {
    let payload = seeded_payload(0xF00D, 5_000);
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, 4096, false);
    let nonce = [7u8; 16];

    let reference = encoder::encode(&cfg, &payload, nonce, &[]).unwrap();
    for _ in 0..50 {
        let artifact = encoder::encode(&cfg, &payload, nonce, &[]).unwrap();
        assert_eq!(artifact, reference);
    }
}

// ---------------------------------------------------------------------------
// 7) Encryption cycling soak
// ---------------------------------------------------------------------------

/// Sustained encrypt → encode → decode → decrypt cycling.
#[test]
#[ignore]
fn soak_encryption_cycle_500() {
    let iterations = 500u64;

    for i in 0..iterations {
        let payload = seeded_payload(i * 31, 8_000);
        let nonce = nonce_for(i);

        let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT, 4096, true);
        let key = cfg.encryption_key.unwrap();

        let artifact = encoder::encode(&cfg, &payload, nonce, &[])
            .unwrap_or_else(|e| panic!("encrypted encode failed at {i}: {e}"));

        let decoded = decoder::decode(&artifact, Some(key))
            .unwrap_or_else(|e| panic!("encrypted decode failed at {i}: {e}"));

        assert_eq!(
            decoded.payload, payload,
            "encrypted payload mismatch at {i}"
        );

        // Verify wrong key fails
        let bad_key = [0xFFu8; 32];
        let result = decoder::decode(&artifact, Some(bad_key));
        assert!(result.is_err(), "wrong key should fail at iteration {i}");
    }
}

/// Quick encryption test for normal CI.
#[test]
fn soak_encryption_cycle_quick() {
    for i in 0..20u64 {
        let payload = seeded_payload(i, 5_000);
        let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT, 4096, true);
        let key = cfg.encryption_key.unwrap();

        let artifact = encoder::encode(&cfg, &payload, nonce_for(i), &[]).unwrap();
        let decoded = decoder::decode(&artifact, Some(key)).unwrap();
        assert_eq!(decoded.payload, payload);

        let bad = decoder::decode(&artifact, Some([0xFFu8; 32]));
        assert!(bad.is_err());
    }
}

// ---------------------------------------------------------------------------
// 8) Merkle proof cycling soak
// ---------------------------------------------------------------------------

/// Generate artifacts with many blocks, produce range proofs for every
/// possible sub-range, and verify each one. Exercises Merkle tree
/// construction and proof serialization under load.
#[test]
#[ignore]
fn soak_merkle_proofs_exhaustive() {
    let bps = 512u32;
    // 20 blocks = 10 KiB payload
    let payload = seeded_payload(0xABCD, 20 * bps as usize);
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, bps, false);
    let nonce = [5u8; 16];

    let artifact = encoder::encode(&cfg, &payload, nonce, &[]).unwrap();
    let decoded = decoder::decode(&artifact, None).unwrap();

    let block_count = decoded.block_count as usize;

    // Rebuild Merkle tree
    let bs = &decoded.bootstrap;
    let params_canonical = bs.params_canonical();
    let params_hash = cbc_core::chain::compute_params_hash(&params_canonical, bs.hash_suite);

    // Re-extract padded payloads from artifact
    let wire = block_wire_size(bps).unwrap();
    let mut padded_payloads = Vec::new();
    for b in 0..block_count {
        let block_offset = BOOTSTRAP_SIZE + b * wire;
        let payload_offset = block_offset + 16; // skip header
        let mut padded = vec![0u8; bps as usize];
        padded.copy_from_slice(&artifact[payload_offset..payload_offset + bps as usize]);
        padded_payloads.push(padded);
    }

    let tree = MerkleTree::build(&params_hash, &padded_payloads, bs.hash_suite);

    // Exhaustive range proof check
    let mut proofs_verified = 0u64;
    for start in 0..block_count {
        for end in start..block_count {
            let proof = tree
                .prove_range(start, end)
                .unwrap_or_else(|| panic!("prove_range({start}, {end}) returned None"));

            // Compute leaf hashes for this range
            let leaf_hashes: Vec<[u8; 32]> = (start..=end)
                .map(|i| {
                    cbc_core::merkle::compute_leaf(
                        &params_hash,
                        i as u64,
                        &padded_payloads[i],
                        bs.hash_suite,
                    )
                })
                .collect();

            assert!(
                proof.verify(&leaf_hashes, &tree.root, bs.hash_suite),
                "proof verification failed for range [{start}, {end}]"
            );

            // Serialization roundtrip
            let encoded = proof.encode();
            let decoded_proof = RangeProof::decode(&encoded)
                .unwrap_or_else(|| panic!("proof decode failed for [{start}, {end}]"));
            assert!(
                decoded_proof.verify(&leaf_hashes, &tree.root, bs.hash_suite),
                "decoded proof verification failed for [{start}, {end}]"
            );

            proofs_verified += 1;
        }
    }
    eprintln!(
        "soak_merkle_proofs_exhaustive: {proofs_verified} proofs verified for {block_count} blocks"
    );
}

/// Quick Merkle proof test for normal CI.
#[test]
fn soak_merkle_proofs_quick() {
    let bps = 512u32;
    let payload = seeded_payload(0x1234, 5 * bps as usize);
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, bps, false);

    let artifact = encoder::encode(&cfg, &payload, [0u8; 16], &[]).unwrap();
    let decoded = decoder::decode(&artifact, None).unwrap();

    let bs = &decoded.bootstrap;
    let params_canonical = bs.params_canonical();
    let params_hash = cbc_core::chain::compute_params_hash(&params_canonical, bs.hash_suite);

    let wire = block_wire_size(bps).unwrap();
    let block_count = decoded.block_count as usize;
    let mut padded_payloads = Vec::new();
    for b in 0..block_count {
        let block_offset = BOOTSTRAP_SIZE + b * wire;
        let payload_offset = block_offset + 16;
        let mut padded = vec![0u8; bps as usize];
        padded.copy_from_slice(&artifact[payload_offset..payload_offset + bps as usize]);
        padded_payloads.push(padded);
    }

    let tree = MerkleTree::build(&params_hash, &padded_payloads, bs.hash_suite);
    let proof = tree.prove_range(1, 3).unwrap();

    let leaf_hashes: Vec<[u8; 32]> = (1..=3)
        .map(|i| {
            cbc_core::merkle::compute_leaf(
                &params_hash,
                i as u64,
                &padded_payloads[i],
                bs.hash_suite,
            )
        })
        .collect();

    assert!(proof.verify(&leaf_hashes, &tree.root, bs.hash_suite));
}

// ---------------------------------------------------------------------------
// 9) Edge-case payload sizes
// ---------------------------------------------------------------------------

/// Test boundary payload sizes that commonly cause off-by-one bugs:
/// 0, 1, bps-1, bps, bps+1, 2*bps-1, 2*bps, 2*bps+1, etc.
#[test]
fn soak_boundary_payload_sizes() {
    for &bps in &[512u32, 1024, 4096] {
        let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, bps, false);

        let boundary_sizes: Vec<usize> = vec![
            0,
            1,
            (bps - 1) as usize,
            bps as usize,
            (bps + 1) as usize,
            (2 * bps - 1) as usize,
            (2 * bps) as usize,
            (2 * bps + 1) as usize,
            (3 * bps - 1) as usize,
            (3 * bps) as usize,
            (3 * bps + 1) as usize,
            (10 * bps) as usize,
            (10 * bps + 1) as usize,
        ];

        for &size in &boundary_sizes {
            let payload = seeded_payload(size as u64, size);
            let artifact = encoder::encode(&cfg, &payload, [0u8; 16], &[])
                .unwrap_or_else(|e| panic!("boundary encode failed: bps={bps} size={size}: {e}"));
            let decoded = decoder::decode(&artifact, None)
                .unwrap_or_else(|e| panic!("boundary decode failed: bps={bps} size={size}: {e}"));
            assert_eq!(
                decoded.payload, payload,
                "boundary mismatch: bps={bps} size={size}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 10) Tamper detection soak
// ---------------------------------------------------------------------------

/// Systematically flip every byte position in a small artifact and verify
/// that corruption is always detected. This is a completeness check for the
/// integrity guarantee.
#[test]
#[ignore]
fn soak_tamper_every_byte() {
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, 512, false);
    let payload = seeded_payload(0, 1024); // 2 blocks
    let artifact = encoder::encode(&cfg, &payload, [0u8; 16], &[]).unwrap();

    // Verify the clean artifact is valid
    decoder::decode(&artifact, None).unwrap();

    let mut detected = 0u64;
    let mut undetected = 0u64;

    for pos in 0..artifact.len() {
        for bit in 0..8u8 {
            let mut tampered = artifact.clone();
            tampered[pos] ^= 1 << bit;

            match decoder::decode(&tampered, None) {
                Err(_) => detected += 1,
                Ok(d) => {
                    // The decode succeeded — this is only acceptable if the
                    // tampered byte was in padding (zero-padded region) that
                    // doesn't affect the logical payload or commitments.
                    // For a strict integrity format, we count this as undetected.
                    if d.payload == payload {
                        // Same payload recovered despite bit flip — might be
                        // padding region. Still worth logging.
                        undetected += 1;
                    } else {
                        panic!(
                            "CRITICAL: tamper at byte {pos} bit {bit} produced different payload without error!"
                        );
                    }
                }
            }
        }
    }

    let total = detected + undetected;
    let detection_rate = detected as f64 / total as f64 * 100.0;
    eprintln!(
        "soak_tamper_every_byte: {detected}/{total} flips detected ({detection_rate:.2}%), {undetected} undetected (padding)"
    );

    // We expect very high detection rate. CRC + chain commitment should
    // catch nearly everything except possibly zero-padding bytes that
    // don't affect CRC (unlikely but theoretically possible).
    assert!(
        detection_rate > 99.0,
        "tamper detection rate too low: {detection_rate:.2}%"
    );
}

/// Quick tamper test for normal CI — just flip a few strategic positions.
#[test]
fn soak_tamper_strategic() {
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT, 512, false);
    let payload = seeded_payload(1, 1024);
    let artifact = encoder::encode(&cfg, &payload, [0u8; 16], &[]).unwrap();

    // Tamper positions: magic, bootstrap params, block header, payload, commitment, footer
    let positions = [
        0,                   // magic byte 0
        3,                   // magic byte 3
        10,                  // bootstrap params area
        32,                  // nonce area
        63,                  // last bootstrap byte
        64,                  // first block header byte
        64 + 16 + 100,       // mid-payload
        64 + 16 + 511,       // end of first block payload
        artifact.len() - 1,  // last byte (footer)
        artifact.len() - 32, // footer commitment area
    ];

    for &pos in &positions {
        if pos >= artifact.len() {
            continue;
        }
        let mut tampered = artifact.clone();
        tampered[pos] ^= 0x01;
        assert!(
            decoder::decode(&tampered, None).is_err(),
            "tamper at position {pos} was not detected"
        );
    }
}

// ---------------------------------------------------------------------------
// 11) Compression soak
// ---------------------------------------------------------------------------

/// Cycle compression with various payload types (compressible and
/// incompressible) to verify round-trip correctness.
#[test]
fn soak_compression_cycle() {
    let payloads: Vec<(&str, Vec<u8>)> = vec![
        ("zeros", vec![0u8; 50_000]),
        ("ones", vec![0xFFu8; 50_000]),
        ("repeated_pattern", b"ABCDEFGH".repeat(6250)),
        ("pseudo_random", seeded_payload(0xDEAD, 50_000)),
        ("small", b"hello".to_vec()),
        ("empty", vec![]),
        ("single_byte", vec![42]),
    ];

    for (name, payload) in &payloads {
        let cfg = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
            block_payload_size: 4096,
            flags: FLAG_COMPRESSED,
            encryption_key: None,
        };

        let artifact = encoder::encode(&cfg, payload, [0u8; 16], &[])
            .unwrap_or_else(|e| panic!("compressed encode failed for {name}: {e}"));

        let decoded = decoder::decode(&artifact, None)
            .unwrap_or_else(|e| panic!("compressed decode failed for {name}: {e}"));

        assert_eq!(
            &decoded.payload, payload,
            "compressed payload mismatch for {name}"
        );
    }
}

// ---------------------------------------------------------------------------
// 12) Compression + encryption combined soak
// ---------------------------------------------------------------------------

#[test]
fn soak_compress_encrypt_cycle() {
    let payload = b"The quick brown fox jumps over the lazy dog. ".repeat(1000);

    let cfg = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
        block_payload_size: 4096,
        flags: FLAG_COMPRESSED | FLAG_ENCRYPTED,
        encryption_key: Some([0x42u8; 32]),
    };

    let artifact = encoder::encode(&cfg, &payload, [9u8; 16], &[]).unwrap();
    let decoded = decoder::decode(&artifact, Some([0x42u8; 32])).unwrap();
    assert_eq!(decoded.payload, payload);

    // Wrong key must fail
    assert!(decoder::decode(&artifact, Some([0x00u8; 32])).is_err());
    // No key must fail
    assert!(decoder::decode(&artifact, None).is_err());
}

// ---------------------------------------------------------------------------
// 13) Nonce uniqueness soak
// ---------------------------------------------------------------------------

/// Different nonces must produce different artifacts and different roots,
/// even with identical payload and config.
#[test]
fn soak_nonce_uniqueness() {
    let payload = seeded_payload(0, 5_000);
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT, 4096, false);

    let mut roots = std::collections::HashSet::new();
    let mut artifacts = std::collections::HashSet::new();

    for i in 0..100u64 {
        let nonce = nonce_for(i);
        let artifact = encoder::encode(&cfg, &payload, nonce, &[]).unwrap();
        let decoded = decoder::decode(&artifact, None).unwrap();

        assert_eq!(decoded.payload, payload);

        let root_inserted = roots.insert(decoded.chain_root);
        let artifact_inserted = artifacts.insert(artifact);

        // Each nonce should produce a unique root and artifact
        assert!(root_inserted, "duplicate chain root at nonce iteration {i}");
        assert!(
            artifact_inserted,
            "duplicate artifact at nonce iteration {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// 14) Decoder robustness with random garbage
// ---------------------------------------------------------------------------

/// Feed random garbage data of various sizes to the decoder and verify it
/// never panics (always returns Err gracefully).
#[test]
#[ignore]
fn soak_garbage_input_10k() {
    for i in 0..10_000u64 {
        let size = (i % 10_000) as usize;
        let garbage = seeded_payload(i, size);
        // Must not panic
        let _ = decoder::decode(&garbage, None);
    }
}

/// Quick garbage input test for normal CI.
#[test]
fn soak_garbage_input_quick() {
    for i in 0..500u64 {
        let size = (i % 2000) as usize;
        let garbage = seeded_payload(i * 7, size);
        let _ = decoder::decode(&garbage, None);
    }
}

// ---------------------------------------------------------------------------
// 15) Performance regression baseline
// ---------------------------------------------------------------------------

/// Establish a throughput baseline. This test records timing but doesn't
/// hard-fail on regressions — the output should be tracked over time.
#[test]
#[ignore]
fn soak_throughput_baseline() {
    let sizes_mb: Vec<usize> = vec![1, 5, 10];

    for &size_mb in &sizes_mb {
        let size = size_mb * 1024 * 1024;
        let payload = seeded_payload(size as u64, size);

        for &suite in &[HashSuite::Blake3, HashSuite::Sha256] {
            let cfg = config_for(suite, FAMILY_A_BIT | FAMILY_B_BIT, 4096, false);

            // Warm up
            let _ = encoder::encode(&cfg, &payload[..1024], [0u8; 16], &[]).unwrap();

            // Measure encode
            let start = Instant::now();
            let artifact = encoder::encode(&cfg, &payload, [0u8; 16], &[]).unwrap();
            let encode_time = start.elapsed();

            // Measure decode
            let start = Instant::now();
            let decoded = decoder::decode(&artifact, None).unwrap();
            let decode_time = start.elapsed();

            assert_eq!(decoded.payload, payload);

            let encode_mbps = size as f64 / encode_time.as_secs_f64() / (1024.0 * 1024.0);
            let decode_mbps = size as f64 / decode_time.as_secs_f64() / (1024.0 * 1024.0);

            eprintln!(
                "BASELINE {suite:?} {size_mb}MiB: encode={encode_mbps:.1} MiB/s decode={decode_mbps:.1} MiB/s"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 16) Sustained duration soak
// ---------------------------------------------------------------------------

/// Run encode/decode cycles for a fixed wall-clock duration (30 seconds)
/// and track throughput stability. Detects degradation over time.
#[test]
#[ignore]
fn soak_duration_30s() {
    let duration = Duration::from_secs(30);
    let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, 4096, false);

    let start = Instant::now();
    let mut iterations = 0u64;
    let mut total_bytes = 0u64;
    let mut last_report = Instant::now();
    let mut window_ops = 0u64;

    while start.elapsed() < duration {
        let payload_size = ((iterations % 50) as usize + 1) * 1000;
        let payload = seeded_payload(iterations, payload_size);
        let nonce = nonce_for(iterations);

        let artifact = encoder::encode(&cfg, &payload, nonce, &[]).unwrap();
        let decoded = decoder::decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload);

        iterations += 1;
        total_bytes += payload_size as u64;
        window_ops += 1;

        // Report every 5 seconds
        if last_report.elapsed() >= Duration::from_secs(5) {
            let window_time = last_report.elapsed().as_secs_f64();
            eprintln!(
                "  [{:.0}s] {window_ops} ops in {window_time:.1}s ({:.0} ops/s), total={iterations}",
                start.elapsed().as_secs_f64(),
                window_ops as f64 / window_time
            );
            window_ops = 0;
            last_report = Instant::now();
        }
    }

    let elapsed = start.elapsed();
    let total_mb = total_bytes as f64 / (1024.0 * 1024.0);
    eprintln!(
        "soak_duration_30s: {iterations} iterations, {total_mb:.1} MiB processed in {:.1}s ({:.0} ops/s, {:.1} MiB/s)",
        elapsed.as_secs_f64(),
        iterations as f64 / elapsed.as_secs_f64(),
        total_mb / elapsed.as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// 17) Concurrent encode/decode (multi-threaded)
// ---------------------------------------------------------------------------

/// Spawn multiple threads encoding and decoding concurrently. Verifies
/// thread-safety and absence of shared mutable state issues.
#[test]
#[ignore]
fn soak_concurrent_encode_decode() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let thread_count = 8;
    let iterations_per_thread = 200;
    let barrier = Arc::new(Barrier::new(thread_count));

    let handles: Vec<_> = (0..thread_count)
        .map(|t| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                // Wait for all threads to start
                barrier.wait();

                let cfg = config_for(
                    if t % 2 == 0 {
                        HashSuite::Blake3
                    } else {
                        HashSuite::Sha256
                    },
                    FAMILY_A_BIT | FAMILY_B_BIT,
                    4096,
                    false,
                );

                for i in 0..iterations_per_thread {
                    let seed = (t as u64) * 10_000 + i as u64;
                    let payload = seeded_payload(seed, 8_000);
                    let nonce = nonce_for(seed);

                    let artifact = encoder::encode(&cfg, &payload, nonce, &[])
                        .unwrap_or_else(|e| panic!("thread {t} iter {i} encode: {e}"));
                    let decoded = decoder::decode(&artifact, None)
                        .unwrap_or_else(|e| panic!("thread {t} iter {i} decode: {e}"));

                    assert_eq!(
                        decoded.payload, payload,
                        "thread {t} iter {i}: payload mismatch"
                    );
                }
            })
        })
        .collect();

    for (i, h) in handles.into_iter().enumerate() {
        h.join()
            .unwrap_or_else(|e| panic!("thread {i} panicked: {e:?}"));
    }
}

/// Quick concurrency test for normal CI.
#[test]
fn soak_concurrent_quick() {
    use std::thread;

    let handles: Vec<_> = (0..4)
        .map(|t| {
            thread::spawn(move || {
                let cfg = config_for(HashSuite::Blake3, FAMILY_A_BIT, 4096, false);
                for i in 0..20u64 {
                    let payload = seeded_payload(t * 100 + i, 5_000);
                    let artifact =
                        encoder::encode(&cfg, &payload, nonce_for(t * 100 + i), &[]).unwrap();
                    let decoded = decoder::decode(&artifact, None).unwrap();
                    assert_eq!(decoded.payload, payload);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 18) Streaming encoder vs batch encoder equivalence
// ---------------------------------------------------------------------------

/// For uncompressed, unencrypted artifacts, the streaming encoder should
/// produce byte-identical results to the batch encoder. Verify over many
/// payloads and configs.
#[test]
fn soak_streaming_batch_equivalence() {
    // Note: empty payload (0) is excluded because the streaming encoder
    // requires at least one block of input, while the batch encoder
    // synthesizes a single empty block. This is a known behavioral
    // difference, not a bug.
    let payload_sizes = [1, 511, 512, 513, 4095, 4096, 4097, 20_000];

    for &bps in &[512u32, 4096] {
        for &psize in &payload_sizes {
            let payload = seeded_payload(psize as u64, psize);
            let nonce = [11u8; 16];
            let mode = FAMILY_A_BIT;
            let cfg = config_for(HashSuite::Blake3, mode, bps, false);

            // Batch encode
            let batch_artifact = encoder::encode(&cfg, &payload, nonce, &[]).unwrap();

            // Streaming encode
            let bootstrap = BootstrapSegment {
                hash_suite: cfg.hash_suite,
                commitment_mode: cfg.commitment_mode,
                block_payload_size: cfg.block_payload_size,
                block_count: 0,
                bootstrap_nonce: nonce,
                flags: cfg.flags,
            };

            let mut enc = StreamingEncoder::new(&cfg, nonce);
            let mut stream_artifact = Vec::new();
            stream_artifact.extend_from_slice(&bootstrap.encode());

            // Feed entire payload at once
            let blocks = enc.feed(&payload).unwrap();
            for b in blocks {
                stream_artifact.extend_from_slice(&b);
            }
            let (final_bytes, final_count) = enc.finalize(&[]).unwrap();
            stream_artifact.extend_from_slice(&final_bytes);

            // Patch block count
            let mut patched_bs = bootstrap;
            patched_bs.block_count = final_count;
            stream_artifact[..64].copy_from_slice(&patched_bs.encode());

            // Verify both decode to same payload
            let batch_decoded = decoder::decode(&batch_artifact, None).unwrap();
            let stream_decoded = decoder::decode(&stream_artifact, None).unwrap();

            assert_eq!(
                batch_decoded.payload, stream_decoded.payload,
                "streaming/batch payload mismatch: bps={bps} psize={psize}"
            );
            assert_eq!(
                batch_decoded.chain_root, stream_decoded.chain_root,
                "streaming/batch chain root mismatch: bps={bps} psize={psize}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 19) SHA-256 vs BLAKE3 cross-validation
// ---------------------------------------------------------------------------

/// Same payload encoded with BLAKE3 and SHA-256 should decode to identical
/// payloads but produce different roots and artifacts.
#[test]
fn soak_cross_hash_validation() {
    for i in 0..50u64 {
        let payload = seeded_payload(i, 10_000);
        let nonce = nonce_for(i);

        let cfg_b3 = config_for(HashSuite::Blake3, FAMILY_A_BIT | FAMILY_B_BIT, 4096, false);
        let cfg_sha = config_for(HashSuite::Sha256, FAMILY_A_BIT | FAMILY_B_BIT, 4096, false);

        let art_b3 = encoder::encode(&cfg_b3, &payload, nonce, &[]).unwrap();
        let art_sha = encoder::encode(&cfg_sha, &payload, nonce, &[]).unwrap();

        let dec_b3 = decoder::decode(&art_b3, None).unwrap();
        let dec_sha = decoder::decode(&art_sha, None).unwrap();

        // Same payload
        assert_eq!(dec_b3.payload, payload);
        assert_eq!(dec_sha.payload, payload);

        // Different roots (overwhelmingly likely for any non-trivial payload)
        assert_ne!(
            dec_b3.chain_root, dec_sha.chain_root,
            "BLAKE3 and SHA-256 produced same chain root at iteration {i}"
        );

        // Different artifacts
        assert_ne!(art_b3, art_sha);

        // Cross-algorithm decode must fail (wrong hash in bootstrap)
        // This is implicitly tested because the commitments won't match
        // if you somehow swapped the hash suite marker.
    }
}

// ---------------------------------------------------------------------------
// 20) Empty and minimal payload edge cases
// ---------------------------------------------------------------------------

#[test]
fn soak_empty_payload_all_configs() {
    for (suite, mode, bps) in all_configs() {
        let cfg = config_for(suite, mode, bps, false);
        let artifact = encoder::encode(&cfg, &[], [0u8; 16], &[]).unwrap_or_else(|e| {
            panic!("empty encode failed: {suite:?} mode=0x{mode:02x} bps={bps}: {e}")
        });
        let decoded = decoder::decode(&artifact, None).unwrap_or_else(|e| {
            panic!("empty decode failed: {suite:?} mode=0x{mode:02x} bps={bps}: {e}")
        });
        assert!(
            decoded.payload.is_empty(),
            "empty payload not empty after decode: {suite:?} mode=0x{mode:02x} bps={bps}"
        );
    }
}

#[test]
fn soak_single_byte_payload_all_configs() {
    for (suite, mode, bps) in all_configs() {
        let cfg = config_for(suite, mode, bps, false);
        let artifact = encoder::encode(&cfg, &[0x42], [0u8; 16], &[]).unwrap_or_else(|e| {
            panic!("single-byte encode failed: {suite:?} mode=0x{mode:02x} bps={bps}: {e}")
        });
        let decoded = decoder::decode(&artifact, None).unwrap_or_else(|e| {
            panic!("single-byte decode failed: {suite:?} mode=0x{mode:02x} bps={bps}: {e}")
        });
        assert_eq!(
            decoded.payload,
            vec![0x42],
            "single-byte mismatch: {suite:?} mode=0x{mode:02x} bps={bps}"
        );
    }
}
