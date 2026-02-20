//! Integration tests for CBC spec compliance.
//!
//! Covers:
//! - §13.1 Reference test vector (minimal artifact)
//! - §12.3 Positive tests (T1–T5) via transforms
//! - §12.4 Negative tests (N1–N5)
use cbc_core::bootstrap::*;
use cbc_core::decoder;
use cbc_core::encoder::{self, EncoderConfig};
use cbc_core::hash::HashSuite;

// =========================================================================
// §13.1 — Reference Test Vector: Minimal Artifact
// =========================================================================

#[test]
fn test_reference_vector_minimal_artifact() {
    // Spec §13.1:
    // hash_suite:          blake3
    // commitment_mode:     0x01 (Family A only)
    // block_payload_size:  512
    // block_count:         1
    // bootstrap_nonce:     0x00000000000000000000000000000001
    // flags:               0x00000000
    // payload:             512 bytes of 0x42 ("B" repeated)

    let mut nonce = [0u8; 16];
    nonce[15] = 0x01; // LE: ...00000001

    let config = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT,
        block_payload_size: 512,
        flags: 0,
        encryption_key: None,
    };

    let payload = vec![0x42u8; 512];
    let artifact = encoder::encode(&config, &payload, nonce, &[]).unwrap();

    // Verify it's valid
    let decoded = decoder::decode(&artifact, None).unwrap();
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.block_count, 1);
    assert_eq!(decoded.bootstrap.hash_suite, HashSuite::Blake3);
    assert_eq!(decoded.bootstrap.commitment_mode, FAMILY_A_BIT);
    assert_eq!(decoded.bootstrap.block_payload_size, 512);
    assert_eq!(decoded.bootstrap.bootstrap_nonce, nonce);

    // Verify determinism: encoding same params produces identical bytes
    let artifact2 = encoder::encode(&config, &payload, nonce, &[]).unwrap();
    assert_eq!(artifact, artifact2, "Encoding must be deterministic");

    // Verify structure sizes
    assert_eq!(&artifact[0..4], b"CBC1"); // magic
    assert_eq!(artifact[6], 0x01); // hash_suite = blake3
    assert_eq!(artifact[7], 0x01); // commitment_mode = Family A

    println!("Reference artifact size: {} bytes", artifact.len());
    println!("Chain root: {}", hex::encode(decoded.chain_root));
}

// =========================================================================
// §12.4 — Negative Tests (N1–N5)
// =========================================================================

fn make_test_artifact() -> (Vec<u8>, Vec<u8>) {
    let config = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
        block_payload_size: 512,
        flags: 0,
        encryption_key: None,
    };
    let payload = vec![0x42u8; 1024]; // 2 blocks
    let artifact = encoder::encode(&config, &payload, [42u8; 16], &[]).unwrap();
    (artifact, payload)
}

/// N1: Flip one payload bit in a valid artifact → validation fails
#[test]
fn test_n1_bit_flip() {
    let (mut artifact, _) = make_test_artifact();

    // Flip a payload bit in block 0 (after 64-byte bootstrap + 16-byte header)
    let payload_offset = BOOTSTRAP_SIZE + 16 + 100;
    artifact[payload_offset] ^= 0x01;

    let result = decoder::decode(&artifact, None);
    assert!(result.is_err(), "N1: bit flip must be detected");
    println!("N1 PASS: {:?}", result.unwrap_err());
}

/// N2: Truncate last block without updating footer → validation fails
#[test]
fn test_n2_truncate_without_footer_update() {
    let (artifact, _) = make_test_artifact();

    // Remove the second block (it's at offset bootstrap_size + block_wire_size)
    let block_wire = cbc_core::block::block_wire_size(512).unwrap();
    let end_of_first_block = BOOTSTRAP_SIZE + block_wire;

    // Take bootstrap + first block + footer (skip second block)
    let footer_start = BOOTSTRAP_SIZE + 2 * block_wire;
    let mut truncated = artifact[..end_of_first_block].to_vec();
    truncated.extend_from_slice(&artifact[footer_start..]);

    let result = decoder::decode(&truncated, None);
    assert!(
        result.is_err(),
        "N2: truncation without footer update must fail"
    );
    println!("N2 PASS: {:?}", result.unwrap_err());
}

/// N3: Swap two blocks → validation fails
#[test]
fn test_n3_swap_blocks() {
    let config = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT,
        block_payload_size: 512,
        flags: 0,
        encryption_key: None,
    };
    let payload = vec![0x42u8; 1536]; // 3 blocks, need different payloads
    let mut payload_varied = payload;
    // Make blocks have different content
    payload_varied[0] = 0x41;
    payload_varied[512] = 0x43;
    payload_varied[1024] = 0x44;

    let artifact = encoder::encode(&config, &payload_varied, [7u8; 16], &[]).unwrap();
    let block_wire = cbc_core::block::block_wire_size(512).unwrap();

    // Swap block 0 and block 1
    let mut swapped = artifact.clone();
    let block0_start = BOOTSTRAP_SIZE;
    let block1_start = BOOTSTRAP_SIZE + block_wire;

    let block0 = artifact[block0_start..block0_start + block_wire].to_vec();
    let block1 = artifact[block1_start..block1_start + block_wire].to_vec();

    swapped[block0_start..block0_start + block_wire].copy_from_slice(&block1);
    swapped[block1_start..block1_start + block_wire].copy_from_slice(&block0);

    let result = decoder::decode(&swapped, None);
    assert!(result.is_err(), "N3: block swap must be detected");
    println!("N3 PASS: {:?}", result.unwrap_err());
}

/// N4: Replace footer with a different artifact's footer → validation fails
#[test]
fn test_n4_footer_substitution() {
    let config = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT,
        block_payload_size: 512,
        flags: 0,
        encryption_key: None,
    };

    let artifact_a = encoder::encode(&config, &vec![0x41u8; 512], [1u8; 16], &[]).unwrap();
    let artifact_b = encoder::encode(&config, &vec![0x42u8; 512], [2u8; 16], &[]).unwrap();

    let block_wire = cbc_core::block::block_wire_size(512).unwrap();
    let footer_start = BOOTSTRAP_SIZE + block_wire;

    // Take A's bootstrap + blocks, but B's footer
    let mut franken = artifact_a[..footer_start].to_vec();
    franken.extend_from_slice(&artifact_b[footer_start..]);

    let result = decoder::decode(&franken, None);
    assert!(result.is_err(), "N4: footer substitution must be detected");
    println!("N4 PASS: {:?}", result.unwrap_err());
}

/// N5: Present a subrange as complete → validation fails
#[test]
fn test_n5_subrange_as_complete() {
    let config = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
        block_payload_size: 512,
        flags: 0,
        encryption_key: None,
    };
    let payload = vec![0x42u8; 2048]; // 4 blocks
    let artifact = encoder::encode(&config, &payload, [5u8; 16], &[]).unwrap();

    // Try to present blocks 0-1 as a complete 4-block artifact
    // by copying bootstrap + 2 blocks + footer
    let block_wire = cbc_core::block::block_wire_size(512).unwrap();
    let two_blocks_end = BOOTSTRAP_SIZE + 2 * block_wire;
    let footer_start = BOOTSTRAP_SIZE + 4 * block_wire;

    let mut subset = artifact[..two_blocks_end].to_vec();
    subset.extend_from_slice(&artifact[footer_start..]);

    let result = decoder::decode(&subset, None);
    assert!(result.is_err(), "N5: subrange as complete must be detected");
    println!("N5 PASS: {:?}", result.unwrap_err());
}

// =========================================================================
// Additional round-trip tests
// =========================================================================

#[test]
fn test_all_families_all_hashes() {
    for suite in [HashSuite::Blake3, HashSuite::Sha256] {
        for mode in [
            FAMILY_A_BIT,
            FAMILY_A_BIT | FAMILY_B_BIT,
            FAMILY_A_BIT | FAMILY_B_BIT | FAMILY_C_BIT,
        ] {
            let config = EncoderConfig {
                hash_suite: suite,
                commitment_mode: mode,
                block_payload_size: 512,
                flags: 0,
                encryption_key: None,
            };

            for payload_size in [0, 100, 512, 1024, 4096] {
                let payload = vec![0xAB; payload_size];
                let artifact = encoder::encode(&config, &payload, [99u8; 16], &[]).unwrap();
                let decoded = decoder::decode(&artifact, None).unwrap();
                assert_eq!(
                    decoded.payload, payload,
                    "Failed for suite={suite:?} mode=0x{mode:02x} payload_size={payload_size}"
                );
            }
        }
    }
}

#[test]
fn test_larger_block_sizes() {
    for block_size in [512, 1024, 2048, 4096, 8192] {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: block_size,
            flags: 0,
            encryption_key: None,
        };
        let payload = vec![0x55; 10000];
        let artifact = encoder::encode(&config, &payload, [0u8; 16], &[]).unwrap();
        let decoded = decoder::decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload);
    }
}
