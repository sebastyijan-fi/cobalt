/// Integration tests for CBC transforms — §12.3 positive tests (T1–T5).
///
/// Each test validates:
/// 1. Source artifact is valid
/// 2. Transform produces a new valid artifact
/// 3. Derived artifact has a different root
/// 4. Derived payload matches expected content
/// 5. Receipt is valid and links source → derived

use cbc_core::bootstrap::*;
use cbc_core::decoder;
use cbc_core::encoder::{self, EncoderConfig};
use cbc_core::hash::HashSuite;
use cbc_transform::receipt::{self, TransformType};

fn make_source(payload_size: usize) -> (Vec<u8>, Vec<u8>) {
    let config = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
        block_payload_size: 512,
        flags: 0,
    };
    let payload = (0..payload_size).map(|i| (i % 256) as u8).collect::<Vec<_>>();
    let artifact = encoder::encode(&config, &payload, [42u8; 16], &[]);
    (artifact, payload)
}

fn signing_key() -> cbc_transform::SigningKey {
    cbc_transform::receipt::generate_ed25519_key()
}

/// T1: Truncation — keep first N blocks from artifact
#[test]
fn test_t1_truncation() {
    let (source, _payload) = make_source(2048); // 4 blocks @ 512
    let source_decoded = decoder::decode(&source).unwrap();
    assert_eq!(source_decoded.block_count, 4);

    let key = signing_key();
    let (derived, receipt) = cbc_transform::truncate(&source, 2, &key).unwrap();

    // Derived is valid
    let derived_decoded = decoder::decode(&derived).unwrap();
    assert_eq!(derived_decoded.block_count, 2);

    // Different root
    assert_ne!(source_decoded.chain_root, derived_decoded.chain_root,
        "T1: derived must have different root");

    // Payload is the first 1024 bytes
    assert_eq!(derived_decoded.payload.len(), 1024);

    // Verify receipt
    assert_eq!(receipt.transform_type, TransformType::Truncation);
    assert_eq!(receipt.source_root, source_decoded.chain_root);
    assert_eq!(receipt.derived_root, derived_decoded.chain_root);
    receipt::verify_receipt(&receipt, HashSuite::Blake3).unwrap();
}

/// T2: Rechunk — change block payload size
#[test]
fn test_t2_rechunk() {
    let (source, payload) = make_source(2048); // 4 blocks @ 512
    let source_decoded = decoder::decode(&source).unwrap();

    let key = signing_key();
    let (derived, receipt) = cbc_transform::rechunk(&source, 1024, &key).unwrap();

    let derived_decoded = decoder::decode(&derived).unwrap();
    assert_eq!(derived_decoded.block_count, 2); // 2048 / 1024 = 2
    assert_eq!(derived_decoded.bootstrap.block_payload_size, 1024);

    // Same payload content
    assert_eq!(derived_decoded.payload, payload);

    // Different root
    assert_ne!(source_decoded.chain_root, derived_decoded.chain_root);

    // Valid receipt
    assert_eq!(receipt.transform_type, TransformType::Rechunk);
    receipt::verify_receipt(&receipt, HashSuite::Blake3).unwrap();
}

/// T3: Recompression — identity transform (no actual compression, validates structure)
#[test]
fn test_t3_recompress() {
    let (source, payload) = make_source(1024);
    let source_decoded = decoder::decode(&source).unwrap();

    let key = signing_key();
    let (derived, receipt) = cbc_transform::recompress(&source, &key).unwrap();

    let derived_decoded = decoder::decode(&derived).unwrap();
    assert_eq!(derived_decoded.payload, payload);

    // Different root (new nonce)
    assert_ne!(source_decoded.chain_root, derived_decoded.chain_root);

    // Valid receipt
    assert_eq!(receipt.transform_type, TransformType::Recompress);
    receipt::verify_receipt(&receipt, HashSuite::Blake3).unwrap();
}

/// T4: Concatenation — merge multiple artifacts
#[test]
fn test_t4_concatenation() {
    let (source_a, payload_a) = make_source(512);
    let (source_b, payload_b) = make_source(1024);

    let key = signing_key();
    let (derived, receipts) = cbc_transform::concatenate(
        &[&source_a, &source_b], &key
    ).unwrap();

    let derived_decoded = decoder::decode(&derived).unwrap();

    // Payload is concatenation
    let mut expected = payload_a.clone();
    expected.extend_from_slice(&payload_b);
    assert_eq!(derived_decoded.payload, expected);

    // Receipts — one per source
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].transform_type, TransformType::Concatenate);
    assert_eq!(receipts[1].transform_type, TransformType::Concatenate);

    for r in &receipts {
        receipt::verify_receipt(r, HashSuite::Blake3).unwrap();
    }
}

/// T5: Subrange extraction — extract blocks [start..end]
#[test]
fn test_t5_subrange_extract() {
    let (source, payload) = make_source(2048); // 4 blocks @ 512
    let source_decoded = decoder::decode(&source).unwrap();
    assert_eq!(source_decoded.block_count, 4);

    let key = signing_key();
    let (derived, receipt) = cbc_transform::subrange_extract(&source, 1, 2, &key).unwrap();

    let derived_decoded = decoder::decode(&derived).unwrap();
    assert_eq!(derived_decoded.block_count, 2);

    // Payload is blocks 1-2 from source (bytes 512..1536)
    assert_eq!(derived_decoded.payload, &payload[512..1536]);

    // Different root
    assert_ne!(source_decoded.chain_root, derived_decoded.chain_root);

    // Valid receipt
    assert_eq!(receipt.transform_type, TransformType::SubrangeExtract);
    receipt::verify_receipt(&receipt, HashSuite::Blake3).unwrap();
}

// =========================================================================
// End-to-end provenance chain test
// =========================================================================

/// Test receipt chaining: A → B → C with verifiable lineage
#[test]
fn test_receipt_chain_provenance() {
    let (source_a, _) = make_source(2048); // 4 blocks
    let a_decoded = decoder::decode(&source_a).unwrap();

    let key = signing_key();

    // A → B: subrange extract blocks 0..2
    let (artifact_b, receipt_ab) =
        cbc_transform::subrange_extract(&source_a, 0, 2, &key).unwrap();
    let b_decoded = decoder::decode(&artifact_b).unwrap();

    // B → C: rechunk to 1024-byte blocks
    let (artifact_c, receipt_bc) =
        cbc_transform::rechunk(&artifact_b, 1024, &key).unwrap();
    let c_decoded = decoder::decode(&artifact_c).unwrap();

    // Verify lineage: C → B → A
    assert_eq!(receipt_bc.source_root, b_decoded.chain_root);
    assert_eq!(receipt_bc.derived_root, c_decoded.chain_root);
    assert_eq!(receipt_ab.source_root, a_decoded.chain_root);
    assert_eq!(receipt_ab.derived_root, b_decoded.chain_root);

    // All receipts valid
    receipt::verify_receipt(&receipt_ab, HashSuite::Blake3).unwrap();
    receipt::verify_receipt(&receipt_bc, HashSuite::Blake3).unwrap();

    // Follow chain: receipt_bc.source_root == receipt_ab.derived_root
    assert_eq!(receipt_bc.source_root, receipt_ab.derived_root,
        "Receipt chain must link B → A through source/derived roots");
}
