/// Integration tests for Merkle range proofs (§4.2 / G4 selective disclosure).
use cbc_core::bootstrap::*;
use cbc_core::chain;
use cbc_core::encoder::{self, EncoderConfig};
use cbc_core::hash::HashSuite;
use cbc_core::merkle::{self, MerkleTree};

fn make_payloads(count: usize) -> Vec<Vec<u8>> {
    (0..count).map(|i| vec![(i % 256) as u8; 512]).collect()
}

fn build_tree(payloads: &[Vec<u8>]) -> (MerkleTree, [u8; 32]) {
    let params = [0xAAu8; 32];
    let tree = MerkleTree::build(&params, payloads, HashSuite::Blake3);
    let root = tree.root;
    (tree, root)
}

fn leaf_hashes(payloads: &[Vec<u8>], range: std::ops::RangeInclusive<usize>) -> Vec<[u8; 32]> {
    let params = [0xAAu8; 32];
    range
        .map(|i| merkle::compute_leaf(&params, i as u64, &payloads[i], HashSuite::Blake3))
        .collect()
}

// ==========================================
// Single block proof
// ==========================================

#[test]
fn test_prove_single_block() {
    let payloads = make_payloads(8);
    let (tree, root) = build_tree(&payloads);

    // Prove block 3 alone
    let proof = tree.prove_range(3, 3).unwrap();
    let leaves = leaf_hashes(&payloads, 3..=3);

    assert!(
        proof.verify(&leaves, &root, HashSuite::Blake3),
        "Single block proof must verify"
    );
}

// ==========================================
// Range proof — middle blocks
// ==========================================

#[test]
fn test_prove_range_middle() {
    let payloads = make_payloads(8);
    let (tree, root) = build_tree(&payloads);

    // Prove blocks 2..=5
    let proof = tree.prove_range(2, 5).unwrap();
    let leaves = leaf_hashes(&payloads, 2..=5);

    assert!(
        proof.verify(&leaves, &root, HashSuite::Blake3),
        "Middle range proof must verify"
    );
}

// ==========================================
// Range proof — entire tree
// ==========================================

#[test]
fn test_prove_full_range() {
    let payloads = make_payloads(8);
    let (tree, root) = build_tree(&payloads);

    let proof = tree.prove_range(0, 7).unwrap();
    let leaves = leaf_hashes(&payloads, 0..=7);

    assert!(
        proof.verify(&leaves, &root, HashSuite::Blake3),
        "Full range proof must verify with zero proof nodes"
    );

    // Full range needs no additional siblings
    assert_eq!(
        proof.proof_nodes.len(),
        0,
        "Full range proof should have no proof nodes"
    );
}

// ==========================================
// Range proof — first blocks
// ==========================================

#[test]
fn test_prove_range_prefix() {
    let payloads = make_payloads(8);
    let (tree, root) = build_tree(&payloads);

    let proof = tree.prove_range(0, 2).unwrap();
    let leaves = leaf_hashes(&payloads, 0..=2);

    assert!(proof.verify(&leaves, &root, HashSuite::Blake3));
}

// ==========================================
// Range proof — last blocks
// ==========================================

#[test]
fn test_prove_range_suffix() {
    let payloads = make_payloads(8);
    let (tree, root) = build_tree(&payloads);

    let proof = tree.prove_range(6, 7).unwrap();
    let leaves = leaf_hashes(&payloads, 6..=7);

    assert!(proof.verify(&leaves, &root, HashSuite::Blake3));
}

// ==========================================
// Tampered block in range proof fails
// ==========================================

#[test]
fn test_tampered_leaf_fails() {
    let payloads = make_payloads(8);
    let (tree, root) = build_tree(&payloads);

    let proof = tree.prove_range(2, 5).unwrap();
    let mut leaves = leaf_hashes(&payloads, 2..=5);

    // Tamper with one leaf
    leaves[1][0] ^= 0xFF;

    assert!(
        !proof.verify(&leaves, &root, HashSuite::Blake3),
        "Tampered leaf must fail verification"
    );
}

// ==========================================
// Wrong number of leaves fails
// ==========================================

#[test]
fn test_wrong_leaf_count_fails() {
    let payloads = make_payloads(8);
    let (tree, root) = build_tree(&payloads);

    let proof = tree.prove_range(2, 5).unwrap();
    let leaves = leaf_hashes(&payloads, 2..=4); // Only 3, expect 4

    assert!(
        !proof.verify(&leaves, &root, HashSuite::Blake3),
        "Wrong leaf count must fail"
    );
}

// ==========================================
// Proof serialization roundtrip
// ==========================================

#[test]
fn test_range_proof_encode_decode() {
    let payloads = make_payloads(8);
    let (tree, root) = build_tree(&payloads);

    let proof = tree.prove_range(2, 5).unwrap();
    let encoded = proof.encode();
    let decoded = merkle::RangeProof::decode(&encoded).unwrap();

    assert_eq!(decoded.start, proof.start);
    assert_eq!(decoded.end, proof.end);
    assert_eq!(decoded.leaf_count, proof.leaf_count);
    assert_eq!(decoded.proof_nodes.len(), proof.proof_nodes.len());

    // Decoded proof must still verify
    let leaves = leaf_hashes(&payloads, 2..=5);
    assert!(
        decoded.verify(&leaves, &root, HashSuite::Blake3),
        "Decoded proof must verify"
    );
}

// ==========================================
// Odd-numbered leaf count
// ==========================================

#[test]
fn test_prove_range_odd_leaf_count() {
    let payloads = make_payloads(7); // Odd number
    let (tree, root) = build_tree(&payloads);

    // Prove blocks 1..=4
    let proof = tree.prove_range(1, 4).unwrap();
    let leaves = leaf_hashes(&payloads, 1..=4);

    assert!(
        proof.verify(&leaves, &root, HashSuite::Blake3),
        "Range proof with odd leaf count must verify"
    );
}

// ==========================================
// End-to-end: encode artifact → extract range proof → verify
// ==========================================

#[test]
fn test_end_to_end_selective_disclosure() {
    let config = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
        block_payload_size: 512,
        flags: 0,
        encryption_key: None,
    };
    let payload = (0..4096u32).map(|i| (i % 256) as u8).collect::<Vec<_>>();
    let artifact = encoder::encode(&config, &payload, [42u8; 16], &[]).unwrap();
    let decoded = cbc_core::decoder::decode(&artifact, None).unwrap();

    // Build tree from decoded blocks
    let block_count = decoded.block_count as usize;
    let params_canonical = decoded.bootstrap.params_canonical();
    let params_hash = chain::compute_params_hash(&params_canonical, HashSuite::Blake3);

    let padded_payloads: Vec<Vec<u8>> = (0..block_count)
        .map(|i| {
            let start = i * 512;
            let end = ((i + 1) * 512).min(payload.len());
            let mut block_payload = vec![0u8; 512];
            if start < payload.len() {
                let actual_len = end - start;
                block_payload[..actual_len].copy_from_slice(&payload[start..end]);
            }
            block_payload
        })
        .collect();

    let tree = MerkleTree::build(&params_hash, &padded_payloads, HashSuite::Blake3);

    // Verify our tree root matches the artifact's
    assert_eq!(tree.root, decoded.merkle_root.unwrap());

    // Generate range proof for blocks 2..=5
    let proof = tree.prove_range(2, 5).unwrap();
    let leaves: Vec<[u8; 32]> = (2..=5)
        .map(|i| {
            merkle::compute_leaf(
                &params_hash,
                i as u64,
                &padded_payloads[i],
                HashSuite::Blake3,
            )
        })
        .collect();

    // A third party with only the Merkle root can verify these blocks
    assert!(
        proof.verify(&leaves, &decoded.merkle_root.unwrap(), HashSuite::Blake3),
        "End-to-end selective disclosure proof must verify"
    );
}
