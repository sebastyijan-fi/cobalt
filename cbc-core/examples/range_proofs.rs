//! Example: Selective Disclosure with Merkle Range Proofs
//!
//! This example shows how to encode a file into Cobalt, generate a Merkle
//! range proof for a specific subset of blocks, and verify that proof
//! against the public root commitment.

use cbc_core::bootstrap::{FAMILY_A_BIT, FAMILY_B_BIT};
use cbc_core::{decoder, encoder, EncoderConfig, HashSuite, merkle::MerkleTree};
use cbc_core::chain;

fn main() {
    let payload = vec![0u8; 2000]; // 2000 bytes ensures ~4 blocks with 512-byte size

    // 1. Configure for Family B (Merkle Tree enabled)
    let config = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT, // Family B enables Merkle range proofs; Family A is mandatory
        block_payload_size: 512,        // 512 bytes is the minimum allowed block size
        flags: 0,
        encryption_key: None,
    };

    println!("--- Step 1: Encoding payload into Cobalt ---");
    let artifact = encoder::encode_random_nonce(&config, &payload, &[]).unwrap();
    println!("Artifact size: {} bytes", artifact.len());

    // 2. Decode to access the Merkle Root
    println!("\n--- Step 2: Extracting Merkle Root ---");
    let decoded = decoder::decode(&artifact, None).unwrap();
    let root = decoded.merkle_root.expect("Merkle Root missing (Family B not enabled)");
    println!("Merkle Root: {}", hex::encode(root));
    println!("Total blocks: {}", decoded.block_count);

    // 3. To generate a proof, we need the padded payloads (internal library logic simulation)
    println!("\n--- Step 3: Generating range proof for blocks 1 to 2 ---");
    let bps = config.block_payload_size as usize;
    let padded_payloads: Vec<Vec<u8>> = payload.chunks(bps).map(|chunk| {
        let mut p = chunk.to_vec();
        p.resize(bps, 0);
        p
    }).collect();

    let params_canonical = decoded.bootstrap.params_canonical();
    let params_hash = chain::compute_params_hash(&params_canonical, config.hash_suite);

    let tree = MerkleTree::build(&params_hash, &padded_payloads, config.hash_suite);
    let proof = tree.prove_range(1, 2).unwrap();
    let proof_bytes = proof.encode();
    println!("Proof size: {} bytes", proof_bytes.len());

    // 4. Verification (Simulating a recipient who only has the root)
    println!("\n--- Step 4: Verifying the range proof ---");
    let leaf_hashes: Vec<[u8; 32]> = padded_payloads[1..=2]
        .iter()
        .enumerate()
        .map(|(i, p)| {
            cbc_core::merkle::compute_leaf(&params_hash, (i + 1) as u64, p, config.hash_suite)
        })
        .collect();

    if proof.verify(&leaf_hashes, &root, config.hash_suite) {
        println!("✓ Range proof verified successfully!");
    } else {
        println!("✗ Range proof verification failed!");
        std::process::exit(1);
    }
}
