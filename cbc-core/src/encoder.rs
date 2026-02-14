/// CBC Encoder — produces a complete CBC artifact from raw payload bytes.

use crate::block::Block;
use crate::bootstrap::{BootstrapSegment, FAMILY_A_BIT, FAMILY_B_BIT, FAMILY_C_BIT};
use crate::chain;
use crate::footer::StreamFooter;
use crate::hash::HashSuite;
use crate::merkle::MerkleTree;
use crate::prefix;

/// Configuration for encoding a CBC artifact.
#[derive(Debug, Clone)]
pub struct EncoderConfig {
    pub hash_suite: HashSuite,
    pub commitment_mode: u8,
    pub block_payload_size: u32,
    pub flags: u32,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 4096,
            flags: 0,
        }
    }
}

/// Encode a payload into a complete CBC artifact.
///
/// `receipts` are pre-encoded receipt byte blobs to embed in the footer.
pub fn encode(
    config: &EncoderConfig,
    payload: &[u8],
    nonce: [u8; 16],
    receipts: &[Vec<u8>],
) -> Vec<u8> {
    let block_payload_size = config.block_payload_size;

    // 1. Chunk payload into blocks
    let chunks = chunk_payload(payload, block_payload_size);
    let block_count = chunks.len() as u32;

    // 2. Build bootstrap segment
    let bootstrap = BootstrapSegment {
        hash_suite: config.hash_suite,
        commitment_mode: config.commitment_mode,
        block_payload_size,
        block_count,
        bootstrap_nonce: nonce,
        flags: config.flags,
    };
    let bootstrap_bytes = bootstrap.encode();
    let params_canonical = bootstrap.params_canonical();

    // 3. Create blocks with zero-padded payloads
    let mut blocks: Vec<Block> = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| Block::new(i as u32, chunk.clone(), block_payload_size))
        .collect();

    // Build padded payloads for commitment computation
    let padded_payloads: Vec<Vec<u8>> = blocks
        .iter()
        .map(|b| b.padded_payload(block_payload_size))
        .collect();

    // 4. Compute chain commitments (Family A — always required)
    let (commitments, chain_root) =
        chain::compute_chain(&params_canonical, &nonce, &padded_payloads, config.hash_suite);

    // Set commitments on blocks
    for (block, commitment) in blocks.iter_mut().zip(commitments.iter()) {
        block.commitment = *commitment;
    }

    // 5. Compute Merkle tree (Family B, if enabled)
    let params_hash = chain::compute_params_hash(&params_canonical, config.hash_suite);
    let merkle_root = if config.commitment_mode & FAMILY_B_BIT != 0 {
        let tree = MerkleTree::build(&params_hash, &padded_payloads, config.hash_suite);
        Some(tree.root)
    } else {
        None
    };

    // 6. Build output buffer
    let mut output = Vec::new();

    // Bootstrap segment
    output.extend_from_slice(&bootstrap_bytes);

    // Blocks (with optional Family C prefix markers)
    let use_prefix = config.commitment_mode & FAMILY_C_BIT != 0;
    for block in &blocks {
        if use_prefix {
            let marker = prefix::encode_prefix_marker(
                prefix::BLOCK_TYPE_DATA,
                block_payload_size,
            );
            output.extend_from_slice(&marker);
        }
        output.extend_from_slice(&block.encode(block_payload_size));
    }

    // 7. Encode footer
    let footer_bytes = StreamFooter::encode(
        chain_root,
        merkle_root,
        receipts,
        &params_hash,
        config.hash_suite,
    );
    output.extend_from_slice(&footer_bytes);

    output
}

/// Encode with a random nonce (convenience function).
pub fn encode_random_nonce(
    config: &EncoderConfig,
    payload: &[u8],
    receipts: &[Vec<u8>],
) -> Vec<u8> {
    let mut nonce = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    encode(config, payload, nonce, receipts)
}

/// Split payload into chunks of block_payload_size.
fn chunk_payload(payload: &[u8], block_payload_size: u32) -> Vec<Vec<u8>> {
    let bps = block_payload_size as usize;
    if payload.is_empty() {
        // Even empty payload gets one block with zero-length payload
        return vec![vec![]];
    }
    payload.chunks(bps).map(|c| c.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_payload() {
        let payload = vec![0x42u8; 1024];
        let chunks = chunk_payload(&payload, 512);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 512);
        assert_eq!(chunks[1].len(), 512);
    }

    #[test]
    fn test_chunk_payload_partial_last() {
        let payload = vec![0x42u8; 700];
        let chunks = chunk_payload(&payload, 512);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 512);
        assert_eq!(chunks[1].len(), 188);
    }

    #[test]
    fn test_chunk_payload_empty() {
        let chunks = chunk_payload(&[], 512);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 0);
    }

    #[test]
    fn test_encode_produces_valid_magic() {
        let config = EncoderConfig::default();
        let payload = vec![0x42u8; 512];
        let artifact = encode(&config, &payload, [0u8; 16], &[]);
        assert_eq!(&artifact[0..4], b"CBC1");
    }

    #[test]
    fn test_encode_minimal() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 512,
            flags: 0,
        };
        let payload = vec![0x42u8; 512];
        let nonce = [0u8; 16];
        let artifact = encode(&config, &payload, nonce, &[]);
        // Should have: 64 (bootstrap) + 560 (block) + footer
        assert!(artifact.len() > 64 + 560);
    }
}
