use crate::block::Block;
use crate::bootstrap::{BootstrapSegment, FAMILY_A_BIT, FAMILY_B_BIT, FAMILY_C_BIT};
use crate::chain;
use crate::error::{CbcError, Result};
use crate::footer::StreamFooter;
use crate::hash::HashSuite;
use crate::merkle::MerkleTree;
use crate::prefix;
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

/// Configuration for encoding a CBC artifact.
#[derive(Debug, Clone)]
pub struct EncoderConfig {
    pub hash_suite: HashSuite,
    pub commitment_mode: u8,
    pub block_payload_size: u32,
    pub flags: u32,
    /// Symmetric key for encryption (32 bytes for AES-GCM-256).
    pub encryption_key: Option<[u8; 32]>,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 4096,
            flags: 0,
            encryption_key: None,
        }
    }
}

/// Encode a payload into a complete CBC artifact.
pub fn encode(
    config: &EncoderConfig,
    payload: &[u8],
    nonce: [u8; 16],
    receipts: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let block_payload_size = config.block_payload_size;
    if block_payload_size == 0 {
        return Err(CbcError::InvalidBlockPayloadSize(0));
    }
    let is_compressed = config.flags & crate::bootstrap::FLAG_COMPRESSED != 0;
    let is_encrypted = config.flags & crate::bootstrap::FLAG_ENCRYPTED != 0;

    if is_encrypted && block_payload_size < 16 {
        return Err(CbcError::msg(format!(
            "block_payload_size ({block_payload_size}) must be at least 16 bytes when encryption is enabled"
        )));
    }

    let effective_bps = if is_encrypted {
        block_payload_size - 16 // 16 bytes for AES-GCM tag
    } else {
        block_payload_size
    };

    // 1. Optional Compression
    let processed_payload = if is_compressed {
        #[cfg(feature = "std")]
        {
            zstd::encode_all(payload, 0).map_err(|e| CbcError::CompressionError(e.to_string()))?
        }
        #[cfg(not(feature = "std"))]
        {
            return Err(CbcError::CompressionError(
                "Compression not supported in no_std builds".to_string(),
            ));
        }
    } else {
        payload.to_vec()
    };

    // 2. Chunk payload into blocks
    let chunks = chunk_payload(&processed_payload, effective_bps);
    let block_count = chunks.len() as u32;

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

    // 3. Create blocks
    let mut blocks: Vec<Block> = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk): (usize, &Vec<u8>)| {
            Block::new(i as u32, chunk.clone(), block_payload_size)
        })
        .collect();

    if is_encrypted {
        let key = config
            .encryption_key
            .as_ref()
            .ok_or(CbcError::MissingEncryptionKey)?;

        for block in &mut blocks {
            block.encrypt(key, &nonce, block_payload_size)?;
        }
    }

    let padded_payloads: Vec<Vec<u8>> = blocks
        .iter()
        .map(|b: &Block| b.padded_payload(block_payload_size))
        .collect();

    // 4. Compute chain commitments
    let (commitments, chain_root) = chain::compute_chain(
        &params_canonical,
        &nonce,
        &blocks,
        block_payload_size,
        config.hash_suite,
    );

    for (block, commitment) in blocks.iter_mut().zip(commitments.iter()) {
        block.commitment = *commitment;
    }

    // 5. Compute Merkle tree
    let params_hash = chain::compute_params_hash(&params_canonical, config.hash_suite);
    let merkle_root = if config.commitment_mode & FAMILY_B_BIT != 0 {
        let tree = MerkleTree::build(&params_hash, &padded_payloads, config.hash_suite);
        Some(tree.root)
    } else {
        None
    };

    // 6. Build output buffer
    let mut output = Vec::new();
    output.extend_from_slice(&bootstrap_bytes);

    let use_prefix = config.commitment_mode & FAMILY_C_BIT != 0;
    for block in &blocks {
        if use_prefix {
            let marker = prefix::encode_prefix_marker(prefix::BLOCK_TYPE_DATA, block_payload_size);
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

    Ok(output)
}

#[cfg(feature = "std")]
pub fn encode_random_nonce(
    config: &EncoderConfig,
    payload: &[u8],
    receipts: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    encode(config, payload, nonce, receipts)
}

fn chunk_payload(payload: &[u8], block_payload_size: u32) -> Vec<Vec<u8>> {
    let bps = block_payload_size as usize;
    if payload.is_empty() {
        return vec![vec![]];
    }
    payload.chunks(bps).map(|c: &[u8]| c.to_vec()).collect()
}
