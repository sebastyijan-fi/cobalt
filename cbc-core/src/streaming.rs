/// CBC Streaming Mode — encode and decode artifacts incrementally.
///
/// `StreamingEncoder` writes blocks one at a time with `block_count = 0` in the
/// bootstrap header (unknown until finalization). `StreamingDecoder` validates
/// blocks as they arrive, accumulating the chain commitment.
use crate::block::Block;
use crate::bootstrap::{BootstrapSegment, FAMILY_B_BIT, FAMILY_C_BIT};
use crate::chain;
use crate::encoder::EncoderConfig;
use crate::error::{CbcError, Result};
use crate::footer::StreamFooter;
use crate::hash::HashSuite;
use crate::merkle::MerkleTree;
use crate::prefix;

/// Streaming encoder — write blocks incrementally.
///
/// # Usage
///
/// ```rust,ignore
/// let mut enc = StreamingEncoder::new(&config, nonce);
/// enc.write_block(b"chunk1");
/// enc.write_block(b"chunk2");
/// let artifact = enc.finalize(&[]);
/// ```
pub struct StreamingEncoder {
    config: EncoderConfig,
    nonce: [u8; 16],
    _params_canonical: [u8; 40],
    params_hash: [u8; 32],
    blocks: Vec<Block>,
    padded_payloads: Vec<Vec<u8>>,
    prev_commitment: [u8; 32],
    payload_bytes: usize,
}

impl StreamingEncoder {
    /// Create a new streaming encoder.
    pub fn new(config: &EncoderConfig, nonce: [u8; 16]) -> Self {
        // Build a temporary bootstrap to get params_canonical
        let bootstrap = BootstrapSegment {
            hash_suite: config.hash_suite,
            commitment_mode: config.commitment_mode,
            block_payload_size: config.block_payload_size,
            block_count: 0, // Streaming: unknown until finalize
            bootstrap_nonce: nonce,
            flags: config.flags,
        };
        let params_canonical = bootstrap.params_canonical();
        let params_hash = chain::compute_params_hash(&params_canonical, config.hash_suite);
        let c0 = chain::compute_c0(&params_canonical, &nonce, config.hash_suite);

        Self {
            config: config.clone(),
            nonce,
            _params_canonical: params_canonical,
            params_hash,
            blocks: Vec::new(),
            padded_payloads: Vec::new(),
            prev_commitment: c0,
            payload_bytes: 0,
        }
    }

    /// Write a block of payload data. The data will be zero-padded to
    /// `block_payload_size`. Returns the block index.
    pub fn write_block(&mut self, data: &[u8]) -> u32 {
        let index = self.blocks.len() as u32;
        let bps = self.config.block_payload_size;

        let mut block = Block::new(index, data.to_vec(), bps);
        let padded = block.padded_payload(bps);

        // Compute chain commitment for this block
        let commitment = chain::compute_ci(
            &self.params_hash,
            index as u64,
            &padded,
            &self.prev_commitment,
            self.config.hash_suite,
        );
        block.commitment = commitment;
        self.prev_commitment = commitment;

        self.padded_payloads.push(padded);
        self.payload_bytes += data.len();
        self.blocks.push(block);

        index
    }

    /// Write raw payload bytes, automatically chunking into blocks.
    pub fn write_payload(&mut self, payload: &[u8]) {
        let bps = self.config.block_payload_size as usize;
        if payload.is_empty() {
            self.write_block(&[]);
            return;
        }
        for chunk in payload.chunks(bps) {
            self.write_block(chunk);
        }
    }

    /// Number of blocks written so far.
    pub fn block_count(&self) -> u32 {
        self.blocks.len() as u32
    }

    /// Total payload bytes written.
    pub fn payload_size(&self) -> usize {
        self.payload_bytes
    }

    /// Finalize the artifact: compute the footer, build the complete byte stream.
    ///
    /// `receipts` are pre-encoded receipt byte blobs to embed in the footer.
    pub fn finalize(self, receipts: &[Vec<u8>]) -> Vec<u8> {
        let block_count = self.blocks.len() as u32;
        let bps = self.config.block_payload_size;

        // Build the real bootstrap with correct block_count
        let bootstrap = BootstrapSegment {
            hash_suite: self.config.hash_suite,
            commitment_mode: self.config.commitment_mode,
            block_payload_size: bps,
            block_count,
            bootstrap_nonce: self.nonce,
            flags: self.config.flags,
        };

        // Re-compute params_canonical with the real block_count
        let real_params_canonical = bootstrap.params_canonical();
        let real_params_hash =
            chain::compute_params_hash(&real_params_canonical, self.config.hash_suite);

        // Re-compute chain with real params (block_count changes the hash)
        let c0 = chain::compute_c0(&real_params_canonical, &self.nonce, self.config.hash_suite);
        let mut chain_root = c0;
        let mut real_blocks = Vec::with_capacity(self.blocks.len());

        for (i, block) in self.blocks.into_iter().enumerate() {
            let padded = &self.padded_payloads[i];
            let commitment = chain::compute_ci(
                &real_params_hash,
                i as u64,
                padded,
                &chain_root,
                self.config.hash_suite,
            );
            chain_root = commitment;

            let mut real_block = block;
            real_block.commitment = commitment;
            real_blocks.push(real_block);
        }

        // Merkle tree
        let merkle_root = if self.config.commitment_mode & FAMILY_B_BIT != 0 {
            let tree = MerkleTree::build(
                &real_params_hash,
                &self.padded_payloads,
                self.config.hash_suite,
            );
            Some(tree.root)
        } else {
            None
        };

        // Build output
        let mut output = Vec::new();
        output.extend_from_slice(&bootstrap.encode());

        let use_prefix = self.config.commitment_mode & FAMILY_C_BIT != 0;
        for block in &real_blocks {
            if use_prefix {
                let marker = prefix::encode_prefix_marker(prefix::BLOCK_TYPE_DATA, bps);
                output.extend_from_slice(&marker);
            }
            output.extend_from_slice(&block.encode(bps));
        }

        let footer_bytes = StreamFooter::encode(
            chain_root,
            merkle_root,
            receipts,
            &real_params_hash,
            self.config.hash_suite,
        );
        output.extend_from_slice(&footer_bytes);

        output
    }
}

/// Streaming decoder — validate blocks incrementally.
///
/// Reads bytes progressively and validates each block as it arrives.
/// The full validation (footer, Merkle root) happens at `finalize()`.
pub struct StreamingDecoder {
    bootstrap: Option<BootstrapSegment>,
    suite: HashSuite,
    _params_canonical: [u8; 40],
    params_hash: [u8; 32],
    prev_commitment: [u8; 32],
    blocks_validated: u32,
    payload: Vec<u8>,
    padded_payloads: Vec<Vec<u8>>,
}

impl StreamingDecoder {
    /// Initialize a decoder from a bootstrap segment (first 64 bytes).
    pub fn from_bootstrap(bootstrap_bytes: &[u8; 64]) -> Result<Self> {
        let bootstrap = BootstrapSegment::decode(bootstrap_bytes)?;
        let suite = bootstrap.hash_suite;
        let params_canonical = bootstrap.params_canonical();
        let params_hash = chain::compute_params_hash(&params_canonical, suite);
        let c0 = chain::compute_c0(&params_canonical, &bootstrap.bootstrap_nonce, suite);

        Ok(Self {
            bootstrap: Some(bootstrap),
            suite,
            _params_canonical: params_canonical,
            params_hash,
            prev_commitment: c0,
            blocks_validated: 0,
            payload: Vec::new(),
            padded_payloads: Vec::new(),
        })
    }

    /// Feed a block and validate it against the chain.
    ///
    /// Returns the payload bytes from the block if valid.
    pub fn feed_block(&mut self, block_bytes: &[u8], is_last: bool) -> Result<Vec<u8>> {
        let bootstrap = self
            .bootstrap
            .as_ref()
            .ok_or(CbcError::InsufficientData { need: 64, have: 0 })?;
        let bps = bootstrap.block_payload_size;

        let block = Block::decode(block_bytes, bps, self.blocks_validated, is_last)?;
        let padded = block.padded_payload(bps);

        // Verify chain commitment
        let expected = chain::compute_ci(
            &self.params_hash,
            self.blocks_validated as u64,
            &padded,
            &self.prev_commitment,
            self.suite,
        );

        if block.commitment != expected {
            return Err(CbcError::ChainCommitmentMismatch {
                index: self.blocks_validated,
            });
        }

        self.prev_commitment = expected;
        self.blocks_validated += 1;

        self.payload.extend_from_slice(&block.payload);
        self.padded_payloads.push(padded);

        Ok(block.payload)
    }

    /// Current chain root (after all blocks fed so far).
    pub fn chain_root(&self) -> [u8; 32] {
        self.prev_commitment
    }

    /// Number of blocks validated so far.
    pub fn blocks_validated(&self) -> u32 {
        self.blocks_validated
    }

    /// Finalize: verify the footer and Merkle root.
    ///
    /// Returns the full payload if everything passes.
    pub fn finalize(self, footer_bytes: &[u8]) -> Result<Vec<u8>> {
        let bootstrap = self
            .bootstrap
            .ok_or(CbcError::InsufficientData { need: 64, have: 0 })?;

        // Verify block count
        if bootstrap.block_count != 0 && self.blocks_validated != bootstrap.block_count {
            return Err(CbcError::InsufficientData {
                need: bootstrap.block_count as usize,
                have: self.blocks_validated as usize,
            });
        }

        // Parse and verify footer
        let has_merkle = bootstrap.commitment_mode & FAMILY_B_BIT != 0;
        let footer = StreamFooter::decode(footer_bytes, has_merkle, &self.params_hash, self.suite)?;

        // Verify chain root
        if footer.chain_root != self.prev_commitment {
            return Err(CbcError::ChainRootMismatch);
        }

        // Verify Merkle root if Family B
        if bootstrap.commitment_mode & FAMILY_B_BIT != 0 {
            let computed_merkle =
                MerkleTree::build(&self.params_hash, &self.padded_payloads, self.suite).root;
            match footer.merkle_root {
                Some(mr) if mr != computed_merkle => {
                    return Err(CbcError::MerkleRootMismatch);
                }
                None => {
                    return Err(CbcError::MerkleRootMismatch);
                }
                _ => {}
            }
        }

        Ok(self.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::FAMILY_A_BIT;
    use crate::decoder;

    #[test]
    fn test_streaming_encode_matches_buffer() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
            block_payload_size: 512,
            flags: 0,
        };
        let payload = vec![0x42u8; 1500]; // 3 blocks
        let nonce = [0x01u8; 16];

        // Buffer encode
        let buffer_artifact = crate::encoder::encode(&config, &payload, nonce, &[]);

        // Streaming encode
        let mut enc = StreamingEncoder::new(&config, nonce);
        enc.write_payload(&payload);
        let stream_artifact = enc.finalize(&[]);

        assert_eq!(
            buffer_artifact, stream_artifact,
            "Streaming encode must produce identical output to buffer encode"
        );
    }

    #[test]
    fn test_streaming_encode_manual_blocks() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 512,
            flags: 0,
        };
        let nonce = [42u8; 16];

        let mut enc = StreamingEncoder::new(&config, nonce);
        enc.write_block(&[0xAA; 512]); // Full block
        enc.write_block(&[0xBB; 512]); // Full block
        enc.write_block(&[0xCC; 300]); // Last block, partial OK
        assert_eq!(enc.block_count(), 3);

        let artifact = enc.finalize(&[]);

        // Must decode successfully
        let decoded = decoder::decode(&artifact).unwrap();
        assert_eq!(decoded.payload.len(), 1324);
        assert_eq!(&decoded.payload[0..512], &[0xAA; 512]);
        assert_eq!(&decoded.payload[512..1024], &[0xBB; 512]);
        assert_eq!(&decoded.payload[1024..1324], &[0xCC; 300]);
    }

    #[test]
    fn test_streaming_decode() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
            block_payload_size: 512,
            flags: 0,
        };
        let payload = vec![0x42u8; 1500];
        let nonce = [0x01u8; 16];
        let artifact = crate::encoder::encode(&config, &payload, nonce, &[]);

        // Parse bootstrap
        let mut bootstrap_bytes = [0u8; 64];
        bootstrap_bytes.copy_from_slice(&artifact[0..64]);
        let mut dec = StreamingDecoder::from_bootstrap(&bootstrap_bytes).unwrap();

        let bootstrap = BootstrapSegment::decode(&bootstrap_bytes).unwrap();
        let bps = bootstrap.block_payload_size;
        let block_wire_size = crate::block::block_wire_size(bps);

        // Feed blocks
        let mut offset = 64;
        for i in 0..bootstrap.block_count {
            let block_end = offset + block_wire_size;
            let is_last = i == bootstrap.block_count - 1;
            let _block_payload = dec
                .feed_block(&artifact[offset..block_end], is_last)
                .unwrap();
            offset = block_end;
        }

        assert_eq!(dec.blocks_validated(), 3);

        // Finalize with footer
        let result = dec.finalize(&artifact[offset..]).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn test_streaming_decode_tampered_block_fails() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 512,
            flags: 0,
        };
        let payload = vec![0x42u8; 1024]; // 2 blocks
        let nonce = [0x01u8; 16];
        let mut artifact = crate::encoder::encode(&config, &payload, nonce, &[]);

        // Tamper with second block
        artifact[64 + 560 + 10] ^= 0xFF;

        let mut bootstrap_bytes = [0u8; 64];
        bootstrap_bytes.copy_from_slice(&artifact[0..64]);
        let mut dec = StreamingDecoder::from_bootstrap(&bootstrap_bytes).unwrap();

        let bps = 512;
        let bws = crate::block::block_wire_size(bps);

        // First block should succeed
        let _b0 = dec.feed_block(&artifact[64..64 + bws], false).unwrap();

        // Second block should fail (tampered)
        let result = dec.feed_block(&artifact[64 + bws..64 + 2 * bws], true);
        assert!(result.is_err(), "Tampered block must fail validation");
    }
}
