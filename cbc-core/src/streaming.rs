/// CBC Streaming Mode — encode and decode artifacts incrementally.
///
/// `StreamingEncoder` writes blocks one at a time with `block_count = 0` in the
/// bootstrap header (unknown until finalization). `StreamingDecoder` validates
/// blocks as they arrive, accumulating the chain commitment.
use crate::block::Block;
use crate::bootstrap::BootstrapSegment;
use crate::chain;
use crate::encoder::EncoderConfig;
use crate::error::{CbcError, Result};
use crate::footer::StreamFooter;
use crate::merkle::MerkleTree;
use crate::prefix;
use alloc::vec::Vec;
use alloc::string::ToString;

/// Streaming encoder — write blocks incrementally.
pub struct StreamingEncoder {
    config: EncoderConfig,
    nonce: [u8; 16],
    _params_canonical: [u8; 64],
    params_hash: [u8; 32],
    blocks: Vec<Block>,
    padded_payloads: Vec<Vec<u8>>,
    prev_commitment: [u8; 32],
    payload_bytes: usize,
    /// Persistent zstd accumulator for streaming compression.
    zstd_accumulator: Vec<u8>,
    /// Internal buffer for non-aligned writes (uncompressed).
    buffer: Vec<u8>,
}

impl StreamingEncoder {
    /// Create a new streaming encoder.
    pub fn new(config: &EncoderConfig, nonce: [u8; 16]) -> Self {
        let bootstrap = BootstrapSegment {
            hash_suite: config.hash_suite,
            commitment_mode: config.commitment_mode,
            block_payload_size: config.block_payload_size,
            block_count: 0,
            bootstrap_nonce: nonce,
            flags: config.flags,
        };
        let params_canonical = bootstrap.params_canonical();
        let params_hash = chain::compute_params_hash(&params_canonical, config.hash_suite);
        let c0 = chain::compute_c0(&params_canonical, &nonce, config.hash_suite);

        Self {
            config: config.clone(),
            nonce,
            _params_canonical: bootstrap.encode(),
            params_hash,
            blocks: Vec::new(),
            padded_payloads: Vec::new(),
            prev_commitment: c0,
            payload_bytes: 0,
            zstd_accumulator: Vec::new(),
            buffer: Vec::new(),
        }
    }

    fn is_encrypted(&self) -> bool {
        self.config.flags & crate::bootstrap::FLAG_ENCRYPTED != 0
    }

    fn is_compressed(&self) -> bool {
        self.config.flags & crate::bootstrap::FLAG_COMPRESSED != 0
    }

    pub fn write_block(&mut self, data: &[u8]) -> Result<u32> {
        let index = self.blocks.len() as u32;
        let bps = self.config.block_payload_size;

        let mut block = Block::new(index, data.to_vec(), bps);
        let padded = block.padded_payload(bps);

        let commitment = chain::compute_ci(
            &self.params_hash,
            index as u64,
            &padded,
            &self.prev_commitment,
            self.config.hash_suite,
        );

        if self.is_encrypted() {
            let key = self
                .config
                .encryption_key
                .as_ref()
                .ok_or(CbcError::MissingEncryptionKey)?;
            block.encrypt(key, &self.nonce, bps)?;
        }

        block.commitment = commitment;
        self.blocks.push(block);
        self.padded_payloads.push(padded);
        self.prev_commitment = commitment;
        self.payload_bytes += data.len();

        Ok(index)
    }

    pub fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        if self.is_compressed() {
            self.zstd_accumulator.extend_from_slice(payload);
            Ok(())
        } else {
            self.buffer.extend_from_slice(payload);
            let bps = self.config.block_payload_size as usize;
            
            while self.buffer.len() >= bps {
                let chunk: Vec<u8> = self.buffer.drain(0..bps).collect();
                self.write_block(&chunk)?;
            }
            Ok(())
        }
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    pub fn finalize(mut self, _receipts: &[Vec<u8>]) -> Result<Vec<u8>> {
        if !self.is_compressed() && !self.buffer.is_empty() {
            let last_chunk = core::mem::take(&mut self.buffer);
            self.write_block(&last_chunk)?;
        }

        let (final_blocks, final_padded, final_commitment) = if self.is_compressed() {
            // ... (rest of compressed logic)
            #[cfg(feature = "std")]
            {
                let compressed = zstd::encode_all(&self.zstd_accumulator[..], 0)
                    .map_err(|e| CbcError::CompressionError(e.to_string()))?;
                
                // Re-generate blocks from compressed data
                let mut temp_encoder = Self::new(&self.config, self.nonce);
                for chunk in compressed.chunks(self.config.block_payload_size as usize) {
                    temp_encoder.write_block(chunk)?;
                }
                (temp_encoder.blocks, temp_encoder.padded_payloads, temp_encoder.prev_commitment)
            }
            #[cfg(not(feature = "std"))]
            {
                return Err(CbcError::CompressionError("Compression not supported in no_std builds".to_string()));
            }
        } else {
            (self.blocks, self.padded_payloads, self.prev_commitment)
        };

        let chain_root = final_commitment;

        let final_block_count = final_blocks.len() as u32;
        let mut final_bootstrap = BootstrapSegment::decode(&self._params_canonical).unwrap();
        final_bootstrap.block_count = final_block_count;

        let mut output = final_bootstrap.encode().to_vec();

        let has_prefix = final_bootstrap.family_c();
        let bps = final_bootstrap.block_payload_size;

        for block in &final_blocks {
            if has_prefix {
                let marker = prefix::encode_prefix_marker(
                    prefix::BLOCK_TYPE_DATA,
                    bps,
                );
                output.extend_from_slice(&marker);
            }
            output.extend_from_slice(&block.encode(bps));
        }

        let params_hash = chain::compute_params_hash(&final_bootstrap.params_canonical(), final_bootstrap.hash_suite);
        let merkle_root = if final_bootstrap.family_b() {
            let tree = MerkleTree::build(
                &params_hash,
                &final_padded,
                self.config.hash_suite,
            );
            Some(tree.root)
        } else {
            None
        };

        let footer_bytes = StreamFooter::encode(
            chain_root,
            merkle_root,
            &[], // Receipts TBD in streaming
            &params_hash,
            final_bootstrap.hash_suite,
        );
        output.extend_from_slice(&footer_bytes);
        Ok(output)
    }
}

pub struct StreamingDecoder {
    decryption_key: Option<[u8; 32]>,
    bootstrap: Option<BootstrapSegment>,
    params_hash: [u8; 32],
    prev_commitment: [u8; 32],
    expected_index: u32,
    payload: Vec<u8>,
    padded_payloads: Vec<Vec<u8>>,
}

impl Default for StreamingDecoder {
    fn default() -> Self {
        Self::new(None)
    }
}

impl StreamingDecoder {
    pub fn new(key: Option<[u8; 32]>) -> Self {
        Self {
            decryption_key: key,
            bootstrap: None,
            params_hash: [0u8; 32],
            prev_commitment: [0u8; 32],
            expected_index: 0,
            payload: Vec::new(),
            padded_payloads: Vec::new(),
        }
    }

    pub fn bootstrap(&self) -> Option<&BootstrapSegment> {
        self.bootstrap.as_ref()
    }

    pub fn feed_bootstrap(&mut self, bootstrap_bytes: &[u8]) -> Result<()> {
        let bs = BootstrapSegment::decode(bootstrap_bytes.try_into().map_err(|_| {
            CbcError::InsufficientData {
                need: 64,
                have: bootstrap_bytes.len(),
            }
        })?)?;
        self.params_hash = chain::compute_params_hash(&bs.params_canonical(), bs.hash_suite);
        self.prev_commitment =
            chain::compute_c0(&bs.params_canonical(), &bs.bootstrap_nonce, bs.hash_suite);
        self.bootstrap = Some(bs);
        Ok(())
    }

    pub fn feed_block(&mut self, block_bytes: &[u8], is_last: bool) -> Result<Vec<u8>> {
        let bootstrap = self.bootstrap.as_ref().ok_or(CbcError::FooterCommitmentMismatch)?;
        let bps = bootstrap.block_payload_size;

        let (mut block, _consumed) = if bootstrap.family_c() {
            let prefix_size = prefix::prefix_marker_size(bps);
            let (bt, ps, c) = prefix::decode_prefix_marker(&block_bytes[..prefix_size])?;
            if bt != prefix::BLOCK_TYPE_DATA || ps != bps || c != prefix_size {
                return Err(CbcError::PrefixParseError("invalid streaming prefix".to_string()));
            }
            (Block::decode(&block_bytes[prefix_size..], bps, self.expected_index, is_last)?, prefix_size)
        } else {
            (Block::decode(block_bytes, bps, self.expected_index, is_last)?, 0)
        };

        if bootstrap.flags & crate::bootstrap::FLAG_ENCRYPTED != 0 {
            let key = self.decryption_key.ok_or(CbcError::MissingEncryptionKey)?;
            block.decrypt(&key, &bootstrap.bootstrap_nonce, bps)?;
        }

        let padded = block.padded_payload(bps);

        let commitment = chain::compute_ci(
            &self.params_hash,
            self.expected_index as u64,
            &padded,
            &self.prev_commitment,
            bootstrap.hash_suite,
        );
        if commitment != block.commitment {
            return Err(CbcError::ChainCommitmentMismatch {
                index: self.expected_index,
            });
        }

        let chunk = if is_last {
            &block.payload[..block.header.payload_length as usize]
        } else {
            if block.header.payload_length != bps {
                return Err(CbcError::NonFullPayload {
                    index: self.expected_index,
                    length: block.header.payload_length,
                    expected: bps,
                });
            }
            &block.payload
        };

        let result = chunk.to_vec();
        self.payload.extend_from_slice(chunk);
        self.padded_payloads.push(padded);
        self.prev_commitment = commitment;
        self.expected_index += 1;

        Ok(result)
    }

    pub fn finalize(self, footer_bytes: &[u8]) -> Result<Vec<u8>> {
        let bootstrap = self.bootstrap.ok_or(CbcError::FooterCommitmentMismatch)?;
        let footer = StreamFooter::decode(footer_bytes, bootstrap.family_b(), &self.params_hash, bootstrap.hash_suite)?;

        if footer.chain_root != self.prev_commitment {
            return Err(CbcError::ChainRootMismatch);
        }

        if let Some(mr) = footer.merkle_root {
            let tree = MerkleTree::build(
                &self.params_hash,
                &self.padded_payloads,
                bootstrap.hash_suite,
            );
            if mr != tree.root {
                return Err(CbcError::MerkleRootMismatch);
            }
        }

        if bootstrap.flags & crate::bootstrap::FLAG_COMPRESSED != 0 {
            #[cfg(feature = "std")]
            {
                zstd::decode_all(&self.payload[..]).map_err(|e| CbcError::DecompressionError(e.to_string()))
            }
            #[cfg(not(feature = "std"))]
            {
                Err(CbcError::DecompressionError("Decompression not supported in no_std builds".to_string()))
            }
        } else {
            Ok(self.payload)
        }
    }
}
