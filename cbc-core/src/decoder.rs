/// CBC Decoder — validates and extracts payload from a CBC artifact.
///
/// A compliant decoder (§10.1):
/// 1. MUST verify params_mac
/// 2. MUST verify every block commitment (Family A)
/// 3. MUST verify Merkle root if Family B declared
/// 4. MUST verify prefix parse if Family C declared
/// 5. MUST verify footer_commitment
/// 6. MUST treat any failure as hard error
/// 7. MUST NOT expose payload from a failed artifact
use crate::block::{block_wire_size, Block};
use crate::bootstrap::{BootstrapSegment, BOOTSTRAP_SIZE};
use crate::chain;
use crate::error::{CbcError, Result};
use crate::footer::StreamFooter;
use crate::merkle;
use crate::prefix;
use alloc::vec::Vec;
use alloc::string::ToString;
use alloc::format;

/// Result of a successful decode.
#[derive(Debug)]
pub struct DecodedArtifact {
    pub bootstrap: BootstrapSegment,
    pub payload: Vec<u8>,
    pub chain_root: [u8; 32],
    pub merkle_root: Option<[u8; 32]>,
    pub receipt_slots: Vec<Vec<u8>>,
    pub block_count: u32,
}

/// Validate and decode a CBC artifact.
///
/// Returns the decoded payload only if ALL validation checks pass.
pub fn decode(data: &[u8], key: Option<[u8; 32]>) -> Result<DecodedArtifact> {
    // 1. Parse and verify bootstrap segment (params_mac)
    if data.len() < BOOTSTRAP_SIZE {
        return Err(CbcError::InsufficientData {
            need: BOOTSTRAP_SIZE,
            have: data.len(),
        });
    }

    let mut bootstrap_bytes = [0u8; BOOTSTRAP_SIZE];
    bootstrap_bytes.copy_from_slice(&data[..BOOTSTRAP_SIZE]);
    let bootstrap = BootstrapSegment::decode(&bootstrap_bytes)?;

    let block_payload_size = bootstrap.block_payload_size;
    let block_count = bootstrap.block_count;
    let suite = bootstrap.hash_suite;
    let params_canonical = bootstrap.params_canonical();
    let params_hash = chain::compute_params_hash(&params_canonical, suite);
    let has_merkle = bootstrap.family_b();
    let has_prefix = bootstrap.family_c();

    // Determine prefix marker size (if Family C)
    let prefix_size = if has_prefix {
        prefix::prefix_marker_size(block_payload_size)
    } else {
        0
    };

    let wire_size = block_wire_size(block_payload_size);
    let block_total_size = prefix_size + wire_size;

    // Check we have enough data for all blocks
    let blocks_start = BOOTSTRAP_SIZE;
    let blocks_end = blocks_start + (block_count as usize) * block_total_size;

    if data.len() < blocks_end {
        return Err(CbcError::InsufficientData {
            need: blocks_end,
            have: data.len(),
        });
    }

    // 2. Parse all blocks
    let mut blocks = Vec::with_capacity(block_count as usize);
    let mut offset = blocks_start;

    for i in 0..block_count {
        let is_last = i == block_count - 1;

        // Family C prefix check
        if has_prefix {
            let marker_data = &data[offset..];
            let (block_type, payload_size, consumed) = prefix::decode_prefix_marker(marker_data)?;
            if block_type != prefix::BLOCK_TYPE_DATA {
                return Err(CbcError::PrefixParseError(format!(
                    "block {i}: unexpected block type 0x{block_type:02x}"
                )));
            }
            if payload_size != block_payload_size {
                return Err(CbcError::PrefixParseError(format!(
                    "block {i}: prefix payload size {payload_size} != {block_payload_size}"
                )));
            }
            if consumed != prefix_size {
                return Err(CbcError::PrefixParseError(format!(
                    "block {i}: prefix marker size mismatch"
                )));
            }
            offset += prefix_size;
        }

        let block = Block::decode(&data[offset..], block_payload_size, i, is_last)?;
        blocks.push(block);
        offset += wire_size;
    }

    // 3. Compute chain commitments and verify (Family A)
    let padded_payloads: Vec<Vec<u8>> = blocks
        .iter()
        .map(|b: &Block| b.padded_payload(block_payload_size))
        .collect();

    // 3. Verify chain commitments (Family A)
    let commitments: Vec<[u8; 32]> = blocks.iter().map(|b| b.commitment).collect();
    let chain_root = chain::verify_chain(
        &params_canonical,
        &bootstrap.bootstrap_nonce,
        &padded_payloads,
        &commitments,
        suite,
    )?;

    // 4. Verify Merkle root (Family B)
    let merkle_root = if has_merkle {
        let tree = merkle::MerkleTree::build(&params_hash, &padded_payloads, suite);
        Some(tree.root)
    } else {
        None
    };

    // 5. Parse and verify footer
    let footer_data = &data[offset..];
    let footer = StreamFooter::decode(footer_data, has_merkle, &params_hash, suite)?;

    // 6. Verify chain root matches footer
    if footer.chain_root != chain_root {
        return Err(CbcError::ChainRootMismatch);
    }

    // Verify Merkle root matches footer (if enabled)
    if let (Some(computed), Some(footer_merkle)) = (merkle_root, footer.merkle_root) {
        if computed != footer_merkle {
            return Err(CbcError::MerkleRootMismatch);
        }
    }

    // 7. Extract payload (concatenate all block payloads)
    let is_encrypted = bootstrap.flags & crate::bootstrap::FLAG_ENCRYPTED != 0;
    let is_compressed = bootstrap.flags & crate::bootstrap::FLAG_COMPRESSED != 0;
    
    let mut raw_payload = Vec::new();
    for mut block in blocks {
        if is_encrypted {
            let k = key.ok_or(CbcError::MissingEncryptionKey)?;
            block.decrypt(&k, &bootstrap.bootstrap_nonce, block_payload_size)?;
        }
        raw_payload.extend_from_slice(&block.payload);
    }

    // 8. Optional Decompression
    let final_payload = if is_compressed {
        #[cfg(feature = "std")]
        {
            zstd::decode_all(&raw_payload[..]).map_err(|e| CbcError::DecompressionError(e.to_string()))?
        }
        #[cfg(not(feature = "std"))]
        {
            return Err(CbcError::DecompressionError("Decompression not supported in no_std builds".to_string()));
        }
    } else {
        raw_payload
    };

    Ok(DecodedArtifact {
        bootstrap,
        payload: final_payload,
        chain_root,
        merkle_root,
        receipt_slots: footer.receipt_slots,
        block_count,
    })
}

/// Validate a CBC artifact without extracting payload.
/// Returns Ok(()) if valid.
pub fn validate(data: &[u8]) -> Result<()> {
    decode(data, None).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::bootstrap::{FAMILY_A_BIT, FAMILY_B_BIT, FAMILY_C_BIT};
    use crate::encoder::{self, EncoderConfig};
    use crate::hash::HashSuite;

    #[test]
    fn test_roundtrip_family_a() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 512,
            flags: 0,
            encryption_key: None,
        };
        let payload = vec![0x42u8; 1024];
        let artifact = encoder::encode(&config, &payload, [0u8; 16], &[]).unwrap();
        let decoded = decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.block_count, 2);
    }

    #[test]
    fn test_roundtrip_family_ab() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
            block_payload_size: 512,
            flags: 0,
            encryption_key: None,
        };
        let payload = vec![0x42u8; 1500];
        let artifact = encoder::encode(&config, &payload, [1u8; 16], &[]).unwrap();
        let decoded = decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_roundtrip_family_abc() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT | FAMILY_C_BIT,
            block_payload_size: 512,
            flags: 0,
            encryption_key: None,
        };
        let payload = vec![0x42u8; 1500];
        let artifact = encoder::encode(&config, &payload, [2u8; 16], &[]).unwrap();
        let decoded = decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_roundtrip_sha256() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Sha256,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 512,
            flags: 0,
            encryption_key: None,
        };
        let payload = vec![0x42u8; 1024];
        let artifact = encoder::encode(&config, &payload, [3u8; 16], &[]).unwrap();
        let decoded = decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_bit_flip_detected() {
        let config = EncoderConfig::default();
        let payload = vec![0x42u8; 1024];
        let mut artifact = encoder::encode(&config, &payload, [4u8; 16], &[]).unwrap();
        
        // Flip one bit in the first block
        artifact[70] ^= 0x01;
        
        assert!(decode(&artifact, None).is_err());
    }

    #[test]
    fn test_truncated_artifact_detected() {
        let config = EncoderConfig::default();
        let payload = vec![0x42u8; 1024];
        let mut artifact = encoder::encode(&config, &payload, [5u8; 16], &[]).unwrap();
        
        // Remove trailing bytes
        artifact.truncate(artifact.len() - 10);
        
        assert!(decode(&artifact, None).is_err());
    }

    #[test]
    fn test_empty_payload() {
        let config = EncoderConfig::default();
        let payload = vec![];
        let artifact = encoder::encode(&config, &payload, [6u8; 16], &[]).unwrap();
        let decoded = decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.block_count, 1);
    }

    #[test]
    fn test_large_payload() {
        let config = EncoderConfig {
            block_payload_size: 4096,
            ..EncoderConfig::default()
        };
        // 1 MiB payload
        let payload = vec![0xAA; 1024 * 1024];
        let artifact = encoder::encode(&config, &payload, [7u8; 16], &[]).unwrap();
        let decoded = decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.block_count, 256); // 1 MiB / 4 KiB = 256 blocks
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_roundtrip_compressed() {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 512,
            flags: crate::bootstrap::FLAG_COMPRESSED,
            encryption_key: None,
        };
        let payload = vec![0x42u8; 1024];
        let artifact = encoder::encode(&config, &payload, [0u8; 16], &[]).unwrap();
        let decoded = decode(&artifact, None).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_roundtrip_compressed_encrypted() {
        let key = [0xAAu8; 32];
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 512,
            flags: crate::bootstrap::FLAG_COMPRESSED | crate::bootstrap::FLAG_ENCRYPTED,
            encryption_key: Some(key),
        };
        let payload = vec![0x42u8; 1024];
        let artifact = encoder::encode(&config, &payload, [0u8; 16], &[]).unwrap();
        let decoded = decode(&artifact, Some(key)).unwrap();
        assert_eq!(decoded.payload, payload);
    }
}
