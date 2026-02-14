//! CBC Transform operations (§9).
//!
//! Each transform decodes the source artifact, extracts/transforms the payload,
//! re-encodes with new parameters, and produces a signed receipt.
use crate::error::Result;
use crate::receipt::{self, Receipt, SigningKey, TransformType};
use cbc_core::decoder;
use cbc_core::encoder::{self, EncoderConfig};

/// Get current Unix timestamp in seconds.
fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Helper: extract roots from a decoded artifact.
fn extract_roots(decoded: &decoder::DecodedArtifact) -> ([u8; 32], [u8; 32]) {
    let chain_root = decoded.chain_root;
    let merkle_root = decoded.merkle_root.unwrap_or([0u8; 32]);
    (chain_root, merkle_root)
}

/// Helper: decode, extract roots, re-encode, create receipt.
fn transform_reencode(
    source: &[u8],
    new_payload: &[u8],
    new_config: &EncoderConfig,
    transform_type: TransformType,
    transform_desc: Vec<u8>,
    signing_key: &SigningKey,
    existing_receipts: Vec<Vec<u8>>,
) -> Result<(Vec<u8>, Receipt)> {
    let decoded_source = decoder::decode(source, None)?;
    let (source_chain_root, source_merkle_root) = extract_roots(&decoded_source);

    // Generate new nonce
    let mut nonce = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);

    // Encode the new artifact without receipts first to get the derived root
    let temp_artifact = encoder::encode(new_config, new_payload, nonce, &[])?;
    let decoded_derived = decoder::decode(&temp_artifact, None)?;
    let (derived_chain_root, derived_merkle_root) = extract_roots(&decoded_derived);

    // Create receipt
    let receipt = receipt::create_receipt(
        source_chain_root,
        source_merkle_root,
        derived_chain_root,
        derived_merkle_root,
        transform_type,
        transform_desc,
        now_timestamp(),
        signing_key,
        new_config.hash_suite,
    )?;

    // Now re-encode the artifact with all receipts included
    let mut all_receipts = existing_receipts;
    // Also carry forward source receipts
    for r in &decoded_source.receipt_slots {
        all_receipts.push(r.clone());
    }
    all_receipts.push(receipt.encode());

    let final_artifact = encoder::encode(new_config, new_payload, nonce, &all_receipts)?;

    Ok((final_artifact, receipt))
}

/// T1: Truncation — remove trailing blocks (§9.5).
pub fn truncate(
    source: &[u8],
    keep_blocks: u32,
    signing_key: &SigningKey,
) -> Result<(Vec<u8>, Receipt)> {
    let decoded = decoder::decode(source, None)?;
    let block_payload_size = decoded.bootstrap.block_payload_size;

    if keep_blocks == 0 || keep_blocks >= decoded.block_count {
        return Err(crate::error::TransformError::InvalidTransform(format!(
            "keep_blocks ({keep_blocks}) must be > 0 and < block_count ({})",
            decoded.block_count
        )));
    }

    // Extract payload for kept blocks
    let keep_bytes = (keep_blocks - 1) as usize * block_payload_size as usize;
    let new_payload = if keep_bytes < decoded.payload.len() {
        // Last kept block may be partial
        let full_blocks_payload = keep_bytes;
        let remaining = decoded.payload.len() - full_blocks_payload;
        let last_block_len = remaining.min(block_payload_size as usize);
        decoded.payload[..full_blocks_payload + last_block_len].to_vec()
    } else {
        decoded.payload.clone()
    };

    // Truncate to keep_blocks worth of payload
    let max_bytes = keep_blocks as usize * block_payload_size as usize;
    let truncated_payload = &new_payload[..new_payload.len().min(max_bytes)];

    let config = EncoderConfig {
        hash_suite: decoded.bootstrap.hash_suite,
        commitment_mode: decoded.bootstrap.commitment_mode,
        block_payload_size,
        flags: decoded.bootstrap.flags,
        encryption_key: None,
    };

    let desc = keep_blocks.to_le_bytes().to_vec();
    transform_reencode(
        source,
        truncated_payload,
        &config,
        TransformType::Truncation,
        desc,
        signing_key,
        vec![],
    )
}

/// T2: Rechunk — rewrite with a different block_payload_size (§9.2).
pub fn rechunk(
    source: &[u8],
    new_block_size: u32,
    signing_key: &SigningKey,
) -> Result<(Vec<u8>, Receipt)> {
    let decoded = decoder::decode(source, None)?;

    let mut desc = Vec::new();
    desc.extend_from_slice(&decoded.bootstrap.block_payload_size.to_le_bytes());
    desc.extend_from_slice(&new_block_size.to_le_bytes());

    let config = EncoderConfig {
        hash_suite: decoded.bootstrap.hash_suite,
        commitment_mode: decoded.bootstrap.commitment_mode,
        block_payload_size: new_block_size,
        flags: decoded.bootstrap.flags,
        encryption_key: None,
    };

    transform_reencode(
        source,
        &decoded.payload,
        &config,
        TransformType::Rechunk,
        desc,
        signing_key,
        vec![],
    )
}

/// T3: Recompress — toggle compression flag (§9.3).
///
/// Note: actual compression/decompression is not implemented in v0.1;
/// this toggles the flag and re-encodes (payload bytes unchanged).
pub fn recompress(source: &[u8], signing_key: &SigningKey) -> Result<(Vec<u8>, Receipt)> {
    let decoded = decoder::decode(source, None)?;

    let new_flags = decoded.bootstrap.flags ^ cbc_core::bootstrap::FLAG_COMPRESSED;

    let config = EncoderConfig {
        hash_suite: decoded.bootstrap.hash_suite,
        commitment_mode: decoded.bootstrap.commitment_mode,
        block_payload_size: decoded.bootstrap.block_payload_size,
        flags: new_flags,
        encryption_key: None,
    };

    let desc = new_flags.to_le_bytes().to_vec();
    transform_reencode(
        source,
        &decoded.payload,
        &config,
        TransformType::Recompress,
        desc,
        signing_key,
        vec![],
    )
}

/// T4: Concatenate multiple artifacts (§9.4).
pub fn concatenate(sources: &[&[u8]], signing_key: &SigningKey) -> Result<(Vec<u8>, Vec<Receipt>)> {
    if sources.len() < 2 {
        return Err(crate::error::TransformError::InvalidTransform(
            "concatenation requires at least 2 sources".to_string(),
        ));
    }

    // Decode all sources and collect payloads
    let mut decoded_sources = Vec::new();
    let mut combined_payload = Vec::new();

    for src in sources {
        let decoded = decoder::decode(src, None)?;
        combined_payload.extend_from_slice(&decoded.payload);
        decoded_sources.push(decoded);
    }

    // Use first source's settings for the result
    let first = &decoded_sources[0];
    let config = EncoderConfig {
        hash_suite: first.bootstrap.hash_suite,
        commitment_mode: first.bootstrap.commitment_mode,
        block_payload_size: first.bootstrap.block_payload_size,
        flags: first.bootstrap.flags,
        encryption_key: None,
    };

    // Generate new nonce and encode
    let mut nonce = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);

    let temp = encoder::encode(&config, &combined_payload, nonce, &[])?;
    let decoded_derived = decoder::decode(&temp, None)?;
    let (derived_chain_root, derived_merkle_root) = extract_roots(&decoded_derived);

    // Build transform descriptor with all source roots
    let mut desc = Vec::new();
    for d in &decoded_sources {
        desc.extend_from_slice(&d.chain_root);
    }

    // Create receipts for each source
    let mut receipts = Vec::new();
    let mut receipt_bytes = Vec::new();

    // Carry forward any existing receipts from sources
    for d in &decoded_sources {
        for r in &d.receipt_slots {
            receipt_bytes.push(r.clone());
        }
    }

    for d in &decoded_sources {
        let (src_root, src_merkle) = extract_roots(d);
        let receipt = receipt::create_receipt(
            src_root,
            src_merkle,
            derived_chain_root,
            derived_merkle_root,
            TransformType::Concatenate,
            desc.clone(),
            now_timestamp(),
            signing_key,
            config.hash_suite,
        )?;
        receipt_bytes.push(receipt.encode());
        receipts.push(receipt);
    }

    let final_artifact = encoder::encode(&config, &combined_payload, nonce, &receipt_bytes);

    Ok((final_artifact?, receipts))
}

/// T5: Subrange extraction (§9.1).
pub fn subrange_extract(
    source: &[u8],
    start_block: u32,
    end_block: u32, // inclusive
    signing_key: &SigningKey,
) -> Result<(Vec<u8>, Receipt)> {
    let decoded = decoder::decode(source, None)?;
    let block_payload_size = decoded.bootstrap.block_payload_size;

    if start_block > end_block || end_block >= decoded.block_count {
        return Err(crate::error::TransformError::InvalidTransform(format!(
            "invalid range [{start_block}, {end_block}] for artifact with {} blocks",
            decoded.block_count
        )));
    }

    // Extract the payload for the specified block range
    let start_byte = start_block as usize * block_payload_size as usize;
    let end_byte =
        ((end_block as usize + 1) * block_payload_size as usize).min(decoded.payload.len());
    let new_payload = decoded.payload[start_byte..end_byte].to_vec();

    let config = EncoderConfig {
        hash_suite: decoded.bootstrap.hash_suite,
        commitment_mode: decoded.bootstrap.commitment_mode,
        block_payload_size,
        flags: decoded.bootstrap.flags,
        encryption_key: None,
    };

    // Descriptor: start_block (u32 LE) + end_block (u32 LE)
    let mut desc = Vec::new();
    desc.extend_from_slice(&start_block.to_le_bytes());
    desc.extend_from_slice(&end_block.to_le_bytes());

    transform_reencode(
        source,
        &new_payload,
        &config,
        TransformType::SubrangeExtract,
        desc,
        signing_key,
        vec![],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc_core::bootstrap::FAMILY_A_BIT;

    fn make_test_artifact(payload: &[u8]) -> Vec<u8> {
        let config = EncoderConfig {
            hash_suite: cbc_core::HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 512,
            flags: 0,
            encryption_key: None,
        };
        encoder::encode(&config, payload, [42u8; 16], &[]).unwrap()
    }

    fn test_key() -> SigningKey {
        receipt::generate_ed25519_key()
    }

    #[test]
    fn test_truncate() {
        let payload = vec![0x42u8; 1536]; // 3 blocks at 512
        let artifact = make_test_artifact(&payload);
        let key = test_key();

        let (derived, receipt) = truncate(&artifact, 2, &key).unwrap();

        // Derived artifact is valid
        let decoded = decoder::decode(&derived, None).unwrap();
        assert_eq!(decoded.block_count, 2);
        assert_eq!(decoded.payload.len(), 1024);

        // Roots differ
        let original = decoder::decode(&artifact, None).unwrap();
        assert_ne!(original.chain_root, decoded.chain_root);

        // Receipt verifies
        receipt::verify_receipt(&receipt, cbc_core::HashSuite::Blake3).unwrap();
        assert_eq!(receipt.source_root, original.chain_root);
        assert_eq!(receipt.derived_root, decoded.chain_root);
    }

    #[test]
    fn test_rechunk() {
        let payload = vec![0x42u8; 2048]; // 4 blocks at 512
        let artifact = make_test_artifact(&payload);
        let key = test_key();

        let (derived, receipt) = rechunk(&artifact, 1024, &key).unwrap();

        let decoded = decoder::decode(&derived, None).unwrap();
        assert_eq!(decoded.bootstrap.block_payload_size, 1024);
        assert_eq!(decoded.payload, payload); // Payload unchanged

        receipt::verify_receipt(&receipt, cbc_core::HashSuite::Blake3).unwrap();
    }

    #[test]
    fn test_recompress() {
        let payload = vec![0x42u8; 512];
        let artifact = make_test_artifact(&payload);
        let key = test_key();

        let (derived, receipt) = recompress(&artifact, &key).unwrap();

        let decoded = decoder::decode(&derived, None).unwrap();
        assert!(decoded.bootstrap.flags & cbc_core::bootstrap::FLAG_COMPRESSED != 0);

        receipt::verify_receipt(&receipt, cbc_core::HashSuite::Blake3).unwrap();
    }

    #[test]
    fn test_concatenate() {
        let a1 = make_test_artifact(&vec![0x41u8; 512]);
        let a2 = make_test_artifact(&vec![0x42u8; 512]);
        let key = test_key();

        let (derived, receipts) = concatenate(&[&a1, &a2], &key).unwrap();

        let decoded = decoder::decode(&derived, None).unwrap();
        assert_eq!(decoded.payload.len(), 1024);
        assert_eq!(&decoded.payload[..512], &vec![0x41u8; 512]);
        assert_eq!(&decoded.payload[512..], &vec![0x42u8; 512]);

        assert_eq!(receipts.len(), 2);
        for r in &receipts {
            receipt::verify_receipt(r, cbc_core::HashSuite::Blake3).unwrap();
        }
    }

    #[test]
    fn test_subrange_extract() {
        let payload = vec![0x42u8; 2048]; // 4 blocks
        let artifact = make_test_artifact(&payload);
        let key = test_key();

        let (derived, receipt) = subrange_extract(&artifact, 1, 2, &key).unwrap();

        let decoded = decoder::decode(&derived, None).unwrap();
        assert_eq!(decoded.block_count, 2);
        assert_eq!(decoded.payload.len(), 1024);

        receipt::verify_receipt(&receipt, cbc_core::HashSuite::Blake3).unwrap();
        assert_eq!(receipt.transform_type, TransformType::SubrangeExtract);
    }
}
