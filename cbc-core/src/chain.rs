use crate::block::Block;
use crate::hash::HashSuite;
use alloc::vec::Vec;

/// Compute the initial commitment c₀.
///
/// c₀ = H("CBC-v1" || params_canonical || bootstrap_nonce)
pub fn compute_c0(params_canonical: &[u8; 40], nonce: &[u8; 16], suite: HashSuite) -> [u8; 32] {
    suite.hash(&[b"CBC-v1", params_canonical.as_slice(), nonce.as_slice()])
}

/// cᵢ = H("CBC-v1-block" || params_hash || header_bytes || padded_payload || cᵢ₋₁)
///
/// `header_bytes` is the 16-byte encoded block header.
/// `padded_payload` must be the zero-padded payload (full block_payload_size).
pub fn compute_ci(
    params_hash: &[u8; 32],
    header_bytes: &[u8; 16],
    padded_payload: &[u8],
    prev_commitment: &[u8; 32],
    suite: HashSuite,
) -> [u8; 32] {
    suite.hash(&[
        b"CBC-v1-block",
        params_hash.as_slice(),
        header_bytes,
        padded_payload,
        prev_commitment.as_slice(),
    ])
}

/// Compute the params_hash used in block commitments.
///
/// params_hash = H(params_canonical)
pub fn compute_params_hash(params_canonical: &[u8; 40], suite: HashSuite) -> [u8; 32] {
    suite.hash(&[params_canonical.as_slice()])
}

/// Compute commitments for all blocks, returning the commitment for each block
/// and the final chain root.
pub fn compute_chain(
    params_canonical: &[u8; 40],
    nonce: &[u8; 16],
    blocks: &[Block],
    block_payload_size: u32,
    suite: HashSuite,
) -> (Vec<[u8; 32]>, [u8; 32]) {
    let params_hash = compute_params_hash(params_canonical, suite);
    let mut prev = compute_c0(params_canonical, nonce, suite);
    let mut commitments = Vec::with_capacity(blocks.len());

    for block in blocks {
        let header_bytes = block.header.encode();
        let padded = block.padded_payload(block_payload_size);
        let ci = compute_ci(&params_hash, &header_bytes, &padded, &prev, suite);
        commitments.push(ci);
        prev = ci;
    }

    let root = if commitments.is_empty() {
        prev
    } else {
        commitments[commitments.len() - 1]
    };

    (commitments, root)
}

/// Verify the chain commitments of a set of blocks.
pub fn verify_chain(
    params_canonical: &[u8; 40],
    nonce: &[u8; 16],
    blocks: &[Block],
    block_payload_size: u32,
    suite: HashSuite,
) -> crate::error::Result<[u8; 32]> {
    let params_hash = compute_params_hash(params_canonical, suite);
    let mut prev = compute_c0(params_canonical, nonce, suite);

    for (i, block) in blocks.iter().enumerate() {
        let header_bytes = block.header.encode();
        let padded = block.padded_payload(block_payload_size);
        let expected = compute_ci(&params_hash, &header_bytes, &padded, &prev, suite);
        // Constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        if expected.ct_eq(&block.commitment).unwrap_u8() == 0 {
            return Err(crate::error::CbcError::ChainCommitmentMismatch { index: i as u32 });
        }
        prev = expected;
    }

    Ok(prev)
}
