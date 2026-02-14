/// Chain commitment logic (Family A).
///
/// Provides integrity and ordering guarantees by chaining block commitments.
use crate::hash::HashSuite;
use alloc::vec::Vec;

/// Compute the initial commitment c₀.
///
/// c₀ = H("CBC-v1" || params_canonical || bootstrap_nonce)
pub fn compute_c0(params_canonical: &[u8; 40], nonce: &[u8; 16], suite: HashSuite) -> [u8; 32] {
    suite.hash(&[b"CBC-v1", params_canonical.as_slice(), nonce.as_slice()])
}

/// Compute commitment cᵢ for block i.
///
/// cᵢ = H("CBC-v1-block" || params_hash || i_le64 || payloadᵢ || cᵢ₋₁)
///
/// `padded_payload` must be the zero-padded payload (full block_payload_size).
pub fn compute_ci(
    params_hash: &[u8; 32],
    index: u64,
    padded_payload: &[u8],
    prev_commitment: &[u8; 32],
    suite: HashSuite,
) -> [u8; 32] {
    let index_bytes = index.to_le_bytes();
    suite.hash(&[
        b"CBC-v1-block",
        params_hash.as_slice(),
        &index_bytes,
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
    padded_payloads: &[Vec<u8>],
    suite: HashSuite,
) -> (Vec<[u8; 32]>, [u8; 32]) {
    let params_hash = compute_params_hash(params_canonical, suite);
    let mut prev = compute_c0(params_canonical, nonce, suite);
    let mut commitments = Vec::with_capacity(padded_payloads.len());

    for (i, payload) in padded_payloads.iter().enumerate() {
        let ci = compute_ci(&params_hash, i as u64, payload, &prev, suite);
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
    padded_payloads: &[Vec<u8>],
    commitments: &[[u8; 32]],
    suite: HashSuite,
) -> crate::error::Result<[u8; 32]> {
    let params_hash = compute_params_hash(params_canonical, suite);
    let mut prev = compute_c0(params_canonical, nonce, suite);

    for (i, (payload, commitment)) in padded_payloads.iter().zip(commitments.iter()).enumerate() {
        let expected = compute_ci(&params_hash, i as u64, payload, &prev, suite);
        if expected != *commitment {
            return Err(crate::error::CbcError::ChainCommitmentMismatch { index: i as u32 });
        }
        prev = expected;
    }

    Ok(prev)
}
