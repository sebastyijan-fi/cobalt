/// Family A — Linear hash-chain constraints (§4.1).
///
/// Provides integrity and ordering guarantees by chaining block commitments.
use crate::hash::HashSuite;

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
///
/// Returns (commitments_vec, chain_root).
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
        prev // c₀ is the root if no blocks
    } else {
        commitments[commitments.len() - 1]
    };

    (commitments, root)
}

/// Verify the chain commitments of a set of blocks.
///
/// Returns Ok(chain_root) if all commitments match, Err otherwise.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> [u8; 40] {
        let mut params = [0u8; 40];
        params[0..4].copy_from_slice(&[0x43, 0x42, 0x43, 0x31]); // CBC1
        params
    }

    #[test]
    fn test_c0_deterministic() {
        let params = test_params();
        let nonce = [0u8; 16];
        let c0a = compute_c0(&params, &nonce, HashSuite::Blake3);
        let c0b = compute_c0(&params, &nonce, HashSuite::Blake3);
        assert_eq!(c0a, c0b);
    }

    #[test]
    fn test_different_nonce_different_c0() {
        let params = test_params();
        let c0a = compute_c0(&params, &[0u8; 16], HashSuite::Blake3);
        let c0b = compute_c0(&params, &[1u8; 16], HashSuite::Blake3);
        assert_ne!(c0a, c0b);
    }

    #[test]
    fn test_chain_single_block() {
        let params = test_params();
        let nonce = [0u8; 16];
        let payloads = vec![vec![0x42u8; 512]];
        let (commitments, root) = compute_chain(&params, &nonce, &payloads, HashSuite::Blake3);
        assert_eq!(commitments.len(), 1);
        assert_eq!(root, commitments[0]);
    }

    #[test]
    fn test_chain_verify_success() {
        let params = test_params();
        let nonce = [0u8; 16];
        let payloads = vec![vec![0x42u8; 512], vec![0x43u8; 512]];
        let (commitments, _root) = compute_chain(&params, &nonce, &payloads, HashSuite::Blake3);
        let result = verify_chain(&params, &nonce, &payloads, &commitments, HashSuite::Blake3);
        assert!(result.is_ok());
    }

    #[test]
    fn test_chain_tamper_detected() {
        let params = test_params();
        let nonce = [0u8; 16];
        let payloads = vec![vec![0x42u8; 512], vec![0x43u8; 512]];
        let (commitments, _root) = compute_chain(&params, &nonce, &payloads, HashSuite::Blake3);

        // Tamper with first payload
        let mut tampered = payloads.clone();
        tampered[0][0] = 0xFF;
        let result = verify_chain(&params, &nonce, &tampered, &commitments, HashSuite::Blake3);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_ordering_matters() {
        let params = test_params();
        let nonce = [0u8; 16];
        let payloads = vec![vec![0x42u8; 512], vec![0x43u8; 512]];
        let (commitments, _) = compute_chain(&params, &nonce, &payloads, HashSuite::Blake3);

        // Swap blocks
        let swapped_payloads = vec![payloads[1].clone(), payloads[0].clone()];
        let swapped_commitments = [commitments[1], commitments[0]];
        let result = verify_chain(
            &params,
            &nonce,
            &swapped_payloads,
            &swapped_commitments,
            HashSuite::Blake3,
        );
        assert!(result.is_err());
    }
}
