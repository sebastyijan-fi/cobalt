/// Family B — Merkle range constraints (§4.2).
///
/// Blocks become leaves in a binary Merkle tree for random-access verification
/// and partial proofs.

use crate::hash::HashSuite;

/// Compute a Merkle leaf hash.
///
/// leafᵢ = H("CBC-v1-leaf" || params_hash || i_le64 || payloadᵢ)
pub fn compute_leaf(
    params_hash: &[u8; 32],
    index: u64,
    padded_payload: &[u8],
    suite: HashSuite,
) -> [u8; 32] {
    let index_bytes = index.to_le_bytes();
    suite.hash(&[
        b"CBC-v1-leaf",
        params_hash.as_slice(),
        &index_bytes,
        padded_payload,
    ])
}

/// Compute a Merkle internal node.
///
/// nodeⱼ = H("CBC-v1-node" || left_child || right_child)
pub fn compute_node(left: &[u8; 32], right: &[u8; 32], suite: HashSuite) -> [u8; 32] {
    suite.hash(&[b"CBC-v1-node", left.as_slice(), right.as_slice()])
}

/// A binary Merkle tree built from block payloads.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All nodes in the tree, stored level by level.
    /// Level 0 = leaves, last element = root.
    nodes: Vec<Vec<[u8; 32]>>,
    /// The root hash.
    pub root: [u8; 32],
    /// Number of leaves.
    pub leaf_count: usize,
}

/// A Merkle proof for a range of leaves.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The sibling hashes needed to reconstruct the root.
    pub siblings: Vec<(usize, [u8; 32])>, // (level, hash)
    /// The leaf index this proof is for.
    pub leaf_index: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from padded payloads.
    pub fn build(
        params_hash: &[u8; 32],
        padded_payloads: &[Vec<u8>],
        suite: HashSuite,
    ) -> Self {
        if padded_payloads.is_empty() {
            return Self {
                nodes: vec![],
                root: [0u8; 32],
                leaf_count: 0,
            };
        }

        // Compute leaves
        let leaves: Vec<[u8; 32]> = padded_payloads
            .iter()
            .enumerate()
            .map(|(i, payload)| compute_leaf(params_hash, i as u64, payload, suite))
            .collect();

        let leaf_count = leaves.len();
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves];

        // Build tree bottom-up
        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next_level = Vec::with_capacity((current.len() + 1) / 2);

            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next_level.push(compute_node(&current[i], &current[i + 1], suite));
                } else {
                    // Odd node: promote it (hash with itself)
                    next_level.push(compute_node(&current[i], &current[i], suite));
                }
                i += 2;
            }

            levels.push(next_level);
        }

        let root = levels.last().unwrap()[0];

        Self {
            nodes: levels,
            root,
            leaf_count,
        }
    }

    /// Generate a proof for a single leaf.
    pub fn prove(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }

        let mut siblings = Vec::new();
        let mut idx = leaf_index;

        for level in 0..self.nodes.len() - 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < self.nodes[level].len() {
                self.nodes[level][sibling_idx]
            } else {
                // Odd: node is paired with itself
                self.nodes[level][idx]
            };
            siblings.push((level, sibling));
            idx /= 2;
        }

        Some(MerkleProof {
            siblings,
            leaf_index,
        })
    }

    /// Verify a proof against a known root.
    pub fn verify_proof(
        proof: &MerkleProof,
        leaf_hash: [u8; 32],
        root: &[u8; 32],
        suite: HashSuite,
    ) -> bool {
        let mut current = leaf_hash;
        let mut idx = proof.leaf_index;

        for (_level, sibling) in &proof.siblings {
            current = if idx % 2 == 0 {
                compute_node(&current, sibling, suite)
            } else {
                compute_node(sibling, &current, suite)
            };
            idx /= 2;
        }

        current == *root
    }

    /// Get the leaf hashes (for optional footer storage).
    pub fn leaves(&self) -> &[[u8; 32]] {
        if self.nodes.is_empty() {
            &[]
        } else {
            &self.nodes[0]
        }
    }
}

/// Compute the Merkle root directly (without building the full tree).
pub fn compute_merkle_root(
    params_hash: &[u8; 32],
    padded_payloads: &[Vec<u8>],
    suite: HashSuite,
) -> [u8; 32] {
    MerkleTree::build(params_hash, padded_payloads, suite).root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params_hash() -> [u8; 32] {
        [0xAA; 32]
    }

    #[test]
    fn test_single_leaf_tree() {
        let ph = test_params_hash();
        let payloads = vec![vec![0x42u8; 512]];
        let tree = MerkleTree::build(&ph, &payloads, HashSuite::Blake3);
        assert_eq!(tree.leaf_count, 1);
        // Root should equal the single leaf hash
        let expected = compute_leaf(&ph, 0, &payloads[0], HashSuite::Blake3);
        assert_eq!(tree.root, expected);
    }

    #[test]
    fn test_two_leaf_tree() {
        let ph = test_params_hash();
        let payloads = vec![vec![0x42u8; 512], vec![0x43u8; 512]];
        let tree = MerkleTree::build(&ph, &payloads, HashSuite::Blake3);
        assert_eq!(tree.leaf_count, 2);

        let l0 = compute_leaf(&ph, 0, &payloads[0], HashSuite::Blake3);
        let l1 = compute_leaf(&ph, 1, &payloads[1], HashSuite::Blake3);
        let expected_root = compute_node(&l0, &l1, HashSuite::Blake3);
        assert_eq!(tree.root, expected_root);
    }

    #[test]
    fn test_three_leaf_tree() {
        let ph = test_params_hash();
        let payloads = vec![vec![0x42u8; 512], vec![0x43u8; 512], vec![0x44u8; 512]];
        let tree = MerkleTree::build(&ph, &payloads, HashSuite::Blake3);
        assert_eq!(tree.leaf_count, 3);
        // Root is computable
        assert_ne!(tree.root, [0u8; 32]);
    }

    #[test]
    fn test_proof_verification() {
        let ph = test_params_hash();
        let payloads = vec![
            vec![0x42u8; 512],
            vec![0x43u8; 512],
            vec![0x44u8; 512],
            vec![0x45u8; 512],
        ];
        let tree = MerkleTree::build(&ph, &payloads, HashSuite::Blake3);

        for i in 0..4 {
            let proof = tree.prove(i).unwrap();
            let leaf = compute_leaf(&ph, i as u64, &payloads[i], HashSuite::Blake3);
            assert!(
                MerkleTree::verify_proof(&proof, leaf, &tree.root, HashSuite::Blake3),
                "Proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn test_tampered_leaf_proof_fails() {
        let ph = test_params_hash();
        let payloads = vec![vec![0x42u8; 512], vec![0x43u8; 512]];
        let tree = MerkleTree::build(&ph, &payloads, HashSuite::Blake3);
        let proof = tree.prove(0).unwrap();
        // Use wrong leaf hash
        let fake_leaf = [0xFF; 32];
        assert!(!MerkleTree::verify_proof(
            &proof,
            fake_leaf,
            &tree.root,
            HashSuite::Blake3,
        ));
    }

    #[test]
    fn test_deterministic_root() {
        let ph = test_params_hash();
        let payloads = vec![vec![0x42u8; 512], vec![0x43u8; 512]];
        let r1 = compute_merkle_root(&ph, &payloads, HashSuite::Blake3);
        let r2 = compute_merkle_root(&ph, &payloads, HashSuite::Blake3);
        assert_eq!(r1, r2);
    }
}
