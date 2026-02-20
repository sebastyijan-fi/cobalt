/// Family B — Merkle range constraints (§4.2).
///
/// Merkle Tree (Family B) — provides O(log n) range proofs for selective disclosure.
use crate::hash::HashSuite;
use alloc::vec;
use alloc::vec::Vec;

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
    pub fn build(params_hash: &[u8; 32], padded_payloads: &[Vec<u8>], suite: HashSuite) -> Self {
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

        Self::build_from_leaves(&leaves, suite)
    }

    /// Build a Merkle tree from pre-computed leaf hashes.
    pub fn build_from_leaves(leaves: &[[u8; 32]], suite: HashSuite) -> Self {
        let leaf_count = leaves.len();
        if leaf_count == 0 {
            return Self {
                nodes: vec![],
                root: [0u8; 32],
                leaf_count: 0,
            };
        }

        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves.to_vec()];

        // Build tree bottom-up
        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next_level = Vec::with_capacity(current.len().div_ceil(2));

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
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
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
            current = if idx.is_multiple_of(2) {
                compute_node(&current, sibling, suite)
            } else {
                compute_node(sibling, &current, suite)
            };
            idx /= 2;
        }

        // Constant-time comparison
        use subtle::ConstantTimeEq;
        current.ct_eq(root).unwrap_u8() == 1
    }

    /// Get the leaf hashes (for optional footer storage).
    pub fn leaves(&self) -> &[[u8; 32]] {
        if self.nodes.is_empty() {
            &[]
        } else {
            &self.nodes[0]
        }
    }

    /// Generate a range proof for leaves [start..=end].
    pub fn prove_range(&self, start: usize, end: usize) -> Option<RangeProof> {
        if start > end || end >= self.leaf_count || self.nodes.is_empty() {
            return None;
        }

        let mut proof_nodes: Vec<ProofNode> = Vec::new();
        let mut range_start = start;
        let mut range_end = end;

        // Walk up each level, collecting siblings outside the covered range
        for level in 0..self.nodes.len() - 1 {
            let level_nodes = &self.nodes[level];

            // If the range start is odd, we need its left sibling
            if range_start % 2 == 1 {
                proof_nodes.push(ProofNode {
                    level,
                    index: range_start - 1,
                    hash: level_nodes[range_start - 1],
                    side: Side::Left,
                });
            }

            // If the range end is even, we need its right sibling
            if range_end.is_multiple_of(2) {
                if range_end + 1 < level_nodes.len() {
                    proof_nodes.push(ProofNode {
                        level,
                        index: range_end + 1,
                        hash: level_nodes[range_end + 1],
                        side: Side::Right,
                    });
                } else {
                    // Odd node — paired with itself
                    proof_nodes.push(ProofNode {
                        level,
                        index: range_end,
                        hash: level_nodes[range_end],
                        side: Side::Right,
                    });
                }
            }

            // Move to parent level
            range_start /= 2;
            range_end /= 2;
        }

        Some(RangeProof {
            start,
            end,
            leaf_count: self.leaf_count,
            proof_nodes,
        })
    }
}

/// Side indicator for proof nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// A sibling hash in a range proof.
#[derive(Debug, Clone)]
pub struct ProofNode {
    pub level: usize,
    pub index: usize,
    pub hash: [u8; 32],
    pub side: Side,
}

/// A Merkle range proof for a contiguous range of leaves [start..=end].
#[derive(Debug, Clone)]
pub struct RangeProof {
    pub start: usize,
    pub end: usize,
    pub leaf_count: usize,
    pub proof_nodes: Vec<ProofNode>,
}

impl RangeProof {
    /// Verify this range proof against a known root.
    pub fn verify(&self, leaf_hashes: &[[u8; 32]], root: &[u8; 32], suite: HashSuite) -> bool {
        let expected_count = self.end - self.start + 1;
        if leaf_hashes.len() != expected_count {
            return false;
        }

        // Build initial level: leaves with their absolute indices
        let mut current: Vec<(usize, [u8; 32])> = leaf_hashes
            .iter()
            .enumerate()
            .map(|(i, h)| (self.start + i, *h))
            .collect();

        let mut level = 0;
        let mut level_size = self.leaf_count;

        // Walk up the tree until we reach the root
        while level_size > 1 || current.len() != 1 || current[0].0 != 0 {
            // Insert proof nodes for this level
            for pn in &self.proof_nodes {
                if pn.level == level {
                    current.push((pn.index, pn.hash));
                }
            }
            current.sort_by_key(|(idx, _)| *idx);
            current.dedup_by_key(|(idx, _)| *idx);

            // Pair up nodes to compute parent level
            let mut next: Vec<(usize, [u8; 32])> = Vec::new();
            let mut i = 0;
            while i < current.len() {
                let (idx, hash) = current[i];
                let parent_idx = idx / 2;

                if idx % 2 == 0 {
                    // Left child
                    if i + 1 < current.len() && current[i + 1].0 == idx + 1 {
                        // Has right sibling
                        let (_, right) = current[i + 1];
                        next.push((parent_idx, compute_node(&hash, &right, suite)));
                        i += 2;
                    } else if idx + 1 >= level_size {
                        // Last node in an odd-sized level: pair with itself
                        next.push((parent_idx, compute_node(&hash, &hash, suite)));
                        i += 1;
                    } else {
                        // Missing right sibling — proof is incomplete
                        return false;
                    }
                } else {
                    // Right child without preceding left — proof is incomplete
                    return false;
                }
            }

            if next.is_empty() {
                return false;
            }

            level += 1;
            level_size = level_size.div_ceil(2);
            current = next;
        }

        current.len() == 1 && current[0].1 == *root
    }

    /// Encode range proof to bytes for transport.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.start as u32).to_le_bytes());
        buf.extend_from_slice(&(self.end as u32).to_le_bytes());
        buf.extend_from_slice(&(self.leaf_count as u32).to_le_bytes());
        buf.extend_from_slice(&(self.proof_nodes.len() as u32).to_le_bytes());

        for node in &self.proof_nodes {
            buf.extend_from_slice(&(node.level as u16).to_le_bytes());
            buf.extend_from_slice(&(node.index as u32).to_le_bytes());
            buf.push(if node.side == Side::Left { 0 } else { 1 });
            buf.extend_from_slice(&node.hash);
        }

        buf
    }

    /// Decode range proof from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        let start = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let end = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let leaf_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let node_count = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        // CAPACITY BOMB MITIGATION:
        // 1. Check if node_count is within a reasonable upper bound for a binary tree (e.g., 1024).
        // 2. Check if the remaining data is sufficient to contain 'node_count' nodes.
        // Each node is exactly 39 bytes on the wire.
        if node_count > 1024 || 16 + (node_count * 39) > data.len() {
            return None;
        }

        let mut offset = 16;
        let mut proof_nodes = Vec::with_capacity(node_count);

        for _ in 0..node_count {
            if offset + 39 > data.len() {
                return None;
            }
            let level = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let index = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;
            let side = if data[offset] == 0 {
                Side::Left
            } else {
                Side::Right
            };
            offset += 1;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            proof_nodes.push(ProofNode {
                level,
                index,
                hash,
                side,
            });
        }

        Some(RangeProof {
            start,
            end,
            leaf_count,
            proof_nodes,
        })
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
}
