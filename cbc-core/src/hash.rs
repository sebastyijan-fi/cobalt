//! Hash suite abstraction for CBC v0.1 (§8.1).
//!
//! CBC supports two hash algorithms, both producing 32-byte digests:
//! - **BLAKE3** (0x01) — default, high-performance
//! - **SHA-256** (0x02) — widely deployed, NIST-approved

/// Hash algorithm identifier (§8.1).
///
/// Used throughout the format for all commitment, chain, and Merkle computations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashSuite {
    Blake3 = 0x01,
    Sha256 = 0x02,
}

impl HashSuite {
    /// Decode a hash suite identifier byte. Returns `None` for unknown IDs.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(Self::Blake3),
            0x02 => Some(Self::Sha256),
            _ => None,
        }
    }

    /// Return the wire-format identifier byte for this hash suite.
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Compute a 32-byte hash over concatenated input slices.
    pub fn hash(self, parts: &[&[u8]]) -> [u8; 32] {
        match self {
            Self::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                for part in parts {
                    hasher.update(part);
                }
                *hasher.finalize().as_bytes()
            }
            Self::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                for part in parts {
                    hasher.update(part);
                }
                let result = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&result);
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suite_ids() {
        assert_eq!(HashSuite::from_id(0x01), Some(HashSuite::Blake3));
        assert_eq!(HashSuite::from_id(0x02), Some(HashSuite::Sha256));
        assert_eq!(HashSuite::from_id(0x00), None);
        assert_eq!(HashSuite::from_id(0xFF), None);
    }

    #[test]
    fn test_blake3_deterministic() {
        let h1 = HashSuite::Blake3.hash(&[b"hello", b" ", b"world"]);
        let h2 = HashSuite::Blake3.hash(&[b"hello world"]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_deterministic() {
        let h1 = HashSuite::Sha256.hash(&[b"hello", b" ", b"world"]);
        let h2 = HashSuite::Sha256.hash(&[b"hello world"]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_suites_differ() {
        let data = b"test data";
        let b3 = HashSuite::Blake3.hash(&[data]);
        let s256 = HashSuite::Sha256.hash(&[data]);
        assert_ne!(b3, s256);
    }
}
