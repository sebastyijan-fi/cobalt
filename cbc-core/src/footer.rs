/// Stream Footer — appears after the last block in a CBC artifact (§5.4).
use crate::error::{CbcError, Result};
use crate::hash::HashSuite;
use alloc::format;
use alloc::vec::Vec;

/// Footer magic bytes: "CBCF" (0x43 0x42 0x43 0x46).
pub const FOOTER_MAGIC: [u8; 4] = [0x43, 0x42, 0x43, 0x46];

/// The fixed portion of the footer (before receipts), without merkle_root.
pub const FOOTER_FIXED_SIZE_A: usize = 4 + 4 + 32 + 4; // magic + length + chain_root + receipt_count = 44
/// With merkle_root (Family B).
pub const FOOTER_FIXED_SIZE_AB: usize = FOOTER_FIXED_SIZE_A + 32; // + merkle_root = 76

/// Footer commitment size.
pub const FOOTER_COMMITMENT_SIZE: usize = 32;

/// Represents the stream footer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFooter {
    pub chain_root: [u8; 32],
    pub merkle_root: Option<[u8; 32]>,
    pub receipt_count: u32,
    pub receipt_slots: Vec<Vec<u8>>, // Raw receipt bytes
    pub footer_commitment: [u8; 32],
}

impl StreamFooter {
    /// Encode the footer to bytes.
    pub fn encode(
        chain_root: [u8; 32],
        merkle_root: Option<[u8; 32]>,
        receipt_slots: &[Vec<u8>],
        params_hash: &[u8; 32],
        suite: HashSuite,
    ) -> Vec<u8> {
        let receipt_count = receipt_slots.len() as u32;

        // Build footer bytes up to (but not including) footer_commitment
        let mut buf = Vec::new();

        // footer_magic
        buf.extend_from_slice(&FOOTER_MAGIC);

        // footer_length — placeholder, we'll fill it at the end
        let length_offset = buf.len();
        buf.extend_from_slice(&0u32.to_le_bytes());

        // chain_root
        buf.extend_from_slice(&chain_root);

        // merkle_root (only if Family B)
        if let Some(mr) = merkle_root {
            buf.extend_from_slice(&mr);
        }

        // receipt_count
        buf.extend_from_slice(&receipt_count.to_le_bytes());

        // receipt_slots
        for receipt in receipt_slots {
            // Each receipt is length-prefixed (u32 LE) for easy parsing
            let len = receipt.len() as u32;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(receipt);
        }

        // Compute footer_commitment over everything so far
        let footer_commitment = suite.hash(&[b"CBC-v1-footer", params_hash.as_slice(), &buf]);

        buf.extend_from_slice(&footer_commitment);

        // Fill in footer_length
        let total_len = buf.len() as u32;
        buf[length_offset..length_offset + 4].copy_from_slice(&total_len.to_le_bytes());

        // Recompute footer_commitment now that length is set
        let commitment_offset = buf.len() - FOOTER_COMMITMENT_SIZE;
        let pre_commitment = &buf[..commitment_offset];
        let footer_commitment =
            suite.hash(&[b"CBC-v1-footer", params_hash.as_slice(), pre_commitment]);
        buf[commitment_offset..].copy_from_slice(&footer_commitment);

        buf
    }

    /// Decode and verify a footer from bytes.
    pub fn decode(
        bytes: &[u8],
        has_merkle: bool,
        params_hash: &[u8; 32],
        suite: HashSuite,
    ) -> Result<Self> {
        let min_size = if has_merkle {
            FOOTER_FIXED_SIZE_AB + FOOTER_COMMITMENT_SIZE
        } else {
            FOOTER_FIXED_SIZE_A + FOOTER_COMMITMENT_SIZE
        };

        if bytes.len() < min_size {
            return Err(CbcError::InsufficientData {
                need: min_size,
                have: bytes.len(),
            });
        }

        let mut offset = 0;

        // footer_magic
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[offset..offset + 4]);
        if magic != FOOTER_MAGIC {
            return Err(CbcError::InvalidFooterMagic);
        }
        offset += 4;

        // footer_length
        let footer_length = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        if bytes.len() < footer_length {
            return Err(CbcError::InsufficientData {
                need: footer_length,
                have: bytes.len(),
            });
        }

        // chain_root
        let mut chain_root = [0u8; 32];
        chain_root.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // merkle_root
        let merkle_root = if has_merkle {
            let mut mr = [0u8; 32];
            mr.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            Some(mr)
        } else {
            None
        };

        // receipt_count
        let receipt_count = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        // Security: Limit receipt count to prevent OOM via Vec::with_capacity.
        // Even 64k receipts is extremely large for any reasonable use case.
        if receipt_count > 65536 {
            return Err(CbcError::msg(format!(
                "receipt count too large: {receipt_count}"
            )));
        }

        // receipt_slots
        let mut receipt_slots = Vec::with_capacity(receipt_count as usize);
        for _ in 0..receipt_count {
            if offset + 4 > footer_length - FOOTER_COMMITMENT_SIZE {
                return Err(CbcError::InsufficientData {
                    need: offset + 4,
                    have: footer_length - FOOTER_COMMITMENT_SIZE,
                });
            }
            let receipt_len = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + receipt_len > footer_length - FOOTER_COMMITMENT_SIZE {
                return Err(CbcError::InsufficientData {
                    need: offset + receipt_len,
                    have: footer_length - FOOTER_COMMITMENT_SIZE,
                });
            }
            receipt_slots.push(bytes[offset..offset + receipt_len].to_vec());
            offset += receipt_len;
        }

        // footer_commitment
        let commitment_offset = footer_length - FOOTER_COMMITMENT_SIZE;
        let mut footer_commitment = [0u8; 32];
        footer_commitment.copy_from_slice(&bytes[commitment_offset..footer_length]);

        // Verify footer_commitment
        let pre_commitment = &bytes[..commitment_offset];
        let expected = suite.hash(&[b"CBC-v1-footer", params_hash.as_slice(), pre_commitment]);

        if expected != footer_commitment {
            return Err(CbcError::FooterCommitmentMismatch);
        }

        Ok(Self {
            chain_root,
            merkle_root,
            receipt_count,
            receipt_slots,
            footer_commitment,
        })
    }

    /// Total encoded size of this footer. Returns None if overflow occurs.
    pub fn encoded_size(&self) -> Option<usize> {
        let mut size: usize = 4 + 4 + 32; // magic + length + chain_root
        if self.merkle_root.is_some() {
            size = size.checked_add(32)?;
        }
        size = size.checked_add(4)?; // receipt_count
        for receipt in &self.receipt_slots {
            size = size.checked_add(4)?.checked_add(receipt.len())?;
        }
        size.checked_add(FOOTER_COMMITMENT_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_footer_roundtrip_no_merkle() {
        let chain_root = [0xAA; 32];
        let params_hash = [0xBB; 32];
        let suite = HashSuite::Blake3;

        let encoded = StreamFooter::encode(chain_root, None, &[], &params_hash, suite);
        let decoded = StreamFooter::decode(&encoded, false, &params_hash, suite).unwrap();

        assert_eq!(decoded.chain_root, chain_root);
        assert_eq!(decoded.merkle_root, None);
        assert_eq!(decoded.receipt_count, 0);
    }

    #[test]
    fn test_footer_roundtrip_with_merkle() {
        let chain_root = [0xAA; 32];
        let merkle_root = [0xCC; 32];
        let params_hash = [0xBB; 32];
        let suite = HashSuite::Blake3;

        let encoded = StreamFooter::encode(chain_root, Some(merkle_root), &[], &params_hash, suite);
        let decoded = StreamFooter::decode(&encoded, true, &params_hash, suite).unwrap();

        assert_eq!(decoded.chain_root, chain_root);
        assert_eq!(decoded.merkle_root, Some(merkle_root));
    }

    #[test]
    fn test_footer_with_receipts() {
        let chain_root = [0xAA; 32];
        let params_hash = [0xBB; 32];
        let suite = HashSuite::Blake3;
        let receipts = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8, 9, 10]];

        let encoded = StreamFooter::encode(chain_root, None, &receipts, &params_hash, suite);
        let decoded = StreamFooter::decode(&encoded, false, &params_hash, suite).unwrap();

        assert_eq!(decoded.receipt_count, 2);
        assert_eq!(decoded.receipt_slots, receipts);
    }

    #[test]
    fn test_footer_commitment_tamper_detected() {
        let chain_root = [0xAA; 32];
        let params_hash = [0xBB; 32];
        let suite = HashSuite::Blake3;

        let mut encoded = StreamFooter::encode(chain_root, None, &[], &params_hash, suite);
        // Tamper with chain_root in the encoded bytes
        encoded[8] ^= 0x01;
        let err = StreamFooter::decode(&encoded, false, &params_hash, suite).unwrap_err();
        assert!(matches!(err, CbcError::FooterCommitmentMismatch));
    }

    #[test]
    fn test_footer_wrong_magic() {
        let mut data = vec![0x00; 100];
        data[0..4].copy_from_slice(b"XXXX");
        let err = StreamFooter::decode(&data, false, &[0; 32], HashSuite::Blake3).unwrap_err();
        assert!(matches!(err, CbcError::InvalidFooterMagic));
    }
}
