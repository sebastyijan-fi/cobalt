/// Block format — the fundamental unit of payload + commitment (§5.3).
use crate::error::{CbcError, Result};

/// Block header size in bytes.
pub const BLOCK_HEADER_SIZE: usize = 16;
/// Commitment size in bytes (32-byte hash output).
pub const COMMITMENT_SIZE: usize = 32;

/// Calculate total wire size of a single block.
pub fn block_wire_size(block_payload_size: u32) -> usize {
    BLOCK_HEADER_SIZE + block_payload_size as usize + COMMITMENT_SIZE
}

/// Block header (16 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub block_index: u32,
    pub payload_length: u32,
    pub block_flags: u32,
    pub local_check: u32, // CRC-32C of payload bytes
}

/// A complete block: header + payload + commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    /// The actual payload bytes (NOT zero-padded; length = header.payload_length).
    pub payload: Vec<u8>,
    /// The commitment hash (32 bytes).
    pub commitment: [u8; 32],
}

impl BlockHeader {
    /// Encode header to 16 bytes.
    pub fn encode(&self) -> [u8; BLOCK_HEADER_SIZE] {
        let mut buf = [0u8; BLOCK_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.block_index.to_le_bytes());
        buf[4..8].copy_from_slice(&self.payload_length.to_le_bytes());
        buf[8..12].copy_from_slice(&self.block_flags.to_le_bytes());
        buf[12..16].copy_from_slice(&self.local_check.to_le_bytes());
        buf
    }

    /// Decode header from 16 bytes.
    pub fn decode(bytes: &[u8; BLOCK_HEADER_SIZE]) -> Self {
        Self {
            block_index: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            payload_length: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            block_flags: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            local_check: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        }
    }
}

impl Block {
    /// Encode a block to its wire format.
    ///
    /// The payload is zero-padded to `block_payload_size`.
    pub fn encode(&self, block_payload_size: u32) -> Vec<u8> {
        let wire_size = block_wire_size(block_payload_size);
        let mut buf = vec![0u8; wire_size];

        // Header (16 bytes)
        buf[..BLOCK_HEADER_SIZE].copy_from_slice(&self.header.encode());

        // Payload (zero-padded)
        let payload_offset = BLOCK_HEADER_SIZE;
        buf[payload_offset..payload_offset + self.payload.len()].copy_from_slice(&self.payload);
        // Rest is already zero-padded

        // Commitment (32 bytes at end)
        let commit_offset = BLOCK_HEADER_SIZE + block_payload_size as usize;
        buf[commit_offset..commit_offset + COMMITMENT_SIZE].copy_from_slice(&self.commitment);

        buf
    }

    /// Decode a block from wire bytes.
    ///
    /// Validates: sequential index, payload_length ≤ block_payload_size,
    /// CRC-32C of the full padded payload, and block_flags == 0.
    pub fn decode(
        bytes: &[u8],
        block_payload_size: u32,
        expected_index: u32,
        is_last: bool,
    ) -> Result<Self> {
        let wire_size = block_wire_size(block_payload_size);
        if bytes.len() < wire_size {
            return Err(CbcError::InsufficientData {
                need: wire_size,
                have: bytes.len(),
            });
        }

        // Parse header
        let mut header_bytes = [0u8; BLOCK_HEADER_SIZE];
        header_bytes.copy_from_slice(&bytes[..BLOCK_HEADER_SIZE]);
        let header = BlockHeader::decode(&header_bytes);

        // Validate block index
        if header.block_index != expected_index {
            return Err(CbcError::BlockIndexMismatch {
                expected: expected_index,
                got: header.block_index,
            });
        }

        // Validate block flags
        if header.block_flags != 0 {
            return Err(CbcError::NonZeroBlockFlags(header.block_flags));
        }

        // Validate payload length
        if header.payload_length > block_payload_size {
            return Err(CbcError::PayloadLengthExceeded {
                length: header.payload_length,
                max: block_payload_size,
            });
        }

        // Non-final blocks must have full payload
        if !is_last && header.payload_length != block_payload_size {
            return Err(CbcError::NonFullPayload {
                index: header.block_index,
                length: header.payload_length,
                expected: block_payload_size,
            });
        }

        // Extract padded payload for CRC and commitment
        let payload_offset = BLOCK_HEADER_SIZE;
        let padded_payload = &bytes[payload_offset..payload_offset + block_payload_size as usize];

        // Verify CRC-32C over padded payload
        let computed_crc = crc32c::crc32c(padded_payload);
        if computed_crc != header.local_check {
            return Err(CbcError::Crc32Mismatch {
                index: header.block_index,
                expected: header.local_check,
                got: computed_crc,
            });
        }

        // Extract actual payload (not padded)
        let payload =
            bytes[payload_offset..payload_offset + header.payload_length as usize].to_vec();

        // Extract commitment
        let commit_offset = BLOCK_HEADER_SIZE + block_payload_size as usize;
        let mut commitment = [0u8; COMMITMENT_SIZE];
        commitment.copy_from_slice(&bytes[commit_offset..commit_offset + COMMITMENT_SIZE]);

        Ok(Self {
            header,
            payload,
            commitment,
        })
    }

    /// Create a new block from payload bytes. Computes CRC-32C over zero-padded payload.
    ///
    /// The `commitment` field is set to all zeros — the caller must fill it via
    /// the chain commitment computation.
    pub fn new(index: u32, payload: Vec<u8>, block_payload_size: u32) -> Self {
        // Build zero-padded payload for CRC
        let mut padded = vec![0u8; block_payload_size as usize];
        padded[..payload.len()].copy_from_slice(&payload);
        let local_check = crc32c::crc32c(&padded);

        Self {
            header: BlockHeader {
                block_index: index,
                payload_length: payload.len() as u32,
                block_flags: 0,
                local_check,
            },
            payload,
            commitment: [0u8; 32],
        }
    }

    /// Returns the zero-padded payload (full block_payload_size).
    pub fn padded_payload(&self, block_payload_size: u32) -> Vec<u8> {
        let mut padded = vec![0u8; block_payload_size as usize];
        padded[..self.payload.len()].copy_from_slice(&self.payload);
        padded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_wire_size() {
        assert_eq!(block_wire_size(512), 512 + 32 + 16);
        assert_eq!(block_wire_size(4096), 4096 + 32 + 16);
    }

    #[test]
    fn test_header_roundtrip() {
        let header = BlockHeader {
            block_index: 42,
            payload_length: 1000,
            block_flags: 0,
            local_check: 0xDEADBEEF,
        };
        let encoded = header.encode();
        let decoded = BlockHeader::decode(&encoded);
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_block_new_computes_crc() {
        let payload = vec![0x42u8; 512];
        let block = Block::new(0, payload.clone(), 512);
        assert_eq!(block.header.block_index, 0);
        assert_eq!(block.header.payload_length, 512);
        assert_ne!(block.header.local_check, 0); // CRC should be computed
    }

    #[test]
    fn test_block_encode_decode_roundtrip() {
        let payload = vec![0xAB; 256];
        let mut block = Block::new(5, payload.clone(), 512);
        block.commitment = [0xFF; 32]; // Set a dummy commitment

        let encoded = block.encode(512);
        assert_eq!(encoded.len(), block_wire_size(512));

        let decoded = Block::decode(&encoded, 512, 5, true).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.commitment, [0xFF; 32]);
        assert_eq!(decoded.header.payload_length, 256);
    }

    #[test]
    fn test_block_wrong_index_rejected() {
        let block = Block::new(0, vec![0u8; 512], 512);
        let encoded = block.encode(512);
        let err = Block::decode(&encoded, 512, 1, false).unwrap_err();
        assert!(matches!(err, CbcError::BlockIndexMismatch { .. }));
    }

    #[test]
    fn test_crc_tamper_detected() {
        let block = Block::new(0, vec![0x42u8; 512], 512);
        let mut encoded = block.encode(512);
        // Flip a payload bit
        encoded[BLOCK_HEADER_SIZE] ^= 0x01;
        let err = Block::decode(&encoded, 512, 0, false).unwrap_err();
        assert!(matches!(err, CbcError::Crc32Mismatch { .. }));
    }
}
