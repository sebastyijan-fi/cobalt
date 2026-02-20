use crate::error::{CbcError, Result};
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

/// Block header size in bytes.
pub const BLOCK_HEADER_SIZE: usize = 16;
/// Commitment size in bytes (32-byte hash output).
pub const COMMITMENT_SIZE: usize = 32;

/// Calculate total wire size of a single block. Returns None if overflow occurs.
pub fn block_wire_size(block_payload_size: u32) -> Option<usize> {
    BLOCK_HEADER_SIZE
        .checked_add(block_payload_size as usize)?
        .checked_add(COMMITMENT_SIZE)
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
    pub fn encode(&self, block_payload_size: u32) -> Vec<u8> {
        let wire_size =
            block_wire_size(block_payload_size).expect("block size too large for platform");
        let mut buf = vec![0u8; wire_size];

        buf[..BLOCK_HEADER_SIZE].copy_from_slice(&self.header.encode());

        let payload_offset = BLOCK_HEADER_SIZE;
        buf[payload_offset..payload_offset + self.payload.len()].copy_from_slice(&self.payload);

        let commit_offset = BLOCK_HEADER_SIZE + block_payload_size as usize;
        buf[commit_offset..commit_offset + COMMITMENT_SIZE].copy_from_slice(&self.commitment);

        buf
    }

    /// Decode a block from wire bytes.
    pub fn decode(
        bytes: &[u8],
        block_payload_size: u32,
        expected_index: u32,
        is_last: bool,
    ) -> Result<Self> {
        let wire_size = block_wire_size(block_payload_size).ok_or_else(|| {
            CbcError::msg(format!(
                "block size {block_payload_size} too large for platform"
            ))
        })?;
        if bytes.len() < wire_size {
            return Err(CbcError::InsufficientData {
                need: wire_size,
                have: bytes.len(),
            });
        }

        let mut header_bytes = [0u8; BLOCK_HEADER_SIZE];
        header_bytes.copy_from_slice(&bytes[..BLOCK_HEADER_SIZE]);
        let header = BlockHeader::decode(&header_bytes);

        if header.block_index != expected_index {
            return Err(CbcError::BlockIndexMismatch {
                expected: expected_index,
                got: header.block_index,
            });
        }

        if header.block_flags != 0 {
            return Err(CbcError::NonZeroBlockFlags(header.block_flags));
        }

        if header.payload_length > block_payload_size {
            return Err(CbcError::PayloadLengthExceeded {
                length: header.payload_length,
                max: block_payload_size,
            });
        }

        if !is_last && header.payload_length != block_payload_size {
            return Err(CbcError::NonFullPayload {
                index: header.block_index,
                length: header.payload_length,
                expected: block_payload_size,
            });
        }

        let payload_offset = BLOCK_HEADER_SIZE;
        let padded_payload = &bytes[payload_offset..payload_offset + block_payload_size as usize];

        let computed_crc = crc32c::crc32c(padded_payload);
        if computed_crc != header.local_check {
            return Err(CbcError::Crc32Mismatch {
                index: header.block_index,
                expected: header.local_check,
                got: computed_crc,
            });
        }

        let payload =
            bytes[payload_offset..payload_offset + header.payload_length as usize].to_vec();

        let commit_offset = BLOCK_HEADER_SIZE + block_payload_size as usize;
        let mut commitment = [0u8; COMMITMENT_SIZE];
        commitment.copy_from_slice(&bytes[commit_offset..commit_offset + COMMITMENT_SIZE]);

        Ok(Self {
            header,
            payload,
            commitment,
        })
    }

    /// Create a new block from payload bytes.
    pub fn new(index: u32, payload: Vec<u8>, block_payload_size: u32) -> Self {
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

    /// Encrypt the block payload using AES-GCM-256.
    pub fn encrypt(
        &mut self,
        key: &[u8; 32],
        bootstrap_nonce: &[u8; 16],
        block_payload_size: u32,
    ) -> Result<()> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm,
        };

        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&bootstrap_nonce[..12]);
        let index_bytes = self.header.block_index.to_le_bytes();
        for i in 0..4 {
            nonce_bytes[i] ^= index_bytes[i];
        }
        let nonce = nonce_bytes.as_ref().into();

        let ciphertext = cipher
            .encrypt(nonce, self.payload.as_slice())
            .map_err(|e: aes_gcm::Error| CbcError::EncryptionError(e.to_string()))?;

        self.payload = ciphertext;
        self.header.payload_length = self.payload.len() as u32;

        let padded = self.padded_payload(block_payload_size);
        self.header.local_check = crc32c::crc32c(&padded);

        Ok(())
    }

    /// Decrypt the block payload using AES-GCM-256.
    pub fn decrypt(
        &mut self,
        key: &[u8; 32],
        bootstrap_nonce: &[u8; 16],
        block_payload_size: u32,
    ) -> Result<()> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm,
        };

        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&bootstrap_nonce[..12]);
        let index_bytes = self.header.block_index.to_le_bytes();
        for i in 0..4 {
            nonce_bytes[i] ^= index_bytes[i];
        }
        let nonce = nonce_bytes.as_ref().into();

        let plaintext = cipher
            .decrypt(nonce, self.payload.as_slice())
            .map_err(|e: aes_gcm::Error| CbcError::DecryptionError(e.to_string()))?;

        self.payload = plaintext;
        self.header.payload_length = self.payload.len() as u32;

        let padded = self.padded_payload(block_payload_size);
        self.header.local_check = crc32c::crc32c(&padded);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_wire_size() {
        assert_eq!(block_wire_size(512).unwrap(), 512 + 32 + 16);
    }

    #[test]
    fn test_block_encryption_tamper() {
        let mut block = Block::new(0, b"SECRET".to_vec(), 32);
        let key = [1u8; 32];
        let nonce = [2u8; 16];

        // Encrypt
        block.encrypt(&key, &nonce, 32).unwrap();
        // Decrypt (valid)
        let mut block_valid = block.clone();
        block_valid.decrypt(&key, &nonce, 32).unwrap();
        assert_eq!(block_valid.payload, b"SECRET");

        // Tamper ciphertext
        let mut block_tampered = block.clone();
        block_tampered.payload[0] ^= 0x01;

        // Decrypt (invalid)
        let result = block_tampered.decrypt(&key, &nonce, 32);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decryption error"));
    }
}
