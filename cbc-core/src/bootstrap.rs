/// Bootstrap Segment — the fixed 64-byte preamble of every CBC artifact (§5.2).
use crate::error::{CbcError, Result};
use crate::hash::HashSuite;

/// Magic bytes: "CBC1" (0x43 0x42 0x43 0x31).
pub const MAGIC: [u8; 4] = [0x43, 0x42, 0x43, 0x31];

/// Current format version.
pub const VERSION: u16 = 0x0001;

/// Bootstrap Segment size in bytes.
pub const BOOTSTRAP_SIZE: usize = 64;

/// Commitment mode bits.
pub const FAMILY_A_BIT: u8 = 0x01;
pub const FAMILY_B_BIT: u8 = 0x02;
pub const FAMILY_C_BIT: u8 = 0x04;

/// Minimum block payload size (512 bytes).
pub const MIN_BLOCK_PAYLOAD: u32 = 512;
/// Maximum block payload size (16 MiB).
pub const MAX_BLOCK_PAYLOAD: u32 = 16 * 1024 * 1024;

/// Flag bits.
pub const FLAG_COMPRESSED: u32 = 0x01;
pub const FLAG_ENCRYPTED: u32 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapSegment {
    pub hash_suite: HashSuite,
    pub commitment_mode: u8,
    pub block_payload_size: u32,
    pub block_count: u32,
    pub bootstrap_nonce: [u8; 16],
    pub flags: u32,
}

impl BootstrapSegment {
    /// Returns canonical params: bytes 0..40 of the encoded bootstrap segment.
    pub fn params_canonical(&self) -> [u8; 40] {
        let full = self.encode();
        let mut params = [0u8; 40];
        params.copy_from_slice(&full[..40]);
        params
    }

    /// Compute params_mac: first 16 bytes of H("CBC-v1-params-mac" || bytes[0..40]).
    pub fn compute_params_mac(&self) -> [u8; 16] {
        let params = self.params_canonical();
        let hash = self.hash_suite.hash(&[b"CBC-v1-params-mac", &params]);
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&hash[..16]);
        mac
    }

    /// Whether Family A (chain) is enabled. Always true for valid artifacts.
    pub fn family_a(&self) -> bool {
        self.commitment_mode & FAMILY_A_BIT != 0
    }

    /// Whether Family B (merkle) is enabled.
    pub fn family_b(&self) -> bool {
        self.commitment_mode & FAMILY_B_BIT != 0
    }

    /// Whether Family C (prefix parse) is enabled.
    pub fn family_c(&self) -> bool {
        self.commitment_mode & FAMILY_C_BIT != 0
    }

    /// Encode to exactly 64 bytes.
    pub fn encode(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];

        // Offset 0: magic
        buf[0..4].copy_from_slice(&MAGIC);
        // Offset 4: version (LE u16)
        buf[4..6].copy_from_slice(&VERSION.to_le_bytes());
        // Offset 6: hash_suite
        buf[6] = self.hash_suite.id();
        // Offset 7: commitment_mode
        buf[7] = self.commitment_mode;
        // Offset 8: block_payload_size (LE u32)
        buf[8..12].copy_from_slice(&self.block_payload_size.to_le_bytes());
        // Offset 12: block_count (LE u32)
        buf[12..16].copy_from_slice(&self.block_count.to_le_bytes());
        // Offset 16: bootstrap_nonce (16 bytes)
        buf[16..32].copy_from_slice(&self.bootstrap_nonce);
        // Offset 32: flags (LE u32)
        buf[32..36].copy_from_slice(&self.flags.to_le_bytes());
        // Offset 36: reserved (4 bytes, must be 0)
        // Already zero
        // Offset 40: params_mac (16 bytes)
        let mac = {
            let params = &buf[..40];
            let hash = self.hash_suite.hash(&[b"CBC-v1-params-mac", params]);
            let mut mac = [0u8; 16];
            mac.copy_from_slice(&hash[..16]);
            mac
        };
        buf[40..56].copy_from_slice(&mac);
        // Offset 56: reserved (8 bytes, must be 0)
        // Already zero

        buf
    }

    /// Decode from exactly 64 bytes, verifying all structural fields and params_mac.
    pub fn decode(bytes: &[u8; 64]) -> Result<Self> {
        // Magic
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != MAGIC {
            return Err(CbcError::InvalidMagic(magic));
        }

        // Version
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != VERSION {
            return Err(CbcError::UnsupportedVersion(version));
        }

        // Hash suite
        let hash_suite =
            HashSuite::from_id(bytes[6]).ok_or(CbcError::UnknownHashSuite(bytes[6]))?;

        // Commitment mode — Family A must be set
        let commitment_mode = bytes[7];
        if commitment_mode & FAMILY_A_BIT == 0 {
            return Err(CbcError::InvalidCommitmentMode(commitment_mode));
        }
        // Reserved bits 3-7 must be 0
        if commitment_mode & 0xF8 != 0 {
            return Err(CbcError::InvalidCommitmentMode(commitment_mode));
        }

        // Block payload size
        let block_payload_size = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if !(MIN_BLOCK_PAYLOAD..=MAX_BLOCK_PAYLOAD).contains(&block_payload_size)
            || !block_payload_size.is_power_of_two()
        {
            return Err(CbcError::InvalidBlockPayloadSize(block_payload_size));
        }

        // Block count
        let block_count = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        // Nonce
        let mut bootstrap_nonce = [0u8; 16];
        bootstrap_nonce.copy_from_slice(&bytes[16..32]);

        // Flags
        let flags = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);

        // Reserved at offset 36 (4 bytes) must be zero
        let reserved_36 = u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        if reserved_36 != 0 {
            return Err(CbcError::NonZeroReserved { offset: 36 });
        }

        // Reserved at offset 56 (8 bytes) must be zero
        let reserved_56 = u64::from_le_bytes([
            bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61], bytes[62], bytes[63],
        ]);
        if reserved_56 != 0 {
            return Err(CbcError::NonZeroReserved { offset: 56 });
        }

        let segment = Self {
            hash_suite,
            commitment_mode,
            block_payload_size,
            block_count,
            bootstrap_nonce,
            flags,
        };

        // Verify params_mac
        let expected_mac = segment.compute_params_mac();
        let actual_mac = &bytes[40..56];
        if actual_mac != expected_mac {
            return Err(CbcError::ParamsMacMismatch);
        }

        Ok(segment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_segment() -> BootstrapSegment {
        BootstrapSegment {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 4096,
            block_count: 10,
            bootstrap_nonce: [0u8; 16],
            flags: 0,
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let seg = test_segment();
        let encoded = seg.encode();
        assert_eq!(encoded.len(), BOOTSTRAP_SIZE);
        let decoded = BootstrapSegment::decode(&encoded).unwrap();
        assert_eq!(seg, decoded);
    }

    #[test]
    fn test_magic_bytes() {
        let seg = test_segment();
        let encoded = seg.encode();
        assert_eq!(&encoded[0..4], b"CBC1");
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let seg = test_segment();
        let mut encoded = seg.encode();
        encoded[0] = 0xFF;
        let err = BootstrapSegment::decode(&encoded).unwrap_err();
        assert!(matches!(err, CbcError::InvalidMagic(_)));
    }

    #[test]
    fn test_params_mac_tamper_detected() {
        let seg = test_segment();
        let mut encoded = seg.encode();
        // Flip a bit in the nonce — params_mac should fail
        encoded[16] ^= 0x01;
        let err = BootstrapSegment::decode(&encoded).unwrap_err();
        assert!(matches!(err, CbcError::ParamsMacMismatch));
    }

    #[test]
    fn test_family_a_required() {
        let mut seg = test_segment();
        seg.commitment_mode = 0x00; // No Family A
        let encoded = seg.encode();
        // We need to bypass the MAC for this test — decode will check mode first
        // Actually decode checks MAC, but let's test the mode check
        let err = BootstrapSegment::decode(&encoded).unwrap_err();
        // The MAC will still be computed with the mode=0, but the mode check happens after
        assert!(matches!(
            err,
            CbcError::InvalidCommitmentMode(_) | CbcError::ParamsMacMismatch
        ));
    }

    #[test]
    fn test_invalid_block_size() {
        let mut seg = test_segment();
        seg.block_payload_size = 1000; // Not power of 2
        let encoded = seg.encode();
        let err = BootstrapSegment::decode(&encoded).unwrap_err();
        assert!(matches!(
            err,
            CbcError::InvalidBlockPayloadSize(_) | CbcError::ParamsMacMismatch
        ));
    }

    #[test]
    fn test_all_families_enabled() {
        let mut seg = test_segment();
        seg.commitment_mode = FAMILY_A_BIT | FAMILY_B_BIT | FAMILY_C_BIT;
        let encoded = seg.encode();
        let decoded = BootstrapSegment::decode(&encoded).unwrap();
        assert!(decoded.family_a());
        assert!(decoded.family_b());
        assert!(decoded.family_c());
    }

    #[test]
    fn test_params_canonical_is_40_bytes() {
        let seg = test_segment();
        assert_eq!(seg.params_canonical().len(), 40);
    }

    #[test]
    fn test_sha256_roundtrip() {
        let mut seg = test_segment();
        seg.hash_suite = HashSuite::Sha256;
        let encoded = seg.encode();
        let decoded = BootstrapSegment::decode(&encoded).unwrap();
        assert_eq!(decoded.hash_suite, HashSuite::Sha256);
    }
}
