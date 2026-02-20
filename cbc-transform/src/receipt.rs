//! CBC Transform Receipts — signed proof of derivation (§6).
use crate::error::{Result, TransformError};

/// Transform type codes (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TransformType {
    Unspecified = 0x0000,
    Truncation = 0x0001,
    Rechunk = 0x0002,
    Recompress = 0x0003,
    Concatenate = 0x0004,
    SubrangeExtract = 0x0005,
    Encrypt = 0x0006,
    Decrypt = 0x0007,
    Custom = 0x0008,
}

impl TransformType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0000 => Some(Self::Unspecified),
            0x0001 => Some(Self::Truncation),
            0x0002 => Some(Self::Rechunk),
            0x0003 => Some(Self::Recompress),
            0x0004 => Some(Self::Concatenate),
            0x0005 => Some(Self::SubrangeExtract),
            0x0006 => Some(Self::Encrypt),
            0x0007 => Some(Self::Decrypt),
            0x0008 => Some(Self::Custom),
            _ => None,
        }
    }
}

/// Signature algorithm IDs (§8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigAlgorithm {
    EcdsaP256Sha256 = 0x01,
    Ed25519 = 0x02,
}

impl SigAlgorithm {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::EcdsaP256Sha256),
            0x02 => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// A transform receipt (§6.2).
#[derive(Debug, Clone)]
pub struct Receipt {
    pub receipt_version: u16,
    pub sig_alg: SigAlgorithm,
    pub source_root: [u8; 32],
    pub source_merkle_root: [u8; 32],
    pub derived_root: [u8; 32],
    pub derived_merkle_root: [u8; 32],
    pub timestamp: u64,
    pub transform_type: TransformType,
    pub transform_desc: Vec<u8>,
    pub signer_id: Vec<u8>,
    pub sig_bytes: Vec<u8>,
}

impl Receipt {
    /// Encode receipt to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        buf.extend_from_slice(&self.receipt_version.to_le_bytes());
        buf.push(self.sig_alg as u8);
        buf.push(0x00); // reserved
        buf.extend_from_slice(&self.source_root);
        buf.extend_from_slice(&self.source_merkle_root);
        buf.extend_from_slice(&self.derived_root);
        buf.extend_from_slice(&self.derived_merkle_root);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&(self.transform_type as u16).to_le_bytes());
        buf.extend_from_slice(&(self.transform_desc.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.transform_desc);
        buf.extend_from_slice(&(self.signer_id.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.signer_id);
        buf.extend_from_slice(&(self.sig_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.sig_bytes);

        buf
    }

    /// Decode receipt from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 144 {
            return Err(TransformError::InvalidTransform(
                "receipt too short".to_string(),
            ));
        }

        let mut offset = 0;

        let receipt_version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let sig_alg = SigAlgorithm::from_u8(data[offset]).ok_or_else(|| {
            TransformError::InvalidTransform(format!(
                "unknown sig algorithm: 0x{:02x}",
                data[offset]
            ))
        })?;
        offset += 1;

        // reserved
        offset += 1;

        let mut source_root = [0u8; 32];
        source_root.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut source_merkle_root = [0u8; 32];
        source_merkle_root.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut derived_root = [0u8; 32];
        derived_root.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut derived_merkle_root = [0u8; 32];
        derived_merkle_root.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let timestamp = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        let transform_type_raw = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let transform_type = TransformType::from_u16(transform_type_raw).ok_or_else(|| {
            TransformError::InvalidTransform(format!(
                "unknown transform type: 0x{transform_type_raw:04x}"
            ))
        })?;
        offset += 2;

        let transform_desc_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + transform_desc_len > data.len() {
            return Err(TransformError::InvalidTransform(
                "transform descriptor truncated".to_string(),
            ));
        }
        let transform_desc = data[offset..offset + transform_desc_len].to_vec();
        offset += transform_desc_len;

        if offset + 2 > data.len() {
            return Err(TransformError::InvalidTransform(
                "signer_id length truncated".to_string(),
            ));
        }
        let signer_id_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + signer_id_len > data.len() {
            return Err(TransformError::InvalidTransform(
                "signer_id truncated".to_string(),
            ));
        }
        let signer_id = data[offset..offset + signer_id_len].to_vec();
        offset += signer_id_len;

        if offset + 2 > data.len() {
            return Err(TransformError::InvalidTransform(
                "sig_len truncated".to_string(),
            ));
        }
        let sig_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + sig_len > data.len() {
            return Err(TransformError::InvalidTransform(
                "signature truncated".to_string(),
            ));
        }
        let sig_bytes = data[offset..offset + sig_len].to_vec();

        Ok(Self {
            receipt_version,
            sig_alg,
            source_root,
            source_merkle_root,
            derived_root,
            derived_merkle_root,
            timestamp,
            transform_type,
            transform_desc,
            signer_id,
            sig_bytes,
        })
    }

    /// Get the receipt body bytes (everything before sig_len) for signing/verification.
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.receipt_version.to_le_bytes());
        buf.push(self.sig_alg as u8);
        buf.push(0x00);
        buf.extend_from_slice(&self.source_root);
        buf.extend_from_slice(&self.source_merkle_root);
        buf.extend_from_slice(&self.derived_root);
        buf.extend_from_slice(&self.derived_merkle_root);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&(self.transform_type as u16).to_le_bytes());
        buf.extend_from_slice(&(self.transform_desc.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.transform_desc);
        buf.extend_from_slice(&(self.signer_id.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.signer_id);

        buf
    }

    /// Compute the receipt body hash using the artifact's hash suite.
    pub fn body_hash(&self, suite: cbc_core::HashSuite) -> [u8; 32] {
        let body = self.body_bytes();
        suite.hash(&[b"CBC-v1-receipt", &body])
    }
}

/// Signing key abstraction.
pub enum SigningKey {
    EcdsaP256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl SigningKey {
    /// Get the public key bytes for this signing key.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            SigningKey::EcdsaP256(key) => key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            SigningKey::Ed25519(key) => key.verifying_key().to_bytes().to_vec(),
        }
    }

    /// Sign a body hash, returning the signature bytes.
    pub fn sign_hash(&self, body_hash: &[u8; 32]) -> Result<Vec<u8>> {
        match self {
            SigningKey::EcdsaP256(key) => {
                use p256::ecdsa::{signature::Signer, Signature};
                let sig: Signature = key.sign(body_hash);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            SigningKey::Ed25519(key) => {
                use ed25519_dalek::Signer;
                let sig = key.sign(body_hash);
                Ok(sig.to_bytes().to_vec())
            }
        }
    }

    /// Get the signature algorithm.
    pub fn algorithm(&self) -> SigAlgorithm {
        match self {
            SigningKey::EcdsaP256(_) => SigAlgorithm::EcdsaP256Sha256,
            SigningKey::Ed25519(_) => SigAlgorithm::Ed25519,
        }
    }
}

/// Create and sign a receipt for a transform.
#[allow(clippy::too_many_arguments)]
pub fn create_receipt(
    source_root: [u8; 32],
    source_merkle_root: [u8; 32],
    derived_root: [u8; 32],
    derived_merkle_root: [u8; 32],
    transform_type: TransformType,
    transform_desc: Vec<u8>,
    timestamp: u64,
    signing_key: &SigningKey,
    hash_suite: cbc_core::HashSuite,
) -> Result<Receipt> {
    let sig_alg = signing_key.algorithm();
    // Get public key bytes FIRST so body_hash includes them
    let pub_bytes = signing_key.public_key_bytes();

    let mut receipt = Receipt {
        receipt_version: 0x0001,
        sig_alg,
        source_root,
        source_merkle_root,
        derived_root,
        derived_merkle_root,
        timestamp,
        transform_type,
        transform_desc,
        signer_id: pub_bytes,
        sig_bytes: Vec::new(),
    };

    // Now body_hash is computed with signer_id populated
    let body_hash = receipt.body_hash(hash_suite);
    let sig_bytes = signing_key.sign_hash(&body_hash)?;
    receipt.sig_bytes = sig_bytes;

    Ok(receipt)
}

/// Create and sign a receipt for a transform using an enterprise KMS.
#[allow(clippy::too_many_arguments)]
pub async fn create_kms_receipt(
    source_root: [u8; 32],
    source_merkle_root: [u8; 32],
    derived_root: [u8; 32],
    derived_merkle_root: [u8; 32],
    transform_type: TransformType,
    transform_desc: Vec<u8>,
    timestamp: u64,
    kms_signer: &dyn cbc_kms::KmsSigner,
    key_id: &str,
    signer_public_key: Vec<u8>,
    sig_alg: SigAlgorithm,
    hash_suite: cbc_core::HashSuite,
) -> Result<Receipt> {
    let mut receipt = Receipt {
        receipt_version: 0x0001,
        sig_alg,
        source_root,
        source_merkle_root,
        derived_root,
        derived_merkle_root,
        timestamp,
        transform_type,
        transform_desc,
        signer_id: signer_public_key,
        sig_bytes: Vec::new(),
    };

    let body_hash = receipt.body_hash(hash_suite);

    // Call the KMS to sign the hash
    let sig_bytes = kms_signer
        .sign(key_id, &body_hash)
        .await
        .map_err(|e| TransformError::ReceiptGenerationError(format!("KMS sign failed: {}", e)))?;

    receipt.sig_bytes = sig_bytes;

    Ok(receipt)
}

/// Verify a receipt's signature.
pub fn verify_receipt(receipt: &Receipt, hash_suite: cbc_core::HashSuite) -> Result<()> {
    let body_hash = receipt.body_hash(hash_suite);

    match receipt.sig_alg {
        SigAlgorithm::EcdsaP256Sha256 => {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            use p256::EncodedPoint;

            let point = EncodedPoint::from_bytes(&receipt.signer_id).map_err(|e| {
                TransformError::VerificationError(format!("invalid public key: {e}"))
            })?;
            let verifying_key = VerifyingKey::from_encoded_point(&point).map_err(|e| {
                TransformError::VerificationError(format!("invalid public key: {e}"))
            })?;
            let sig = Signature::from_der(&receipt.sig_bytes).map_err(|e| {
                TransformError::VerificationError(format!("invalid signature: {e}"))
            })?;

            verifying_key.verify(&body_hash, &sig).map_err(|e| {
                TransformError::VerificationError(format!("signature verification failed: {e}"))
            })?;
        }
        SigAlgorithm::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};

            let pub_bytes: [u8; 32] = receipt.signer_id.as_slice().try_into().map_err(|_| {
                TransformError::VerificationError("invalid Ed25519 public key length".to_string())
            })?;
            let verifying_key = VerifyingKey::from_bytes(&pub_bytes).map_err(|e| {
                TransformError::VerificationError(format!("invalid public key: {e}"))
            })?;
            let sig_bytes: [u8; 64] = receipt.sig_bytes.as_slice().try_into().map_err(|_| {
                TransformError::VerificationError("invalid Ed25519 signature length".to_string())
            })?;
            let sig = Signature::from_bytes(&sig_bytes);

            verifying_key.verify(&body_hash, &sig).map_err(|e| {
                TransformError::VerificationError(format!("signature verification failed: {e}"))
            })?;
        }
    }

    Ok(())
}

/// Generate an Ed25519 signing key pair.
pub fn generate_ed25519_key() -> SigningKey {
    use rand::rngs::OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    SigningKey::Ed25519(key)
}

/// Generate an ECDSA P-256 signing key pair.
pub fn generate_ecdsa_key() -> SigningKey {
    use rand::rngs::OsRng;
    let key = p256::ecdsa::SigningKey::random(&mut OsRng);
    SigningKey::EcdsaP256(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_encode_decode_roundtrip() {
        let receipt = Receipt {
            receipt_version: 1,
            sig_alg: SigAlgorithm::Ed25519,
            source_root: [0xAA; 32],
            source_merkle_root: [0x00; 32],
            derived_root: [0xBB; 32],
            derived_merkle_root: [0x00; 32],
            timestamp: 1234567890,
            transform_type: TransformType::Truncation,
            transform_desc: vec![1, 2, 3],
            signer_id: vec![0xFF; 32],
            sig_bytes: vec![0xDD; 64],
        };

        let encoded = receipt.encode();
        let decoded = Receipt::decode(&encoded).unwrap();

        assert_eq!(decoded.receipt_version, 1);
        assert_eq!(decoded.source_root, [0xAA; 32]);
        assert_eq!(decoded.derived_root, [0xBB; 32]);
        assert_eq!(decoded.transform_type, TransformType::Truncation);
        assert_eq!(decoded.transform_desc, vec![1, 2, 3]);
        assert_eq!(decoded.signer_id, vec![0xFF; 32]);
        assert_eq!(decoded.sig_bytes, vec![0xDD; 64]);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let key = generate_ed25519_key();
        let receipt = create_receipt(
            [0xAA; 32],
            [0x00; 32],
            [0xBB; 32],
            [0x00; 32],
            TransformType::Truncation,
            vec![],
            1234567890,
            &key,
            cbc_core::HashSuite::Blake3,
        )
        .unwrap();

        verify_receipt(&receipt, cbc_core::HashSuite::Blake3).unwrap();
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let key = generate_ecdsa_key();
        let receipt = create_receipt(
            [0xCC; 32],
            [0x00; 32],
            [0xDD; 32],
            [0x00; 32],
            TransformType::Rechunk,
            vec![4, 5, 6],
            1234567890,
            &key,
            cbc_core::HashSuite::Blake3,
        )
        .unwrap();

        verify_receipt(&receipt, cbc_core::HashSuite::Blake3).unwrap();
    }

    #[test]
    fn test_tampered_receipt_fails() {
        let key = generate_ed25519_key();
        let mut receipt = create_receipt(
            [0xAA; 32],
            [0x00; 32],
            [0xBB; 32],
            [0x00; 32],
            TransformType::Truncation,
            vec![],
            1234567890,
            &key,
            cbc_core::HashSuite::Blake3,
        )
        .unwrap();

        // Tamper with derived_root
        receipt.derived_root[0] ^= 0x01;
        assert!(verify_receipt(&receipt, cbc_core::HashSuite::Blake3).is_err());
    }
}
