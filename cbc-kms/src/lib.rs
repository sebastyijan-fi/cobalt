use async_trait::async_trait;
use thiserror::Error;

pub mod aws;
pub mod vault;

pub use aws::AwsKmsSigner;
pub use vault::VaultSigner;

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("AWS KMS Error: {0}")]
    Aws(String),
    #[error("Vault Error: {0}")]
    Vault(String),
    #[error("General Error: {0}")]
    General(String),
}

/// Abstract signer for Enterprise Key Management Systems.
/// Allows Cobalt transforms to use HSMs instead of local keys.
#[async_trait]
pub trait KmsSigner: Send + Sync {
    /// Sign a payload (typically a hash or small digest) using a specific key ID.
    async fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, KmsError>;

    /// Verify a signature using a specific key ID (useful for some KMS systems).
    async fn verify(
        &self,
        key_id: &str,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, KmsError>;
}
