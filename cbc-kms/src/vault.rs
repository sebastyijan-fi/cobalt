use crate::{KmsError, KmsSigner};
use async_trait::async_trait;
use reqwest::Client;

/// HashiCorp Vault Transit Engine Signer Stub
#[allow(dead_code)]
pub struct VaultSigner {
    client: Client,
    vault_url: String,
    token: String,
}

impl VaultSigner {
    pub fn new(vault_url: String, token: String) -> Self {
        Self {
            client: Client::new(),
            vault_url,
            token,
        }
    }
}

#[async_trait]
impl KmsSigner for VaultSigner {
    async fn sign(&self, _key_id: &str, _payload: &[u8]) -> Result<Vec<u8>, KmsError> {
        // In a real implementation, this would hit the HashiCorp Vault transit engine transit/sign/{name} endpoint.
        // For the enterprise demo, we return a stub.
        Err(KmsError::Vault(
            "Vault transit engine sign not fully implemented yet in stub".into(),
        ))
    }

    async fn verify(
        &self,
        _key_id: &str,
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<bool, KmsError> {
        Err(KmsError::Vault(
            "Vault transit engine verify not fully implemented yet in stub".into(),
        ))
    }
}
