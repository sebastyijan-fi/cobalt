use crate::{KmsError, KmsSigner};
use async_trait::async_trait;
use base64::Engine;
use reqwest::Client;
use serde_json::json;

/// HashiCorp Vault Transit Engine Signer
pub struct VaultSigner {
    client: Client,
    vault_url: String, // e.g. "http://127.0.0.1:8200"
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
    async fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
        let url = format!("{}/v1/transit/sign/{}", self.vault_url, key_id);
        let b64_payload = base64::prelude::BASE64_STANDARD.encode(payload);

        let req_body = json!({
            "input": b64_payload
        });

        let res = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&req_body)
            .send()
            .await
            .map_err(|e| KmsError::Vault(e.to_string()))?;

        if !res.status().is_success() {
            let err_text = res.text().await.unwrap_or_default();
            return Err(KmsError::Vault(format!("Vault error: {}", err_text)));
        }

        let data: serde_json::Value = res
            .json()
            .await
            .map_err(|e| KmsError::Vault(e.to_string()))?;

        let sig_str = data["data"]["signature"]
            .as_str()
            .ok_or_else(|| KmsError::Vault("Missing signature in response".into()))?;

        Ok(sig_str.as_bytes().to_vec())
    }

    async fn verify(
        &self,
        key_id: &str,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, KmsError> {
        let url = format!("{}/v1/transit/verify/{}", self.vault_url, key_id);
        let b64_payload = base64::prelude::BASE64_STANDARD.encode(payload);
        let sig_str = String::from_utf8(signature.to_vec())
            .map_err(|_| KmsError::Vault("Invalid signature format".into()))?;

        let req_body = json!({
            "input": b64_payload,
            "signature": sig_str
        });

        let res = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&req_body)
            .send()
            .await
            .map_err(|e| KmsError::Vault(e.to_string()))?;

        if !res.status().is_success() {
            let err_text = res.text().await.unwrap_or_default();
            return Err(KmsError::Vault(format!("Vault error: {}", err_text)));
        }

        let data: serde_json::Value = res
            .json()
            .await
            .map_err(|e| KmsError::Vault(e.to_string()))?;

        let valid = data["data"]["valid"].as_bool().unwrap_or(false);

        Ok(valid)
    }
}
