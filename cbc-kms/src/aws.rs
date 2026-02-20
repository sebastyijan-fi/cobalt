use crate::{KmsError, KmsSigner};
use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client;

/// AWS KMS Signer implementation
pub struct AwsKmsSigner {
    client: Client,
}

impl AwsKmsSigner {
    pub async fn new() -> Self {
        let config: SdkConfig =
            aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        Self { client }
    }
}

#[async_trait]
impl KmsSigner for AwsKmsSigner {
    async fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
        let req = self
            .client
            .sign()
            .key_id(key_id)
            .message(Blob::new(payload))
            .message_type(aws_sdk_kms::types::MessageType::Raw)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256);

        let resp = req
            .send()
            .await
            .map_err(|e| KmsError::Aws(format!("Sign error: {:?}", e)))?;

        let sig = resp
            .signature()
            .ok_or_else(|| KmsError::Aws("No signature returned".into()))?;

        Ok(sig.clone().into_inner())
    }

    async fn verify(
        &self,
        key_id: &str,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, KmsError> {
        let req = self
            .client
            .verify()
            .key_id(key_id)
            .message(Blob::new(payload))
            .message_type(aws_sdk_kms::types::MessageType::Raw)
            .signature(Blob::new(signature))
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256);

        let resp = req
            .send()
            .await
            .map_err(|e| KmsError::Aws(format!("Verify error: {:?}", e)))?;

        Ok(resp.signature_valid())
    }
}
