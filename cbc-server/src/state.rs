use cbc_kms::aws::AwsKmsSigner;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub kms_signer: Arc<AwsKmsSigner>,
}

impl AppState {
    pub async fn new() -> Self {
        // Initialize an AWS KMS signer for enterprise deployments
        let signer = AwsKmsSigner::new().await;

        Self {
            kms_signer: Arc::new(signer),
        }
    }
}
