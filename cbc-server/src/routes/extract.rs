use crate::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ExtractRequest {
    artifact_base64: String,
    start_block: u64,
    end_block: u64,
    kms_key_id: String,
}

#[derive(Serialize)]
pub struct ExtractResponse {
    status: String,
    derived_artifact_base64: String,
    receipt_base64: String,
}

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<ExtractRequest>,
) -> impl IntoResponse {
    // 1. Decode base64
    let artifact_bytes = match base64::prelude::BASE64_STANDARD.decode(&req.artifact_base64) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("Failed to decode base64 artifact: {}", e);
            let res = ExtractResponse {
                status: "error".into(),
                derived_artifact_base64: "Error: Base64 decode failed".to_string(),
                receipt_base64: "".into(),
            };
            return (StatusCode::BAD_REQUEST, Json(res));
        }
    };

    // 2. Perform `subrange_extract`
    let signing_key = cbc_transform::receipt::generate_ed25519_key();
    let extract_result = cbc_transform::subrange_extract(
        &artifact_bytes,
        req.start_block as u32,
        req.end_block as u32,
        &signing_key,
    );

    match extract_result {
        Ok((derived_artifact, _inner_receipt)) => {
            // 3. To securely sign it, we would compute a body hash or just sign the new chain root.
            // For now, let's just make a mock hash of the derived artifact to sign.
            // In a strict implementation, we'd sign the extracted Merkle Root or Chain Root.
            let mock_body_hash = [0u8; 32]; // Replace with real hash logic

            // Demonstrate KMS Signer integration
            match state
                .kms_signer
                .sign(&req.kms_key_id, &mock_body_hash)
                .await
            {
                Ok(sig) => {
                    use base64::Engine;
                    let res = ExtractResponse {
                        status: "success".into(),
                        derived_artifact_base64: base64::prelude::BASE64_STANDARD
                            .encode(&derived_artifact),
                        // The actual receipt would enclose the signature and proof
                        receipt_base64: base64::prelude::BASE64_STANDARD.encode(&sig),
                    };
                    (StatusCode::OK, Json(res))
                }
                Err(e) => {
                    tracing::error!("KMS Signing failed: {:?}", e);
                    let res = ExtractResponse {
                        status: "error".into(),
                        derived_artifact_base64: "".into(),
                        receipt_base64: "".into(),
                    };
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(res))
                }
            }
        }
        Err(e) => {
            tracing::error!("Extraction failed: {:?}", e);
            let res = ExtractResponse {
                status: "error".into(),
                derived_artifact_base64: "".into(),
                receipt_base64: "".into(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(res))
        }
    }
}
