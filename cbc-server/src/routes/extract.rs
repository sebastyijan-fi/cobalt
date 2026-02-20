use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use cbc_kms::KmsSigner;
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
    // 1. We would decode the source artifact
    // 2. Perform `subrange_extract`
    // 3. Compute the derivation body_hash

    let mock_body_hash = [0u8; 32];

    // Demonstrate KMS Signer integration
    match state
        .kms_signer
        .sign(&req.kms_key_id, &mock_body_hash)
        .await
    {
        Ok(_sig) => {
            let res = ExtractResponse {
                status: "success".into(),
                derived_artifact_base64: "c3R1Yg==".into(),
                receipt_base64: "receipt_with_kms_signature".into(),
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
