use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ValidateRequest {
    artifact_base64: String,
}

#[derive(Serialize)]
pub struct ValidateResponse {
    valid: bool,
    merkle_root: String,
}

pub async fn handle(
    State(_state): State<AppState>,
    Json(req): Json<ValidateRequest>,
) -> impl IntoResponse {
    use base64::Engine;
    // Decode base64 
    let artifact_bytes = match base64::prelude::BASE64_STANDARD.decode(&req.artifact_base64) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("Failed to decode base64 artifact: {}", e);
            let res = ValidateResponse {
                valid: false,
                merkle_root: format!("Error: Base64 decode failed"),
            };
            return (StatusCode::BAD_REQUEST, Json(res));
        }
    };

    // Run real cryptographic validation
    match cbc_core::decoder::decode(&artifact_bytes, None) {
        Ok(decoded) => {
            let root = match decoded.merkle_root {
                Some(mr) => hex::encode(mr),
                None => "No Merkle Root (Family A)".into(),
            };
            
            let res = ValidateResponse {
                valid: true,
                merkle_root: root,
            };
            (StatusCode::OK, Json(res))
        },
        Err(e) => {
            tracing::warn!("Artifact validation failed: {:?}", e);
            let res = ValidateResponse {
                valid: false,
                merkle_root: format!("Validation Failed: {:?}", e),
            };
            (StatusCode::UNPROCESSABLE_ENTITY, Json(res))
        }
    }
}
