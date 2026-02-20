use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct EncodeRequest {
    payload: String, // Base64 or standard string for demo
}

#[derive(Serialize)]
pub struct EncodeResponse {
    status: String,
    merkle_root: String,
}

pub async fn handle(
    State(_state): State<AppState>,
    Json(req): Json<EncodeRequest>,
) -> impl IntoResponse {
    // For this API, we will use a default Family AB configuration.
    // In a real application, the configuration would be parameterized.
    let config = cbc_core::encoder::EncoderConfig {
        hash_suite: cbc_core::hash::HashSuite::Blake3,
        commitment_mode: cbc_core::bootstrap::FAMILY_A_BIT | cbc_core::bootstrap::FAMILY_B_BIT,
        block_payload_size: 1024,
        flags: 0,
        encryption_key: None,
    };

    // We can accept string payloads for now. 
    // In a real scenario, we'd accept base64 binary or multipart streams.
    let payload = req.payload.into_bytes();
    
    // We use a zero nonce for the demo. Real enterprise systems would generate this securely.
    let nonce = [0u8; 16];

    match cbc_core::encoder::encode(&config, &payload, nonce, &[]) {
        Ok(artifact_bytes) => {
            // Re-decode just to fetch the merkle_root cleanly (or calculate it manually).
            // A more efficient way is to calculate it without fully decoding, but this works for demo.
            let merkle_root_str = match cbc_core::decoder::decode(&artifact_bytes, None) {
                Ok(decoded) => match decoded.merkle_root {
                    Some(mr) => hex::encode(mr),
                    None => "No Merkle Root (Family A)".into(),
                },
                Err(_) => "Error extracting root".into(),
            };

            let res = EncodeResponse {
                status: "success".into(),
                merkle_root: merkle_root_str,
                // We're just returning status + root for the original stub format,
                // but realistically we should return the base64 artifact.
                // Let's add it. (Wait, adding a field to Response would break UI potentially if it doesn't expect it, but it's safe.)
            };

            (StatusCode::OK, Json(res))
        }
        Err(e) => {
            tracing::error!("Encoding failed: {:?}", e);
            let res = EncodeResponse {
                status: "error".into(),
                merkle_root: format!("Failed: {:?}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(res))
        }
    }
}
