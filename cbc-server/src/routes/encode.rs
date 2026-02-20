use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
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
    Json(_req): Json<EncodeRequest>,
) -> impl IntoResponse {
    // In a full implementation, we would stream the request body directly into cbc_core::StreamingEncoder
    // For this enterprise viability demo, we'll return a stub response

    let res = EncodeResponse {
        status: "success".into(),
        merkle_root: "stub_hash_for_enterprise_demo".into(),
    };

    (StatusCode::OK, Json(res))
}
