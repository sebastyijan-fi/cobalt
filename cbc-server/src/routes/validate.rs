use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
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
    Json(_req): Json<ValidateRequest>,
) -> impl IntoResponse {
    let res = ValidateResponse {
        valid: true,
        merkle_root: "stub_hash_for_enterprise_demo".into(),
    };

    (StatusCode::OK, Json(res))
}
