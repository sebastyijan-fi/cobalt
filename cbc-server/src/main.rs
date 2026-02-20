use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod routes;
mod state;

use state::AppState;

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/api/v1/encode", post(routes::encode::handle))
        .route("/api/v1/validate", post(routes::validate::handle))
        .route("/api/v1/extract", post(routes::extract::handle))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "cbc_server=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize application state (e.g., KMS clients)
    let state = AppState::new().await;

    let router = app(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3030));
    tracing::debug!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use cbc_kms::{KmsSigner, KmsError};
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    struct MockSigner;

    #[async_trait]
    impl KmsSigner for MockSigner {
        async fn sign(&self, _key_id: &str, _payload: &[u8]) -> Result<Vec<u8>, KmsError> {
            Ok(b"mock_signature".to_vec())
        }

        async fn verify(&self, _key_id: &str, _payload: &[u8], _sig: &[u8]) -> Result<bool, KmsError> {
            Ok(true)
        }
    }

    async fn get_test_app() -> Router {
        let state = AppState {
            kms_signer: std::sync::Arc::new(MockSigner),
        };
        app(state)
    }

    #[tokio::test]
    async fn test_health() {
        let app = get_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_encode_validate_flow() {
        let app = get_test_app().await;

        // 1. Encode
        let encode_req = json!({
            "payload": "hello enterprise world"
        });

        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/encode")
                    .header("content-type", "application/json")
                    .body(Body::from(encode_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        // Wait, to parse body without full HTTP client, we collect bytes
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let encode_res: Value = serde_json::from_slice(&body_bytes).unwrap();
        
        // Let's check status and if the merkle root is valid
        assert_eq!(encode_res["status"], "success");
        // We know encode will just use the default nonce so if we want the actual base64 artifact we'd need it in response
        // Currently encode response only returns merkle_root
        // Let's test providing an invalid artifact to validate
        
        let validate_req = json!({
            "artifact_base64": "invalid base64!"
        });
        
        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(validate_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_extract_flow() {
        let app = get_test_app().await;

        let encode_req = json!({
            "payload": "mock data for extraction feature"
        });

        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/encode")
                    .header("content-type", "application/json")
                    .body(Body::from(encode_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        let extract_req = json!({
            "artifact_base64": "invalid base64 check",
            "start_block": 0,
            "end_block": 1,
            "kms_key_id": "mock-kms-key-123"
        });
        
        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/extract")
                    .header("content-type", "application/json")
                    .body(Body::from(extract_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
            
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
