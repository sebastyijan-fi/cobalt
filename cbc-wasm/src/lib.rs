use cbc_core::decoder;
use cbc_core::BootstrapSegment;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct ValidationResult {
    valid: bool,
    version: u16,
    file_size: usize,
    hash_suite: String,
    block_count: u32,
    block_payload_size: u32,
    merkle_root: Option<String>,
    error: Option<String>,
    suggestion: Option<String>,
}

#[wasm_bindgen]
pub fn validate_artifact(data: &[u8]) -> JsValue {
    let mut result = ValidationResult {
        valid: false,
        version: 0,
        file_size: data.len(),
        hash_suite: "Unknown".to_string(),
        block_count: 0,
        block_payload_size: 0,
        merkle_root: None,
        error: None,
        suggestion: None,
    };

    if data.len() < 64 {
        result.error = Some("File too small".to_string());
        result.suggestion = Some("The Cobalt header requires at least 64 bytes.".to_string());
        return serde_wasm_bindgen::to_value(&result).unwrap();
    }

    // Decode bootstrap to fill metadata
    let mut bs_bytes = [0u8; 64];
    bs_bytes.copy_from_slice(&data[..64]);

    match BootstrapSegment::decode(&bs_bytes) {
        Ok(bs) => {
            result.version = 1; // CBC1 format version implied by magic bytes
            result.hash_suite = format!("{:?}", bs.hash_suite);
            result.block_count = bs.block_count;
            result.block_payload_size = bs.block_payload_size;
        }
        Err(e) => {
            result.error = Some(format!("Invalid bootstrap: {}", e));
            result.suggestion = Some(e.suggestion().to_string());
            return serde_wasm_bindgen::to_value(&result).unwrap();
        }
    }

    // Validate full artifact
    match decoder::validate(data) {
        Ok(_) => {
            result.valid = true;
            // Get Merkle root if available
            if let Ok(decoded) = decoder::decode(data, None) {
                result.merkle_root = decoded.merkle_root.map(hex::encode);
            }
        }
        Err(e) => {
            result.valid = false;
            result.error = Some(format!("Validation failed: {}", e));
            result.suggestion = Some(e.suggestion().to_string());
        }
    }

    serde_wasm_bindgen::to_value(&result).unwrap()
}
