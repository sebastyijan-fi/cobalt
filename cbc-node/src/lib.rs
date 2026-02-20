#![deny(clippy::all)]

use cbc_core::{decoder, BootstrapSegment};
use napi::Result;
use napi_derive::napi;
use std::fs;

#[napi(object)]
pub struct InspectionResult {
    pub valid_bootstrap: bool,
    pub version: u16,
    pub hash_suite: String,
    pub block_count: u32,
    pub block_payload_size: u32,
    pub families: Vec<String>,
}

#[napi]
pub fn inspect_file(path: String) -> Result<InspectionResult> {
    let data = fs::read(&path)
        .map_err(|e| napi::Error::from_reason(format!("Failed to read file: {}", e)))?;

    if data.len() < 64 {
        return Err(napi::Error::from_reason(
            "File too small to be a CBC artifact",
        ));
    }

    let mut bs_bytes = [0u8; 64];
    bs_bytes.copy_from_slice(&data[..64]);

    let bs = BootstrapSegment::decode(&bs_bytes)
        .map_err(|e| napi::Error::from_reason(format!("Invalid bootstrap: {:?}", e)))?;

    Ok(InspectionResult {
        valid_bootstrap: true,
        version: 1,
        hash_suite: format!("{:?}", bs.hash_suite),
        block_count: bs.block_count,
        block_payload_size: bs.block_payload_size,
        families: vec![
            if bs.family_a() { "A" } else { "" },
            if bs.family_b() { "B" } else { "" },
            if bs.family_c() { "C" } else { "" },
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect(),
    })
}

#[napi]
pub fn validate_file(path: String) -> Result<bool> {
    let data = fs::read(&path)
        .map_err(|e| napi::Error::from_reason(format!("Failed to read file: {}", e)))?;
    match decoder::validate(&data) {
        Ok(_) => Ok(true),
        Err(e) => Err(napi::Error::from_reason(format!(
            "Validation failed: {:?}",
            e
        ))),
    }
}
