use base64::Engine;
use cbc_core::bootstrap::*;
use cbc_core::encoder::{self, EncoderConfig};
use cbc_core::hash::HashSuite;
use serde::Serialize;
use std::fs::File;
use std::io::Write;

#[derive(Serialize)]
pub struct ConformanceSuite {
    pub version: String,
    pub vectors: Vec<TestVector>,
}

#[derive(Serialize)]
pub struct TestVector {
    pub id: String,
    pub r#type: String, // "valid" or "invalid"
    pub description: String,
    pub artifact_base64: String,
    pub expected_payload_base64: Option<String>,
    pub expected_error: Option<String>,
}

pub fn generate_vectors() {
    let mut vectors = Vec::new();

    // 1. T1: Minimal Valid Artifact
    let mut nonce = [0u8; 16];
    nonce[15] = 0x01;
    let config_minimal = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT,
        block_payload_size: 512,
        flags: 0,
        encryption_key: None,
    };
    let payload_t1 = vec![0x42u8; 512];
    let artifact_t1 = encoder::encode(&config_minimal, &payload_t1, nonce, &[]).unwrap();

    vectors.push(TestVector {
        id: "T1-MINIMAL".to_string(),
        r#type: "valid".to_string(),
        description: "Minimal Family A artifact with BLAKE3".to_string(),
        artifact_base64: base64::prelude::BASE64_STANDARD.encode(&artifact_t1),
        expected_payload_base64: Some(base64::prelude::BASE64_STANDARD.encode(&payload_t1)),
        expected_error: None,
    });

    // 2. N1: Bit Flip
    let config_n1 = EncoderConfig {
        hash_suite: HashSuite::Blake3,
        commitment_mode: FAMILY_A_BIT | FAMILY_B_BIT,
        block_payload_size: 512,
        flags: 0,
        encryption_key: None,
    };
    let payload_n1 = vec![0x42u8; 1024];
    let mut artifact_n1 = encoder::encode(&config_n1, &payload_n1, [42u8; 16], &[]).unwrap();
    let payload_offset = BOOTSTRAP_SIZE + 16 + 100;
    artifact_n1[payload_offset] ^= 0x01; // flip bit

    vectors.push(TestVector {
        id: "N1-BIT-FLIP".to_string(),
        r#type: "invalid".to_string(),
        description: "Flipped a bit in the data payload".to_string(),
        artifact_base64: base64::prelude::BASE64_STANDARD.encode(&artifact_n1),
        expected_payload_base64: None,
        expected_error: Some("Crc32Mismatch".to_string()),
    });

    // 3. N6: Malformed Footer Underflow
    let mut artifact_n6 = encoder::encode(&config_n1, &payload_n1, [42u8; 16], &[]).unwrap();
    let block_wire = cbc_core::block::block_wire_size(512).unwrap();
    let footer_start = BOOTSTRAP_SIZE + 2 * block_wire;
    artifact_n6[footer_start + 4] = 0;
    artifact_n6[footer_start + 5] = 0;
    artifact_n6[footer_start + 6] = 0;
    artifact_n6[footer_start + 7] = 0;

    vectors.push(TestVector {
        id: "N6-MALFORMED-FOOTER".to_string(),
        r#type: "invalid".to_string(),
        description: "Footer length claiming to be 0 bytes (underflow risk)".to_string(),
        artifact_base64: base64::prelude::BASE64_STANDARD.encode(&artifact_n6),
        expected_payload_base64: None,
        expected_error: Some("footer length 0 is smaller than minimum required".to_string()),
    });

    // Generate output
    let suite = ConformanceSuite {
        version: "1.0".to_string(),
        vectors,
    };

    let json_str = serde_json::to_string_pretty(&suite).unwrap();

    let path = "tests/conformance/vectors.json";
    let mut file = File::create(path).unwrap();
    file.write_all(json_str.as_bytes()).unwrap();
    println!("Generated vectors to {:?}", path);
}

#[test]
fn build_conformance_vectors() {
    generate_vectors();
}
