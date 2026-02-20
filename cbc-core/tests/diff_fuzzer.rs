use cbc_core::{decoder, encoder, EncoderConfig, HashSuite};
use proptest::prelude::*;
use std::io::Write;
use std::process::Command;

fn hash_suite_strategy() -> impl Strategy<Value = HashSuite> {
    prop_oneof![Just(HashSuite::Blake3), Just(HashSuite::Sha256),]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))] // Fewer cases as it spawns Python

    #[test]
    fn test_differential_oracle_full(
        payload in prop::collection::vec(any::<u8>(), 1..5000),
        suite in hash_suite_strategy(),
        bps_power in 9..12u32, // 512 to 4096
        nonce in prop::array::uniform16(0..u8::MAX),
    ) {
        let bps = 1 << bps_power;
        let config = EncoderConfig {
            hash_suite: suite,
            commitment_mode: cbc_core::bootstrap::FAMILY_A_BIT,
            block_payload_size: bps,
            flags: 0,
            encryption_key: None,
        };

        // 1. Encode with Rust
        let artifact = encoder::encode(&config, &payload, nonce, &[]).unwrap();
        let rust_decoded = decoder::decode(&artifact, None).unwrap();
        let rust_root = rust_decoded.chain_root;

        // 2. Save to temp file
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(&artifact).unwrap();
        let path = temp_file.path().to_str().unwrap();

        // 3. Verify with Python Oracle
        let output = Command::new("python3")
            .arg("../scripts/ref_oracle.py")
            .arg(path)
            .arg("--json")
            .output()
            .expect("Failed to run python3 scripts/ref_oracle.py");

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("Python Oracle failed verification: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let oracle_json: serde_json::Value = serde_json::from_str(&stdout)
            .expect("Failed to parse Oracle JSON output");

        let oracle_root_hex = oracle_json["chain_root"].as_str().unwrap();
        let rust_root_hex = hex::encode(rust_root);

        prop_assert_eq!(rust_root_hex, oracle_root_hex, "Rust and Python Oracle disagreed on Chain Root!");
    }
}
