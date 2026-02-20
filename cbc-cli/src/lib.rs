pub mod cli;
pub use cli::*;

use std::fs;
use std::process;

pub fn load_config() -> CbcConfig {
    let config_path = std::path::Path::new("cbc.toml");
    if config_path.exists() {
        if let Ok(content) = fs::read_to_string(config_path) {
            if let Ok(config) = toml::from_str(&content) {
                return config;
            }
        }
    }
    CbcConfig::default()
}

pub fn parse_families(s: &str) -> u8 {
    let mut mode: u8 = 0;
    for part in s.split('+') {
        match part.trim().to_uppercase().as_str() {
            "A" => mode |= cbc_core::bootstrap::FAMILY_A_BIT,
            "B" => mode |= cbc_core::bootstrap::FAMILY_B_BIT,
            "C" => mode |= cbc_core::bootstrap::FAMILY_C_BIT,
            _ => {
                eprintln!("Unknown family: {part}. Valid: A, B, C");
                process::exit(1);
            }
        }
    }
    if mode & cbc_core::bootstrap::FAMILY_A_BIT == 0 {
        mode |= cbc_core::bootstrap::FAMILY_A_BIT; // Always include A
    }
    mode
}

pub fn parse_hash(s: &str) -> cbc_core::HashSuite {
    match s.to_lowercase().as_str() {
        "blake3" => cbc_core::HashSuite::Blake3,
        "sha256" => cbc_core::HashSuite::Sha256,
        _ => {
            eprintln!("Unknown hash suite: {s}. Valid: blake3, sha256");
            process::exit(1);
        }
    }
}
