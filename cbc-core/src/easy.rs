//! High-level "Zero-Friction" API for Cobalt.
//!
//! This module provides a simplified interface for common use cases.
//! It uses sensible defaults: Blake3, Family A (Linear Chain), and 64KB block sizes.

use crate::bootstrap::FAMILY_A_BIT;
use crate::decoder::{self, DecodedArtifact};
use crate::encoder::{self, EncoderConfig};
use crate::error::Result;
use crate::hash::HashSuite;
use alloc::vec::Vec;

/// A high-level wrapper for Cobalt artifacts.
pub struct Easy;

impl Easy {
    /// Captures a payload into a Cobalt container with default high-assurance settings.
    ///
    /// - Hash Suite: Blake3
    /// - Commitment: Family A (Linear Chain)
    /// - Block Size: 64 KB
    pub fn capture(payload: &[u8], nonce: [u8; 16]) -> Result<Vec<u8>> {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 64 * 1024,
            flags: 0,
            encryption_key: None,
        };
        encoder::encode(&config, payload, nonce, &[])
    }

    /// Releases (decodes and verifies) a Cobalt artifact.
    pub fn release(data: &[u8]) -> Result<DecodedArtifact> {
        decoder::decode(data, None)
    }

    /// Captures a payload with encryption.
    pub fn capture_encrypted(payload: &[u8], nonce: [u8; 16], key: [u8; 32]) -> Result<Vec<u8>> {
        let config = EncoderConfig {
            hash_suite: HashSuite::Blake3,
            commitment_mode: FAMILY_A_BIT,
            block_payload_size: 64 * 1024,
            flags: 0,
            encryption_key: Some(key),
        };
        encoder::encode(&config, payload, nonce, &[])
    }

    /// Releases (decodes, decrypts, and verifies) an encrypted Cobalt artifact.
    pub fn release_encrypted(data: &[u8], key: [u8; 32]) -> Result<DecodedArtifact> {
        decoder::decode(data, Some(key))
    }
}

/// Convenience function for 1-liner encoding.
pub fn capture(payload: &[u8], nonce: [u8; 16]) -> Result<Vec<u8>> {
    Easy::capture(payload, nonce)
}

/// Convenience function for 1-liner decoding.
pub fn release(data: &[u8]) -> Result<DecodedArtifact> {
    Easy::release(data)
}
