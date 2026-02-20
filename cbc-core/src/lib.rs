//! # CBC Core
//!
//! Context-Bound Container format library (v0.1).
//!
//! A CBC artifact is a self-validating, tamper-evident binary container.
//! Validity depends on intrinsic relational constraints among blocks:
//!
//! - **Family A** — Linear hash-chain commitments bind every block to a single root
//! - **Family B** — Merkle tree enables O(log n) range proofs for selective disclosure
//! - **Family C** — Prefix parse constraints enable structural resynchronization
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use cbc_core::{EncoderConfig, HashSuite, encoder, decoder};
//! use cbc_core::bootstrap::FAMILY_A_BIT;
//!
//! let config = EncoderConfig {
//!     hash_suite: HashSuite::Blake3,
//!     commitment_mode: FAMILY_A_BIT,
//!     block_payload_size: 4096,
//!     flags: 0,
//!     encryption_key: None,
//! };
//!
//! let artifact = encoder::encode(&config, b"hello world", [0u8; 16], &[]).unwrap();
//! let decoded = decoder::decode(&artifact, None).unwrap();
//! assert_eq!(decoded.payload, b"hello world");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod block;
pub mod bootstrap;
pub mod chain;
pub mod decoder;
pub mod easy;
pub mod encoder;
pub mod error;
pub mod footer;
pub mod hash;
pub mod merkle;
pub mod prefix;
pub mod streaming;

// Re-export key types at crate root
pub use bootstrap::BootstrapSegment;
pub use decoder::DecodedArtifact;
pub use encoder::EncoderConfig;
pub use error::{CbcError, Result};
pub use hash::HashSuite;
