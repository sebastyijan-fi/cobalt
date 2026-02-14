/// CBC Core — Context-Bound Container format library (v0.1).
///
/// This crate implements the CBC v0.1 specification:
/// - Bootstrap Segment (64-byte preamble)
/// - Block format with CRC-32C integrity
/// - Family A: Linear hash-chain commitments
/// - Family B: Merkle tree range constraints
/// - Family C: Prefix parse constraints
/// - Stream Footer with commitment verification
/// - Full encoder and decoder with mandatory validation

pub mod error;
pub mod hash;
pub mod bootstrap;
pub mod block;
pub mod chain;
pub mod merkle;
pub mod prefix;
pub mod footer;
pub mod encoder;
pub mod decoder;

// Re-export key types at crate root
pub use bootstrap::BootstrapSegment;
pub use decoder::DecodedArtifact;
pub use encoder::EncoderConfig;
pub use error::{CbcError, Result};
pub use hash::HashSuite;
