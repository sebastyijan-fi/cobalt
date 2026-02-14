//! Error types for CBC encoding, decoding, and validation.
//!
//! All fallible operations in `cbc-core` return [`Result<T>`] which uses
//! [`CbcError`] as the error type. The decoder (§10.1) treats every error
//! as a hard failure — there is no "warn and continue" path.

use thiserror::Error;

/// All errors that can occur during CBC encoding, decoding, or validation.
///
/// Each variant corresponds to a specific integrity or format check.
/// The decoder uses the hard-error model: any failed check aborts decoding.
#[derive(Debug, Error)]
pub enum CbcError {
    /// The first 4 bytes are not `CBC1` (0x43 0x42 0x43 0x31).
    #[error("invalid magic bytes: expected CBC1, got {0:?}")]
    InvalidMagic([u8; 4]),

    /// Bootstrap declares a version this library does not support.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),

    /// Bootstrap `hash_suite` field is not 0x01 (BLAKE3) or 0x02 (SHA-256).
    #[error("unknown hash suite: 0x{0:02x}")]
    UnknownHashSuite(u8),

    /// `commitment_mode` does not have bit 0 (Family A) set.
    #[error("invalid commitment mode: Family A (bit 0) must be set, got 0x{0:02x}")]
    InvalidCommitmentMode(u8),

    #[error("invalid block payload size: {0} (must be power of 2, 512..=16MiB)")]
    InvalidBlockPayloadSize(u32),

    #[error("reserved field is non-zero at offset {offset}")]
    NonZeroReserved { offset: usize },

    #[error("params MAC verification failed")]
    ParamsMacMismatch,

    #[error("block index mismatch: expected {expected}, got {got}")]
    BlockIndexMismatch { expected: u32, got: u32 },

    #[error("payload length {length} exceeds block payload size {max}")]
    PayloadLengthExceeded { length: u32, max: u32 },

    #[error("non-full payload in non-final block {index}: length {length}, expected {expected}")]
    NonFullPayload {
        index: u32,
        length: u32,
        expected: u32,
    },

    #[error("block flags must be zero, got 0x{0:08x}")]
    NonZeroBlockFlags(u32),

    #[error("CRC-32C mismatch in block {index}: expected 0x{expected:08x}, got 0x{got:08x}")]
    Crc32Mismatch { index: u32, expected: u32, got: u32 },

    #[error("chain commitment mismatch at block {index}")]
    ChainCommitmentMismatch { index: u32 },

    #[error("chain root mismatch: footer root does not match final block commitment")]
    ChainRootMismatch,

    #[error("merkle root mismatch")]
    MerkleRootMismatch,

    #[error("invalid footer magic: expected CBCF")]
    InvalidFooterMagic,

    #[error("footer commitment verification failed")]
    FooterCommitmentMismatch,

    #[error("prefix parse validation failed: {0}")]
    PrefixParseError(String),

    #[error("insufficient data: need {need} bytes, have {have}")]
    InsufficientData { need: usize, have: usize },

    #[error("invalid receipt: {0}")]
    InvalidReceipt(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias: all fallible operations return `Result<T, CbcError>`.
pub type Result<T> = std::result::Result<T, CbcError>;
