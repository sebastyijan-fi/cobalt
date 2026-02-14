//! Error types for CBC encoding, decoding, and validation.
//!
//! All fallible operations in `cbc-core` return [`Result<T>`] which uses
//! [`CbcError`] as the error type. The decoder (§10.1) treats every error
//! as a hard failure — there is no "warn and continue" path.

#[cfg(feature = "std")]
use thiserror::Error;

use alloc::string::String;
#[cfg(not(feature = "std"))]
use core::fmt;

/// All errors that can occur during CBC encoding, decoding, or validation.
///
/// Each variant corresponds to a specific integrity or format check.
/// The decoder uses the hard-error model: any failed check aborts decoding.
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum CbcError {
    /// The first 4 bytes are not `CBC1` (0x43 0x42 0x43 0x31).
    #[cfg_attr(feature = "std", error("invalid magic bytes: expected CBC1, got {0:?}"))]
    InvalidMagic([u8; 4]),

    /// Bootstrap declares a version this library does not support.
    #[cfg_attr(feature = "std", error("unsupported version: {0}"))]
    UnsupportedVersion(u16),

    /// Bootstrap `hash_suite` field is not 0x01 (BLAKE3) or 0x02 (SHA-256).
    #[cfg_attr(feature = "std", error("unknown hash suite: 0x{0:02x}"))]
    UnknownHashSuite(u8),

    /// `commitment_mode` does not have bit 0 (Family A) set.
    #[cfg_attr(feature = "std", error("invalid commitment mode: Family A (bit 0) must be set, got 0x{0:02x}"))]
    InvalidCommitmentMode(u8),

    #[cfg_attr(feature = "std", error("invalid block payload size: {0} (must be power of 2, 512..=16MiB)"))]
    InvalidBlockPayloadSize(u32),

    #[cfg_attr(feature = "std", error("reserved field is non-zero at offset {offset}"))]
    NonZeroReserved { offset: usize },

    #[cfg_attr(feature = "std", error("params MAC verification failed"))]
    ParamsMacMismatch,

    #[cfg_attr(feature = "std", error("block index mismatch: expected {expected}, got {got}"))]
    BlockIndexMismatch { expected: u32, got: u32 },

    #[cfg_attr(feature = "std", error("payload length {length} exceeds block payload size {max}"))]
    PayloadLengthExceeded { length: u32, max: u32 },

    #[cfg_attr(feature = "std", error("non-full payload in non-final block {index}: length {length}, expected {expected}"))]
    NonFullPayload {
        index: u32,
        length: u32,
        expected: u32,
    },

    #[cfg_attr(feature = "std", error("non-zero block flags: 0x{0:08x}"))]
    NonZeroBlockFlags(u32),

    #[cfg_attr(feature = "std", error("encryption error: {0}"))]
    EncryptionError(String),

    #[cfg_attr(feature = "std", error("decryption error: {0}"))]
    DecryptionError(String),

    #[cfg_attr(feature = "std", error("missing encryption key"))]
    MissingEncryptionKey,

    #[cfg_attr(feature = "std", error("compression error: {0}"))]
    CompressionError(String),

    #[cfg_attr(feature = "std", error("decompression error: {0}"))]
    DecompressionError(String),

    #[cfg_attr(feature = "std", error("CRC-32C mismatch in block {index}: expected 0x{expected:08x}, got 0x{got:08x}"))]
    Crc32Mismatch { index: u32, expected: u32, got: u32 },

    #[cfg_attr(feature = "std", error("chain commitment mismatch at block {index}"))]
    ChainCommitmentMismatch { index: u32 },

    #[cfg_attr(feature = "std", error("chain root mismatch: footer root does not match final block commitment"))]
    ChainRootMismatch,

    #[cfg_attr(feature = "std", error("merkle root mismatch"))]
    MerkleRootMismatch,

    #[cfg_attr(feature = "std", error("invalid footer magic: expected CBCF"))]
    InvalidFooterMagic,

    #[cfg_attr(feature = "std", error("footer commitment verification failed"))]
    FooterCommitmentMismatch,

    #[cfg_attr(feature = "std", error("prefix parse validation failed: {0}"))]
    PrefixParseError(String),

    #[cfg_attr(feature = "std", error("insufficient data: need {need} bytes, have {have}"))]
    InsufficientData { need: usize, have: usize },

    #[cfg_attr(feature = "std", error("invalid receipt: {0}"))]
    InvalidReceipt(String),

    #[cfg(feature = "std")]
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(not(feature = "std"))]
impl fmt::Display for CbcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(m) => write!(f, "invalid magic bytes: expected CBC1, got {:?}", m),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version: {}", v),
            Self::UnknownHashSuite(h) => write!(f, "unknown hash suite: 0x{:02x}", h),
            Self::InvalidCommitmentMode(m) => write!(f, "invalid commitment mode: Family A (bit 0) must be set, got 0x{:02x}", m),
            Self::InvalidBlockPayloadSize(s) => write!(f, "invalid block payload size: {} (must be power of 2, 512..=16MiB)", s),
            Self::NonZeroReserved { offset } => write!(f, "reserved field is non-zero at offset {}", offset),
            Self::ParamsMacMismatch => write!(f, "params MAC verification failed"),
            Self::BlockIndexMismatch { expected, got } => write!(f, "block index mismatch: expected {}, got {}", expected, got),
            Self::PayloadLengthExceeded { length, max } => write!(f, "payload length {} exceeds block payload size {}", length, max),
            Self::NonFullPayload { index, length, expected } => {
                write!(f, "non-full payload in non-final block {}: length {}, expected {}", index, length, expected)
            }
            Self::NonZeroBlockFlags(flags) => write!(f, "non-zero block flags: 0x{:08x}", flags),
            Self::EncryptionError(s) => write!(f, "encryption error: {}", s),
            Self::DecryptionError(s) => write!(f, "decryption error: {}", s),
            Self::MissingEncryptionKey => write!(f, "missing encryption key"),
            Self::CompressionError(s) => write!(f, "compression error: {}", s),
            Self::DecompressionError(s) => write!(f, "decompression error: {}", s),
            Self::Crc32Mismatch { index, expected, got } => {
                write!(f, "CRC-32C mismatch in block {}: expected 0x{:08x}, got 0x{:08x}", index, expected, got)
            }
            Self::ChainCommitmentMismatch { index } => write!(f, "chain commitment mismatch at block {}", index),
            Self::ChainRootMismatch => write!(f, "chain root mismatch: footer root does not match final block commitment"),
            Self::MerkleRootMismatch => write!(f, "merkle root mismatch"),
            Self::InvalidFooterMagic => write!(f, "invalid footer magic: expected CBCF"),
            Self::FooterCommitmentMismatch => write!(f, "footer commitment verification failed"),
            Self::PrefixParseError(s) => write!(f, "prefix parse validation failed: {}", s),
            Self::InsufficientData { need, have } => write!(f, "insufficient data: need {} bytes, have {}", need, have),
            Self::InvalidReceipt(s) => write!(f, "invalid receipt: {}", s),
        }
    }
}

/// Convenience alias: all fallible operations return `Result<T, CbcError>`.
pub type Result<T> = core::result::Result<T, CbcError>;
