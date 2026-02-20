//! Error types for CBC encoding, decoding, and validation.
//!
//! All fallible operations in `cbc-core` return [`Result<T>`] which uses
//! [`CbcError`] as the error type. The decoder (§10.1) treats every error
//! as a hard failure — there is no "warn and continue" path.

use alloc::string::String;
use alloc::string::ToString;
#[cfg(not(feature = "std"))]
use core::fmt;
#[cfg(feature = "std")]
use std::fmt;

/// All errors that can occur during CBC encoding, decoding, or validation.
///
/// Each variant corresponds to a specific integrity or format check.
/// The decoder uses the hard-error model: any failed check aborts decoding.
#[derive(Debug)]
pub enum CbcError {
    /// The first 4 bytes are not `CBC1` (0x43 0x42 0x43 0x31).
    InvalidMagic([u8; 4]),

    /// Bootstrap declares a version this library does not support.
    UnsupportedVersion(u16),

    /// Bootstrap `hash_suite` field is not 0x01 (BLAKE3) or 0x02 (SHA-256).
    UnknownHashSuite(u8),

    /// `commitment_mode` does not have bit 0 (Family A) set.
    InvalidCommitmentMode(u8),

    InvalidBlockPayloadSize(u32),

    NonZeroReserved {
        offset: usize,
    },

    /// Params MAC verification failed.
    ParamsMacMismatch,

    BlockIndexMismatch {
        expected: u32,
        got: u32,
    },

    PayloadLengthExceeded {
        length: u32,
        max: u32,
    },

    NonFullPayload {
        index: u32,
        length: u32,
        expected: u32,
    },

    NonZeroBlockFlags(u32),

    EncryptionError(String),

    DecryptionError(String),

    MissingEncryptionKey,

    CompressionError(String),

    DecompressionError(String),

    Crc32Mismatch {
        index: u32,
        expected: u32,
        got: u32,
    },

    ChainCommitmentMismatch {
        index: u32,
    },

    ChainRootMismatch,

    MerkleRootMismatch,

    InvalidFooterMagic,

    FooterCommitmentMismatch,

    PrefixParseError(String),

    InsufficientData {
        need: usize,
        have: usize,
    },

    InvalidReceipt(String),

    /// Generic error message.
    Other(String),

    #[cfg(feature = "std")]
    Io(std::io::Error),
}

#[cfg(feature = "std")]
impl From<std::io::Error> for CbcError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CbcError {}

impl CbcError {
    pub fn msg<S: Into<String>>(s: S) -> Self {
        Self::Other(s.into())
    }

    /// Returns a human-readable suggestion for resolving the error.
    pub fn suggestion(&self) -> &str {
        match self {
            Self::InvalidMagic(_) => "This file does not appear to be a Cobalt artifact (missing 'CBC1' magic).",
            Self::UnsupportedVersion(_v) => "This artifact was created with a newer or incompatible version of Cobalt.",
            Self::UnknownHashSuite(_) => "The hash algorithm used in this artifact is not supported by this library version.",
            Self::InvalidCommitmentMode(_) => "The artifact header is malformed (Family A commitment is required).",
            Self::InvalidBlockPayloadSize(_) => "The block size in the header is invalid (must be a power of 2 between 512B and 16MiB).",
            Self::ParamsMacMismatch => "The artifact header has been tampered with or corrupted (MAC mismatch).",
            Self::ChainCommitmentMismatch { .. } => "INTEGRITY FAILURE: A block has been modified or corrupted. The cryptographic chain is broken.",
            Self::Crc32Mismatch { .. } => "Lower-level corruption detected in a block payload (CRC mismatch).",
            Self::DecryptionError(_) => "Failed to decrypt block. Check your key and ensuring the artifact wasn't truncated.",
            Self::InsufficientData { .. } => "The artifact is truncated or incomplete.",
            Self::InvalidFooterMagic => "The artifact's footer is missing or corrupted.",
            Self::FooterCommitmentMismatch => "The global footer commitment failed. The entire artifact is untrusted.",
            #[cfg(feature = "std")]
            Self::Io(_e) => "An underlying I/O error occurred while reading/writing the artifact.",
            _ => "Check the artifact specification and ensure your implementation matches.",
        }
    }
}

impl fmt::Display for CbcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidMagic(m) => {
                alloc::format!("invalid magic bytes: expected CBC1, got {:?}", m)
            }
            Self::UnsupportedVersion(v) => alloc::format!("unsupported version: {}", v),
            Self::UnknownHashSuite(h) => alloc::format!("unknown hash suite: 0x{:02x}", h),
            Self::InvalidCommitmentMode(m) => alloc::format!(
                "invalid commitment mode: Family A (bit 0) must be set, got 0x{:02x}",
                m
            ),
            Self::InvalidBlockPayloadSize(s) => alloc::format!(
                "invalid block payload size: {} (must be power of 2, 512..=16MiB)",
                s
            ),
            Self::NonZeroReserved { offset } => {
                alloc::format!("reserved field is non-zero at offset {}", offset)
            }
            Self::ParamsMacMismatch => "params MAC verification failed".to_string(),
            Self::BlockIndexMismatch { expected, got } => {
                alloc::format!("block index mismatch: expected {}, got {}", expected, got)
            }
            Self::PayloadLengthExceeded { length, max } => alloc::format!(
                "payload length {} exceeds block payload size {}",
                length,
                max
            ),
            Self::NonFullPayload {
                index,
                length,
                expected,
            } => {
                alloc::format!(
                    "non-full payload in non-final block {}: length {}, expected {}",
                    index,
                    length,
                    expected
                )
            }
            Self::NonZeroBlockFlags(flags) => {
                alloc::format!("non-zero block flags: 0x{:08x}", flags)
            }
            Self::EncryptionError(s) => alloc::format!("encryption error: {}", s),
            Self::DecryptionError(s) => alloc::format!("decryption error: {}", s),
            Self::MissingEncryptionKey => "missing encryption key".to_string(),
            Self::CompressionError(s) => alloc::format!("compression error: {}", s),
            Self::DecompressionError(s) => alloc::format!("decompression error: {}", s),
            Self::Crc32Mismatch {
                index,
                expected,
                got,
            } => {
                alloc::format!(
                    "CRC-32C mismatch in block {}: expected 0x{:08x}, got 0x{:08x}",
                    index,
                    expected,
                    got
                )
            }
            Self::ChainCommitmentMismatch { index } => {
                alloc::format!("chain commitment mismatch at block {}", index)
            }
            Self::ChainRootMismatch => {
                "chain root mismatch: footer root does not match final block commitment".to_string()
            }
            Self::MerkleRootMismatch => "merkle root mismatch".to_string(),
            Self::InvalidFooterMagic => "invalid footer magic: expected CBCF".to_string(),
            Self::FooterCommitmentMismatch => "footer commitment verification failed".to_string(),
            Self::PrefixParseError(s) => alloc::format!("prefix parse validation failed: {}", s),
            Self::InsufficientData { need, have } => {
                alloc::format!("insufficient data: need {} bytes, have {}", need, have)
            }
            Self::InvalidReceipt(s) => alloc::format!("invalid receipt: {}", s),
            Self::Other(s) => s.to_string(),
            #[cfg(feature = "std")]
            Self::Io(e) => alloc::format!("I/O error: {}", e),
        };
        write!(f, "{} (Suggestion: {})", msg, self.suggestion())
    }
}

/// Convenience alias: all fallible operations return `Result<T, CbcError>`.
pub type Result<T> = core::result::Result<T, CbcError>;
