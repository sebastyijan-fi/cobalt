/// CBC Transform — error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransformError {
    #[error("CBC error: {0}")]
    Cbc(#[from] cbc_core::CbcError),

    #[error("invalid transform: {0}")]
    InvalidTransform(String),

    #[error("signing error: {0}")]
    SigningError(String),

    #[error("verification error: {0}")]
    VerificationError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TransformError>;
