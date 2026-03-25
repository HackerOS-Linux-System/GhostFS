use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HfsError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Database error: {0}")]
    Sled(#[from] sled::Error),

    #[error("Serialization error: {0}")]
    Bincode(#[from] bincode::Error),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Compression error: {0}")]
    CompressionError(String),

    #[error("Encryption/decryption error")]
    CryptoError,

    #[error("Entry not found")]
    NoEntry,

    #[error("Quota exceeded (user {0})")]
    QuotaExceeded(u32),   // now with a field

    #[error("Corrupted data detected")]
    CorruptedData,

    #[error("Missing encryption key")]
    MissingKey,

    #[error("Time conversion error")]
    TimeError,

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

impl From<HfsError> for libc::c_int {
    fn from(e: HfsError) -> Self {
        match e {
            HfsError::NoEntry => libc::ENOENT,
            HfsError::QuotaExceeded(_) => libc::EDQUOT,
            HfsError::CorruptedData => libc::EIO,
            HfsError::InvalidArgument(_) => libc::EINVAL,
            _ => libc::EIO,
        }
    }
}
