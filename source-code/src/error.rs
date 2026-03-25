use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HfsError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Sled database error: {0}")]
    Sled(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Compression error: {0}")]
    CompressionError(String),
    #[error("Crypto error")]
    CryptoError,
    #[error("Entry not found")]
    NoEntry,
    #[error("Quota exceeded")]
    QuotaExceeded,
    #[error("Corrupted data")]
    CorruptedData,
    #[error("Missing encryption key")]
    MissingKey,
    #[error("Time error")]
    TimeError,
}

impl From<HfsError> for libc::c_int {
    fn from(e: HfsError) -> Self {
        match e {
            HfsError::NoEntry => libc::ENOENT,
            HfsError::QuotaExceeded => libc::EDQUOT,
            HfsError::CorruptedData => libc::EIO,
            _ => libc::EIO,
        }
    }
}
