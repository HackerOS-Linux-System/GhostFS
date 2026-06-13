
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

    #[error("KDF error: {0}")]
    KdfError(String),

    #[error("Superblock HMAC verification failed — volume may be tampered")]
    SuperblockTampered,

    #[error("Entry not found")]
    NoEntry,

    #[error("Quota exceeded for uid {0}")]
    QuotaExceeded(u32),

    #[error("I/O rate limit exceeded for uid {0}")]
    RateLimited(u32),

    #[error("Corrupted data detected")]
    CorruptedData,

    #[error("Missing encryption key")]
    MissingKey,

    #[error("Time conversion error")]
    TimeError,

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("MAC access denied")]
    MacDenied,

    #[error("IDS alert: {0}")]
    IdsAlert(String),

    #[error("Forensics chain broken at seq {0}")]
    ForensicsChainBroken(u64),

    #[error("Permission denied")]
    PermissionDenied,
}

impl From<HfsError> for libc::c_int {
    fn from(e: HfsError) -> Self {
        match e {
            HfsError::NoEntry            => libc::ENOENT,
            HfsError::QuotaExceeded(_)   => libc::EDQUOT,
            HfsError::RateLimited(_)     => libc::EBUSY,
            HfsError::CorruptedData      => libc::EIO,
            HfsError::InvalidArgument(_) => libc::EINVAL,
            HfsError::MacDenied          => libc::EACCES,
            HfsError::PermissionDenied   => libc::EACCES,
            HfsError::SuperblockTampered => libc::EIO,
            _                            => libc::EIO,
        }
    }
}
