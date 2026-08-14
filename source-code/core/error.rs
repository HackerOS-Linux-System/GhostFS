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

    #[error("TPM error: {0}")]
    TpmError(String),

    #[error("Backup error: {0}")]
    BackupError(String),

    #[error("Backup file corrupted or truncated")]
    BackupCorrupted,

    #[error("Backup checksum mismatch — file may be tampered or corrupted")]
    BackupChecksumMismatch,

    #[error("Backup was created by an incompatible GhostFS version: {0}")]
    BackupVersionMismatch(String),

    #[error("UID {0} has been auto-locked by GhostFS IDS after repeated intrusion alerts — \
             all filesystem access denied until an administrator clears it \
             ('ghostfs ids unlock --device <dev> --uid {0}')")]
    UidLockedOut(u32),

    #[error("Operation blocked: inode {0} is under WORM/immutable protection \
             (see 'user.ghostfs.worm.lock' / 'user.ghostfs.worm.retain_until' xattrs)")]
    WormLocked(u64),

    #[error("Volume is under manual lockdown (ALL access denied, including root): {0} \
             — clear with 'ghostfs lockdown disable --device <dev>'")]
    VolumeLockedDown(String),
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
            HfsError::TpmError(_)        => libc::EIO,
            HfsError::BackupError(_)          => libc::EIO,
            HfsError::BackupCorrupted          => libc::EIO,
            HfsError::BackupChecksumMismatch   => libc::EIO,
            HfsError::BackupVersionMismatch(_) => libc::EIO,
            HfsError::UidLockedOut(_)   => libc::EACCES,
            HfsError::WormLocked(_)     => libc::EPERM,
            HfsError::VolumeLockedDown(_) => libc::EPERM,
            _                            => libc::EIO,
        }
    }
}
