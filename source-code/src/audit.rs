use sled::Db;
use serde::{Serialize, Deserialize};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use crate::error::HfsError;

#[derive(Serialize, Deserialize)]
struct AuditEntry {
    timestamp: u64,
    uid: u32,
    operation: String,
    ino: u64,
    name: Option<Vec<u8>>,
}

pub struct Audit {
    db: Db,
}

impl Audit {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    pub fn log(&self, uid: u32, operation: &str, ino: u64, name: Option<&OsStr>) -> Result<(), HfsError> {
        let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HfsError::TimeError)?
        .as_secs();
        let entry = AuditEntry {
            timestamp,
            uid,
            operation: operation.to_string(),
            ino,
            name: name.map(|n| n.as_bytes().to_vec()),
        };
        let key = format!("audit:{}:{}", timestamp, rand::random::<u64>());
        self.db.insert(key.as_bytes(), bincode::serialize(&entry)?)?;
        Ok(())
    }
}
