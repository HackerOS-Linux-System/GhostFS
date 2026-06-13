use sled::Db;
use serde::{Serialize, Deserialize};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use crate::error::HfsError;

const MAX_AUDIT_ENTRIES: u64 = 100_000;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: u64,
    pub uid: u32,
    pub operation: String,
    pub ino: u64,
    pub name: Option<Vec<u8>>,
    pub event_count: u64,
}

pub struct Audit { db: Db }

impl Audit {
    pub fn new(db: &Db) -> Result<Self, HfsError> { Ok(Self { db: db.clone() }) }

    fn load_seq(&self) -> Result<u64, HfsError> {
        Ok(match self.db.get(b"audit:seq")? {
            Some(v) => bincode::deserialize(&v)?,
           None => 0,
        })
    }
    fn load_event_count(&self) -> Result<u64, HfsError> {
        Ok(match self.db.get(b"audit:event_count")? {
            Some(v) => bincode::deserialize(&v)?,
           None => 0,
        })
    }

    pub fn log(&self, uid: u32, operation: &str, ino: u64, name: Option<&OsStr>) -> Result<(), HfsError> {
        let seq = self.load_seq()?;
        let event_count = self.load_event_count()?;
        let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HfsError::TimeError)?.as_secs();
        let entry = AuditEntry { seq, timestamp, uid, operation: operation.to_string(),
            ino, name: name.map(|n| n.as_bytes().to_vec()), event_count: event_count + 1 };
            let key = format!("audit:entry:{:016}", seq);
            self.db.insert(key.as_bytes(), bincode::serialize(&entry)?)?;
            self.db.insert(b"audit:seq", bincode::serialize(&(seq + 1))?)?;
            self.db.insert(b"audit:event_count", bincode::serialize(&(event_count + 1))?)?;
            if seq > MAX_AUDIT_ENTRIES {
                let prune_key = format!("audit:entry:{:016}", seq - MAX_AUDIT_ENTRIES);
                self.db.remove(prune_key.as_bytes())?;
            }
            Ok(())
    }

    pub fn tail(&self, n: usize) -> Result<Vec<AuditEntry>, HfsError> {
        let seq = self.load_seq()?;
        let start = seq.saturating_sub(n as u64);
        let mut out = Vec::new();
        for s in start..seq {
            let key = format!("audit:entry:{:016}", s);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                if let Ok(e) = bincode::deserialize::<AuditEntry>(&raw) { out.push(e); }
            }
        }
        Ok(out)
    }
}
