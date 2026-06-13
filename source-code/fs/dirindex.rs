use sled::Db;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use hex;
use crate::error::HfsError;

const INDEX_PREFIX: &str = "didx:";
const COUNT_PREFIX: &str = "didx_count:";

fn entry_hash(name: &OsStr) -> String {
    let hash = blake3::hash(name.as_bytes());
    hex::encode(&hash.as_bytes()[..8]) // 8-byte prefix is enough to sort/partition
}

fn entry_key(parent: u64, name: &OsStr) -> String {
    format!(
        "{}{}:{}:{}",
        INDEX_PREFIX,
        parent,
        entry_hash(name),
            String::from_utf8_lossy(name.as_bytes())
    )
}

#[derive(Clone)]
pub struct DirIndex {
    db: Db,
}

impl DirIndex {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    pub fn insert(&self, parent: u64, name: &OsStr, ino: u64) -> Result<(), HfsError> {
        let key = entry_key(parent, name);
        self.db
        .insert(key.as_bytes(), bincode::serialize(&ino)?)?;
        // Increment entry count
        let count_key = format!("{}{}", COUNT_PREFIX, parent);
        let count: u64 = match self.db.get(count_key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
            None => 0,
        };
        self.db
        .insert(count_key.as_bytes(), bincode::serialize(&(count + 1))?)?;
        Ok(())
    }

    pub fn lookup(&self, parent: u64, name: &OsStr) -> Result<Option<u64>, HfsError> {
        let key = entry_key(parent, name);
        match self.db.get(key.as_bytes())? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    pub fn remove(&self, parent: u64, name: &OsStr) -> Result<(), HfsError> {
        let key = entry_key(parent, name);
        if self.db.remove(key.as_bytes())?.is_some() {
            let count_key = format!("{}{}", COUNT_PREFIX, parent);
            let count: u64 = match self.db.get(count_key.as_bytes())? {
                Some(v) => bincode::deserialize(&v)?,
                None => 0,
            };
            if count > 0 {
                self.db.insert(
                    count_key.as_bytes(),
                               bincode::serialize(&(count - 1))?,
                )?;
            }
        }
        Ok(())
    }

    /// Return all (name, ino) pairs for a directory, sorted by hash (stable order).
    pub fn list(&self, parent: u64) -> Result<Vec<(OsString, u64)>, HfsError> {
        let prefix = format!("{}{}:", INDEX_PREFIX, parent);
        let mut entries = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (k, v) = item?;
            let k_str = String::from_utf8(k.to_vec())?;
            // key = didx:<parent>:<hash>:<name>
            // Strip "didx:<parent>:<hash>:" (3 colon-separated segments after prefix)
            let rest = &k_str[prefix.len()..];
            // rest = "<hash>:<name>"
            if let Some(colon) = rest.find(':') {
                let name_str = &rest[colon + 1..];
                let ino: u64 = bincode::deserialize(&v)?;
                entries.push((OsString::from(name_str), ino));
            }
        }
        Ok(entries)
    }

    pub fn entry_count(&self, parent: u64) -> Result<u64, HfsError> {
        let count_key = format!("{}{}", COUNT_PREFIX, parent);
        Ok(match self.db.get(count_key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
           None => 0,
        })
    }
}
