use sled::Db;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use crate::error::HfsError;

#[derive(Serialize, Deserialize, Clone)]
struct Version {
    timestamp: u64,
    inode: Vec<u8>,
    blocks: BTreeMap<usize, Vec<u8>>,
}

#[derive(Clone)]
pub struct Versioning {
    db: Db,
}

impl Versioning {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    pub fn create_version(&self, ino: u64) -> Result<(), HfsError> {
        let inode_key = format!("inode:{}", ino);
        let inode_data = self.db.get(inode_key.as_bytes())?
        .ok_or(HfsError::NoEntry)?;

        let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HfsError::TimeError)?
        .as_secs();

        let version = Version {
            timestamp,
            inode: inode_data.to_vec(),
            blocks: BTreeMap::new(),
        };

        let version_key = format!("versions:{}:{}", ino, timestamp);
        self.db.insert(version_key.as_bytes(), bincode::serialize(&version)?)?;

        let list_key = format!("version_list:{}", ino);
        let mut versions: Vec<u64> = match self.db.get(list_key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
            None => Vec::new(),
        };
        versions.push(timestamp);
        self.db.insert(list_key.as_bytes(), bincode::serialize(&versions)?)?;
        Ok(())
    }

    pub fn list_versions(&self, ino: u64) -> Result<Vec<u64>, HfsError> {
        let list_key = format!("version_list:{}", ino);
        match self.db.get(list_key.as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn restore_version(&self, ino: u64, timestamp: u64) -> Result<(), HfsError> {
        let version_key = format!("versions:{}:{}", ino, timestamp);
        let version_data = self.db.get(version_key.as_bytes())?
        .ok_or(HfsError::NoEntry)?;
        let version: Version = bincode::deserialize(&version_data)?;

        let inode_key = format!("inode:{}", ino);
        self.db.insert(inode_key.as_bytes(), version.inode)?;

        for (block_idx, data) in version.blocks {
            let block_key = format!("data:{}:{}", ino, block_idx);
            self.db.insert(block_key.as_bytes(), data)?;
        }
        Ok(())
    }
}
