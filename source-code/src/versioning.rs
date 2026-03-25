use sled::Db;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use crate::error::HfsError;

#[derive(Serialize, Deserialize, Clone)]
struct Version {
    timestamp: u64,
    inode: Vec<u8>,               // serialized Inode
    blocks: BTreeMap<usize, Vec<u8>>, // changed blocks (block index -> data)
}

pub struct Versioning {
    db: Db,
}

impl Versioning {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    /// Create a new version of the file identified by `ino`.
    /// This stores the current inode and a snapshot of all blocks that have been modified.
    /// In a full implementation, you would track changes during writes and pass them here.
    /// For simplicity, we store the full inode and an empty block map,
    /// which means that restore will only restore the inode metadata, not the data.
    /// A production version would need to also store block diffs or use copy-on-write.
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
            blocks: BTreeMap::new(), // no block diffs stored here
        };

        let version_key = format!("versions:{}:{}", ino, timestamp);
        self.db.insert(version_key.as_bytes(), bincode::serialize(&version)?)?;

        // Update the version list for this inode
        let list_key = format!("version_list:{}", ino);
        let mut versions: Vec<u64> = match self.db.get(list_key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
            None => Vec::new(),
        };
        versions.push(timestamp);
        self.db.insert(list_key.as_bytes(), bincode::serialize(&versions)?)?;

        Ok(())
    }

    /// List all version timestamps for a given inode.
    pub fn list_versions(&self, ino: u64) -> Result<Vec<u64>, HfsError> {
        let list_key = format!("version_list:{}", ino);
        match self.db.get(list_key.as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None => Ok(Vec::new()),
        }
    }

    /// Restore a file to a previous version.
    /// This replaces the current inode and the blocks stored in the version.
    pub fn restore_version(&self, ino: u64, timestamp: u64) -> Result<(), HfsError> {
        let version_key = format!("versions:{}:{}", ino, timestamp);
        let version_data = self.db.get(version_key.as_bytes())?
            .ok_or(HfsError::NoEntry)?;
        let version: Version = bincode::deserialize(&version_data)?;

        // Restore inode
        let inode_key = format!("inode:{}", ino);
        self.db.insert(inode_key.as_bytes(), version.inode)?;

        // Restore blocks (if any)
        for (block_idx, data) in version.blocks {
            let block_key = format!("data:{}:{}", ino, block_idx);
            self.db.insert(block_key.as_bytes(), data)?;
        }

        Ok(())
    }
}
