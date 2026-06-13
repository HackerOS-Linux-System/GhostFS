use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;
use crate::FS_BLOCK_SIZE;

/// Maximum number of versions kept per inode.
const MAX_VERSIONS: usize = 8;

#[derive(Serialize, Deserialize, Clone)]
pub struct Version {
    pub timestamp: u64,
    /// Serialised Inode (metadata snapshot)
    pub inode: Vec<u8>,
    /// Optional block snapshots captured during repair or explicit checkpoint.
    /// Key = block_idx, Value = raw (encrypted + compressed) bytes as stored in sled.
    pub blocks: std::collections::BTreeMap<usize, Vec<u8>>,
}

#[derive(Clone)]
pub struct Versioning {
    db: Db,
}

impl Versioning {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn list_key(ino: u64) -> String {
        format!("version_list:{}", ino)
    }

    fn version_key(ino: u64, ts: u64) -> String {
        format!("versions:{}:{}", ino, ts)
    }

    /// Snapshot the current inode metadata.
    /// Blocks are NOT copied here (cheap path called on every write).
    pub fn create_version(&self, ino: u64) -> Result<(), HfsError> {
        let inode_key  = format!("inode:{}", ino);
        let inode_data = match self.db.get(inode_key.as_bytes())? {
            Some(d) => d.to_vec(),
            None    => return Ok(()), // inode doesn't exist yet — nothing to snapshot
        };

        let timestamp = current_timestamp()?;
        let version = Version {
            timestamp,
            inode:  inode_data,
            blocks: std::collections::BTreeMap::new(),
        };

        let mut batch = sled::Batch::default();
        batch.insert(
            Self::version_key(ino, timestamp).as_bytes(),
                     bincode::serialize(&version)?,
        );

        // Maintain the sorted timestamp list
        let mut list = self.load_list(ino)?;
        list.push(timestamp);
        list.sort_unstable();

        // Evict oldest snapshots if over cap
        while list.len() > MAX_VERSIONS {
            let old_ts = list.remove(0);
            batch.remove(Self::version_key(ino, old_ts).as_bytes());
        }

        batch.insert(
            Self::list_key(ino).as_bytes(),
                     bincode::serialize(&list)?,
        );
        self.db.apply_batch(batch)?;
        Ok(())
    }

    /// Create a full checkpoint: snapshot inode + all block data.
    /// More expensive — called explicitly (e.g. before a truncate or bulk write).
    pub fn create_full_checkpoint(&self, ino: u64) -> Result<(), HfsError> {
        let inode_key  = format!("inode:{}", ino);
        let inode_data = match self.db.get(inode_key.as_bytes())? {
            Some(d) => d.to_vec(),
            None    => return Ok(()),
        };

        let inode: crate::serialization::Inode = bincode::deserialize(&inode_data)?;
        let block_count =
        (inode.attr.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64;

        let mut blocks = std::collections::BTreeMap::new();
        for idx in 0..block_count as usize {
            let bkey = format!("data:{}:{}", ino, idx);
            if let Some(raw) = self.db.get(bkey.as_bytes())? {
                blocks.insert(idx, raw.to_vec());
            }
        }

        let timestamp = current_timestamp()?;
        let version = Version { timestamp, inode: inode_data, blocks };

        let mut batch = sled::Batch::default();
        batch.insert(
            Self::version_key(ino, timestamp).as_bytes(),
                     bincode::serialize(&version)?,
        );

        let mut list = self.load_list(ino)?;
        list.push(timestamp);
        list.sort_unstable();
        while list.len() > MAX_VERSIONS {
            let old_ts = list.remove(0);
            batch.remove(Self::version_key(ino, old_ts).as_bytes());
        }
        batch.insert(
            Self::list_key(ino).as_bytes(),
                     bincode::serialize(&list)?,
        );
        self.db.apply_batch(batch)?;
        Ok(())
    }

    pub fn list_versions(&self, ino: u64) -> Result<Vec<u64>, HfsError> {
        self.load_list(ino)
    }

    /// Restore inode metadata (and blocks if the snapshot has them).
    pub fn restore_version(&self, ino: u64, timestamp: u64) -> Result<(), HfsError> {
        let vkey = Self::version_key(ino, timestamp);
        let raw  = self.db.get(vkey.as_bytes())?.ok_or(HfsError::NoEntry)?;
        let version: Version = bincode::deserialize(&raw)?;

        let mut batch = sled::Batch::default();
        // Restore inode metadata
        batch.insert(
            format!("inode:{}", ino).as_bytes(),
                version.inode.clone(),
        );
        // Restore block data if available in the snapshot
        for (block_idx, data) in &version.blocks {
            batch.insert(
                format!("data:{}:{}", ino, block_idx).as_bytes(),
                    data.clone(),
            );
        }
        self.db.apply_batch(batch)?;
        Ok(())
    }

    /// Remove all version records for a deleted inode.
    pub fn remove_all_versions(&self, ino: u64) -> Result<(), HfsError> {
        let list = self.load_list(ino)?;
        let mut batch = sled::Batch::default();
        for ts in list {
            batch.remove(Self::version_key(ino, ts).as_bytes());
        }
        batch.remove(Self::list_key(ino).as_bytes());
        self.db.apply_batch(batch)?;
        Ok(())
    }

    fn load_list(&self, ino: u64) -> Result<Vec<u64>, HfsError> {
        match self.db.get(Self::list_key(ino).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(Vec::new()),
        }
    }
}

fn current_timestamp() -> Result<u64, HfsError> {
    std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs())
    .map_err(|_| HfsError::TimeError)
}
