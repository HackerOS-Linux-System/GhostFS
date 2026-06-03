use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;



#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Extent {
    /// First logical block number covered by this extent
    pub logical_start: u64,
    /// Number of blocks in the run
    pub length: u32,
    /// Physical key prefix (e.g. "data:<ino>:<logical_start>")
    pub phys_key_prefix: String,
}

#[derive(Clone)]
pub struct ExtentTree {
    db: Db,
}

impl ExtentTree {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn index_key(ino: u64) -> String {
        format!("ext_idx:{}", ino)
    }

    fn extent_key(ino: u64, logical_start: u64) -> String {
        format!("ext:{}:{}", ino, logical_start)
    }

    fn load_index(&self, ino: u64) -> Result<Vec<u64>, HfsError> {
        match self.db.get(Self::index_key(ino).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None => Ok(Vec::new()),
        }
    }

    fn save_index(&self, ino: u64, index: &Vec<u64>) -> Result<(), HfsError> {
        self.db.insert(
            Self::index_key(ino).as_bytes(),
                       bincode::serialize(index)?,
        )?;
        Ok(())
    }

    /// Record that block `block_idx` of inode `ino` lives at key `phys_key`.
    /// Merges with adjacent extents when possible (extent coalescing).
    pub fn record(
        &self,
        ino: u64,
        block_idx: usize,
        phys_key: &str,
    ) -> Result<(), HfsError> {
        let mut index = self.load_index(ino)?;
        let logical = block_idx as u64;

        // Check if this block extends an existing extent
        if let Some(&prev_start) = index.iter().rev().find(|&&s| s <= logical) {
            let ekey = Self::extent_key(ino, prev_start);
            if let Some(raw) = self.db.get(ekey.as_bytes())? {
                let mut ext: Extent = bincode::deserialize(&raw)?;
                if prev_start + ext.length as u64 == logical {
                    // Coalesce: extend the run by one block
                    ext.length += 1;
                    self.db.insert(ekey.as_bytes(), bincode::serialize(&ext)?)?;
                    return Ok(());
                }
            }
        }

        // New extent for this block
        let ext = Extent {
            logical_start: logical,
            length: 1,
            phys_key_prefix: phys_key.to_string(),
        };
        let ekey = Self::extent_key(ino, logical);
        self.db.insert(ekey.as_bytes(), bincode::serialize(&ext)?)?;
        // Insert into sorted index
        let pos = index.partition_point(|&s| s < logical);
        index.insert(pos, logical);
        self.save_index(ino, &index)?;
        Ok(())
    }

    /// Resolve logical block to its physical storage key (if tracked).
    pub fn resolve(&self, ino: u64, block_idx: usize) -> Option<String> {
        let logical = block_idx as u64;
        let index = self.load_index(ino).ok()?;
        // Binary search for the extent whose start <= logical
        let pos = index.partition_point(|&s| s <= logical);
        if pos == 0 {
            return None;
        }
        let start = index[pos - 1];
        let ekey = Self::extent_key(ino, start);
        let raw = self.db.get(ekey.as_bytes()).ok()??;
        let ext: Extent = bincode::deserialize(&raw).ok()?;
        if logical < start + ext.length as u64 {
            // Within this extent — compute the actual key
            let offset = logical - start;
            if offset == 0 {
                Some(ext.phys_key_prefix.clone())
            } else {
                // Keys beyond the prefix are the standard data:<ino>:<block> pattern
                Some(format!("data:{}:{}", ino, block_idx))
            }
        } else {
            None
        }
    }

    /// Remove extent tracking for a single block.
    pub fn remove(&self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let logical = block_idx as u64;
        let mut index = self.load_index(ino)?;
        let pos = index.partition_point(|&s| s < logical);
        if pos < index.len() && index[pos] == logical {
            let ekey = Self::extent_key(ino, logical);
            if let Some(raw) = self.db.get(ekey.as_bytes())? {
                let ext: Extent = bincode::deserialize(&raw)?;
                if ext.length == 1 {
                    self.db.remove(ekey.as_bytes())?;
                    index.remove(pos);
                    self.save_index(ino, &index)?;
                } else {
                    // Shrink: split the extent
                    let mut ext = ext;
                    ext.logical_start += 1;
                    ext.length -= 1;
                    let new_ekey = Self::extent_key(ino, ext.logical_start);
                    self.db.remove(ekey.as_bytes())?;
                    self.db.insert(new_ekey.as_bytes(), bincode::serialize(&ext)?)?;
                    index[pos] = ext.logical_start;
                    self.save_index(ino, &index)?;
                }
            }
        }
        Ok(())
    }

    /// Remove all extent records for a deleted inode.
    pub fn remove_all(&self, ino: u64) -> Result<(), HfsError> {
        let prefix = format!("ext:{}:", ino);
        let keys: Vec<_> = self
        .db
        .scan_prefix(prefix.as_bytes())
        .filter_map(|r| r.ok())
        .map(|(k, _)| k)
        .collect();
        let mut batch = sled::Batch::default();
        for k in keys {
            batch.remove(k);
        }
        self.db.remove(Self::index_key(ino).as_bytes())?;
        self.db.apply_batch(batch)?;
        Ok(())
    }
}
