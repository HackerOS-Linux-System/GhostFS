use sled::Db;
use crate::error::HfsError;

#[derive(Clone)]
pub struct Deduplication {
    db: Db,
}

impl Deduplication {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    pub fn find_duplicate(&self, data: &[u8]) -> Result<Option<(u64, usize)>, HfsError> {
        let hash = blake3::hash(data);
        let key = format!("dedup:{}", hash);
        match self.db.get(key.as_bytes())? {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn insert_hash(&self, ino: u64, block_idx: usize, data: &[u8]) -> Result<(), HfsError> {
        let hash = blake3::hash(data);
        let key = format!("dedup:{}", hash);
        let value = bincode::serialize(&(ino, block_idx))?;
        self.db.insert(key.as_bytes(), value)?;
        Ok(())
    }

    pub fn add_reference(&self, ino: u64, block_idx: usize, orig_ino: u64, orig_idx: usize) -> Result<(), HfsError> {
        let ref_key = format!("ref:{}:{}", ino, block_idx);
        self.db.insert(ref_key.as_bytes(), bincode::serialize(&(orig_ino, orig_idx))?)?;
        let refcount_key = format!("refcount:{}:{}", orig_ino, orig_idx);
        let count: u64 = match self.db.get(refcount_key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
            None => 0,
        };
        self.db.insert(refcount_key.as_bytes(), bincode::serialize(&(count + 1))?)?;
        Ok(())
    }

    pub fn remove_reference(&self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let ref_key = format!("ref:{}:{}", ino, block_idx);
        if let Some(ref_value) = self.db.get(ref_key.as_bytes())? {
            let (orig_ino, orig_idx): (u64, usize) = bincode::deserialize(&ref_value)?;
            let refcount_key = format!("refcount:{}:{}", orig_ino, orig_idx);
            if let Some(v) = self.db.get(refcount_key.as_bytes())? {
                let count: u64 = bincode::deserialize(&v)?;
                if count > 1 {
                    self.db.insert(refcount_key.as_bytes(), bincode::serialize(&(count - 1))?)?;
                } else {
                    self.db.remove(refcount_key.as_bytes())?;
                }
            }
            self.db.remove(ref_key.as_bytes())?;
        }
        Ok(())
    }

    pub fn verify(&self, ino: u64, block_idx: usize, data: &[u8]) -> Result<(), HfsError> {
        let ref_key = format!("ref:{}:{}", ino, block_idx);
        if let Some(ref_value) = self.db.get(ref_key.as_bytes())? {
            let (orig_ino, orig_idx): (u64, usize) = bincode::deserialize(&ref_value)?;
            let orig_key = format!("dedup:{}:{}", orig_ino, orig_idx);
            if let Some(stored_hash) = self.db.get(orig_key.as_bytes())? {
                let computed = blake3::hash(data);
                if computed.as_bytes() != stored_hash.as_ref() {
                    return Err(HfsError::CorruptedData);
                }
            } else {
                return Err(HfsError::CorruptedData);
            }
        } else {
            let hash_key = format!("hash:{}:{}", ino, block_idx);
            if let Some(stored_hash) = self.db.get(hash_key.as_bytes())? {
                let computed = blake3::hash(data);
                if computed.as_bytes() != stored_hash.as_ref() {
                    return Err(HfsError::CorruptedData);
                }
            }
        }
        Ok(())
    }
}
