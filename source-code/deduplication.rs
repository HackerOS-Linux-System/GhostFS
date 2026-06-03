use sled::Db;
use crate::error::HfsError;

#[derive(Clone)]
pub struct Deduplication { db: Db }

impl Deduplication {
    pub fn new(db: &Db) -> Result<Self, HfsError> { Ok(Self { db: db.clone() }) }

    pub fn find_duplicate(&self, data: &[u8]) -> Result<Option<(u64, usize)>, HfsError> {
        let hash = blake3::hash(data);
        let key = format!("dedup:{}", hash);
        match self.db.get(key.as_bytes())? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None    => Ok(None),
        }
    }
    pub fn insert_hash(&self, ino: u64, block_idx: usize, data: &[u8]) -> Result<(), HfsError> {
        let hash = blake3::hash(data);
        let key  = format!("dedup:{}", hash);
        self.db.insert(key.as_bytes(), bincode::serialize(&(ino, block_idx))?)?;
        let hkey = format!("hash:{}:{}", ino, block_idx);
        self.db.insert(hkey.as_bytes(), hash.as_bytes().to_vec())?;
        Ok(())
    }
    pub fn add_reference(&self, ino: u64, block_idx: usize, orig_ino: u64, orig_idx: usize) -> Result<(), HfsError> {
        let rk = format!("ref:{}:{}", ino, block_idx);
        self.db.insert(rk.as_bytes(), bincode::serialize(&(orig_ino, orig_idx))?)?;
        let ck = format!("refcount:{}:{}", orig_ino, orig_idx);
        let c: u64 = self.db.get(ck.as_bytes())?.map(|v| bincode::deserialize(&v).unwrap_or(0)).unwrap_or(0);
        self.db.insert(ck.as_bytes(), bincode::serialize(&(c+1))?)?;
        Ok(())
    }
    pub fn remove_reference(&self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let rk = format!("ref:{}:{}", ino, block_idx);
        if let Some(rv) = self.db.get(rk.as_bytes())? {
            let (orig_ino, orig_idx): (u64, usize) = bincode::deserialize(&rv)?;
            let ck = format!("refcount:{}:{}", orig_ino, orig_idx);
            if let Some(v) = self.db.get(ck.as_bytes())? {
                let c: u64 = bincode::deserialize(&v)?;
                if c > 1 { self.db.insert(ck.as_bytes(), bincode::serialize(&(c-1))?)?; }
                else      { self.db.remove(ck.as_bytes())?; }
            }
            self.db.remove(rk.as_bytes())?;
        }
        Ok(())
    }
    pub fn verify(&self, ino: u64, block_idx: usize, data: &[u8]) -> Result<(), HfsError> {
        let hkey = format!("hash:{}:{}", ino, block_idx);
        if let Some(stored) = self.db.get(hkey.as_bytes())? {
            let computed = blake3::hash(data);
            if computed.as_bytes().as_ref() != stored.as_ref() {
                return Err(HfsError::CorruptedData);
            }
        }
        Ok(())
    }
}
