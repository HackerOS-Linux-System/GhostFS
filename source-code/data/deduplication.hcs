use sled::Db;
use crate::error::HfsError;

#[derive(Clone)]
pub struct Deduplication { db: Db }

impl Deduplication {
    pub fn new(db: &Db) -> Result<Self, HfsError> { Ok(Self { db: db.clone() }) }

    pub fn find_duplicate(&self, data: &[u8]) -> Result<Option<(u64, usize)>, HfsError> {
        let hash = blake3::hash(data);
        let key  = format!("dedup:{}", hash);
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
        // Inicjalizuj licznik referencji dla nowego bloku na 1.
        let ck = format!("refcount:{}:{}", ino, block_idx);
        self.db.insert(ck.as_bytes(), bincode::serialize(&1u64)?)?;
        Ok(())
    }

    pub fn add_reference(&self, ino: u64, block_idx: usize, orig_ino: u64, orig_idx: usize) -> Result<(), HfsError> {
        let rk = format!("ref:{}:{}", ino, block_idx);
        self.db.insert(rk.as_bytes(), bincode::serialize(&(orig_ino, orig_idx))?)?;
        let ck = format!("refcount:{}:{}", orig_ino, orig_idx);
        let c: u64 = self.db.get(ck.as_bytes())?.map(|v| bincode::deserialize(&v).unwrap_or(0)).unwrap_or(0);
        self.db.insert(ck.as_bytes(), bincode::serialize(&(c + 1))?)?;
        Ok(())
    }

    /// Usuń referencję i wyczyść wpis dedup:hash gdy refcount spada do zera.
    pub fn remove_reference(&self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let rk = format!("ref:{}:{}", ino, block_idx);
        if let Some(rv) = self.db.get(rk.as_bytes())? {
            // Blok jest kopią — dekrementuj refcount oryginału.
            let (orig_ino, orig_idx): (u64, usize) = bincode::deserialize(&rv)?;
            let ck = format!("refcount:{}:{}", orig_ino, orig_idx);
            if let Some(v) = self.db.get(ck.as_bytes())? {
                let c: u64 = bincode::deserialize(&v)?;
                if c > 1 {
                    self.db.insert(ck.as_bytes(), bincode::serialize(&(c - 1))?)?;
                } else {
                    // Ostatnia referencja — usuń cały wpis dedup.
                    self.db.remove(ck.as_bytes())?;
                    self.purge_dedup_entry(orig_ino, orig_idx)?;
                }
            }
            self.db.remove(rk.as_bytes())?;
        } else {
            // Blok jest oryginałem — sprawdź jego własny refcount.
            let ck = format!("refcount:{}:{}", ino, block_idx);
            if let Some(v) = self.db.get(ck.as_bytes())? {
                let c: u64 = bincode::deserialize(&v)?;
                if c <= 1 {
                    self.db.remove(ck.as_bytes())?;
                    self.purge_dedup_entry(ino, block_idx)?;
                } else {
                    self.db.insert(ck.as_bytes(), bincode::serialize(&(c - 1))?)?;
                }
            }
        }
        Ok(())
    }

    /// Usuń wpis dedup:<hash> i hash:<ino>:<idx> dla danego bloku.
    fn purge_dedup_entry(&self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let hkey = format!("hash:{}:{}", ino, block_idx);
        if let Some(stored_hash) = self.db.get(hkey.as_bytes())? {
            // Odtwórz klucz dedup z zapisanego hasha.
            let hash_hex = hex::encode(&stored_hash);
            let dedup_key = format!("dedup:{}", hash_hex);
            // Usuń tylko jeśli nadal wskazuje na ten blok (może być już nadpisany).
            if let Some(v) = self.db.get(dedup_key.as_bytes())? {
                let (stored_ino, stored_idx): (u64, usize) = bincode::deserialize(&v)?;
                if stored_ino == ino && stored_idx == block_idx {
                    self.db.remove(dedup_key.as_bytes())?;
                    log::debug!("dedup: purged hash entry for ino={} block={}", ino, block_idx);
                }
            }
            self.db.remove(hkey.as_bytes())?;
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
