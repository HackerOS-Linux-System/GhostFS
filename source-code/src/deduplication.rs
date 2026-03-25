use sled::Db;
use blake3::Hasher;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

pub struct Deduplication {
    db: Db,
}

impl Deduplication {
    pub fn new(db: &Db) -> Result<Self, ()> {
        Ok(Self { db: db.clone() })
    }

    pub fn find_duplicate(&self, data: &[u8]) -> Result<(Option<u64>, Option<usize>), ()> {
        let hash = blake3::hash(data);
        let key = format!("dedup:{}", hash);
        if let Some(value) = self.db.get(key.as_bytes()).map_err(|_| ())? {
            let (ino, block_idx): (u64, usize) = bincode::deserialize(&value).map_err(|_| ())?;
            Ok((Some(ino), Some(block_idx)))
        } else {
            Ok((None, None))
        }
    }

    pub fn insert_hash(&self, ino: u64, block_idx: usize, data: &[u8]) -> Result<(), ()> {
        let hash = blake3::hash(data);
        let key = format!("dedup:{}", hash);
        let value = bincode::serialize(&(ino, block_idx)).map_err(|_| ())?;
        self.db.insert(key.as_bytes(), value).map_err(|_| ())?;
        Ok(())
    }

    pub fn add_reference(&self, ino: u64, block_idx: usize, original_ino: u64, original_idx: usize) -> Result<(), ()> {
        // Zapisujemy mapowanie referencji
        let key = format!("ref:{}:{}", ino, block_idx);
        let value = bincode::serialize(&(original_ino, original_idx)).map_err(|_| ())?;
        self.db.insert(key.as_bytes(), value).map_err(|_| ())?;
        // Zwiększamy licznik referencji dla oryginalnego bloku (opcjonalnie)
        let refcount_key = format!("refcount:{}:{}", original_ino, original_idx);
        let count: u64 = match self.db.get(refcount_key.as_bytes()).map_err(|_| ())? {
            Some(v) => bincode::deserialize(&v).map_err(|_| ())?,
            None => 0,
        };
        let new_count = count + 1;
        self.db.insert(refcount_key.as_bytes(), bincode::serialize(&new_count).map_err(|_| ())?).map_err(|_| ())?;
        Ok(())
    }

    pub fn verify(&self, ino: u64, block_idx: usize, data: &[u8]) -> Result<(), ()> {
        // Sprawdź czy blok jest referencją
        let ref_key = format!("ref:{}:{}", ino, block_idx);
        if let Some(ref_value) = self.db.get(ref_key.as_bytes()).map_err(|_| ())? {
            let (orig_ino, orig_idx): (u64, usize) = bincode::deserialize(&ref_value).map_err(|_| ())?;
            // Pobierz oryginalny blok i porównaj hash
            let orig_hash_key = format!("dedup:{}:{}", orig_ino, orig_idx);
            if let Some(orig_hash) = self.db.get(orig_hash_key.as_bytes()).map_err(|_| ())? {
                let computed_hash = blake3::hash(data);
                if computed_hash.as_bytes() != orig_hash.as_ref() {
                    return Err(());
                }
            } else {
                return Err(());
            }
        } else {
            // Normalny blok – sprawdź czy hash się zgadza
            let hash_key = format!("dedup:{}:{}", ino, block_idx);
            if let Some(stored_hash) = self.db.get(hash_key.as_bytes()).map_err(|_| ())? {
                let computed_hash = blake3::hash(data);
                if computed_hash.as_bytes() != stored_hash.as_ref() {
                    return Err(());
                }
            }
        }
        Ok(())
    }
}
