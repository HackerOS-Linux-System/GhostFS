use sled::Db;
use rand::Rng;
use crate::error::HfsError;

const WIPE_PASSES: usize = 1;

#[derive(Clone)]
pub struct SecureDelete {
    _db: Db,
}

impl SecureDelete {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { _db: db.clone() })
    }

    pub fn wipe_block(&self, db: &Db, key: &str) -> Result<(), HfsError> {
        if let Some(current) = db.get(key.as_bytes())? {
            let size = current.len();
            for _ in 0..WIPE_PASSES {
                let random_data: Vec<u8> = (0..size).map(|_| rand::thread_rng().gen::<u8>()).collect();
                db.insert(key.as_bytes(), random_data)?;
            }
            db.flush()?;
            db.remove(key.as_bytes())?;
            db.flush()?;
        }
        Ok(())
    }

    pub fn wipe_inode_blocks(&self, db: &Db, ino: u64) -> Result<(), HfsError> {
        let prefix = format!("data:{}:", ino);
        let keys: Vec<String> = db
            .scan_prefix(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .filter_map(|(k, _)| String::from_utf8(k.to_vec()).ok())
            .collect();
        for key in &keys { self.wipe_block(db, key)?; }
        log::info!("GhostFS secure_delete: wiped {} blocks for ino={}", keys.len(), ino);
        Ok(())
    }

    pub fn wipe_metadata(&self, db: &Db, ino: u64) -> Result<(), HfsError> {
        let prefixes = [
            format!("xattr:{}:", ino),
            format!("mac:label:{}", ino),
            format!("itree:{}:", ino),
            format!("hash:{}:", ino),
            format!("ref:{}:", ino),
        ];
        for prefix in &prefixes {
            let keys: Vec<Vec<u8>> = db
                .scan_prefix(prefix.as_bytes())
                .filter_map(|r| r.ok())
                .map(|(k, _)| k.to_vec())
                .collect();
            for key in keys {
                if let Some(current) = db.get(&key)? {
                    let zeros = vec![0u8; current.len()];
                    db.insert(&key, zeros)?;
                    db.flush()?;
                    db.remove(&key)?;
                }
            }
        }
        db.flush()?;
        Ok(())
    }
}
