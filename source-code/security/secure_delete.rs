use sled::Db;
use rand::Rng;
use crate::error::HfsError;

/// Number of overwrite passes (1 = random, sufficient with AES encryption).
/// Increase to 3 for DOD 5220.22-M compliance (if required by policy).
const WIPE_PASSES: usize = 1;

#[derive(Clone)]
pub struct SecureDelete {
    _db: Db,
}

impl SecureDelete {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { _db: db.clone() })
    }

    /// Securely wipe a sled key:
    /// 1. Read the current value to determine its size.
    /// 2. Overwrite with `WIPE_PASSES` rounds of random bytes.
    /// 3. Flush to storage.
    /// 4. Remove the key (tombstone).
    pub fn wipe_block(&self, db: &Db, key: &str) -> Result<(), HfsError> {
        if let Some(current) = db.get(key.as_bytes())? {
            let size = current.len();
            for _ in 0..WIPE_PASSES {
                let random_data: Vec<u8> = (0..size)
                .map(|_| rand::thread_rng().gen::<u8>())
                .collect();
                db.insert(key.as_bytes(), random_data)?;
            }
            // Flush to storage before removing the key
            db.flush()?;
            db.remove(key.as_bytes())?;
            db.flush()?;
        }
        Ok(())
    }

    /// Wipe all data blocks for a given inode (called on secure unlink).
    pub fn wipe_inode_blocks(&self, db: &Db, ino: u64) -> Result<(), HfsError> {
        let prefix = format!("data:{}:", ino);
        // Collect all keys first (can't modify while iterating)
        let keys: Vec<String> = db
        .scan_prefix(prefix.as_bytes())
        .filter_map(|r| r.ok())
        .filter_map(|(k, _)| String::from_utf8(k.to_vec()).ok())
        .collect();

        for key in &keys {
            self.wipe_block(db, key)?;
        }

        log::info!("GhostFS secure_delete: wiped {} blocks for ino={}", keys.len(), ino);
        Ok(())
    }

    /// Wipe MAC labels, xattrs, forensics traces for an inode.
    /// Called when a classified file is deleted.
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
                    let size = current.len();
                    let zeros = vec![0u8; size];
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
