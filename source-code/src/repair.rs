use sled::Db;
use crate::crypto::Crypto;
use crate::compression::Compression;
use crate::deduplication::Deduplication;
use crate::versioning::Versioning;
use crate::error::HfsError;
use crate::FS_BLOCK_SIZE;

#[derive(Clone)]
pub struct Repair {
    db: Db,
    crypto: Option<Crypto>,
    compression: Compression,
    dedup: Deduplication,
    versioning: Versioning,
}

impl Repair {
    pub fn new(db: &Db, crypto: &Option<Crypto>, compression: &Compression, dedup: &Deduplication, versioning: &Versioning) -> Result<Self, HfsError> {
        Ok(Self {
            db: db.clone(),
           crypto: crypto.clone(),
           compression: compression.clone(),
           dedup: dedup.clone(),
           versioning: versioning.clone(),
        })
    }

    pub fn verify_and_repair(&self, ino: u64) -> Result<bool, HfsError> {
        let inode_key = format!("inode:{}", ino);
        let inode_data = match self.db.get(inode_key.as_bytes())? {
            Some(d) => d,
            None => return Ok(false),
        };
        let inode: crate::serialization::Inode = bincode::deserialize(&inode_data)?;

        let block_count = (inode.attr.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64;
        let mut corrupted = false;

        for block_idx in 0..block_count as usize {
            let block_key = format!("data:{}:{}", ino, block_idx);
            if let Some(encrypted) = self.db.get(block_key.as_bytes())? {
                let decrypted = if let Some(crypto) = &self.crypto {
                    crypto.decrypt(&encrypted)?
                } else {
                    encrypted.to_vec()
                };
                let decompressed = self.compression.decompress(&decrypted)?;

                if let Err(_) = self.dedup.verify(ino, block_idx, &decompressed) {
                    corrupted = true;
                    if let Ok(versions) = self.versioning.list_versions(ino) {
                        if let Some(&latest) = versions.iter().max() {
                            if self.versioning.restore_version(ino, latest).is_ok() {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        Ok(corrupted)
    }

    pub fn scan_and_repair(&self) -> Result<(), HfsError> {
        let prefix = "inode:";
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (k, _) = item?;
            let k_str = String::from_utf8(k.to_vec())?;
            if let Some(ino_str) = k_str.strip_prefix(prefix) {
                if let Ok(ino) = ino_str.parse::<u64>() {
                    let _ = self.verify_and_repair(ino);
                }
            }
        }
        Ok(())
    }
}
