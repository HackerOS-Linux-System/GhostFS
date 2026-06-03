use sled::Db;
use crate::crypto::Crypto;
use crate::compression::Compression;
use crate::deduplication::Deduplication;
use crate::versioning::Versioning;
use crate::error::HfsError;
use crate::FS_BLOCK_SIZE;

#[derive(Clone)]
pub struct Repair {
    db:          Db,
    crypto:      Option<Crypto>,
    compression: Compression,
    dedup:       Deduplication,
    versioning:  Versioning,
}

impl Repair {
    pub fn new(
        db:          &Db,
        crypto:      &Option<Crypto>,
        compression: &Compression,
        dedup:       &Deduplication,
        versioning:  &Versioning,
    ) -> Result<Self, HfsError> {
        Ok(Self {
            db:          db.clone(),
           crypto:      crypto.clone(),
           compression: compression.clone(),
           dedup:       dedup.clone(),
           versioning:  versioning.clone(),
        })
    }

    /// Verify all blocks of a single inode and attempt repair if corrupted.
    /// Returns `true` if the inode needed (and received) repair.
    pub fn verify_and_repair(&self, ino: u64) -> Result<bool, HfsError> {
        let inode_key  = format!("inode:{}", ino);
        let inode_data = match self.db.get(inode_key.as_bytes())? {
            Some(d) => d,
            None    => return Ok(false),
        };
        let inode: crate::serialization::Inode = bincode::deserialize(&inode_data)?;
        let block_count =
        (inode.attr.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64;

        let mut corrupted = false;

        for block_idx in 0..block_count as usize {
            let block_key = format!("data:{}:{}", ino, block_idx);
            let raw = match self.db.get(block_key.as_bytes())? {
                Some(v) => v,
                None    => continue, // sparse block — OK
            };

            // Decrypt
            let decrypted = match &self.crypto {
                Some(c) => match c.decrypt(&raw) {
                    Ok(d)  => d,
                    Err(_) => {
                        log::error!("repair: crypto failure ino={} block={}", ino, block_idx);
                        corrupted = true;
                        break;
                    }
                },
                None => raw.to_vec(),
            };

            // Decompress
            let decompressed = match self.compression.decompress(&decrypted) {
                Ok(d)  => d,
                Err(_) => {
                    log::error!("repair: decompress failure ino={} block={}", ino, block_idx);
                    corrupted = true;
                    break;
                }
            };

            // Dedup hash verification
            if self.dedup.verify(ino, block_idx, &decompressed).is_err() {
                log::warn!(
                    "repair: hash mismatch ino={} block={} — attempting restore",
                    ino, block_idx
                );
                corrupted = true;
                break;
            }

            // Cybersec: Merkle leaf verification
            #[cfg(feature = "cybersec")]
            {
                let leaf_key = format!("itree:{}:leaf:{}", ino, block_idx);
                if let Ok(Some(stored_hash)) = self.db.get(leaf_key.as_bytes()) {
                    let computed = blake3::hash(&decompressed);
                    if computed.as_bytes().as_ref() != stored_hash.as_ref() {
                        log::warn!(
                            "repair: Merkle mismatch ino={} block={} — attempting restore",
                            ino, block_idx
                        );
                        corrupted = true;
                        break;
                    }
                }
            }
        }

        if corrupted {
            // Attempt restore from most recent version
            if let Ok(versions) = self.versioning.list_versions(ino) {
                if let Some(&latest) = versions.iter().max() {
                    if self.versioning.restore_version(ino, latest).is_ok() {
                        log::info!("repair: restored ino={} from version ts={}", ino, latest);
                        return Ok(true);
                    }
                }
            }
            log::error!("repair: could not recover ino={} — no usable version", ino);
        }

        Ok(corrupted)
    }

    /// Scan every inode in the database and repair as needed.
    /// Called by the background repair thread (hourly).
    pub fn scan_and_repair(&self) -> Result<(), HfsError> {
        let prefix = "inode:";
        let mut repaired = 0u64;
        let mut scanned  = 0u64;

        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (k, _) = item?;
            let k_str  = String::from_utf8(k.to_vec())?;
            if let Some(ino_str) = k_str.strip_prefix(prefix) {
                if let Ok(ino) = ino_str.parse::<u64>() {
                    scanned += 1;
                    if self.verify_and_repair(ino).unwrap_or(false) {
                        repaired += 1;
                    }
                }
            }
        }

        log::info!(
            "GhostFS repair scan complete: {} inodes scanned, {} repaired",
            scanned, repaired
        );
        Ok(())
    }
}
