use sled::Db;
use blake3;
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

    pub fn verify_and_repair(&self, ino: u64) -> Result<bool, HfsError> {
        let inode_key  = format!("inode:{}", ino);
        let inode_data = match self.db.get(inode_key.as_bytes())? {
            Some(d) => d,
            None    => return Ok(false),
        };
        let inode: crate::serialization::Inode = bincode::deserialize(&inode_data)?;
        let block_count = (inode.attr.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64;

        let mut corrupted = false;
        for block_idx in 0..block_count as usize {
            let block_key = format!("data:{}:{}", ino, block_idx);
            let raw = match self.db.get(block_key.as_bytes())? {
                Some(v) => v,
                None    => continue,
            };
            let decrypted = match &self.crypto {
                Some(c) => match c.decrypt(&raw) {
                    Ok(d)  => d,
                    Err(_) => { corrupted = true; break; }
                },
                None => raw.to_vec(),
            };
            let decompressed = match self.compression.decompress(&decrypted) {
                Ok(d)  => d,
                Err(_) => { corrupted = true; break; }
            };
            if self.dedup.verify(ino, block_idx, &decompressed).is_err() {
                corrupted = true; break;
            }
            // Merkle leaf verification
            let leaf_key = format!("itree:{}:leaf:{}", ino, block_idx);
            if let Ok(Some(stored_hash)) = self.db.get(leaf_key.as_bytes()) {
                let computed = blake3::hash(&decompressed);
                if computed.as_bytes().as_ref() != stored_hash.as_ref() {
                    corrupted = true; break;
                }
            }
        }

        if corrupted {
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
                    if self.verify_and_repair(ino).unwrap_or(false) { repaired += 1; }
                }
            }
        }
        log::info!("GhostFS repair: {} scanned, {} repaired", scanned, repaired);
        Ok(())
    }
}
