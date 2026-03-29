pub mod crypto;
pub mod compression;
pub mod deduplication;
pub mod versioning;
pub mod audit;
pub mod quota;
pub mod xattr;
pub mod repair;
pub mod cache;
pub mod error;
pub mod serialization;
pub mod fs;

use std::path::Path;
use sled::Db;
use anyhow::{Context, Result};
use crate::compression::{Compression, CompressionType};
use crate::deduplication::Deduplication;
use crate::versioning::Versioning;
use crate::audit::Audit;
use crate::quota::Quota;
use crate::xattr::XAttr;
use crate::repair::Repair;
use crate::cache::Cache;
use crate::error::HfsError;
use crate::serialization::Inode;
use std::sync::atomic::AtomicU64;
use crossbeam::channel::Sender;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

#[cfg(feature = "cybersec")]
use crate::crypto::{Crypto, Key};

#[cfg(feature = "normal")]
use crate::crypto::{Crypto, Key};

pub const FS_BLOCK_SIZE: u32 = 4096;
pub const ROOT_INO: u64 = 1;
pub const TTL: std::time::Duration = std::time::Duration::from_secs(1);

pub struct GhostFS {
    pub(crate) db: Db,
    pub(crate) next_ino: AtomicU64,

    #[cfg(feature = "cybersec")]
    pub(crate) crypto: Crypto,

    #[cfg(feature = "normal")]
    pub(crate) crypto: Option<Crypto>,

    pub(crate) compression: Compression,
    pub(crate) dedup: Deduplication,
    pub(crate) versioning: Versioning,
    pub(crate) audit: Audit,
    pub(crate) quota: Quota,
    pub(crate) xattr: XAttr,
    pub(crate) repair: Repair,
    pub(crate) cache: Cache,
    pub(crate) noatime: bool,
    pub(crate) background_repair_sender: Option<Sender<()>>,
}

impl GhostFS {
    pub fn new(db_path: &Path, cybersecurity: bool, key: Option<Key>, compression_type: Option<String>, noatime: bool) -> Result<Self> {
        let db = sled::open(db_path)
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;

        #[cfg(feature = "cybersec")]
        let crypto = {
            if !cybersecurity {
                return Err(anyhow::anyhow!("This build requires cybersecurity mode (--features cybersec)"));
            }
            let key = key.ok_or_else(|| anyhow::anyhow!("Cybersecurity mode requires a key"))?;
            Crypto::new(key)?
        };

        #[cfg(feature = "normal")]
        let crypto = if cybersecurity {
            let key = key.ok_or_else(|| anyhow::anyhow!("Cybersecurity mode requires a key"))?;
            Some(Crypto::new(key)?)
        } else {
            None
        };

        let compression = Compression::new(match compression_type.as_deref() {
            Some("zlib") => CompressionType::Zlib,
                                           #[cfg(feature = "zstd")]
                                           Some("zstd") => CompressionType::Zstd,
                                           #[cfg(feature = "lz4")]
                                           Some("lz4") => CompressionType::Lz4,
                                           _ => CompressionType::None,
        });

        let dedup = Deduplication::new(&db)?;
        let versioning = Versioning::new(&db)?;
        let audit = Audit::new(&db)?;
        let quota = Quota::new(&db)?;
        let xattr = XAttr::new(&db)?;

        #[cfg(feature = "cybersec")]
        let repair = Repair::new(&db, &Some(crypto.clone()), &compression, &dedup, &versioning)?;

        #[cfg(feature = "normal")]
        let repair = Repair::new(&db, &crypto, &compression, &dedup, &versioning)?;

        let cache = Cache::new();

        let next_ino = match db.get(b"next_ino")? {
            Some(v) => bincode::deserialize(&v)?,
            None => {
                let mut batch = sled::Batch::default();
                batch.insert(b"next_ino", bincode::serialize(&(ROOT_INO + 1))?);
                let root_attr = fuser::FileAttr {
                    ino: ROOT_INO,
                    size: 0,
                    blocks: 0,
                    atime: std::time::UNIX_EPOCH,
                    mtime: std::time::UNIX_EPOCH,
                    ctime: std::time::UNIX_EPOCH,
                    crtime: std::time::UNIX_EPOCH,
                    kind: fuser::FileType::Directory,
                    perm: 0o755,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: FS_BLOCK_SIZE,
                    flags: 0,
                };
                batch.insert(
                    format!("inode:{}", ROOT_INO).as_bytes(),
                        bincode::serialize(&Inode { attr: root_attr.into(), parent: 0 })?,
                );
                db.apply_batch(batch)?;
                ROOT_INO + 1
            }
        };

        let (tx, rx) = crossbeam::channel::unbounded();
        let repair_clone = repair.clone();
        std::thread::spawn(move || {
            while let Ok(()) = rx.recv() {
                std::thread::sleep(std::time::Duration::from_secs(3600));
                if let Err(e) = repair_clone.scan_and_repair() {
                    log::error!("Background repair failed: {}", e);
                }
            }
        });

        Ok(Self {
            db,
            next_ino: AtomicU64::new(next_ino),
           crypto,
           compression,
           dedup,
           versioning,
           audit,
           quota,
           xattr,
           repair,
           cache,
           noatime,
           background_repair_sender: Some(tx),
        })
    }

    // ---------- Helper methods (wszystkie dostępne dla modułu fs) ----------
    pub(crate) fn get_inode(&mut self, ino: u64) -> Result<Option<Inode>, HfsError> {
        if let Some(cached) = self.cache.get_inode(ino) {
            return Ok(Some(cached));
        }
        let key = format!("inode:{}", ino);
        let data = self.db.get(key.as_bytes())?;
        match data {
            Some(bytes) => {
                let inode: Inode = bincode::deserialize(&bytes)?;
                self.cache.put_inode(ino, inode.clone());
                Ok(Some(inode))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn put_inode(&mut self, ino: u64, inode: &Inode) -> Result<(), HfsError> {
        let key = format!("inode:{}", ino);
        self.db.insert(key.as_bytes(), bincode::serialize(inode)?)?;
        self.cache.put_inode(ino, inode.clone());
        Ok(())
    }

    pub(crate) fn delete_inode(&mut self, ino: u64) -> Result<(), HfsError> {
        let key = format!("inode:{}", ino);
        self.db.remove(key.as_bytes())?;
        self.cache.remove_inode(ino);
        Ok(())
    }

    pub(crate) fn lookup_name(&self, parent: u64, name: &OsStr) -> Result<Option<u64>, HfsError> {
        let key = format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes()));
        match self.db.get(key.as_bytes())? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn insert_name(&self, parent: u64, name: &OsStr, ino: u64) -> Result<(), HfsError> {
        let key = format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes()));
        self.db.insert(key.as_bytes(), bincode::serialize(&ino)?)?;
        Ok(())
    }

    pub(crate) fn delete_name(&self, parent: u64, name: &OsStr) -> Result<(), HfsError> {
        let key = format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes()));
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    pub(crate) fn get_block(&mut self, ino: u64, block_idx: usize) -> Result<Vec<u8>, HfsError> {
        if let Some(cached) = self.cache.get_block(ino, block_idx) {
            return Ok(cached);
        }
        let key = format!("data:{}:{}", ino, block_idx);
        let encrypted = match self.db.get(key.as_bytes())? {
            Some(data) => data.to_vec(),
            None => return Ok(vec![0u8; FS_BLOCK_SIZE as usize]),
        };
        #[cfg(feature = "cybersec")]
        let decrypted = self.crypto.decrypt(&encrypted)?;
        #[cfg(feature = "normal")]
        let decrypted = if let Some(crypto) = &self.crypto {
            crypto.decrypt(&encrypted)?
        } else {
            encrypted
        };
        let decompressed = self.compression.decompress(&decrypted)?;
        self.dedup.verify(ino, block_idx, &decompressed)?;
        self.cache.put_block(ino, block_idx, decompressed.clone());
        Ok(decompressed)
    }

    pub(crate) fn put_block(&mut self, ino: u64, block_idx: usize, data: &[u8]) -> Result<(), HfsError> {
        if let Some((orig_ino, orig_idx)) = self.dedup.find_duplicate(data)? {
            self.dedup.add_reference(ino, block_idx, orig_ino, orig_idx)?;
            return Ok(());
        }
        let compressed = self.compression.compress(data)?;
        #[cfg(feature = "cybersec")]
        let encrypted = self.crypto.encrypt(&compressed)?;
        #[cfg(feature = "normal")]
        let encrypted = if let Some(crypto) = &self.crypto {
            crypto.encrypt(&compressed)?
        } else {
            compressed
        };
        let key = format!("data:{}:{}", ino, block_idx);
        self.db.insert(key.as_bytes(), encrypted)?;
        self.dedup.insert_hash(ino, block_idx, data)?;
        self.cache.put_block(ino, block_idx, data.to_vec());
        Ok(())
    }

    pub(crate) fn remove_block(&mut self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let key = format!("data:{}:{}", ino, block_idx);
        self.db.remove(key.as_bytes())?;
        self.cache.remove_block(ino, block_idx);
        self.dedup.remove_reference(ino, block_idx)?;
        Ok(())
    }

    pub(crate) fn read_data(&mut self, ino: u64, offset: i64, size: u32) -> Result<Vec<u8>, HfsError> {
        let mut result = Vec::with_capacity(size as usize);
        let start_block = (offset as usize) / FS_BLOCK_SIZE as usize;
        let end_block = ((offset as usize + size as usize - 1) / FS_BLOCK_SIZE as usize) + 1;
        let inner_offset = (offset as usize) % FS_BLOCK_SIZE as usize;

        for block_idx in start_block..end_block {
            let mut block = self.get_block(ino, block_idx)?;
            if block_idx == start_block {
                block.drain(0..inner_offset);
            }
            let take = (size as usize - result.len()).min(block.len());
            result.extend_from_slice(&block[0..take]);
            if result.len() >= size as usize {
                break;
            }
        }
        Ok(result)
    }

    pub(crate) fn write_data(&mut self, ino: u64, offset: i64, data: &[u8]) -> Result<u32, HfsError> {
        if data.is_empty() {
            return Ok(0);
        }
        let start_block = (offset as usize) / FS_BLOCK_SIZE as usize;
        let end_block = ((offset as usize + data.len() - 1) / FS_BLOCK_SIZE as usize) + 1;
        let inner_offset = (offset as usize) % FS_BLOCK_SIZE as usize;

        let mut pos = 0;
        for block_idx in start_block..end_block {
            let mut block = self.get_block(ino, block_idx)?;
            let block_start = if block_idx == start_block {
                inner_offset
            } else {
                0
            };
            if block.len() < FS_BLOCK_SIZE as usize {
                block.resize(FS_BLOCK_SIZE as usize, 0);
            }
            let bytes_to_write = (FS_BLOCK_SIZE as usize - block_start).min(data.len() - pos);
            block[block_start..block_start + bytes_to_write]
            .copy_from_slice(&data[pos..pos + bytes_to_write]);
            self.put_block(ino, block_idx, &block)?;
            pos += bytes_to_write;
        }
        Ok(data.len() as u32)
    }

    pub(crate) fn update_size(&mut self, ino: u64, new_size: u64) -> Result<(), HfsError> {
        if let Some(mut inode) = self.get_inode(ino)? {
            inode.attr.size = new_size;
            self.put_inode(ino, &inode)?;
        }
        Ok(())
    }

    pub(crate) fn is_dir_empty(&self, ino: u64) -> Result<bool, HfsError> {
        let prefix = format!("dir:{}:", ino);
        let mut iter = self.db.scan_prefix(prefix.as_bytes());
        Ok(iter.next().is_none())
    }

    pub(crate) fn readdir_entries(&mut self, ino: u64) -> Result<Vec<(u64, fuser::FileType, OsString)>, HfsError> {
        let prefix = format!("dir:{}:", ino);
        let iter = self.db.scan_prefix(prefix.as_bytes());
        let mut entries = Vec::new();
        for item in iter {
            let (k, v) = item?;
            let k_str = String::from_utf8(k.to_vec())?;
            if !k_str.starts_with(&prefix) {
                break;
            }
            let name = OsString::from(k_str[prefix.len()..].to_string());
            let child_ino: u64 = bincode::deserialize(&v)?;
            if let Some(inode) = self.get_inode(child_ino)? {
                entries.push((child_ino, inode.attr.kind.into(), name));
            }
        }
        Ok(entries)
    }

    pub(crate) fn check_permission(&mut self, ino: u64, uid: u32, gid: u32, access_mask: i32) -> Result<bool, HfsError> {
        let inode = self.get_inode(ino)?.ok_or(HfsError::NoEntry)?;
        let mode = inode.attr.perm;
        if uid == inode.attr.uid {
            Ok((mode as i32 & access_mask) == access_mask)
        } else if gid == inode.attr.gid {
            Ok(((mode >> 3) as i32 & access_mask) == access_mask)
        } else {
            Ok(((mode >> 6) as i32 & access_mask) == access_mask)
        }
    }

    pub(crate) fn check_quota(&self, uid: u32, additional: u64) -> Result<(), HfsError> {
        self.quota.check_quota(uid, additional)
    }

    pub(crate) fn update_quota(&self, uid: u32, delta: u64) -> Result<(), HfsError> {
        self.quota.update_usage(uid, delta)
    }

    pub(crate) fn log_audit(&self, uid: u32, operation: &str, ino: u64, name: Option<&OsStr>) -> Result<(), HfsError> {
        self.audit.log(uid, operation, ino, name)
    }

    pub(crate) fn create_version(&self, ino: u64) -> Result<(), HfsError> {
        self.versioning.create_version(ino)
    }

    pub(crate) fn with_batch<F>(&self, f: F) -> Result<(), HfsError>
    where
    F: FnOnce(&mut sled::Batch) -> Result<(), HfsError>,
    {
        let mut batch = sled::Batch::default();
        f(&mut batch)?;
        self.db.apply_batch(batch)?;
        Ok(())
    }
}

// Public API do formatowania
pub fn format(db_path: &Path, _encryption: bool, block_size: Option<u32>) -> Result<(), HfsError> {
    let db = sled::open(db_path)?;
    let mut batch = sled::Batch::default();
    batch.insert(b"next_ino", bincode::serialize(&(ROOT_INO + 1))?);
    let root_attr = fuser::FileAttr {
        ino: ROOT_INO,
        size: 0,
        blocks: 0,
        atime: std::time::UNIX_EPOCH,
        mtime: std::time::UNIX_EPOCH,
        ctime: std::time::UNIX_EPOCH,
        crtime: std::time::UNIX_EPOCH,
        kind: fuser::FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: block_size.unwrap_or(FS_BLOCK_SIZE),
        flags: 0,
    };
    let inode = Inode { attr: root_attr.into(), parent: 0 };
    batch.insert(
        format!("inode:{}", ROOT_INO).as_bytes(),
            bincode::serialize(&inode)?,
    );
    db.apply_batch(batch)?;
    db.flush()?;
    Ok(())
}
