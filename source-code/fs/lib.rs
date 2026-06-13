// ── core ─────────────────────────────────────────────────────────────────────
#[path = "../core/error.rs"]        pub mod error;
#[path = "../core/serialization.rs"]pub mod serialization;
#[path = "../core/cache.rs"]        pub mod cache;
#[path = "../core/journal.rs"]      pub mod journal;

// ── fs ───────────────────────────────────────────────────────────────────────
#[path = "fs.rs"]                   pub mod fs;
#[path = "extents.rs"]              pub mod extents;
#[path = "dirindex.rs"]             pub mod dirindex;
#[path = "xattr.rs"]                pub mod xattr;

// ── data ─────────────────────────────────────────────────────────────────────
#[path = "../data/compression.rs"]  pub mod compression;
#[path = "../data/deduplication.rs"]pub mod deduplication;
#[path = "../data/versioning.rs"]   pub mod versioning;
#[path = "../data/repair.rs"]       pub mod repair;

// ── audit ────────────────────────────────────────────────────────────────────
#[path = "../audit/audit.rs"]       pub mod audit;
#[path = "../audit/quota.rs"]       pub mod quota;

// ── security ─────────────────────────────────────────────────────────────────
#[path = "../security/crypto.rs"]       pub mod crypto;
#[path = "../security/integrity.rs"]    pub mod integrity;
#[path = "../security/mac.rs"]          pub mod mac;
#[path = "../security/ids.rs"]          pub mod ids;
#[path = "../security/forensics.rs"]    pub mod forensics;
#[path = "../security/kdf.rs"]          pub mod kdf;
#[path = "../security/superblock.rs"]   pub mod superblock;
#[path = "../security/secure_delete.rs"]pub mod secure_delete;
#[path = "../security/rate_limit.rs"]   pub mod rate_limit;

pub use error::HfsError;
pub use crypto::Key;

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
use crate::journal::Journal;
use crate::extents::ExtentTree;
use crate::dirindex::DirIndex;
use crate::crypto::Crypto;
use crate::integrity::IntegrityTree;
use crate::mac::MacLabels;
use crate::ids::Ids;
use crate::forensics::Forensics;
use crate::secure_delete::SecureDelete;
use crate::rate_limit::RateLimiter;
use crate::superblock::Superblock;
use std::sync::atomic::AtomicU64;
use crossbeam::channel::Sender;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

pub const FS_BLOCK_SIZE: u32 = 4096;
pub const ROOT_INO: u64      = 1;
pub const TTL: std::time::Duration = std::time::Duration::from_secs(1);

pub struct GhostFS {
    pub(crate) db:          Db,
    pub(crate) next_ino:    AtomicU64,
    pub(crate) crypto:      Crypto,
    pub(crate) integrity:   IntegrityTree,
    pub(crate) mac:         MacLabels,
    pub(crate) ids:         Ids,
    pub(crate) forensics:   Forensics,
    pub(crate) secure_del:  SecureDelete,
    pub         rate_limit: RateLimiter,
    pub(crate) compression: Compression,
    pub(crate) dedup:       Deduplication,
    pub(crate) versioning:  Versioning,
    pub(crate) audit:       Audit,
    pub(crate) quota:       Quota,
    pub(crate) xattr:       XAttr,
    #[allow(dead_code)]
    pub(crate) repair:      Repair,
    pub(crate) cache:       Cache,
    pub(crate) journal:     Journal,
    pub(crate) extents:     ExtentTree,
    pub(crate) dirindex:    DirIndex,
    pub(crate) noatime:     bool,
    #[allow(dead_code)]
    pub(crate) background_repair_sender: Option<Sender<()>>,
}

impl GhostFS {
    pub fn new(
        db_path:          &Path,
        key:              Key,
        compression_type: Option<String>,
        noatime:          bool,
    ) -> Result<Self> {
        let db = sled::open(db_path)
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;

        let crypto = Crypto::new(key)?;

        let compression = Compression::new(match compression_type.as_deref() {
            Some("zlib") => CompressionType::Zlib,
                                           #[cfg(feature = "zstd")]
                                           Some("zstd") => CompressionType::Zstd,
                                           #[cfg(feature = "lz4")]
                                           Some("lz4")  => CompressionType::Lz4,
                                           _            => CompressionType::None,
        });

        let dedup      = Deduplication::new(&db)?;
        let versioning = Versioning::new(&db)?;
        let audit      = Audit::new(&db)?;
        let quota      = Quota::new(&db)?;
        let xattr      = XAttr::new(&db)?;
        let journal    = Journal::new(&db)?;
        let extents    = ExtentTree::new(&db)?;
        let dirindex   = DirIndex::new(&db)?;
        let integrity  = IntegrityTree::new(&db)?;
        let mac        = MacLabels::new(&db)?;
        let ids        = Ids::new(&db)?;
        let forensics  = Forensics::new(&db)?;
        let secure_del = SecureDelete::new(&db)?;
        let rate_limit = RateLimiter::new();
        let repair     = Repair::new(&db, &Some(crypto.clone()), &compression, &dedup, &versioning)?;
        let cache      = Cache::new();

        let next_ino = match db.get(b"next_ino")? {
            Some(v) => bincode::deserialize(&v)?,
            None => {
                let mut batch = sled::Batch::default();
                batch.insert(b"next_ino", bincode::serialize(&(ROOT_INO + 1))?);
                let root_attr = fuser::FileAttr {
                    ino: ROOT_INO, size: 0, blocks: 0,
                    atime: std::time::UNIX_EPOCH, mtime: std::time::UNIX_EPOCH,
                    ctime: std::time::UNIX_EPOCH, crtime: std::time::UNIX_EPOCH,
                    kind: fuser::FileType::Directory,
                    perm: 0o755, nlink: 2, uid: 0, gid: 0,
                    rdev: 0, blksize: FS_BLOCK_SIZE, flags: 0,
                };
                batch.insert(
                    format!("inode:{}", ROOT_INO).as_bytes(),
                        bincode::serialize(&serialization::Inode { attr: root_attr.into(), parent: 0 })?,
                );
                db.apply_batch(batch)?;
                ROOT_INO + 1
            }
        };

        let (tx, rx) = crossbeam::channel::unbounded::<()>();
        let repair_clone = repair.clone();
        std::thread::spawn(move || {
            while let Ok(()) = rx.recv() {
                std::thread::sleep(std::time::Duration::from_secs(3600));
                if let Err(e) = repair_clone.scan_and_repair() {
                    log::error!("Background repair failed: {}", e);
                }
            }
        });

        journal.recover(&db)?;

        Ok(Self {
            db, next_ino: AtomicU64::new(next_ino),
           crypto, integrity, mac, ids, forensics, secure_del, rate_limit,
           compression, dedup, versioning, audit, quota, xattr,
           repair, cache, noatime,
           background_repair_sender: Some(tx),
           journal, extents, dirindex,
        })
    }

    pub fn zeroize_keys(&mut self) {
        self.crypto.zeroize();
        log::info!("GhostFS: cryptographic keys zeroed from memory");
    }

    // ── Inode ops ─────────────────────────────────────────────────────────────

    pub(crate) fn get_inode(&mut self, ino: u64) -> Result<Option<serialization::Inode>, HfsError> {
        if let Some(cached) = self.cache.get_inode(ino) { return Ok(Some(cached)); }
        let key = format!("inode:{}", ino);
        match self.db.get(key.as_bytes())? {
            Some(bytes) => {
                let inode: serialization::Inode = bincode::deserialize(&bytes)?;
                self.cache.put_inode(ino, inode.clone());
                Ok(Some(inode))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn put_inode(&mut self, ino: u64, inode: &serialization::Inode) -> Result<(), HfsError> {
        let key = format!("inode:{}", ino);
        self.db.insert(key.as_bytes(), bincode::serialize(inode)?)?;
        self.cache.put_inode(ino, inode.clone());
        Ok(())
    }

    pub(crate) fn lookup_name(&self, parent: u64, name: &OsStr) -> Result<Option<u64>, HfsError> {
        if let Some(ino) = self.dirindex.lookup(parent, name)? { return Ok(Some(ino)); }
        let key = format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes()));
        match self.db.get(key.as_bytes())? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None    => Ok(None),
        }
    }

    // ── Block ops ─────────────────────────────────────────────────────────────

    pub(crate) fn get_block(&mut self, ino: u64, block_idx: usize) -> Result<Vec<u8>, HfsError> {
        if let Some(cached) = self.cache.get_block(ino, block_idx) { return Ok(cached); }
        let physical_key = self.extents.resolve(ino, block_idx)
        .unwrap_or_else(|| format!("data:{}:{}", ino, block_idx));
        let raw = match self.db.get(physical_key.as_bytes())? {
            Some(data) => data.to_vec(),
            None       => return Ok(vec![0u8; FS_BLOCK_SIZE as usize]),
        };
        let fek          = self.crypto.derive_fek(ino);
        let decrypted    = self.crypto.decrypt_with_key(&fek, &raw)?;
        let decompressed = self.compression.decompress(&decrypted)?;
        self.dedup.verify(ino, block_idx, &decompressed)?;
        self.integrity.verify_block(ino, block_idx, &decompressed)?;
        self.cache.put_block(ino, block_idx, decompressed.clone());
        Ok(decompressed)
    }

    pub(crate) fn put_block(&mut self, ino: u64, block_idx: usize, data: &[u8]) -> Result<(), HfsError> {
        if let Some((orig_ino, orig_idx)) = self.dedup.find_duplicate(data)? {
            self.dedup.add_reference(ino, block_idx, orig_ino, orig_idx)?;
            return Ok(());
        }
        let fek        = self.crypto.derive_fek(ino);
        let compressed = self.compression.compress(data)?;
        let encrypted  = self.crypto.encrypt_with_key(&fek, &compressed)?;
        let key        = format!("data:{}:{}", ino, block_idx);
        self.journal.log_write(ino, block_idx, &self.db.get(key.as_bytes())?.map(|v| v.to_vec()))?;
        self.db.insert(key.as_bytes(), encrypted)?;
        self.dedup.insert_hash(ino, block_idx, data)?;
        self.extents.record(ino, block_idx, &key)?;
        self.cache.put_block(ino, block_idx, data.to_vec());
        self.integrity.update_block(ino, block_idx, data)?;
        Ok(())
    }

    pub(crate) fn remove_block(&mut self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let key = format!("data:{}:{}", ino, block_idx);
        self.secure_del.wipe_block(&self.db, &key)?;
        self.cache.remove_block(ino, block_idx);
        self.dedup.remove_reference(ino, block_idx)?;
        self.extents.remove(ino, block_idx)?;
        self.integrity.remove_block(ino, block_idx)?;
        Ok(())
    }

    // ── Data I/O ──────────────────────────────────────────────────────────────

    pub(crate) fn read_data(&mut self, ino: u64, offset: i64, size: u32) -> Result<Vec<u8>, HfsError> {
        let mut result   = Vec::with_capacity(size as usize);
        let start_block  = (offset as usize) / FS_BLOCK_SIZE as usize;
        let end_block    = ((offset as usize + size as usize - 1) / FS_BLOCK_SIZE as usize) + 1;
        let inner_offset = (offset as usize) % FS_BLOCK_SIZE as usize;
        for block_idx in start_block..end_block {
            let mut block = self.get_block(ino, block_idx)?;
            if block_idx == start_block { block.drain(0..inner_offset); }
            let take = (size as usize - result.len()).min(block.len());
            result.extend_from_slice(&block[0..take]);
            if result.len() >= size as usize { break; }
        }
        Ok(result)
    }

    pub(crate) fn write_data(&mut self, ino: u64, offset: i64, data: &[u8]) -> Result<u32, HfsError> {
        if data.is_empty() { return Ok(0); }
        let start_block  = (offset as usize) / FS_BLOCK_SIZE as usize;
        let end_block    = ((offset as usize + data.len() - 1) / FS_BLOCK_SIZE as usize) + 1;
        let inner_offset = (offset as usize) % FS_BLOCK_SIZE as usize;
        let mut pos = 0;
        for block_idx in start_block..end_block {
            let mut block = self.get_block(ino, block_idx)?;
            let bstart = if block_idx == start_block { inner_offset } else { 0 };
            if block.len() < FS_BLOCK_SIZE as usize { block.resize(FS_BLOCK_SIZE as usize, 0); }
            let to_write = (FS_BLOCK_SIZE as usize - bstart).min(data.len() - pos);
            block[bstart..bstart + to_write].copy_from_slice(&data[pos..pos + to_write]);
            self.put_block(ino, block_idx, &block)?;
            pos += to_write;
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
        Ok(self.db.scan_prefix(prefix.as_bytes()).next().is_none())
    }

    pub(crate) fn readdir_entries(&mut self, ino: u64) -> Result<Vec<(u64, fuser::FileType, OsString)>, HfsError> {
        if let Ok(indexed) = self.dirindex.list(ino) {
            if !indexed.is_empty() {
                let mut entries = Vec::new();
                for (name, child_ino) in indexed {
                    if let Some(inode) = self.get_inode(child_ino)? {
                        entries.push((child_ino, inode.attr.kind.into(), name));
                    }
                }
                return Ok(entries);
            }
        }
        let prefix = format!("dir:{}:", ino);
        let mut entries = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (k, v) = item?;
            let k_str  = String::from_utf8(k.to_vec())?;
            if !k_str.starts_with(&prefix) { break; }
            let name      = OsString::from(k_str[prefix.len()..].to_string());
            let child_ino: u64 = bincode::deserialize(&v)?;
            if let Some(inode) = self.get_inode(child_ino)? {
                entries.push((child_ino, inode.attr.kind.into(), name));
            }
        }
        Ok(entries)
    }

    /// Constant-time MAC (Bell-LaPadula) + DAC (Unix mode) permission check.
    pub(crate) fn check_permission(&mut self, ino: u64, uid: u32, gid: u32, access_mask: i32) -> Result<bool, HfsError> {
        let inode  = self.get_inode(ino)?.ok_or(HfsError::NoEntry)?;
        let mac_ok = self.mac.check_ct(ino, uid, gid, access_mask)?;
        self.ids.record_access(uid, ino, access_mask)?;
        let mode   = inode.attr.perm;
        let dac_ok = if uid == 0                  { true }
        else if uid == inode.attr.uid          { (mode as i32 & access_mask) == access_mask }
        else if gid == inode.attr.gid          { ((mode >> 3) as i32 & access_mask) == access_mask }
        else                                   { ((mode >> 6) as i32 & access_mask) == access_mask };
        Ok(mac_ok & dac_ok)
    }

    pub(crate) fn check_quota(&self, uid: u32, additional: u64) -> Result<(), HfsError> {
        self.quota.check_quota(uid, additional)
    }

    pub(crate) fn update_quota(&self, uid: u32, delta: u64) -> Result<(), HfsError> {
        self.quota.update_usage(uid, delta)
    }

    pub(crate) fn log_audit(&self, uid: u32, op: &str, ino: u64, name: Option<&OsStr>) -> Result<(), HfsError> {
        self.audit.log(uid, op, ino, name)?;
        self.forensics.record(uid, op, ino, name)?;
        Ok(())
    }

    pub(crate) fn create_version(&self, ino: u64) -> Result<(), HfsError> {
        self.versioning.create_version(ino)
    }

    pub(crate) fn with_batch<F>(&self, f: F) -> Result<(), HfsError>
    where F: FnOnce(&mut sled::Batch) -> Result<(), HfsError> {
        let mut batch = sled::Batch::default();
        f(&mut batch)?;
        self.journal.commit_barrier()?;
        self.db.apply_batch(batch)?;
        Ok(())
    }
}

/// Inicjalizacja nowego wolumenu z uwierzytelnionym superblock.
pub fn format(db_path: &Path, master_key: &Key, block_size: Option<u32>) -> Result<(), HfsError> {
    let db = sled::open(db_path)?;
    let mut batch = sled::Batch::default();
    let bs = block_size.unwrap_or(FS_BLOCK_SIZE);
    batch.insert(b"next_ino", bincode::serialize(&(ROOT_INO + 1))?);
    let root_attr = fuser::FileAttr {
        ino: ROOT_INO, size: 0, blocks: 0,
        atime: std::time::UNIX_EPOCH, mtime: std::time::UNIX_EPOCH,
        ctime: std::time::UNIX_EPOCH, crtime: std::time::UNIX_EPOCH,
        kind: fuser::FileType::Directory,
        perm: 0o755, nlink: 2, uid: 0, gid: 0,
        rdev: 0, blksize: bs, flags: 0,
    };
    batch.insert(
        format!("inode:{}", ROOT_INO).as_bytes(),
            bincode::serialize(&serialization::Inode { attr: root_attr.into(), parent: 0 })?,
    );
    let sb = Superblock::new(bs, master_key)?;
    batch.insert(b"sb:data", bincode::serialize(&sb)?);
    db.apply_batch(batch)?;
    db.flush()?;
    Ok(())
}
