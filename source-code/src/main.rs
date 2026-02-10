use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use blake3::Hasher;
use clap::Parser;
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXAttr, Request,
};
use libc::{c_int, ENOENT, EIO, EEXIST, EISDIR, ENOTDIR, ENOTEMPTY, ENOSPC};
use rand::Rng;
use rocksdb::{DB, Options, PrefixIterator, WriteBatch};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);
const FS_BLOCK_SIZE: u32 = 4096;
const ROOT_INO: u64 = 1;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

#[derive(Serialize, Deserialize, Clone)]
struct Inode {
    attr: FileAttr,
    parent: u64,
}

struct HackerFS {
    db: Arc<DB>,
    next_ino: AtomicU64,
    cipher: Option<Arc<Aes256Gcm>>,
    cybersecurity: bool,
}

impl HackerFS {
    fn new(db_path: &Path, cybersecurity: bool, key: Option<[u8; 32]>) -> Result<Self, c_int> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = Arc::new(DB::open(&opts, db_path).map_err(|_| EIO)?);

        let cipher = if cybersecurity {
            let key_bytes = key.ok_or(EIO)?;
            Some(Arc::new(Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| EIO)?))
        } else {
            None
        };

        let next_ino = match db.get(b"next_ino") {
            Ok(Some(v)) => bincode::deserialize(&v).map_err(|_| EIO)?,
            Ok(None) => {
                let mut batch = WriteBatch::default();
                batch.put(b"next_ino", bincode::serialize(&(ROOT_INO + 1)).map_err(|_| EIO)?);
                let root_attr = FileAttr {
                    ino: ROOT_INO,
                    size: 0,
                    blocks: 0,
                    atime: UNIX_EPOCH,
                    mtime: UNIX_EPOCH,
                    ctime: UNIX_EPOCH,
                    crtime: UNIX_EPOCH,
                    kind: FileType::Directory,
                    perm: 0o755,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: FS_BLOCK_SIZE,
                    flags: 0,
                };
                batch.put(
                    format!("inode:{}", ROOT_INO).as_bytes(),
                        bincode::serialize(&Inode {
                            attr: root_attr,
                            parent: 0,
                        })
                        .map_err(|_| EIO)?,
                );
                db.write(batch).map_err(|_| EIO)?;
                ROOT_INO + 1
            }
            Err(_) => return Err(EIO),
        };

        Ok(Self {
            db,
            next_ino: AtomicU64::new(next_ino),
           cipher,
           cybersecurity,
        })
    }

    fn get_inode(&self, ino: u64) -> Result<Option<Inode>, c_int> {
        self.db
        .get(format!("inode:{}", ino).as_bytes())
        .map_err(|_| EIO)?
        .map(|v| bincode::deserialize(&v).map_err(|_| EIO))
        .transpose()
    }

    fn put_inode(&self, ino: u64, inode: Inode) -> Result<(), c_int> {
        self.db
        .put(
            format!("inode:{}", ino).as_bytes(),
                bincode::serialize(&inode).map_err(|_| EIO)?,
        )
        .map_err(|_| EIO)
    }

    fn delete_inode(&self, ino: u64) -> Result<(), c_int> {
        self.db.delete(format!("inode:{}", ino).as_bytes()).map_err(|_| EIO)
    }

    fn lookup_name(&self, parent: u64, name: &OsStr) -> Result<Option<u64>, c_int> {
        let key = format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes()));
        self.db
        .get(key.as_bytes())
        .map_err(|_| EIO)?
        .map(|v| bincode::deserialize(&v).map_err(|_| EIO))
        .transpose()
    }

    fn put_dir_entry(&self, parent: u64, name: &OsStr, child_ino: u64) -> Result<(), c_int> {
        let key = format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes()));
        self.db
        .put(key.as_bytes(), bincode::serialize(&child_ino).map_err(|_| EIO)?)
        .map_err(|_| EIO)
    }

    fn delete_dir_entry(&self, parent: u64, name: &OsStr) -> Result<(), c_int> {
        let key = format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes()));
        self.db.delete(key.as_bytes()).map_err(|_| EIO)
    }

    fn get_block(&self, ino: u64, block_idx: usize) -> Result<Vec<u8>, c_int> {
        let key = format!("data:{}:{}", ino, block_idx);
        if let Some(mut data) = self.db.get(key.as_bytes()).map_err(|_| EIO)? {
            if self.cybersecurity {
                if data.len() < NONCE_SIZE + TAG_SIZE {
                    return Err(EIO);
                }
                let nonce_slice = &data[0..NONCE_SIZE];
                let ciphertext = &data[NONCE_SIZE..data.len() - TAG_SIZE];
                let tag = &data[data.len() - TAG_SIZE..];
                let nonce = Nonce::from_slice(nonce_slice);
                let payload = Payload {
                    msg: ciphertext,
                    aad: b"", // No AAD for simplicity
                };
                let plaintext = self.cipher.as_ref().unwrap().decrypt(nonce, payload).map_err(|_| EIO)?;

                // Verify hash
                let hash_key = format!("hash:{}:{}", ino, block_idx);
                if let Some(stored_hash) = self.db.get(hash_key.as_bytes()).map_err(|_| EIO)? {
                    let mut hasher = Hasher::new();
                    hasher.update(&plaintext);
                    let computed_hash = hasher.finalize();
                    if stored_hash != computed_hash.as_bytes() {
                        return Err(EIO); // Tampered data
                    }
                } else {
                    return Err(EIO);
                }

                Ok(plaintext)
            } else {
                Ok(data)
            }
        } else {
            Ok(vec![0u8; FS_BLOCK_SIZE as usize])
        }
    }

    fn put_block(&self, ino: u64, block_idx: usize, mut data: Vec<u8>) -> Result<(), c_int> {
        let key = format!("data:{}:{}", ino, block_idx);
        let hash_key = format!("hash:{}:{}", ino, block_idx);

        if self.cybersecurity {
            // Compute hash of plaintext
            let mut hasher = Hasher::new();
            hasher.update(&data);
            let hash = hasher.finalize();

            // Encrypt
            let nonce: [u8; NONCE_SIZE] = rand::thread_rng().gen();
            let nonce_slice = Nonce::from_slice(&nonce);
            let payload = Payload {
                msg: &data,
                aad: b"",
            };
            let mut ciphertext = self.cipher.as_ref().unwrap().encrypt(nonce_slice, payload).map_err(|_| EIO)?;
            let mut stored_data = nonce.to_vec();
            stored_data.append(&mut ciphertext);
            let tag = ciphertext.split_off(ciphertext.len() - TAG_SIZE); // Wait, encrypt returns ciphertext + tag
            // Actually, encrypt returns vec with ciphertext + tag appended
            // So stored_data = nonce + encrypt output
            stored_data.append(&mut ciphertext); // Fix: encrypt returns ciphertext||tag
            let encrypt_result = self.cipher.as_ref().unwrap().encrypt(nonce_slice, &*data).map_err(|_| EIO)?;
            let mut stored_data = nonce.to_vec();
            stored_data.extend_from_slice(&encrypt_result);

            self.db.put(key.as_bytes(), stored_data).map_err(|_| EIO)?;
            self.db.put(hash_key.as_bytes(), hash.as_bytes()).map_err(|_| EIO)?;
        } else {
            if data.iter().all(|&b| b == 0) {
                self.db.delete(key.as_bytes()).map_err(|_| EIO)?; // Sparse
            } else {
                self.db.put(key.as_bytes(), data).map_err(|_| EIO)?;
            }
        }
        Ok(())
    }

    fn read_data(&self, ino: u64, offset: i64, size: u32) -> Result<Vec<u8>, c_int> {
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

    fn write_data(&self, ino: u64, offset: i64, data: &[u8]) -> Result<u32, c_int> {
        let data_len = data.len();
        if data_len == 0 {
            return Ok(0);
        }
        let start_block = (offset as usize) / FS_BLOCK_SIZE as usize;
        let end_block = ((offset as usize + data_len - 1) / FS_BLOCK_SIZE as usize) + 1;
        let inner_offset = (offset as usize) % FS_BLOCK_SIZE as usize;

        let mut pos = 0;
        for block_idx in start_block..end_block {
            let mut block = self.get_block(ino, block_idx)?;
            let block_start = if block_idx == start_block { inner_offset } else { 0 };
            let bytes_to_write = (FS_BLOCK_SIZE as usize - block_start).min(data_len - pos);
            block.resize(FS_BLOCK_SIZE as usize, 0);
            block[block_start..block_start + bytes_to_write].copy_from_slice(&data[pos..pos + bytes_to_write]);
            self.put_block(ino, block_idx, block[0..FS_BLOCK_SIZE as usize].to_vec())?;
            pos += bytes_to_write;
        }

        Ok(data_len as u32)
    }

    fn update_size(&self, ino: u64, new_size: u64) -> Result<(), c_int> {
        if let Some(mut inode) = self.get_inode(ino)? {
            inode.attr.size = new_size;
            self.put_inode(ino, inode)?;
        }
        Ok(())
    }

    fn is_dir_empty(&self, ino: u64) -> Result<bool, c_int> {
        let prefix = format!("dir:{}:", ino);
        Ok(self.db.prefix_iterator(prefix.as_bytes()).next().is_none())
    }

    fn readdir_entries(&self, ino: u64) -> Result<Vec<(u64, FileType, OsString)>, c_int> {
        let prefix = format!("dir:{}:", ino);
        let iter = self.db.prefix_iterator(prefix.as_bytes());
        let mut entries = Vec::new();
        for res in iter {
            let (k, v) = res.map_err(|_| EIO)?;
            let k_str = String::from_utf8(k.to_vec()).map_err(|_| EIO)?;
            if !k_str.starts_with(&prefix) {
                break;
            }
            let name = OsString::from(k_str[prefix.len()..].to_string());
            let child_ino: u64 = bincode::deserialize(&v).map_err(|_| EIO)?;
            let inode = self.get_inode(child_ino)?.ok_or(ENOENT)?;
            entries.push((child_ino, inode.attr.kind, name));
        }
        Ok(entries)
    }

    fn delete_data_blocks(&self, ino: u64) -> Result<(), c_int> {
        let prefix = format!("data:{}:", ino);
        let iter = self.db.prefix_iterator(prefix.as_bytes());
        let mut batch = WriteBatch::default();
        for res in iter {
            let (k, _) = res.map_err(|_| EIO)?;
            let k_str = String::from_utf8(k.to_vec()).map_err(|_| EIO)?;
            if !k_str.starts_with(&prefix) {
                break;
            }
            batch.delete(&k);
        }
        let hash_prefix = format!("hash:{}:", ino);
        let hash_iter = self.db.prefix_iterator(hash_prefix.as_bytes());
        for res in hash_iter {
            let (k, _) = res.map_err(|_| EIO)?;
            let k_str = String::from_utf8(k.to_vec()).map_err(|_| EIO)?;
            if !k_str.starts_with(&hash_prefix) {
                break;
            }
            batch.delete(&k);
        }
        self.db.write(batch).map_err(|_| EIO)
    }

    fn get_xattrs(&self, ino: u64) -> Result<Vec<OsString>, c_int> {
        let prefix = format!("xattr:{}:", ino);
        let iter = self.db.prefix_iterator(prefix.as_bytes());
        let mut names = Vec::new();
        for res in iter {
            let (k, _) = res.map_err(|_| EIO)?;
            let k_str = String::from_utf8(k.to_vec()).map_err(|_| EIO)?;
            if !k_str.starts_with(&prefix) {
                break;
            }
            names.push(OsString::from(k_str[prefix.len()..].to_string()));
        }
        Ok(names)
    }

    fn get_xattr(&self, ino: u64, name: &OsStr) -> Result<Option<Vec<u8>>, c_int> {
        let key = format!("xattr:{}:{}", ino, String::from_utf8_lossy(name.as_bytes()));
        self.db.get(key.as_bytes()).map_err(|_| EIO)
    }

    fn put_xattr(&self, ino: u64, name: &OsStr, value: &[u8]) -> Result<(), c_int> {
        let key = format!("xattr:{}:{}", ino, String::from_utf8_lossy(name.as_bytes()));
        self.db.put(key.as_bytes(), value).map_err(|_| EIO)
    }

    fn delete_xattr(&self, ino: u64, name: &OsStr) -> Result<(), c_int> {
        let key = format!("xattr:{}:{}", ino, String::from_utf8_lossy(name.as_bytes()));
        self.db.delete(key.as_bytes()).map_err(|_| EIO)
    }
}

impl Filesystem for HackerFS {
    fn lookup(&self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.lookup_name(parent, name) {
            Ok(Some(ino)) => {
                if let Ok(Some(inode)) = self.get_inode(ino) {
                    reply.entry(&TTL, &inode.attr, 0);
                    return;
                }
            }
            _ => {}
        }
        reply.error(ENOENT);
    }

    fn getattr(&self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match self.get_inode(ino) {
            Ok(Some(inode)) => reply.attr(&TTL, &inode.attr),
            _ => reply.error(ENOENT),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let mut inode = match self.get_inode(ino) {
            Ok(Some(i)) => i,
            _ => {
                reply.error(ENOENT);
                return;
            }
        };
        let mut attr = inode.attr;
        if let Some(m) = mode {
            attr.perm = m as u16;
        }
        if let Some(u) = uid {
            attr.uid = u;
        }
        if let Some(g) = gid {
            attr.gid = g;
        }
        if let Some(s) = size {
            attr.size = s;
            if let Err(e) = self.update_size(ino, s) {
                reply.error(e);
                return;
            }
        }
        if let Some(a) = atime {
            attr.atime = a;
        }
        if let Some(m) = mtime {
            attr.mtime = m;
        }
        inode.attr = attr;
        if self.put_inode(ino, inode).is_err() {
            reply.error(EIO);
            return;
        }
        reply.attr(&TTL, &attr);
    }

    fn mknod(
        &self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        if self.lookup_name(parent, name).unwrap_or(None).is_some() {
            reply.error(EEXIST);
            return;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now();
        let perm = (mode & !umask) as u16;
        let kind = if mode & libc::S_IFIFO as u32 != 0 {
            FileType::NamedPipe
        } else if mode & libc::S_IFCHR as u32 != 0 {
            FileType::CharDevice
        } else if mode & libc::S_IFBLK as u32 != 0 {
            FileType::BlockDevice
        } else {
            FileType::RegularFile
        };
        let attr = FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm,
            nlink: 1,
            uid: req.uid(),
            gid: req.gid(),
            rdev,
            blksize: FS_BLOCK_SIZE,
            flags: 0,
        };
        let mut batch = WriteBatch::default();
        batch.put(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst)).unwrap());
        let inode = Inode { attr, parent };
        batch.put(
            format!("inode:{}", ino).as_bytes(),
                bincode::serialize(&inode).unwrap(),
        );
        let name_str = String::from_utf8_lossy(name.as_bytes()).to_string();
        batch.put(
            format!("dir:{}:{}", parent, name_str).as_bytes(),
                bincode::serialize(&ino).unwrap(),
        );
        if let Ok(Some(mut parent_inode)) = self.get_inode(parent) {
            parent_inode.attr.mtime = now;
            batch.put(
                format!("inode:{}", parent).as_bytes(),
                    bincode::serialize(&parent_inode).unwrap(),
            );
        }
        if self.db.write(batch).is_err() {
            reply.error(EIO);
            return;
        }
        reply.entry(&TTL, &attr, 0);
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        if self.lookup_name(parent, name).unwrap_or(None).is_some() {
            reply.error(EEXIST);
            return;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now();
        let perm = (mode & !umask) as u16;
        let attr = FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm,
            nlink: 2,
            uid: req.uid(),
            gid: req.gid(),
            rdev: 0,
            blksize: FS_BLOCK_SIZE,
            flags: 0,
        };
        let mut batch = WriteBatch::default();
        batch.put(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst)).unwrap());
        let inode = Inode { attr, parent };
        batch.put(
            format!("inode:{}", ino).as_bytes(),
                bincode::serialize(&inode).unwrap(),
        );
        let name_str = String::from_utf8_lossy(name.as_bytes()).to_string();
        batch.put(
            format!("dir:{}:{}", parent, name_str).as_bytes(),
                bincode::serialize(&ino).unwrap(),
        );
        if let Ok(Some(mut parent_inode)) = self.get_inode(parent) {
            parent_inode.attr.mtime = now;
            parent_inode.attr.nlink += 1;
            batch.put(
                format!("inode:{}", parent).as_bytes(),
                    bincode::serialize(&parent_inode).unwrap(),
            );
        }
        if self.db.write(batch).is_err() {
            reply.error(EIO);
            return;
        }
        reply.entry(&TTL, &attr, 0);
    }

    fn unlink(&self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if let Ok(Some(ino)) = self.lookup_name(parent, name) {
            if let Ok(Some(mut inode)) = self.get_inode(ino) {
                if inode.attr.kind == FileType::Directory {
                    reply.error(EISDIR);
                    return;
                }
                inode.attr.nlink -= 1;
                let mut batch = WriteBatch::default();
                let name_str = String::from_utf8_lossy(name.as_bytes()).to_string();
                batch.delete(format!("dir:{}:{}", parent, name_str).as_bytes());
                if inode.attr.nlink == 0 {
                    batch.delete(format!("inode:{}", ino).as_bytes());
                    // Delete data blocks
                    let data_prefix = format!("data:{}:", ino);
                    let data_iter = self.db.prefix_iterator(data_prefix.as_bytes());
                    for res in data_iter {
                        if let Ok((k, _)) = res {
                            let k_str = String::from_utf8(k.to_vec()).unwrap();
                            if !k_str.starts_with(&data_prefix) {
                                break;
                            }
                            batch.delete(&k);
                        }
                    }
                    let hash_prefix = format!("hash:{}:", ino);
                    let hash_iter = self.db.prefix_iterator(hash_prefix.as_bytes());
                    for res in hash_iter {
                        if let Ok((k, _)) = res {
                            let k_str = String::from_utf8(k.to_vec()).unwrap();
                            if !k_str.starts_with(&hash_prefix) {
                                break;
                            }
                            batch.delete(&k);
                        }
                    }
                    // Delete xattrs
                    let xattr_prefix = format!("xattr:{}:", ino);
                    let xattr_iter = self.db.prefix_iterator(xattr_prefix.as_bytes());
                    for res in xattr_iter {
                        if let Ok((k, _)) = res {
                            let k_str = String::from_utf8(k.to_vec()).unwrap();
                            if !k_str.starts_with(&xattr_prefix) {
                                break;
                            }
                            batch.delete(&k);
                        }
                    }
                } else {
                    batch.put(
                        format!("inode:{}", ino).as_bytes(),
                            bincode::serialize(&inode).unwrap(),
                    );
                }
                let now = SystemTime::now();
                if let Ok(Some(mut parent_inode)) = self.get_inode(parent) {
                    parent_inode.attr.mtime = now;
                    batch.put(
                        format!("inode:{}", parent).as_bytes(),
                            bincode::serialize(&parent_inode).unwrap(),
                    );
                }
                if self.db.write(batch).is_err() {
                    reply.error(EIO);
                    return;
                }
                reply.ok();
                return;
            }
        }
        reply.error(ENOENT);
    }

    fn rmdir(&self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if let Ok(Some(ino)) = self.lookup_name(parent, name) {
            if let Ok(Some(inode)) = self.get_inode(ino) {
                if inode.attr.kind != FileType::Directory {
                    reply.error(ENOTDIR);
                    return;
                }
                if !self.is_dir_empty(ino).unwrap_or(false) {
                    reply.error(ENOTEMPTY);
                    return;
                }
                let mut batch = WriteBatch::default();
                let name_str = String::from_utf8_lossy(name.as_bytes()).to_string();
                batch.delete(format!("dir:{}:{}", parent, name_str).as_bytes());
                batch.delete(format!("inode:{}", ino).as_bytes());
                let now = SystemTime::now();
                if let Ok(Some(mut parent_inode)) = self.get_inode(parent) {
                    parent_inode.attr.mtime = now;
                    parent_inode.attr.nlink -= 1;
                    batch.put(
                        format!("inode:{}", parent).as_bytes(),
                            bincode::serialize(&parent_inode).unwrap(),
                    );
                }
                if self.db.write(batch).is_err() {
                    reply.error(EIO);
                    return;
                }
                reply.ok();
                return;
            }
        }
        reply.error(ENOENT);
    }

    fn symlink(
        &self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        if self.lookup_name(parent, name).unwrap_or(None).is_some() {
            reply.error(EEXIST);
            return;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now();
        let target = link.to_str().unwrap_or("").as_bytes().to_vec();
        let size = target.len() as u64;
        let attr = FileAttr {
            ino,
            size,
            blocks: (size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid: req.uid(),
            gid: req.gid(),
            rdev: 0,
            blksize: FS_BLOCK_SIZE,
            flags: 0,
        };
        let mut batch = WriteBatch::default();
        batch.put(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst)).unwrap());
        let inode = Inode { attr, parent };
        batch.put(
            format!("inode:{}", ino).as_bytes(),
                bincode::serialize(&inode).unwrap(),
        );
        let name_str = String::from_utf8_lossy(name.as_bytes()).to_string();
        batch.put(
            format!("dir:{}:{}", parent, name_str).as_bytes(),
                bincode::serialize(&ino).unwrap(),
        );
        // Store target in data:0 for symlink
        let symlink_key = format!("data:{}:0", ino);
        batch.put(symlink_key.as_bytes(), target);
        if let Ok(Some(mut parent_inode)) = self.get_inode(parent) {
            parent_inode.attr.mtime = now;
            batch.put(
                format!("inode:{}", parent).as_bytes(),
                    bincode::serialize(&parent_inode).unwrap(),
            );
        }
        if self.db.write(batch).is_err() {
            reply.error(EIO);
            return;
        }
        reply.entry(&TTL, &attr, 0);
    }

    fn readlink(&self, _req: &Request, ino: u64, reply: fuser::ReplyData) {
        if let Ok(Some(inode)) = self.get_inode(ino) {
            if inode.attr.kind != FileType::Symlink {
                reply.error(ENOENT);
                return;
            }
            let key = format!("data:{}:0", ino);
            if let Ok(Some(data)) = self.db.get(key.as_bytes()) {
                reply.data(&data);
                return;
            }
        }
        reply.error(EIO);
    }

    fn link(&self, req: &Request, ino: u64, newparent: u64, newname: &OsStr, reply: ReplyEntry) {
        if self.lookup_name(newparent, newname).unwrap_or(None).is_some() {
            reply.error(EEXIST);
            return;
        }
        if let Ok(Some(mut inode)) = self.get_inode(ino) {
            if inode.attr.kind == FileType::Directory {
                reply.error(EISDIR);
                return;
            }
            inode.attr.nlink += 1;
            let mut batch = WriteBatch::default();
            batch.put(
                format!("inode:{}", ino).as_bytes(),
                    bincode::serialize(&inode).unwrap(),
            );
            let newname_str = String::from_utf8_lossy(newname.as_bytes()).to_string();
            batch.put(
                format!("dir:{}:{}", newparent, newname_str).as_bytes(),
                    bincode::serialize(&ino).unwrap(),
            );
            let now = SystemTime::now();
            if let Ok(Some(mut newparent_inode)) = self.get_inode(newparent) {
                newparent_inode.attr.mtime = now;
                batch.put(
                    format!("inode:{}", newparent).as_bytes(),
                        bincode::serialize(&newparent_inode).unwrap(),
                );
            }
            if self.db.write(batch).is_err() {
                reply.error(EIO);
                return;
            }
            reply.entry(&TTL, &inode.attr, 0);
            return;
        }
        reply.error(ENOENT);
    }

    fn rename(
        &self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        if let Ok(Some(ino)) = self.lookup_name(parent, name) {
            if let Ok(Some(mut inode)) = self.get_inode(ino) {
                if self.lookup_name(newparent, newname).unwrap_or(None).is_some() {
                    reply.error(EEXIST);
                    return;
                }
                let mut batch = WriteBatch::default();
                let name_str = String::from_utf8_lossy(name.as_bytes()).to_string();
                batch.delete(format!("dir:{}:{}", parent, name_str).as_bytes());
                let newname_str = String::from_utf8_lossy(newname.as_bytes()).to_string();
                batch.put(
                    format!("dir:{}:{}", newparent, newname_str).as_bytes(),
                        bincode::serialize(&ino).unwrap(),
                );
                let now = SystemTime::now();
                if parent != newparent {
                    if inode.attr.kind == FileType::Directory {
                        inode.parent = newparent;
                    }
                    if let Ok(Some(mut old_parent_inode)) = self.get_inode(parent) {
                        old_parent_inode.attr.mtime = now;
                        if inode.attr.kind == FileType::Directory {
                            old_parent_inode.attr.nlink -= 1;
                        }
                        batch.put(
                            format!("inode:{}", parent).as_bytes(),
                                bincode::serialize(&old_parent_inode).unwrap(),
                        );
                    }
                    if let Ok(Some(mut new_parent_inode)) = self.get_inode(newparent) {
                        new_parent_inode.attr.mtime = now;
                        if inode.attr.kind == FileType::Directory {
                            new_parent_inode.attr.nlink += 1;
                        }
                        batch.put(
                            format!("inode:{}", newparent).as_bytes(),
                                bincode::serialize(&new_parent_inode).unwrap(),
                        );
                    }
                } else {
                    if let Ok(Some(mut parent_inode)) = self.get_inode(parent) {
                        parent_inode.attr.mtime = now;
                        batch.put(
                            format!("inode:{}", parent).as_bytes(),
                                bincode::serialize(&parent_inode).unwrap(),
                        );
                    }
                }
                batch.put(
                    format!("inode:{}", ino).as_bytes(),
                        bincode::serialize(&inode).unwrap(),
                );
                if self.db.write(batch).is_err() {
                    reply.error(EIO);
                    return;
                }
                reply.ok();
                return;
            }
        }
        reply.error(ENOENT);
    }

    fn open(&self, _req: &Request, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn read(
        &self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        match self.read_data(ino, offset, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e),
        }
    }

    fn write(
        &self,
        req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.write_data(ino, offset, data) {
            Ok(written) => {
                if let Ok(Some(mut inode)) = self.get_inode(ino) {
                    let new_size = (offset as u64 + written as u64).max(inode.attr.size);
                    inode.attr.size = new_size;
                    inode.attr.mtime = SystemTime::now();
                    if self.put_inode(ino, inode).is_err() {
                        reply.error(EIO);
                        return;
                    }
                }
                reply.written(written);
            }
            Err(e) => reply.error(e),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyEmpty,
    ) {
        if self.db.flush().is_err() {
            reply.error(EIO);
        } else {
            reply.ok();
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if self.db.flush().is_err() {
            reply.error(EIO);
        } else {
            reply.ok();
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        if self.lookup_name(parent, name).unwrap_or(None).is_some() {
            reply.error(EEXIST);
            return;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now();
        let perm = (mode & !umask) as u16;
        let attr = FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::RegularFile,
            perm,
            nlink: 1,
            uid: req.uid(),
            gid: req.gid(),
            rdev: 0,
            blksize: FS_BLOCK_SIZE,
            flags: 0,
        };
        let mut batch = WriteBatch::default();
        batch.put(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst)).unwrap());
        let inode = Inode { attr, parent };
        batch.put(
            format!("inode:{}", ino).as_bytes(),
                bincode::serialize(&inode).unwrap(),
        );
        let name_str = String::from_utf8_lossy(name.as_bytes()).to_string();
        batch.put(
            format!("dir:{}:{}", parent, name_str).as_bytes(),
                bincode::serialize(&ino).unwrap(),
        );
        if let Ok(Some(mut parent_inode)) = self.get_inode(parent) {
            parent_inode.attr.mtime = now;
            batch.put(
                format!("inode:{}", parent).as_bytes(),
                    bincode::serialize(&parent_inode).unwrap(),
            );
        }
        if self.db.write(batch).is_err() {
            reply.error(EIO);
            return;
        }
        reply.created(&TTL, &attr, 0, 0, flags as u32);
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let inode = match self.get_inode(ino) {
            Ok(Some(i)) => i,
            _ => {
                reply.error(ENOENT);
                return;
            }
        };
        let parent_ino = if inode.parent == 0 { ino } else { inode.parent };
        let parent_kind = FileType::Directory; // Assume
        let mut entries: Vec<(u64, FileType, OsString)> = vec![
            (ino, FileType::Directory, OsString::from(".")),
            (parent_ino, parent_kind, OsString::from("..")),
        ];
        if let Ok(mut child_entries) = self.readdir_entries(ino) {
            entries.append(&mut child_entries);
        }
        let to_skip = offset as usize;
        for (i, entry) in entries.into_iter().enumerate().skip(to_skip) {
            if reply.add(entry.0, (i + 1) as i64, entry.1, &entry.2) {
                break;
            }
        }
        reply.ok();
    }

    fn getxattr(&self, _req: &Request, ino: u64, name: &OsStr, size: u32, reply: ReplyXAttr) {
        match self.get_xattr(ino, name) {
            Ok(Some(value)) => {
                if size == 0 {
                    reply.size(value.len() as u32);
                } else if size >= value.len() as u32 {
                    reply.data(&value);
                } else {
                    reply.error(libc::ERANGE);
                }
            }
            Ok(None) => reply.error(libc::ENODATA),
            Err(e) => reply.error(e),
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        if self.get_inode(ino).is_err() || self.get_inode(ino).unwrap().is_none() {
            reply.error(ENOENT);
            return;
        }
        if self.put_xattr(ino, name, value).is_err() {
            reply.error(EIO);
        } else {
            reply.ok();
        }
    }

    fn listxattr(&self, _req: &Request, ino: u64, size: u32, reply: ReplyXAttr) {
        match self.get_xattrs(ino) {
            Ok(names) => {
                let mut data = Vec::new();
                for name in names {
                    data.extend_from_slice(name.as_bytes());
                    data.push(0);
                }
                if size == 0 {
                    reply.size(data.len() as u32);
                } else if size >= data.len() as u32 {
                    reply.data(&data);
                } else {
                    reply.error(libc::ERANGE);
                }
            }
            Err(e) => reply.error(e),
        }
    }

    fn removexattr(&self, _req: &Request, ino: u64, name: &OsStr, reply: ReplyEmpty) {
        if self.delete_xattr(ino, name).is_err() {
            reply.error(EIO);
        } else {
            reply.ok();
        }
    }

    fn statfs(&self, _req: &Request, _ino: u64, reply: fuser::ReplyStatfs) {
        // Dummy stats
        reply.statfs(0, 0, 0, 0, 0, FS_BLOCK_SIZE, 255, 0);
    }
}

#[derive(Parser)]
struct Args {
    mount_point: String,
    db_path: String,
    #[clap(long)]
    cybersecurity: bool,
    #[clap(long)]
    key: Option<String>,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let key = if args.cybersecurity {
        if let Some(k) = args.key {
            let bytes = hex::decode(k).expect("Invalid hex key");
            if bytes.len() != 32 {
                eprintln!("Key must be 32 bytes");
                std::process::exit(1);
            }
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&bytes);
            Some(key_array)
        } else {
            eprintln!("Key required for cybersecurity mode");
            std::process::exit(1);
        }
    } else {
        None
    };
    let fs = HackerFS::new(Path::new(&args.db_path), args.cybersecurity, key).expect("Failed to init FS");
    let options = vec![
        MountOption::RW,
        MountOption::FSName("hackerfs".to_string()),
    ];
    fuser::mount2(fs, &args.mount_point, &options).unwrap();
}

