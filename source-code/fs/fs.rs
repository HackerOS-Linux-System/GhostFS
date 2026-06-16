use crate::*;
use crate::{mac, ids};
use fuser::{
    Filesystem, Request, ReplyAttr, ReplyEntry, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyOpen, ReplyWrite, ReplyXattr, ReplyCreate, ReplyStatfs,
};
use libc::{EEXIST, EIO, ENOENT, ENOTDIR, ENOTEMPTY, EISDIR, ERANGE, ENODATA, EACCES, ELOOP};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::time::SystemTime;
use std::sync::atomic::Ordering;

impl Filesystem for GhostFS {
    fn lookup(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        // O_NOFOLLOW enforcement: sprawdź czy name nie jest symlinkiem
        // Jeśli lookup wynika z symlink traversal poza wolumen — odrzuć
        match self.lookup_name(parent, name) {
            Ok(Some(ino)) => {
                if let Ok(Some(inode)) = self.get_inode(ino) {
                    // Blokuj symlinki wskazujące poza GhostFS (path traversal ochrona)
                    if inode.attr.kind == fuser::FileType::Symlink.into() {
                        if let Ok(Some(target)) = self.db.get(format!("data:{}:0", ino).as_bytes()) {
                            let target_str = String::from_utf8_lossy(&target);
                            // Absolutne ścieżki lub "../" mogą wychodzić poza FS
                            if target_str.starts_with('/') || target_str.contains("../") {
                                log::warn!("O_NOFOLLOW: blocking symlink ino={} target='{}' uid={}",
                                    ino, target_str, req.uid());
                                self.ids.emit_alert(req.uid(),
                                    ids::AlertKind::SymlinkTraversal { ino },
                                    &format!("symlink to '{}' blocked", target_str)).ok();
                                reply.error(ELOOP);
                                return;
                            }
                        }
                    }
                    reply.entry(&TTL, &inode.attr.into(), 0);
                    return;
                }
            }
            _ => {}
        }
        reply.error(ENOENT);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.get_inode(ino) {
            Ok(Some(inode)) => reply.attr(&TTL, &inode.attr.into()),
            _               => reply.error(ENOENT),
        }
    }

    fn setattr(
        &mut self, req: &Request, ino: u64, mode: Option<u32>, uid: Option<u32>,
        gid: Option<u32>, size: Option<u64>, atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>, _ctime: Option<SystemTime>, _fh: Option<u64>,
        _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>, _flags: Option<u32>, reply: ReplyAttr,
    ) {
        let mut inode = match self.get_inode(ino) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        if req.uid() != 0 && req.uid() != inode.attr.uid { reply.error(EACCES); return; }
        let mut attr: fuser::FileAttr = inode.attr.into();
        if let Some(m) = mode { attr.perm = m as u16; }
        if let Some(u) = uid  { attr.uid  = u; }
        if let Some(g) = gid  { attr.gid  = g; }
        if let Some(s) = size {
            attr.size = s;
            if let Err(e) = self.update_size(ino, s) { reply.error(e.into()); return; }
        }
        let now = SystemTime::now();
        if let Some(a) = atime {
            attr.atime = match a { fuser::TimeOrNow::SpecificTime(t) => t, fuser::TimeOrNow::Now => now };
        }
        if let Some(m) = mtime {
            attr.mtime = match m { fuser::TimeOrNow::SpecificTime(t) => t, fuser::TimeOrNow::Now => now };
        }
        inode.attr = attr.into();
        if self.put_inode(ino, &inode).is_err() { reply.error(EIO); return; }
        self.log_audit(req.uid(), "setattr", ino, None).ok();
        reply.attr(&TTL, &attr);
    }

    fn mknod(&mut self, req: &Request, parent: u64, name: &OsStr, mode: u32, umask: u32, rdev: u32, reply: ReplyEntry) {
        if let Err(e) = self.check_quota(req.uid(), 0) { reply.error(e.into()); return; }
        if self.lookup_name(parent, name).unwrap_or(None).is_some() { reply.error(EEXIST); return; }
        let ino  = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let now  = SystemTime::now();
        let perm = (mode & !umask) as u16;
        let kind = if mode & libc::S_IFIFO as u32 != 0 { fuser::FileType::NamedPipe }
            else if mode & libc::S_IFCHR as u32 != 0   { fuser::FileType::CharDevice }
            else if mode & libc::S_IFBLK as u32 != 0   { fuser::FileType::BlockDevice }
            else                                         { fuser::FileType::RegularFile };
        let attr  = fuser::FileAttr { ino, size: 0, blocks: 0, atime: now, mtime: now, ctime: now, crtime: now,
            kind, perm, nlink: 1, uid: req.uid(), gid: req.gid(), rdev, blksize: FS_BLOCK_SIZE, flags: 0 };
        let inode = serialization::Inode { attr: attr.into(), parent };
        let pi    = self.get_inode(parent).ok().flatten();
        if let Err(e) = self.with_batch(|b| {
            b.insert(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst))?);
            b.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
            b.insert(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
            if let Some(p) = pi { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = now;
                b.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
            Ok(())
        }) { reply.error(e.into()); return; }
        self.dirindex.insert(parent, name, ino).ok();
        self.log_audit(req.uid(), "mknod", ino, Some(name)).ok();
        reply.entry(&TTL, &attr, 0);
    }

    fn mkdir(&mut self, req: &Request, parent: u64, name: &OsStr, mode: u32, umask: u32, reply: ReplyEntry) {
        if self.lookup_name(parent, name).unwrap_or(None).is_some() { reply.error(EEXIST); return; }
        let ino  = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let now  = SystemTime::now();
        let perm = (mode & !umask) as u16;
        let attr = fuser::FileAttr { ino, size: 0, blocks: 0, atime: now, mtime: now, ctime: now, crtime: now,
            kind: fuser::FileType::Directory, perm, nlink: 2, uid: req.uid(), gid: req.gid(),
            rdev: 0, blksize: FS_BLOCK_SIZE, flags: 0 };
        let inode = serialization::Inode { attr: attr.into(), parent };
        let pi = self.get_inode(parent).ok().flatten();
        if let Err(e) = self.with_batch(|b| {
            b.insert(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst))?);
            b.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
            b.insert(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
            if let Some(p) = pi { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = now; pa.nlink += 1;
                b.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
            Ok(())
        }) { reply.error(e.into()); return; }
        self.dirindex.insert(parent, name, ino).ok();
        self.log_audit(req.uid(), "mkdir", ino, Some(name)).ok();
        reply.entry(&TTL, &attr, 0);
    }

    fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let ino = match self.lookup_name(parent, name) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        let inode = match self.get_inode(ino) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        if fuser::FileType::from(inode.attr.kind) == fuser::FileType::Directory { reply.error(EISDIR); return; }
        if let Err(e) = self.check_permission(parent, req.uid(), req.gid(), libc::W_OK) { reply.error(e.into()); return; }
        self.ids.record_delete(req.uid(), ino).ok();
        // Secure wipe dla plików Confidential+
        let mac_label = self.mac.get_label(ino).unwrap_or_default();
        let is_classified = mac_label.level as u8 >= 2;
        let mut inode = inode;
        inode.attr.nlink -= 1;
        let pi = self.get_inode(parent).ok().flatten();
        if inode.attr.nlink == 0 {
            if is_classified {
                self.secure_del.wipe_inode_blocks(&self.db, ino).ok();
                self.secure_del.wipe_metadata(&self.db, ino).ok();
            }
            let dp  = format!("data:{}:", ino);
            let hp  = format!("hash:{}:", ino);
            let rp  = format!("ref:{}:",  ino);
            let xp  = format!("xattr:{}:", ino);
            if let Err(e) = self.with_batch(|b| {
                b.remove(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes());
                b.remove(format!("inode:{}", ino).as_bytes());
                for item in self.db.scan_prefix(dp.as_bytes()) { let (k,_) = item?; b.remove(k); }
                for item in self.db.scan_prefix(hp.as_bytes()) { let (k,_) = item?; b.remove(k); }
                for item in self.db.scan_prefix(rp.as_bytes()) { let (k,_) = item?; b.remove(k); }
                for item in self.db.scan_prefix(xp.as_bytes()) { let (k,_) = item?; b.remove(k); }
                if let Some(p) = pi { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = SystemTime::now();
                    b.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
                Ok(())
            }) { reply.error(e.into()); return; }
            self.extents.remove_all(ino).ok();
            let keys: Vec<_> = self.db.scan_prefix(format!("itree:{}:", ino).as_bytes())
                .filter_map(|r| r.ok()).map(|(k,_)| k).collect();
            let mut batch = sled::Batch::default();
            for k in keys { batch.remove(k); }
            self.db.apply_batch(batch).ok();
        } else {
            if let Err(e) = self.with_batch(|b| {
                b.remove(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes());
                b.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
                if let Some(p) = pi { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = SystemTime::now();
                    b.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
                Ok(())
            }) { reply.error(e.into()); return; }
        }
        self.dirindex.remove(parent, name).ok();
        self.log_audit(req.uid(), "unlink", ino, Some(name)).ok();
        reply.ok();
    }

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let ino = match self.lookup_name(parent, name) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        let inode = match self.get_inode(ino) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        if inode.attr.kind != fuser::FileType::Directory.into() { reply.error(ENOTDIR); return; }
        if !self.is_dir_empty(ino).unwrap_or(false) { reply.error(ENOTEMPTY); return; }
        let pi = self.get_inode(parent).ok().flatten();
        if let Err(e) = self.with_batch(|b| {
            b.remove(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes());
            b.remove(format!("inode:{}", ino).as_bytes());
            if let Some(p) = pi { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = SystemTime::now(); pa.nlink -= 1;
                b.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
            Ok(())
        }) { reply.error(e.into()); return; }
        self.dirindex.remove(parent, name).ok();
        self.log_audit(req.uid(), "rmdir", ino, Some(name)).ok();
        reply.ok();
    }

    fn symlink(&mut self, req: &Request, parent: u64, name: &OsStr, link: &std::path::Path, reply: ReplyEntry) {
        if self.lookup_name(parent, name).unwrap_or(None).is_some() { reply.error(EEXIST); return; }
        let ino    = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let now    = SystemTime::now();
        let target = link.to_str().unwrap_or("").as_bytes().to_vec();
        let size   = target.len() as u64;
        let attr   = fuser::FileAttr { ino, size, blocks: (size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64,
            atime: now, mtime: now, ctime: now, crtime: now, kind: fuser::FileType::Symlink,
            perm: 0o777, nlink: 1, uid: req.uid(), gid: req.gid(), rdev: 0, blksize: FS_BLOCK_SIZE, flags: 0 };
        let inode = serialization::Inode { attr: attr.into(), parent };
        let pi    = self.get_inode(parent).ok().flatten();
        if let Err(e) = self.with_batch(|b| {
            b.insert(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst))?);
            b.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
            b.insert(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
            b.insert(format!("data:{}:0", ino).as_bytes(), target);
            if let Some(p) = pi { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = now;
                b.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
            Ok(())
        }) { reply.error(e.into()); return; }
        self.dirindex.insert(parent, name, ino).ok();
        self.log_audit(req.uid(), "symlink", ino, Some(name)).ok();
        reply.entry(&TTL, &attr, 0);
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        match self.get_inode(ino) {
            Ok(Some(inode)) => {
                if inode.attr.kind != fuser::FileType::Symlink.into() { reply.error(ENOENT); return; }
                match self.db.get(format!("data:{}:0", ino).as_bytes()) {
                    Ok(Some(data)) => reply.data(&data), _ => reply.error(EIO),
                }
            }
            _ => reply.error(ENOENT),
        }
    }

    fn link(&mut self, req: &Request, ino: u64, newparent: u64, newname: &OsStr, reply: ReplyEntry) {
        if self.lookup_name(newparent, newname).unwrap_or(None).is_some() { reply.error(EEXIST); return; }
        let mut inode = match self.get_inode(ino) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        if fuser::FileType::from(inode.attr.kind) == fuser::FileType::Directory { reply.error(EISDIR); return; }
        inode.attr.nlink += 1;
        let npi = self.get_inode(newparent).ok().flatten();
        if let Err(e) = self.with_batch(|b| {
            b.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
            b.insert(format!("dir:{}:{}", newparent, String::from_utf8_lossy(newname.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
            if let Some(p) = npi { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = SystemTime::now();
                b.insert(format!("inode:{}", newparent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
            Ok(())
        }) { reply.error(e.into()); return; }
        self.dirindex.insert(newparent, newname, ino).ok();
        self.log_audit(req.uid(), "link", ino, Some(newname)).ok();
        reply.entry(&TTL, &inode.attr.into(), 0);
    }

    fn rename(&mut self, req: &Request, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, _flags: u32, reply: ReplyEmpty) {
        let ino = match self.lookup_name(parent, name) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        let mut inode = match self.get_inode(ino) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        if let Ok(Some(tino)) = self.lookup_name(newparent, newname) {
            if let Ok(Some(t)) = self.get_inode(tino) {
                if fuser::FileType::from(t.attr.kind) == fuser::FileType::Directory
                    && !self.is_dir_empty(tino).unwrap_or(false)
                { reply.error(ENOTEMPTY); return; }
            }
        }
        let now  = SystemTime::now();
        let kind = fuser::FileType::from(inode.attr.kind);
        let op   = self.get_inode(parent).ok().flatten();
        let np   = self.get_inode(newparent).ok().flatten();
        if let Err(e) = self.with_batch(|b| {
            b.remove(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes());
            b.insert(format!("dir:{}:{}", newparent, String::from_utf8_lossy(newname.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
            if parent != newparent && kind == fuser::FileType::Directory {
                inode.parent = newparent;
                b.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
            }
            if let Some(p) = op { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = now;
                if kind == fuser::FileType::Directory { pa.nlink -= 1; }
                b.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
            if parent != newparent {
                if let Some(p) = np { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = now;
                    if kind == fuser::FileType::Directory { pa.nlink += 1; }
                    b.insert(format!("inode:{}", newparent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
            }
            Ok(())
        }) { reply.error(e.into()); return; }
        self.dirindex.remove(parent, name).ok();
        self.dirindex.insert(newparent, newname, ino).ok();
        self.log_audit(req.uid(), "rename", ino, Some(newname)).ok();
        reply.ok();
    }

    fn open(&mut self, req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        // Canary check — trigger alert jeśli plik jest honeypot
        self.canary.check_and_trigger(ino, req.uid()).ok();
        reply.opened(0, 0);
    }

    fn read(&mut self, req: &Request, ino: u64, _fh: u64, offset: i64, size: u32, _flags: i32, _lock: Option<u64>, reply: ReplyData) {
        // Fsfreeze check
        if self.frozen.load(std::sync::atomic::Ordering::SeqCst) { reply.error(EIO); return; }

        match self.check_permission(ino, req.uid(), req.gid(), libc::R_OK) {
            Ok(true)  => {}
            Ok(false) => { self.ids.record_perm_fail(req.uid(), ino).ok(); reply.error(EACCES); return; }
            Err(e)    => { reply.error(e.into()); return; }
        }
        match self.get_inode(ino) { Ok(Some(_)) => {} _ => { reply.error(ENOENT); return; } }
        if !self.noatime {
            if let Ok(Some(mut inode)) = self.get_inode(ino) {
                inode.attr.atime = SystemTime::now();
                let _ = self.put_inode(ino, &inode);
            }
        }
        let owner = self.get_inode(ino).ok().flatten().map(|i| i.attr.uid).unwrap_or(0);
        self.ids.record_read(req.uid(), ino, size as u64, owner).ok();
        match self.read_data(ino, offset, size) {
            Ok(data) => reply.data(&data),
            Err(e)   => reply.error(e.into()),
        }
    }

    fn write(&mut self, req: &Request, ino: u64, _fh: u64, offset: i64, data: &[u8], _wf: u32, _flags: i32, _lock: Option<u64>, reply: ReplyWrite) {
        // Fsfreeze check
        if self.frozen.load(std::sync::atomic::Ordering::SeqCst) { reply.error(EIO); return; }

        match self.check_permission(ino, req.uid(), req.gid(), libc::W_OK) {
            Ok(true)  => {}
            Ok(false) => { self.ids.record_perm_fail(req.uid(), ino).ok(); reply.error(EACCES); return; }
            Err(_)    => { reply.error(ENOENT); return; }
        }
        if let Err(e) = self.rate_limit.check_io(req.uid(), data.len() as u64) { reply.error(e.into()); return; }
        let uid = req.uid();
        if let Err(e) = self.check_quota(uid, data.len() as u64) { reply.error(e.into()); return; }
        if let Err(e) = self.create_version(ino) { reply.error(e.into()); return; }
        match self.write_data(ino, offset, data) {
            Ok(written) => {
                if let Ok(Some(mut inode)) = self.get_inode(ino) {
                    let new_size = (offset as u64 + written as u64).max(inode.attr.size);
                    inode.attr.size   = new_size;
                    inode.attr.mtime  = SystemTime::now();
                    inode.attr.blocks = (new_size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64;
                    if self.put_inode(ino, &inode).is_err() { reply.error(EIO); return; }
                }
                self.update_quota(uid, data.len() as u64).ok();
                self.log_audit(uid, "write", ino, None).ok();
                reply.written(written);
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn flush(&mut self, _req: &Request, _ino: u64, _fh: u64, _lock: u64, reply: ReplyEmpty) {
        if self.journal.commit_barrier().is_err() || self.db.flush().is_err() { reply.error(EIO); }
        else { reply.ok(); }
    }

    fn fsync(&mut self, _req: &Request, ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        let dirty = self.cache.flush_dirty();
        for (d_ino, block_idx, block_data) in dirty {
            if d_ino == ino && self.put_block(d_ino, block_idx, &block_data).is_err() {
                reply.error(EIO); return;
            }
        }
        if self.journal.commit_barrier().is_err() || self.db.flush().is_err() { reply.error(EIO); }
        else { reply.ok(); }
    }

    fn create(&mut self, req: &Request, parent: u64, name: &OsStr, mode: u32, umask: u32, flags: i32, reply: ReplyCreate) {
        if self.lookup_name(parent, name).unwrap_or(None).is_some() { reply.error(EEXIST); return; }
        let ino  = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let now  = SystemTime::now();
        let perm = (mode & !umask) as u16;
        let attr = fuser::FileAttr { ino, size: 0, blocks: 0, atime: now, mtime: now, ctime: now, crtime: now,
            kind: fuser::FileType::RegularFile, perm, nlink: 1, uid: req.uid(), gid: req.gid(),
            rdev: 0, blksize: FS_BLOCK_SIZE, flags: 0 };
        let inode = serialization::Inode { attr: attr.into(), parent };
        let pi    = self.get_inode(parent).ok().flatten();
        if let Err(e) = self.with_batch(|b| {
            b.insert(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst))?);
            b.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
            b.insert(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
            if let Some(p) = pi { let mut pa: fuser::FileAttr = p.attr.into(); pa.mtime = now;
                b.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&serialization::Inode { attr: pa.into(), parent: p.parent })?); }
            Ok(())
        }) { reply.error(e.into()); return; }
        self.dirindex.insert(parent, name, ino).ok();
        self.log_audit(req.uid(), "create", ino, Some(name)).ok();
        reply.created(&TTL, &attr, 0, 0, flags as u32);
    }

    fn readdir(&mut self, req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        let inode = match self.get_inode(ino) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        self.ids.record_readdir(req.uid()).ok();
        let parent_ino = if inode.parent == 0 { ino } else { inode.parent };
        let mut entries: Vec<(u64, fuser::FileType, OsString)> = vec![
            (ino, fuser::FileType::Directory, OsString::from(".")),
            (parent_ino, fuser::FileType::Directory, OsString::from("..")),
        ];
        if let Ok(mut ch) = self.readdir_entries(ino) { entries.append(&mut ch); }
        for (i, e) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(e.0, (i + 1) as i64, e.1, &e.2) { break; }
        }
        reply.ok();
    }

    fn getxattr(&mut self, _req: &Request, ino: u64, name: &OsStr, size: u32, reply: ReplyXattr) {
        if name.to_string_lossy() == mac::XATTR_LABEL {
            let label = self.mac.get_label(ino).unwrap_or_default();
            let value = mac::MacLabels::label_to_xattr(&label);
            if size == 0 { reply.size(value.len() as u32); }
            else if size >= value.len() as u32 { reply.data(&value); }
            else { reply.error(ERANGE); }
            return;
        }
        match self.xattr.get(ino, name) {
            Ok(Some(v)) => { if size == 0 { reply.size(v.len() as u32); } else if size >= v.len() as u32 { reply.data(&v); } else { reply.error(ERANGE); } }
            Ok(None)    => reply.error(ENODATA),
            Err(e)      => reply.error(e.into()),
        }
    }

    fn setxattr(&mut self, req: &Request, ino: u64, name: &OsStr, value: &[u8], _flags: i32, _pos: u32, reply: ReplyEmpty) {
        let inode = match self.get_inode(ino) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        if req.uid() != 0 && req.uid() != inode.attr.uid {
            let ns = name.to_string_lossy();
            if ns.starts_with("security.") {
                self.ids.emit_alert(req.uid(), ids::AlertKind::SuspiciousXattr, &format!("ino={} attr={}", ino, ns)).ok();
            }
            reply.error(EACCES); return;
        }
        if name.to_string_lossy() == mac::XATTR_LABEL {
            match self.mac.handle_setxattr_label(ino, value) {
                Ok(()) => { self.log_audit(req.uid(), "setxattr:mac_label", ino, Some(name)).ok(); reply.ok(); }
                Err(e) => reply.error(e.into()),
            }
            return;
        }
        if self.xattr.set(ino, name, value).is_err() { reply.error(EIO); }
        else { self.log_audit(req.uid(), "setxattr", ino, Some(name)).ok(); reply.ok(); }
    }

    fn listxattr(&mut self, _req: &Request, ino: u64, size: u32, reply: ReplyXattr) {
        match self.xattr.list(ino) {
            Ok(names) => {
                let mut data = Vec::new();
                data.extend_from_slice(mac::XATTR_LABEL.as_bytes()); data.push(0);
                for n in names { data.extend_from_slice(n.as_encoded_bytes()); data.push(0); }
                if size == 0 { reply.size(data.len() as u32); }
                else if size >= data.len() as u32 { reply.data(&data); }
                else { reply.error(ERANGE); }
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn removexattr(&mut self, req: &Request, ino: u64, name: &OsStr, reply: ReplyEmpty) {
        let inode = match self.get_inode(ino) { Ok(Some(i)) => i, _ => { reply.error(ENOENT); return; } };
        if req.uid() != 0 && req.uid() != inode.attr.uid { reply.error(EACCES); return; }
        if self.xattr.remove(ino, name).is_err() { reply.error(EIO); } else { reply.ok(); }
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        let used    = self.db.size_on_disk().unwrap_or(0);
        let bs      = FS_BLOCK_SIZE as u64;
        let total   = 1024 * 1024 * 1024 * 1024 / bs;
        let free    = total.saturating_sub(used / bs);
        reply.statfs(total, free, free, 0, 0, FS_BLOCK_SIZE, 255, FS_BLOCK_SIZE);
    }

    fn access(&mut self, req: &Request, ino: u64, mask: i32, reply: ReplyEmpty) {
        match self.check_permission(ino, req.uid(), req.gid(), mask) {
            Ok(true)  => reply.ok(),
            Ok(false) => { self.ids.record_perm_fail(req.uid(), ino).ok(); reply.error(EACCES); }
            Err(_)    => reply.error(ENOENT),
        }
    }
}
