use crate::*;
use fuser::{Filesystem, Request, ReplyAttr, ReplyEntry, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyOpen, ReplyWrite, ReplyXattr, ReplyCreate, ReplyStatfs};
    use libc::{EEXIST, EIO, ENOENT, ENOTDIR, ENOTEMPTY, EISDIR, ERANGE, ENODATA, EACCES};
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStrExt;
    use std::time::SystemTime;
    use std::sync::atomic::Ordering;

    impl Filesystem for HFS {
        fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
            match self.lookup_name(parent, name) {
                Ok(Some(ino)) => {
                    if let Ok(Some(inode)) = self.get_inode(ino) {
                        reply.entry(&TTL, &inode.attr.into(), 0);
                        return;
                    }
                }
                _ => {}
            }
            reply.error(ENOENT);
        }

        fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
            if let Ok(Some(inode)) = self.get_inode(ino) {
                reply.attr(&TTL, &inode.attr.into());
            } else {
                reply.error(ENOENT);
            }
        }

        fn setattr(&mut self, _req: &Request, ino: u64, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>,
                   size: Option<u64>, atime: Option<fuser::TimeOrNow>, mtime: Option<fuser::TimeOrNow>,
                   _ctime: Option<SystemTime>, _fh: Option<u64>, _crtime: Option<SystemTime>,
                   _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, _flags: Option<u32>,
                   reply: ReplyAttr) {
            let mut inode = match self.get_inode(ino) {
                Ok(Some(i)) => i,
                _ => { reply.error(ENOENT); return; }
            };
            let mut attr: fuser::FileAttr = inode.attr.into();

            if let Some(m) = mode { attr.perm = m as u16; }
            if let Some(u) = uid { attr.uid = u; }
            if let Some(g) = gid { attr.gid = g; }
            if let Some(s) = size {
                attr.size = s;
                if let Err(e) = self.update_size(ino, s) {
                    reply.error(e.into());
                    return;
                }
            }

            let now = SystemTime::now();
            if let Some(a) = atime {
                attr.atime = match a {
                    fuser::TimeOrNow::SpecificTime(t) => t,
                    fuser::TimeOrNow::Now => now,
                };
            }
            if let Some(m) = mtime {
                attr.mtime = match m {
                    fuser::TimeOrNow::SpecificTime(t) => t,
                    fuser::TimeOrNow::Now => now,
                };
            }

            inode.attr = attr.into();
            if self.put_inode(ino, &inode).is_err() {
                reply.error(EIO);
                return;
            }
            reply.attr(&TTL, &attr);
                   }

                   fn mknod(&mut self, req: &Request, parent: u64, name: &OsStr, mode: u32, umask: u32, rdev: u32, reply: ReplyEntry) {
                       if let Err(e) = self.check_quota(req.uid(), 0) {
                           reply.error(e.into());
                           return;
                       }
                       if self.lookup_name(parent, name).unwrap_or(None).is_some() {
                           reply.error(EEXIST);
                           return;
                       }
                       let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
                       let now = SystemTime::now();
                       let perm = (mode & !umask) as u16;
                       let kind = if mode & libc::S_IFIFO as u32 != 0 {
                           fuser::FileType::NamedPipe
                       } else if mode & libc::S_IFCHR as u32 != 0 {
                           fuser::FileType::CharDevice
                       } else if mode & libc::S_IFBLK as u32 != 0 {
                           fuser::FileType::BlockDevice
                       } else {
                           fuser::FileType::RegularFile
                       };
                       let attr = fuser::FileAttr {
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
                       let inode = serialization::Inode { attr: attr.into(), parent };

                       // Pobierz rodzica przed rozpoczęciem transakcji
                       let parent_inode = self.get_inode(parent).ok().flatten();

                       if let Err(e) = self.with_batch(|batch| {
                           batch.insert(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst))?);
                           batch.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
                           batch.insert(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
                           if let Some(mut parent_inode) = parent_inode {
                               let mut parent_attr: fuser::FileAttr = parent_inode.attr.into();
                               parent_attr.mtime = now;
                               let new_parent_inode = serialization::Inode { attr: parent_attr.into(), parent: parent_inode.parent };
                               batch.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&new_parent_inode)?);
                           }
                           Ok(())
                       }) {
                           reply.error(e.into());
                           return;
                       }
                       self.log_audit(req.uid(), "mknod", ino, Some(name)).ok();
                       reply.entry(&TTL, &attr, 0);
                   }

                   fn mkdir(&mut self, req: &Request, parent: u64, name: &OsStr, mode: u32, umask: u32, reply: ReplyEntry) {
                       if self.lookup_name(parent, name).unwrap_or(None).is_some() {
                           reply.error(EEXIST);
                           return;
                       }
                       let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
                       let now = SystemTime::now();
                       let perm = (mode & !umask) as u16;
                       let attr = fuser::FileAttr {
                           ino,
                           size: 0,
                           blocks: 0,
                           atime: now,
                           mtime: now,
                           ctime: now,
                           crtime: now,
                           kind: fuser::FileType::Directory,
                           perm,
                           nlink: 2,
                           uid: req.uid(),
                           gid: req.gid(),
                           rdev: 0,
                           blksize: FS_BLOCK_SIZE,
                           flags: 0,
                       };
                       let inode = serialization::Inode { attr: attr.into(), parent };

                       let parent_inode = self.get_inode(parent).ok().flatten();

                       if let Err(e) = self.with_batch(|batch| {
                           batch.insert(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst))?);
                           batch.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
                           batch.insert(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
                           if let Some(mut parent_inode) = parent_inode {
                               let mut parent_attr: fuser::FileAttr = parent_inode.attr.into();
                               parent_attr.mtime = now;
                               parent_attr.nlink += 1;
                               let new_parent_inode = serialization::Inode { attr: parent_attr.into(), parent: parent_inode.parent };
                               batch.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&new_parent_inode)?);
                           }
                           Ok(())
                       }) {
                           reply.error(e.into());
                           return;
                       }
                       self.log_audit(req.uid(), "mkdir", ino, Some(name)).ok();
                       reply.entry(&TTL, &attr, 0);
                   }

                   fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
                       let ino = match self.lookup_name(parent, name) {
                           Ok(Some(i)) => i,
                           _ => { reply.error(ENOENT); return; }
                       };
                       let inode = match self.get_inode(ino) {
                           Ok(Some(i)) => i,
                           _ => { reply.error(ENOENT); return; }
                       };
                       let kind: fuser::FileType = inode.attr.kind.into();
                       if kind == fuser::FileType::Directory {
                           reply.error(EISDIR);
                           return;
                       }

                       let mut inode = inode;
                       inode.attr.nlink -= 1;
                       let parent_inode = self.get_inode(parent).ok().flatten();

                       if inode.attr.nlink == 0 {
                           let data_prefix = format!("data:{}:", ino);
                           let hash_prefix = format!("hash:{}:", ino);
                           let ref_prefix = format!("ref:{}:", ino);
                           let xattr_prefix = format!("xattr:{}:", ino);
                           if let Err(e) = self.with_batch(|batch| {
                               batch.remove(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes());
                               batch.remove(format!("inode:{}", ino).as_bytes());
                               for item in self.db.scan_prefix(data_prefix.as_bytes()) {
                                   let (k, _) = item?;
                                   batch.remove(k);
                               }
                               for item in self.db.scan_prefix(hash_prefix.as_bytes()) {
                                   let (k, _) = item?;
                                   batch.remove(k);
                               }
                               for item in self.db.scan_prefix(ref_prefix.as_bytes()) {
                                   let (k, _) = item?;
                                   batch.remove(k);
                               }
                               for item in self.db.scan_prefix(xattr_prefix.as_bytes()) {
                                   let (k, _) = item?;
                                   batch.remove(k);
                               }
                               if let Some(mut parent_inode) = parent_inode {
                                   let mut parent_attr: fuser::FileAttr = parent_inode.attr.into();
                                   parent_attr.mtime = SystemTime::now();
                                   let new_parent_inode = serialization::Inode { attr: parent_attr.into(), parent: parent_inode.parent };
                                   batch.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&new_parent_inode)?);
                               }
                               Ok(())
                           }) {
                               reply.error(e.into());
                               return;
                           }
                       } else {
                           if let Err(e) = self.with_batch(|batch| {
                               batch.remove(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes());
                               batch.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
                               if let Some(mut parent_inode) = parent_inode {
                                   let mut parent_attr: fuser::FileAttr = parent_inode.attr.into();
                                   parent_attr.mtime = SystemTime::now();
                                   let new_parent_inode = serialization::Inode { attr: parent_attr.into(), parent: parent_inode.parent };
                                   batch.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&new_parent_inode)?);
                               }
                               Ok(())
                           }) {
                               reply.error(e.into());
                               return;
                           }
                       }
                       self.log_audit(req.uid(), "unlink", ino, Some(name)).ok();
                       reply.ok();
                   }

                   fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
                       let ino = match self.lookup_name(parent, name) {
                           Ok(Some(i)) => i,
                           _ => { reply.error(ENOENT); return; }
                       };
                       let inode = match self.get_inode(ino) {
                           Ok(Some(i)) => i,
                           _ => { reply.error(ENOENT); return; }
                       };
                       if inode.attr.kind != fuser::FileType::Directory.into() {
                           reply.error(ENOTDIR);
                           return;
                       }
                       if !self.is_dir_empty(ino).unwrap_or(false) {
                           reply.error(ENOTEMPTY);
                           return;
                       }
                       let parent_inode = self.get_inode(parent).ok().flatten();

                       if let Err(e) = self.with_batch(|batch| {
                           batch.remove(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes());
                           batch.remove(format!("inode:{}", ino).as_bytes());
                           if let Some(mut parent_inode) = parent_inode {
                               let mut parent_attr: fuser::FileAttr = parent_inode.attr.into();
                               parent_attr.mtime = SystemTime::now();
                               parent_attr.nlink -= 1;
                               let new_parent_inode = serialization::Inode { attr: parent_attr.into(), parent: parent_inode.parent };
                               batch.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&new_parent_inode)?);
                           }
                           Ok(())
                       }) {
                           reply.error(e.into());
                           return;
                       }
                       self.log_audit(req.uid(), "rmdir", ino, Some(name)).ok();
                       reply.ok();
                   }

                   fn symlink(&mut self, req: &Request, parent: u64, name: &OsStr, link: &std::path::Path, reply: ReplyEntry) {
                       if self.lookup_name(parent, name).unwrap_or(None).is_some() {
                           reply.error(EEXIST);
                           return;
                       }
                       let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
                       let now = SystemTime::now();
                       let target = link.to_str().unwrap_or("").as_bytes().to_vec();
                       let size = target.len() as u64;
                       let attr = fuser::FileAttr {
                           ino,
                           size,
                           blocks: (size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64,
                           atime: now,
                           mtime: now,
                           ctime: now,
                           crtime: now,
                           kind: fuser::FileType::Symlink,
                           perm: 0o777,
                           nlink: 1,
                           uid: req.uid(),
                           gid: req.gid(),
                           rdev: 0,
                           blksize: FS_BLOCK_SIZE,
                           flags: 0,
                       };
                       let inode = serialization::Inode { attr: attr.into(), parent };

                       let parent_inode = self.get_inode(parent).ok().flatten();

                       if let Err(e) = self.with_batch(|batch| {
                           batch.insert(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst))?);
                           batch.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
                           batch.insert(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
                           batch.insert(format!("data:{}:0", ino).as_bytes(), target);
                           if let Some(mut parent_inode) = parent_inode {
                               let mut parent_attr: fuser::FileAttr = parent_inode.attr.into();
                               parent_attr.mtime = now;
                               let new_parent_inode = serialization::Inode { attr: parent_attr.into(), parent: parent_inode.parent };
                               batch.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&new_parent_inode)?);
                           }
                           Ok(())
                       }) {
                           reply.error(e.into());
                           return;
                       }
                       self.log_audit(req.uid(), "symlink", ino, Some(name)).ok();
                       reply.entry(&TTL, &attr, 0);
                   }

                   fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
                       if let Ok(Some(inode)) = self.get_inode(ino) {
                           if inode.attr.kind != fuser::FileType::Symlink.into() {
                               reply.error(ENOENT);
                               return;
                           }
                           match self.db.get(format!("data:{}:0", ino).as_bytes()) {
                               Ok(Some(data)) => reply.data(&data),
                               _ => reply.error(EIO),
                           }
                       } else {
                           reply.error(ENOENT);
                       }
                   }

                   fn link(&mut self, req: &Request, ino: u64, newparent: u64, newname: &OsStr, reply: ReplyEntry) {
                       if self.lookup_name(newparent, newname).unwrap_or(None).is_some() {
                           reply.error(EEXIST);
                           return;
                       }
                       let mut inode = match self.get_inode(ino) {
                           Ok(Some(i)) => i,
                           _ => { reply.error(ENOENT); return; }
                       };
                       let kind: fuser::FileType = inode.attr.kind.into();
                       if kind == fuser::FileType::Directory {
                           reply.error(EISDIR);
                           return;
                       }
                       inode.attr.nlink += 1;
                       let newparent_inode = self.get_inode(newparent).ok().flatten();

                       if let Err(e) = self.with_batch(|batch| {
                           batch.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
                           batch.insert(format!("dir:{}:{}", newparent, String::from_utf8_lossy(newname.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
                           if let Some(mut newparent_inode) = newparent_inode {
                               let mut parent_attr: fuser::FileAttr = newparent_inode.attr.into();
                               parent_attr.mtime = SystemTime::now();
                               let new_parent_inode = serialization::Inode { attr: parent_attr.into(), parent: newparent_inode.parent };
                               batch.insert(format!("inode:{}", newparent).as_bytes(), bincode::serialize(&new_parent_inode)?);
                           }
                           Ok(())
                       }) {
                           reply.error(e.into());
                           return;
                       }
                       self.log_audit(req.uid(), "link", ino, Some(newname)).ok();
                       reply.entry(&TTL, &inode.attr.into(), 0);
                   }

                   fn rename(&mut self, req: &Request, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, _flags: u32, reply: ReplyEmpty) {
                       let ino = match self.lookup_name(parent, name) {
                           Ok(Some(i)) => i,
                           _ => { reply.error(ENOENT); return; }
                       };
                       let mut inode = match self.get_inode(ino) {
                           Ok(Some(i)) => i,
                           _ => { reply.error(ENOENT); return; }
                       };
                       if self.lookup_name(newparent, newname).unwrap_or(None).is_some() {
                           reply.error(EEXIST);
                           return;
                       }
                       let now = SystemTime::now();
                       let kind: fuser::FileType = inode.attr.kind.into();

                       let old_parent = self.get_inode(parent).ok().flatten();
                       let new_parent = self.get_inode(newparent).ok().flatten();

                       if let Err(e) = self.with_batch(|batch| {
                           batch.remove(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes());
                           batch.insert(format!("dir:{}:{}", newparent, String::from_utf8_lossy(newname.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
                           if parent != newparent && kind == fuser::FileType::Directory {
                               inode.parent = newparent;
                               batch.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
                           }
                           if let Some(mut old_parent) = old_parent {
                               let mut parent_attr: fuser::FileAttr = old_parent.attr.into();
                               parent_attr.mtime = now;
                               if kind == fuser::FileType::Directory {
                                   parent_attr.nlink -= 1;
                               }
                               let new_old_parent = serialization::Inode { attr: parent_attr.into(), parent: old_parent.parent };
                               batch.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&new_old_parent)?);
                           }
                           if let Some(mut new_parent) = new_parent {
                               let mut parent_attr: fuser::FileAttr = new_parent.attr.into();
                               parent_attr.mtime = now;
                               if kind == fuser::FileType::Directory {
                                   parent_attr.nlink += 1;
                               }
                               let new_new_parent = serialization::Inode { attr: parent_attr.into(), parent: new_parent.parent };
                               batch.insert(format!("inode:{}", newparent).as_bytes(), bincode::serialize(&new_new_parent)?);
                           }
                           Ok(())
                       }) {
                           reply.error(e.into());
                           return;
                       }
                       self.log_audit(req.uid(), "rename", ino, Some(newname)).ok();
                       reply.ok();
                   }

                   fn open(&mut self, _req: &Request, _ino: u64, _flags: i32, reply: ReplyOpen) {
                       reply.opened(0, 0);
                   }

                   fn read(&mut self, req: &Request, ino: u64, _fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyData) {
                       if let Ok(Some(inode)) = self.get_inode(ino) {
                           if let Err(e) = self.check_permission(ino, req.uid(), req.gid(), libc::R_OK) {
                               reply.error(e.into());
                               return;
                           }
                       } else {
                           reply.error(ENOENT);
                           return;
                       }
                       if !self.noatime {
                           if let Ok(Some(mut inode)) = self.get_inode(ino) {
                               inode.attr.atime = SystemTime::now();
                               let _ = self.put_inode(ino, &inode);
                           }
                       }
                       match self.read_data(ino, offset, size) {
                           Ok(data) => reply.data(&data),
                           Err(e) => reply.error(e.into()),
                       }
                   }

                   fn write(&mut self, req: &Request, ino: u64, _fh: u64, offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyWrite) {
                       if let Ok(Some(inode)) = self.get_inode(ino) {
                           if let Err(e) = self.check_permission(ino, req.uid(), req.gid(), libc::W_OK) {
                               reply.error(e.into());
                               return;
                           }
                       } else {
                           reply.error(ENOENT);
                           return;
                       }
                       let uid = req.uid();
                       if let Err(e) = self.check_quota(uid, data.len() as u64) {
                           reply.error(e.into());
                           return;
                       }
                       if let Err(e) = self.create_version(ino) {
                           reply.error(e.into());
                           return;
                       }
                       match self.write_data(ino, offset, data) {
                           Ok(written) => {
                               if let Ok(Some(mut inode)) = self.get_inode(ino) {
                                   let new_size = (offset as u64 + written as u64).max(inode.attr.size);
                                   inode.attr.size = new_size;
                                   inode.attr.mtime = SystemTime::now();
                                   if self.put_inode(ino, &inode).is_err() {
                                       reply.error(EIO);
                                       return;
                                   }
                               }
                               self.update_quota(uid, data.len() as u64).ok();
                               self.log_audit(uid, "write", ino, None).ok();
                               reply.written(written);
                           }
                           Err(e) => reply.error(e.into()),
                       }
                   }

                   fn flush(&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
                       if self.db.flush().is_err() {
                           reply.error(EIO);
                       } else {
                           reply.ok();
                       }
                   }

                   fn fsync(&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
                       if self.db.flush().is_err() {
                           reply.error(EIO);
                       } else {
                           reply.ok();
                       }
                   }

                   fn create(&mut self, req: &Request, parent: u64, name: &OsStr, mode: u32, umask: u32, flags: i32, reply: ReplyCreate) {
                       if self.lookup_name(parent, name).unwrap_or(None).is_some() {
                           reply.error(EEXIST);
                           return;
                       }
                       let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
                       let now = SystemTime::now();
                       let perm = (mode & !umask) as u16;
                       let attr = fuser::FileAttr {
                           ino,
                           size: 0,
                           blocks: 0,
                           atime: now,
                           mtime: now,
                           ctime: now,
                           crtime: now,
                           kind: fuser::FileType::RegularFile,
                           perm,
                           nlink: 1,
                           uid: req.uid(),
                           gid: req.gid(),
                           rdev: 0,
                           blksize: FS_BLOCK_SIZE,
                           flags: 0,
                       };
                       let inode = serialization::Inode { attr: attr.into(), parent };

                       let parent_inode = self.get_inode(parent).ok().flatten();

                       if let Err(e) = self.with_batch(|batch| {
                           batch.insert(b"next_ino", bincode::serialize(&self.next_ino.load(Ordering::SeqCst))?);
                           batch.insert(format!("inode:{}", ino).as_bytes(), bincode::serialize(&inode)?);
                           batch.insert(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes(), bincode::serialize(&ino)?);
                           if let Some(mut parent_inode) = parent_inode {
                               let mut parent_attr: fuser::FileAttr = parent_inode.attr.into();
                               parent_attr.mtime = now;
                               let new_parent_inode = serialization::Inode { attr: parent_attr.into(), parent: parent_inode.parent };
                               batch.insert(format!("inode:{}", parent).as_bytes(), bincode::serialize(&new_parent_inode)?);
                           }
                           Ok(())
                       }) {
                           reply.error(e.into());
                           return;
                       }
                       self.log_audit(req.uid(), "create", ino, Some(name)).ok();
                       reply.created(&TTL, &attr, 0, 0, flags as u32);
                   }

                   fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
                       let inode = match self.get_inode(ino) {
                           Ok(Some(i)) => i,
                           _ => { reply.error(ENOENT); return; }
                       };
                       let parent_ino = if inode.parent == 0 { ino } else { inode.parent };
                       let parent_kind = fuser::FileType::Directory;
                       let mut entries: Vec<(u64, fuser::FileType, OsString)> = vec![
                           (ino, fuser::FileType::Directory, OsString::from(".")),
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

                   fn getxattr(&mut self, _req: &Request, ino: u64, name: &OsStr, size: u32, reply: ReplyXattr) {
                       let name_str = name.to_string_lossy();
                       if name_str.starts_with("security.") {
                           if let Ok(Some(_inode)) = self.get_inode(ino) {
                               // permissions are checked in setxattr
                           }
                       }
                       match self.xattr.get(ino, name) {
                           Ok(Some(value)) => {
                               if size == 0 {
                                   reply.size(value.len() as u32);
                               } else if size >= value.len() as u32 {
                                   reply.data(&value);
                               } else {
                                   reply.error(ERANGE);
                               }
                           }
                           Ok(None) => reply.error(ENODATA),
                           Err(e) => reply.error(e.into()),
                       }
                   }

                   fn setxattr(&mut self, req: &Request, ino: u64, name: &OsStr, value: &[u8], _flags: i32, _position: u32, reply: ReplyEmpty) {
                       if let Ok(Some(inode)) = self.get_inode(ino) {
                           if req.uid() != 0 && req.uid() != inode.attr.uid {
                               reply.error(EACCES);
                               return;
                           }
                       } else {
                           reply.error(ENOENT);
                           return;
                       }
                       if self.xattr.set(ino, name, value).is_err() {
                           reply.error(EIO);
                       } else {
                           reply.ok();
                       }
                   }

                   fn listxattr(&mut self, _req: &Request, ino: u64, size: u32, reply: ReplyXattr) {
                       match self.xattr.list(ino) {
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
                                   reply.error(ERANGE);
                               }
                           }
                           Err(e) => reply.error(e.into()),
                       }
                   }

                   fn removexattr(&mut self, req: &Request, ino: u64, name: &OsStr, reply: ReplyEmpty) {
                       if let Ok(Some(inode)) = self.get_inode(ino) {
                           if req.uid() != 0 && req.uid() != inode.attr.uid {
                               reply.error(EACCES);
                               return;
                           }
                       } else {
                           reply.error(ENOENT);
                           return;
                       }
                       if self.xattr.remove(ino, name).is_err() {
                           reply.error(EIO);
                       } else {
                           reply.ok();
                       }
                   }

                   fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
                       reply.statfs(0, 0, 0, 0, 0, FS_BLOCK_SIZE, 255, 0);
                   }

                   fn access(&mut self, req: &Request, ino: u64, mask: i32, reply: ReplyEmpty) {
                       if let Ok(Some(inode)) = self.get_inode(ino) {
                           if self.check_permission(ino, req.uid(), req.gid(), mask).unwrap_or(false) {
                               reply.ok();
                           } else {
                               reply.error(EACCES);
                           }
                       } else {
                           reply.error(ENOENT);
                       }
                   }
    }
