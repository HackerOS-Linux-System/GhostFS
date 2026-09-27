use serde::{Serialize, Deserialize};
use std::time::SystemTime;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerFileType {
    NamedPipe, CharDevice, BlockDevice, Directory, RegularFile, Symlink, Socket,
}

impl From<fuser::FileType> for SerFileType {
    fn from(kind: fuser::FileType) -> Self {
        match kind {
            fuser::FileType::NamedPipe    => SerFileType::NamedPipe,
            fuser::FileType::CharDevice   => SerFileType::CharDevice,
            fuser::FileType::BlockDevice  => SerFileType::BlockDevice,
            fuser::FileType::Directory    => SerFileType::Directory,
            fuser::FileType::RegularFile  => SerFileType::RegularFile,
            fuser::FileType::Symlink      => SerFileType::Symlink,
            fuser::FileType::Socket       => SerFileType::Socket,
        }
    }
}
impl From<SerFileType> for fuser::FileType {
    fn from(kind: SerFileType) -> Self {
        match kind {
            SerFileType::NamedPipe    => fuser::FileType::NamedPipe,
            SerFileType::CharDevice   => fuser::FileType::CharDevice,
            SerFileType::BlockDevice  => fuser::FileType::BlockDevice,
            SerFileType::Directory    => fuser::FileType::Directory,
            SerFileType::RegularFile  => fuser::FileType::RegularFile,
            SerFileType::Symlink      => fuser::FileType::Symlink,
            SerFileType::Socket       => fuser::FileType::Socket,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerFileAttr {
    pub ino: u64, pub size: u64, pub blocks: u64,
    pub atime: SystemTime, pub mtime: SystemTime,
    pub ctime: SystemTime, pub crtime: SystemTime,
    pub kind: SerFileType, pub perm: u16, pub nlink: u32,
    pub uid: u32, pub gid: u32, pub rdev: u32,
    pub blksize: u32, pub flags: u32,
}
impl From<fuser::FileAttr> for SerFileAttr {
    fn from(a: fuser::FileAttr) -> Self {
        Self { ino: a.ino, size: a.size, blocks: a.blocks,
            atime: a.atime, mtime: a.mtime, ctime: a.ctime, crtime: a.crtime,
            kind: a.kind.into(), perm: a.perm, nlink: a.nlink,
            uid: a.uid, gid: a.gid, rdev: a.rdev, blksize: a.blksize, flags: a.flags }
    }
}
impl From<SerFileAttr> for fuser::FileAttr {
    fn from(a: SerFileAttr) -> Self {
        Self { ino: a.ino, size: a.size, blocks: a.blocks,
            atime: a.atime, mtime: a.mtime, ctime: a.ctime, crtime: a.crtime,
            kind: a.kind.into(), perm: a.perm, nlink: a.nlink,
            uid: a.uid, gid: a.gid, rdev: a.rdev, blksize: a.blksize, flags: a.flags }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Inode {
    pub attr: SerFileAttr,
    pub parent: u64,
}
