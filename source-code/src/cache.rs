use lru::LruCache;
use dashmap::DashMap;
use std::sync::Arc;
use std::num::NonZeroUsize;
use crate::serialization::Inode;

pub struct Cache {
    inodes: DashMap<u64, Inode>,
    blocks: DashMap<(u64, usize), Arc<Vec<u8>>>,
    inode_lru: LruCache<u64, ()>,
    block_lru: LruCache<(u64, usize), ()>,
}

impl Cache {
    pub fn new() -> Self {
        let cap = NonZeroUsize::new(10000).unwrap();
        Self {
            inodes: DashMap::new(),
            blocks: DashMap::new(),
            inode_lru: LruCache::new(cap),
            block_lru: LruCache::new(cap),
        }
    }

    pub fn get_inode(&self, ino: u64) -> Option<Inode> {
        if let Some(entry) = self.inodes.get(&ino) {
            self.inode_lru.put(ino, ());
            Some(entry.clone())
        } else {
            None
        }
    }

    pub fn put_inode(&self, ino: u64, inode: Inode) {
        self.inodes.insert(ino, inode);
        self.inode_lru.put(ino, ());
        while self.inodes.len() > self.inode_lru.cap().get() {
            if let Some((old_ino, _)) = self.inode_lru.pop_lru() {
                self.inodes.remove(&old_ino);
            }
        }
    }

    pub fn remove_inode(&self, ino: u64) {
        self.inodes.remove(&ino);
        self.inode_lru.pop(&ino);
    }

    pub fn get_block(&self, ino: u64, idx: usize) -> Option<Vec<u8>> {
        let key = (ino, idx);
        if let Some(entry) = self.blocks.get(&key) {
            self.block_lru.put(key, ());
            Some(entry.as_ref().to_vec())
        } else {
            None
        }
    }

    pub fn put_block(&self, ino: u64, idx: usize, data: Vec<u8>) {
        let key = (ino, idx);
        self.blocks.insert(key, Arc::new(data));
        self.block_lru.put(key, ());
        while self.blocks.len() > self.block_lru.cap().get() {
            if let Some((old_key, _)) = self.block_lru.pop_lru() {
                self.blocks.remove(&old_key);
            }
        }
    }

    pub fn remove_block(&self, ino: u64, idx: usize) {
        let key = (ino, idx);
        self.blocks.remove(&key);
        self.block_lru.pop(&key);
    }
}
