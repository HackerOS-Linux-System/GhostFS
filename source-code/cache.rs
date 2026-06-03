use lru::LruCache;
use dashmap::DashMap;
use std::sync::Arc;
use std::num::NonZeroUsize;
use crate::serialization::Inode;

pub const INODE_CACHE_CAP: usize = 10_000;
pub const BLOCK_CACHE_CAP: usize = 10_000;
pub const READ_AHEAD_BLOCKS: usize = 8;

pub struct Cache {
    inodes: DashMap<u64, Inode>,
    blocks: DashMap<(u64, usize), Arc<Vec<u8>>>,
    dirty_blocks: DashMap<(u64, usize), Arc<Vec<u8>>>,
    inode_lru: LruCache<u64, ()>,
    block_lru: LruCache<(u64, usize), ()>,
}

impl Cache {
    pub fn new() -> Self {
        let icap = NonZeroUsize::new(INODE_CACHE_CAP).unwrap();
        let bcap = NonZeroUsize::new(BLOCK_CACHE_CAP).unwrap();
        Self {
            inodes: DashMap::new(),
            blocks: DashMap::new(),
            dirty_blocks: DashMap::new(),
            inode_lru: LruCache::new(icap),
            block_lru: LruCache::new(bcap),
        }
    }

    // ---------- Inode cache ----------

    pub fn get_inode(&mut self, ino: u64) -> Option<Inode> {
        if let Some(entry) = self.inodes.get(&ino) {
            self.inode_lru.put(ino, ());
            return Some(entry.clone());
        }
        None
    }

    pub fn put_inode(&mut self, ino: u64, inode: Inode) {
        self.inodes.insert(ino, inode);
        self.inode_lru.put(ino, ());
        self.evict_inodes();
    }

    pub fn remove_inode(&mut self, ino: u64) {
        self.inodes.remove(&ino);
        self.inode_lru.pop(&ino);
    }

    fn evict_inodes(&mut self) {
        while self.inodes.len() > self.inode_lru.cap().get() {
            if let Some((old, _)) = self.inode_lru.pop_lru() {
                self.inodes.remove(&old);
            } else {
                break;
            }
        }
    }

    // ---------- Block cache ----------

    pub fn get_block(&mut self, ino: u64, idx: usize) -> Option<Vec<u8>> {
        let key = (ino, idx);
        if let Some(entry) = self.blocks.get(&key) {
            self.block_lru.put(key, ());
            return Some(entry.as_ref().to_vec());
        }
        None
    }

    pub fn put_block(&mut self, ino: u64, idx: usize, data: Vec<u8>) {
        let key = (ino, idx);
        self.blocks.insert(key, Arc::new(data));
        self.block_lru.put(key, ());
        self.evict_blocks();
    }

    /// Mark a block as dirty (pending write-back).
    pub fn mark_dirty(&mut self, ino: u64, idx: usize, data: Vec<u8>) {
        let key = (ino, idx);
        self.dirty_blocks.insert(key, Arc::new(data));
    }

    /// Drain all dirty blocks for a write-back flush.
    /// Returns vec of (ino, block_idx, data).
    pub fn flush_dirty(&mut self) -> Vec<(u64, usize, Vec<u8>)> {
        let keys: Vec<_> = self.dirty_blocks.iter().map(|r| *r.key()).collect();
        let mut out = Vec::new();
        for key in keys {
            if let Some((_, data)) = self.dirty_blocks.remove(&key) {
                out.push((key.0, key.1, data.as_ref().to_vec()));
            }
        }
        out
    }

    pub fn remove_block(&mut self, ino: u64, idx: usize) {
        let key = (ino, idx);
        self.blocks.remove(&key);
        self.dirty_blocks.remove(&key);
        self.block_lru.pop(&key);
    }

    /// Return read-ahead hint: the next N block indices to prefetch.
    pub fn read_ahead_hint(last_block: usize) -> Vec<usize> {
        (last_block + 1..=last_block + READ_AHEAD_BLOCKS).collect()
    }

    fn evict_blocks(&mut self) {
        while self.blocks.len() > self.block_lru.cap().get() {
            if let Some((old, _)) = self.block_lru.pop_lru() {
                self.blocks.remove(&old);
            } else {
                break;
            }
        }
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}
