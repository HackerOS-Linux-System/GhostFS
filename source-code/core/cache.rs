use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use crate::serialization::Inode;

const INODE_CACHE_SIZE: usize = 1024;
const BLOCK_CACHE_SIZE: usize = 512;

/// Thread-safe cache łączący DashMap dla szybkiego dostępu
/// i LruCache chroniony Mutexem dla eviction policy.
/// Wszystkie metody są bezpieczne do wywołania z wielu wątków FUSE jednocześnie.
#[derive(Clone)]
pub struct Cache {
    inode_lru: Arc<Mutex<LruCache<u64, Inode>>>,
    block_lru: Arc<Mutex<LruCache<(u64, usize), Vec<u8>>>>,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            inode_lru: Arc::new(Mutex::new(
                LruCache::new(NonZeroUsize::new(INODE_CACHE_SIZE).unwrap()),
            )),
            block_lru: Arc::new(Mutex::new(
                LruCache::new(NonZeroUsize::new(BLOCK_CACHE_SIZE).unwrap()),
            )),
        }
    }

    pub fn get_inode(&self, ino: u64) -> Option<Inode> {
        self.inode_lru.lock().unwrap().get(&ino).cloned()
    }

    pub fn put_inode(&self, ino: u64, inode: Inode) {
        self.inode_lru.lock().unwrap().put(ino, inode);
    }

    pub fn invalidate_inode(&self, ino: u64) {
        self.inode_lru.lock().unwrap().pop(&ino);
    }

    pub fn get_block(&self, ino: u64, block_idx: usize) -> Option<Vec<u8>> {
        self.block_lru.lock().unwrap().get(&(ino, block_idx)).cloned()
    }

    pub fn put_block(&self, ino: u64, block_idx: usize, data: Vec<u8>) {
        self.block_lru.lock().unwrap().put((ino, block_idx), data);
    }

    pub fn remove_block(&self, ino: u64, block_idx: usize) {
        self.block_lru.lock().unwrap().pop(&(ino, block_idx));
    }

    pub fn invalidate_inode_blocks(&self, ino: u64) {
        let mut lru = self.block_lru.lock().unwrap();
        // Zbierz klucze do usunięcia — LruCache nie wspiera retain, więc
        // iterujemy i zbieramy, a potem usuwamy (unikamy borrow conflict).
        let keys: Vec<(u64, usize)> = lru.iter()
            .filter(|((i, _), _)| *i == ino)
            .map(|(k, _)| *k)
            .collect();
        for k in keys { lru.pop(&k); }
    }
}

impl Default for Cache {
    fn default() -> Self { Self::new() }
}
