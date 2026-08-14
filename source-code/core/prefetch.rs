use std::sync::Arc;

use dashmap::DashMap;
use rayon::{ThreadPool, ThreadPoolBuilder};
use sled::Db;

use crate::cache::Cache;
use crate::compression::Compression;
use crate::crypto::Crypto;
use crate::deduplication::Deduplication;
use crate::extents::ExtentTree;
use crate::integrity::IntegrityTree;
use crate::FS_BLOCK_SIZE;

/// Ile bloków do przodu prefetchujemy po wykryciu sekwencyjnego wzorca.
const DEFAULT_WINDOW: usize = 8;
/// Ile kolejnych sekwencyjnych odczytów musi wystąpić zanim uznamy wzorzec
/// za "sekwencyjny" i zaczniemy prefetchować (unika marnowania I/O na
/// losowy dostęp, np. bazy danych, mmap).
const SEQUENTIAL_TRIGGER: u32 = 2;

#[derive(Clone)]
pub struct Prefetcher {
    pool: Arc<ThreadPool>,
    window: usize,
    /// (ostatni odczytany block_idx, licznik kolejnych sekwencyjnych trafień)
    access_pattern: Arc<DashMap<u64, (usize, u32)>>,
    /// Bloki aktualnie w locie (prefetch w trakcie) — unika duplikowania
    /// pracy gdy kilka wątków FUSE czyta ten sam plik jednocześnie.
    in_flight: Arc<DashMap<(u64, usize), ()>>,
}

impl Prefetcher {
    pub fn new() -> Self {
        Self::with_window(DEFAULT_WINDOW)
    }

    pub fn with_window(window: usize) -> Self {
        // Pula ograniczona do min(4, dostępne rdzenie) — prefetch to praca
        // w tle, nie chcemy konkurować o CPU z właściwymi żądaniami FUSE.
        let threads = std::thread::available_parallelism()
            .map(|n| n.get().min(4))
            .unwrap_or(2);
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("ghostfs-prefetch-{i}"))
            .build()
            .expect("failed to build ghostfs prefetch thread pool");

        Self {
            pool: Arc::new(pool),
            window,
            access_pattern: Arc::new(DashMap::new()),
            in_flight: Arc::new(DashMap::new()),
        }
    }

    /// Wywoływane po KAŻDYM zwykłym (synchronicznym) odczycie bloku przez
    /// `GhostFS::get_block`. Aktualizuje wzorzec dostępu i — jeśli dostęp
    /// jest sekwencyjny — zleca prefetch kolejnych `window` bloków.
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_read(
        &self,
        ino: u64,
        block_idx: usize,
        db: &Db,
        crypto: &Crypto,
        compression: &Compression,
        dedup: &Deduplication,
        integrity: &IntegrityTree,
        extents: &ExtentTree,
        cache: &Cache,
    ) {
        let is_sequential = {
            let mut entry = self.access_pattern.entry(ino).or_insert((block_idx, 0));
            let (last_idx, streak) = *entry;
            let seq = block_idx == last_idx + 1 || (block_idx == 0 && last_idx == 0);
            let new_streak = if seq { streak.saturating_add(1) } else { 0 };
            *entry = (block_idx, new_streak);
            new_streak >= SEQUENTIAL_TRIGGER
        };

        if !is_sequential {
            return;
        }

        for offset in 1..=self.window {
            let target = block_idx + offset;
            // Już w cache'u? Nic do roboty.
            if cache.get_block(ino, target).is_some() {
                continue;
            }
            let key = (ino, target);
            if self.in_flight.contains_key(&key) {
                continue; // ktoś inny już to prefetchuje
            }
            self.in_flight.insert(key, ());

            let db = db.clone();
            let crypto = crypto.clone();
            let compression = compression.clone();
            let dedup = dedup.clone();
            let integrity = integrity.clone();
            let extents = extents.clone();
            let cache = cache.clone();
            let in_flight = self.in_flight.clone();

            self.pool.spawn(move || {
                if let Err(e) = prefetch_one(
                    ino, target, &db, &crypto, &compression, &dedup, &integrity, &extents, &cache,
                ) {
                    log::debug!(
                        "GhostFS prefetch: ino={ino} block={target} skipped ({e}) — non-fatal"
                    );
                }
                in_flight.remove(&key);
            });
        }
    }

    /// Zresetuj wzorzec dostępu dla inode — wołane przy `open()`/`lseek()`
    /// z dużym skokiem, żeby nie prefetchować bloków, które i tak nie będą
    /// czytane (np. po `seek` na koniec pliku).
    pub fn reset(&self, ino: u64) {
        self.access_pattern.remove(&ino);
    }
}

impl Default for Prefetcher {
    fn default() -> Self { Self::new() }
}

/// Odpowiednik `GhostFS::get_block`, ale bez `&mut self` — bo działa na
/// klonach uchwytów (sled::Db, Crypto, ... wszystkie są tanie do klonowania:
/// Arc/Clone wewnętrznie), na osobnym wątku puli rayon.
#[allow(clippy::too_many_arguments)]
fn prefetch_one(
    ino: u64,
    block_idx: usize,
    db: &Db,
    crypto: &Crypto,
    compression: &Compression,
    dedup: &Deduplication,
    integrity: &IntegrityTree,
    extents: &ExtentTree,
    cache: &Cache,
) -> Result<(), crate::error::HfsError> {
    let pk = extents
        .resolve(ino, block_idx)
        .unwrap_or_else(|| format!("data:{}:{}", ino, block_idx));
    let raw = match db.get(pk.as_bytes())? {
        Some(d) => d.to_vec(),
        // Koniec pliku / dziura — nie ma czego prefetchować, to nie błąd.
        None => return Ok(()),
    };
    let fek = crypto.derive_fek(ino);
    let decrypted = crypto.decrypt_with_key(&fek, &raw)?;
    let decompressed = compression.decompress(&decrypted)?;
    dedup.verify(ino, block_idx, &decompressed)?;
    integrity.verify_block(ino, block_idx, &decompressed)?;

    debug_assert!(decompressed.len() <= (FS_BLOCK_SIZE as usize) * 2, "unexpectedly large block");
    cache.put_block(ino, block_idx, decompressed);
    Ok(())
}
