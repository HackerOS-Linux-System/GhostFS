use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use crate::error::HfsError;

const DEFAULT_RATE: u64    = 100 * 1024 * 1024; // 100 MiB/s
const DEFAULT_BURST: u64   = 2;
/// Usuń kubełki które nie były używane przez 10 minut.
const BUCKET_TTL_SECS: u64 = 600;

struct Bucket {
    tokens:      u64,
    capacity:    u64,
    refill_rate: u64,
    last_refill: Instant,
    last_used:   Instant,
}

impl Bucket {
    fn new(rate: u64) -> Self {
        let now = Instant::now();
        Self {
            tokens:      rate * DEFAULT_BURST,
            capacity:    rate * DEFAULT_BURST,
            refill_rate: rate,
            last_refill: now,
            last_used:   now,
        }
    }

    fn try_consume(&mut self, bytes: u64) -> bool {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        let added   = (elapsed * self.refill_rate as f64) as u64;
        if added > 0 {
            self.tokens     = (self.tokens + added).min(self.capacity);
            self.last_refill = Instant::now();
        }
        if self.tokens >= bytes {
            self.tokens   -= bytes;
            self.last_used = Instant::now();
            true
        } else {
            false
        }
    }

    fn is_expired(&self) -> bool {
        self.last_used.elapsed().as_secs() > BUCKET_TTL_SECS
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    buckets:    Arc<Mutex<HashMap<u32, Bucket>>>,
    rate_bps:   u64,
    /// UID-y z whitelisty — bez ograniczeń (red team tools).
    whitelist:  Arc<Mutex<std::collections::HashSet<u32>>>,
    evict_ctr:  Arc<Mutex<u64>>,
    /// UID-y zablokowane CAŁKOWICIE (nie throttling — odmowa wszystkiego).
    /// Ustawiane przez `security::response::AutoResponse` po przekroczeniu
    /// progu powtarzających się alertów IDS. To jest w pamięci (per-mount);
    /// trwały stan lockoutu żyje w DB przez `AutoResponse` tak, by
    /// przetrwał remount — `GhostFS::new` odtwarza ten set z DB przy starcie
    /// (patrz `fs/lib.rs`).
    lockout:    Arc<Mutex<std::collections::HashSet<u32>>>,
}

impl RateLimiter {
    pub fn new() -> Self { Self::with_rate(DEFAULT_RATE) }

    pub fn with_rate(rate_bps: u64) -> Self {
        Self {
            buckets:   Arc::new(Mutex::new(HashMap::new())),
            rate_bps,
            whitelist: Arc::new(Mutex::new(std::collections::HashSet::new())),
            evict_ctr: Arc::new(Mutex::new(0)),
            lockout:   Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// Zablokuj UID CAŁKOWICIE — `check_io` będzie zwracać `UidLockedOut`
    /// niezależnie od whitelisty/budżetu. Wołane przez `AutoResponse`.
    pub fn lock_uid(&self, uid: u32) {
        self.lockout.lock().unwrap().insert(uid);
    }

    pub fn unlock_uid(&self, uid: u32) {
        self.lockout.lock().unwrap().remove(&uid);
    }

    pub fn is_locked(&self, uid: u32) -> bool {
        self.lockout.lock().unwrap().contains(&uid)
    }

    /// Dodaj UID do whitelisty (brak throttlingu — np. red team agent UID).
    pub fn allow_uid(&self, uid: u32) {
        self.whitelist.lock().unwrap().insert(uid);
        log::debug!("rate_limit: uid={} whitelisted (unlimited I/O)", uid);
    }

    pub fn remove_whitelist(&self, uid: u32) {
        self.whitelist.lock().unwrap().remove(&uid);
    }

    pub fn check_io(&self, uid: u32, bytes: u64) -> Result<(), HfsError> {
        // Lockout jest sprawdzany PRZED root-bypassem świadomie NIE dotyczy
        // root (AutoResponse nigdy nie blokuje uid=0 — patrz response.rs),
        // ale sprawdzenie samo w sobie musi być pierwsze: całkowita blokada
        // > throttling, niezależnie od whitelisty.
        if self.lockout.lock().unwrap().contains(&uid) {
            return Err(HfsError::UidLockedOut(uid));
        }
        // Root i whitelista — bez ograniczeń.
        if uid == 0 || self.whitelist.lock().unwrap().contains(&uid) {
            return Ok(());
        }

        let rate = self.rate_bps;
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets.entry(uid).or_insert_with(|| Bucket::new(rate));

        if bucket.try_consume(bytes) {
            // Ewakuuj stare kubełki co 1000 operacji — zapobiega memory leak.
            drop(bucket); // zwolnij borrow
            let mut ctr = self.evict_ctr.lock().unwrap();
            *ctr += 1;
            if *ctr % 1000 == 0 {
                buckets.retain(|_, b| !b.is_expired());
                log::debug!("rate_limit: evicted stale buckets, {} remaining", buckets.len());
            }
            Ok(())
        } else {
            log::warn!("rate_limit: uid={} throttled ({}B)", uid, bytes);
            Err(HfsError::RateLimited(uid))
        }
    }
}

impl Default for RateLimiter { fn default() -> Self { Self::new() } }
