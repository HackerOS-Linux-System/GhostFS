use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use crate::error::HfsError;

/// Default rate limit per UID in bytes/second (100 MiB/s).
const DEFAULT_RATE_BYTES_PER_SEC: u64 = 100 * 1024 * 1024;
/// Burst capacity = 2× the per-second limit.
const DEFAULT_BURST_FACTOR: u64 = 2;

struct Bucket {
    tokens:          u64,
    capacity:        u64,
    refill_rate:     u64, // tokens per second
    last_refill:     Instant,
}

impl Bucket {
    fn new(rate_bps: u64) -> Self {
        Self {
            tokens:      rate_bps * DEFAULT_BURST_FACTOR,
            capacity:    rate_bps * DEFAULT_BURST_FACTOR,
            refill_rate: rate_bps,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time, then consume `bytes`.
    /// Returns `true` if the request is allowed, `false` if throttled.
    fn try_consume(&mut self, bytes: u64) -> bool {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        let new_tokens = (elapsed * self.refill_rate as f64) as u64;
        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = Instant::now();
        }

        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    buckets:      Arc<Mutex<HashMap<u32, Bucket>>>,
    rate_bps:     u64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_rate(DEFAULT_RATE_BYTES_PER_SEC)
    }

    pub fn with_rate(rate_bps: u64) -> Self {
        Self {
            buckets:  Arc::new(Mutex::new(HashMap::new())),
            rate_bps,
        }
    }

    /// Check if `uid` is allowed to perform an I/O of `bytes` bytes.
    /// Returns `Err(HfsError::RateLimited)` if the bucket is exhausted.
    /// Root (uid=0) is always allowed.
    pub fn check_io(&self, uid: u32, bytes: u64) -> Result<(), HfsError> {
        if uid == 0 { return Ok(()); }

        let mut buckets = self.buckets.lock().unwrap();
        let rate = self.rate_bps;
        let bucket = buckets.entry(uid).or_insert_with(|| Bucket::new(rate));

        if bucket.try_consume(bytes) {
            Ok(())
        } else {
            log::warn!(
                "GhostFS rate_limit: uid={} throttled (requested {}B, tokens={})",
                       uid, bytes, bucket.tokens
            );
            Err(HfsError::RateLimited(uid))
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self { Self::new() }
}
