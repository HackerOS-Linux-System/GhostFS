use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuotaEntry {
    pub limit:        u64,
    pub used:         u64,
    pub last_updated: u64,
}

#[derive(Clone)]
pub struct Quota { db: Db }

impl Quota {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn entry_key(uid: u32) -> String {
        format!("quota:{}", uid)
    }

    fn timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn set_limit(&self, uid: u32, limit: u64) -> Result<(), HfsError> {
        let entry = match self.db.get(Self::entry_key(uid).as_bytes())? {
            Some(v) => {
                let mut e: QuotaEntry = bincode::deserialize(&v)?;
                e.limit        = limit;
                e.last_updated = Self::timestamp();
                e
            }
            None => QuotaEntry { limit, used: 0, last_updated: Self::timestamp() },
        };
        self.db.insert(Self::entry_key(uid).as_bytes(), bincode::serialize(&entry)?)?;
        Ok(())
    }

    pub fn check_quota(&self, uid: u32, additional: u64) -> Result<(), HfsError> {
        match self.db.get(Self::entry_key(uid).as_bytes())? {
            Some(v) => {
                let e: QuotaEntry = bincode::deserialize(&v)?;
                if e.limit > 0 && e.used + additional > e.limit {
                    return Err(HfsError::QuotaExceeded(uid));
                }
            }
            None => {} // Brak wpisu = brak limitu.
        }
        Ok(())
    }

    /// Dodaj do użycia (przy zapisie).
    pub fn update_usage(&self, uid: u32, delta: u64) -> Result<(), HfsError> {
        let mut entry = self.load_or_default(uid)?;
        entry.used         = entry.used.saturating_add(delta);
        entry.last_updated = Self::timestamp();
        self.db.insert(Self::entry_key(uid).as_bytes(), bincode::serialize(&entry)?)?;
        Ok(())
    }

    /// Zwolnij używane miejsce przy kasowaniu pliku (unlink/rmdir).
    ///
    /// Ta metoda MUSI być wywoływana z `fs.rs` przy każdym `unlink()` i `rmdir()`.
    /// Bez tego użycie rośnie bez ograniczeń i generuje fałszywe EDQUOT.
    pub fn release_usage(&self, uid: u32, bytes: u64) -> Result<(), HfsError> {
        let mut entry = self.load_or_default(uid)?;
        entry.used         = entry.used.saturating_sub(bytes);
        entry.last_updated = Self::timestamp();
        self.db.insert(Self::entry_key(uid).as_bytes(), bincode::serialize(&entry)?)?;
        log::debug!("quota: released {}B for uid={} (now used={})", bytes, uid, entry.used);
        Ok(())
    }

    pub fn get_usage(&self, uid: u32) -> Result<(u64, u64), HfsError> {
        let e = self.load_or_default(uid)?;
        Ok((e.used, e.limit))
    }

    fn load_or_default(&self, uid: u32) -> Result<QuotaEntry, HfsError> {
        match self.db.get(Self::entry_key(uid).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(QuotaEntry { limit: 0, used: 0, last_updated: Self::timestamp() }),
        }
    }
}
