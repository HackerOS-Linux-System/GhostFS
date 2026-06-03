use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct UserQuota {
    pub limit: u64,   // bytes; 0 = unlimited
    pub used:  u64,   // bytes currently consumed
}

pub struct Quota {
    db: Db,
}

impl Quota {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn quota_key(uid: u32) -> String {
        format!("quota:{}", uid)
    }

    pub fn get_quota(&self, uid: u32) -> Result<UserQuota, HfsError> {
        match self.db.get(Self::quota_key(uid).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(UserQuota::default()),
        }
    }

    fn set_quota(&self, uid: u32, quota: &UserQuota) -> Result<(), HfsError> {
        self.db.insert(
            Self::quota_key(uid).as_bytes(),
                       bincode::serialize(quota)?,
        )?;
        Ok(())
    }

    /// Check whether uid can allocate `additional` more bytes.
    pub fn check_quota(&self, uid: u32, additional: u64) -> Result<(), HfsError> {
        let q = self.get_quota(uid)?;
        if q.limit > 0 && q.used.saturating_add(additional) > q.limit {
            return Err(HfsError::QuotaExceeded(uid));
        }
        Ok(())
    }

    /// Increment the usage counter for uid.
    pub fn update_usage(&self, uid: u32, delta: u64) -> Result<(), HfsError> {
        let mut q = self.get_quota(uid)?;
        q.used = q.used.saturating_add(delta);
        self.set_quota(uid, &q)
    }

    /// Decrement the usage counter (e.g. after unlink).
    pub fn release_usage(&self, uid: u32, delta: u64) -> Result<(), HfsError> {
        let mut q = self.get_quota(uid)?;
        q.used = q.used.saturating_sub(delta);
        self.set_quota(uid, &q)
    }

    /// Set the hard limit for uid (bytes; 0 = unlimited).
    pub fn set_limit(&self, uid: u32, limit: u64) -> Result<(), HfsError> {
        let mut q = self.get_quota(uid)?;
        q.limit = limit;
        self.set_quota(uid, &q)
    }

    /// Pretty-print quota info for uid (used by CLI).
    pub fn show(&self, uid: u32) -> Result<(), HfsError> {
        let q = self.get_quota(uid)?;
        let limit_str = if q.limit == 0 {
            "unlimited".to_string()
        } else {
            format!("{} bytes ({:.1} MiB)", q.limit, q.limit as f64 / 1_048_576.0)
        };
        println!(
            "uid={} used={} bytes ({:.1} MiB)  limit={}",
                 uid,
                 q.used,
                 q.used as f64 / 1_048_576.0,
                 limit_str,
        );
        Ok(())
    }
}
