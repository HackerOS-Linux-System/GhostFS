use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

#[derive(Serialize, Deserialize, Default, Clone)]
struct UserQuota {
    limit: u64,
    used: u64,
}

pub struct Quota {
    db: Db,
}

impl Quota {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn get_quota(&self, uid: u32) -> Result<UserQuota, HfsError> {
        let key = format!("quota:{}", uid);
        match self.db.get(key.as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None => Ok(UserQuota::default()),
        }
    }

    fn set_quota(&self, uid: u32, quota: &UserQuota) -> Result<(), HfsError> {
        let key = format!("quota:{}", uid);
        self.db.insert(key.as_bytes(), bincode::serialize(quota)?)?;
        Ok(())
    }

    pub fn check_quota(&self, uid: u32, additional: u64) -> Result<(), HfsError> {
        let quota = self.get_quota(uid)?;
        if quota.limit > 0 && quota.used + additional > quota.limit {
            return Err(HfsError::QuotaExceeded(uid));
        }
        Ok(())
    }

    pub fn update_usage(&self, uid: u32, delta: u64) -> Result<(), HfsError> {
        let mut quota = self.get_quota(uid)?;
        quota.used = quota.used.saturating_add(delta);
        self.set_quota(uid, &quota)
    }

    pub fn set_limit(&self, uid: u32, limit: u64) -> Result<(), HfsError> {
        let mut quota = self.get_quota(uid)?;
        quota.limit = limit;
        self.set_quota(uid, &quota)
    }
}
