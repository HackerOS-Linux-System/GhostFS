use sled::Db;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Default)]
struct UserQuota {
    limit: u64,   // 0 oznacza brak limitu
    used: u64,
}

pub struct Quota {
    db: Db,
}

impl Quota {
    pub fn new(db: &Db) -> Result<Self, ()> {
        Ok(Self { db: db.clone() })
    }

    fn get_quota(&self, uid: u32) -> Result<UserQuota, ()> {
        let key = format!("quota:{}", uid);
        match self.db.get(key.as_bytes()).map_err(|_| ())? {
            Some(v) => bincode::deserialize(&v).map_err(|_| ()),
            None => Ok(UserQuota::default()),
        }
    }

    fn set_quota(&self, uid: u32, quota: UserQuota) -> Result<(), ()> {
        let key = format!("quota:{}", uid);
        self.db.insert(key.as_bytes(), bincode::serialize(&quota).map_err(|_| ())?).map_err(|_| ())?;
        Ok(())
    }

    pub fn check_quota(&self, uid: u32, additional: u64) -> Result<(), c_int> {
        let quota = self.get_quota(uid)?;
        if quota.limit > 0 && quota.used + additional > quota.limit {
            return Err(libc::EDQUOT);
        }
        Ok(())
    }

    pub fn update_usage(&self, uid: u32, delta: u64) -> Result<(), ()> {
        let mut quota = self.get_quota(uid)?;
        quota.used += delta;
        self.set_quota(uid, quota)
    }

    pub fn set_limit(&self, uid: u32, limit: u64) -> Result<(), ()> {
        let mut quota = self.get_quota(uid)?;
        quota.limit = limit;
        self.set_quota(uid, quota)
    }
}
