use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

const PERM_FAIL_THRESHOLD: u32   = 20;
const MASS_DELETE_THRESHOLD: u32 = 50;
const ENUM_THRESHOLD: u32        = 500;
const EXFIL_THRESHOLD_BYTES: u64 = 512 * 1024 * 1024;
const LATERAL_THRESHOLD: u32     = 10;
const WINDOW_SECS: u64           = 60;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AlertKind {
    BruteForce,
    MassDelete,
    PrivilegeEscalation,
    SuspiciousXattr,
    RapidEnumeration,
    IntegrityViolation { ino: u64 },
    MacViolation       { ino: u64 },
    MassRead           { bytes_read: u64 },
    LateralMovement    { reader_uid: u32, owner_uid: u32 },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdsAlert {
    pub timestamp: u64,
    pub uid:       u32,
    pub kind:      AlertKind,
    pub detail:    String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UidStats {
    pub window_start:    u64,
    pub perm_fails:      u32,
    pub deletes:         u32,
    pub readdirs:        u32,
    pub bytes_read:      u64,
    pub cross_uid_reads: u32,
}

#[derive(Clone)]
pub struct Ids { db: Db }

impl Ids {
    pub fn new(db: &Db) -> Result<Self, HfsError> { Ok(Self { db: db.clone() }) }

    fn now() -> u64 {
        std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs()
    }

    fn stats_key(uid: u32) -> String { format!("ids:stats:{}", uid) }

    fn load_stats(&self, uid: u32) -> Result<UidStats, HfsError> {
        match self.db.get(Self::stats_key(uid).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(UidStats::default()),
        }
    }

    fn save_stats(&self, uid: u32, stats: &UidStats) -> Result<(), HfsError> {
        self.db.insert(Self::stats_key(uid).as_bytes(), bincode::serialize(stats)?)?;
        Ok(())
    }

    fn reset_if_expired(stats: &mut UidStats, now: u64) {
        if now.saturating_sub(stats.window_start) >= WINDOW_SECS {
            *stats = UidStats { window_start: now, ..Default::default() };
        }
    }

    pub fn emit_alert(&self, uid: u32, kind: AlertKind, detail: &str) -> Result<(), HfsError> {
        let now = Self::now();
        let seq: u64 = rand::random();
        let alert = IdsAlert { timestamp: now, uid, kind, detail: detail.to_string() };
        let key   = format!("ids:alert:{}:{}", now, seq);
        self.db.insert(key.as_bytes(), bincode::serialize(&alert)?)?;
        log::warn!("[GhostFS IDS] uid={} {:?}: {}", uid, alert.kind, detail);
        Ok(())
    }

    pub fn record_perm_fail(&self, uid: u32, ino: u64) -> Result<(), HfsError> {
        let now = Self::now();
        let mut s = self.load_stats(uid)?;
        Self::reset_if_expired(&mut s, now);
        s.perm_fails += 1;
        if s.perm_fails == PERM_FAIL_THRESHOLD {
            self.emit_alert(uid, AlertKind::BruteForce,
                            &format!("ino={} {} perm-fails in {}s", ino, PERM_FAIL_THRESHOLD, WINDOW_SECS))?;
        }
        self.save_stats(uid, &s)
    }

    pub fn record_read(&self, uid: u32, ino: u64, bytes: u64, owner_uid: u32) -> Result<(), HfsError> {
        let now = Self::now();
        let mut s = self.load_stats(uid)?;
        Self::reset_if_expired(&mut s, now);
        s.bytes_read = s.bytes_read.saturating_add(bytes);
        if uid != 0 && s.bytes_read >= EXFIL_THRESHOLD_BYTES {
            self.emit_alert(uid, AlertKind::MassRead { bytes_read: s.bytes_read },
                            &format!("ino={} read {}B in {}s", ino, s.bytes_read, WINDOW_SECS))?;
                            s.bytes_read = 0;
        }
        if uid != owner_uid && uid != 0 {
            s.cross_uid_reads += 1;
            if s.cross_uid_reads == LATERAL_THRESHOLD {
                self.emit_alert(uid, AlertKind::LateralMovement { reader_uid: uid, owner_uid },
                                &format!("{} cross-uid reads in {}s (owner={})", LATERAL_THRESHOLD, WINDOW_SECS, owner_uid))?;
            }
        }
        self.save_stats(uid, &s)
    }

    pub fn record_access(&self, uid: u32, _ino: u64, _mask: i32) -> Result<(), HfsError> {
        let now = Self::now();
        let mut s = self.load_stats(uid)?;
        Self::reset_if_expired(&mut s, now);
        self.save_stats(uid, &s)
    }

    pub fn record_delete(&self, uid: u32, ino: u64) -> Result<(), HfsError> {
        let now = Self::now();
        let mut s = self.load_stats(uid)?;
        Self::reset_if_expired(&mut s, now);
        s.deletes += 1;
        if s.deletes == MASS_DELETE_THRESHOLD {
            self.emit_alert(uid, AlertKind::MassDelete,
                            &format!("ino={} {} deletes in {}s", ino, MASS_DELETE_THRESHOLD, WINDOW_SECS))?;
        }
        self.save_stats(uid, &s)
    }

    pub fn record_readdir(&self, uid: u32) -> Result<(), HfsError> {
        let now = Self::now();
        let mut s = self.load_stats(uid)?;
        Self::reset_if_expired(&mut s, now);
        s.readdirs += 1;
        if s.readdirs == ENUM_THRESHOLD {
            self.emit_alert(uid, AlertKind::RapidEnumeration,
                            &format!("{} readdirs in {}s", ENUM_THRESHOLD, WINDOW_SECS))?;
        }
        self.save_stats(uid, &s)
    }

    pub fn recent_alerts(&self, n: usize) -> Result<Vec<IdsAlert>, HfsError> {
        let mut alerts: Vec<IdsAlert> = self.db
        .scan_prefix(b"ids:alert:")
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| bincode::deserialize::<IdsAlert>(&v).ok())
        .collect();
        alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        alerts.truncate(n);
        Ok(alerts)
    }
}
