use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

const PERM_FAIL_THRESHOLD: u32 = 20;   // per 60 s
const MASS_DELETE_THRESHOLD: u32 = 50; // per 60 s
const ENUM_THRESHOLD: u32 = 500;       // readdirs per 60 s
const WINDOW_SECS: u64 = 60;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AlertKind {
    BruteForce,
    MassDelete,
    PrivilegeEscalation,
    SuspiciousXattr,
    RapidEnumeration,
    IntegrityViolation { ino: u64 },
    MacViolation { ino: u64 },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdsAlert {
    pub timestamp: u64,
    pub uid: u32,
    pub kind: AlertKind,
    pub detail: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UidStats {
    pub window_start: u64,
    pub perm_fails: u32,
    pub deletes: u32,
    pub readdirs: u32,
}

#[derive(Clone)]
pub struct Ids {
    db: Db,
}

impl Ids {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
    }

    fn stats_key(uid: u32) -> String {
        format!("ids:stats:{}", uid)
    }

    fn load_stats(&self, uid: u32) -> Result<UidStats, HfsError> {
        match self.db.get(Self::stats_key(uid).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None => Ok(UidStats::default()),
        }
    }

    fn save_stats(&self, uid: u32, stats: &UidStats) -> Result<(), HfsError> {
        self.db.insert(
            Self::stats_key(uid).as_bytes(),
                       bincode::serialize(stats)?,
        )?;
        Ok(())
    }

    fn reset_if_expired(stats: &mut UidStats, now: u64) {
        if now.saturating_sub(stats.window_start) >= WINDOW_SECS {
            *stats = UidStats { window_start: now, ..Default::default() };
        }
    }

    pub fn emit_alert(&self, uid: u32, kind: AlertKind, detail: &str) -> Result<(), HfsError> {
        let now = Self::now();
        let seq: u64 = rand::random::<u64>();
        let alert = IdsAlert {
            timestamp: now,
            uid,
            kind,
            detail: detail.to_string(),
        };
        let key = format!("ids:alert:{}:{}", now, seq);
        self.db.insert(key.as_bytes(), bincode::serialize(&alert)?)?;
        log::warn!("[GhostFS IDS] uid={} {:?}: {}", uid, alert.kind, detail);
        Ok(())
    }

    /// Record a permission check; call after DAC/MAC deny.
    pub fn record_perm_fail(&self, uid: u32, ino: u64) -> Result<(), HfsError> {
        let now = Self::now();
        let mut stats = self.load_stats(uid)?;
        Self::reset_if_expired(&mut stats, now);
        stats.perm_fails += 1;
        if stats.perm_fails == PERM_FAIL_THRESHOLD {
            self.emit_alert(
                uid,
                AlertKind::BruteForce,
                &format!("ino={} {} perm-fails in {}s", ino, PERM_FAIL_THRESHOLD, WINDOW_SECS),
            )?;
        }
        self.save_stats(uid, &stats)
    }

    /// Record any access (used for anomaly baseline).
    pub fn record_access(&self, uid: u32, _ino: u64, _mask: i32) -> Result<(), HfsError> {
        // Lightweight: just keep stats fresh (no alert on every access)
        let now = Self::now();
        let mut stats = self.load_stats(uid)?;
        Self::reset_if_expired(&mut stats, now);
        self.save_stats(uid, &stats)
    }

    /// Record an unlink; alert on mass-delete.
    pub fn record_delete(&self, uid: u32, ino: u64) -> Result<(), HfsError> {
        let now = Self::now();
        let mut stats = self.load_stats(uid)?;
        Self::reset_if_expired(&mut stats, now);
        stats.deletes += 1;
        if stats.deletes == MASS_DELETE_THRESHOLD {
            self.emit_alert(
                uid,
                AlertKind::MassDelete,
                &format!("ino={} {} deletes in {}s", ino, MASS_DELETE_THRESHOLD, WINDOW_SECS),
            )?;
        }
        self.save_stats(uid, &stats)
    }

    /// Record a readdir; alert on rapid enumeration.
    pub fn record_readdir(&self, uid: u32) -> Result<(), HfsError> {
        let now = Self::now();
        let mut stats = self.load_stats(uid)?;
        Self::reset_if_expired(&mut stats, now);
        stats.readdirs += 1;
        if stats.readdirs == ENUM_THRESHOLD {
            self.emit_alert(
                uid,
                AlertKind::RapidEnumeration,
                &format!("{} readdirs in {}s", ENUM_THRESHOLD, WINDOW_SECS),
            )?;
        }
        self.save_stats(uid, &stats)
    }

    /// Return the N most recent alerts for reporting / SIEM export.
    pub fn recent_alerts(&self, n: usize) -> Result<Vec<IdsAlert>, HfsError> {
        let prefix = "ids:alert:";
        let mut alerts: Vec<IdsAlert> = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, v) = item?;
            if let Ok(a) = bincode::deserialize::<IdsAlert>(&v) {
                alerts.push(a);
            }
        }
        // Most recent first
        alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        alerts.truncate(n);
        Ok(alerts)
    }
}
