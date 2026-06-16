use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

const PERM_FAIL_THRESHOLD: u32   = 20;
const MASS_DELETE_THRESHOLD: u32 = 50;
const ENUM_THRESHOLD: u32        = 500;
const EXFIL_THRESHOLD_BYTES: u64 = 512 * 1024 * 1024;
const LATERAL_THRESHOLD: u32     = 10;
const WINDOW_SECS: u64           = 60;

/// Godziny "nocne" — aktywność w tym czasie jest podejrzana
const NIGHT_HOUR_START: u32 = 0;  // 00:00
const NIGHT_HOUR_END:   u32 = 5;  // 05:00
/// Próg aktywności nocnej triggerujący alert
const NIGHT_OPS_THRESHOLD: u32 = 10;

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
    NightTimeAnomaly   { hour: u32, ops: u32 },
    SuddenActivitySpike{ baseline_ops: u32, current_ops: u32 },
    /// Plik canary (honeypot) został otwarty
    CanaryTriggered    { ino: u64 },
    /// Symlink wskazujący poza wolumen (path traversal) zablokowany
    SymlinkTraversal   { ino: u64 },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdsAlert {
    pub timestamp: u64,
    pub uid:       u32,
    pub kind:      AlertKind,
    pub detail:    String,
}

/// Okno bieżące (60s)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WindowStats {
    pub window_start:    u64,
    pub perm_fails:      u32,
    pub deletes:         u32,
    pub readdirs:        u32,
    pub bytes_read:      u64,
    pub cross_uid_reads: u32,
    pub total_ops:       u32,
}

/// Persystentny profil dzienny per-UID — przechowywany w sled między sesjami
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UidProfile {
    /// Średnia liczba operacji na okno z ostatnich 7 dni (krocząca)
    pub baseline_ops_avg: f32,
    /// Liczba próbek do baseline
    pub baseline_samples: u32,
    /// Operacje per godzina (indeks 0..23) — histogram z ostatnich 7 dni
    pub hourly_histogram: [u32; 24],
    /// Ostatni czas aktualizacji profilu
    pub last_updated:     u64,
}

#[derive(Clone)]
#[derive(Clone)]
pub struct Ids { db: Db }

impl Ids {
    pub fn new(db: &Db) -> Result<Self, HfsError> { Ok(Self { db: db.clone() }) }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs()
    }

    fn current_hour() -> u32 {
        (Self::now() % 86400 / 3600) as u32
    }

    fn window_key(uid: u32)  -> String { format!("ids:window:{}", uid) }
    fn profile_key(uid: u32) -> String { format!("ids:profile:{}", uid) }

    fn load_window(&self, uid: u32) -> Result<WindowStats, HfsError> {
        match self.db.get(Self::window_key(uid).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(WindowStats::default()),
        }
    }

    fn save_window(&self, uid: u32, s: &WindowStats) -> Result<(), HfsError> {
        self.db.insert(Self::window_key(uid).as_bytes(), bincode::serialize(s)?)?;
        Ok(())
    }

    fn load_profile(&self, uid: u32) -> Result<UidProfile, HfsError> {
        match self.db.get(Self::profile_key(uid).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(UidProfile::default()),
        }
    }

    fn save_profile(&self, uid: u32, p: &UidProfile) -> Result<(), HfsError> {
        self.db.insert(Self::profile_key(uid).as_bytes(), bincode::serialize(p)?)?;
        Ok(())
    }

    fn reset_if_expired(s: &mut WindowStats, now: u64) -> bool {
        if now.saturating_sub(s.window_start) >= WINDOW_SECS {
            *s = WindowStats { window_start: now, ..Default::default() };
            return true;
        }
        false
    }

    /// Aktualizuj profil po zamknięciu okna — krocząca średnia + histogram godzinowy.
    fn update_profile(&self, uid: u32, closed_window: &WindowStats) -> Result<(), HfsError> {
        let mut profile = self.load_profile(uid)?;
        let hour        = Self::current_hour() as usize;

        // Krocząca średnia (EMA, alpha=0.1)
        let ops = closed_window.total_ops as f32;
        if profile.baseline_samples == 0 {
            profile.baseline_ops_avg = ops;
        } else {
            profile.baseline_ops_avg = 0.9 * profile.baseline_ops_avg + 0.1 * ops;
        }
        profile.baseline_samples += 1;

        // Histogram godzinowy (decay weekly: dziel przez 2 raz na tydzień — uproszczone)
        profile.hourly_histogram[hour] = profile.hourly_histogram[hour].saturating_add(closed_window.total_ops);
        profile.last_updated = Self::now();
        self.save_profile(uid, &profile)
    }

    /// Sprawdź anomalie na podstawie profilu.
    fn check_anomalies(&self, uid: u32, current: &WindowStats) -> Result<(), HfsError> {
        if uid == 0 { return Ok(()); }
        let profile = self.load_profile(uid)?;

        // Anomalia 1: nagły skok aktywności (>5x baseline)
        let baseline = profile.baseline_ops_avg;
        if baseline > 10.0 && current.total_ops as f32 > baseline * 5.0 {
            self.emit_alert(uid, AlertKind::SuddenActivitySpike {
                baseline_ops: baseline as u32,
                current_ops:  current.total_ops,
            }, &format!("{}x spike over baseline", current.total_ops as f32 / baseline))?;
        }

        // Anomalia 2: aktywność nocna gdy historycznie jej nie było
        let hour = Self::current_hour();
        if hour >= NIGHT_HOUR_START && hour < NIGHT_HOUR_END {
            let night_baseline: u32 = profile.hourly_histogram
                [NIGHT_HOUR_START as usize..NIGHT_HOUR_END as usize]
                .iter().sum();
            if night_baseline == 0 && current.total_ops >= NIGHT_OPS_THRESHOLD {
                self.emit_alert(uid, AlertKind::NightTimeAnomaly {
                    hour,
                    ops: current.total_ops,
                }, &format!("Unusual activity at {:02}:00 — no historical baseline", hour))?;
            }
        }
        Ok(())
    }

    pub fn emit_alert(&self, uid: u32, kind: AlertKind, detail: &str) -> Result<(), HfsError> {
        let now   = Self::now();
        let seq: u64 = rand::random();
        let alert = IdsAlert { timestamp: now, uid, kind, detail: detail.to_string() };
        let key   = format!("ids:alert:{}:{}", now, seq);
        self.db.insert(key.as_bytes(), bincode::serialize(&alert)?)?;
        log::warn!("[GhostFS IDS] uid={} {:?}: {}", uid, alert.kind, detail);
        Ok(())
    }

    fn tick(&self, uid: u32) -> Result<(), HfsError> {
        let now     = Self::now();
        let mut s   = self.load_window(uid)?;
        let expired = Self::reset_if_expired(&mut s, now);
        if expired && s.total_ops > 0 {
            // Zamknięte okno — aktualizuj profil i sprawdź anomalie
            let closed = s.clone();
            self.update_profile(uid, &closed)?;
            self.check_anomalies(uid, &closed)?;
        }
        s.total_ops += 1;
        self.save_window(uid, &s)?;
        Ok(())
    }

    pub fn record_perm_fail(&self, uid: u32, ino: u64) -> Result<(), HfsError> {
        self.tick(uid)?;
        let now   = Self::now();
        let mut s = self.load_window(uid)?;
        Self::reset_if_expired(&mut s, now);
        s.perm_fails += 1;
        if s.perm_fails == PERM_FAIL_THRESHOLD {
            self.emit_alert(uid, AlertKind::BruteForce,
                &format!("ino={} {} perm-fails in {}s", ino, PERM_FAIL_THRESHOLD, WINDOW_SECS))?;
        }
        self.save_window(uid, &s)
    }

    pub fn record_read(&self, uid: u32, ino: u64, bytes: u64, owner_uid: u32) -> Result<(), HfsError> {
        self.tick(uid)?;
        let now   = Self::now();
        let mut s = self.load_window(uid)?;
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
                    &format!("{} cross-uid reads in {}s", LATERAL_THRESHOLD, WINDOW_SECS))?;
            }
        }
        self.save_window(uid, &s)
    }

    pub fn record_access(&self, uid: u32, _ino: u64, _mask: i32) -> Result<(), HfsError> {
        self.tick(uid)
    }

    pub fn record_delete(&self, uid: u32, ino: u64) -> Result<(), HfsError> {
        self.tick(uid)?;
        let now   = Self::now();
        let mut s = self.load_window(uid)?;
        Self::reset_if_expired(&mut s, now);
        s.deletes += 1;
        if s.deletes == MASS_DELETE_THRESHOLD {
            self.emit_alert(uid, AlertKind::MassDelete,
                &format!("ino={} {} deletes in {}s", ino, MASS_DELETE_THRESHOLD, WINDOW_SECS))?;
        }
        self.save_window(uid, &s)
    }

    pub fn record_readdir(&self, uid: u32) -> Result<(), HfsError> {
        self.tick(uid)?;
        let now   = Self::now();
        let mut s = self.load_window(uid)?;
        Self::reset_if_expired(&mut s, now);
        s.readdirs += 1;
        if s.readdirs == ENUM_THRESHOLD {
            self.emit_alert(uid, AlertKind::RapidEnumeration,
                &format!("{} readdirs in {}s", ENUM_THRESHOLD, WINDOW_SECS))?;
        }
        self.save_window(uid, &s)
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
