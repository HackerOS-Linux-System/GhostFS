use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

const ALERT_TTL_SECS:       u64   = 7 * 24 * 3600; // 7 dni
const ALERT_PRUNE_INTERVAL: u64   = 3600;           // przycinaj co godzinę
const HISTOGRAM_DECAY_SECS: u64   = 3600;           // half-life histogramu
/// Współczynnik decay per godzinę (≈ exp(-ln2)) — wartości starsze o DECAY_SECS maleją o ~50%.
const DECAY_FACTOR: f64           = 0.5;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdsAlert {
    pub uid:          u32,
    pub ino:          u64,
    pub reason:       String,
    pub timestamp:    u64,
    pub access_mask:  i32,
}

/// Profil zachowania UID z mechanizmem decay dla histogramu godzinowego.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UidProfile {
    /// Godzinowy histogram dostępów — wartości wygasają przez decay.
    /// Klucz: godzina (0–23), wartość: ważona liczba dostępów.
    pub hourly_histogram: [f64; 24],
    /// Unix timestamp ostatniego decay — co HISTOGRAM_DECAY_SECS aplikujemy decay.
    pub last_decay_ts:    u64,
    pub total_accesses:   u64,
}

impl UidProfile {
    fn new(now: u64) -> Self {
        Self {
            hourly_histogram: [0.0; 24],
            last_decay_ts:    now,
            total_accesses:   0,
        }
    }

    /// Zastosuj exponential decay do histogramu jeśli minął wymagany czas.
    fn apply_decay(&mut self, now: u64) {
        if now <= self.last_decay_ts {
            return;
        }
        let elapsed_secs = now - self.last_decay_ts;
        // Liczba pełnych epok decay które minęły.
        let epochs = elapsed_secs as f64 / HISTOGRAM_DECAY_SECS as f64;
        if epochs < 0.1 {
            return; // Za mało czasu — nie warto przeliczać.
        }
        let factor = DECAY_FACTOR.powf(epochs);
        for v in &mut self.hourly_histogram {
            *v *= factor;
            // Wyzeruj wartości poniżej progu szumu.
            if *v < 0.001 { *v = 0.0; }
        }
        self.last_decay_ts = now;
    }

    fn avg_hourly(&self) -> f64 {
        let sum: f64 = self.hourly_histogram.iter().sum();
        sum / 24.0
    }

    fn is_anomalous_hour(&self, hour: u8) -> bool {
        let avg = self.avg_hourly();
        if avg < 1.0 { return false; } // Za mało danych.
        let current = self.hourly_histogram[hour as usize];
        // Brak aktywności w godzinie przy średniej > 10 — anomalia nocna.
        current < avg * 0.1 && avg > 10.0
    }
}

#[derive(Clone)]
pub struct Ids {
    db:              Db,
    last_prune_key:  String,
}

impl Ids {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self {
            db:             db.clone(),
            last_prune_key: "ids:last_prune".to_string(),
        })
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn alert_key(ts: u64, uid: u32) -> String {
        // Padding timestamp → sortowanie chronologiczne.
        format!("ids:alert:{:016}:{}", ts, uid)
    }

    fn profile_key(uid: u32) -> String {
        format!("ids:profile:{}", uid)
    }

    /// Zapisz alert z TTL — alerty starsze niż ALERT_TTL_SECS są usuwane przez `prune_alerts`.
    pub fn add_alert(&self, uid: u32, ino: u64, reason: &str, access_mask: i32) -> Result<(), HfsError> {
        let now = Self::now();
        let alert = IdsAlert { uid, ino, reason: reason.to_string(), timestamp: now, access_mask };
        let key   = Self::alert_key(now, uid);
        self.db.insert(key.as_bytes(), bincode::serialize(&alert)?)?;
        log::warn!("GhostFS IDS alert: uid={} ino={} reason={}", uid, ino, reason);
        // Opcjonalne przycinanie co ALERT_PRUNE_INTERVAL.
        self.maybe_prune(now)?;
        Ok(())
    }

    /// Usuń alerty starsze niż ALERT_TTL_SECS.
    pub fn prune_alerts(&self) -> Result<u64, HfsError> {
        let now     = Self::now();
        let cutoff  = now.saturating_sub(ALERT_TTL_SECS);
        let cutoff_key = Self::alert_key(cutoff, 0);

        let old_keys: Vec<_> = self.db
            .range(b"ids:alert:".as_ref()..cutoff_key.as_bytes())
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .filter(|k| k.starts_with(b"ids:alert:"))
            .collect();

        let removed = old_keys.len() as u64;
        let mut batch = sled::Batch::default();
        for k in old_keys { batch.remove(k); }
        self.db.apply_batch(batch)?;

        if removed > 0 {
            log::info!("GhostFS IDS: pruned {} expired alerts (older than {}s)", removed, ALERT_TTL_SECS);
        }
        Ok(removed)
    }

    fn maybe_prune(&self, now: u64) -> Result<(), HfsError> {
        let last: u64 = match self.db.get(self.last_prune_key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
            None    => 0,
        };
        if now.saturating_sub(last) >= ALERT_PRUNE_INTERVAL {
            self.prune_alerts()?;
            self.db.insert(self.last_prune_key.as_bytes(), bincode::serialize(&now)?)?;
        }
        Ok(())
    }

    /// Odnotuj dostęp i zaktualizuj profil UID z decay histogramu.
    pub fn record_access(&self, uid: u32, ino: u64, access_mask: i32) -> Result<(), HfsError> {
        let now   = Self::now();
        let hour  = ((now / 3600) % 24) as u8;

        let mut profile = self.load_profile(uid, now)?;
        // Zastosuj decay przed aktualizacją — stare wartości maleją.
        profile.apply_decay(now);
        profile.hourly_histogram[hour as usize] += 1.0;
        profile.total_accesses += 1;

        let anomalous = profile.is_anomalous_hour(hour);
        self.save_profile(uid, &profile)?;

        if anomalous {
            self.add_alert(uid, ino, "Unusual access hour (nighttime anomaly)", access_mask)?;
        }
        Ok(())
    }

    pub fn get_alerts(&self, limit: usize) -> Result<Vec<IdsAlert>, HfsError> {
        // Odczytaj od końca (najnowsze) — zakres od końca do początku.
        let alerts: Vec<IdsAlert> = self.db
            .scan_prefix(b"ids:alert:")
            .filter_map(|r| r.ok())
            .filter_map(|(_, v)| bincode::deserialize::<IdsAlert>(&v).ok())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .take(limit)
            .collect();
        Ok(alerts)
    }

    fn load_profile(&self, uid: u32, now: u64) -> Result<UidProfile, HfsError> {
        match self.db.get(Self::profile_key(uid).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(UidProfile::new(now)),
        }
    }

    fn save_profile(&self, uid: u32, profile: &UidProfile) -> Result<(), HfsError> {
        self.db.insert(Self::profile_key(uid).as_bytes(), bincode::serialize(profile)?)?;
        Ok(())
    }
}
