use sled::Db;
use crate::error::HfsError;
use crate::ids::Ids;
use crate::rate_limit::RateLimiter;
use crate::syslog::{SyslogSender, Severity};

/// Okno czasowe, w którym liczymy powtarzające się alerty.
const ESCALATION_WINDOW_SECS: u64 = 900; // 15 minut
/// Od tylu alertów w oknie: głośne ostrzeżenie (jeszcze bez blokady).
const WARN_THRESHOLD: u64 = 3;
/// Od tylu alertów w oknie: pełny lockout UID.
const LOCKOUT_THRESHOLD: u64 = 6;

const LOCKOUT_KEY_PREFIX: &str = "ids:lockout:";
/// Globalny "przycisk paniki" — patrz `enable_global_lockdown`. Osobny
/// klucz od per-UID `LOCKOUT_KEY_PREFIX`: to blokuje WSZYSTKICH, łącznie
/// z rootem, bez wyjątku.
const GLOBAL_LOCKDOWN_KEY: &[u8] = b"lockdown:global";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseAction {
    None,
    Warned,
    LockedOut,
}

#[derive(Clone)]
pub struct AutoResponse {
    db: Db,
    syslog: SyslogSender,
}

impl AutoResponse {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone(), syslog: SyslogSender::new(db)? })
    }

    /// Wołane zaraz po `Ids::add_alert` (patrz `fs/lib.rs::check_permission`).
    /// Zwraca podjętą akcję — wołający decyduje czy natychmiast odmówić
    /// bieżącej operacji (LockedOut zawsze powinno skutkować odmową).
    pub fn evaluate(&self, ids: &Ids, rate_limit: &RateLimiter, uid: u32) -> Result<ResponseAction, HfsError> {
        if uid == 0 {
            return Ok(ResponseAction::None);
        }
        let count = ids.count_recent_alerts(uid, ESCALATION_WINDOW_SECS)?;

        if count >= LOCKOUT_THRESHOLD {
            self.persist_lock(uid)?;
            rate_limit.lock_uid(uid);
            log::error!(
                "GhostFS AUTO-RESPONSE: uid={} LOCKED OUT after {} IDS alerts in {}s — \
                 all filesystem access denied. Clear with 'ghostfs ids unlock --uid {}'.",
                uid, count, ESCALATION_WINDOW_SECS, uid
            );
            self.syslog.send(
                Severity::Critical, "IDS_LOCKOUT",
                &format!("uid={} locked out after {} IDS alerts in {}s", uid, count, ESCALATION_WINDOW_SECS),
            );
            return Ok(ResponseAction::LockedOut);
        }
        if count >= WARN_THRESHOLD {
            log::warn!(
                "GhostFS AUTO-RESPONSE: uid={} has {} IDS alerts in {}s — approaching lockout \
                 threshold of {}",
                uid, count, ESCALATION_WINDOW_SECS, LOCKOUT_THRESHOLD
            );
            self.syslog.send(
                Severity::Warning, "IDS_ESCALATION",
                &format!("uid={} has {} IDS alerts in {}s (lockout at {})", uid, count, ESCALATION_WINDOW_SECS, LOCKOUT_THRESHOLD),
            );
            return Ok(ResponseAction::Warned);
        }
        Ok(ResponseAction::None)
    }

    fn persist_lock(&self, uid: u32) -> Result<(), HfsError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        self.db.insert(format!("{}{}", LOCKOUT_KEY_PREFIX, uid).as_bytes(), bincode::serialize(&now)?)?;
        Ok(())
    }

    /// Ręczne odblokowanie przez administratora (`ghostfs ids unlock --uid`).
    pub fn unlock_uid(&self, rate_limit: &RateLimiter, uid: u32) -> Result<(), HfsError> {
        self.db.remove(format!("{}{}", LOCKOUT_KEY_PREFIX, uid).as_bytes())?;
        rate_limit.unlock_uid(uid);
        log::info!("GhostFS AUTO-RESPONSE: uid={} manually unlocked", uid);
        Ok(())
    }

    pub fn is_locked(&self, uid: u32) -> Result<bool, HfsError> {
        Ok(self.db.get(format!("{}{}", LOCKOUT_KEY_PREFIX, uid).as_bytes())?.is_some())
    }

    /// Lista aktualnie zablokowanych UID-ów wraz z timestampem lockoutu —
    /// używane przy starcie mountu (odtworzenie stanu `RateLimiter` z DB,
    /// bo `RateLimiter::lockout` jest tylko w pamięci) i przez `ghostfs ids`.
    pub fn list_locked(&self) -> Result<Vec<(u32, u64)>, HfsError> {
        let mut out = Vec::new();
        for item in self.db.scan_prefix(LOCKOUT_KEY_PREFIX.as_bytes()) {
            let (k, v) = item?;
            let ks = String::from_utf8_lossy(&k);
            if let Some(uid_str) = ks.strip_prefix(LOCKOUT_KEY_PREFIX) {
                if let Ok(uid) = uid_str.parse::<u32>() {
                    let ts: u64 = bincode::deserialize(&v)?;
                    out.push((uid, ts));
                }
            }
        }
        Ok(out)
    }

    /// "Przycisk paniki" — blokuje CAŁKOWICIE wszystkich, łącznie z rootem,
    /// na WSZYSTKICH mountach tego wolumenu (bieżących i przyszłych),
    /// bez potrzeby dostępu do żadnego konkretnego procesu FUSE: flaga
    /// żyje w współdzielonej bazie sled, więc żywy mount wykrywa ją przy
    /// najbliższej operacji (patrz `GhostFS::check_permission`), a nowy
    /// mount odmawia się uruchomić dopóki nie zostanie zdjęta. To odróżnia
    /// to od `freeze()`/dead man's switch, które żyją tylko w pamięci
    /// JEDNEGO procesu — lockdown działa MIĘDZYPROCESOWO, bo `ghostfs
    /// lockdown enable` z osobnego wywołania CLI (bez dostępu do żywego
    /// mountu) i tak skutecznie zatrzymuje już działający wolumin.
    pub fn enable_global_lockdown(&self, reason: &str) -> Result<(), HfsError> {
        self.db.insert(GLOBAL_LOCKDOWN_KEY, reason.as_bytes())?;
        log::error!("GhostFS LOCKDOWN ENABLED (all access denied, including root): {}", reason);
        self.syslog.send(Severity::Emergency, "LOCKDOWN_ENABLED", reason);
        Ok(())
    }

    pub fn disable_global_lockdown(&self) -> Result<(), HfsError> {
        self.db.remove(GLOBAL_LOCKDOWN_KEY)?;
        log::warn!("GhostFS LOCKDOWN DISABLED — access restored");
        self.syslog.send(Severity::Notice, "LOCKDOWN_DISABLED", "manual lockdown lifted");
        Ok(())
    }

    /// `Some(reason)` jeśli lockdown jest aktywny — sprawdzane na SAMYM
    /// początku `check_permission`, przed czymkolwiek innym.
    pub fn is_global_lockdown(&self) -> Result<Option<String>, HfsError> {
        Ok(self.db.get(GLOBAL_LOCKDOWN_KEY)?.map(|v| String::from_utf8_lossy(&v).into_owned()))
    }
}
