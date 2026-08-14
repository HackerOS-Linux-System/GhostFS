use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use dashmap::DashMap;
use sled::Db;
use libc;
use crate::error::HfsError;
use crate::syslog::{SyslogSender, Severity};
use crate::ids::Ids;

/// Okno czasowe do liczenia "tempa" zapisów.
const WINDOW_SECS: u64 = 60;
/// Minimalna liczba ODRĘBNYCH inode dotkniętych w oknie, by w ogóle zacząć
/// rozważać alarm — pojedynczy duży plik o wysokiej entropii to normalność
/// (wideo, archiwum), nie ransomware.
const MIN_DISTINCT_FILES: usize = 15;
/// Minimalny odsetek zapisów w oknie, które muszą mieć wysoką entropię.
const MIN_HIGH_ENTROPY_RATIO: f64 = 0.75;
/// Próg entropii Shannona (bity/bajt, max 8.0) uznawany za "wygląda jak
/// zaszyfrowane/losowe". 7.5 to standardowy próg używany w tego typu
/// heurystykach (np. detekcja spakowanych/zaszyfrowanych sekcji PE).
const HIGH_ENTROPY_THRESHOLD: f64 = 7.5;
/// Minimalny rozmiar zapisu branego pod uwagę — bardzo małe zapisy (kilka
/// bajtów) mają statystycznie niestabilną entropię i generowałyby szum.
const MIN_WRITE_SIZE_FOR_CHECK: usize = 256;

struct UidWindow {
    window_start:        u64,
    touched_inodes:       HashSet<u64>,
    total_writes:         u32,
    high_entropy_writes:  u32,
}

impl UidWindow {
    fn new(now: u64) -> Self {
        Self { window_start: now, touched_inodes: HashSet::new(), total_writes: 0, high_entropy_writes: 0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RansomwareVerdict {
    Clean,
    Suspicious,
    Triggered,
}

#[derive(Clone)]
pub struct RansomwareGuard {
    db:       Db,
    windows:  Arc<DashMap<u32, UidWindow>>,
    whitelist: Arc<DashMap<u32, ()>>,
    syslog:   SyslogSender,
    ids:      Ids,
    enabled:  Arc<AtomicBool>,
}

impl RansomwareGuard {
    pub fn new(db: &Db, ids: &Ids) -> Result<Self, HfsError> {
        let enabled = db.get(b"ransomware:enabled")?
            .map(|v| v.first().copied().unwrap_or(1) != 0)
            .unwrap_or(true); // domyślnie WŁĄCZONE — to cybersecurity fs
        let guard = Self {
            db: db.clone(),
            windows: Arc::new(DashMap::new()),
            whitelist: Arc::new(DashMap::new()),
            syslog: SyslogSender::new(db)?,
            ids: ids.clone(),
            enabled: Arc::new(AtomicBool::new(enabled)),
        };
        for uid in guard.load_whitelist()? {
            guard.whitelist.insert(uid, ());
        }
        Ok(guard)
    }

    pub fn set_enabled(&self, on: bool) -> Result<(), HfsError> {
        self.enabled.store(on, Ordering::SeqCst);
        self.db.insert(b"ransomware:enabled", &[on as u8])?;
        Ok(())
    }

    pub fn is_enabled(&self) -> bool { self.enabled.load(Ordering::SeqCst) }

    fn load_whitelist(&self) -> Result<Vec<u32>, HfsError> {
        match self.db.get(b"ransomware:whitelist")? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(Vec::new()),
        }
    }

    fn save_whitelist(&self) -> Result<(), HfsError> {
        let uids: Vec<u32> = self.whitelist.iter().map(|e| *e.key()).collect();
        self.db.insert(b"ransomware:whitelist", bincode::serialize(&uids)?)?;
        Ok(())
    }

    /// Wyłącz UID z detekcji — dla znanych procesów, które legalnie robią
    /// masowe zapisy wysokiej entropii (backup software, transkodery,
    /// bazy danych z natywną kompresją stron).
    pub fn allow_uid(&self, uid: u32) -> Result<(), HfsError> {
        self.whitelist.insert(uid, ());
        self.save_whitelist()
    }

    pub fn disallow_uid(&self, uid: u32) -> Result<(), HfsError> {
        self.whitelist.remove(&uid);
        self.save_whitelist()
    }

    pub fn is_whitelisted(&self, uid: u32) -> bool {
        uid == 0 || self.whitelist.contains_key(&uid)
    }

    /// Entropia Shannona danych (bity/bajt, zakres 0.0–8.0). Pojedynczy
    /// przebieg po histogramie 256 wartości bajtowych — tanie, O(n).
    fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = [0u32; 256];
        for &b in data { counts[b as usize] += 1; }
        let len = data.len() as f64;
        counts.iter()
            .filter(|&&c| c > 0)
            .map(|&c| { let p = c as f64 / len; -p * p.log2() })
            .sum()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    /// Wołane z `fs/fs.rs::write` PRZED zaszyfrowaniem/zapisem — `data` to
    /// surowy plaintext otrzymany od klienta FUSE (dokładnie to, co
    /// ransomware wysłałoby jako już-zaszyfrowaną zawartość pliku).
    /// Zwraca werdykt; `Triggered` oznacza że wołający (GhostFS::write_data
    /// / fs.rs) powinien już zastać wolumin zamrożony — ten moduł sam
    /// wywołuje freeze przez przekazany `frozen`, wołający tylko reaguje
    /// na zwrócony werdykt (np. do logowania/testów).
    pub fn on_write(&self, uid: u32, ino: u64, data: &[u8], frozen: &Arc<AtomicBool>) -> RansomwareVerdict {
        if !self.is_enabled() || self.is_whitelisted(uid) || data.len() < MIN_WRITE_SIZE_FOR_CHECK {
            return RansomwareVerdict::Clean;
        }

        let entropy      = Self::shannon_entropy(data);
        let high_entropy = entropy >= HIGH_ENTROPY_THRESHOLD;
        let now = Self::now();

        let mut window = self.windows.entry(uid).or_insert_with(|| UidWindow::new(now));
        if now.saturating_sub(window.window_start) > WINDOW_SECS {
            *window = UidWindow::new(now);
        }
        window.touched_inodes.insert(ino);
        window.total_writes += 1;
        if high_entropy { window.high_entropy_writes += 1; }

        let distinct_files = window.touched_inodes.len();
        let ratio = window.high_entropy_writes as f64 / window.total_writes.max(1) as f64;

        if distinct_files >= MIN_DISTINCT_FILES && ratio >= MIN_HIGH_ENTROPY_RATIO {
            drop(window); // zwolnij borrow przed loggingiem/mutacją stanu globalnego
            self.trigger(uid, distinct_files, ratio, frozen);
            return RansomwareVerdict::Triggered;
        }

        if distinct_files >= MIN_DISTINCT_FILES / 2 && ratio >= MIN_HIGH_ENTROPY_RATIO * 0.6 {
            return RansomwareVerdict::Suspicious;
        }
        RansomwareVerdict::Clean
    }

    fn trigger(&self, uid: u32, distinct_files: usize, ratio: f64, frozen: &Arc<AtomicBool>) {
        log::error!(
            "GhostFS RANSOMWARE GUARD: uid={} rewrote {} distinct files with {:.0}% high-entropy \
             content in {}s — FREEZING volume immediately. If this is a false positive (backup/\
             transcode/compression tool), whitelist it with \
             'ghostfs ransomware allow --uid {}' after investigation, then remount.",
            uid, distinct_files, ratio * 100.0, WINDOW_SECS, uid
        );
        self.syslog.send(
            Severity::Emergency, "RANSOMWARE_DETECTED",
            &format!(
                "uid={} touched {} files, {:.0}% high-entropy writes in {}s — volume frozen",
                uid, distinct_files, ratio * 100.0, WINDOW_SECS
            ),
        );
        self.ids.add_alert(
            uid, 0,
            &format!("RANSOMWARE BEHAVIOR: {} files rewritten, {:.0}% high-entropy in {}s",
                distinct_files, ratio * 100.0, WINDOW_SECS),
            libc::W_OK,
        ).ok();
        frozen.store(true, Ordering::SeqCst);
    }
}
