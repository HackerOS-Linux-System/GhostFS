use sled::Db;
use serde::{Serialize, Deserialize};
use std::time::Duration;
#[cfg(feature = "canary-https")]
use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::HfsError;
use crate::ids::Ids;
use crate::syslog::{SyslogSender, Severity};

const CANARY_KEY_DB:       &[u8] = b"canary:hmac_key";
const CANARY_ENDPOINT_DB:  &[u8] = b"canary:endpoint";
const CANARY_INTERVAL_DB:  &[u8] = b"canary:interval_secs";
const DEFAULT_INTERVAL:    u64   = 300; // 5 minut
const BEACON_TIMEOUT_SECS: u64  = 10;
const MARKER_PREFIX:       &str = "canary:marker:";

/// Konfiguracja pojedynczego pliku-pułapki (honeytoken) — patrz
/// `Canary::mark`. Osobne pojęcie od "beacon" (heartbeat całego wolumenu,
/// reszta tego pliku) — tu chodzi o KONKRETNE pliki-przynęty
/// ("passwords.txt", "id_rsa", "backup_2023.sql"...), które żaden
/// legalny proces nie powinien dotknąć. Dotknięcie = natychmiastowy,
/// jednoznaczny sygnał intruzji, bez czekania na wzorce/heurystyki IDS.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CanaryConfig {
    pub description: String,
    /// Opcjonalny URL beaconu SPECYFICZNY dla tego pliku — jeśli ustawiony,
    /// dotknięcie tego konkretnego honeytoken wysyła natychmiastowy alert
    /// HTTP (niezależnie od okresowego heartbeatu wolumenu poniżej).
    pub beacon_url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BeaconPayload {
    pub hostname:     String,
    pub timestamp_us: u128,
    pub seq:          u64,
    pub volume_id:    String,
    /// HMAC-BLAKE3 nad (timestamp_us || seq || volume_id), klucz z DB.
    pub hmac:         String,
}

#[derive(Clone)]
pub struct Canary {
    db:     Db,
    ids:    Ids,
    syslog: SyslogSender,
    /// Sekwencja beaconu — inkrementowana przy każdym wysłaniu.
    seq_key: String,
}

impl Canary {
    pub fn new(db: &Db, ids: &Ids) -> Result<Self, HfsError> {
        Ok(Self {
            db:      db.clone(),
            ids:     ids.clone(),
            syslog:  SyslogSender::new(db)?,
            seq_key: "canary:seq".to_string(),
        })
    }

    fn marker_key(ino: u64) -> String {
        format!("{}{}", MARKER_PREFIX, ino)
    }

    /// Oznacz inode jako plik-pułapkę (honeytoken). Nie zmienia zawartości
    /// pliku — działa czysto na metadanych, więc plik może (i zwykle
    /// powinien) wyglądać jak coś atrakcyjnego dla atakującego.
    pub fn mark(&self, ino: u64, config: CanaryConfig) -> Result<(), HfsError> {
        self.db.insert(Self::marker_key(ino).as_bytes(), bincode::serialize(&config)?)?;
        log::info!("GhostFS canary: ino={} marked as honeytoken ('{}')", ino, config.description);
        Ok(())
    }

    pub fn unmark(&self, ino: u64) -> Result<(), HfsError> {
        self.db.remove(Self::marker_key(ino).as_bytes())?;
        Ok(())
    }

    pub fn list_canaries(&self) -> Result<Vec<(u64, CanaryConfig)>, HfsError> {
        let mut out = Vec::new();
        for item in self.db.scan_prefix(MARKER_PREFIX.as_bytes()) {
            let (k, v) = item?;
            let ks = String::from_utf8_lossy(&k);
            if let Some(ino_str) = ks.strip_prefix(MARKER_PREFIX) {
                if let Ok(ino) = ino_str.parse::<u64>() {
                    let cfg: CanaryConfig = bincode::deserialize(&v)?;
                    out.push((ino, cfg));
                }
            }
        }
        Ok(out)
    }

    /// Szybkie sprawdzenie na gorącej ścieżce FUSE (`read`/`open`/`getattr`)
    /// — czy TEN inode jest honeytoken. Tanie: pojedynczy point lookup.
    pub fn is_canary(&self, ino: u64) -> Result<bool, HfsError> {
        Ok(self.db.get(Self::marker_key(ino).as_bytes())?.is_some())
    }

    /// Wyzwól alarm — wołane przez `fs.rs` gdy ktoś dotknie oznaczonego
    /// inode. Zawsze: głośny log + krytyczny alert IDS (widoczny w
    /// `ghostfs ids list` i podlegający tej samej eskalacji auto-response
    /// co inne alerty — patrz `security/response.rs`, próg lockoutu wynosi
    /// tu efektywnie 1 dotknięcie zamiast kilku, bo honeytoken nie ma
    /// żadnego legalnego uzasadnienia dostępu). Dodatkowo: jeśli honeytoken
    /// ma własny `beacon_url`, próbuje natychmiastowego beaconu HTTP
    /// (best-effort, nigdy nie blokuje ani nie failuje operacji na pliku).
    pub fn trigger(&self, ino: u64, uid: u32, access_mask: i32) -> Result<bool, HfsError> {
        let config = match self.db.get(Self::marker_key(ino).as_bytes())? {
            Some(v) => bincode::deserialize::<CanaryConfig>(&v)?,
            None    => return Ok(false), // nie honeytoken — nic do zrobienia
        };
        log::error!(
            "GhostFS CANARY TRIGGERED: uid={} touched honeytoken ino={} ('{}') — \
             this file has NO legitimate access pattern; treat as active intrusion.",
            uid, ino, config.description
        );
        self.ids.add_alert(
            uid, ino,
            &format!("CANARY TRIGGERED: honeytoken '{}' accessed", config.description),
            access_mask,
        )?;
        self.syslog.send(
            Severity::Critical, "CANARY_TRIGGER",
            &format!("honeytoken '{}' (ino={}) accessed by uid={}", config.description, ino, uid),
        );
        if let Some(url) = &config.beacon_url {
            self.fire_immediate_beacon(url, ino, uid);
        }
        Ok(true)
    }

    /// Best-effort, non-blocking natychmiastowy beacon dla POJEDYNCZEGO
    /// honeytoken (odrębny od okresowego `send_beacon` całego wolumenu
    /// poniżej). Bez feature `canary-https` tylko loguje — patrz komentarz
    /// przy `send_beacon`.
    fn fire_immediate_beacon(&self, url: &str, ino: u64, uid: u32) {
        #[cfg(feature = "canary-https")]
        {
            let url = url.to_string();
            std::thread::spawn(move || {
                let body = format!(r#"{{"event":"canary_triggered","ino":{},"uid":{}}}"#, ino, uid);
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(BEACON_TIMEOUT_SECS))
                    .build();
                if let Ok(client) = client {
                    if let Err(e) = client.post(&url).body(body).send() {
                        log::warn!("GhostFS canary: immediate beacon to {} failed: {}", url, e);
                    }
                }
            });
        }
        #[cfg(not(feature = "canary-https"))]
        {
            log::warn!(
                "GhostFS canary: honeytoken ino={} uid={} has beacon_url={} configured, but this \
                 binary was built without the 'canary-https' feature — beacon NOT sent, alert was \
                 still logged and recorded in IDS.",
                ino, uid, url
            );
        }
    }

    /// Skonfiguruj canary przy mkfs/mount.
    /// `hmac_key` — 32-bajtowy klucz HMAC (hex), `endpoint` — HTTPS URL,
    /// `interval_secs` — interwał beaconu.
    pub fn configure(
        &self,
        hmac_key_hex: &str,
        endpoint:     &str,
        interval_secs: u64,
    ) -> Result<(), HfsError> {
        if !endpoint.starts_with("https://") {
            return Err(HfsError::InvalidArgument(
                "Canary endpoint must use HTTPS (e.g. https://siem.example.com/canary)".into()
            ));
        }
        let key_bytes = hex::decode(hmac_key_hex)
            .map_err(|_| HfsError::InvalidArgument("Invalid canary HMAC key (must be hex)".into()))?;
        if key_bytes.len() != 32 {
            return Err(HfsError::InvalidArgument("Canary HMAC key must be 32 bytes (64 hex chars)".into()));
        }
        self.db.insert(CANARY_KEY_DB,      key_bytes)?;
        self.db.insert(CANARY_ENDPOINT_DB, endpoint.as_bytes())?;
        self.db.insert(CANARY_INTERVAL_DB, bincode::serialize(&interval_secs)?)?;
        log::info!("GhostFS canary: configured endpoint={} interval={}s", endpoint, interval_secs);
        Ok(())
    }

    fn load_hmac_key(&self) -> Result<Option<[u8; 32]>, HfsError> {
        match self.db.get(CANARY_KEY_DB)? {
            Some(v) if v.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Ok(Some(arr))
            }
            _ => Ok(None),
        }
    }

    fn load_endpoint(&self) -> Result<Option<String>, HfsError> {
        match self.db.get(CANARY_ENDPOINT_DB)? {
            Some(v) => Ok(Some(String::from_utf8(v.to_vec()).map_err(HfsError::Utf8)?)),
            None    => Ok(None),
        }
    }

    fn load_interval(&self) -> Result<u64, HfsError> {
        match self.db.get(CANARY_INTERVAL_DB)? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(DEFAULT_INTERVAL),
        }
    }

    fn next_seq(&self) -> Result<u64, HfsError> {
        let seq: u64 = match self.db.get(self.seq_key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
            None    => 0,
        };
        self.db.insert(self.seq_key.as_bytes(), bincode::serialize(&(seq + 1))?)?;
        Ok(seq)
    }

    fn compute_hmac(key: &[u8; 32], timestamp_us: u128, seq: u64, volume_id: &str) -> String {
        let mut h = blake3::Hasher::new_keyed(key);
        h.update(&timestamp_us.to_le_bytes());
        h.update(&seq.to_le_bytes());
        h.update(volume_id.as_bytes());
        hex::encode(h.finalize().as_bytes())
    }

    /// Wyślij pojedynczy beacon HTTPS z HMAC.
    /// Wymaga feature `reqwest` z TLS. Blokuje wątek przez maksymalnie BEACON_TIMEOUT_SECS.
    #[cfg(feature = "canary-https")]
    pub fn send_beacon(&self) -> Result<(), HfsError> {
        let hmac_key = match self.load_hmac_key()? {
            Some(k) => k,
            None    => {
                log::debug!("GhostFS canary: not configured, skipping beacon");
                return Ok(());
            }
        };
        let endpoint = match self.load_endpoint()? {
            Some(e) => e,
            None    => return Ok(()),
        };

        let timestamp_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros();
        let seq       = self.next_seq()?;
        let hostname  = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let volume_id = hex::encode(&hmac_key[..8]); // pierwsze 8 bajtów klucza jako vol-id

        let hmac = Self::compute_hmac(&hmac_key, timestamp_us, seq, &volume_id);

        let payload = BeaconPayload {
            hostname, timestamp_us, seq, volume_id, hmac,
        };

        let json = serde_json::to_string(&payload)
            .map_err(|e| HfsError::InvalidArgument(format!("Beacon JSON error: {}", e)))?;

        // reqwest blocking z TLS (native-tls lub rustls według Cargo.toml).
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(BEACON_TIMEOUT_SECS))
            .https_only(true)           // wymuś HTTPS — odrzuć przekierowania na HTTP
            .build()
            .map_err(|e| HfsError::InvalidArgument(format!("HTTP client error: {}", e)))?;

        let resp = client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("X-GhostFS-Version", env!("CARGO_PKG_VERSION"))
            .body(json)
            .send()
            .map_err(|e| {
                log::warn!("GhostFS canary beacon failed: {}", e);
                HfsError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string()))
            })?;

        if resp.status().is_success() {
            log::debug!("GhostFS canary: beacon sent (seq={} status={})", seq, resp.status());
        } else {
            log::warn!("GhostFS canary: beacon rejected by server (status={})", resp.status());
        }
        Ok(())
    }

    /// Wersja bez featu https — loguje ostrzeżenie i działa jako no-op.
    #[cfg(not(feature = "canary-https"))]
    pub fn send_beacon(&self) -> Result<(), HfsError> {
        log::warn!(
            "GhostFS canary: compiled without 'canary-https' feature — \
             beacon not sent. Add reqwest to dependencies and enable the feature."
        );
        Ok(())
    }

    /// Uruchom wątek tła wysyłający beacony co `interval_secs`.
    pub fn start_background_beacon(&self) {
        let canary = self.clone();
        std::thread::Builder::new()
            .name("ghostfs-canary".into())
            .spawn(move || {
                let interval = canary.load_interval().unwrap_or(DEFAULT_INTERVAL);
                log::info!("GhostFS canary: background beacon thread started (interval={}s)", interval);
                loop {
                    std::thread::sleep(Duration::from_secs(interval));
                    if let Err(e) = canary.send_beacon() {
                        log::error!("GhostFS canary: beacon error: {}", e);
                    }
                }
            })
            .ok();
    }
}
