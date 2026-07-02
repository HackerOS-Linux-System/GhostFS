use sled::Db;
use serde::{Serialize, Deserialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::error::HfsError;
use crate::ids::Ids;

const CANARY_KEY_DB:       &[u8] = b"canary:hmac_key";
const CANARY_ENDPOINT_DB:  &[u8] = b"canary:endpoint";
const CANARY_INTERVAL_DB:  &[u8] = b"canary:interval_secs";
const DEFAULT_INTERVAL:    u64   = 300; // 5 minut
const BEACON_TIMEOUT_SECS: u64  = 10;

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
    /// Sekwencja beaconu — inkrementowana przy każdym wysłaniu.
    seq_key: String,
}

impl Canary {
    pub fn new(db: &Db, _ids: &Ids) -> Result<Self, HfsError> {
        Ok(Self {
            db:      db.clone(),
            seq_key: "canary:seq".to_string(),
        })
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
