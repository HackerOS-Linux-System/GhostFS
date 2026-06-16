use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;
use crate::ids::{Ids, AlertKind};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CanaryConfig {
    /// URL do którego wysyłany jest beacon (HTTP GET), None = tylko log lokalny
    pub beacon_url: Option<String>,
    /// Opis pliku (niewidoczny dla atakującego)
    pub description: String,
}

pub struct Canary {
    db:  Db,
    ids: Ids,
}

impl Canary {
    pub fn new(db: &Db, ids: &Ids) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone(), ids: ids.clone() })
    }

    /// Oznacz inode jako canary file.
    pub fn mark(&self, ino: u64, config: CanaryConfig) -> Result<(), HfsError> {
        let key = format!("canary:{}", ino);
        self.db.insert(key.as_bytes(), bincode::serialize(&config)?)?;
        log::info!("GhostFS canary: ino={} marked ({})", ino, config.description);
        Ok(())
    }

    /// Usuń oznaczenie canary.
    pub fn unmark(&self, ino: u64) -> Result<(), HfsError> {
        let key = format!("canary:{}", ino);
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    /// Sprawdź czy inode jest canary — wywołać przy każdym open()/read().
    /// Jeśli tak: emituj alert i opcjonalnie wyślij beacon.
    pub fn check_and_trigger(&self, ino: u64, uid: u32) -> Result<(), HfsError> {
        let key = format!("canary:{}", ino);
        if let Some(raw) = self.db.get(key.as_bytes())? {
            let config: CanaryConfig = bincode::deserialize(&raw)?;
            let detail = format!(
                "CANARY TRIGGERED: ino={} uid={} desc='{}'",
                ino, uid, config.description
            );
            log::error!("[GhostFS CANARY] {}", detail);

            self.ids.emit_alert(uid, AlertKind::CanaryTriggered { ino }, &detail)?;

            // Beacon — fire and forget w osobnym wątku
            if let Some(url) = config.beacon_url {
                let beacon_detail = detail.clone();
                std::thread::spawn(move || {
                    if let Err(e) = Self::send_beacon(&url, &beacon_detail) {
                        log::warn!("Canary beacon failed: {}", e);
                    }
                });
            }
        }
        Ok(())
    }

    /// Wyślij beacon HTTP GET (bez zewnętrznych crate — używa std TcpStream).
    fn send_beacon(url: &str, detail: &str) -> Result<(), String> {
        use std::io::Write;
        use std::net::TcpStream;

        // Parsuj URL ręcznie (bez reqwest aby uniknąć zależności)
        let url = url.trim_start_matches("http://");
        let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
        let path = format!("/{}?detail={}", path, urlencodeish(detail));
        let host = host_port.split(':').next().unwrap_or(host_port);
        let port: u16 = host_port.split(':').nth(1)
            .and_then(|p| p.parse().ok()).unwrap_or(80);

        let mut stream = TcpStream::connect((host, port))
            .map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let req = format!("GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: ghostfs-canary/0.3\r\n\r\n", path, host);
        stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Lista wszystkich canary ino w wolumenie.
    pub fn list_canaries(&self) -> Result<Vec<(u64, CanaryConfig)>, HfsError> {
        let mut out = Vec::new();
        for item in self.db.scan_prefix(b"canary:") {
            let (k, v) = item?;
            let k_str  = String::from_utf8(k.to_vec())?;
            if let Some(ino_str) = k_str.strip_prefix("canary:") {
                if let Ok(ino) = ino_str.parse::<u64>() {
                    if let Ok(cfg) = bincode::deserialize::<CanaryConfig>(&v) {
                        out.push((ino, cfg));
                    }
                }
            }
        }
        Ok(out)
    }
}

fn urlencodeish(s: &str) -> String {
    s.chars().map(|c| match c {
        'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
        ' ' => "+".to_string(),
        c   => format!("%{:02X}", c as u32),
    }).collect()
}
