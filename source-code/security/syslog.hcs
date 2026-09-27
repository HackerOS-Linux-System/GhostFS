use sled::Db;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::HfsError;

const SYSLOG_ENDPOINT_DB: &[u8] = b"syslog:endpoint";
const SYSLOG_FACILITY_DB: &[u8] = b"syslog:facility";
const SYSLOG_STREAM_AUDIT_DB: &[u8] = b"syslog:stream_audit";
/// Facility domyślna: local0 (16) — konwencjonalny wybór dla aplikacji
/// niebędących częścią standardowego stosu systemowego (auth, cron, itd.).
const DEFAULT_FACILITY: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Emergency = 0,
    Alert     = 1,
    Critical  = 2,
    Error     = 3,
    Warning   = 4,
    Notice    = 5,
    Info      = 6,
    Debug     = 7,
}

#[derive(Clone)]
pub struct SyslogSender {
    db: Db,
}

impl SyslogSender {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    /// Skonfiguruj endpoint SIEM (`host:port`, zwykle port 514) i opcjonalnie
    /// facility (0-23, domyślnie 16=local0). Wołane przez `ghostfs siem configure`.
    pub fn configure(&self, endpoint: &str, facility: Option<u8>) -> Result<(), HfsError> {
        self.db.insert(SYSLOG_ENDPOINT_DB, endpoint.as_bytes())?;
        if let Some(f) = facility {
            if f > 23 {
                return Err(HfsError::InvalidArgument("Syslog facility must be 0-23".into()));
            }
            self.db.insert(SYSLOG_FACILITY_DB, &[f])?;
        }
        log::info!("GhostFS SIEM: syslog endpoint configured -> {}", endpoint);
        Ok(())
    }

    pub fn disable(&self) -> Result<(), HfsError> {
        self.db.remove(SYSLOG_ENDPOINT_DB)?;
        Ok(())
    }

    /// Włącz/wyłącz strumieniowanie KAŻDEGO wpisu audytu (nie tylko
    /// alertów bezpieczeństwa) na żywo do SIEM. Motywacja: lokalny log
    /// audytu (`audit:*`/`forensics:*` w sled DB) jest hash-chained i
    /// HMAC-owany, więc wykrywa manipulację — ale atakujący z dostępem
    /// roota do samego pliku wolumenu może w skrajnym przypadku USUNĄĆ
    /// cały wolumin razem z logiem. Wpis wysłany na żywo do zewnętrznego
    /// SIEM w momencie zdarzenia przetrwa nawet to — mamy niezależną,
    /// zdalną kopię chronologii operacji.
    ///
    /// Świadomy kompromis wydajnościowy: obecna implementacja `send()`
    /// odpala osobny wątek OS per wiadomość (proste, wystarczające dla
    /// rzadkich alertów). Przy WŁĄCZONYM pełnym streamingu audytu na
    /// bardzo obciążonym wolumenie (dużo mutacji/sekundę) to może być
    /// zauważalne. Dla takich obciążeń zalecane jest kierowanie
    /// `endpoint` na lokalny relay (rsyslog/syslog-ng) zamiast wprost do
    /// zdalnego SIEM — patrz komentarz modułu.
    pub fn set_stream_audit(&self, on: bool) -> Result<(), HfsError> {
        self.db.insert(SYSLOG_STREAM_AUDIT_DB, &[on as u8])?;
        Ok(())
    }

    pub fn stream_audit_enabled(&self) -> bool {
        self.db.get(SYSLOG_STREAM_AUDIT_DB).ok().flatten()
            .and_then(|v| v.first().copied())
            .map(|b| b != 0)
            .unwrap_or(false)
    }

    fn endpoint(&self) -> Option<String> {
        self.db.get(SYSLOG_ENDPOINT_DB).ok().flatten()
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
    }

    fn facility(&self) -> u8 {
        self.db.get(SYSLOG_FACILITY_DB).ok().flatten()
            .and_then(|v| v.first().copied())
            .unwrap_or(DEFAULT_FACILITY)
    }

    /// Wyślij zdarzenie bezpieczeństwa do skonfigurowanego SIEM. No-op
    /// (natychmiastowy powrót) jeśli endpoint nie jest skonfigurowany —
    /// więc bezpiecznie wołać to bezwarunkowo z gorących ścieżek (IDS,
    /// AutoResponse, Canary) bez sprawdzania "czy w ogóle skonfigurowane"
    /// za każdym razem w miejscu wywołania.
    ///
    /// `msg_id` — RFC 5424 MSGID, krótki identyfikator typu zdarzenia
    /// (np. "CANARY_TRIGGER", "IDS_LOCKOUT", "CHAIN_VIOLATION") — pozwala
    /// SIEM-owi filtrować/routować bez parsowania treści wiadomości.
    pub fn send(&self, severity: Severity, msg_id: &str, message: &str) {
        let endpoint = match self.endpoint() {
            Some(e) => e,
            None    => return, // SIEM nieskonfigurowany — cicho pomiń
        };
        let facility = self.facility();
        let packet = Self::format_rfc5424(facility, severity, msg_id, message);

        // Wysyłka na osobnym wątku — UDP send() rzadko blokuje, ale
        // rozwiązanie nazwy hosta (jeśli `endpoint` to hostname, nie IP)
        // MOŻE, a żadna operacja FUSE nie powinna czekać na DNS.
        std::thread::spawn(move || {
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    if let Err(e) = socket.send_to(packet.as_bytes(), &endpoint) {
                        log::debug!("GhostFS SIEM: syslog send to {} failed: {}", endpoint, e);
                    }
                }
                Err(e) => log::debug!("GhostFS SIEM: could not bind UDP socket for syslog: {}", e),
            }
        });
    }

    fn format_rfc5424(facility: u8, severity: Severity, msg_id: &str, message: &str) -> String {
        // PRI = facility*8 + severity
        let pri = (facility as u32) * 8 + (severity as u32);
        let timestamp = Self::rfc3339_now();
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "ghostfs-host".to_string());
        // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        format!(
            "<{}>1 {} {} ghostfs {} {} - {}",
            pri, timestamp, hostname, std::process::id(), msg_id, message
        )
    }

    /// Minimalny RFC3339 UTC timestamp bez zależności od `chrono` —
    /// wystarczający dla RFC 5424 (dopuszcza dowolną precyzję ułamkową,
    /// tu pomijamy ją całkowicie, co jest zgodne ze specyfikacją).
    fn rfc3339_now() -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = now.as_secs();
        let (days, rem) = (secs / 86400, secs % 86400);
        let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
        let (y, m, d) = Self::civil_from_days(days as i64);
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
    }

    /// Howard Hinnant's civil_from_days algorithm — konwersja dni od
    /// epoki Unix na (rok, miesiąc, dzień), bez zależności zewnętrznych.
    fn civil_from_days(z: i64) -> (i64, u32, u32) {
        let z = z + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = (z - era * 146097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        (if m <= 2 { y + 1 } else { y }, m, d)
    }
}
