use sled::Db;
use serde::{Serialize, Deserialize};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use blake3::Hasher;
use crate::error::HfsError;
use crate::crypto::Key;

const MAX_AUDIT_ENTRIES: u64 = 100_000;
const MAX_AUDIT_BLOCK:   u64 = 100;
const AUDIT_HMAC_CONTEXT: &[u8] = b"ghostfs-audit-hmac-v1";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEntry {
    pub seq:         u64,
    pub timestamp:   u64,
    pub uid:         u32,
    pub operation:   String,
    pub ino:         u64,
    pub name:        Option<Vec<u8>>,
    pub event_count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditBlockSig {
    pub block_num: u64,
    pub start_seq: u64,
    pub end_seq:   u64,
    pub hmac:      [u8; 32],
}

pub struct Audit {
    db:          Db,
    signing_key: Option<Key>,
}

impl Audit {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone(), signing_key: None })
    }

    pub fn set_signing_key(&mut self, master_key: &Key) {
        let mut h = Hasher::new_keyed(master_key);
        h.update(AUDIT_HMAC_CONTEXT);
        self.signing_key = Some(*h.finalize().as_bytes());
    }

    fn load_seq(&self) -> Result<u64, HfsError> {
        Ok(match self.db.get(b"audit:seq")? {
            Some(v) => bincode::deserialize(&v)?,
            None    => 0,
        })
    }

    fn load_event_count(&self) -> Result<u64, HfsError> {
        Ok(match self.db.get(b"audit:event_count")? {
            Some(v) => bincode::deserialize(&v)?,
            None    => 0,
        })
    }

    fn compute_block_hmac(&self, start: u64, end: u64, sk: &Key) -> Result<[u8; 32], HfsError> {
        let mut h = Hasher::new_keyed(sk);
        for seq in start..end {
            let key = format!("audit:entry:{:016}", seq);
            if let Some(raw) = self.db.get(key.as_bytes())? { h.update(&raw); }
        }
        Ok(*h.finalize().as_bytes())
    }

    fn sign_block(&self, block_num: u64, start: u64, end: u64) -> Result<(), HfsError> {
        let sk = match &self.signing_key { Some(k) => *k, None => return Ok(()) };
        let hmac = self.compute_block_hmac(start, end, &sk)?;
        let sig  = AuditBlockSig { block_num, start_seq: start, end_seq: end, hmac };
        let key  = format!("audit:sig:{:016}", block_num);
        self.db.insert(key.as_bytes(), bincode::serialize(&sig)?)?;
        Ok(())
    }

    /// Sprawdź czy blok zawierający `seq` jest już podpisany.
    fn block_is_signed(&self, seq: u64) -> bool {
        let block_num = seq / MAX_AUDIT_BLOCK;
        let sig_key   = format!("audit:sig:{:016}", block_num);
        self.db.get(sig_key.as_bytes()).unwrap_or(None).is_some()
    }

    pub fn log(&self, uid: u32, operation: &str, ino: u64, name: Option<&OsStr>) -> Result<(), HfsError> {
        let seq         = self.load_seq()?;
        let event_count = self.load_event_count()?;
        let timestamp   = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| HfsError::TimeError)?.as_secs();

        let entry = AuditEntry {
            seq, timestamp, uid,
            operation:   operation.to_string(),
            ino,
            name:        name.map(|n| n.as_bytes().to_vec()),
            event_count: event_count + 1,
        };
        let key = format!("audit:entry:{:016}", seq);
        self.db.insert(key.as_bytes(), bincode::serialize(&entry)?)?;
        self.db.insert(b"audit:seq",         bincode::serialize(&(seq + 1))?)?;
        self.db.insert(b"audit:event_count", bincode::serialize(&(event_count + 1))?)?;

        // Podpisz blok na granicy.
        if (seq + 1) % MAX_AUDIT_BLOCK == 0 {
            let block_num = seq / MAX_AUDIT_BLOCK;
            self.sign_block(block_num, block_num * MAX_AUDIT_BLOCK, (block_num + 1) * MAX_AUDIT_BLOCK)?;
        }

        // Przytnij TYLKO wpisy których blok jest już podpisany.
        // Nigdy nie usuwamy wpisów z niepodpisanego bloku.
        if seq > MAX_AUDIT_ENTRIES {
            let candidate = seq - MAX_AUDIT_ENTRIES;
            if self.block_is_signed(candidate) {
                let prune_key = format!("audit:entry:{:016}", candidate);
                self.db.remove(prune_key.as_bytes())?;
            }
        }
        Ok(())
    }

    pub fn tail(&self, n: usize) -> Result<Vec<AuditEntry>, HfsError> {
        let seq   = self.load_seq()?;
        let start = seq.saturating_sub(n as u64);
        let mut out = Vec::new();
        for s in start..seq {
            let key = format!("audit:entry:{:016}", s);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                if let Ok(e) = bincode::deserialize::<AuditEntry>(&raw) { out.push(e); }
            }
        }
        Ok(out)
    }

    pub fn verify_signatures(&self) -> Result<usize, HfsError> {
        let sk = match &self.signing_key {
            Some(k) => *k,
            None    => return Err(HfsError::MissingKey),
        };
        let mut verified = 0;
        for item in self.db.scan_prefix(b"audit:sig:") {
            let (_, v) = item?;
            let sig: AuditBlockSig = bincode::deserialize(&v)?;
            let computed = self.compute_block_hmac(sig.start_seq, sig.end_seq, &sk)?;
            if computed != sig.hmac { return Err(HfsError::CorruptedData); }
            verified += 1;
        }
        Ok(verified)
    }
}
