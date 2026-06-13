use sled::Db;
use serde::{Serialize, Deserialize};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use crate::error::HfsError;

const HEAD_KEY: &[u8] = b"forensics:head";
const PREV_HASH_KEY: &[u8] = b"forensics:prev_hash";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ForensicsEntry {
    pub seq: u64,
    /// Microseconds since UNIX epoch
    pub timestamp_us: u128,
    pub uid: u32,
    pub operation: String,
    pub ino: u64,
    pub name: Option<Vec<u8>>,
    /// BLAKE3 hash of the *previous* ForensicsEntry (serialised), all-zero for seq 0
    pub prev_hash: [u8; 32],
    /// BLAKE3 hash of this entry's fields (excluding self_hash), computed and stored here
    pub self_hash: [u8; 32],
}

#[derive(Clone)]
pub struct Forensics {
    db: Db,
}

impl Forensics {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn timestamp_us() -> u128 {
        std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
    }

    fn load_head(&self) -> Result<u64, HfsError> {
        Ok(match self.db.get(HEAD_KEY)? {
            Some(v) => bincode::deserialize(&v)?,
           None => 0,
        })
    }

    fn load_prev_hash(&self) -> Result<[u8; 32], HfsError> {
        Ok(match self.db.get(PREV_HASH_KEY)? {
            Some(v) if v.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                arr
            }
            _ => [0u8; 32],
        })
    }

    fn compute_hash(entry: &ForensicsEntry) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&entry.seq.to_le_bytes());
        hasher.update(&entry.timestamp_us.to_le_bytes());
        hasher.update(&entry.uid.to_le_bytes());
        hasher.update(entry.operation.as_bytes());
        hasher.update(&entry.ino.to_le_bytes());
        if let Some(n) = &entry.name {
            hasher.update(n);
        }
        hasher.update(&entry.prev_hash);
        *hasher.finalize().as_bytes()
    }

    /// Append a new entry to the forensics log.
    pub fn record(
        &self,
        uid: u32,
        operation: &str,
        ino: u64,
        name: Option<&OsStr>,
    ) -> Result<(), HfsError> {
        let seq = self.load_head()?;
        let prev_hash = self.load_prev_hash()?;

        let mut entry = ForensicsEntry {
            seq,
            timestamp_us: Self::timestamp_us(),
            uid,
            operation: operation.to_string(),
            ino,
            name: name.map(|n| n.as_bytes().to_vec()),
            prev_hash,
            self_hash: [0u8; 32],
        };
        entry.self_hash = Self::compute_hash(&entry);

        let key = format!("forensics:seq:{}", seq);
        self.db
        .insert(key.as_bytes(), bincode::serialize(&entry)?)?;
        self.db
        .insert(HEAD_KEY, bincode::serialize(&(seq + 1))?)?;
        self.db.insert(PREV_HASH_KEY, entry.self_hash.to_vec())?;
        Ok(())
    }

    /// Verify the entire hash chain.  Returns the number of entries verified,
    /// or an error at the first broken link.
    pub fn verify_chain(&self) -> Result<u64, HfsError> {
        let head = self.load_head()?;
        let mut expected_prev = [0u8; 32];
        for seq in 0..head {
            let key = format!("forensics:seq:{}", seq);
            let raw = self.db.get(key.as_bytes())?.ok_or(HfsError::CorruptedData)?;
            let entry: ForensicsEntry = bincode::deserialize(&raw)?;
            if entry.prev_hash != expected_prev {
                return Err(HfsError::CorruptedData);
            }
            let computed = Self::compute_hash(&entry);
            if computed != entry.self_hash {
                return Err(HfsError::CorruptedData);
            }
            expected_prev = entry.self_hash;
        }
        Ok(head)
    }

    /// Export the N most recent entries for SIEM ingestion / court-admissible export.
    pub fn tail(&self, n: usize) -> Result<Vec<ForensicsEntry>, HfsError> {
        let head = self.load_head()?;
        let start = head.saturating_sub(n as u64);
        let mut out = Vec::new();
        for seq in start..head {
            let key = format!("forensics:seq:{}", seq);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                if let Ok(e) = bincode::deserialize::<ForensicsEntry>(&raw) {
                    out.push(e);
                }
            }
        }
        Ok(out)
    }
}
