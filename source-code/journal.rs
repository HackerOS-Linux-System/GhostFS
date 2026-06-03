use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

const JOURNAL_PREFIX: &str = "journal:seq:";
const JOURNAL_HEAD: &[u8] = b"journal:head";
const JOURNAL_COMMITTED: &[u8] = b"journal:committed";
/// Flush the sled tree to disk on every commit barrier.
/// In a production build this maps to fdatasync(2).
const SYNC_ON_BARRIER: bool = true;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum JournalOp {
    WriteBlock {
        ino: u64,
        block_idx: usize,
        /// Previous content of the block (None if block was absent)
        before: Option<Vec<u8>>,
    },
    DeleteBlock {
        ino: u64,
        block_idx: usize,
        before: Option<Vec<u8>>,
    },
    MetaUpdate {
        key: String,
        before: Option<Vec<u8>>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JournalRecord {
    pub seq: u64,
    pub op: JournalOp,
    pub committed: bool,
}

#[derive(Clone)]
pub struct Journal {
    db: Db,
}

impl Journal {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn next_seq(&self) -> Result<u64, HfsError> {
        let seq: u64 = match self.db.get(JOURNAL_HEAD)? {
            Some(v) => bincode::deserialize(&v)?,
            None => 0,
        };
        self.db.insert(JOURNAL_HEAD, bincode::serialize(&(seq + 1))?)?;
        Ok(seq)
    }

    fn last_committed(&self) -> Result<u64, HfsError> {
        Ok(match self.db.get(JOURNAL_COMMITTED)? {
            Some(v) => bincode::deserialize(&v)?,
           None => 0,
        })
    }

    /// Append a write-block record to the journal.
    pub fn log_write(
        &self,
        ino: u64,
        block_idx: usize,
        before: &Option<Vec<u8>>,
    ) -> Result<(), HfsError> {
        let seq = self.next_seq()?;
        let record = JournalRecord {
            seq,
            op: JournalOp::WriteBlock {
                ino,
                block_idx,
                before: before.clone(),
            },
            committed: false,
        };
        let key = format!("{}{}", JOURNAL_PREFIX, seq);
        self.db
        .insert(key.as_bytes(), bincode::serialize(&record)?)?;
        Ok(())
    }

    /// Commit barrier — mark all pending records as committed and optionally sync.
    pub fn commit_barrier(&self) -> Result<(), HfsError> {
        let head: u64 = match self.db.get(JOURNAL_HEAD)? {
            Some(v) => bincode::deserialize(&v)?,
            None => 0,
        };
        // Mark every pending record as committed
        let committed = self.last_committed()?;
        for seq in committed..head {
            let key = format!("{}{}", JOURNAL_PREFIX, seq);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                let mut record: JournalRecord = bincode::deserialize(&raw)?;
                record.committed = true;
                self.db
                .insert(key.as_bytes(), bincode::serialize(&record)?)?;
            }
        }
        self.db.insert(JOURNAL_COMMITTED, bincode::serialize(&head)?)?;
        if SYNC_ON_BARRIER {
            self.db.flush()?;
        }
        // Prune committed records older than 256 entries to keep journal compact
        if head > 256 {
            let prune_before = head - 256;
            for seq in 0..prune_before {
                let key = format!("{}{}", JOURNAL_PREFIX, seq);
                self.db.remove(key.as_bytes())?;
            }
        }
        Ok(())
    }

    /// Replay uncommitted records on startup for crash recovery.
    pub fn recover(&self, _db: &Db) -> Result<(), HfsError> {
        let committed = self.last_committed()?;
        let head: u64 = match self.db.get(JOURNAL_HEAD)? {
            Some(v) => bincode::deserialize(&v)?,
            None => 0,
        };
        if head == committed {
            return Ok(()); // clean journal
        }
        log::warn!(
            "GhostFS journal recovery: replaying {} uncommitted records",
            head - committed
        );
        for seq in committed..head {
            let key = format!("{}{}", JOURNAL_PREFIX, seq);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                let record: JournalRecord = bincode::deserialize(&raw)?;
                if !record.committed {
                    // Undo: restore the 'before' image
                    match &record.op {
                        JournalOp::WriteBlock { ino, block_idx, before } |
                        JournalOp::DeleteBlock { ino, block_idx, before } => {
                            let data_key = format!("data:{}:{}", ino, block_idx);
                            match before {
                                Some(prev) => {
                                    self.db.insert(data_key.as_bytes(), prev.clone())?;
                                }
                                None => {
                                    self.db.remove(data_key.as_bytes())?;
                                }
                            }
                        }
                        JournalOp::MetaUpdate { key: meta_key, before } => {
                            match before {
                                Some(prev) => {
                                    self.db.insert(meta_key.as_bytes(), prev.clone())?;
                                }
                                None => {
                                    self.db.remove(meta_key.as_bytes())?;
                                }
                            }
                        }
                    }
                }
            }
        }
        // Reset head to committed after undo
        self.db.insert(JOURNAL_HEAD, bincode::serialize(&committed)?)?;
        self.db.flush()?;
        log::info!("GhostFS journal recovery complete.");
        Ok(())
    }
}
