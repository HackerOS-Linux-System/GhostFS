use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

const JOURNAL_PREFIX: &str    = "journal:seq:";
const JOURNAL_HEAD: &[u8]     = b"journal:head";
const JOURNAL_COMMITTED: &[u8]= b"journal:committed";
/// Minimalna liczba zapisanych rekordów przed przycinaniem (bufor bezpieczeństwa).
const PRUNE_KEEP: u64 = 512;
const SYNC_ON_BARRIER: bool = true;

/// Stan rekordu journala — rozróżniamy pending/committed dla redo i undo.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum JournalState {
    /// Zapis zalogowany, ale commit_barrier() jeszcze nie wywołany.
    Pending,
    /// Commit barrier przeszedł — dane MUSZĄ trafić na dysk.
    Committed,
    /// Dane faktycznie utrwalone w sled (po apply_batch + flush).
    Flushed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum JournalOp {
    WriteBlock {
        ino: u64,
        block_idx: usize,
        /// Stan PRZED zapisem (do undo).
        before: Option<Vec<u8>>,
        /// Stan PO zapisie (do redo).
        after: Option<Vec<u8>>,
    },
    DeleteBlock {
        ino: u64,
        block_idx: usize,
        before: Option<Vec<u8>>,
    },
    MetaUpdate {
        key: String,
        before: Option<Vec<u8>>,
        after: Option<Vec<u8>>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JournalRecord {
    pub seq:   u64,
    pub op:    JournalOp,
    pub state: JournalState,
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
            None    => 0,
        };
        self.db.insert(JOURNAL_HEAD, bincode::serialize(&(seq + 1))?)?;
        Ok(seq)
    }

    fn last_committed(&self) -> Result<u64, HfsError> {
        Ok(match self.db.get(JOURNAL_COMMITTED)? {
            Some(v) => bincode::deserialize(&v)?,
            None    => 0,
        })
    }

    /// Loguj zapis bloku z wartością PRZED i PO (potrzebne do redo).
    pub fn log_write(
        &self,
        ino: u64,
        block_idx: usize,
        before: &Option<Vec<u8>>,
        after: &Option<Vec<u8>>,
    ) -> Result<(), HfsError> {
        let seq = self.next_seq()?;
        let record = JournalRecord {
            seq,
            op: JournalOp::WriteBlock {
                ino,
                block_idx,
                before: before.clone(),
                after:  after.clone(),
            },
            state: JournalState::Pending,
        };
        let key = format!("{}{:016}", JOURNAL_PREFIX, seq);
        self.db.insert(key.as_bytes(), bincode::serialize(&record)?)?;
        Ok(())
    }

    /// Loguj usunięcie bloku.
    pub fn log_delete(
        &self,
        ino: u64,
        block_idx: usize,
        before: &Option<Vec<u8>>,
    ) -> Result<(), HfsError> {
        let seq = self.next_seq()?;
        let record = JournalRecord {
            seq,
            op: JournalOp::DeleteBlock { ino, block_idx, before: before.clone() },
            state: JournalState::Pending,
        };
        let key = format!("{}{:016}", JOURNAL_PREFIX, seq);
        self.db.insert(key.as_bytes(), bincode::serialize(&record)?)?;
        Ok(())
    }

    /// Loguj aktualizację metadanych.
    pub fn log_meta(
        &self,
        meta_key: &str,
        before: &Option<Vec<u8>>,
        after: &Option<Vec<u8>>,
    ) -> Result<(), HfsError> {
        let seq = self.next_seq()?;
        let record = JournalRecord {
            seq,
            op: JournalOp::MetaUpdate {
                key:    meta_key.to_string(),
                before: before.clone(),
                after:  after.clone(),
            },
            state: JournalState::Pending,
        };
        let key = format!("{}{:016}", JOURNAL_PREFIX, seq);
        self.db.insert(key.as_bytes(), bincode::serialize(&record)?)?;
        Ok(())
    }

    /// Oznacz wszystkie Pending rekordy jako Committed, opcjonalnie flushuj.
    pub fn commit_barrier(&self) -> Result<(), HfsError> {
        let head: u64 = match self.db.get(JOURNAL_HEAD)? {
            Some(v) => bincode::deserialize(&v)?,
            None    => 0,
        };
        let committed = self.last_committed()?;

        // Wszystkie rekordy między committed a head przechodzą w stan Committed.
        for seq in committed..head {
            let key = format!("{}{:016}", JOURNAL_PREFIX, seq);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                let mut record: JournalRecord = bincode::deserialize(&raw)?;
                if record.state == JournalState::Pending {
                    record.state = JournalState::Committed;
                    self.db.insert(key.as_bytes(), bincode::serialize(&record)?)?;
                }
            }
        }

        self.db.insert(JOURNAL_COMMITTED, bincode::serialize(&head)?)?;

        if SYNC_ON_BARRIER {
            self.db.flush()?;
        }

        // Po flushu oznaczamy Committed → Flushed i bezpiecznie przycinamy.
        self.mark_flushed_and_prune(head)?;
        Ok(())
    }

    /// Po udanym flushu oznacz rekordy jako Flushed i usuń stare.
    /// Przycinamy tylko rekordy Flushed starsze niż PRUNE_KEEP sekwencji od końca.
    fn mark_flushed_and_prune(&self, up_to_seq: u64) -> Result<(), HfsError> {
        // Oznacz jako Flushed
        for seq in 0..up_to_seq {
            let key = format!("{}{:016}", JOURNAL_PREFIX, seq);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                let mut record: JournalRecord = bincode::deserialize(&raw)?;
                if record.state == JournalState::Committed {
                    record.state = JournalState::Flushed;
                    self.db.insert(key.as_bytes(), bincode::serialize(&record)?)?;
                }
            }
        }

        // Przytnij — ale zachowaj PRUNE_KEEP ostatnich rekordów jako bufor.
        if up_to_seq > PRUNE_KEEP {
            let prune_before = up_to_seq - PRUNE_KEEP;
            for seq in 0..prune_before {
                let key = format!("{}{:016}", JOURNAL_PREFIX, seq);
                // Usuń tylko Flushed — nigdy Pending/Committed.
                if let Some(raw) = self.db.get(key.as_bytes())? {
                    let record: JournalRecord = bincode::deserialize(&raw)?;
                    if record.state == JournalState::Flushed {
                        self.db.remove(key.as_bytes())?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Recovery po awarii:
    /// 1. Redo: nałóż zacommitowane operacje (mogły nie trafić na dysk przed crashem).
    /// 2. Undo: cofnij niezacommitowane operacje (były w locie przy crashu).
    pub fn recover(&self, _db: &Db) -> Result<(), HfsError> {
        let committed = self.last_committed()?;
        let head: u64 = match self.db.get(JOURNAL_HEAD)? {
            Some(v) => bincode::deserialize(&v)?,
            None    => 0,
        };

        if head == committed {
            log::info!("GhostFS journal: clean — no recovery needed");
            return Ok(());
        }

        log::warn!(
            "GhostFS journal recovery: committed={} head={} ({} records to process)",
            committed, head, head - committed
        );

        // === REDO PASS: rekordy Committed ale jeszcze nie Flushed ===
        // Iterujemy od najstarszego do najnowszego (rosnące seq).
        let mut redo_count = 0u64;
        for seq in 0..committed {
            let key = format!("{}{:016}", JOURNAL_PREFIX, seq);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                let record: JournalRecord = bincode::deserialize(&raw)?;
                if record.state == JournalState::Committed {
                    self.apply_redo(&record)?;
                    redo_count += 1;
                }
            }
        }

        // === UNDO PASS: rekordy Pending (nie zdążyły się zacommitować) ===
        // Iterujemy OD KOŃCA do początku (malejące seq) — klasyczny undo.
        let mut undo_count = 0u64;
        let pending_seqs: Vec<u64> = (committed..head)
            .filter(|&seq| {
                let key = format!("{}{:016}", JOURNAL_PREFIX, seq);
                self.db.get(key.as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|raw| bincode::deserialize::<JournalRecord>(&raw).ok())
                    .map(|r| r.state == JournalState::Pending)
                    .unwrap_or(false)
            })
            .collect();

        for seq in pending_seqs.into_iter().rev() {
            let key = format!("{}{:016}", JOURNAL_PREFIX, seq);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                let record: JournalRecord = bincode::deserialize(&raw)?;
                self.apply_undo(&record)?;
                undo_count += 1;
            }
        }

        // Przywróć wskaźnik head do ostatniego zacommitowanego stanu.
        self.db.insert(JOURNAL_HEAD, bincode::serialize(&committed)?)?;
        self.db.flush()?;

        log::info!(
            "GhostFS journal recovery complete: redo={} undo={}",
            redo_count, undo_count
        );
        Ok(())
    }

    /// Nałóż operację redo (committed → zapisz `after` na dysk).
    fn apply_redo(&self, record: &JournalRecord) -> Result<(), HfsError> {
        match &record.op {
            JournalOp::WriteBlock { ino, block_idx, after, .. } => {
                let data_key = format!("data:{}:{}", ino, block_idx);
                match after {
                    Some(data) => { self.db.insert(data_key.as_bytes(), data.clone())?; }
                    None       => { self.db.remove(data_key.as_bytes())?; }
                }
            }
            JournalOp::MetaUpdate { key: meta_key, after, .. } => {
                match after {
                    Some(data) => { self.db.insert(meta_key.as_bytes(), data.clone())?; }
                    None       => { self.db.remove(meta_key.as_bytes())?; }
                }
            }
            JournalOp::DeleteBlock { ino, block_idx, .. } => {
                let data_key = format!("data:{}:{}", ino, block_idx);
                self.db.remove(data_key.as_bytes())?;
            }
        }
        Ok(())
    }

    /// Cofnij operację undo (pending → przywróć `before`).
    fn apply_undo(&self, record: &JournalRecord) -> Result<(), HfsError> {
        match &record.op {
            JournalOp::WriteBlock { ino, block_idx, before, .. }
            | JournalOp::DeleteBlock { ino, block_idx, before } => {
                let data_key = format!("data:{}:{}", ino, block_idx);
                match before {
                    Some(prev) => { self.db.insert(data_key.as_bytes(), prev.clone())?; }
                    None       => { self.db.remove(data_key.as_bytes())?; }
                }
            }
            JournalOp::MetaUpdate { key: meta_key, before, .. } => {
                match before {
                    Some(prev) => { self.db.insert(meta_key.as_bytes(), prev.clone())?; }
                    None       => { self.db.remove(meta_key.as_bytes())?; }
                }
            }
        }
        Ok(())
    }
}
