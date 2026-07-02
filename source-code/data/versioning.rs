use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;
use crate::FS_BLOCK_SIZE;

const MAX_VERSIONS: usize = 8;

/// Ile bloków maksymalnie zapisujemy w wersji delta (zabezpieczenie pamięci).
/// Pliki większe niż ten próg są wersjonowane jako pełny checkpoint zamiast delty.
const DELTA_MAX_BLOCKS: usize = 256;

#[derive(Serialize, Deserialize, Clone)]
pub struct Version {
    pub timestamp: u64,
    pub inode:     Vec<u8>,
    /// Snapshot bloków danych — pełny lub delta (bloki zmienione od poprzedniej wersji).
    pub blocks:    std::collections::BTreeMap<usize, Vec<u8>>,
    /// Czy to pełny snapshot (wszystkie bloki) czy delta (tylko zmienione).
    pub full:      bool,
}

#[derive(Clone)]
pub struct Versioning {
    db: Db,
}

impl Versioning {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn list_key(ino: u64) -> String {
        format!("version_list:{}", ino)
    }

    fn version_key(ino: u64, ts: u64) -> String {
        format!("versions:{}:{}", ino, ts)
    }

    /// Utwórz wersję z aktualnym stanem inode ORAZ jego blokami danych.
    ///
    /// Dla małych plików (≤ DELTA_MAX_BLOCKS) wykonywany jest pełny snapshot bloków.
    /// Dla dużych plików rejestrujemy tylko metadane inode i oznaczamy wersję jako
    /// niepełną — `restore_version()` zwróci błąd i system powinien użyć
    /// `create_full_checkpoint()` dla takich plików.
    pub fn create_version(&self, ino: u64) -> Result<(), HfsError> {
        let inode_key  = format!("inode:{}", ino);
        let inode_data = match self.db.get(inode_key.as_bytes())? {
            Some(d) => d.to_vec(),
            None    => return Ok(()),
        };

        // Odczytaj metadane inode aby obliczyć liczbę bloków.
        let inode: crate::serialization::Inode = bincode::deserialize(&inode_data)?;
        let block_count = (inode.attr.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64;

        let (blocks, full) = if block_count as usize <= DELTA_MAX_BLOCKS {
            // Pełny snapshot bloków.
            let mut blk_map = std::collections::BTreeMap::new();
            for idx in 0..block_count as usize {
                let bkey = format!("data:{}:{}", ino, idx);
                if let Some(raw) = self.db.get(bkey.as_bytes())? {
                    blk_map.insert(idx, raw.to_vec());
                }
            }
            (blk_map, true)
        } else {
            // Plik za duży na delta — zapisz tylko metadane.
            // Wywołaj create_full_checkpoint() osobno dla dużych plików.
            log::debug!("versioning: ino={} too large ({} blocks) for inline snapshot, inode-only", ino, block_count);
            (std::collections::BTreeMap::new(), false)
        };

        let timestamp = current_timestamp()?;
        let version = Version { timestamp, inode: inode_data, blocks, full };

        let mut batch = sled::Batch::default();
        batch.insert(
            Self::version_key(ino, timestamp).as_bytes(),
            bincode::serialize(&version)?,
        );

        let mut list = self.load_list(ino)?;
        list.push(timestamp);
        list.sort_unstable();
        while list.len() > MAX_VERSIONS {
            let old_ts = list.remove(0);
            batch.remove(Self::version_key(ino, old_ts).as_bytes());
        }
        batch.insert(Self::list_key(ino).as_bytes(), bincode::serialize(&list)?);
        self.db.apply_batch(batch)?;
        Ok(())
    }

    /// Utwórz pełny checkpoint — zawsze zapisuje wszystkie bloki niezależnie od rozmiaru.
    pub fn create_full_checkpoint(&self, ino: u64) -> Result<(), HfsError> {
        let inode_key  = format!("inode:{}", ino);
        let inode_data = match self.db.get(inode_key.as_bytes())? {
            Some(d) => d.to_vec(),
            None    => return Ok(()),
        };

        let inode: crate::serialization::Inode = bincode::deserialize(&inode_data)?;
        let block_count = (inode.attr.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64;

        let mut blocks = std::collections::BTreeMap::new();
        for idx in 0..block_count as usize {
            let bkey = format!("data:{}:{}", ino, idx);
            if let Some(raw) = self.db.get(bkey.as_bytes())? {
                blocks.insert(idx, raw.to_vec());
            }
        }

        let timestamp = current_timestamp()?;
        let version   = Version { timestamp, inode: inode_data, blocks, full: true };

        let mut batch = sled::Batch::default();
        batch.insert(
            Self::version_key(ino, timestamp).as_bytes(),
            bincode::serialize(&version)?,
        );
        let mut list = self.load_list(ino)?;
        list.push(timestamp);
        list.sort_unstable();
        while list.len() > MAX_VERSIONS {
            let old_ts = list.remove(0);
            batch.remove(Self::version_key(ino, old_ts).as_bytes());
        }
        batch.insert(Self::list_key(ino).as_bytes(), bincode::serialize(&list)?);
        self.db.apply_batch(batch)?;
        Ok(())
    }

    pub fn list_versions(&self, ino: u64) -> Result<Vec<u64>, HfsError> {
        self.load_list(ino)
    }

    /// Przywróć wersję — odtwarza zarówno metadane inode jak i bloki danych.
    ///
    /// Zwraca `Err(HfsError::InvalidArgument)` jeśli wersja jest niepełna
    /// (duży plik wersjonowany inode-only). W takim przypadku użyj
    /// `create_full_checkpoint()` przed zapisem aby mieć użyteczne wersje.
    pub fn restore_version(&self, ino: u64, timestamp: u64) -> Result<(), HfsError> {
        let vkey = Self::version_key(ino, timestamp);
        let raw  = self.db.get(vkey.as_bytes())?.ok_or(HfsError::NoEntry)?;
        let version: Version = bincode::deserialize(&raw)?;

        if !version.full && !version.blocks.is_empty() {
            return Err(HfsError::InvalidArgument(
                format!("version ts={} for ino={} is inode-only (file too large for block snapshot); use full checkpoint", timestamp, ino)
            ));
        }

        let mut batch = sled::Batch::default();

        // Przywróć metadane inode.
        batch.insert(format!("inode:{}", ino).as_bytes(), version.inode.clone());

        if version.full {
            // Usuń wszystkie istniejące bloki tego inode przed przywróceniem.
            let data_prefix = format!("data:{}:", ino);
            let existing_keys: Vec<_> = self.db
                .scan_prefix(data_prefix.as_bytes())
                .filter_map(|r| r.ok())
                .map(|(k, _)| k)
                .collect();
            for k in existing_keys {
                batch.remove(k);
            }

            // Zapisz bloki z wersji.
            for (block_idx, data) in &version.blocks {
                batch.insert(
                    format!("data:{}:{}", ino, block_idx).as_bytes(),
                    data.clone(),
                );
            }
            log::info!("versioning: restored ino={} ts={} ({} blocks)", ino, timestamp, version.blocks.len());
        } else {
            log::warn!("versioning: ino={} ts={} inode-only version — blocks NOT restored", ino, timestamp);
        }

        self.db.apply_batch(batch)?;
        Ok(())
    }

    pub fn remove_all_versions(&self, ino: u64) -> Result<(), HfsError> {
        let list = self.load_list(ino)?;
        let mut batch = sled::Batch::default();
        for ts in list {
            batch.remove(Self::version_key(ino, ts).as_bytes());
        }
        batch.remove(Self::list_key(ino).as_bytes());
        self.db.apply_batch(batch)?;
        Ok(())
    }

    fn load_list(&self, ino: u64) -> Result<Vec<u64>, HfsError> {
        match self.db.get(Self::list_key(ino).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(Vec::new()),
        }
    }
}

fn current_timestamp() -> Result<u64, HfsError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| HfsError::TimeError)
}
