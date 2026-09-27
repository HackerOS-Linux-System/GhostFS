use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Extent {
    pub logical_start:   u64,
    pub length:          u32,
    pub phys_key_prefix: String,
}

#[derive(Clone)]
pub struct ExtentTree { db: Db }

impl ExtentTree {
    pub fn new(db: &Db) -> Result<Self, HfsError> { Ok(Self { db: db.clone() }) }

    fn index_key(ino: u64) -> String { format!("ext_idx:{}", ino) }
    fn extent_key(ino: u64, start: u64) -> String { format!("ext:{}:{}", ino, start) }

    fn load_index(&self, ino: u64) -> Result<Vec<u64>, HfsError> {
        match self.db.get(Self::index_key(ino).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(Vec::new()),
        }
    }

    fn save_index(&self, ino: u64, index: &[u64]) -> Result<(), HfsError> {
        self.db.insert(Self::index_key(ino).as_bytes(), bincode::serialize(index)?)?;
        Ok(())
    }

    pub fn record(&self, ino: u64, block_idx: usize, phys_key: &str) -> Result<(), HfsError> {
        let mut index   = self.load_index(ino)?;
        let logical     = block_idx as u64;

        // Sprawdź czy możemy rozszerzyć istniejący ekstent.
        if let Some(&prev_start) = index.iter().rev().find(|&&s| s <= logical) {
            let ekey = Self::extent_key(ino, prev_start);
            if let Some(raw) = self.db.get(ekey.as_bytes())? {
                let mut ext: Extent = bincode::deserialize(&raw)?;
                if prev_start + ext.length as u64 == logical {
                    ext.length += 1;
                    self.db.insert(ekey.as_bytes(), bincode::serialize(&ext)?)?;
                    return Ok(());
                }
            }
        }

        let ext  = Extent { logical_start: logical, length: 1, phys_key_prefix: phys_key.to_string() };
        let ekey = Self::extent_key(ino, logical);
        self.db.insert(ekey.as_bytes(), bincode::serialize(&ext)?)?;
        let pos = index.partition_point(|&s| s < logical);
        index.insert(pos, logical);
        self.save_index(ino, &index)?;
        Ok(())
    }

    pub fn resolve(&self, ino: u64, block_idx: usize) -> Option<String> {
        let logical = block_idx as u64;
        let index   = self.load_index(ino).ok()?;
        let pos     = index.partition_point(|&s| s <= logical);
        if pos == 0 { return None; }
        let start = index[pos - 1];
        let ekey  = Self::extent_key(ino, start);
        let raw   = self.db.get(ekey.as_bytes()).ok()??;
        let ext: Extent = bincode::deserialize(&raw).ok()?;
        if logical < start + ext.length as u64 {
            let offset = logical - start;
            if offset == 0 { Some(ext.phys_key_prefix.clone()) }
            else           { Some(format!("data:{}:{}", ino, block_idx)) }
        } else { None }
    }

    /// Usuń blok z ekstrenta — obsługuje 3 przypadki:
    /// 1. Blok jest jedynym w ekstrenta → usuń ekstent.
    /// 2. Blok jest na początku ekstrenta → przesuń start.
    /// 3. Blok jest w środku → split na dwa ekstenty [start..block-1] i [block+1..end].
    pub fn remove(&self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let logical = block_idx as u64;
        let mut index = self.load_index(ino)?;

        // Znajdź ekstent zawierający blok.
        let pos = index.partition_point(|&s| s <= logical);
        if pos == 0 { return Ok(()); }
        let start = index[pos - 1];
        let ekey  = Self::extent_key(ino, start);
        let ext: Extent = match self.db.get(ekey.as_bytes())? {
            Some(raw) => bincode::deserialize(&raw)?,
            None      => return Ok(()),
        };

        // Sprawdź czy blok faktycznie należy do tego ekstrenta.
        if logical >= start + ext.length as u64 { return Ok(()); }

        let end   = start + ext.length as u64; // exclusive
        let mut batch = sled::Batch::default();

        // Usuń stary ekstent.
        batch.remove(ekey.as_bytes());
        index.retain(|&s| s != start);

        if ext.length == 1 {
            // Przypadek 1: jedyny blok — ekstent znika.
        } else if logical == start {
            // Przypadek 2: blok na początku — przesuń start o 1.
            let new_ext = Extent {
                logical_start:   start + 1,
                length:          ext.length - 1,
                phys_key_prefix: format!("data:{}:{}", ino, start + 1),
            };
            let new_key = Self::extent_key(ino, start + 1);
            batch.insert(new_key.as_bytes(), bincode::serialize(&new_ext)?);
            let ins_pos = index.partition_point(|&s| s < start + 1);
            index.insert(ins_pos, start + 1);
        } else if logical == end - 1 {
            // Blok na końcu — skróć o 1.
            let new_ext = Extent { logical_start: start, length: ext.length - 1, phys_key_prefix: ext.phys_key_prefix.clone() };
            batch.insert(ekey.as_bytes(), bincode::serialize(&new_ext)?);
            let ins_pos = index.partition_point(|&s| s < start);
            index.insert(ins_pos, start);
        } else {
            // Przypadek 3: środek — split na dwa ekstenty.
            // Lewa część: [start .. logical-1]
            let left = Extent {
                logical_start:   start,
                length:          (logical - start) as u32,
                phys_key_prefix: ext.phys_key_prefix.clone(),
            };
            // Prawa część: [logical+1 .. end-1]
            let right = Extent {
                logical_start:   logical + 1,
                length:          (end - logical - 1) as u32,
                phys_key_prefix: format!("data:{}:{}", ino, logical + 1),
            };
            batch.insert(Self::extent_key(ino, start).as_bytes(),     bincode::serialize(&left)?);
            batch.insert(Self::extent_key(ino, logical + 1).as_bytes(), bincode::serialize(&right)?);
            let p1 = index.partition_point(|&s| s < start);
            index.insert(p1, start);
            let p2 = index.partition_point(|&s| s < logical + 1);
            index.insert(p2, logical + 1);
        }

        self.db.apply_batch(batch)?;
        self.save_index(ino, &index)?;
        Ok(())
    }

    pub fn remove_all(&self, ino: u64) -> Result<(), HfsError> {
        let prefix = format!("ext:{}:", ino);
        let keys: Vec<_> = self.db.scan_prefix(prefix.as_bytes())
            .filter_map(|r| r.ok()).map(|(k, _)| k).collect();
        let mut batch = sled::Batch::default();
        for k in keys { batch.remove(k); }
        self.db.remove(Self::index_key(ino).as_bytes())?;
        self.db.apply_batch(batch)?;
        Ok(())
    }
}
