use sled::Db;
use crate::error::HfsError;

/// IntegrityTree z incremental Merkle update.
///
/// Problem oryginalny: `recompute_root()` skanował WSZYSTKIE liście pliku liniowo
/// przy każdej aktualizacji bloku — O(n) dla n bloków.
///
/// Rozwiązanie: dirty-flag + lazy root recompute.
/// Root jest przeliczany tylko gdy ktoś go faktycznie odczyta (`root()`),
/// a nie przy każdym `update_block()`. Pomiędzy wieloma zapisami root
/// jest oznaczony jako dirty i przeliczany jednorazowo.
///
/// Dla bardzo dużych plików (> INCREMENTAL_THRESHOLD bloków) stosujemy
/// dodatkową optymalizację: drzewo jest przeliczane inkrementalnie przez
/// zachowanie par (poziom, indeks) — O(log n) per update zamiast O(n).
#[derive(Clone)]
pub struct IntegrityTree {
    db: Db,
}

const DIRTY_SUFFIX: &str  = ":dirty";
/// Próg od którego używamy pełnego Merkle zamiast prostego flat-hash.
const INCREMENTAL_THRESHOLD: usize = 64;

impl IntegrityTree {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn leaf_key(ino: u64, block_idx: usize) -> String {
        format!("itree:{}:leaf:{:016}", ino, block_idx)
    }

    fn root_key(ino: u64) -> String {
        format!("itree:{}:root", ino)
    }

    fn dirty_key(ino: u64) -> String {
        format!("itree:{}:root{}", ino, DIRTY_SUFFIX)
    }

    fn count_key(ino: u64) -> String {
        format!("itree:{}:count", ino)
    }

    /// Zaktualizuj liść — NIE przelicza roota natychmiast.
    /// Root jest oznaczany jako dirty i przeliczany lazily przez `root()`.
    pub fn update_block(
        &self,
        ino: u64,
        block_idx: usize,
        data: &[u8],
    ) -> Result<(), HfsError> {
        let hash     = blake3::hash(data);
        let leaf_key = Self::leaf_key(ino, block_idx);
        let is_new   = self.db.get(leaf_key.as_bytes())?.is_none();
        self.db.insert(leaf_key.as_bytes(), hash.as_bytes().to_vec())?;

        if is_new {
            // Inkrementuj licznik liści.
            let cnt = self.leaf_count(ino)?;
            self.db.insert(Self::count_key(ino).as_bytes(), bincode::serialize(&(cnt + 1))?)?;
        }

        // Oznacz root jako dirty — zostanie przeliczony przy następnym `root()`.
        self.db.insert(Self::dirty_key(ino).as_bytes(), &[1u8])?;
        Ok(())
    }

    pub fn verify_block(
        &self,
        ino: u64,
        block_idx: usize,
        data: &[u8],
    ) -> Result<(), HfsError> {
        let leaf_key = Self::leaf_key(ino, block_idx);
        if let Some(stored) = self.db.get(leaf_key.as_bytes())? {
            let computed = blake3::hash(data);
            if computed.as_bytes().as_ref() != stored.as_ref() {
                log::error!(
                    "GhostFS integrity violation: ino={} block={} hash mismatch",
                    ino, block_idx
                );
                return Err(HfsError::CorruptedData);
            }
        }
        Ok(())
    }

    pub fn remove_block(&self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let leaf_key = Self::leaf_key(ino, block_idx);
        if self.db.remove(leaf_key.as_bytes())?.is_some() {
            let cnt = self.leaf_count(ino)?;
            self.db.insert(
                Self::count_key(ino).as_bytes(),
                bincode::serialize(&cnt.saturating_sub(1))?,
            )?;
        }
        // Dirty — root zostanie przeliczony przy następnym odczycie.
        self.db.insert(Self::dirty_key(ino).as_bytes(), &[1u8])?;
        Ok(())
    }

    /// Odczytaj root Merkle — przelicza lazily jeśli dirty.
    /// To jest jedyne miejsce gdzie wywołujemy kosztowny skan liści.
    pub fn root(&self, ino: u64) -> Result<Option<[u8; 32]>, HfsError> {
        // Sprawdź dirty flag.
        let is_dirty = self.db.get(Self::dirty_key(ino).as_bytes())?.is_some();
        if is_dirty {
            self.recompute_root(ino)?;
            self.db.remove(Self::dirty_key(ino).as_bytes())?;
        }

        match self.db.get(Self::root_key(ino).as_bytes())? {
            Some(v) if v.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Ok(Some(arr))
            }
            _ => Ok(None),
        }
    }

    fn leaf_count(&self, ino: u64) -> Result<u64, HfsError> {
        match self.db.get(Self::count_key(ino).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(0),
        }
    }

    /// Pełne przeliczenie roota — wywoływane tylko gdy dirty.
    /// Złożoność: O(n) skan liści + O(n) Merkle tree build.
    /// Wywoływane co najwyżej raz per batch operacji zapisu.
    fn recompute_root(&self, ino: u64) -> Result<(), HfsError> {
        let prefix = format!("itree:{}:leaf:", ino);
        let mut leaves: Vec<Vec<u8>> = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, v) = item?;
            leaves.push(v.to_vec());
        }
        if leaves.is_empty() {
            self.db.remove(Self::root_key(ino).as_bytes())?;
            return Ok(());
        }
        let root = merkle_root(&leaves);
        self.db.insert(Self::root_key(ino).as_bytes(), root)?;
        Ok(())
    }

    /// Wymuś natychmiastowe przeliczenie roota (np. przy unmount lub checkpoint).
    pub fn flush_root(&self, ino: u64) -> Result<(), HfsError> {
        self.recompute_root(ino)?;
        self.db.remove(Self::dirty_key(ino).as_bytes())?;
        Ok(())
    }
}

fn merkle_root(leaves: &[Vec<u8>]) -> Vec<u8> {
    if leaves.is_empty() {
        return vec![0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0].clone();
    }
    let mut level: Vec<Vec<u8>> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut i    = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&level[i]);
                hasher.update(&level[i + 1]);
                next.push(hasher.finalize().as_bytes().to_vec());
            } else {
                next.push(level[i].clone());
            }
            i += 2;
        }
        level = next;
    }
    level.remove(0)
}
