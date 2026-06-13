use sled::Db;
use crate::error::HfsError;

#[derive(Clone)]
pub struct IntegrityTree {
    db: Db,
}

impl IntegrityTree {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn leaf_key(ino: u64, block_idx: usize) -> String {
        format!("itree:{}:leaf:{}", ino, block_idx)
    }
    fn root_key(ino: u64) -> String {
        format!("itree:{}:root", ino)
    }

    /// Store the leaf hash for a block and recompute the root.
    pub fn update_block(
        &self,
        ino: u64,
        block_idx: usize,
        data: &[u8],
    ) -> Result<(), HfsError> {
        let hash = blake3::hash(data);
        let leaf_key = Self::leaf_key(ino, block_idx);
        self.db.insert(leaf_key.as_bytes(), hash.as_bytes().to_vec())?;
        self.recompute_root(ino)?;
        Ok(())
    }

    /// Verify a block's hash against the stored leaf hash.
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
                    ino,
                    block_idx
                );
                return Err(HfsError::CorruptedData);
            }
        }
        Ok(())
    }

    /// Remove the leaf hash when a block is deleted.
    pub fn remove_block(&self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let leaf_key = Self::leaf_key(ino, block_idx);
        self.db.remove(leaf_key.as_bytes())?;
        self.recompute_root(ino)?;
        Ok(())
    }

    /// Return the current Merkle root for a file (for external verification / export).
    pub fn root(&self, ino: u64) -> Result<Option<[u8; 32]>, HfsError> {
        match self.db.get(Self::root_key(ino).as_bytes())? {
            Some(v) if v.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Ok(Some(arr))
            }
            _ => Ok(None),
        }
    }

    /// Recompute the Merkle root from all leaf hashes stored for `ino`.
    /// We use a simple linear accumulation: iteratively hash pairs of nodes.
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
        self.db.insert(Self::root_key(ino).as_bytes(), root.to_vec())?;
        Ok(())
    }
}

/// Compute Merkle root from a flat list of leaf hashes.
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
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&level[i]);
                hasher.update(&level[i + 1]);
                next.push(hasher.finalize().as_bytes().to_vec());
            } else {
                // Odd node: promote as-is
                next.push(level[i].clone());
            }
            i += 2;
        }
        level = next;
    }
    level.remove(0)
}
