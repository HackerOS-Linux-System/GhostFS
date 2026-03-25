use crate::crypto::Crypto;
use crate::compression::Compression;
use crate::deduplication::Deduplication;
use crate::versioning::Versioning;
use sled::Db;
use std::collections::HashSet;

pub struct Repair {
    db: Db,
    crypto: Option<Crypto>,
    compression: Compression,
    dedup: Deduplication,
    versioning: Versioning,
}

impl Repair {
    pub fn new(db: &Db, crypto: &Option<Crypto>, compression: &Compression, dedup: &Deduplication, versioning: &Versioning) -> Result<Self, ()> {
        Ok(Self {
            db: db.clone(),
            crypto: crypto.clone(),
            compression: compression.clone(),
            dedup: dedup.clone(),
            versioning: versioning.clone(),
        })
    }

    pub fn verify_and_repair(&self, ino: u64) -> Result<bool, ()> {
        // Sprawdza integralność inode'a i bloków, naprawia jeśli to możliwe.
        // Zwraca true jeśli naprawiono.

        // 1. Sprawdź inode
        let inode_key = format!("inode:{}", ino);
        let inode_data = match self.db.get(inode_key.as_bytes()).map_err(|_| ())? {
            Some(d) => d,
            None => return Ok(false), // brak inode'a
        };
        let inode: crate::Inode = bincode::deserialize(&inode_data).map_err(|_| ())?;

        // 2. Sprawdź bloki danych
        let mut corrupted = false;
        for block_idx in 0..((inode.attr.size + FS_BLOCK_SIZE as u64 - 1) / FS_BLOCK_SIZE as u64) as usize {
            let block_key = format!("data:{}:{}", ino, block_idx);
            if let Some(block_data) = self.db.get(block_key.as_bytes()).map_err(|_| ())? {
                // Dekompresja i deszyfrowanie
                let decrypted = if let Some(crypto) = &self.crypto {
                    crypto.decrypt(&block_data).map_err(|_| ())?
                } else {
                    block_data.to_vec()
                };
                let decompressed = self.compression.decompress(&decrypted).map_err(|_| ())?;
                if let Err(_) = self.dedup.verify(ino, block_idx, &decompressed) {
                    corrupted = true;
                    // Próba naprawy: przywróć z poprzedniej wersji
                    if let Ok(versions) = self.versioning.list_versions(ino) {
                        if let Some(&latest) = versions.iter().max() {
                            if let Ok(_) = self.versioning.restore_version(ino, latest) {
                                // Po przywróceniu wersji przerywamy, bo inode i bloki są zastąpione
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        Ok(corrupted)
    }

    // Można dodać periodiczną naprawę w tle
}
