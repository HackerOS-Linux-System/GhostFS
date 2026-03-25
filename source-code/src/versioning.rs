use sled::Db;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone)]
struct Version {
    timestamp: u64,
    inode: Vec<u8>,      // serializowany Inode
    // Można też przechowywać listę zmienionych bloków
}

pub struct Versioning {
    db: Db,
}

impl Versioning {
    pub fn new(db: &Db) -> Result<Self, ()> {
        Ok(Self { db: db.clone() })
    }

    pub fn create_version(&self, ino: u64) -> Result<(), ()> {
        // Pobierz aktualny inode
        let key_inode = format!("inode:{}", ino);
        let inode_data = self.db.get(key_inode.as_bytes()).map_err(|_| ())?.ok_or(())?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs();
        let version = Version {
            timestamp,
            inode: inode_data.to_vec(),
        };
        let version_key = format!("versions:{}:{}", ino, timestamp);
        self.db.insert(version_key.as_bytes(), bincode::serialize(&version).map_err(|_| ())?).map_err(|_| ())?;
        // Aktualizuj listę wersji
        let list_key = format!("version_list:{}", ino);
        let mut versions: Vec<u64> = match self.db.get(list_key.as_bytes()).map_err(|_| ())? {
            Some(v) => bincode::deserialize(&v).map_err(|_| ())?,
            None => Vec::new(),
        };
        versions.push(timestamp);
        self.db.insert(list_key.as_bytes(), bincode::serialize(&versions).map_err(|_| ())?).map_err(|_| ())?;
        Ok(())
    }

    pub fn list_versions(&self, ino: u64) -> Result<Vec<u64>, ()> {
        let list_key = format!("version_list:{}", ino);
        match self.db.get(list_key.as_bytes()).map_err(|_| ())? {
            Some(v) => bincode::deserialize(&v).map_err(|_| ())?,
            None => Ok(Vec::new()),
        }
    }

    pub fn restore_version(&self, ino: u64, timestamp: u64) -> Result<(), ()> {
        let version_key = format!("versions:{}:{}", ino, timestamp);
        let version_data = self.db.get(version_key.as_bytes()).map_err(|_| ())?.ok_or(())?;
        let version: Version = bincode::deserialize(&version_data).map_err(|_| ())?;
        // Przywróć inode
        let inode_key = format!("inode:{}", ino);
        self.db.insert(inode_key.as_bytes(), version.inode).map_err(|_| ())?;
        // Opcjonalnie przywróć bloki danych – wymaga przechowywania różnic
        // Uproszczenie: zakładamy, że każda wersja zawiera pełny obraz pliku.
        // W praktyce trzeba by przechowywać zmodyfikowane bloki.
        Ok(())
    }
}
