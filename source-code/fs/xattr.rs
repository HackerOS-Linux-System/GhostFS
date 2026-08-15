use sled::Db;
use serde::{Serialize, Deserialize};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use crate::error::HfsError;
use crate::crypto::Crypto;

/// Rozszerzone atrybuty (xattr) — szyfrowane od v1.1.
///
/// Wcześniej: klucz sled = `xattr:{ino}:{nazwa}` (NAZWA WPROST, jawnym
/// tekstem, w samym kluczu), wartość = surowe bajty BEZ szyfrowania.
/// xattr bywają wrażliwe (etykiety SELinux/AppArmor, tokeny aplikacji,
/// metadane typu "pobrano z <url>", niestandardowe ACL) — dla systemu
/// plików reklamującego się jako cybersecurity-focused to była ta sama
/// klasa luki co niedawno naprawione nazwy plików (dirindex.rs) i
/// metadane inode (Crypto::derive_inode_enc_key).
///
/// Teraz: klucz = `xattr:{ino}:{blind_index_hex}` (blind index kluczowany
/// master_key — deterministyczny dla O(1) lookup, ale odporny na atak
/// słownikowy na typowe nazwy xattr bez znajomości klucza), wartość =
/// bincode(EncryptedXattr { encrypted_name, encrypted_value }), oba pola
/// AES-256-GCM pod kluczem per-inode.
const XATTR_PREFIX: &str = "xattr:";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct EncryptedXattr {
    /// nonce (12B) || AES-256-GCM ciphertext nazwy atrybutu.
    encrypted_name: Vec<u8>,
    /// nonce (12B) || AES-256-GCM ciphertext wartości atrybutu.
    encrypted_value: Vec<u8>,
}

#[derive(Clone)]
pub struct XAttr {
    db: Db,
    crypto: Crypto,
}

impl XAttr {
    pub fn new(db: &Db, crypto: Crypto) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone(), crypto })
    }

    fn key(&self, ino: u64, name: &OsStr) -> String {
        let blind = self.crypto.xattr_blind_index(ino, name.as_bytes());
        format!("{}{}:{}", XATTR_PREFIX, ino, hex::encode(blind))
    }

    fn prefix(ino: u64) -> String {
        format!("{}{}:", XATTR_PREFIX, ino)
    }

    pub fn get(&self, ino: u64, name: &OsStr) -> Result<Option<Vec<u8>>, HfsError> {
        let key = self.key(ino, name);
        match self.db.get(key.as_bytes())? {
            Some(v) => {
                let entry: EncryptedXattr = bincode::deserialize(&v)?;
                let enc_key = self.crypto.derive_xattr_enc_key(ino);
                let value = self.crypto.decrypt_with_key(&enc_key, &entry.encrypted_value)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub fn set(&self, ino: u64, name: &OsStr, value: &[u8]) -> Result<(), HfsError> {
        let key = self.key(ino, name);
        let enc_key = self.crypto.derive_xattr_enc_key(ino);
        let encrypted_name = self.crypto.encrypt_with_key(&enc_key, name.as_bytes())?;
        let encrypted_value = self.crypto.encrypt_with_key(&enc_key, value)?;
        let entry = EncryptedXattr { encrypted_name, encrypted_value };
        self.db.insert(key.as_bytes(), bincode::serialize(&entry)?)?;
        Ok(())
    }

    /// Lista nazw xattr — wymaga odszyfrowania KAŻDEJ (nie tylko blind
    /// index) bo `listxattr(2)` z definicji potrzebuje jawnych nazw.
    /// Koszt pomijalny (AES-NI/BLAKE3 rzędu GB/s), ten sam kompromis co
    /// `DirIndex::list`.
    pub fn list(&self, ino: u64) -> Result<Vec<OsString>, HfsError> {
        let enc_key = self.crypto.derive_xattr_enc_key(ino);
        let prefix = Self::prefix(ino);
        let mut names = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, v) = item?;
            let entry: EncryptedXattr = bincode::deserialize(&v)?;
            let name_bytes = self.crypto.decrypt_with_key(&enc_key, &entry.encrypted_name)?;
            names.push(OsString::from(std::ffi::OsStr::from_bytes(&name_bytes)));
        }
        Ok(names)
    }

    pub fn remove(&self, ino: u64, name: &OsStr) -> Result<(), HfsError> {
        let key = self.key(ino, name);
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    /// Usuń WSZYSTKIE xattr danego inode — wołane przy `unlink`/`rmdir`
    /// żeby nie zostawiać osieroconych wpisów. Wcześniej ta metoda nie
    /// istniała — sprawdź `fs/fs.rs` czy jest wołana przy kasowaniu.
    pub fn remove_all(&self, ino: u64) -> Result<(), HfsError> {
        let prefix = Self::prefix(ino);
        let keys: Vec<_> = self.db
            .scan_prefix(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .collect();
        let mut batch = sled::Batch::default();
        for k in keys { batch.remove(k); }
        self.db.apply_batch(batch)?;
        Ok(())
    }
}
