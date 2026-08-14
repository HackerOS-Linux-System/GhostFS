use sled::Db;
use serde::{Serialize, Deserialize};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use crate::error::HfsError;
use crate::crypto::Crypto;

/// DirIndex — indeks katalogów z bezpiecznym kodowaniem NAZW.
///
/// v0.4 (cybersec hardening): poprzednia wersja przechowywała nazwy plików
/// jako base64 WPROST w kluczu sled (`didx:<parent>:<hash>:<base64_name>`)
/// oraz jako surowe bajty w wartości — czyli w ogóle nieszyfrowane. Ktoś z
/// dostępem tylko do plików bazy sled (np. skopiowany obraz dysku, backup
/// bez klucza) mógł odczytać CAŁĄ strukturę katalogów i nazwy plików bez
/// znajomości master key, mimo że same dane (`data:*`) były zaszyfrowane.
/// Dla systemu plików reklamującego się jako "cybersecurity-focused" to
/// była poważna luka poufności metadanych.
///
/// Teraz:
///   - Klucz sled = `didx:<parent_ino>:<blind_index_hex>`, gdzie
///     `blind_index = HMAC-BLAKE3(master_key-derived subkey, name)` —
///     deterministyczny (pozwala na lookup O(1) bez znajomości WSZYSTKICH
///     nazw w katalogu), ale jednokierunkowy i kluczowany, więc atakujący
///     bez master_key nie może zbudować tęczowej tablicy typowych nazw
///     plików i dopasować jej do indeksu (patrz `Crypto::dirname_blind_index`).
///   - Wartość = AES-256-GCM(nazwa) pod kluczem per-katalog
///     (`Crypto::derive_dir_enc_key`), więc PEŁNA nazwa pliku jest
///     odzyskiwalna WYŁĄCZNIE ze znajomością master key.
///
/// Format klucza: `didx:<parent_ino>:<blind_index_hex>`
/// Format wartości: bincode(EncryptedDirEntry { nonce_and_ciphertext, ino })

const INDEX_PREFIX: &str = "didx:";

/// Wpis indeksu katalogowego — nazwa PRZECHOWYWANA ZASZYFROWANA.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct EncryptedDirEntry {
    /// nonce (12B) || AES-256-GCM ciphertext nazwy pliku.
    encrypted_name: Vec<u8>,
    ino: u64,
}

#[derive(Clone)]
pub struct DirIndex {
    db: Db,
    crypto: Crypto,
}

impl DirIndex {
    pub fn new(db: &Db, crypto: Crypto) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone(), crypto })
    }

    /// Zbuduj klucz DB dla wpisu katalogu — blind index kluczowany master_key,
    /// NIE zawiera nazwy pliku w żadnej odzyskiwalnej formie.
    fn build_key(&self, parent: u64, name: &OsStr) -> String {
        let blind = self.crypto.dirname_blind_index(parent, name.as_bytes());
        format!("{}{}:{}", INDEX_PREFIX, parent, hex::encode(blind))
    }

    /// Prefix do skanowania wszystkich wpisów danego katalogu.
    fn parent_prefix(parent: u64) -> String {
        format!("{}{}:", INDEX_PREFIX, parent)
    }

    pub fn insert(&self, parent: u64, name: &OsStr, ino: u64) -> Result<(), HfsError> {
        let key = self.build_key(parent, name);
        let dir_key = self.crypto.derive_dir_enc_key(parent);
        let encrypted_name = self.crypto.encrypt_with_key(&dir_key, name.as_bytes())?;
        let entry = EncryptedDirEntry { encrypted_name, ino };
        self.db.insert(key.as_bytes(), bincode::serialize(&entry)?)?;
        Ok(())
    }

    pub fn remove(&self, parent: u64, name: &OsStr) -> Result<(), HfsError> {
        let key = self.build_key(parent, name);
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    /// Lookup O(1) — blind index katalogu + lookup po kluczu. Nie wymaga
    /// deszyfrowania: blind index jest deterministyczny, więc lookup po
    /// (parent, name) trafia bezpośrednio w klucz bez skanowania.
    pub fn lookup(&self, parent: u64, name: &OsStr) -> Result<Option<u64>, HfsError> {
        let key = self.build_key(parent, name);
        match self.db.get(key.as_bytes())? {
            Some(v) => {
                let entry: EncryptedDirEntry = bincode::deserialize(&v)?;
                Ok(Some(entry.ino))
            }
            None => Ok(None),
        }
    }

    /// Lista zawartości katalogu — WYMAGA odszyfrowania każdej nazwy
    /// (O(n) AEAD-decrypt na katalog), nieuniknione: readdir(2) z definicji
    /// potrzebuje jawnych nazw, więc jedyny sposób uniknięcia deszyfrowania
    /// tutaj byłby trzymanie nazw jawnym tekstem — dokładnie to, co
    /// naprawiamy. Koszt jest pomijalny (BLAKE3/AES-NI są rzędu GB/s).
    pub fn list(&self, parent: u64) -> Result<Vec<(OsString, u64)>, HfsError> {
        let dir_key = self.crypto.derive_dir_enc_key(parent);
        let prefix = Self::parent_prefix(parent);
        let mut out = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, v) = item?;
            let entry: EncryptedDirEntry = bincode::deserialize(&v)?;
            let name_bytes = self.crypto.decrypt_with_key(&dir_key, &entry.encrypted_name)?;
            let name = OsString::from(OsStr::from_bytes(&name_bytes));
            out.push((name, entry.ino));
        }
        Ok(out)
    }

    pub fn remove_all(&self, parent: u64) -> Result<(), HfsError> {
        let prefix = Self::parent_prefix(parent);
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
