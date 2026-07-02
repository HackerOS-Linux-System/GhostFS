use sled::Db;
use serde::{Serialize, Deserialize};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use crate::error::HfsError;

/// DirIndex — indeks katalogów z bezpiecznym kodowaniem nazw.
///
/// Naprawiono dwa błędy oryginału:
/// 1. Kolizje hashów: zamiast skróconego 8-bajtowego prefiksu Blake3 używamy
///    pełnego 32-bajtowego hasha (hex), co redukuje prawdopodobieństwo kolizji do 2^-256.
/// 2. Błędne parsowanie nazw z dwukropkami: zamiast `split(':')` i indeksowania
///    pozycji, nazwa pliku jest przechowywana jako base64url-encoded wartość,
///    co gwarantuje brak dwukropków w kluczu i poprawne roundtrip dla dowolnych nazw.
///
/// Format klucza: `didx:<parent_ino>:<blake3_full_hex>:<base64url_name>`
/// Format wartości: bincode(ino: u64)

const INDEX_PREFIX: &str = "didx:";

/// Wpis indeksu katalogowego z pełnymi danymi (name + ino) przechowywany jako wartość.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct DirEntry {
    name: Vec<u8>,
    ino:  u64,
}

#[derive(Clone)]
pub struct DirIndex {
    db: Db,
}

impl DirIndex {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    /// Zbuduj klucz DB dla wpisu katalogu.
    ///
    /// Nazwa pliku jest kodowana jako base64url (RFC 4648, bez paddingu) —
    /// gwarantuje brak dwukropków w kluczu niezależnie od zawartości nazwy.
    fn build_key(parent: u64, name: &OsStr) -> String {
        let name_bytes = name.as_bytes();
        let hash       = blake3::hash(name_bytes);
        let hash_hex   = hex::encode(hash.as_bytes()); // pełne 32B = 64 znaki hex
        let name_b64   = base64_url_encode(name_bytes);
        format!("{}{}:{}:{}", INDEX_PREFIX, parent, hash_hex, name_b64)
    }

    /// Prefix do skanowania wszystkich wpisów danego katalogu.
    fn parent_prefix(parent: u64) -> String {
        format!("{}{}", INDEX_PREFIX, parent)
    }

    pub fn insert(&self, parent: u64, name: &OsStr, ino: u64) -> Result<(), HfsError> {
        let key   = Self::build_key(parent, name);
        let entry = DirEntry { name: name.as_bytes().to_vec(), ino };
        self.db.insert(key.as_bytes(), bincode::serialize(&entry)?)?;
        Ok(())
    }

    pub fn remove(&self, parent: u64, name: &OsStr) -> Result<(), HfsError> {
        let key = Self::build_key(parent, name);
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    /// Lookup O(1) — hash katalogu + lookup po kluczu.
    pub fn lookup(&self, parent: u64, name: &OsStr) -> Result<Option<u64>, HfsError> {
        let key = Self::build_key(parent, name);
        match self.db.get(key.as_bytes())? {
            Some(v) => {
                let entry: DirEntry = bincode::deserialize(&v)?;
                Ok(Some(entry.ino))
            }
            None => Ok(None),
        }
    }

    /// Lista zawartości katalogu.
    ///
    /// Nazwa pliku jest odczytywana BEZPOŚREDNIO z wartości wpisu (pole `DirEntry::name`),
    /// a NIE parsowana ze struktury klucza. Eliminuje błąd oryginalnego `split(':')`.
    pub fn list(&self, parent: u64) -> Result<Vec<(OsString, u64)>, HfsError> {
        let prefix = Self::parent_prefix(parent);
        let mut out = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, v) = item?;
            let entry: DirEntry = bincode::deserialize(&v)?;
            let name = OsString::from(OsStr::from_bytes(&entry.name));
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

/// Kodowanie base64url bez paddingu (RFC 4648 §5).
/// Używa znaków [A-Za-z0-9-_] — żadnych dwukropków.
fn base64_url_encode(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity((input.len() * 4 + 2) / 3);
    let mut i   = 0;
    while i < input.len() {
        let b0 = input[i] as usize;
        let b1 = if i + 1 < input.len() { input[i + 1] as usize } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as usize } else { 0 };
        out.push(TABLE[(b0 >> 2) & 0x3F]);
        out.push(TABLE[((b0 << 4) | (b1 >> 4)) & 0x3F]);
        if i + 1 < input.len() { out.push(TABLE[((b1 << 2) | (b2 >> 6)) & 0x3F]); }
        if i + 2 < input.len() { out.push(TABLE[b2 & 0x3F]); }
        i += 3;
    }
    String::from_utf8(out).unwrap_or_default()
}
