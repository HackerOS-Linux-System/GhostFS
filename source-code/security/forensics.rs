use sled::Db;
use serde::{Serialize, Deserialize};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use blake3::Hasher;
use crate::error::HfsError;

const HEAD_KEY:      &[u8] = b"forensics:head";
const PREV_HASH_KEY: &[u8] = b"forensics:prev_hash";
/// Liczba wpisów per epoka (po zamknięciu epoki wpisy są WORM)
const MAX_EPOCH_ENTRIES: u64 = 1000;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ForensicsEntry {
    pub seq:          u64,
    pub timestamp_us: u128,
    pub uid:          u32,
    pub operation:    String,
    pub ino:          u64,
    pub name:         Option<Vec<u8>>,
    pub prev_hash:    [u8; 32],
    pub self_hash:    [u8; 32],
}

#[derive(Clone)]
pub struct Forensics {
    db:     Db,
    /// Osobne drzewo dla zapieczętowanych epok (WORM)
    sealed: sled::Tree,
}

impl Forensics {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        let sealed = db.open_tree("forensics_sealed")?;
        Ok(Self { db: db.clone(), sealed })
    }

    fn timestamp_us() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_micros()
    }

    fn load_head(&self) -> Result<u64, HfsError> {
        Ok(match self.db.get(HEAD_KEY)? {
            Some(v) => bincode::deserialize(&v)?,
            None    => 0,
        })
    }

    fn load_prev_hash(&self) -> Result<[u8; 32], HfsError> {
        Ok(match self.db.get(PREV_HASH_KEY)? {
            Some(v) if v.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                arr
            }
            _ => [0u8; 32],
        })
    }

    fn compute_hash(e: &ForensicsEntry) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(&e.seq.to_le_bytes());
        h.update(&e.timestamp_us.to_le_bytes());
        h.update(&e.uid.to_le_bytes());
        h.update(e.operation.as_bytes());
        h.update(&e.ino.to_le_bytes());
        if let Some(n) = &e.name { h.update(n); }
        h.update(&e.prev_hash);
        *h.finalize().as_bytes()
    }

    /// Zamknij epokę — oblicz HMAC wszystkich wpisów i zapisz do sealed tree (WORM).
    fn seal_epoch(&self, epoch: u64, start_seq: u64, end_seq: u64) -> Result<(), HfsError> {
        let seal_key = format!("epoch:{}", epoch);
        // Już zapieczętowana?
        if self.sealed.get(seal_key.as_bytes())?.is_some() {
            return Ok(());
        }
        let mut hasher = Hasher::new();
        for seq in start_seq..end_seq {
            let key = format!("forensics:seq:{}", seq);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                hasher.update(&raw);
            }
        }
        let epoch_hash = hasher.finalize();
        // WORM: compare-and-swap — tylko jeśli klucz nie istnieje
        self.sealed.compare_and_swap(
            seal_key.as_bytes(),
            None::<&[u8]>,
            Some(epoch_hash.as_bytes().as_ref()),
        ).map_err(|_| HfsError::InvalidArgument("Epoch seal CAS failed".into()))?
         .map_err(|_| HfsError::InvalidArgument("Epoch already sealed".into()))?;
        log::info!("GhostFS forensics: epoch {} sealed (seq {}..{})", epoch, start_seq, end_seq);
        Ok(())
    }

    pub fn record(&self, uid: u32, operation: &str, ino: u64, name: Option<&OsStr>) -> Result<(), HfsError> {
        let seq       = self.load_head()?;
        let prev_hash = self.load_prev_hash()?;
        let mut entry = ForensicsEntry {
            seq,
            timestamp_us: Self::timestamp_us(),
            uid,
            operation: operation.to_string(),
            ino,
            name: name.map(|n| n.as_bytes().to_vec()),
            prev_hash,
            self_hash: [0u8; 32],
        };
        entry.self_hash = Self::compute_hash(&entry);

        let key = format!("forensics:seq:{}", seq);
        self.db.insert(key.as_bytes(), bincode::serialize(&entry)?)?;
        self.db.insert(HEAD_KEY, bincode::serialize(&(seq + 1))?)?;
        self.db.insert(PREV_HASH_KEY, entry.self_hash.to_vec())?;

        // Zamknij epokę gdy osiągniemy granicę
        if seq > 0 && seq % MAX_EPOCH_ENTRIES == MAX_EPOCH_ENTRIES - 1 {
            let epoch      = seq / MAX_EPOCH_ENTRIES;
            let start_seq  = epoch * MAX_EPOCH_ENTRIES;
            let end_seq    = start_seq + MAX_EPOCH_ENTRIES;
            self.seal_epoch(epoch, start_seq, end_seq)?;
        }
        Ok(())
    }

    /// Weryfikuj łańcuch hash + integralność zapieczętowanych epok.
    pub fn verify_chain(&self) -> Result<u64, HfsError> {
        let head = self.load_head()?;
        let mut expected_prev = [0u8; 32];
        for seq in 0..head {
            let key = format!("forensics:seq:{}", seq);
            let raw = self.db.get(key.as_bytes())?.ok_or(HfsError::CorruptedData)?;
            let entry: ForensicsEntry = bincode::deserialize(&raw)?;
            if entry.prev_hash != expected_prev {
                return Err(HfsError::ForensicsChainBroken(seq));
            }
            if Self::compute_hash(&entry) != entry.self_hash {
                return Err(HfsError::ForensicsChainBroken(seq));
            }
            expected_prev = entry.self_hash;

            // Weryfikuj pieczęć epoki na jej końcu
            if seq > 0 && (seq + 1) % MAX_EPOCH_ENTRIES == 0 {
                let epoch     = seq / MAX_EPOCH_ENTRIES;
                let seal_key  = format!("epoch:{}", epoch);
                let start_seq = epoch * MAX_EPOCH_ENTRIES;
                let end_seq   = start_seq + MAX_EPOCH_ENTRIES;
                if let Some(stored_seal) = self.sealed.get(seal_key.as_bytes())? {
                    let mut hasher = Hasher::new();
                    for s in start_seq..end_seq {
                        let k = format!("forensics:seq:{}", s);
                        if let Some(r) = self.db.get(k.as_bytes())? { hasher.update(&r); }
                    }
                    let computed = hasher.finalize();
                    if computed.as_bytes().as_ref() != stored_seal.as_ref() {
                        return Err(HfsError::ForensicsChainBroken(seq));
                    }
                }
            }
        }
        Ok(head)
    }

    pub fn tail(&self, n: usize) -> Result<Vec<ForensicsEntry>, HfsError> {
        let head  = self.load_head()?;
        let start = head.saturating_sub(n as u64);
        let mut out = Vec::new();
        for seq in start..head {
            let key = format!("forensics:seq:{}", seq);
            if let Some(raw) = self.db.get(key.as_bytes())? {
                if let Ok(e) = bincode::deserialize::<ForensicsEntry>(&raw) { out.push(e); }
            }
        }
        Ok(out)
    }

    /// Eksportuj CAŁY chain-of-custody log do jednego pliku, podpisany
    /// kluczem Ed25519 wolumenu — weryfikowalny przez stronę trzecią
    /// (audytora, sąd) BEZ dostępu do wolumenu ani master key, wyłącznie
    /// na podstawie klucza publicznego przekazanego wcześniej (patrz
    /// `security/signing.rs`). Odmawia eksportu jeśli łańcuch hash jest
    /// naruszony — podpisanie uszkodzonych danych dałoby fałszywe poczucie
    /// autentyczności.
    ///
    /// Format pliku: `b"GFSFOR01"` || u32 LE manifest_len || manifest
    /// (bincode) || payload (bincode-owana lista `ForensicsEntry`, to
    /// dokładnie to, czego hash jest podpisany w manifeście).
    pub fn export_signed(
        &self,
        output: &std::path::Path,
        crypto: &crate::crypto::Crypto,
    ) -> Result<crate::signing::SignedExportManifest, HfsError> {
        let head = self.verify_chain()?;
        let entries = self.tail(head as usize)?;
        let payload = bincode::serialize(&entries)?;
        let payload_hash = *blake3::hash(&payload).as_bytes();

        let signer = crate::signing::ForensicsSigner::load_or_generate(&self.db, crypto)?;
        let signature = signer.sign(&payload_hash);

        let manifest = crate::signing::SignedExportManifest {
            ghostfs_version: env!("CARGO_PKG_VERSION").to_string(),
            exported_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            entry_count: entries.len() as u64,
            payload_hash,
            signature,
            public_key_hex: signer.public_key_hex(),
        };

        let manifest_bytes = bincode::serialize(&manifest)?;
        use std::io::Write;
        let mut file = std::fs::File::create(output)?;
        file.write_all(b"GFSFOR01")?;
        file.write_all(&(manifest_bytes.len() as u32).to_le_bytes())?;
        file.write_all(&manifest_bytes)?;
        file.write_all(&payload)?;
        Ok(manifest)
    }

    /// Odczytaj podpisany eksport i zwróć (manifest, payload) do weryfikacji
    /// przez `signing::verify_signed_export`. Rozdzielone od weryfikacji
    /// celowo — to pozwala audytorowi wczytać plik jednym narzędziem i
    /// zweryfikować innym, bez żadnej zależności od GhostFS/sled.
    pub fn read_signed_export(
        input: &std::path::Path,
    ) -> Result<(crate::signing::SignedExportManifest, Vec<u8>), HfsError> {
        use std::io::Read;
        let mut file = std::fs::File::open(input)?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != b"GFSFOR01" {
            return Err(HfsError::BackupCorrupted);
        }
        let mut len_buf = [0u8; 4];
        file.read_exact(&mut len_buf)?;
        let mlen = u32::from_le_bytes(len_buf) as usize;
        let mut manifest_bytes = vec![0u8; mlen];
        file.read_exact(&mut manifest_bytes)?;
        let manifest: crate::signing::SignedExportManifest = bincode::deserialize(&manifest_bytes)?;
        let mut payload = Vec::new();
        file.read_to_end(&mut payload)?;
        Ok((manifest, payload))
    }
}
