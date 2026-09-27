use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use blake3::Hasher;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sled::Db;

use crate::crypto::Key;
use crate::error::HfsError;
use crate::kdf::KdfParams;
use crate::superblock::Superblock;

const MAGIC: &[u8; 8] = b"GFSBK001";
const FRAME_AAD_PREFIX: &[u8] = b"GFSBK";
const NONCE_SIZE: usize = 12;
/// Ile wpisów sled bufferujemy w jednej ramce przed zaszyfrowaniem —
/// kompromis między narzutem AEAD (per-ramka) a zużyciem pamięci.
const ENTRIES_PER_FRAME: usize = 256;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BackupHeader {
    pub ghostfs_version: String,
    pub created_at: u64,
    pub volume_uuid: [u8; 16],
    pub block_size: u32,
    /// Jeżeli backup jest przyrostowy (tylko wybrane inode), None = pełny.
    pub incremental_since_seq: Option<u64>,
    pub entry_count: u64,
    /// True jeśli plik zaszyfrowano osobnym hasłem backupu (nie wrapping_key
    /// wolumenu źródłowego). Jeśli true, `backup_kdf_params` musi być Some —
    /// pozwala to odtworzyć transport_key z samego hasła backupu, NAWET
    /// jeśli oryginalny wolumin/device już nie istnieje (utrata dysku).
    pub custom_passphrase: bool,
    pub backup_kdf_params: Option<KdfParams>,
    /// KDF params wolumenu ŹRÓDŁOWEGO — zapisywane zawsze (jeśli dostępne
    /// w superblocku w momencie eksportu), tak by w trybie domyślnym
    /// (custom_passphrase=false, transport_key = wrapping_key wolumenu)
    /// restore mógł odtworzyć master key z samej PASSPHRASE użytkownika,
    /// bez potrzeby posiadania oryginalnego pliku wolumenu.
    pub source_kdf_params: Option<KdfParams>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    key: Vec<u8>,
    value: Vec<u8>,
}

pub struct Backup;

impl Backup {
    /// Pełny eksport wolumenu do pliku `output`.
    ///
    /// `transport_key` — klucz szyfrujący sam plik backupu (patrz moduł doc).
    /// Zwraca nagłówek zapisanego backupu (przydatne do logowania/audytu).
    pub fn export_full(
        db: &Db,
        volume_uuid: [u8; 16],
        block_size: u32,
        transport_key: &Key,
        custom_passphrase: bool,
        backup_kdf_params: Option<KdfParams>,
        output: &Path,
    ) -> Result<BackupHeader, HfsError> {
        let source_kdf_params = Superblock::load_kdf_params(db).ok();
        Self::export_filtered(
            db, volume_uuid, block_size, transport_key, custom_passphrase,
            backup_kdf_params, source_kdf_params, output, None, |_k| true,
        )
    }

    /// Eksport przyrostowy — tylko wpisy dotyczące podanego zbioru inode
    /// (np. wyliczonego z `Forensics`/`Audit` logu od danego `since_seq`).
    /// Zawsze eksportuje też metadane globalne (superblock, quota, mac
    /// clearances) — te są małe i tanie, a ich brak uniemożliwiłby restore.
    #[allow(clippy::too_many_arguments)]
    pub fn export_incremental(
        db: &Db,
        volume_uuid: [u8; 16],
        block_size: u32,
        transport_key: &Key,
        custom_passphrase: bool,
        backup_kdf_params: Option<KdfParams>,
        output: &Path,
        since_seq: u64,
        changed_inodes: &[u64],
    ) -> Result<BackupHeader, HfsError> {
        let source_kdf_params = Superblock::load_kdf_params(db).ok();
        let inodes: std::collections::HashSet<u64> = changed_inodes.iter().copied().collect();
        Self::export_filtered(
            db, volume_uuid, block_size, transport_key, custom_passphrase,
            backup_kdf_params, source_kdf_params, output,
            Some(since_seq),
            move |key: &[u8]| Self::key_belongs_to(key, &inodes),
        )
    }

    /// Czy dany klucz sled dotyczy jednego z `inodes` (per-plikowe prefiksy)
    /// lub jest metadaną globalną, którą zawsze trzeba zachować.
    fn key_belongs_to(key: &[u8], inodes: &std::collections::HashSet<u64>) -> bool {
        let s = String::from_utf8_lossy(key);
        // Metadane globalne — zawsze dołączane, niezależnie od filtru.
        const GLOBAL_PREFIXES: &[&str] = &[
            "sb:", "next_ino", "quota:", "mac:clearance:", "canary:",
            "rekey:", "audit:", "forensics:", "ids:profile:",
        ];
        if GLOBAL_PREFIXES.iter().any(|p| s.starts_with(p)) {
            return true;
        }
        // Klucze per-inode mają wzorzec "<prefix>:<ino>[:...]" lub "<prefix>:<ino>".
        for prefix in &["inode:", "data:", "dir:", "xattr:", "mac:label:", "itree:",
                        "ext:", "ext_idx:", "hash:", "ref:", "versions:"] {
            if let Some(rest) = s.strip_prefix(prefix) {
                let ino_part = rest.split(':').next().unwrap_or("");
                if let Ok(ino) = ino_part.parse::<u64>() {
                    return inodes.contains(&ino);
                }
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn export_filtered<F>(
        db: &Db,
        volume_uuid: [u8; 16],
        block_size: u32,
        transport_key: &Key,
        custom_passphrase: bool,
        backup_kdf_params: Option<KdfParams>,
        source_kdf_params: Option<KdfParams>,
        output: &Path,
        incremental_since_seq: Option<u64>,
        filter: F,
    ) -> Result<BackupHeader, HfsError>
    where
        F: Fn(&[u8]) -> bool,
    {
        if output.exists() {
            return Err(HfsError::BackupError(format!(
                "{} already exists — refusing to overwrite", output.display()
            )));
        }

        // Policz wpisy z góry, żeby zapisać poprawny entry_count w nagłówku
        // (nagłówek musi poprzedzać payload, więc nie możemy dopisać go na końcu).
        let mut entry_count: u64 = 0;
        for item in db.iter() {
            let (k, _) = item.map_err(HfsError::Sled)?;
            if filter(&k) { entry_count += 1; }
        }

        let header = BackupHeader {
            ghostfs_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: now_secs(),
            volume_uuid,
            block_size,
            incremental_since_seq,
            entry_count,
            custom_passphrase,
            backup_kdf_params,
            source_kdf_params,
        };

        let file = File::create(output).map_err(HfsError::Io)?;
        let mut w = BufWriter::new(file);

        w.write_all(MAGIC).map_err(HfsError::Io)?;
        let header_bytes = bincode::serialize(&header)?;
        w.write_all(&(header_bytes.len() as u32).to_le_bytes()).map_err(HfsError::Io)?;
        w.write_all(&header_bytes).map_err(HfsError::Io)?;

        let header_hmac = keyed_hash(transport_key, b"ghostfs-backup-header-v1", &header_bytes);
        w.write_all(&header_hmac).map_err(HfsError::Io)?;

        let cipher = Aes256Gcm::new_from_slice(transport_key).map_err(|_| HfsError::CryptoError)?;
        let mut stream_hasher = Hasher::new();
        let mut buf: Vec<Entry> = Vec::with_capacity(ENTRIES_PER_FRAME);
        let mut frame_idx: u64 = 0;
        let mut written: u64 = 0;

        for item in db.iter() {
            let (k, v) = item.map_err(HfsError::Sled)?;
            if !filter(&k) { continue; }
            buf.push(Entry { key: k.to_vec(), value: v.to_vec() });
            if buf.len() >= ENTRIES_PER_FRAME {
                write_frame(&mut w, &cipher, &mut stream_hasher, frame_idx, &buf)?;
                written += buf.len() as u64;
                buf.clear();
                frame_idx += 1;
            }
        }
        if !buf.is_empty() {
            write_frame(&mut w, &cipher, &mut stream_hasher, frame_idx, &buf)?;
            written += buf.len() as u64;
        }

        // Finalny checksum całego (niezaszyfrowanego) strumienia wpisów —
        // pozwala wykryć manipulację/uszkodzenie NIEZALEŻNIE od AEAD tagów
        // per-ramka (obrona w głąb: ktoś z transport_key mógłby usunąć
        // ramki z końca pliku — final checksum + entry_count w nagłówku
        // razem to wykrywają).
        w.write_all(stream_hasher.finalize().as_bytes()).map_err(HfsError::Io)?;
        w.flush().map_err(HfsError::Io)?;

        log::info!(
            "GhostFS backup: exported {} entries ({}) → {}",
            written,
            if incremental_since_seq.is_some() { "incremental" } else { "full" },
            output.display()
        );
        Ok(header)
    }

    /// Odczytaj tylko nagłówek backupu — bez deszyfrowania payloadu.
    /// Przydatne by pokazać użytkownikowi "co to za backup" przed restore.
    pub fn read_header(input: &Path) -> Result<BackupHeader, HfsError> {
        let mut f = File::open(input).map_err(HfsError::Io)?;
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic).map_err(HfsError::Io)?;
        if &magic != MAGIC {
            return Err(HfsError::BackupCorrupted);
        }
        let mut len_buf = [0u8; 4];
        f.read_exact(&mut len_buf).map_err(HfsError::Io)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut header_bytes = vec![0u8; len];
        f.read_exact(&mut header_bytes).map_err(HfsError::Io)?;
        let header: BackupHeader = bincode::deserialize(&header_bytes)?;
        Ok(header)
    }

    /// Zaimportuj backup do NOWEJ (musi nie istnieć) bazy sled pod `new_db_path`.
    /// Zwraca liczbę zaimportowanych wpisów.
    pub fn import(
        input: &Path,
        new_db_path: &Path,
        transport_key: &Key,
    ) -> Result<u64, HfsError> {
        if new_db_path.exists() {
            return Err(HfsError::BackupError(format!(
                "{} already exists — restore refuses to overwrite an existing volume; \
                 restore to a fresh path, then swap it in manually.",
                new_db_path.display()
            )));
        }

        let mut f = BufReader::new(File::open(input).map_err(HfsError::Io)?);

        let mut magic = [0u8; 8];
        f.read_exact(&mut magic).map_err(HfsError::Io)?;
        if &magic != MAGIC { return Err(HfsError::BackupCorrupted); }

        let mut len_buf = [0u8; 4];
        f.read_exact(&mut len_buf).map_err(HfsError::Io)?;
        let hlen = u32::from_le_bytes(len_buf) as usize;
        let mut header_bytes = vec![0u8; hlen];
        f.read_exact(&mut header_bytes).map_err(HfsError::Io)?;
        let header: BackupHeader = bincode::deserialize(&header_bytes)?;

        let mut stored_hmac = [0u8; 32];
        f.read_exact(&mut stored_hmac).map_err(HfsError::Io)?;
        let expected_hmac = keyed_hash(transport_key, b"ghostfs-backup-header-v1", &header_bytes);
        if constant_time_eq(&expected_hmac, &stored_hmac).not() {
            return Err(HfsError::BackupError(
                "Header HMAC mismatch — wrong backup passphrase/key or tampered file".into()
            ));
        }

        if header.ghostfs_version.split('.').next() != env!("CARGO_PKG_VERSION").split('.').next() {
            log::warn!(
                "GhostFS restore: backup was created by version {} (running {}) — proceeding, \
                 but verify compatibility.",
                header.ghostfs_version, env!("CARGO_PKG_VERSION")
            );
        }

        let db = sled::open(new_db_path)?;
        let cipher = Aes256Gcm::new_from_slice(transport_key).map_err(|_| HfsError::CryptoError)?;
        let mut stream_hasher = Hasher::new();
        let mut imported: u64 = 0;
        let mut frame_idx: u64 = 0;
        let mut batch = sled::Batch::default();

        loop {
            let mut len_buf = [0u8; 4];
            match f.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(HfsError::Io(e)),
            };
            // Ostatnie 32 bajty pliku to checksum, nie ramka — wykrywamy to
            // przez próbę: jeśli frame_len wskazywałby poza plik, cofamy się.
            let frame_len = u32::from_le_bytes(len_buf) as usize;
            if frame_len == 0 || frame_len > 64 * 1024 * 1024 {
                // Prawdopodobnie trafiliśmy na końcowy checksum — cofnij i przerwij pętlę ramek.
                break;
            }
            let mut frame = vec![0u8; frame_len];
            f.read_exact(&mut frame).map_err(HfsError::Io)?;

            let nonce = Nonce::from_slice(&frame[..NONCE_SIZE]);
            let mut aad = Vec::with_capacity(FRAME_AAD_PREFIX.len() + 8);
            aad.extend_from_slice(FRAME_AAD_PREFIX);
            aad.extend_from_slice(&frame_idx.to_le_bytes());
            let plaintext = cipher
                .decrypt(nonce, Payload { msg: &frame[NONCE_SIZE..], aad: &aad })
                .map_err(|_| HfsError::BackupError(
                    "Frame decryption failed — wrong key or corrupted backup".into()
                ))?;
            stream_hasher.update(&plaintext);

            let entries: Vec<Entry> = bincode::deserialize(&plaintext)?;
            for e in entries {
                batch.insert(e.key, e.value);
                imported += 1;
                if imported % 4096 == 0 {
                    db.apply_batch(std::mem::take(&mut batch))?;
                }
            }
            frame_idx += 1;
        }
        db.apply_batch(batch)?;
        db.flush()?;

        if imported != header.entry_count {
            log::warn!(
                "GhostFS restore: imported {} entries but header declares {} — \
                 this is expected for incremental backups restored onto a fresh volume \
                 (they intentionally omit unaffected inodes), but unexpected for full backups.",
                imported, header.entry_count
            );
        }

        log::info!(
            "GhostFS restore: imported {} entries from backup created {} (volume_uuid={})",
            imported, header.created_at, hex::encode(header.volume_uuid)
        );
        Ok(imported)
    }
}

fn write_frame(
    w: &mut impl Write,
    cipher: &Aes256Gcm,
    stream_hasher: &mut Hasher,
    frame_idx: u64,
    entries: &[Entry],
) -> Result<(), HfsError> {
    // NB: entries used tylko przez referencję — serializujemy kopię,
    // bo Entry nie implementuje Clone (świadomie, by uniknąć przypadkowych
    // kopii sekretnych bajtów danych w pamięci dłużej niż to konieczne).
    let plaintext = bincode::serialize(entries)?;
    stream_hasher.update(&plaintext);

    let nonce_bytes: [u8; NONCE_SIZE] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut aad = Vec::with_capacity(FRAME_AAD_PREFIX.len() + 8);
    aad.extend_from_slice(FRAME_AAD_PREFIX);
    aad.extend_from_slice(&frame_idx.to_le_bytes());
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| HfsError::CryptoError)?;

    let mut frame = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    frame.extend_from_slice(&nonce_bytes);
    frame.extend_from_slice(&ciphertext);

    w.write_all(&(frame.len() as u32).to_le_bytes()).map_err(HfsError::Io)?;
    w.write_all(&frame).map_err(HfsError::Io)?;
    Ok(())
}

fn keyed_hash(key: &Key, context: &[u8], data: &[u8]) -> [u8; 32] {
    let mut ctx_hasher = Hasher::new_keyed(key);
    ctx_hasher.update(context);
    let subkey = *ctx_hasher.finalize().as_bytes();
    let mut mac = Hasher::new_keyed(&subkey);
    mac.update(data);
    *mac.finalize().as_bytes()
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> ConstBool {
    ConstBool(a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0)
}

/// Mały wrapper by uniknąć przypadkowego `if x == false` (clippy) i
/// jednocześnie zostawić czytelne `.not()` w miejscu użycia.
struct ConstBool(bool);
impl ConstBool {
    fn not(self) -> bool { !self.0 }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
