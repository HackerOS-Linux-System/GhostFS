#[path = "../core/error.rs"]            pub mod error;
#[path = "../core/serialization.rs"]    pub mod serialization;
#[path = "../core/cache.rs"]            pub mod cache;
#[path = "../core/journal.rs"]          pub mod journal;
#[path = "../core/prefetch.rs"]         pub mod prefetch;
#[path = "../data/backup.rs"]           pub mod backup;
#[path = "fs.rs"]                       pub mod fs;
#[path = "extents.rs"]                  pub mod extents;
#[path = "dirindex.rs"]                 pub mod dirindex;
#[path = "xattr.rs"]                    pub mod xattr;
#[path = "../data/compression.rs"]      pub mod compression;
#[path = "../data/deduplication.rs"]    pub mod deduplication;
#[path = "../data/versioning.rs"]       pub mod versioning;
#[path = "../data/repair.rs"]           pub mod repair;
#[path = "../audit/audit.rs"]           pub mod audit;
#[path = "../audit/quota.rs"]           pub mod quota;
#[path = "../security/crypto.rs"]       pub mod crypto;
#[path = "../security/integrity.rs"]    pub mod integrity;
#[path = "../security/mac.rs"]          pub mod mac;
#[path = "../security/ids.rs"]          pub mod ids;
#[path = "../security/forensics.rs"]    pub mod forensics;
#[path = "../security/kdf.rs"]          pub mod kdf;
#[path = "../security/superblock.rs"]   pub mod superblock;
#[path = "../security/secure_delete.rs"]pub mod secure_delete;
#[path = "../security/rate_limit.rs"]   pub mod rate_limit;
#[path = "../security/canary.rs"]       pub mod canary;
#[path = "../security/tpm.rs"]          pub mod tpm;
#[path = "../security/grpc_forensics.rs"]pub mod grpc_forensics;
#[path = "../security/response.rs"]     pub mod response;
#[path = "../security/worm.rs"]         pub mod worm;
#[path = "../security/signing.rs"]      pub mod signing;
#[path = "../security/syslog.rs"]       pub mod syslog;
#[path = "../security/ransomware.rs"]   pub mod ransomware;
#[path = "../security/shamir.rs"]       pub mod shamir;
#[path = "../security/memlock.rs"]      pub mod memlock;

pub use error::HfsError;
pub use crypto::Key;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use sled::Db;
use anyhow::{Context, Result};
use crossbeam::channel::Sender;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::compression::{Compression, CompressionType};
use crate::deduplication::Deduplication;
use crate::versioning::Versioning;
use crate::audit::Audit;
use crate::quota::Quota;
use crate::xattr::XAttr;
use crate::repair::Repair;
use crate::cache::Cache;
use crate::journal::Journal;
use crate::extents::ExtentTree;
use crate::dirindex::DirIndex;
use crate::crypto::Crypto;
use crate::integrity::IntegrityTree;
use crate::mac::MacLabels;
use crate::ids::Ids;
use crate::forensics::Forensics;
use crate::secure_delete::SecureDelete;
use crate::rate_limit::RateLimiter;
use crate::response::{AutoResponse, ResponseAction};
use crate::worm::Worm;
use crate::ransomware::RansomwareGuard;
use crate::syslog::SyslogSender;
use crate::superblock::Superblock;
use crate::canary::Canary;
use crate::prefetch::Prefetcher;

pub const FS_BLOCK_SIZE: u32 = 4096;
pub const ROOT_INO: u64      = 1;
pub const TTL: std::time::Duration = std::time::Duration::from_secs(1);

pub struct GhostFS {
    pub(crate) db:          Db,
    pub(crate) next_ino:    AtomicU64,
    // Security
    pub(crate) crypto:      Crypto,
    pub(crate) integrity:   IntegrityTree,
    pub(crate) mac:         MacLabels,
    pub(crate) ids:         Ids,
    pub(crate) forensics:   Forensics,
    pub(crate) secure_del:  SecureDelete,
    pub(crate) canary:      Canary,
    pub         rate_limit: RateLimiter,
    /// fsfreeze flag — gdy true wszystkie I/O zwracają EIO
    pub(crate) frozen:      Arc<AtomicBool>,
    /// Automatyczna reakcja na powtarzające się alerty IDS (warn → lockout).
    pub(crate) auto_response: AutoResponse,
    /// WORM/immutable — patrz `security/worm.rs`.
    pub(crate) worm: Worm,
    /// Behawioralna detekcja ransomware (entropia + tempo zapisów) —
    /// patrz `security/ransomware.rs`.
    pub(crate) ransomware_guard: RansomwareGuard,
    /// SIEM (syslog) — używane bezpośrednio tu tylko do opcjonalnego
    /// strumieniowania pełnego audytu (patrz `log_audit`); alerty
    /// bezpieczeństwa (IDS lockout, canary, ransomware) mają WŁASNE
    /// instancje wewnątrz odpowiednich modułów.
    pub(crate) syslog: SyslogSender,
    // Core
    pub(crate) compression: Compression,
    pub(crate) dedup:       Deduplication,
    pub(crate) versioning:  Versioning,
    pub(crate) audit:       Audit,
    pub(crate) quota:       Quota,
    pub(crate) xattr:       XAttr,
    #[allow(dead_code)]
    pub(crate) repair:      Repair,
    pub(crate) cache:       Cache,
    pub(crate) journal:     Journal,
    pub(crate) extents:     ExtentTree,
    pub(crate) dirindex:    DirIndex,
    pub(crate) noatime:     bool,
    /// Równoległy odczyt wyprzedzający dla sekwencyjnych wzorców dostępu.
    pub(crate) prefetcher:  Prefetcher,
    #[allow(dead_code)]
    pub(crate) background_repair_sender: Option<Sender<()>>,
}

impl GhostFS {
    pub fn new(
        db_path:          &Path,
        key:              Key,
        compression_type: Option<String>,
        noatime:          bool,
    ) -> Result<Self> {
        let db = sled::open(db_path)
            .with_context(|| format!("Failed to open database at {}", db_path.display()))?;

        // ── Fail-closed superblock verification ─────────────────────────────
        // Wcześniej: żadna weryfikacja hasła/klucza przy mouncie — błędne
        // hasło "montowało się" bez błędu i dopiero pierwszy odczyt bloku
        // kończył się AEAD auth failure (myląca diagnostyka, i co gorsza:
        // operacje METADANYCH — readdir, getattr — działałyby normalnie na
        // NIEZASZYFROWANYCH inode'ach, dając fałszywe poczucie że mount się
        // udał). Teraz: jeśli superblock istnieje, MUSI zweryfikować HMAC
        // pod podanym kluczem, inaczej odmawiamy mountu od razu.
        //
        // `volume_uuid` jest też odczytywany stąd (patrz superblock.rs) —
        // NIE generowany losowo per-mount jak wcześniej, co gwarantuje że
        // dane zapisane w poprzedniej sesji nadal się odszyfrują.
        let volume_uuid = match db.get(b"sb:data")? {
            Some(_) => {
                let sb = Superblock::load_and_verify(&db, &key)
                    .context("Superblock HMAC verification failed — wrong passphrase/key-file, \
                              or the volume metadata has been tampered with. Refusing to mount.")?;
                sb.data.volume_uuid
            }
            None => {
                // Brak superblocka — wolumin utworzony bez `ghostfs mkfs` (np.
                // testowa baza sled) lub bardzo stary format. Nie blokujemy
                // mountu (backward-compat), ale losowy UUID oznacza że dane
                // zapisane w TEJ sesji nie przetrwają kolejnego mountu bez
                // superblocka — logujemy to głośno.
                log::warn!(
                    "GhostFS: no superblock found at {} — mounting WITHOUT verified volume_uuid. \
                     Run 'ghostfs mkfs' to create a proper superblock; data written this session \
                     will not survive a remount without one.", db_path.display()
                );
                rand::random()
            }
        };

        let crypto = Crypto::new_with_uuid(key, volume_uuid)?;

        let compression = Compression::new(match compression_type.as_deref() {
            Some("zlib") => CompressionType::Zlib,
            #[cfg(feature = "zstd")]
            Some("zstd") => CompressionType::Zstd,
            #[cfg(feature = "lz4")]
            Some("lz4")  => CompressionType::Lz4,
            _            => CompressionType::None,
        });

        let dedup      = Deduplication::new(&db)?;
        let versioning = Versioning::new(&db)?;
        let mut audit  = Audit::new(&db)?;
        audit.set_signing_key(&key);
        let quota      = Quota::new(&db)?;
        let xattr      = XAttr::new(&db, crypto.clone())?;
        let journal    = Journal::new(&db)?;
        let extents    = ExtentTree::new(&db)?;
        let dirindex   = DirIndex::new(&db, crypto.clone())?;
        let integrity  = IntegrityTree::new(&db)?;
        let mac        = MacLabels::new(&db)?;
        let ids        = Ids::new(&db)?;
        let forensics  = Forensics::new(&db)?;
        let secure_del = SecureDelete::new(&db)?;
        let canary     = Canary::new(&db, &ids)?;
        let rate_limit = RateLimiter::new();
        let auto_response = AutoResponse::new(&db)?;
        if let Some(reason) = auto_response.is_global_lockdown()? {
            return Err(HfsError::VolumeLockedDown(reason)).context(
                "Volume is under manual lockdown — refusing to mount. \
                 Clear with 'ghostfs lockdown disable --device <dev>' once the incident is resolved."
            );
        }
        let worm = Worm::new(&db)?;
        let ransomware_guard = RansomwareGuard::new(&db, &ids)?;
        let syslog = SyslogSender::new(&db)?;
        // Odtwórz stan lockoutów z DB — `RateLimiter::lockout` żyje tylko
        // w pamięci (per-mount), więc bez tego restart mountu resetowałby
        // cichcem wszystkie aktywne blokady UID nałożone przez poprzednią sesję.
        for (uid, locked_at) in auto_response.list_locked()? {
            rate_limit.lock_uid(uid);
            log::warn!("GhostFS: restored lockout for uid={} (locked at ts={})", uid, locked_at);
        }
        let repair     = Repair::new(&db, &Some(crypto.clone()), &compression, &dedup, &versioning)?;
        let cache      = Cache::new();
        let prefetcher = Prefetcher::new();
        let frozen     = Arc::new(AtomicBool::new(false));

        let next_ino = match db.get(b"next_ino")? {
            Some(v) => bincode::deserialize(&v)?,
            None => {
                let mut batch = sled::Batch::default();
                batch.insert(b"next_ino", bincode::serialize(&(ROOT_INO + 1))?);
                let root_attr = fuser::FileAttr {
                    ino: ROOT_INO, size: 0, blocks: 0,
                    atime: std::time::UNIX_EPOCH, mtime: std::time::UNIX_EPOCH,
                    ctime: std::time::UNIX_EPOCH, crtime: std::time::UNIX_EPOCH,
                    kind: fuser::FileType::Directory,
                    perm: 0o755, nlink: 2, uid: 0, gid: 0,
                    rdev: 0, blksize: FS_BLOCK_SIZE, flags: 0,
                };
                batch.insert(
                    format!("inode:{}", ROOT_INO).as_bytes(),
                    bincode::serialize(&serialization::Inode { attr: root_attr.into(), parent: 0 })?,
                );
                db.apply_batch(batch)?;
                ROOT_INO + 1
            }
        };

        let (tx, rx) = crossbeam::channel::unbounded::<()>();
        let repair_clone = repair.clone();
        std::thread::spawn(move || {
            loop {
                // `recv_timeout` zamiast `recv()` — poprzednio wątek czekał
                // NA ZAWSZE na sygnał z `tx`, którego nikt nigdy nie wysyłał
                // (background_repair_sender był tworzony, ale nigdzie w
                // kodzie nie wołano `.send(())`), więc automatyczna naprawa
                // w tle faktycznie NIGDY się nie uruchamiała. Teraz: odpala
                // się co godzinę samoistnie, a `tx` wciąż pozwala na
                // wcześniejsze, manualne wybudzenie (np. przyszłe
                // `ghostfs repair now` przez kanał administracyjny).
                let _ = rx.recv_timeout(std::time::Duration::from_secs(3600));
                if let Err(e) = repair_clone.scan_and_repair() {
                    log::error!("Background repair failed: {}", e);
                }
            }
        });

        // ── Dead man's switch ────────────────────────────────────────────
        // Okresowo (domyślnie co 10 minut) weryfikuje w tle łańcuchy HMAC
        // audytu i hash-chain forensics BEZ czekania na `ghostfs verify`
        // uruchomiony ręcznie. Jeśli którykolwiek jest naruszony —
        // NATYCHMIAST zamraża wolumin (`freeze()`, ten sam mechanizm co
        // ręczny "live forensics snapshot") i wysyła krytyczny alert do
        // SIEM. Zamrożenie jest świadomie agresywne: skoro ktoś potrafił
        // zmanipulować hash-chain (co samo w sobie wymaga dostępu do
        // wewnętrznych struktur DB, nie tylko FUSE), dalsza praca na
        // wolumenie może zacierać ślady lub pogłębiać szkodę — bezpieczniej
        // zatrzymać I/O i zmusić administratora do świadomej decyzji
        // (offline `ghostfs verify` + świadomy remount) niż działać dalej.
        // `frozen` żyje tylko w pamięci TEGO procesu (nie w DB) — nie ma
        // API "unfreeze na żywo"; recovery to zawsze: zbadaj offline, potem
        // odmontuj/zamontuj ponownie. To celowe — brak żywego "unfreeze"
        // wyklucza scenariusz, w którym atakujący z dostępem do tego samego
        // procesu po prostu cofa zamrożenie.
        let dms_forensics = forensics.clone();
        let dms_audit     = audit.clone();
        let dms_frozen    = frozen.clone();
        let dms_syslog    = crate::syslog::SyslogSender::new(&db)?;
        std::thread::spawn(move || {
            const CHECK_INTERVAL_SECS: u64 = 600;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(CHECK_INTERVAL_SECS));
                if dms_frozen.load(std::sync::atomic::Ordering::SeqCst) {
                    continue; // już zamrożone (ręcznie lub przez wcześniejszą detekcję)
                }
                let audit_ok     = dms_audit.verify_signatures().is_ok();
                let forensics_ok = dms_forensics.verify_chain().is_ok();
                if !audit_ok || !forensics_ok {
                    log::error!(
                        "GhostFS DEAD MAN'S SWITCH: integrity violation detected \
                         (audit_ok={}, forensics_ok={}) — FREEZING volume (read/write and all \
                         mutating operations now return EIO). This flag lives only in this \
                         mount's memory — to recover: 1) investigate offline with \
                         'ghostfs verify --device <dev>' (safe, does not need this mount), \
                         2) if the cause is understood/resolved, unmount and remount \
                         (a fresh mount starts unfrozen). There is no live 'unfreeze' command \
                         by design — resuming I/O on a volume with an unresolved chain \
                         violation without a deliberate remount is exactly what this switch \
                         exists to prevent.",
                        audit_ok, forensics_ok
                    );
                    dms_syslog.send(
                        crate::syslog::Severity::Emergency, "CHAIN_VIOLATION",
                        &format!("volume auto-frozen: audit_ok={} forensics_ok={}", audit_ok, forensics_ok),
                    );
                    dms_frozen.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        journal.recover(&db)?;

        Ok(Self {
            db, next_ino: AtomicU64::new(next_ino),
            crypto, integrity, mac, ids, forensics, secure_del, canary, rate_limit, frozen,
            auto_response, worm, ransomware_guard, syslog,
            compression, dedup, versioning, audit, quota, xattr,
            repair, cache, noatime, prefetcher,
            background_repair_sender: Some(tx),
            journal, extents, dirindex,
        })
    }

    /// Zamroź wszystkie operacje I/O (live forensics snapshot).
    /// Po wywołaniu read/write zwracają EIO dopóki unfreeze() nie zostanie wywołane.
    pub fn freeze(&self) {
        self.frozen.store(true, std::sync::atomic::Ordering::SeqCst);
        self.db.flush().ok();
        log::info!("GhostFS: filesystem frozen for forensics snapshot");
    }

    /// Odmroź operacje I/O.
    pub fn unfreeze(&self) {
        self.frozen.store(false, std::sync::atomic::Ordering::SeqCst);
        log::info!("GhostFS: filesystem unfrozen");
    }

    pub fn zeroize_keys(&mut self) {
        self.crypto.zeroize();
        log::info!("GhostFS: cryptographic keys zeroed from memory");
    }

    // ── Inode ops ─────────────────────────────────────────────────────────────

    /// Zaszyfruj strukturę `Inode` (metadane: rozmiar, uprawnienia, czasy,
    /// uid/gid) do postaci gotowej do zapisu jako wartość klucza sled
    /// `inode:{ino}`. Patrz `Crypto::derive_inode_enc_key` dla uzasadnienia.
    pub(crate) fn encrypt_inode(&self, inode: &serialization::Inode) -> Result<Vec<u8>, HfsError> {
        let plain = bincode::serialize(inode)?;
        let key = self.crypto.derive_inode_enc_key();
        self.crypto.encrypt_with_key(&key, &plain)
    }

    /// Odwrotność `encrypt_inode` — wołane przez `get_inode` oraz przez
    /// `data/repair.rs`, który (w przeciwieństwie do `data/versioning.rs`,
    /// które kopiuje bajty inode 1:1 jako nieprzezroczysty blob i NIE
    /// wymaga zmian) musi znać `attr.size`, więc realnie deserializuje.
    pub(crate) fn decrypt_inode(&self, raw: &[u8]) -> Result<serialization::Inode, HfsError> {
        let key = self.crypto.derive_inode_enc_key();
        let plain = self.crypto.decrypt_with_key(&key, raw)?;
        Ok(bincode::deserialize(&plain)?)
    }

    pub(crate) fn get_inode(&mut self, ino: u64) -> Result<Option<serialization::Inode>, HfsError> {
        if let Some(cached) = self.cache.get_inode(ino) { return Ok(Some(cached)); }
        match self.db.get(format!("inode:{}", ino).as_bytes())? {
            Some(b) => {
                let inode = self.decrypt_inode(&b)?;
                self.cache.put_inode(ino, inode.clone());
                Ok(Some(inode))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn put_inode(&mut self, ino: u64, inode: &serialization::Inode) -> Result<(), HfsError> {
        let enc = self.encrypt_inode(inode)?;
        self.db.insert(format!("inode:{}", ino).as_bytes(), enc)?;
        self.cache.put_inode(ino, inode.clone());
        Ok(())
    }

    pub(crate) fn lookup_name(&self, parent: u64, name: &OsStr) -> Result<Option<u64>, HfsError> {
        if let Some(ino) = self.dirindex.lookup(parent, name)? { return Ok(Some(ino)); }
        // Fallback WYŁĄCZNIE dla wpisów zapisanych przez wersje GhostFS
        // sprzed szyfrowania nazw katalogów (< v0.4) — te NIGDY nie trafiły
        // do zaszyfrowanego dirindex, tylko do tego jawnego klucza. Od v0.4
        // żaden kod już tu NIE PISZE (patrz historia fs.rs) — to czysta
        // ścieżka odczytu dla migracji, nie aktywny mechanizm przechowywania.
        match self.db.get(format!("dir:{}:{}", parent, String::from_utf8_lossy(name.as_bytes())).as_bytes())? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None    => Ok(None),
        }
    }

    // ── Block ops ─────────────────────────────────────────────────────────────

    pub(crate) fn get_block(&mut self, ino: u64, block_idx: usize) -> Result<Vec<u8>, HfsError> {
        if let Some(cached) = self.cache.get_block(ino, block_idx) { return Ok(cached); }
        let pk  = self.extents.resolve(ino, block_idx).unwrap_or_else(|| format!("data:{}:{}", ino, block_idx));
        let raw = match self.db.get(pk.as_bytes())? {
            Some(d) => d.to_vec(),
            None    => return Ok(vec![0u8; FS_BLOCK_SIZE as usize]),
        };
        let fek          = self.crypto.derive_fek(ino);
        let decrypted    = self.crypto.decrypt_with_key(&fek, &raw)?;
        let decompressed = self.compression.decompress(&decrypted)?;
        self.dedup.verify(ino, block_idx, &decompressed)?;
        self.integrity.verify_block(ino, block_idx, &decompressed)?;
        self.cache.put_block(ino, block_idx, decompressed.clone());

        // Sekwencyjny wzorzec? Zleć odczyt kolejnych bloków w tle (rayon).
        // Non-blocking — nie opóźnia odpowiedzi na bieżące żądanie FUSE.
        self.prefetcher.on_block_read(
            ino, block_idx, &self.db, &self.crypto, &self.compression,
            &self.dedup, &self.integrity, &self.extents, &self.cache,
        );

        Ok(decompressed)
    }

    pub(crate) fn put_block(&mut self, ino: u64, block_idx: usize, data: &[u8]) -> Result<(), HfsError> {
        if let Some((oi, ob)) = self.dedup.find_duplicate(data)? {
            self.dedup.add_reference(ino, block_idx, oi, ob)?;
            return Ok(());
        }
        let fek       = self.crypto.derive_fek(ino);
        let compressed = self.compression.compress(data)?;
        let encrypted  = self.crypto.encrypt_with_key(&fek, &compressed)?;
        let key        = format!("data:{}:{}", ino, block_idx);
        let before     = self.db.get(key.as_bytes())?.map(|v| v.to_vec());
        let after      = Some(encrypted.clone());
        self.journal.log_write(ino, block_idx, &before, &after)?;
        self.db.insert(key.as_bytes(), encrypted)?;
        self.dedup.insert_hash(ino, block_idx, data)?;
        self.extents.record(ino, block_idx, &key)?;
        self.cache.put_block(ino, block_idx, data.to_vec());
        self.integrity.update_block(ino, block_idx, data)?;
        Ok(())
    }

    pub(crate) fn remove_block(&mut self, ino: u64, block_idx: usize) -> Result<(), HfsError> {
        let key = format!("data:{}:{}", ino, block_idx);
        self.secure_del.wipe_block(&self.db, &key)?;
        self.cache.remove_block(ino, block_idx);
        self.dedup.remove_reference(ino, block_idx)?;
        self.extents.remove(ino, block_idx)?;
        self.integrity.remove_block(ino, block_idx)?;
        Ok(())
    }

    pub(crate) fn read_data(&mut self, ino: u64, offset: i64, size: u32) -> Result<Vec<u8>, HfsError> {
        let mut result   = Vec::with_capacity(size as usize);
        let start_block  = (offset as usize) / FS_BLOCK_SIZE as usize;
        let end_block    = ((offset as usize + size as usize - 1) / FS_BLOCK_SIZE as usize) + 1;
        let inner_offset = (offset as usize) % FS_BLOCK_SIZE as usize;
        for bi in start_block..end_block {
            let mut block = self.get_block(ino, bi)?;
            if bi == start_block { block.drain(0..inner_offset); }
            let take = (size as usize - result.len()).min(block.len());
            result.extend_from_slice(&block[0..take]);
            if result.len() >= size as usize { break; }
        }
        Ok(result)
    }

    pub(crate) fn write_data(&mut self, ino: u64, offset: i64, data: &[u8]) -> Result<u32, HfsError> {
        if data.is_empty() { return Ok(0); }
        let start_block  = (offset as usize) / FS_BLOCK_SIZE as usize;
        let end_block    = ((offset as usize + data.len() - 1) / FS_BLOCK_SIZE as usize) + 1;
        let inner_offset = (offset as usize) % FS_BLOCK_SIZE as usize;
        let mut pos = 0;
        for bi in start_block..end_block {
            let mut block  = self.get_block(ino, bi)?;
            let bstart = if bi == start_block { inner_offset } else { 0 };
            if block.len() < FS_BLOCK_SIZE as usize { block.resize(FS_BLOCK_SIZE as usize, 0); }
            let n = (FS_BLOCK_SIZE as usize - bstart).min(data.len() - pos);
            block[bstart..bstart + n].copy_from_slice(&data[pos..pos + n]);
            self.put_block(ino, bi, &block)?;
            pos += n;
        }
        Ok(data.len() as u32)
    }

    pub(crate) fn update_size(&mut self, ino: u64, new_size: u64) -> Result<(), HfsError> {
        if let Some(mut inode) = self.get_inode(ino)? {
            inode.attr.size = new_size;
            self.put_inode(ino, &inode)?;
        }
        Ok(())
    }

    pub(crate) fn is_dir_empty(&self, ino: u64) -> Result<bool, HfsError> {
        // Sprawdź zaszyfrowany dirindex NAJPIERW (aktywny mechanizm od v0.4).
        // Wcześniej ta funkcja sprawdzała WYŁĄCZNIE stary jawny prefiks
        // "dir:{ino}:" — od kiedy nic już tam nie pisze (patrz `lookup_name`),
        // to zawsze zwracałoby `true` (katalog "pusty"), pozwalając na
        // `rmdir` NIEPUSTEGO katalogu — poważny bug korupcji danych, nie
        // tylko przeoczenie. Legacy prefiks wciąż sprawdzany jako fallback
        // dla wpisów sprzed migracji.
        if !self.dirindex.list(ino)?.is_empty() {
            return Ok(false);
        }
        Ok(self.db.scan_prefix(format!("dir:{}:", ino).as_bytes()).next().is_none())
    }

    pub(crate) fn readdir_entries(&mut self, ino: u64) -> Result<Vec<(u64, fuser::FileType, OsString)>, HfsError> {
        // Uwaga: jeśli katalog ma MIESZANY stan (część wpisów sprzed v0.4 w
        // starym jawnym formacie, część nowych w dirindex — możliwe tylko
        // jeśli entries dodawano zarówno przed jak i po aktualizacji bez
        // pełnej migracji), zwracamy TYLKO wpisy z dirindex, ignorując stare.
        // `is_dir_empty` powyżej sprawdza oba źródła poprawnie; to tylko
        // listowanie zawartości ma ten wąski, rzadki przypadek brzegowy.
        if let Ok(indexed) = self.dirindex.list(ino) {
            if !indexed.is_empty() {
                let mut out = Vec::new();
                for (name, cino) in indexed {
                    if let Some(inode) = self.get_inode(cino)? { out.push((cino, inode.attr.kind.into(), name)); }
                }
                return Ok(out);
            }
        }
        let prefix = format!("dir:{}:", ino);
        let mut out = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (k, v) = item?;
            let ks     = String::from_utf8(k.to_vec())?;
            if !ks.starts_with(&prefix) { break; }
            let name = OsString::from(ks[prefix.len()..].to_string());
            let cino: u64 = bincode::deserialize(&v)?;
            if let Some(inode) = self.get_inode(cino)? { out.push((cino, inode.attr.kind.into(), name)); }
        }
        Ok(out)
    }

    pub(crate) fn check_permission(&mut self, ino: u64, uid: u32, gid: u32, access_mask: i32) -> Result<bool, HfsError> {
        // Globalny lockdown — sprawdzane JAKO PIERWSZE, przed wszystkim
        // innym (nawet przed per-UID lockoutem). Blokuje WSZYSTKICH,
        // łącznie z rootem, bez wyjątku — to "przycisk paniki", nie
        // zwykła kontrola dostępu. Patrz `AutoResponse::enable_global_lockdown`.
        if let Some(reason) = self.auto_response.is_global_lockdown()? {
            return Err(HfsError::VolumeLockedDown(reason));
        }

        // Fail-closed: UID zablokowany przez AutoResponse -> odmowa
        // WSZYSTKIEGO, sprawdzane przed jakąkolwiek inną logiką (MAC/DAC).
        if self.auto_response.is_locked(uid)? {
            return Err(HfsError::UidLockedOut(uid));
        }

        let inode  = self.get_inode(ino)?.ok_or(HfsError::NoEntry)?;

        // Honeytoken check — samo DOTKNIĘCIE oznaczonego inode jest
        // sygnałem intruzji, niezależnie od tego czy MAC/DAC poniżej i tak
        // odrzucą operację. Wołane dla WSZYSTKICH uid (w tym root — patrz
        // `AutoResponse::evaluate`, które celowo nigdy nie blokuje uid=0,
        // ale wciąż loguje/alertuje). Zwrócone `true` wymusza natychmiastową
        // ewaluację auto-response PONIŻEJ zamiast czekać na osobną anomalię
        // z `record_access` — honeytoken nie ma żadnego uzasadnienia
        // dostępu, więc nie ma powodu czekać.
        let canary_hit = self.canary.trigger(ino, uid, access_mask)?;

        let mac_ok = self.mac.check_ct(ino, uid, gid, access_mask)?;
        let mut anomalous = self.ids.record_access(uid, ino, access_mask)? || canary_hit;

        let mode   = inode.attr.perm;
        let dac_ok = if uid == 0                  { true }
            else if uid == inode.attr.uid          { (mode as i32 & access_mask) == access_mask }
            else if gid == inode.attr.gid          { ((mode >> 3) as i32 & access_mask) == access_mask }
            else                                   { ((mode >> 6) as i32 & access_mask) == access_mask };

        // Odmowa MAC to sygnał bezpieczeństwa, nie tylko "brak uprawnień" —
        // ktoś próbował odczytać/zapisać dane spoza swojej klauzuli. Wcześniej
        // to ginęło w `log::debug!` wewnątrz mac.rs bez zasilania IDS.
        if !mac_ok {
            self.ids.add_alert(uid, ino, "MAC policy violation (Bell-LaPadula deny)", access_mask)?;
            anomalous = true;
        }

        if anomalous {
            if self.auto_response.evaluate(&self.ids, &self.rate_limit, uid)? == ResponseAction::LockedOut {
                return Err(HfsError::UidLockedOut(uid));
            }
        }

        Ok(mac_ok & dac_ok)
    }

    pub(crate) fn check_quota(&self, uid: u32, additional: u64) -> Result<(), HfsError> {
        self.quota.check_quota(uid, additional)
    }

    /// Odmawia operacji jeśli inode jest pod ochroną WORM/immutable —
    /// wołane na początku write/truncate/unlink/rename(source)/rmdir
    /// (przez wpis katalogu) w `fs.rs`. Patrz `security/worm.rs`.
    pub(crate) fn ensure_not_worm_locked(&self, ino: u64) -> Result<(), HfsError> {
        if self.worm.is_locked(ino)? {
            return Err(HfsError::WormLocked(ino));
        }
        Ok(())
    }

    pub(crate) fn update_quota(&self, uid: u32, delta: u64) -> Result<(), HfsError> {
        self.quota.update_usage(uid, delta)
    }

    pub(crate) fn log_audit(&self, uid: u32, op: &str, ino: u64, name: Option<&OsStr>) -> Result<(), HfsError> {
        self.audit.log(uid, op, ino, name)?;
        self.forensics.record(uid, op, ino, name)?;
        // Strumieniowanie na żywo do SIEM — opt-in, patrz
        // `SyslogSender::set_stream_audit` dla uzasadnienia i kompromisów.
        if self.syslog.stream_audit_enabled() {
            let name_str = name.map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            self.syslog.send(
                crate::syslog::Severity::Info, "AUDIT",
                &format!("uid={} op={} ino={} name={}", uid, op, ino, name_str),
            );
        }
        Ok(())
    }

    pub(crate) fn create_version(&self, ino: u64) -> Result<(), HfsError> {
        self.versioning.create_version(ino)
    }

    pub(crate) fn with_batch<F>(&self, f: F) -> Result<(), HfsError>
    where F: FnOnce(&mut sled::Batch) -> Result<(), HfsError> {
        let mut batch = sled::Batch::default();
        f(&mut batch)?;
        self.journal.commit_barrier()?;
        self.db.apply_batch(batch)?;
        Ok(())
    }
}

pub fn format(db_path: &Path, master_key: &Key, kdf_params: crate::kdf::KdfParams, block_size: Option<u32>) -> Result<(), HfsError> {
    let db = sled::open(db_path)?;
    let mut batch = sled::Batch::default();
    let bs = block_size.unwrap_or(FS_BLOCK_SIZE);
    batch.insert(b"next_ino", bincode::serialize(&(ROOT_INO + 1))?);
    let root_attr = fuser::FileAttr {
        ino: ROOT_INO, size: 0, blocks: 0,
        atime: std::time::UNIX_EPOCH, mtime: std::time::UNIX_EPOCH,
        ctime: std::time::UNIX_EPOCH, crtime: std::time::UNIX_EPOCH,
        kind: fuser::FileType::Directory,
        perm: 0o755, nlink: 2, uid: 0, gid: 0,
        rdev: 0, blksize: bs, flags: 0,
    };
    // volume_uuid generowany RAZ tutaj i persystowany (patrz superblock.rs
    // doc) — MUSI powstać PRZED zaszyfrowaniem inode roota, bo klucz
    // szyfrujący metadane inode jest z niego derywowany (patrz
    // Crypto::derive_inode_enc_key). GhostFS (i jego pole `crypto`)
    // jeszcze nie istnieje na tym etapie (to funkcja mkfs, nie metoda),
    // więc budujemy tymczasową instancję `Crypto` wyłącznie do tego celu.
    let volume_uuid: [u8; 16] = rand::random();
    let mkfs_crypto = crate::crypto::Crypto::new_with_uuid(*master_key, volume_uuid)?;
    let root_inode = serialization::Inode { attr: root_attr.into(), parent: 0 };
    let root_plain = bincode::serialize(&root_inode)?;
    let root_enc = mkfs_crypto.encrypt_with_key(&mkfs_crypto.derive_inode_enc_key(), &root_plain)?;
    batch.insert(format!("inode:{}", ROOT_INO).as_bytes(), root_enc);
    // Superblock zawiera KDF params i volume_uuid — kluczowe dla round-trip mount.
    let sb = Superblock::new(bs, master_key, kdf_params, volume_uuid)?;
    batch.insert(b"sb:data", bincode::serialize(&sb)?);
    db.apply_batch(batch)?;
    db.flush()?;
    Ok(())
}
