use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use blake3::Hasher;
use rand::Rng;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;
use crate::error::HfsError;

pub type Key = [u8; 32];

const NONCE_SIZE:    usize = 12;
const NONCE_PREFIX_SIZE: usize = 4;
const NONCE_COUNTER_SIZE: usize = NONCE_SIZE - NONCE_PREFIX_SIZE; // 8 bytes
const FEK_CONTEXT:  &[u8] = b"ghostfs-fek-derivation-v1";
const REKEK_CTX:    &[u8] = b"ghostfs-rekey-wrapping-v1";
const DIRENC_CTX:   &[u8] = b"ghostfs-dirname-encryption-v1";
const DIRNAME_BLIND_CTX: &[u8] = b"ghostfs-dirname-blindindex-v1";
const SIGNING_KEY_CTX: &[u8] = b"ghostfs-forensics-signing-key-v1";
const INODE_ENC_CTX: &[u8] = b"ghostfs-inode-metadata-encryption-v1";
const XATTR_ENC_CTX: &[u8] = b"ghostfs-xattr-encryption-v1";
const XATTR_BLIND_CTX: &[u8] = b"ghostfs-xattr-blindindex-v1";

/// AAD = "GFS" || ino (8B LE) || block_idx (8B LE) || volume_uuid (16B)
/// Wiąże szyfrogram z konkretnym blokiem konkretnego pliku konkretnego wolumenu.
/// Atakujący nie może zamienić bloków między plikami bez wykrycia przez AEAD.
fn make_aad(ino: u64, block_idx: u64, volume_uuid: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(3 + 8 + 8 + 16);
    aad.extend_from_slice(b"GFS");
    aad.extend_from_slice(&ino.to_le_bytes());
    aad.extend_from_slice(&block_idx.to_le_bytes());
    aad.extend_from_slice(volume_uuid);
    aad
}

#[derive(Clone)]
pub struct Crypto {
    master_key:    Key,
    master_cipher: Aes256Gcm,
    /// UUID wolumenu — część AAD, zapobiega cross-volume block swapping.
    pub volume_uuid: [u8; 16],
    /// Losowy prefiks nonce dla TEJ sesji (mountu) — patrz `next_nonce()`.
    nonce_prefix:  [u8; NONCE_PREFIX_SIZE],
    /// Monotonicznie rosnący licznik — razem z `nonce_prefix` daje
    /// GWARANTOWANĄ (nie tylko "statystycznie mało prawdopodobną") unikalność
    /// nonce w obrębie sesji, zamiast polegać wyłącznie na 96-bitowej
    /// losowości (podatnej na paradoks urodzinowy przy ok. 2^48 szyfrowań —
    /// dla wolumenu zapisującego miliardy bloków w całym cyklu życia to nie
    /// jest zerowe ryzyko). Współdzielony przez `Arc` między klonami
    /// `Crypto` tak, by WSZYSTKIE wątki FUSE piszące pod tym samym kluczem
    /// czerpały z jednego, nigdy nie powtarzającego się licznika.
    nonce_counter: Arc<AtomicU64>,
}

impl Crypto {
    pub fn new(key: Key) -> Result<Self, HfsError> {
        let master_cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| HfsError::CryptoError)?;
        let volume_uuid = rand::thread_rng().gen::<[u8; 16]>();
        Ok(Self {
            master_key: key, master_cipher, volume_uuid,
            nonce_prefix: rand::thread_rng().gen(),
            nonce_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn new_with_uuid(key: Key, uuid: [u8; 16]) -> Result<Self, HfsError> {
        let master_cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| HfsError::CryptoError)?;
        Ok(Self {
            master_key: key, master_cipher, volume_uuid: uuid,
            nonce_prefix: rand::thread_rng().gen(),
            nonce_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Wygeneruj następny nonce dla tej sesji: `nonce_prefix (4B losowe przy
    /// starcie mountu) || counter (8B, atomowo rosnący)`. Gwarantuje brak
    /// powtórzeń nonce w obrębie jednej sesji niezależnie od liczby
    /// zaszyfrowanych bloków (counter zawija się dopiero po 2^64 operacjach —
    /// praktycznie nieosiągalne), w przeciwieństwie do czysto losowego
    /// 96-bitowego nonce, który polega wyłącznie na statystyce.
    fn next_nonce(&self) -> [u8; NONCE_SIZE] {
        let n = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut out = [0u8; NONCE_SIZE];
        out[..NONCE_PREFIX_SIZE].copy_from_slice(&self.nonce_prefix);
        out[NONCE_PREFIX_SIZE..].copy_from_slice(&n.to_be_bytes()[..NONCE_COUNTER_SIZE]);
        out
    }

    /// Per-inode File Encryption Key: FEK = BLAKE3-KDF(master, ino || volume_uuid)
    pub fn derive_fek(&self, ino: u64) -> Key {
        let mut h = Hasher::new_keyed(&self.master_key);
        h.update(FEK_CONTEXT);
        h.update(&ino.to_le_bytes());
        h.update(&self.volume_uuid);
        *h.finalize().as_bytes()
    }

    /// Klucz szyfrujący NAZWY plików w danym katalogu (`parent_ino`). Osobny
    /// kontekst od FEK, żeby kompromitacja jednego nie ujawniała drugiego.
    /// Patrz `fs/dirindex.rs` — bez tego nazwy plików leżały w superblokcie
    /// db KOMPLETNIE jawnym tekstem (base64 to nie szyfrowanie).
    pub fn derive_dir_enc_key(&self, parent_ino: u64) -> Key {
        let mut h = Hasher::new_keyed(&self.master_key);
        h.update(DIRENC_CTX);
        h.update(&parent_ino.to_le_bytes());
        h.update(&self.volume_uuid);
        *h.finalize().as_bytes()
    }

    /// Blind index (jednokierunkowy, deterministyczny skrót) do wyszukiwania
    /// wpisów katalogu PO NAZWIE bez potrzeby ich odszyfrowywania —
    /// odpowiednik "searchable encryption" w najprostszej, ale bezpiecznej
    /// formie: skrót jest kluczowany master_key, więc atakujący bez klucza
    /// NIE MOŻE zbudować tęczowej tablicy typowych nazw plików
    /// ("id_rsa", "passwords.txt", ...) i porównać jej z indeksem —
    /// w przeciwieństwie do niekluczowanego `blake3::hash(name)`, które
    /// wcześniej było używane i było podatne dokładnie na taki atak
    /// słownikowy (sam hash bez klucza to nie jest ochrona poufności).
    pub fn dirname_blind_index(&self, parent_ino: u64, name: &[u8]) -> [u8; 32] {
        let mut ctx_hasher = Hasher::new_keyed(&self.master_key);
        ctx_hasher.update(DIRNAME_BLIND_CTX);
        ctx_hasher.update(&parent_ino.to_le_bytes());
        ctx_hasher.update(&self.volume_uuid);
        let subkey = *ctx_hasher.finalize().as_bytes();
        let mut h = Hasher::new_keyed(&subkey);
        h.update(name);
        *h.finalize().as_bytes()
    }

    /// Klucz do szyfrowania klucza podpisującego Ed25519 dla forensics
    /// (patrz `security/signing.rs`) — osobny kontekst od FEK/dirname, tak
    /// by kompromitacja jednego nie ujawniała pozostałych.
    pub fn derive_signing_key(&self) -> Key {
        let mut h = Hasher::new_keyed(&self.master_key);
        h.update(SIGNING_KEY_CTX);
        h.update(&self.volume_uuid);
        *h.finalize().as_bytes()
    }

    /// Klucz szyfrujący METADANE inode (rozmiar, uprawnienia, czasy,
    /// uid/gid) — wcześniej `fuser::FileAttr` leżał jako jawny `bincode`
    /// wprost w wartości klucza sled `inode:{ino}`, mimo że dane bloków
    /// (`data:*`) i nazwy plików (`didx:*`, patrz dirindex.rs) były już
    /// szyfrowane. Ktoś z dostępem tylko do plików bazy sled (skopiowany
    /// obraz dysku, backup bez klucza) mógł odczytać rozmiar, właściciela,
    /// uprawnienia i znaczniki czasu KAŻDEGO pliku bez znajomości master
    /// key — dla systemu plików reklamującego się jako "cybersecurity"
    /// to była realna luka poufności metadanych, nie tylko teoretyczna.
    ///
    /// Jeden klucz dla całego wolumenu (nie per-inode jak FEK) — metadane
    /// nie mają tej samej potrzeby izolacji co dane plików, a unikalność
    /// nonce jest i tak gwarantowana przez schemat sesyjny w `next_nonce()`.
    pub fn derive_inode_enc_key(&self) -> Key {
        let mut h = Hasher::new_keyed(&self.master_key);
        h.update(INODE_ENC_CTX);
        h.update(&self.volume_uuid);
        *h.finalize().as_bytes()
    }

    /// Klucz szyfrujący WARTOŚĆ rozszerzonego atrybutu (xattr) danego
    /// inode — patrz `fs/xattr.rs`. Wcześniej zarówno NAZWA (wprost w
    /// kluczu sled) jak i WARTOŚĆ xattr leżały jawnym tekstem — a xattr
    /// bywają wrażliwe (etykiety SELinux/ACL, tokeny, metadane aplikacji
    /// typu "pobrano z <url>"), więc to była realna, nie tylko teoretyczna
    /// luka poufności, tej samej klasy co nazwy plików i metadane inode.
    pub fn derive_xattr_enc_key(&self, ino: u64) -> Key {
        let mut h = Hasher::new_keyed(&self.master_key);
        h.update(XATTR_ENC_CTX);
        h.update(&ino.to_le_bytes());
        h.update(&self.volume_uuid);
        *h.finalize().as_bytes()
    }

    /// Blind index dla NAZWY xattr — ten sam wzorzec co
    /// `dirname_blind_index`: deterministyczny, kluczowany master_key,
    /// pozwala na lookup/set/remove O(1) bez odszyfrowywania, ale odporny
    /// na atak słownikowy na typowe nazwy xattr ("security.selinux",
    /// "user.comment", ...) bez znajomości klucza.
    pub fn xattr_blind_index(&self, ino: u64, name: &[u8]) -> [u8; 32] {
        let mut ctx_hasher = Hasher::new_keyed(&self.master_key);
        ctx_hasher.update(XATTR_BLIND_CTX);
        ctx_hasher.update(&ino.to_le_bytes());
        ctx_hasher.update(&self.volume_uuid);
        let subkey = *ctx_hasher.finalize().as_bytes();
        let mut h = Hasher::new_keyed(&subkey);
        h.update(name);
        *h.finalize().as_bytes()
    }

    /// Zaszyfruj blok danych z pełnym AAD (ino, block_idx, volume_uuid).
    /// Użyj tej metody dla bloków danych — nie `encrypt_with_key` bez kontekstu.
    pub fn encrypt_block(
        &self,
        fek:       &Key,
        plaintext: &[u8],
        ino:       u64,
        block_idx: usize,
    ) -> Result<Vec<u8>, HfsError> {
        let cipher      = Aes256Gcm::new_from_slice(fek).map_err(|_| HfsError::CryptoError)?;
        let nonce_bytes = self.next_nonce();
        let nonce       = Nonce::from_slice(&nonce_bytes);
        let aad         = make_aad(ino, block_idx as u64, &self.volume_uuid);
        let ciphertext  = cipher.encrypt(nonce, Payload { msg: plaintext, aad: &aad })
            .map_err(|_| HfsError::CryptoError)?;
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Odszyfruj blok z weryfikacją AAD.
    pub fn decrypt_block(
        &self,
        fek:       &Key,
        encrypted: &[u8],
        ino:       u64,
        block_idx: usize,
    ) -> Result<Vec<u8>, HfsError> {
        if encrypted.len() < NONCE_SIZE { return Err(HfsError::CryptoError); }
        let cipher = Aes256Gcm::new_from_slice(fek).map_err(|_| HfsError::CryptoError)?;
        let nonce  = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        let aad    = make_aad(ino, block_idx as u64, &self.volume_uuid);
        cipher.decrypt(nonce, Payload { msg: &encrypted[NONCE_SIZE..], aad: &aad })
            .map_err(|_| HfsError::CryptoError)
    }

    // ── Legacy API (metadane, journal, bez block_idx AAD) ──────────────────

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, HfsError> {
        self.encrypt_with_key(&self.master_key.clone(), plaintext)
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, HfsError> {
        self.decrypt_with_key(&self.master_key.clone(), encrypted)
    }

    pub fn encrypt_with_key(&self, fek: &Key, plaintext: &[u8]) -> Result<Vec<u8>, HfsError> {
        let cipher = Aes256Gcm::new_from_slice(fek).map_err(|_| HfsError::CryptoError)?;
        let nonce_bytes = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad: b"ghostfs-meta" })
            .map_err(|_| HfsError::CryptoError)?;
        let mut r = nonce_bytes.to_vec();
        r.extend_from_slice(&ciphertext);
        Ok(r)
    }

    pub fn decrypt_with_key(&self, fek: &Key, encrypted: &[u8]) -> Result<Vec<u8>, HfsError> {
        if encrypted.len() < NONCE_SIZE { return Err(HfsError::CryptoError); }
        let cipher = Aes256Gcm::new_from_slice(fek).map_err(|_| HfsError::CryptoError)?;
        let nonce  = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        cipher.decrypt(nonce, Payload { msg: &encrypted[NONCE_SIZE..], aad: b"ghostfs-meta" })
            .map_err(|_| HfsError::CryptoError)
    }

    // ── Key rotation ────────────────────────────────────────────────────────

    /// Rotacja master key: re-zaszyfruj wszystkie FEK-i nowym kluczem.
    ///
    /// Algorytm:
    ///   1. Dla każdego inode oblicz stary FEK (stary master_key || ino).
    ///   2. Oblicz nowy FEK (nowy master_key || ino).
    ///   3. Re-zaszyfruj każdy blok: odszyfruj starym FEK → zaszyfruj nowym FEK.
    ///   4. Zaktualizuj master_key i master_cipher.
    ///
    /// Operacja jest atomowa per-blok (nie per-wolumin) — przerwa w trakcie
    /// pozostawia wolumin w stanie mieszanym; `rekey_resume()` kontynuuje od ostatniego bloku.
    pub fn rotate_key(&mut self, db: &sled::Db, new_key: Key) -> Result<u64, HfsError> {
        let old_key   = self.master_key;
        let new_uuid  = rand::thread_rng().gen::<[u8; 16]>();
        let new_crypto = Crypto::new_with_uuid(new_key, new_uuid)?;

        let mut batch     = sled::Batch::default();
        let mut reencoded = 0u64;

        // Iteruj po wszystkich blokach danych
        let prefix = b"data:";
        for item in db.scan_prefix(prefix) {
            let (k, v) = item.map_err(HfsError::Sled)?;
            let key_str  = String::from_utf8(k.to_vec()).map_err(HfsError::Utf8)?;
            // Format: data:<ino>:<block_idx>
            let parts: Vec<&str> = key_str.splitn(3, ':').collect();
            if parts.len() != 3 { continue; }
            let ino:       u64   = parts[1].parse().unwrap_or(0);
            let block_idx: usize = parts[2].parse().unwrap_or(0);

            let mut old_fek = Self::derive_fek_raw(&old_key, ino, &self.volume_uuid);
            let decrypted   = self.decrypt_block(&old_fek, &v, ino, block_idx)?;
            old_fek.zeroize();

            let new_fek     = new_crypto.derive_fek(ino);
            let reencrypted = new_crypto.encrypt_block(&new_fek, &decrypted, ino, block_idx)?;

            batch.insert(k, reencrypted);
            reencoded += 1;

            // Commituj co 512 bloków — ograniczenie pamięci batch
            if reencoded % 512 == 0 {
                db.apply_batch(batch)?;
                batch = sled::Batch::default();
            }
        }

        db.apply_batch(batch)?;

        // Zapisz marker postępu — bezpieczeństwo resumable rekey
        db.insert(b"rekey:complete", bincode::serialize(&new_uuid)?)?;
        db.insert(b"rekey:uuid",     new_uuid.to_vec())?;
        db.flush()?;

        self.master_key    = new_key;
        self.master_cipher = Aes256Gcm::new_from_slice(&new_key).map_err(|_| HfsError::CryptoError)?;
        self.volume_uuid   = new_uuid;

        log::info!("GhostFS: key rotation complete — re-encrypted {} blocks", reencoded);
        Ok(reencoded)
    }

    fn derive_fek_raw(master: &Key, ino: u64, uuid: &[u8; 16]) -> Key {
        let mut h = Hasher::new_keyed(master);
        h.update(FEK_CONTEXT);
        h.update(&ino.to_le_bytes());
        h.update(uuid);
        *h.finalize().as_bytes()
    }

    pub fn zeroize(&mut self) {
        self.master_key.zeroize();
    }

    /// Klucz do wrappingu (export/import FEK-ów do backup) — Red Team: key escrow
    pub fn wrapping_key(&self) -> Key {
        let mut h = Hasher::new_keyed(&self.master_key);
        h.update(REKEK_CTX);
        *h.finalize().as_bytes()
    }
}

impl Drop for Crypto {
    fn drop(&mut self) { self.master_key.zeroize(); }
}
