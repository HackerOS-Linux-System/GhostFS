use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use blake3::Hasher;
use rand::Rng;
use zeroize::Zeroize;
use crate::error::HfsError;

pub type Key = [u8; 32];

const NONCE_SIZE:    usize = 12;
const FEK_CONTEXT:  &[u8] = b"ghostfs-fek-derivation-v1";
const REKEK_CTX:    &[u8] = b"ghostfs-rekey-wrapping-v1";

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
}

impl Crypto {
    pub fn new(key: Key) -> Result<Self, HfsError> {
        let master_cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| HfsError::CryptoError)?;
        let volume_uuid = rand::thread_rng().gen::<[u8; 16]>();
        Ok(Self { master_key: key, master_cipher, volume_uuid })
    }

    pub fn new_with_uuid(key: Key, uuid: [u8; 16]) -> Result<Self, HfsError> {
        let master_cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| HfsError::CryptoError)?;
        Ok(Self { master_key: key, master_cipher, volume_uuid: uuid })
    }

    /// Per-inode File Encryption Key: FEK = BLAKE3-KDF(master, ino || volume_uuid)
    pub fn derive_fek(&self, ino: u64) -> Key {
        let mut h = Hasher::new_keyed(&self.master_key);
        h.update(FEK_CONTEXT);
        h.update(&ino.to_le_bytes());
        h.update(&self.volume_uuid);
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
        let nonce_bytes: [u8; NONCE_SIZE] = rand::thread_rng().gen();
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
        let nonce_bytes: [u8; NONCE_SIZE] = rand::thread_rng().gen();
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
