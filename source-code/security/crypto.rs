use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use blake3::Hasher;
use rand::Rng;
use zeroize::Zeroize;
use crate::error::HfsError;

pub type Key = [u8; 32];

const NONCE_SIZE: usize = 12;
const FEK_CONTEXT: &[u8] = b"ghostfs-fek-derivation-v1";

#[derive(Clone)]
pub struct Crypto {
    master_key:    Key,
    master_cipher: Aes256Gcm,
}

impl Crypto {
    pub fn new(key: Key) -> Result<Self, HfsError> {
        let master_cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| HfsError::CryptoError)?;
        Ok(Self { master_key: key, master_cipher })
    }

    pub fn derive_fek(&self, ino: u64) -> Key {
        let mut hasher = Hasher::new_keyed(&self.master_key);
        hasher.update(FEK_CONTEXT);
        hasher.update(&ino.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, HfsError> {
        let nonce_bytes: [u8; NONCE_SIZE] = rand::thread_rng().gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self.master_cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: b"" })
        .map_err(|_| HfsError::CryptoError)?;
        let mut r = nonce_bytes.to_vec();
        r.extend_from_slice(&ciphertext);
        Ok(r)
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, HfsError> {
        if encrypted.len() < NONCE_SIZE { return Err(HfsError::CryptoError); }
        let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        self.master_cipher
        .decrypt(nonce, Payload { msg: &encrypted[NONCE_SIZE..], aad: b"" })
        .map_err(|_| HfsError::CryptoError)
    }

    pub fn encrypt_with_key(&self, fek: &Key, plaintext: &[u8]) -> Result<Vec<u8>, HfsError> {
        let cipher = Aes256Gcm::new_from_slice(fek).map_err(|_| HfsError::CryptoError)?;
        let nonce_bytes: [u8; NONCE_SIZE] = rand::thread_rng().gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: b"" })
        .map_err(|_| HfsError::CryptoError)?;
        let mut r = nonce_bytes.to_vec();
        r.extend_from_slice(&ciphertext);
        Ok(r)
    }

    pub fn decrypt_with_key(&self, fek: &Key, encrypted: &[u8]) -> Result<Vec<u8>, HfsError> {
        if encrypted.len() < NONCE_SIZE { return Err(HfsError::CryptoError); }
        let cipher = Aes256Gcm::new_from_slice(fek).map_err(|_| HfsError::CryptoError)?;
        let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        cipher
        .decrypt(nonce, Payload { msg: &encrypted[NONCE_SIZE..], aad: b"" })
        .map_err(|_| HfsError::CryptoError)
    }

    pub fn zeroize(&mut self) {
        self.master_key.zeroize();
    }
}

impl Drop for Crypto {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}
