use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::Rng;
use crate::error::HfsError;

pub type Key = [u8; 32];
const NONCE_SIZE: usize = 12;

#[derive(Clone)]
pub struct Crypto { cipher: Aes256Gcm }

impl Crypto {
    pub fn new(key: Key) -> Result<Self, HfsError> {
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| HfsError::CryptoError)?;
        Ok(Self { cipher })
    }
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, HfsError> {
        let nonce_bytes: [u8; NONCE_SIZE] = rand::thread_rng().gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self.cipher.encrypt(nonce, Payload { msg: plaintext, aad: b"" })
        .map_err(|_| HfsError::CryptoError)?;
        let mut r = nonce_bytes.to_vec();
        r.extend_from_slice(&ciphertext);
        Ok(r)
    }
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, HfsError> {
        if encrypted.len() < NONCE_SIZE { return Err(HfsError::CryptoError); }
        let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        self.cipher.decrypt(nonce, Payload { msg: &encrypted[NONCE_SIZE..], aad: b"" })
        .map_err(|_| HfsError::CryptoError)
    }
}
