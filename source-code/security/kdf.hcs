use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::Rng;
use crate::error::HfsError;
use crate::crypto::Key;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub m_cost:   u32,
    pub t_cost:   u32,
    pub p_cost:   u32,
    /// 16-byte salt (hex) — przechowywany w superblock
    pub salt_hex: String,
}

impl Default for KdfParams {
    fn default() -> Self {
        let salt: [u8; 16] = rand::thread_rng().gen();
        KdfParams { m_cost: 65_536, t_cost: 3, p_cost: 4, salt_hex: hex::encode(salt) }
    }
}

impl KdfParams {
    pub fn custom(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        let salt: [u8; 16] = rand::thread_rng().gen();
        KdfParams { m_cost, t_cost, p_cost, salt_hex: hex::encode(salt) }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    pub key: Key,
}

/// Derywuj klucz 256-bit z hasła przez Argon2id.
pub fn derive_key(passphrase: &str, params: &KdfParams) -> Result<DerivedKey, HfsError> {
    let salt = hex::decode(&params.salt_hex)
        .map_err(|_| HfsError::InvalidArgument("Invalid KDF salt".into()))?;
    let ap = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| HfsError::KdfError(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, ap);
    let mut out = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), &salt, &mut out)
        .map_err(|e| HfsError::KdfError(e.to_string()))?;
    Ok(DerivedKey { key: out })
}

/// Odczyt hasła bez echa — używa rpassword dla bezpiecznego wejścia.
pub fn read_passphrase(prompt: &str) -> Result<String, HfsError> {
    rpassword::prompt_password(prompt).map_err(HfsError::Io)
}

/// Odczyt hasła z potwierdzeniem (dla mkfs).
pub fn read_passphrase_confirm(prompt: &str) -> Result<String, HfsError> {
    loop {
        let p1 = rpassword::prompt_password(prompt).map_err(HfsError::Io)?;
        let p2 = rpassword::prompt_password("Confirm passphrase: ").map_err(HfsError::Io)?;
        if p1 == p2 {
            return Ok(p1);
        }
        eprintln!("Passphrases do not match — try again.");
    }
}
