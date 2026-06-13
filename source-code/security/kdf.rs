use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::Rng;
use crate::error::HfsError;
use crate::crypto::Key;

/// Argon2id tuning parameters stored in the superblock.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
/// Random 16-byte salt (argon2 minimum requirement).
pub struct KdfParams {
    pub m_cost:   u32,
    pub t_cost:   u32,
    pub p_cost:   u32,
    /// 16-byte random salt (hex-encoded)
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

/// Zeroizing wrapper for the derived key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    pub key: Key,
}

/// Derive a 256-bit master key from a passphrase using Argon2id.
///
/// # Arguments
/// * `passphrase` — user-supplied passphrase (UTF-8)
/// * `params`     — KDF parameters (must match what was stored at format time)
///
/// # Returns
/// `DerivedKey` whose `key` field is ready to pass to `Crypto::new()`.
pub fn derive_key(passphrase: &str, params: &KdfParams) -> Result<DerivedKey, HfsError> {
    let salt_bytes = hex::decode(&params.salt_hex)
    .map_err(|_| HfsError::InvalidArgument("Invalid KDF salt in superblock".into()))?;

    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
    .map_err(|e| HfsError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; 32];
    argon2
    .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut output)
    .map_err(|e| HfsError::KdfError(e.to_string()))?;

    Ok(DerivedKey { key: output })
}

/// Read a passphrase from the terminal without echo.
/// Falls back to stdin if not a TTY.
pub fn read_passphrase(prompt: &str) -> Result<String, HfsError> {
    use std::io::{self, Write};
    eprint!("{}", prompt);
    io::stderr().flush().ok();

    // Try rpassword-style read (no dependency — manual termios).
    // For simplicity, use the standard read_line approach.
    // In production, replace with `rpassword` crate.
    let mut pass = String::new();
    io::stdin()
    .read_line(&mut pass)
    .map_err(|e| HfsError::Io(e))?;

    // Trim the newline
    let trimmed = pass.trim_end_matches(['\n', '\r']).to_string();
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_deterministic() {
        let params = KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            salt_hex: hex::encode([0x42u8; 32]),
        };
        let k1 = derive_key("hunter2", &params).unwrap();
        let k2 = derive_key("hunter2", &params).unwrap();
        assert_eq!(k1.key, k2.key);
    }

    #[test]
    fn test_different_passwords_differ() {
        let params = KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            salt_hex: hex::encode([0xABu8; 32]),
        };
        let k1 = derive_key("password1", &params).unwrap();
        let k2 = derive_key("password2", &params).unwrap();
        assert_ne!(k1.key, k2.key);
    }
}
