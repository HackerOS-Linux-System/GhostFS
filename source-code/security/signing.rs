use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng as RandOsRng;
use sled::Db;
use serde::{Serialize, Deserialize};
use crate::crypto::Crypto;
use crate::error::HfsError;

const SIGNING_KEY_DB: &[u8] = b"forensics:signing_key_encrypted";

#[derive(Clone)]
pub struct ForensicsSigner {
    signing_key: SigningKey,
}

impl ForensicsSigner {
    /// Wczytaj istniejący klucz podpisujący wolumenu lub wygeneruj nowy
    /// (raz, przy pierwszym wywołaniu — zwykle przy mkfs).
    pub fn load_or_generate(db: &Db, crypto: &Crypto) -> Result<Self, HfsError> {
        let key_material = crypto.derive_signing_key();

        match db.get(SIGNING_KEY_DB)? {
            Some(encrypted) => {
                let seed_bytes = crypto.decrypt_with_key(&key_material, &encrypted)?;
                if seed_bytes.len() != 32 {
                    return Err(HfsError::CryptoError);
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                Ok(Self { signing_key: SigningKey::from_bytes(&seed) })
            }
            None => {
                let signing_key = SigningKey::generate(&mut RandOsRng);
                let seed = signing_key.to_bytes();
                let encrypted = crypto.encrypt_with_key(&key_material, &seed)?;
                db.insert(SIGNING_KEY_DB, encrypted)?;
                log::info!("GhostFS forensics: generated new Ed25519 signing keypair for this volume");
                Ok(Self { signing_key })
            }
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        // `[u8; 64]` -> Vec<u8>: serde derywuje Serialize/Deserialize dla
        // tablic tylko do rozmiaru 32 (bez dodatkowej zależności typu
        // `serde-big-array`), a podpis Ed25519 ma 64 bajty. `Vec<u8>` unika
        // tego ograniczenia bez nowej zależności; długość jest i tak stała
        // (64B) i sprawdzana explicite w `verify_signed_export`.
        self.signing_key.sign(message).to_bytes().to_vec()
    }
}

/// Manifest dołączany do każdego podpisanego eksportu forensics — patrz
/// `Forensics::export_signed` w `forensics.rs`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedExportManifest {
    pub ghostfs_version: String,
    pub exported_at:     u64,
    pub entry_count:     u64,
    /// BLAKE3 hash zserializowanych wpisów (to co faktycznie jest podpisane).
    pub payload_hash:    [u8; 32],
    /// Podpis Ed25519 — 64 bajty, przechowywane jako `Vec<u8>` (patrz
    /// komentarz przy `ForensicsSigner::sign`), długość walidowana przy
    /// weryfikacji.
    pub signature:       Vec<u8>,
    pub public_key_hex:  String,
}

/// Zweryfikuj podpisany eksport BEZ dostępu do wolumenu — wyłącznie na
/// podstawie samego pliku eksportu. To jest funkcja, którą uruchomi
/// audytor/sąd, nie administrator GhostFS.
pub fn verify_signed_export(manifest: &SignedExportManifest, payload: &[u8]) -> Result<bool, HfsError> {
    let computed_hash = blake3::hash(payload);
    if computed_hash.as_bytes() != &manifest.payload_hash {
        return Ok(false);
    }
    let pubkey_bytes = hex::decode(&manifest.public_key_hex)
        .map_err(|_| HfsError::InvalidArgument("Invalid public key hex in manifest".into()))?;
    if pubkey_bytes.len() != 32 {
        return Err(HfsError::InvalidArgument("Public key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pubkey_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| HfsError::InvalidArgument("Invalid Ed25519 public key".into()))?;

    if manifest.signature.len() != 64 {
        return Err(HfsError::InvalidArgument(format!(
            "Signature must be 64 bytes, got {}", manifest.signature.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&manifest.signature);
    let signature = Signature::from_bytes(&sig_arr);
    Ok(verifying_key.verify(&manifest.payload_hash, &signature).is_ok())
}
