use serde::{Serialize, Deserialize};
use blake3::Hasher;
use zeroize::Zeroize;
use crate::error::HfsError;
use crate::crypto::Key;
use crate::kdf::KdfParams;

const SB_HMAC_CONTEXT: &[u8] = b"ghostfs-superblock-hmac-v1";
const SB_VERSION: &str = "ghostfs-0.5.0";

/// Plaintext superblock fields (authenticated but not encrypted).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SuperblockData {
    pub version:    String,
    pub block_size: u32,
    pub created_at: u64,
    pub kdf_params: KdfParams,
    /// Flags: bit 0 = encryption enabled, bit 1 = dedup enabled, etc.
    pub flags:      u64,
}

/// On-disk superblock = data + HMAC.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Superblock {
    pub data: SuperblockData,
    /// 32-byte HMAC-BLAKE3 over `data` serialised with bincode.
    pub hmac: [u8; 32],
}

impl Superblock {
    /// Create and authenticate a new superblock.
    pub fn new(block_size: u32, master_key: &Key) -> Result<Self, HfsError> {
        let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

        let data = SuperblockData {
            version: SB_VERSION.to_string(),
            block_size,
            created_at,
            kdf_params: KdfParams::default(),
            flags: 0x01, // encryption enabled
        };

        let hmac = Self::compute_hmac(&data, master_key)?;
        Ok(Superblock { data, hmac })
    }

    /// Verify the superblock HMAC. Returns an error if tampered.
    pub fn verify(&self, master_key: &Key) -> Result<(), HfsError> {
        let expected = Self::compute_hmac(&self.data, master_key)?;
        // Constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        if expected.ct_eq(&self.hmac).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(HfsError::SuperblockTampered)
        }
    }

    /// Derive a superblock-specific HMAC subkey and compute HMAC-BLAKE3.
    fn compute_hmac(data: &SuperblockData, master_key: &Key) -> Result<[u8; 32], HfsError> {
        // Derive a subkey for superblock HMAC (key separation)
        let mut subkey_hasher = Hasher::new_keyed(master_key);
        subkey_hasher.update(SB_HMAC_CONTEXT);
        let subkey_output = subkey_hasher.finalize();
        let subkey: [u8; 32] = *subkey_output.as_bytes();

        // HMAC-BLAKE3 over serialised data
        let serialised = bincode::serialize(data)
        .map_err(|e| HfsError::Bincode(e))?;
        let mut mac_hasher = Hasher::new_keyed(&subkey);
        mac_hasher.update(&serialised);
        let mut result = [0u8; 32];
        result.copy_from_slice(mac_hasher.finalize().as_bytes());

        // Zeroize subkey before returning
        let mut subkey_mut = subkey;
        subkey_mut.zeroize();

        Ok(result)
    }

    /// Extract KDF parameters from a stored superblock (before we have the key).
    /// Used to prompt the user for a passphrase before deriving the master key.
    pub fn load_kdf_params(db: &sled::Db) -> Result<KdfParams, HfsError> {
        match db.get(b"sb:data")? {
            Some(raw) => {
                let sb: Superblock = bincode::deserialize(&raw)?;
                Ok(sb.data.kdf_params)
            }
            None => Err(HfsError::NoEntry),
        }
    }

    /// Load and verify the superblock from the database.
    pub fn load_and_verify(db: &sled::Db, master_key: &Key) -> Result<Self, HfsError> {
        let raw = db.get(b"sb:data")?.ok_or(HfsError::NoEntry)?;
        let sb: Superblock = bincode::deserialize(&raw)?;
        sb.verify(master_key)?;
        log::info!(
            "GhostFS superblock verified: version={} block_size={} created={}",
            sb.data.version, sb.data.block_size, sb.data.created_at
        );
        Ok(sb)
    }
}
