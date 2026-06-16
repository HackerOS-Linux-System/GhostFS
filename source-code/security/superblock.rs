use serde::{Serialize, Deserialize};
use blake3::Hasher;
use zeroize::Zeroize;
use crate::error::HfsError;
use crate::crypto::Key;
use crate::kdf::KdfParams;

const SB_HMAC_CONTEXT: &[u8] = b"ghostfs-superblock-hmac-v1";
pub const SB_VERSION: &str   = "ghostfs-0.3.0";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SuperblockData {
    pub version:    String,
    pub block_size: u32,
    pub created_at: u64,
    /// KDF params zapisywane przy mkfs, odczytywane przy mount
    pub kdf_params: KdfParams,
    pub flags:      u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Superblock {
    pub data: SuperblockData,
    pub hmac: [u8; 32],
}

impl Superblock {
    /// Tworzy nowy superblock z KDF params. Wywołać po derive_key przy mkfs.
    pub fn new(block_size: u32, master_key: &Key, kdf_params: KdfParams) -> Result<Self, HfsError> {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        let data = SuperblockData {
            version: SB_VERSION.to_string(),
            block_size,
            created_at,
            kdf_params,
            flags: 0x01, // encryption enabled
        };
        let hmac = Self::compute_hmac(&data, master_key)?;
        Ok(Superblock { data, hmac })
    }

    pub fn verify(&self, master_key: &Key) -> Result<(), HfsError> {
        let expected = Self::compute_hmac(&self.data, master_key)?;
        // Constant-time compare
        let ok = expected.iter().zip(self.hmac.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
        if ok { Ok(()) } else { Err(HfsError::SuperblockTampered) }
    }

    fn compute_hmac(data: &SuperblockData, master_key: &Key) -> Result<[u8; 32], HfsError> {
        let mut subkey_hasher = Hasher::new_keyed(master_key);
        subkey_hasher.update(SB_HMAC_CONTEXT);
        let subkey = *subkey_hasher.finalize().as_bytes();
        let serialised = bincode::serialize(data).map_err(HfsError::Bincode)?;
        let mut mac_hasher = Hasher::new_keyed(&subkey);
        mac_hasher.update(&serialised);
        let mut result = [0u8; 32];
        result.copy_from_slice(mac_hasher.finalize().as_bytes());
        let mut sk = subkey;
        sk.zeroize();
        Ok(result)
    }

    /// Odczyt KDF params z superblock (przed derywacją klucza — nie znamy jeszcze master_key).
    pub fn load_kdf_params(db: &sled::Db) -> Result<KdfParams, HfsError> {
        let raw = db.get(b"sb:data")?.ok_or(HfsError::NoEntry)?;
        let sb: Superblock = bincode::deserialize(&raw)?;
        Ok(sb.data.kdf_params)
    }

    pub fn load_and_verify(db: &sled::Db, master_key: &Key) -> Result<Self, HfsError> {
        let raw = db.get(b"sb:data")?.ok_or(HfsError::NoEntry)?;
        let sb: Superblock = bincode::deserialize(&raw)?;
        sb.verify(master_key)?;
        log::info!("GhostFS superblock OK: {} bs={} created={}",
            sb.data.version, sb.data.block_size, sb.data.created_at);
        Ok(sb)
    }
}
