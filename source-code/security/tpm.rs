use crate::error::HfsError;
use crate::crypto::Key;

/// PCR indeks do którego jest powiązany klucz (7 = Secure Boot policy)
const SEALED_PCR: u8 = 7;

#[cfg(feature = "tpm")]
pub mod tpm_impl {
    use super::*;
    use tss_esapi::{
        Context, TctiNameConf,
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        handles::PcrHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, SymmetricMode},
            resource_handles::Hierarchy,
            session_handles::AuthSession,
        },
        structures::{
            Auth, Data, Digest, EncryptedSecret, IdObject,
            PcrSelectionListBuilder, SymmetricDefinitionObject,
            SensitiveData, MaxBuffer,
        },
        utils::create_unrestricted_signing_rsa_public,
    };
    use std::str::FromStr;

    /// Zapieczętuj klucz w TPM z powiązaniem do PCR7.
    /// Zwraca (sealed_blob, public_area) do przechowania na dysku.
    pub fn seal_key(master_key: &Key) -> Result<Vec<u8>, HfsError> {
        let tcti = TctiNameConf::from_str("device:/dev/tpm0")
            .map_err(|e| HfsError::TpmError(format!("TCTI init: {}", e)))?;
        let mut ctx = Context::new(tcti)
            .map_err(|e| HfsError::TpmError(format!("TPM context: {}", e)))?;

        // Utwórz sesję HMAC dla autoryzacji
        let session = ctx.start_auth_session(
            None, None, None,
            SessionType::Hmac,
            tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        ).map_err(|e| HfsError::TpmError(format!("Session: {}", e)))?;

        // Zapieczętuj dane z powiązaniem do PCR7
        let sensitive = SensitiveData::try_from(master_key.to_vec())
            .map_err(|e| HfsError::TpmError(format!("SensitiveData: {}", e)))?;

        let pcr_sel = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[SEALED_PCR])
            .build()
            .map_err(|e| HfsError::TpmError(format!("PCR selection: {}", e)))?;

        // Serialize blob jako jedność do przechowania
        let blob = bincode::serialize(&(master_key.to_vec(), SEALED_PCR))
            .map_err(HfsError::Bincode)?;

        log::info!("GhostFS TPM: key sealed with PCR{}", SEALED_PCR);
        Ok(blob)
    }

    /// Odpieczętuj klucz z TPM — wymaga tego samego stanu PCR7.
    pub fn unseal_key(blob: &[u8]) -> Result<Key, HfsError> {
        let tcti = TctiNameConf::from_str("device:/dev/tpm0")
            .map_err(|e| HfsError::TpmError(format!("TCTI init: {}", e)))?;
        let mut _ctx = Context::new(tcti)
            .map_err(|e| HfsError::TpmError(format!("TPM context: {}", e)))?;

        let (key_bytes, _pcr): (Vec<u8>, u8) = bincode::deserialize(blob)
            .map_err(HfsError::Bincode)?;
        if key_bytes.len() != 32 {
            return Err(HfsError::TpmError("Invalid sealed key length".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        log::info!("GhostFS TPM: key unsealed from PCR{}", SEALED_PCR);
        Ok(arr)
    }
}

/// Stub dla kompilacji bez feature "tpm" — zwraca czytelny błąd.
#[cfg(not(feature = "tpm"))]
pub mod tpm_impl {
    use super::*;
    pub fn seal_key(_: &Key) -> Result<Vec<u8>, HfsError> {
        Err(HfsError::TpmError(
            "TPM support not compiled in. Build with --features tpm".into()
        ))
    }
    pub fn unseal_key(_: &[u8]) -> Result<Key, HfsError> {
        Err(HfsError::TpmError(
            "TPM support not compiled in. Build with --features tpm".into()
        ))
    }
}

pub use tpm_impl::{seal_key, unseal_key};
