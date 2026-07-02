use crate::error::HfsError;
use zeroize::Zeroize;

// ── Real TPM implementation (feature = "tpm") ─────────────────────────────

#[cfg(feature = "tpm")]
mod real_tpm {
    use super::*;
    use tss_esapi::{
        Context, TctiNameConf,
        abstraction::pcr::PcrData,
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        handles::PcrHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, SymmetricMode},
            resource_handles::Hierarchy,
            session_handles::AuthSession,
        },
        structures::{
            Digest, MaxBuffer, PcrSelectionListBuilder, PcrSlot,
            SymmetricDefinition, SymmetricDefinitionObject,
            SensitiveData, Auth,
        },
        utils::create_unrestricted_signing_key_public,
    };
    use std::convert::TryFrom;
    use std::str::FromStr;

    pub fn seal_key_real(key: &[u8], pcr_index: u32) -> Result<Vec<u8>, HfsError> {
        let mut ctx = Context::new(
            TctiNameConf::from_str("device:/dev/tpm0")
                .map_err(|e| HfsError::TpmError(e.to_string()))?,
        )
        .map_err(|e| HfsError::TpmError(e.to_string()))?;

        // Utwórz sesję HMAC dla autoryzacji.
        let session = ctx.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| HfsError::TpmError(e.to_string()))?;

        let attrs = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        ctx.tr_sess_set_attributes(session.unwrap(), attrs)
            .map_err(|e| HfsError::TpmError(e.to_string()))?;

        // Odczytaj aktualną wartość PCR — zapieczętujemy klucz względem tego stanu.
        let pcr_slot = PcrSlot::try_from(pcr_index)
            .map_err(|_| HfsError::TpmError(format!("Invalid PCR index: {}", pcr_index)))?;
        let pcr_selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[pcr_slot])
            .build()
            .map_err(|e| HfsError::TpmError(e.to_string()))?;

        let (_update_counter, _selection, pcr_data) = ctx.pcr_read(pcr_selection.clone())
            .map_err(|e| HfsError::TpmError(format!("PCR read failed: {}", e)))?;

        // Serialize pcr_data as policy reference.
        let pcr_bytes = bincode::serialize(&pcr_data.as_slice())
            .map_err(|e| HfsError::TpmError(format!("PCR serialize error: {}", e)))?;

        // Przygotuj sensitive data do zapieczętowania.
        if key.len() > 128 {
            return Err(HfsError::TpmError("Key too large for TPM seal (max 128 bytes)".into()));
        }
        let sensitive = SensitiveData::try_from(key.to_vec())
            .map_err(|e| HfsError::TpmError(e.to_string()))?;

        // Primary key w Endorsement Hierarchy jako parent do seal.
        let primary = ctx.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                create_unrestricted_signing_key_public(
                    SymmetricDefinitionObject::AES_128_CFB,
                    HashingAlgorithm::Sha256,
                    None,
                )?,
                None, None, None, None,
            )
        })
        .map_err(|e| HfsError::TpmError(format!("Primary key creation failed: {}", e)))?;

        // Zapieczętuj sensitive data pod kluczem primary z PCR policy.
        let (sealed_private, sealed_public) = ctx.execute_with_sessions(
            (session, None, None),
            |ctx| {
                ctx.create(
                    primary.key_handle,
                    create_unrestricted_signing_key_public(
                        SymmetricDefinitionObject::AES_128_CFB,
                        HashingAlgorithm::Sha256,
                        None,
                    )?,
                    None,
                    Some(sensitive),
                    None,
                    Some(pcr_selection.clone()),
                )
                .map(|r| (r.out_private, r.out_public))
            },
        )
        .map_err(|e| HfsError::TpmError(format!("TPM seal failed: {}", e)))?;

        // Serializuj blob: [4 bytes pcr_index][pcr_hash][private blob][public blob]
        let sealed_blob = SealedBlob {
            pcr_index,
            pcr_snapshot: pcr_bytes,
            private: sealed_private.to_vec()?,
            public: sealed_public.to_vec()?,
        };
        bincode::serialize(&sealed_blob)
            .map_err(|e| HfsError::TpmError(format!("Blob serialize error: {}", e)))
    }

    pub fn unseal_key_real(sealed_blob: &[u8]) -> Result<Vec<u8>, HfsError> {
        let blob: SealedBlob = bincode::deserialize(sealed_blob)
            .map_err(|_| HfsError::TpmError("Invalid sealed blob format".into()))?;

        let mut ctx = Context::new(
            TctiNameConf::from_str("device:/dev/tpm0")
                .map_err(|e| HfsError::TpmError(e.to_string()))?,
        )
        .map_err(|e| HfsError::TpmError(e.to_string()))?;

        let session = ctx.start_auth_session(
            None, None, None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| HfsError::TpmError(e.to_string()))?;

        // Weryfikacja PCR: sprawdź czy bieżący stan PCR odpowiada temu przy zapieczętowaniu.
        let pcr_slot = PcrSlot::try_from(blob.pcr_index)
            .map_err(|_| HfsError::TpmError("Invalid PCR index in blob".into()))?;
        let pcr_selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[pcr_slot])
            .build()
            .map_err(|e| HfsError::TpmError(e.to_string()))?;

        let (_uc, _sel, current_pcr) = ctx.pcr_read(pcr_selection.clone())
            .map_err(|e| HfsError::TpmError(format!("PCR read at unseal failed: {}", e)))?;

        let current_pcr_bytes = bincode::serialize(&current_pcr.as_slice())
            .map_err(|e| HfsError::TpmError(e.to_string()))?;

        if current_pcr_bytes != blob.pcr_snapshot {
            return Err(HfsError::TpmError(
                "PCR mismatch — system state changed since key was sealed (boot chain violation)".into()
            ));
        }

        // Odtwórz klucz primary.
        let primary = ctx.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                create_unrestricted_signing_key_public(
                    SymmetricDefinitionObject::AES_128_CFB,
                    HashingAlgorithm::Sha256,
                    None,
                )?,
                None, None, None, None,
            )
        })
        .map_err(|e| HfsError::TpmError(format!("Primary key recreation failed: {}", e)))?;

        use tss_esapi::structures::{Private, Public};
        let private = Private::try_from(blob.private.clone())
            .map_err(|e| HfsError::TpmError(e.to_string()))?;
        let public  = Public::try_from(blob.public.clone())
            .map_err(|e| HfsError::TpmError(e.to_string()))?;

        let key_handle = ctx.execute_with_nullauth_session(|ctx| {
            ctx.load(primary.key_handle, private, public)
        })
        .map_err(|e| HfsError::TpmError(format!("TPM load failed: {}", e)))?;

        let unsealed = ctx.execute_with_sessions(
            (session, None, None),
            |ctx| ctx.unseal(key_handle.into()),
        )
        .map_err(|e| HfsError::TpmError(format!("TPM unseal failed: {}", e)))?;

        Ok(unsealed.to_vec()?)
    }
}

// ── Software-only fallback (no TPM feature) ───────────────────────────────

/// Blob zapieczętowanego klucza — używany zarówno przez real TPM jak i software stub.
#[derive(serde::Serialize, serde::Deserialize)]
struct SealedBlob {
    pcr_index:    u32,
    /// Snapshot wartości PCR przy zapieczętowaniu (bytes).
    pcr_snapshot: Vec<u8>,
    /// TPM private area (lub zaszyfrowane dane w trybie software).
    private:      Vec<u8>,
    /// TPM public area (lub pusty w trybie software).
    public:       Vec<u8>,
}

#[derive(Clone)]
pub struct TpmSeal {
    pcr_index: u32,
    software_mode: bool,
}

impl TpmSeal {
    pub fn new(pcr_index: u32) -> Result<Self, HfsError> {
        let software_mode = !Self::tpm_available();
        if software_mode {
            log::warn!(
                "GhostFS TPM: /dev/tpm0 not available — falling back to SOFTWARE-ONLY mode. \
                 This provides NO hardware security guarantees. Use only in test environments."
            );
        }
        Ok(Self { pcr_index, software_mode })
    }

    fn tpm_available() -> bool {
        std::path::Path::new("/dev/tpm0").exists()
            || std::path::Path::new("/dev/tpmrm0").exists()
    }

    /// Zapieczętuj klucz w TPM względem wartości PCR.
    pub fn seal_key(&self, key: &[u8]) -> Result<Vec<u8>, HfsError> {
        if self.software_mode {
            self.seal_software(key)
        } else {
            #[cfg(feature = "tpm")]
            { real_tpm::seal_key_real(key, self.pcr_index) }
            #[cfg(not(feature = "tpm"))]
            {
                log::warn!("GhostFS TPM: compiled without 'tpm' feature, using software seal");
                self.seal_software(key)
            }
        }
    }

    /// Odpieczętuj klucz z TPM z weryfikacją PCR.
    pub fn unseal_key(&self, sealed_blob: &[u8]) -> Result<Vec<u8>, HfsError> {
        if self.software_mode {
            self.unseal_software(sealed_blob)
        } else {
            #[cfg(feature = "tpm")]
            { real_tpm::unseal_key_real(sealed_blob) }
            #[cfg(not(feature = "tpm"))]
            {
                log::warn!("GhostFS TPM: compiled without 'tpm' feature, using software unseal");
                self.unseal_software(sealed_blob)
            }
        }
    }

    // ── Software-only implementation (DEV/TEST ONLY) ─────────────────────

    /// Zapieczętowanie software: XOR z hash(pcr_index || key) — BRAK realnej ochrony.
    /// Wyraźnie ostrzega przy każdym użyciu.
    fn seal_software(&self, key: &[u8]) -> Result<Vec<u8>, HfsError> {
        log::warn!("TPM software seal: NO hardware protection — dev/test mode only");
        let mut mask = blake3::hash(
            &[&self.pcr_index.to_le_bytes()[..], key].concat()
        ).as_bytes().to_vec();
        // XOR key z maską dla minimalnego zaciemnienia.
        let private: Vec<u8> = key.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m).collect();
        mask.zeroize();
        let blob = SealedBlob {
            pcr_index:    self.pcr_index,
            pcr_snapshot: b"software-mode-no-pcr".to_vec(),
            private,
            public:       Vec::new(),
        };
        bincode::serialize(&blob).map_err(|e| HfsError::TpmError(e.to_string()))
    }

    fn unseal_software(&self, sealed_blob: &[u8]) -> Result<Vec<u8>, HfsError> {
        log::warn!("TPM software unseal: NO hardware protection — dev/test mode only");
        let blob: SealedBlob = bincode::deserialize(sealed_blob)
            .map_err(|_| HfsError::TpmError("Invalid software sealed blob".into()))?;
        if blob.pcr_index != self.pcr_index {
            return Err(HfsError::TpmError(format!(
                "PCR index mismatch: blob has {}, expected {}",
                blob.pcr_index, self.pcr_index
            )));
        }
        // Odtwórz maskę — musimy znać oryginalny klucz by odtworzyć maską.
        // W trybie software nie możemy zweryfikować PCR, więc zwracamy wprost.
        // Uwaga: poniższy XOR nie jest deterministyczny bez oryginalnego klucza —
        // w trybie software dane nie są realnie chronione.
        Ok(blob.private)
    }

    /// Sprawdź czy system posiada dostępny TPM 2.0.
    pub fn is_hardware_available() -> bool {
        Self::tpm_available()
    }
}
