use crate::error::HfsError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
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
    //
    // v0.4 FIX: poprzednia implementacja była kryptograficznie zepsuta —
    // `seal_software` maskowała klucz przez XOR z `hash(pcr_index || key)`,
    // czyli maska ZALEŻAŁA od samego klucza, którego `unseal_software` z
    // definicji jeszcze nie zna. `unseal_software` w rezultacie zwracała
    // zamaskowane bajty WPROST, bez żadnego odwrócenia — realny bug, nie
    // tylko "słabe zabezpieczenie dla dev/test", bo odzyskany "klucz" był
    // zwyczajnie NIEPRAWIDŁOWY (nigdy nie równał się oryginalnemu `key`).
    //
    // Nowa implementacja: prawdziwe (odwracalne) AES-256-GCM z kluczem
    // wyprowadzonym z tożsamości maszyny (`/etc/machine-id`) + losowej soli
    // zapisanej w blobie. To WCIĄŻ nie jest ochrona sprzętowa — ktoś z
    // dostępem do tego samego `/etc/machine-id` (czyli root na tej samej
    // maszynie) może odtworzyć klucz seal-key i odpieczętować blob. Ale to
    // uczciwe, działające przybliżenie: blob jest bezużyteczny bez
    // dostępu do TEJ konkretnej maszyny, i (w przeciwieństwie do poprzedniej
    // wersji) faktycznie się poprawnie odszyfrowuje.
    //
    // Analogiczne do "soft PCR": zamiast prawdziwych wartości PCR (TPM),
    // wiążemy blob z hashem (machine-id || kernel release), więc zmiana
    // maszyny/reinstalacja jądra unieważnia blob — przybliżenie "boot chain
    // changed" detection bez prawdziwego TPM.

    fn seal_software(&self, key: &[u8]) -> Result<Vec<u8>, HfsError> {
        log::warn!("TPM software seal: NO hardware protection — dev/test mode only");
        let salt: [u8; 16] = rand::random();
        let mut seal_key = Self::derive_software_seal_key(self.pcr_index, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&seal_key).map_err(|_| HfsError::CryptoError)?;
        seal_key.zeroize();
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = Self::soft_pcr_snapshot(self.pcr_index)?;
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: key, aad: &aad })
            .map_err(|_| HfsError::CryptoError)?;

        let mut private = Vec::with_capacity(16 + 12 + ciphertext.len());
        private.extend_from_slice(&salt);
        private.extend_from_slice(&nonce_bytes);
        private.extend_from_slice(&ciphertext);

        let blob = SealedBlob {
            pcr_index:    self.pcr_index,
            pcr_snapshot: aad,
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

        // "Soft PCR" check — analog wykrywania zmiany boot chain bez
        // prawdziwego TPM: jeśli machine-id/kernel się zmieniły od
        // momentu sealowania, odmawiamy (tak jak prawdziwy TPM odmówiłby
        // unseal po zmianie PCR).
        let current = Self::soft_pcr_snapshot(self.pcr_index)?;
        if current != blob.pcr_snapshot {
            return Err(HfsError::TpmError(
                "Soft-PCR mismatch — machine-id or kernel changed since sealing \
                 (software mode has no real TPM, this is a best-effort approximation). \
                 Boot with ghostfs.recovery=1 to unlock with a passphrase instead.".into()
            ));
        }

        if blob.private.len() < 16 + 12 {
            return Err(HfsError::TpmError("Corrupted software sealed blob (too short)".into()));
        }
        let salt        = &blob.private[..16];
        let nonce_bytes  = &blob.private[16..28];
        let ciphertext   = &blob.private[28..];

        let seal_key = Self::derive_software_seal_key(self.pcr_index, salt)?;
        let cipher   = Aes256Gcm::new_from_slice(&seal_key).map_err(|_| HfsError::CryptoError)?;
        let nonce    = Nonce::from_slice(nonce_bytes);
        let key = cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad: &blob.pcr_snapshot })
            .map_err(|_| HfsError::TpmError(
                "Software unseal failed — wrong machine, corrupted blob, or tampering".into()
            ))?;
        let mut seal_key = seal_key;
        seal_key.zeroize();
        Ok(key)
    }

    /// Klucz seal-key dla trybu software: KDF(machine-id || pcr_index || salt).
    /// Bez prawdziwego TPM to jedyne "coś czego atakujący nie ma" bez
    /// dostępu do samej maszyny — nie udajemy, że to jest bezpieczeństwo
    /// sprzętowe, ale to i tak nieporównywalnie lepsze niż klucz odzyskiwalny
    /// z samego bloba (jak w poprzedniej, zepsutej implementacji).
    fn derive_software_seal_key(pcr_index: u32, salt: &[u8]) -> Result<[u8; 32], HfsError> {
        let machine_id = Self::read_machine_id();
        let mut h = blake3::Hasher::new();
        h.update(b"ghostfs-tpm-software-seal-v1");
        h.update(machine_id.as_bytes());
        h.update(&pcr_index.to_le_bytes());
        h.update(salt);
        Ok(*h.finalize().as_bytes())
    }

    fn read_machine_id() -> String {
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(s) = std::fs::read_to_string(path) {
                let s = s.trim();
                if !s.is_empty() { return s.to_string(); }
            }
        }
        log::warn!(
            "TPM software mode: no /etc/machine-id found — using a fixed fallback identity. \
             This means sealed blobs are NOT bound to this specific machine. Install \
             `systemd` (or run `systemd-machine-id-setup`) to get a real machine-id."
        );
        "ghostfs-no-machine-id-fallback".to_string()
    }

    /// "Soft PCR": hash(machine-id || kernel release || pcr_index) — best-effort
    /// stand-in for a real PCR measurement when no TPM is present.
    fn soft_pcr_snapshot(pcr_index: u32) -> Result<Vec<u8>, HfsError> {
        let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "unknown-kernel".to_string());
        let mut h = blake3::Hasher::new();
        h.update(b"ghostfs-soft-pcr-v1");
        h.update(Self::read_machine_id().as_bytes());
        h.update(kernel_release.trim().as_bytes());
        h.update(&pcr_index.to_le_bytes());
        Ok(h.finalize().as_bytes().to_vec())
    }

    /// Sprawdź czy system posiada dostępny TPM 2.0.
    pub fn is_hardware_available() -> bool {
        Self::tpm_available()
    }
}
