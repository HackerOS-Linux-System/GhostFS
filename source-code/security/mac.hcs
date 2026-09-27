use libc;
use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitivityLevel {
    Unclassified = 0,
    Restricted   = 1,
    Confidential = 2,
    TopSecret    = 3,
}

impl Default for SensitivityLevel { fn default() -> Self { SensitivityLevel::Unclassified } }

impl SensitivityLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v { 0 => Some(Self::Unclassified), 1 => Some(Self::Restricted),
            2 => Some(Self::Confidential), 3 => Some(Self::TopSecret), _ => None }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "Unclassified", Self::Restricted => "Restricted",
            Self::Confidential => "Confidential", Self::TopSecret   => "TopSecret",
        }
    }
}

pub type Compartments = u64;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MacLabel {
    pub level:        SensitivityLevel,
    pub compartments: Compartments,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MacClearance {
    pub level:        SensitivityLevel,
    pub compartments: Compartments,
    /// trusted=true: bypass compartment check (root only).
    /// WAŻNE: trusted NIE bypasuje write-down check — to byłoby naruszenie BLP.
    pub trusted:      bool,
}

impl Default for MacClearance {
    fn default() -> Self {
        MacClearance { level: SensitivityLevel::TopSecret, compartments: u64::MAX, trusted: true }
    }
}

pub const XATTR_LABEL:     &str = "security.ghostfs.label";
pub const XATTR_CLEARANCE: &str = "security.ghostfs.clearance";

#[derive(Clone)]
pub struct MacLabels { db: Db }

impl MacLabels {
    pub fn new(db: &Db) -> Result<Self, HfsError> { Ok(Self { db: db.clone() }) }

    pub fn set_label(&self, ino: u64, label: &MacLabel) -> Result<(), HfsError> {
        self.db.insert(format!("mac:label:{}", ino).as_bytes(), bincode::serialize(label)?)?;
        Ok(())
    }

    pub fn get_label(&self, ino: u64) -> Result<MacLabel, HfsError> {
        Ok(match self.db.get(format!("mac:label:{}", ino).as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
            None    => MacLabel::default(),
        })
    }

    pub fn set_clearance(&self, uid: u32, c: &MacClearance) -> Result<(), HfsError> {
        self.db.insert(format!("mac:clearance:{}", uid).as_bytes(), bincode::serialize(c)?)?;
        Ok(())
    }

    pub fn get_clearance(&self, uid: u32) -> Result<MacClearance, HfsError> {
        if uid == 0 { return Ok(MacClearance::default()); }
        Ok(match self.db.get(format!("mac:clearance:{}", uid).as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
            None    => MacClearance { level: SensitivityLevel::Unclassified, compartments: 0, trusted: false },
        })
    }

    pub fn parse_xattr_label(value: &[u8]) -> Option<MacLabel> {
        let s = std::str::from_utf8(value).ok()?;
        let mut parts = s.splitn(2, ':');
        let level = match parts.next()?.trim() {
            "Unclassified" => SensitivityLevel::Unclassified,
            "Restricted"   => SensitivityLevel::Restricted,
            "Confidential" => SensitivityLevel::Confidential,
            "TopSecret"    => SensitivityLevel::TopSecret,
            _              => return None,
        };
        let comps = u64::from_str_radix(
            parts.next().unwrap_or("0x0").trim().trim_start_matches("0x"), 16
        ).ok()?;
        Some(MacLabel { level, compartments: comps })
    }

    pub fn label_to_xattr(label: &MacLabel) -> Vec<u8> {
        format!("{}:0x{:x}", label.level.as_str(), label.compartments).into_bytes()
    }

    pub fn handle_setxattr_label(&self, ino: u64, value: &[u8]) -> Result<(), HfsError> {
        let label = Self::parse_xattr_label(value)
            .ok_or_else(|| HfsError::InvalidArgument("Invalid MAC label format".into()))?;
        self.set_label(ino, &label)?;
        log::info!("MAC label set: ino={} {:?}:{:#x}", ino, label.level, label.compartments);
        Ok(())
    }

    /// Bell-LaPadula constant-time check z pełną *-property.
    ///
    /// Reguły BLP:
    ///   ss-property (simple security / "no read up"):
    ///     clearance.level >= label.level  (można czytać poziom <= własnego)
    ///   *-property (star property / "no write down"):
    ///     clearance.level <= label.level  (można pisać poziom >= własnego)
    ///     → zapobiega wyciekowi informacji przez trojańskiego konia
    ///   ds-property (discretionary / compartments):
    ///     clearance.compartments ⊇ label.compartments
    ///
    /// `trusted` flag (tylko root) bypass'uje tylko compartment check,
    /// NIE bypass'uje write-down — to zachowanie chroni przed insider threat.
    pub fn check_ct(
        &self,
        ino:         u64,
        uid:         u32,
        _gid:        u32,
        access_mask: i32,
    ) -> Result<bool, HfsError> {
        let label     = self.get_label(ino)?;
        let clearance = self.get_clearance(uid)?;

        // Stałoczasowe obliczenia wszystkich reguł przed decyzją.
        let is_read  = (access_mask & libc::R_OK) != 0;
        let is_write = (access_mask & libc::W_OK) != 0;

        // ss-property: no read up (clearance >= label)
        let read_level_ok:  u8 = (!is_read  || clearance.level >= label.level) as u8;

        // *-property: no write down (clearance <= label)
        // KRYTYCZNE: nawet trusted nie może pisać do niżej sklasyfikowanego pliku.
        let write_level_ok: u8 = (!is_write || clearance.level <= label.level) as u8;

        // ds-property: compartments
        let comps_match: u8 = (label.compartments == 0
            || (clearance.compartments & label.compartments) == label.compartments) as u8;

        // trusted bypass: tylko compartments, nigdy write-down
        let comps_ok: u8 = (clearance.trusted as u8) | comps_match;

        let allowed = (read_level_ok & write_level_ok & comps_ok) != 0;

        if !allowed {
            log::debug!(
                "MAC deny: ino={} uid={} label={:?} clearance={:?} mask={}",
                ino, uid, label.level, clearance.level, access_mask
            );
        }
        Ok(allowed)
    }

    pub fn check(&self, ino: u64, uid: u32, gid: u32, mask: i32) -> Result<bool, HfsError> {
        self.check_ct(ino, uid, gid, mask)
    }
}
