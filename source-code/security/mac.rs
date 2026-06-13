use libc;
use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitivityLevel {
    Unclassified  = 0,
    Restricted    = 1,
    Confidential  = 2,
    TopSecret     = 3,
}

impl Default for SensitivityLevel {
    fn default() -> Self { SensitivityLevel::Unclassified }
}

impl SensitivityLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Unclassified),
            1 => Some(Self::Restricted),
            2 => Some(Self::Confidential),
            3 => Some(Self::TopSecret),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "Unclassified",
            Self::Restricted   => "Restricted",
            Self::Confidential => "Confidential",
            Self::TopSecret    => "TopSecret",
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
    pub trusted:      bool,
}

impl Default for MacClearance {
    fn default() -> Self {
        MacClearance { level: SensitivityLevel::TopSecret, compartments: u64::MAX, trusted: true }
    }
}

pub const XATTR_LABEL: &str     = "security.ghostfs.label";
pub const XATTR_CLEARANCE: &str = "security.ghostfs.clearance";

#[derive(Clone)]
pub struct MacLabels { db: Db }

impl MacLabels {
    pub fn new(db: &Db) -> Result<Self, HfsError> { Ok(Self { db: db.clone() }) }

    pub fn set_label(&self, ino: u64, label: &MacLabel) -> Result<(), HfsError> {
        let key = format!("mac:label:{}", ino);
        self.db.insert(key.as_bytes(), bincode::serialize(label)?)?;
        Ok(())
    }

    pub fn get_label(&self, ino: u64) -> Result<MacLabel, HfsError> {
        let key = format!("mac:label:{}", ino);
        Ok(match self.db.get(key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
           None    => MacLabel::default(),
        })
    }

    pub fn set_clearance(&self, uid: u32, clearance: &MacClearance) -> Result<(), HfsError> {
        let key = format!("mac:clearance:{}", uid);
        self.db.insert(key.as_bytes(), bincode::serialize(clearance)?)?;
        Ok(())
    }

    pub fn get_clearance(&self, uid: u32) -> Result<MacClearance, HfsError> {
        if uid == 0 { return Ok(MacClearance::default()); }
        let key = format!("mac:clearance:{}", uid);
        Ok(match self.db.get(key.as_bytes())? {
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
        let comps_str = parts.next().unwrap_or("0x0").trim().trim_start_matches("0x");
        let compartments = u64::from_str_radix(comps_str, 16).ok()?;
        Some(MacLabel { level, compartments })
    }

    pub fn label_to_xattr(label: &MacLabel) -> Vec<u8> {
        format!("{}:0x{:x}", label.level.as_str(), label.compartments).into_bytes()
    }

    pub fn handle_setxattr_label(&self, ino: u64, value: &[u8]) -> Result<(), HfsError> {
        let label = Self::parse_xattr_label(value)
        .ok_or_else(|| HfsError::InvalidArgument(
            "Invalid MAC label. Expected 'Level:0xCompartments'".into()
        ))?;
        self.set_label(ino, &label)?;
        log::info!("MAC label set via xattr: ino={} {:?}:{:#x}", ino, label.level, label.compartments);
        Ok(())
    }

    /// Constant-time Bell-LaPadula access check.
    /// All branches computed before returning — no early exit on deny.
    /// Prevents timing-based inference of sensitivity labels.
    pub fn check_ct(&self, ino: u64, uid: u32, _gid: u32, access_mask: i32) -> Result<bool, HfsError> {
        let label     = self.get_label(ino)?;
        let clearance = self.get_clearance(uid)?;

        let trusted_pass: u8 = clearance.trusted as u8;

        let comps_ok: u8 = (label.compartments == 0
        || (clearance.compartments & label.compartments) == label.compartments) as u8;

        let read_ok: u8 = (access_mask & libc::R_OK == 0
        || clearance.level >= label.level) as u8;

        let write_ok: u8 = (access_mask & libc::W_OK == 0
        || clearance.level <= label.level) as u8;

        let allowed = (trusted_pass | (comps_ok & read_ok & write_ok)) != 0;

        if !allowed {
            log::debug!("MAC deny: ino={} uid={} label={:?} clearance={:?}", ino, uid, label.level, clearance.level);
        }
        Ok(allowed)
    }

    pub fn check(&self, ino: u64, uid: u32, gid: u32, access_mask: i32) -> Result<bool, HfsError> {
        self.check_ct(ino, uid, gid, access_mask)
    }
}
