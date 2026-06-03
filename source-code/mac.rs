use libc;

use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

/// Sensitivity levels (mirrors common government classification schemes)
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitivityLevel {
    Unclassified = 0,
    Restricted = 1,
    Confidential = 2,
    TopSecret = 3,
}

impl Default for SensitivityLevel {
    fn default() -> Self {
        SensitivityLevel::Unclassified
    }
}

/// Compartments are bit-flags (up to 64 compartments).
pub type Compartments = u64;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MacLabel {
    pub level: SensitivityLevel,
    pub compartments: Compartments,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MacClearance {
    pub level: SensitivityLevel,
    pub compartments: Compartments,
    /// Allow write to any level regardless of No-Write-Down (admin override)
    pub trusted: bool,
}

impl Default for MacClearance {
    fn default() -> Self {
        MacClearance {
            level: SensitivityLevel::TopSecret,
            compartments: u64::MAX,
            trusted: true,
        }
    }
}

#[derive(Clone)]
pub struct MacLabels {
    db: Db,
}

impl MacLabels {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    pub fn set_label(&self, ino: u64, label: &MacLabel) -> Result<(), HfsError> {
        let key = format!("mac:label:{}", ino);
        self.db.insert(key.as_bytes(), bincode::serialize(label)?)?;
        Ok(())
    }

    pub fn get_label(&self, ino: u64) -> Result<MacLabel, HfsError> {
        let key = format!("mac:label:{}", ino);
        Ok(match self.db.get(key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
           None => MacLabel::default(),
        })
    }

    pub fn set_clearance(&self, uid: u32, clearance: &MacClearance) -> Result<(), HfsError> {
        let key = format!("mac:clearance:{}", uid);
        self.db.insert(key.as_bytes(), bincode::serialize(clearance)?)?;
        Ok(())
    }

    pub fn get_clearance(&self, uid: u32) -> Result<MacClearance, HfsError> {
        if uid == 0 {
            return Ok(MacClearance::default()); // root is always trusted
        }
        let key = format!("mac:clearance:{}", uid);
        Ok(match self.db.get(key.as_bytes())? {
            Some(v) => bincode::deserialize(&v)?,
           None => MacClearance {
               level: SensitivityLevel::Unclassified,
               compartments: 0,
               trusted: false,
           },
        })
    }

    /// Return true if subject (uid, gid) may perform `access_mask` on inode.
    /// Called *before* standard DAC checks.
    pub fn check(
        &self,
        ino: u64,
        uid: u32,
        _gid: u32,
        access_mask: i32,
    ) -> Result<bool, HfsError> {
        let label = self.get_label(ino)?;
        let clearance = self.get_clearance(uid)?;

        // Trusted subjects bypass No-Write-Down
        if clearance.trusted {
            return Ok(true);
        }

        // Compartment check: subject must hold all compartments the file requires
        if label.compartments != 0
            && (clearance.compartments & label.compartments) != label.compartments
            {
                return Ok(false);
            }

            // No-Read-Up: reads require clearance.level >= label.level
            if access_mask & libc::R_OK != 0 {
                if clearance.level < label.level {
                    return Ok(false);
                }
            }

            // No-Write-Down: writes require clearance.level <= label.level
            if access_mask & libc::W_OK != 0 {
                if clearance.level > label.level {
                    return Ok(false);
                }
            }

            Ok(true)
    }
}
