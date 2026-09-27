use sled::Db;
use rand::Rng;
use crate::error::HfsError;

/// Standardy nadpisywania.
#[derive(Clone, Copy, Debug)]
pub enum WipeMode {
    /// 1 pass losowych danych (default — szybki).
    Fast,
    /// DoD 5220.22-M: 3 passy (0x00, 0xFF, losowe).
    Dod3,
    /// DoD 5220.22-M-E: 7 passów.
    Dod7,
    /// Gutmann: 35 passów (paranoiczny).
    Gutmann,
    /// Red Team "ghost": nadpisz danymi wyglądającymi jak losowe bajty z rozkładu
    /// uniform — sprawia że narzędzia forensics nie rozróżniają danych od szumu.
    Ghost,
}

impl WipeMode {
    fn passes(self) -> Vec<Option<u8>> {
        match self {
            WipeMode::Fast    => vec![None],
            WipeMode::Dod3    => vec![Some(0x00), Some(0xFF), None],
            WipeMode::Dod7    => vec![
                Some(0x00), Some(0xFF), Some(0x92), Some(0x49),
                Some(0x24), Some(0x00), None,
            ],
            WipeMode::Gutmann => gutmann_passes(),
            WipeMode::Ghost   => vec![None, None, None], // 3x losowe
        }
    }
}

fn gutmann_passes() -> Vec<Option<u8>> {
    // 35 passów Gutmanna: 4 losowe + 27 wzorców + 4 losowe
    let mut p = vec![None, None, None, None];
    // Wzorce Gutmanna (wybrane)
    for &b in &[0x55u8,0xAA,0x92,0x49,0x24,0x00,0x11,0x22,0x33,0x44,
                0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,
                0xFF,0x92,0x49,0x24,0x6D,0xB6,0xDB] {
        p.push(Some(b));
    }
    p.push(None); p.push(None); p.push(None); p.push(None);
    p
}

#[derive(Clone)]
pub struct SecureDelete {
    _db:  Db,
    mode: WipeMode,
}

impl SecureDelete {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { _db: db.clone(), mode: WipeMode::Dod3 })
    }

    pub fn with_mode(db: &Db, mode: WipeMode) -> Result<Self, HfsError> {
        Ok(Self { _db: db.clone(), mode })
    }

    /// Nadpisz i usuń blok według wybranego standardu.
    pub fn wipe_block(&self, db: &Db, key: &str) -> Result<(), HfsError> {
        let current = match db.get(key.as_bytes())? {
            Some(v) => v,
            None    => return Ok(()),
        };
        let size   = current.len();
        let passes = self.mode.passes();

        for pass_byte in &passes {
            let data: Vec<u8> = match pass_byte {
                Some(b) => vec![*b; size],
                None    => (0..size).map(|_| rand::thread_rng().gen::<u8>()).collect(),
            };
            db.insert(key.as_bytes(), data)?;
            db.flush()?; // gwarantuj zapis na dysk przed kolejnym passem
        }

        db.remove(key.as_bytes())?;
        db.flush()?;
        Ok(())
    }

    pub fn wipe_inode_blocks(&self, db: &Db, ino: u64) -> Result<u64, HfsError> {
        let prefix = format!("data:{}:", ino);
        let keys: Vec<String> = db.scan_prefix(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .filter_map(|(k, _)| String::from_utf8(k.to_vec()).ok())
            .collect();
        let count = keys.len() as u64;
        for key in &keys { self.wipe_block(db, key)?; }
        // Wymusz kompakcję sled aby usunąć tombstone'y LSM.
        // sled nie ma publicznego compact() — używamy flush z pełnym sync.
        db.flush()?;
        log::info!("GhostFS secure_delete: wiped {} blocks for ino={} (mode={:?})", count, ino, self.mode);
        Ok(count)
    }

    pub fn wipe_metadata(&self, db: &Db, ino: u64) -> Result<(), HfsError> {
        let prefixes = [
            format!("xattr:{}:", ino),
            format!("mac:label:{}", ino),
            format!("itree:{}:", ino),
            format!("hash:{}:", ino),
            format!("ref:{}:", ino),
        ];
        for prefix in &prefixes {
            let keys: Vec<Vec<u8>> = db.scan_prefix(prefix.as_bytes())
                .filter_map(|r| r.ok()).map(|(k, _)| k.to_vec()).collect();
            for key in keys {
                let key_str = String::from_utf8(key).map_err(HfsError::Utf8)?;
                self.wipe_block(db, &key_str)?;
            }
        }
        db.flush()?;
        Ok(())
    }
}
