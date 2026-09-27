use sled::Db;
use serde::{Serialize, Deserialize};
use crate::error::HfsError;

const WORM_PREFIX: &str = "worm:";

pub const XATTR_LOCK:          &str = "user.ghostfs.worm.lock";
pub const XATTR_RETAIN_UNTIL:  &str = "user.ghostfs.worm.retain_until";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WormState {
    pub immutable:       bool,
    /// Unix epoch seconds. 0 = brak twardej retencji.
    pub retention_until: u64,
}

#[derive(Clone)]
pub struct Worm {
    db: Db,
}

impl Worm {
    pub fn new(db: &Db) -> Result<Self, HfsError> {
        Ok(Self { db: db.clone() })
    }

    fn key(ino: u64) -> String { format!("{}{}", WORM_PREFIX, ino) }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    pub fn get(&self, ino: u64) -> Result<WormState, HfsError> {
        match self.db.get(Self::key(ino).as_bytes())? {
            Some(v) => Ok(bincode::deserialize(&v)?),
            None    => Ok(WormState::default()),
        }
    }

    fn put(&self, ino: u64, state: &WormState) -> Result<(), HfsError> {
        self.db.insert(Self::key(ino).as_bytes(), bincode::serialize(state)?)?;
        Ok(())
    }

    /// Czy TERAZ blokowane są zapisy/truncate/unlink/rename-jako-źródło.
    pub fn is_locked(&self, ino: u64) -> Result<bool, HfsError> {
        let s = self.get(ino)?;
        Ok(s.immutable || s.retention_until > Self::now())
    }

    /// Ustaw/zdejmij `immutable`. Zdjęcie odmawiane jeśli retencja twarda
    /// wciąż aktywna (niezależnie od `is_root`) — patrz dokumentacja modułu.
    pub fn set_immutable(&self, ino: u64, value: bool, is_root: bool) -> Result<(), HfsError> {
        if !is_root {
            return Err(HfsError::InvalidArgument(
                "WORM lock/unlock requires root (uid=0)".into()
            ));
        }
        let mut s = self.get(ino)?;
        if !value && s.retention_until > Self::now() {
            return Err(HfsError::InvalidArgument(format!(
                "Cannot clear immutable flag — active WORM retention until unix_ts={} \
                 ({}s remaining). This cannot be bypassed by root — that is the point.",
                s.retention_until, s.retention_until.saturating_sub(Self::now())
            )));
        }
        s.immutable = value;
        self.put(ino, &s)
    }

    /// Ustaw/wydłuż twardą retencję. TYLKO wydłużanie — próba skrócenia
    /// jest odrzucana, nie ma "force". Automatycznie ustawia `immutable=true`.
    pub fn extend_retention(&self, ino: u64, until: u64, is_root: bool) -> Result<(), HfsError> {
        if !is_root {
            return Err(HfsError::InvalidArgument(
                "WORM retention requires root (uid=0)".into()
            ));
        }
        let mut s = self.get(ino)?;
        if until <= s.retention_until {
            return Err(HfsError::InvalidArgument(format!(
                "WORM retention can only be EXTENDED, never shortened \
                 (current retain_until={}, requested={})", s.retention_until, until
            )));
        }
        s.retention_until = until;
        s.immutable = true;
        self.put(ino, &s)
    }

    pub fn remove_all(&self, ino: u64) -> Result<(), HfsError> {
        self.db.remove(Self::key(ino).as_bytes())?;
        Ok(())
    }
}
