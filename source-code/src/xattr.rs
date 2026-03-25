use sled::Db;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

pub struct XAttr {
    db: Db,
}

impl XAttr {
    pub fn new(db: &Db) -> Result<Self, ()> {
        Ok(Self { db: db.clone() })
    }

    pub fn get(&self, ino: u64, name: &OsStr) -> Result<Option<Vec<u8>>, ()> {
        let key = format!("xattr:{}:{}", ino, String::from_utf8_lossy(name.as_bytes()));
        self.db.get(key.as_bytes()).map(|opt| opt.map(|v| v.to_vec())).map_err(|_| ())
    }

    pub fn set(&self, ino: u64, name: &OsStr, value: &[u8]) -> Result<(), ()> {
        let key = format!("xattr:{}:{}", ino, String::from_utf8_lossy(name.as_bytes()));
        self.db.insert(key.as_bytes(), value).map_err(|_| ())?;
        Ok(())
    }

    pub fn list(&self, ino: u64) -> Result<Vec<OsString>, ()> {
        let prefix = format!("xattr:{}:", ino);
        let mut names = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (k, _) = item.map_err(|_| ())?;
            let k_str = String::from_utf8(k.to_vec()).map_err(|_| ())?;
            if let Some(suffix) = k_str.strip_prefix(&prefix) {
                names.push(OsString::from(suffix));
            }
        }
        Ok(names)
    }

    pub fn remove(&self, ino: u64, name: &OsStr) -> Result<(), ()> {
        let key = format!("xattr:{}:{}", ino, String::from_utf8_lossy(name.as_bytes()));
        self.db.remove(key.as_bytes()).map_err(|_| ())?;
        Ok(())
    }
}
