use sled::Db;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use crate::error::HfsError;

pub struct XAttr { db: Db }

impl XAttr {
    pub fn new(db: &Db) -> Result<Self, HfsError> { Ok(Self { db: db.clone() }) }
    pub fn get(&self, ino: u64, name: &OsStr) -> Result<Option<Vec<u8>>, HfsError> {
        let k = format!("xattr:{}:{}", ino, String::from_utf8_lossy(name.as_bytes()));
        Ok(self.db.get(k.as_bytes())?.map(|v| v.to_vec()))
    }
    pub fn set(&self, ino: u64, name: &OsStr, value: &[u8]) -> Result<(), HfsError> {
        let k = format!("xattr:{}:{}", ino, String::from_utf8_lossy(name.as_bytes()));
        self.db.insert(k.as_bytes(), value)?;
        Ok(())
    }
    pub fn list(&self, ino: u64) -> Result<Vec<OsString>, HfsError> {
        let prefix = format!("xattr:{}:", ino);
        let mut names = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (k, _) = item?;
            let ks = String::from_utf8(k.to_vec())?;
            if let Some(s) = ks.strip_prefix(&prefix) {
                names.push(OsString::from(s));
            }
        }
        Ok(names)
    }
    pub fn remove(&self, ino: u64, name: &OsStr) -> Result<(), HfsError> {
        let k = format!("xattr:{}:{}", ino, String::from_utf8_lossy(name.as_bytes()));
        self.db.remove(k.as_bytes())?;
        Ok(())
    }
}
