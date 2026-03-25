use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use std::io::{Write, Read};

#[derive(Clone, Copy)]
pub enum CompressionType {
    None,
    Zlib,
}

pub struct Compression {
    typ: CompressionType,
}

impl Compression {
    pub fn new(typ: CompressionType) -> Self {
        Self { typ }
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        match self.typ {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Zlib => {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data).map_err(|_| ())?;
                encoder.finish().map_err(|_| ())
            }
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        match self.typ {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Zlib => {
                let mut decoder = ZlibDecoder::new(data);
                let mut result = Vec::new();
                decoder.read_to_end(&mut result).map_err(|_| ())?;
                Ok(result)
            }
        }
    }
}
