use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression as FlateCompression;
use std::io::{Write, Read};
use crate::error::HfsError;

#[cfg(feature = "zstd")]
use zstd::stream::{Encoder as ZstdEncoder, Decoder as ZstdDecoder};
#[cfg(feature = "lz4")]
use lz4::{EncoderBuilder, Decoder};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompressionType { None, Zlib, #[cfg(feature="zstd")] Zstd, #[cfg(feature="lz4")] Lz4 }

#[derive(Clone)]
pub struct Compression { typ: CompressionType }

impl Compression {
    pub fn new(typ: CompressionType) -> Self { Self { typ } }
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, HfsError> {
        match self.typ {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Zlib => {
                let mut e = ZlibEncoder::new(Vec::new(), FlateCompression::default());
                e.write_all(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                e.finish().map_err(|e| HfsError::CompressionError(e.to_string()))
            }
            #[cfg(feature="zstd")]
            CompressionType::Zstd => {
                let mut e = ZstdEncoder::new(Vec::new(), 0).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                e.write_all(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                e.finish().map_err(|e| HfsError::CompressionError(e.to_string()))
            }
            #[cfg(feature="lz4")]
            CompressionType::Lz4 => {
                let mut e = EncoderBuilder::new().build(Vec::new()).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                e.write_all(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                let (r,_) = e.finish(); Ok(r)
            }
        }
    }
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, HfsError> {
        match self.typ {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Zlib => {
                let mut d = ZlibDecoder::new(data);
                let mut r = Vec::new();
                d.read_to_end(&mut r).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                Ok(r)
            }
            #[cfg(feature="zstd")]
            CompressionType::Zstd => {
                let mut d = ZstdDecoder::new(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                let mut r = Vec::new();
                d.read_to_end(&mut r).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                Ok(r)
            }
            #[cfg(feature="lz4")]
            CompressionType::Lz4 => {
                let mut d = Decoder::new(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                let mut r = Vec::new();
                d.read_to_end(&mut r).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                Ok(r)
            }
        }
    }
}
