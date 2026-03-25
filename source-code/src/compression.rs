use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use std::io::{Write, Read};
use crate::error::HfsError;

#[cfg(feature = "zstd")]
use zstd::stream::{Encoder as ZstdEncoder, Decoder as ZstdDecoder};
#[cfg(feature = "lz4")]
use lz4::{EncoderBuilder, Decoder};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    None,
    Zlib,
    #[cfg(feature = "zstd")]
    Zstd,
    #[cfg(feature = "lz4")]
    Lz4,
}

pub struct Compression {
    typ: CompressionType,
}

impl Compression {
    pub fn new(typ: CompressionType) -> Self {
        Self { typ }
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, HfsError> {
        match self.typ {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Zlib => {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                encoder.finish().map_err(|e| HfsError::CompressionError(e.to_string()))
            }
            #[cfg(feature = "zstd")]
            CompressionType::Zstd => {
                let mut encoder = ZstdEncoder::new(Vec::new(), 0)
                    .map_err(|e| HfsError::CompressionError(e.to_string()))?;
                encoder.write_all(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                encoder.finish().map_err(|e| HfsError::CompressionError(e.to_string()))
            }
            #[cfg(feature = "lz4")]
            CompressionType::Lz4 => {
                let mut encoder = EncoderBuilder::new()
                    .build(Vec::new())
                    .map_err(|e| HfsError::CompressionError(e.to_string()))?;
                encoder.write_all(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                let (result, _) = encoder.finish();
                Ok(result)
            }
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, HfsError> {
        match self.typ {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Zlib => {
                let mut decoder = ZlibDecoder::new(data);
                let mut result = Vec::new();
                decoder.read_to_end(&mut result).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                Ok(result)
            }
            #[cfg(feature = "zstd")]
            CompressionType::Zstd => {
                let mut decoder = ZstdDecoder::new(data)
                    .map_err(|e| HfsError::CompressionError(e.to_string()))?;
                let mut result = Vec::new();
                decoder.read_to_end(&mut result).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                Ok(result)
            }
            #[cfg(feature = "lz4")]
            CompressionType::Lz4 => {
                let mut decoder = Decoder::new(data)
                    .map_err(|e| HfsError::CompressionError(e.to_string()))?;
                let mut result = Vec::new();
                decoder.read_to_end(&mut result).map_err(|e| HfsError::CompressionError(e.to_string()))?;
                Ok(result)
            }
        }
    }
}
