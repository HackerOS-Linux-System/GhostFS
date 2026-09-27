use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression as FlateCompression;
use std::io::{Write, Read};
use crate::error::HfsError;

#[cfg(feature = "zstd")]
use zstd::stream::{Encoder as ZstdEncoder, Decoder as ZstdDecoder};
#[cfg(feature = "lz4")]
use lz4::{EncoderBuilder, Decoder};

/// Identyfikatory algorytmów kompresji w nagłówku bloku.
/// Format: pierwsze 2 bajty każdego skompresowanego bloku.
/// `[0x00, 0x00]` = brak kompresji (dane przekazane wprost).
const MAGIC_NONE: [u8; 2] = [0x00, 0x00];
const MAGIC_ZLIB: [u8; 2] = [0x47, 0x5A]; // "GZ"
const MAGIC_ZSTD: [u8; 2] = [0x5A, 0x53]; // "ZS"
const MAGIC_LZ4:  [u8; 2] = [0x4C, 0x34]; // "L4"

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompressionType {
    None,
    Zlib,
    #[cfg(feature = "zstd")]
    Zstd,
    #[cfg(feature = "lz4")]
    Lz4,
}

impl CompressionType {
    fn magic(self) -> [u8; 2] {
        match self {
            CompressionType::None => MAGIC_NONE,
            CompressionType::Zlib => MAGIC_ZLIB,
            #[cfg(feature = "zstd")]
            CompressionType::Zstd => MAGIC_ZSTD,
            #[cfg(feature = "lz4")]
            CompressionType::Lz4  => MAGIC_LZ4,
        }
    }
}

#[derive(Clone)]
pub struct Compression { typ: CompressionType }

impl Compression {
    pub fn new(typ: CompressionType) -> Self { Self { typ } }

    /// Kompresuj dane i poprzedź wynik 2-bajtowym nagłówkiem z identyfikatorem algorytmu.
    ///
    /// Gwarantuje to, że `decompress()` zawsze wie jakim algorytmem odczytać dane,
    /// niezależnie od ustawień wolumenu przy montowaniu (może się różnić od mkfs).
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, HfsError> {
        let compressed = self.compress_raw(data)?;
        let magic      = self.typ.magic();
        let mut out    = Vec::with_capacity(2 + compressed.len());
        out.extend_from_slice(&magic);
        out.extend_from_slice(&compressed);
        Ok(out)
    }

    /// Dekompresuj dane — odczytuje nagłówek i dobiera algorytm automatycznie.
    ///
    /// Ignoruje bieżące ustawienie `self.typ` i dekompresuje zgodnie z nagłówkiem.
    /// Dzięki temu pliki skompresowane zlib można poprawnie odczytać po zmianie
    /// domyślnego algorytmu na zstd i vice versa.
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, HfsError> {
        if data.len() < 2 {
            // Dane krótsze niż nagłówek — traktuj jako nieskompresowane (legacy/puste).
            return Ok(data.to_vec());
        }
        let magic   = [data[0], data[1]];
        let payload = &data[2..];

        match magic {
            MAGIC_NONE => Ok(payload.to_vec()),
            MAGIC_ZLIB => Self::decompress_zlib(payload),
            MAGIC_ZSTD => {
                #[cfg(feature = "zstd")]
                { Self::decompress_zstd(payload) }
                #[cfg(not(feature = "zstd"))]
                {
                    Err(HfsError::CompressionError(
                        "Block compressed with zstd but feature 'zstd' not compiled in".into()
                    ))
                }
            }
            MAGIC_LZ4 => {
                #[cfg(feature = "lz4")]
                { Self::decompress_lz4(payload) }
                #[cfg(not(feature = "lz4"))]
                {
                    Err(HfsError::CompressionError(
                        "Block compressed with lz4 but feature 'lz4' not compiled in".into()
                    ))
                }
            }
            unknown => {
                // Nagłówek nieznany — możliwe że to stary blok bez nagłówka (pre-fix).
                // Próba decompresji bieżącym algorytmem jako fallback.
                log::warn!(
                    "compression: unknown magic [{:#04x},{:#04x}] — \
                     trying legacy decompress with current codec",
                    unknown[0], unknown[1]
                );
                self.decompress_legacy(data)
            }
        }
    }

    // ── Raw compressors (bez nagłówka) ───────────────────────────────────────

    fn compress_raw(&self, data: &[u8]) -> Result<Vec<u8>, HfsError> {
        match self.typ {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Zlib => Self::compress_zlib(data),
            #[cfg(feature = "zstd")]
            CompressionType::Zstd => Self::compress_zstd(data),
            #[cfg(feature = "lz4")]
            CompressionType::Lz4  => Self::compress_lz4(data),
        }
    }

    fn compress_zlib(data: &[u8]) -> Result<Vec<u8>, HfsError> {
        let mut e = ZlibEncoder::new(Vec::new(), FlateCompression::default());
        e.write_all(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
        e.finish().map_err(|e| HfsError::CompressionError(e.to_string()))
    }

    fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>, HfsError> {
        let mut d = ZlibDecoder::new(data);
        let mut r = Vec::new();
        d.read_to_end(&mut r).map_err(|e| HfsError::CompressionError(e.to_string()))?;
        Ok(r)
    }

    #[cfg(feature = "zstd")]
    fn compress_zstd(data: &[u8]) -> Result<Vec<u8>, HfsError> {
        let mut e = ZstdEncoder::new(Vec::new(), 0)
            .map_err(|e| HfsError::CompressionError(e.to_string()))?;
        e.write_all(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
        e.finish().map_err(|e| HfsError::CompressionError(e.to_string()))
    }

    #[cfg(feature = "zstd")]
    fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, HfsError> {
        let mut d = ZstdDecoder::new(data)
            .map_err(|e| HfsError::CompressionError(e.to_string()))?;
        let mut r = Vec::new();
        d.read_to_end(&mut r).map_err(|e| HfsError::CompressionError(e.to_string()))?;
        Ok(r)
    }

    #[cfg(feature = "lz4")]
    fn compress_lz4(data: &[u8]) -> Result<Vec<u8>, HfsError> {
        let mut e = EncoderBuilder::new()
            .build(Vec::new())
            .map_err(|e| HfsError::CompressionError(e.to_string()))?;
        e.write_all(data).map_err(|e| HfsError::CompressionError(e.to_string()))?;
        let (r, _) = e.finish();
        Ok(r)
    }

    #[cfg(feature = "lz4")]
    fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>, HfsError> {
        let mut d = Decoder::new(data)
            .map_err(|e| HfsError::CompressionError(e.to_string()))?;
        let mut r = Vec::new();
        d.read_to_end(&mut r).map_err(|e| HfsError::CompressionError(e.to_string()))?;
        Ok(r)
    }

    /// Legacy fallback dla bloków bez nagłówka (przed wprowadzeniem magic bytes).
    fn decompress_legacy(&self, data: &[u8]) -> Result<Vec<u8>, HfsError> {
        match self.typ {
            CompressionType::None => Ok(data.to_vec()),
            CompressionType::Zlib => Self::decompress_zlib(data),
            #[cfg(feature = "zstd")]
            CompressionType::Zstd => Self::decompress_zstd(data),
            #[cfg(feature = "lz4")]
            CompressionType::Lz4  => Self::decompress_lz4(data),
        }
    }
}
