use flate2::read::GzDecoder;
#[cfg(feature = "save_kdbx4")]
use flate2::write::GzEncoder;
#[cfg(feature = "save_kdbx4")]
use flate2::Compression as Flate2Compression;
use std::io::Read;
#[cfg(feature = "save_kdbx4")]
use std::io::Write;

/// LockAlperen patch: the most a gzip stream may inflate to. The importer
/// accepts 64 MiB files with up to 256 MiB of attachments in total.
pub const MAX_DECOMPRESSED: u64 = 384 * 1024 * 1024;

pub trait Compression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;
}

pub struct NoCompression;

impl Compression for NoCompression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }
}

pub struct GZipCompression;

impl Compression for GZipCompression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut res = Vec::new();
        let mut encoder = GzEncoder::new(&mut res, Flate2Compression::default());
        encoder.write_all(in_buffer)?;
        encoder.flush()?;
        encoder.finish()?;
        Ok(res)
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        // LockAlperen patch: a bounded read, so a small file that inflates to
        // gigabytes (gzip bomb) fails instead of exhausting memory.
        let mut res = Vec::new();
        GzDecoder::new(in_buffer)
            .take(MAX_DECOMPRESSED + 1)
            .read_to_end(&mut res)?;
        if res.len() as u64 > MAX_DECOMPRESSED {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed data is too large",
            ));
        }
        Ok(res)
    }
}

#[cfg(all(test, feature = "save_kdbx4"))]
mod lockalperen_tests {
    use super::*;

    #[test]
    fn gzip_bomb_is_refused() {
        let bomb = GZipCompression
            .compress(&vec![0u8; MAX_DECOMPRESSED as usize + 1])
            .unwrap();
        assert!(bomb.len() < 1024 * 1024);
        assert!(GZipCompression.decompress(&bomb).is_err());
        let ok = GZipCompression.compress(b"hello").unwrap();
        assert_eq!(GZipCompression.decompress(&ok).unwrap(), b"hello");
    }
}
