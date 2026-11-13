//! Binary layout of the `.lav` file header. See `docs/FORMAT.md`.
//!
//! All integers are little-endian. Every header field before the commitment is
//! bound by the key commitment (checked before decryption), and the complete
//! header, commitment included, is the AEAD associated data.

use crate::crypto::{KdfParams, COMMITMENT_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{Error, Result};

pub const MAGIC: [u8; 4] = *b"LKAV";
/// Format 2 adds the key commitment. Format 1 is NOT readable: there is no
/// fallback path that skips the commitment check (downgrade protection).
pub const FORMAT_VERSION: u16 = 2;
pub const CIPHER_XCHACHA20_POLY1305: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;

pub const FLAG_KEYFILE: u16 = 0x0001;
const KNOWN_FLAGS: u16 = FLAG_KEYFILE;

/// magic(4) version(2) cipher(1) kdf(1) flags(2) mem(4) iter(4) par(4) salt(32) nonce(24):
/// every byte the key commitment covers.
pub const COMMITTED_LEN: usize = 4 + 2 + 1 + 1 + 2 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;

/// Committed fields followed by the 32-byte commitment.
pub const HEADER_LEN: usize = COMMITTED_LEN + COMMITMENT_LEN;

/// AEAD tag length (Poly1305).
pub const TAG_LEN: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub flags: u16,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// `HMAC-SHA256(commitment key, label || committed_bytes())`, see
    /// [`crate::crypto::DerivedKeys::commitment`].
    pub commitment: [u8; COMMITMENT_LEN],
}

impl Header {
    pub fn requires_keyfile(&self) -> bool {
        self.flags & FLAG_KEYFILE != 0
    }

    /// The header fields covered by the key commitment (everything but the
    /// commitment itself), exactly as they appear on disk.
    pub fn committed_bytes(&self) -> [u8; COMMITTED_LEN] {
        let mut out = [0u8; COMMITTED_LEN];
        let mut w = Writer {
            buf: &mut out,
            pos: 0,
        };
        w.put(&MAGIC);
        w.put(&FORMAT_VERSION.to_le_bytes());
        w.put(&[CIPHER_XCHACHA20_POLY1305]);
        w.put(&[KDF_ARGON2ID]);
        w.put(&self.flags.to_le_bytes());
        w.put(&self.kdf.memory_kib.to_le_bytes());
        w.put(&self.kdf.iterations.to_le_bytes());
        w.put(&self.kdf.parallelism.to_le_bytes());
        w.put(&self.salt);
        w.put(&self.nonce);
        debug_assert_eq!(w.pos, COMMITTED_LEN);
        out
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..COMMITTED_LEN].copy_from_slice(&self.committed_bytes());
        out[COMMITTED_LEN..].copy_from_slice(&self.commitment);
        out
    }

    /// Parses and validates the header. Returns the header, the raw header bytes
    /// (used as AEAD associated data) and the remaining ciphertext.
    pub fn parse(file: &[u8]) -> Result<(Header, &[u8], &[u8])> {
        if file.len() < MAGIC.len() || file[..MAGIC.len()] != MAGIC {
            return Err(Error::NotAVault);
        }
        // Version first, so any other version (in particular v1, which has no
        // commitment) is reported as such and never parsed further.
        if file.len() < MAGIC.len() + 2 {
            return Err(Error::Malformed);
        }
        let version = u16::from_le_bytes([file[4], file[5]]);
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        if file.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::Malformed);
        }
        let (raw, ciphertext) = file.split_at(HEADER_LEN);
        let mut r = Reader {
            buf: raw,
            pos: MAGIC.len() + 2,
        };

        let [cipher] = r.take();
        if cipher != CIPHER_XCHACHA20_POLY1305 {
            return Err(Error::UnsupportedAlgorithm(cipher));
        }
        let [kdf_id] = r.take();
        if kdf_id != KDF_ARGON2ID {
            return Err(Error::UnsupportedAlgorithm(kdf_id));
        }
        let flags = u16::from_le_bytes(r.take());
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Error::UnknownFlags(flags));
        }
        let kdf = KdfParams {
            memory_kib: u32::from_le_bytes(r.take()),
            iterations: u32::from_le_bytes(r.take()),
            parallelism: u32::from_le_bytes(r.take()),
        };
        kdf.validate()?;
        let salt = r.take();
        let nonce = r.take();
        let commitment = r.take();

        Ok((
            Header {
                flags,
                kdf,
                salt,
                nonce,
                commitment,
            },
            raw,
            ciphertext,
        ))
    }
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    /// Caller guarantees the buffer is exactly HEADER_LEN, so this never panics.
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let out: [u8; N] = self.buf[self.pos..self.pos + N].try_into().unwrap();
        self.pos += N;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            flags: FLAG_KEYFILE,
            kdf: KdfParams::default(),
            salt: [1; SALT_LEN],
            nonce: [2; NONCE_LEN],
            commitment: [3; COMMITMENT_LEN],
        }
    }

    fn file_with(header: &[u8]) -> Vec<u8> {
        let mut f = header.to_vec();
        f.extend_from_slice(&[0u8; TAG_LEN]);
        f
    }

    #[test]
    fn header_roundtrip() {
        let h = sample();
        let file = file_with(&h.to_bytes());
        let (parsed, raw, ct) = Header::parse(&file).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(raw.len(), HEADER_LEN);
        assert_eq!(ct.len(), TAG_LEN);
        assert!(parsed.requires_keyfile());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(matches!(Header::parse(b"nope"), Err(Error::NotAVault)));
        assert!(matches!(Header::parse(b"LKAV"), Err(Error::Malformed)));
        assert!(matches!(
            Header::parse(b"LKAV\x02\x00"),
            Err(Error::Malformed)
        ));
        assert!(matches!(
            Header::parse(b"LKAV\x01\x00"),
            Err(Error::UnsupportedVersion(1))
        ));

        let mut bytes = sample().to_bytes();
        bytes[4] = 9; // version
        assert!(matches!(
            Header::parse(&file_with(&bytes)),
            Err(Error::UnsupportedVersion(9))
        ));

        let mut bytes = sample().to_bytes();
        bytes[8] = 0x80; // unknown flag
        assert!(matches!(
            Header::parse(&file_with(&bytes)),
            Err(Error::UnknownFlags(_))
        ));

        let mut weak = sample();
        weak.kdf.memory_kib = 16;
        assert!(matches!(
            Header::parse(&file_with(&weak.to_bytes())),
            Err(Error::InvalidKdfParams)
        ));
    }
}
