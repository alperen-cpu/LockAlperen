//! Cryptographic primitives. Nothing here is hand-rolled: we only compose
//! audited RustCrypto crates (Argon2id, HKDF-SHA256, XChaCha20-Poly1305).

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

const HKDF_INFO_PAYLOAD: &[u8] = b"LKAV v1 payload encryption key";

/// Argon2id cost parameters, stored in the vault header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Lower bounds = OWASP Password Storage Cheat Sheet minimum for Argon2id
    /// (19 MiB, 2 passes). Enforced for new vaults AND on open, so neither a
    /// caller bug nor an edited file can produce a weak vault. (The header is
    /// also authenticated; this fails fast before any work.)
    pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
    /// Upper bounds stop a malicious file from exhausting RAM/CPU on open
    /// (LA-12): at most 1 GiB and 20 passes, checked before any KDF work.
    pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    pub const MIN_ITERATIONS: u32 = 2;
    pub const MAX_ITERATIONS: u32 = 20;
    pub const MIN_PARALLELISM: u32 = 1;
    pub const MAX_PARALLELISM: u32 = 16;

    pub fn validate(&self) -> Result<()> {
        let ok = (Self::MIN_MEMORY_KIB..=Self::MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (Self::MIN_ITERATIONS..=Self::MAX_ITERATIONS).contains(&self.iterations)
            && (Self::MIN_PARALLELISM..=Self::MAX_PARALLELISM).contains(&self.parallelism)
            // Argon2 requires at least 8 KiB per lane.
            && self.memory_kib >= 8 * self.parallelism;
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidKdfParams)
        }
    }
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 4 lanes: roughly 0.3–0.8 s on a typical desktop CPU.
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// The user's credentials, pre-hashed: SHA-256(NFC(password)) [|| SHA-256(key file)].
///
/// The password is Unicode-normalized (NFC) first, so Turkish letters typed via
/// different keyboards / IMEs / copy-paste always produce the same key.
pub struct CompositeKey(Zeroizing<Vec<u8>>);

impl CompositeKey {
    pub fn new(password: &str, keyfile: Option<&[u8]>) -> Self {
        // Pre-size so the String never reallocates (a realloc would leave an
        // un-wiped copy of the password in freed heap memory). NFC output is
        // at most 3x the input length.
        let mut normalized = Zeroizing::new(String::with_capacity(password.len() * 3 + 4));
        normalized.extend(password.nfc());

        let mut buf = Zeroizing::new(Vec::with_capacity(64));
        buf.extend_from_slice(&sha256(normalized.as_bytes())[..]);
        if let Some(kf) = keyfile {
            buf.extend_from_slice(&sha256(kf)[..]);
        }
        Self(buf)
    }
}

/// Constant-time equality for key material.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// SHA-256 written straight into a self-wiping buffer (no stray copy on the stack).
pub(crate) fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Sha256::new()
        .chain_update(data)
        .finalize_into(GenericArray::from_mut_slice(&mut out[..]));
    out
}

/// Argon2id(composite, salt) -> master key, then HKDF-SHA256 -> payload key.
pub fn derive_payload_key(
    composite: &CompositeKey,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    params.validate()?;
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params.clone());

    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    // Own, self-wiping working memory: the final Argon2 block alone is enough
    // to recompute the master key, so it must not be freed unwiped.
    let mut blocks = Zeroizing::new(vec![Block::default(); argon_params.block_count()]);
    argon
        .hash_password_into_with_memory(&composite.0, salt, &mut master[..], &mut blocks[..])
        .map_err(|_| Error::KeyDerivation)?;

    let hk = Hkdf::<Sha256>::new(None, &master[..]);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_INFO_PAYLOAD, &mut key[..])
        .map_err(|_| Error::KeyDerivation)?;
    Ok(key)
}

pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::EncryptionFailed)?;
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::EncryptionFailed)
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::DecryptionFailed)?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: KdfParams::MIN_MEMORY_KIB,
            iterations: KdfParams::MIN_ITERATIONS,
            parallelism: 1,
        }
    }

    #[test]
    fn kdf_is_deterministic_and_credential_sensitive() {
        let salt = [7u8; SALT_LEN];
        let a = derive_payload_key(&CompositeKey::new("pw", None), &salt, &fast()).unwrap();
        let b = derive_payload_key(&CompositeKey::new("pw", None), &salt, &fast()).unwrap();
        let c = derive_payload_key(&CompositeKey::new("pw2", None), &salt, &fast()).unwrap();
        let d = derive_payload_key(&CompositeKey::new("pw", Some(b"kf")), &salt, &fast()).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
    }

    #[test]
    fn password_is_unicode_normalized() {
        // Precomposed U+015F vs. "s" + combining cedilla U+0327.
        let salt = [9u8; SALT_LEN];
        let a = derive_payload_key(&CompositeKey::new("pa\u{015F}", None), &salt, &fast()).unwrap();
        let b =
            derive_payload_key(&CompositeKey::new("pas\u{0327}", None), &salt, &fast()).unwrap();
        assert!(ct_eq(&a[..], &b[..]));
    }

    #[test]
    fn kdf_rejects_out_of_range_params() {
        let weak = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        assert!(matches!(weak.validate(), Err(Error::InvalidKdfParams)));
        let huge = KdfParams {
            memory_kib: u32::MAX,
            iterations: 1,
            parallelism: 1,
        };
        assert!(huge.validate().is_err());
        assert!(KdfParams::default().validate().is_ok());
    }

    #[test]
    fn aead_roundtrip_and_aad_binding() {
        let key = random_bytes::<KEY_LEN>();
        let nonce = random_bytes::<NONCE_LEN>();
        let ct = encrypt(&key, &nonce, b"header", b"secret").unwrap();
        assert_eq!(&**decrypt(&key, &nonce, b"header", &ct).unwrap(), b"secret");
        assert!(decrypt(&key, &nonce, b"HEADER", &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(decrypt(&key, &nonce, b"header", &bad).is_err());
    }
}
