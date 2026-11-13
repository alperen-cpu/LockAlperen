//! Cryptographic primitives. Nothing here is hand-rolled: we only compose
//! audited RustCrypto crates (Argon2id, HKDF-SHA256, HMAC-SHA256,
//! XChaCha20-Poly1305).

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use unicode_normalization::char::{canonical_combining_class, compose, decompose_canonical};
use unicode_normalization::{is_nfc_quick, IsNormalized};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

/// Commitment length: full SHA-256 output, never truncated.
pub const COMMITMENT_LEN: usize = 32;

/// Unchanged since format v1 on purpose (no unnecessary change to the key
/// schedule); format v1 files are rejected by the header version anyway.
const HKDF_INFO_PAYLOAD: &[u8] = b"LKAV v1 payload encryption key";
/// Separate, purpose-specific key for the key commitment (format v2).
const HKDF_INFO_COMMITMENT: &[u8] = b"LKAV v2 key commitment";
/// Domain label prepended to the HMAC input. The input after it is the
/// fixed-length header prefix, so the encoding is unambiguous.
const COMMITMENT_LABEL: &[u8] = b"LKAV-commit v2";

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
        // Exact final size up front: the buffer never reallocates, and both
        // digests are written straight into it (no returned stack copy).
        let len = if keyfile.is_some() { 64 } else { 32 };
        let mut buf = Zeroizing::new(Vec::with_capacity(len));
        buf.resize(len, 0);
        scrubbed(|| {
            let normalized = nfc_password(password);
            sha256_into(normalized.as_bytes(), &mut buf[..32]);
            if let Some(kf) = keyfile {
                sha256_into(kf, &mut buf[32..64]);
            }
        });
        Self(buf)
    }
}

/// NFC without heap copies that are freed unwiped (PR-1, M5/M6).
///
/// `unicode-normalization`'s iterators buffer combining sequences in a TinyVec
/// that spills to the heap and is freed without wiping. Only a quick-check
/// result of `Yes` proves the input is already NFC; `Maybe` and `No` go
/// through the full algorithm below, which uses the library's own
/// character-level tables (`decompose_canonical`, `canonical_combining_class`,
/// `compose`) and implements only UAX #15 canonical ordering and canonical
/// composition, the same steps as the library's `Recompositions`. Every
/// buffer is exactly pre-sized (no realloc) and self-wiping. Equivalence with
/// `nfc()` is tested over all scalar values and random strings.
pub(crate) fn nfc_password(s: &str) -> Zeroizing<String> {
    if is_nfc_quick(s.chars()) == IsNormalized::Yes {
        let mut out = Zeroizing::new(String::with_capacity(s.len()));
        out.push_str(s);
        return out;
    }
    // Pass 1: exact decomposed length, so pass 2 never reallocates.
    let mut n = 0usize;
    for c in s.chars() {
        decompose_canonical(c, |_| n += 1);
    }
    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(n));
    for c in s.chars() {
        decompose_canonical(c, |d| chars.push(d));
    }
    debug_assert_eq!(chars.len(), n);
    canonical_order(&mut chars);
    let len = compose_in_place(&mut chars);
    let bytes = chars[..len].iter().map(|c| c.len_utf8()).sum();
    let mut out = Zeroizing::new(String::with_capacity(bytes));
    out.extend(chars[..len].iter());
    out
}

/// UAX #15 canonical ordering: stable sort by combining class inside every
/// run of non-starters. Insertion sort: in place, no allocation.
fn canonical_order(v: &mut [char]) {
    let mut i = 0;
    while i < v.len() {
        if canonical_combining_class(v[i]) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < v.len() && canonical_combining_class(v[i]) != 0 {
            i += 1;
        }
        let run = &mut v[start..i];
        for j in 1..run.len() {
            let mut k = j;
            while k > 0 && canonical_combining_class(run[k - 1]) > canonical_combining_class(run[k])
            {
                run.swap(k - 1, k);
                k -= 1;
            }
        }
    }
}

/// UAX #15 canonical composition, in place. Returns the new length.
/// A character composes with the last starter unless it is blocked, i.e. a
/// character written since that starter has a combining class >= its own.
fn compose_in_place(v: &mut [char]) -> usize {
    let mut w = 0;
    let mut starter: Option<usize> = None;
    let mut last_ccc: Option<u8> = None;
    for r in 0..v.len() {
        let c = v[r];
        let ccc = canonical_combining_class(c);
        if let Some(si) = starter {
            let blocked = matches!(last_ccc, Some(l) if l >= ccc);
            if !blocked {
                if let Some(composed) = compose(v[si], c) {
                    v[si] = composed;
                    continue;
                }
            }
        }
        if ccc == 0 {
            starter = Some(w);
            last_ccc = None;
        } else {
            last_ccc = Some(ccc);
        }
        v[w] = c;
        w += 1;
    }
    w
}

/// Constant-time equality for key material.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// SHA-256 of public data (file fingerprints).
pub(crate) fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    sha256_into(data, &mut out[..]);
    out
}

/// SHA-256 written straight into `out` (exactly 32 bytes).
fn sha256_into(data: &[u8], out: &mut [u8]) {
    Sha256::new()
        .chain_update(data)
        .finalize_into(GenericArray::from_mut_slice(out));
}

// ------------------------------------------------------------ stack scrub

/// Bytes overwritten below the current frame after sensitive work.
const SCRUB_BYTES: usize = 64 * 1024;

/// BEST-EFFORT, NOT A GUARANTEE (see docs/FIX_DESIGN_2026-11.md §4.1).
///
/// The RustCrypto 0.10/0.12 crates (hmac, hkdf, sha2, blake2, chacha20) leave
/// key-derived temporaries in stack frames that have returned. Running the
/// sensitive work in a non-inlined frame and then overwriting the same stack
/// region with volatile zero writes (`zeroize`) removes those copies in
/// practice. It cannot reach registers, values the compiler kept in the
/// caller's own frame, other threads' stacks, or deeper call chains.
/// Effectiveness is measured by lav-memtest in release builds only.
pub(crate) fn scrubbed<R>(f: impl FnOnce() -> R) -> R {
    let r = run_in_own_frame(f);
    scrub_stack();
    r
}

#[inline(never)]
fn run_in_own_frame<R>(f: impl FnOnce() -> R) -> R {
    f()
}

#[inline(never)]
fn scrub_stack() {
    let mut buf = [0u8; SCRUB_BYTES];
    buf.zeroize();
    core::hint::black_box(&buf);
}

// ---------------------------------------------------------- derived keys

#[derive(Zeroize, ZeroizeOnDrop)]
struct KeyPair {
    payload: [u8; KEY_LEN],
    commitment: [u8; KEY_LEN],
}

/// Keys derived from one Argon2id output: the payload (AEAD) key and the
/// key-commitment key.
///
/// Both live in ONE heap allocation that is wiped on drop (`ZeroizeOnDrop`)
/// and never moves: HKDF writes straight into it, and moving a `DerivedKeys`
/// (or a `Vault`) only moves the pointer.
///
/// M4 (PR-1): the payload key must not be reachable from outside the crate
/// without the commitment check, and raw-key encryption/decryption must not
/// be public API:
///
/// ```compile_fail,E0624
/// let keys = lav_core::crypto::DerivedKeys::from_master(&[0u8; 32]).unwrap();
/// let _ = keys.payload_key();
/// ```
///
/// ```compile_fail,E0308
/// let raw = [0u8; 32];
/// let _ = lav_core::crypto::decrypt(&raw, &[0u8; 24], b"", &[0u8; 16]);
/// ```
///
/// ```compile_fail,E0603
/// let _ = lav_core::crypto::encrypt(&[0u8; 32], &[0u8; 24], b"", b"x");
/// ```
pub struct DerivedKeys(Box<KeyPair>);

/// A payload key whose commitment was verified. Only
/// [`DerivedKeys::verified_payload_key`] creates one, and [`decrypt`] only
/// accepts this type, so decryption without the commitment check does not
/// type-check.
pub struct VerifiedKey<'a>(&'a [u8; KEY_LEN]);

impl DerivedKeys {
    fn zeroed() -> Self {
        Self(Box::new(KeyPair {
            payload: [0; KEY_LEN],
            commitment: [0; KEY_LEN],
        }))
    }

    /// HKDF-SHA256 (no salt) from the Argon2id master key, one `info` per
    /// purpose. Public only so the key schedule can be pinned by
    /// known-answer tests.
    pub fn from_master(master: &[u8; KEY_LEN]) -> Result<Self> {
        let mut keys = Self::zeroed();
        scrubbed(|| keys.fill_from_master(master))?;
        Ok(keys)
    }

    /// Caller must run this inside [`scrubbed`].
    fn fill_from_master(&mut self, master: &[u8; KEY_LEN]) -> Result<()> {
        let hk = Hkdf::<Sha256>::new(None, &master[..]);
        hk.expand(HKDF_INFO_PAYLOAD, &mut self.0.payload[..])
            .map_err(|_| Error::KeyDerivation)?;
        hk.expand(HKDF_INFO_COMMITMENT, &mut self.0.commitment[..])
            .map_err(|_| Error::KeyDerivation)?;
        Ok(())
    }

    /// `HMAC-SHA256(commitment_key, "LKAV-commit v2" || header_prefix)`, where
    /// `header_prefix` is every header byte except the commitment itself.
    pub fn commitment(&self, header_prefix: &[u8]) -> [u8; COMMITMENT_LEN] {
        scrubbed(|| {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0.commitment[..])
                .expect("HMAC accepts keys of any length");
            mac.update(COMMITMENT_LABEL);
            mac.update(header_prefix);
            mac.finalize().into_bytes().into()
        })
    }

    /// Returns the payload key ONLY if `stored` equals the commitment of these
    /// keys to `header_prefix` (constant-time comparison, full 32 bytes). This
    /// is the only way to obtain a [`VerifiedKey`], and [`decrypt`] accepts
    /// nothing else, so the check always runs before any decryption. A
    /// mismatch is reported exactly like a wrong password.
    pub fn verified_payload_key(
        &self,
        header_prefix: &[u8],
        stored: &[u8],
    ) -> Result<VerifiedKey<'_>> {
        let expected = self.commitment(header_prefix);
        if ct_eq(&expected, stored) {
            Ok(VerifiedKey(&self.0.payload))
        } else {
            Err(Error::DecryptionFailed)
        }
    }

    /// The payload key for SEALING (crate-internal).
    pub(crate) fn payload_key(&self) -> &[u8; KEY_LEN] {
        &self.0.payload
    }

    /// Constant-time comparison of both keys.
    pub fn ct_eq(&self, other: &DerivedKeys) -> bool {
        // Non-short-circuit `&`: both comparisons always run.
        ct_eq(&self.0.payload[..], &other.0.payload[..])
            & ct_eq(&self.0.commitment[..], &other.0.commitment[..])
    }
}

/// Argon2id(composite, salt) -> master key, then HKDF-SHA256 -> purpose keys.
/// Nothing (in particular not the commitment) can be computed without the
/// full Argon2id run.
pub fn derive_keys(
    composite: &CompositeKey,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<DerivedKeys> {
    params.validate()?;
    let mut keys = DerivedKeys::zeroed();
    scrubbed(|| -> Result<()> {
        let argon_params = Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| Error::InvalidKdfParams)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params.clone());

        let mut master = Zeroizing::new([0u8; KEY_LEN]);
        // Own, self-wiping working memory: the final Argon2 block alone is
        // enough to recompute the master key, so it must not be freed unwiped.
        let mut blocks = Zeroizing::new(vec![Block::default(); argon_params.block_count()]);
        argon
            .hash_password_into_with_memory(&composite.0, salt, &mut master[..], &mut blocks[..])
            .map_err(|_| Error::KeyDerivation)?;
        keys.fill_from_master(&master)
    })?;
    Ok(keys)
}

/// Raw-key AEAD encryption. Crate-internal: the vault seals with its own
/// keys; tests use `testing::encrypt` (feature `test-utils`).
pub(crate) fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    scrubbed(|| {
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
    })
}

/// Decryption with a commitment-verified key only.
pub fn decrypt(
    key: &VerifiedKey<'_>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_raw(key.0, nonce, aad, ciphertext)
}

/// Raw-key AEAD decryption. Crate-internal (and `testing` for tests).
pub(crate) fn decrypt_raw(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    scrubbed(|| {
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
    })
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
        let key = |pw, kf| {
            derive_keys(&CompositeKey::new(pw, kf), &salt, &fast())
                .unwrap()
                .0
                .payload
        };
        let a = key("pw", None);
        assert_eq!(a, key("pw", None));
        assert_ne!(a, key("pw2", None));
        assert_ne!(a, key("pw", Some(b"kf")));
    }

    #[test]
    fn password_is_unicode_normalized() {
        // Precomposed U+015F vs. "s" + combining cedilla U+0327.
        let salt = [9u8; SALT_LEN];
        let a = derive_keys(&CompositeKey::new("pa\u{015F}", None), &salt, &fast()).unwrap();
        let b = derive_keys(&CompositeKey::new("pas\u{0327}", None), &salt, &fast()).unwrap();
        assert!(a.ct_eq(&b));
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
        assert_eq!(
            &**decrypt_raw(&key, &nonce, b"header", &ct).unwrap(),
            b"secret"
        );
        assert!(decrypt_raw(&key, &nonce, b"HEADER", &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(decrypt_raw(&key, &nonce, b"header", &bad).is_err());
    }

    #[test]
    fn commitment_and_payload_keys_are_domain_separated() {
        let keys = DerivedKeys::from_master(&[0x42; KEY_LEN]).unwrap();
        assert_ne!(keys.0.payload, keys.0.commitment);
        let other = DerivedKeys::from_master(&[0x43; KEY_LEN]).unwrap();
        assert_ne!(keys.commitment(b"h"), other.commitment(b"h"));
        assert_ne!(keys.commitment(b"h"), keys.commitment(b"H"));
        assert!(!keys.ct_eq(&other));
    }
}
