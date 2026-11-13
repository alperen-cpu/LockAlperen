//! Format v2: key commitment (R2). See docs/FORMAT.md and
//! docs/CRYPTO_REVIEW_R1_R2.md §2.
//!
//! Written before the implementation. Covers: file format, wrong credentials,
//! corrupted / crafted files, v1 downgrade, known-answer vectors.

mod common;

use common::{encrypt_raw_payload, kdf, PW};
use lav_core::crypto::{self, CompositeKey, DerivedKeys, KdfParams, COMMITMENT_LEN, SALT_LEN};
use lav_core::error::UNLOCK_FAILED_MESSAGE;
use lav_core::format::{Header, COMMITTED_LEN, FORMAT_VERSION, HEADER_LEN, TAG_LEN};
use lav_core::testing;
use lav_core::{Error, Vault, VaultData};

const COMMIT_AT: usize = COMMITTED_LEN;

fn sealed() -> Vec<u8> {
    let mut v = Vault::create("v2", PW, None, kdf()).unwrap();
    v.data
        .add_entry(lav_core::Entry::new(v.data.root, "e"))
        .unwrap();
    v.seal().unwrap()
}

fn assert_generic(err: &Error, what: &str) {
    assert_eq!(err.user_message(), UNLOCK_FAILED_MESSAGE, "{what}: {err:?}");
}

fn cbor(v: &VaultData) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).unwrap();
    out
}

// ---------------------------------------------------------------- layout

#[test]
fn layout_is_v2_with_full_32_byte_commitment_at_the_end_of_the_header() {
    assert_eq!(FORMAT_VERSION, 2);
    assert_eq!(COMMITMENT_LEN, 32);
    assert_eq!(COMMITTED_LEN, 78);
    assert_eq!(HEADER_LEN, COMMITTED_LEN + COMMITMENT_LEN);

    let bytes = sealed();
    assert_eq!(&bytes[..4], b"LKAV");
    assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 2);

    let (h, raw, ct) = Header::parse(&bytes).unwrap();
    assert_eq!(raw.len(), HEADER_LEN);
    assert!(ct.len() >= TAG_LEN);
    assert_eq!(&raw[..COMMITTED_LEN], &h.committed_bytes()[..]);
    assert_eq!(&raw[COMMIT_AT..], &h.commitment[..]);

    // The stored commitment is exactly what the user's key yields for the
    // header's security fields.
    let keys = crypto::derive_keys(&CompositeKey::new(PW, None), &h.salt, &h.kdf).unwrap();
    assert_eq!(keys.commitment(&raw[..COMMITTED_LEN]), h.commitment);
    assert_ne!(h.commitment, [0u8; COMMITMENT_LEN]);
}

#[test]
fn header_roundtrip_preserves_commitment() {
    let h = Header {
        flags: 1,
        kdf: KdfParams::default(),
        salt: [3; SALT_LEN],
        nonce: [4; 24],
        commitment: [5; COMMITMENT_LEN],
    };
    let mut file = h.to_bytes().to_vec();
    file.extend([0u8; TAG_LEN]);
    let (parsed, raw, _) = Header::parse(&file).unwrap();
    assert_eq!(parsed, h);
    assert_eq!(raw, &h.to_bytes()[..]);
}

#[test]
fn each_save_has_a_new_nonce_and_therefore_a_new_commitment() {
    let v = Vault::create("v", PW, None, kdf()).unwrap();
    let (a, b) = (v.seal().unwrap(), v.seal().unwrap());
    assert_ne!(a[COMMIT_AT..HEADER_LEN], b[COMMIT_AT..HEADER_LEN]);
    // Same credentials -> same salt; both open.
    assert_eq!(a[22..54], b[22..54]);
    assert!(Vault::unlock(&a, PW, None).is_ok());
    assert!(Vault::unlock(&b, PW, None).is_ok());
}

// ------------------------------------------------------- wrong credentials

#[test]
fn wrong_password_fails_with_generic_error() {
    let bytes = sealed();
    for pw in [
        "",
        "wrong",
        "correct horse batterY",
        "correct horse battery ",
    ] {
        let err = Vault::unlock(&bytes, pw, None).unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed), "{pw:?}: {err:?}");
        assert_generic(&err, pw);
    }
    assert!(Vault::unlock(&bytes, PW, None).is_ok());
}

#[test]
fn wrong_missing_or_unexpected_keyfile_fails_with_generic_error() {
    let bytes = Vault::create("k", PW, Some(b"key file"), kdf())
        .unwrap()
        .seal()
        .unwrap();
    for (what, kf) in [("missing", None), ("wrong", Some(&b"other"[..]))] {
        let err = Vault::unlock(&bytes, PW, kf).unwrap_err();
        assert_generic(&err, what);
    }
    assert!(Vault::unlock(&bytes, PW, Some(b"key file")).is_ok());

    let plain = sealed();
    let err = Vault::unlock(&plain, PW, Some(b"key file")).unwrap_err();
    assert!(matches!(err, Error::UnexpectedKeyFile));
    assert_generic(&err, "unexpected");
}

// ---------------------------------------------------- corrupted / crafted

#[test]
fn every_single_bit_of_the_commitment_is_checked() {
    let bytes = sealed();
    for i in COMMIT_AT..HEADER_LEN {
        for bit in [0x01u8, 0x80] {
            let mut b = bytes.clone();
            b[i] ^= bit;
            let err = Vault::unlock(&b, PW, None).unwrap_err();
            assert!(
                matches!(err, Error::DecryptionFailed),
                "byte {i} bit {bit:#x}: {err:?}"
            );
        }
    }
}

#[test]
fn zeroed_or_truncated_commitment_is_rejected() {
    let bytes = sealed();
    let mut zero = bytes.clone();
    zero[COMMIT_AT..HEADER_LEN].fill(0);
    assert!(matches!(
        Vault::unlock(&zero, PW, None),
        Err(Error::DecryptionFailed)
    ));
    // Cut 16 bytes out of the commitment: lengths shift, must fail.
    let mut short = bytes[..COMMIT_AT + 16].to_vec();
    short.extend_from_slice(&bytes[HEADER_LEN..]);
    assert!(Vault::unlock(&short, PW, None).is_err());
}

#[test]
fn every_security_header_field_is_bound() {
    let bytes = sealed();
    // (offset, description). Values stay inside the accepted ranges so the
    // header still parses and only the commitment / AEAD can catch it.
    let edits: [(usize, &str, u8); 6] = [
        (10, "memory_kib", 0x01),
        (14, "iterations", 0x01),
        (18, "parallelism", 0x01),
        (22, "salt first byte", 0xff),
        (53, "salt last byte", 0x01),
        (54, "nonce", 0x01),
    ];
    for (off, what, x) in edits {
        let mut b = bytes.clone();
        b[off] ^= x;
        if Header::parse(&b).is_err() {
            continue; // out-of-range params are refused even earlier
        }
        let err = Vault::unlock(&b, PW, None).unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed), "{what}: {err:?}");
    }
    // Setting the key-file flag and supplying a key file.
    let mut b = bytes.clone();
    b[8] |= 0x01;
    assert!(matches!(
        Vault::unlock(&b, PW, Some(b"kf")),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn commitment_cannot_be_transplanted_between_files() {
    let a = sealed();
    let b = sealed(); // same password, different salt and nonce
    let mut x = b.clone();
    x[COMMIT_AT..HEADER_LEN].copy_from_slice(&a[COMMIT_AT..HEADER_LEN]);
    assert!(matches!(
        Vault::unlock(&x, PW, None),
        Err(Error::DecryptionFailed)
    ));

    // Same vault, two saves (same salt, different nonce).
    let v = Vault::create("v", PW, None, kdf()).unwrap();
    let (s1, s2) = (v.seal().unwrap(), v.seal().unwrap());
    let mut y = s2.clone();
    y[COMMIT_AT..HEADER_LEN].copy_from_slice(&s1[COMMIT_AT..HEADER_LEN]);
    assert!(matches!(
        Vault::unlock(&y, PW, None),
        Err(Error::DecryptionFailed)
    ));
}

/// R2 regression. A ciphertext that is AEAD-valid under key B but whose header
/// commits to key A must NOT open with B, and must give the same error as a
/// wrong password (the "different error" oracle signal is gone). This is the
/// property a multi-key Poly1305 collision would exploit.
#[test]
fn aead_valid_but_uncommitted_key_is_rejected_before_decryption() {
    let salt = crypto::random_bytes::<SALT_LEN>();
    let nonce = crypto::random_bytes::<24>();
    let ka =
        crypto::derive_keys(&CompositeKey::new("password-of-alice", None), &salt, &kdf()).unwrap();
    let kb =
        crypto::derive_keys(&CompositeKey::new("password-of-bob!", None), &salt, &kdf()).unwrap();

    let mut h = Header {
        flags: 0,
        kdf: kdf(),
        salt,
        nonce,
        commitment: [0; COMMITMENT_LEN],
    };
    h.commitment = ka.commitment(&h.committed_bytes()); // commits to Alice
    let hb = h.to_bytes();
    // ...but the payload is encrypted for Bob, with garbage that would give a
    // distinguishable Serialization error if it were ever decrypted.
    let ct = testing::encrypt(
        &testing::payload_key(&kb),
        &nonce,
        &hb,
        b"\xff\xfe not cbor",
    )
    .unwrap();
    let mut file = hb.to_vec();
    file.extend(&ct);

    // Control: the file IS AEAD-valid under Bob's key.
    assert!(testing::decrypt(&testing::payload_key(&kb), &nonce, &hb, &ct).is_ok());

    for pw in ["password-of-bob!", "password-of-alice", "some-other-guess"] {
        let err = Vault::unlock(&file, pw, None).unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed), "{pw}: {err:?}");
        assert_generic(&err, pw);
    }
}

#[test]
fn commitment_is_verified_through_the_only_payload_key_accessor_for_unlock() {
    let salt = [1u8; SALT_LEN];
    let keys = crypto::derive_keys(&CompositeKey::new(PW, None), &salt, &kdf()).unwrap();
    let prefix = [9u8; COMMITTED_LEN];
    let good = keys.commitment(&prefix);
    assert!(keys.verified_payload_key(&prefix, &good).is_ok());
    let mut bad = good;
    bad[31] ^= 1;
    assert!(matches!(
        keys.verified_payload_key(&prefix, &bad),
        Err(Error::DecryptionFailed)
    ));
    assert!(keys.verified_payload_key(&prefix, &good[..31]).is_err());
    assert!(keys
        .verified_payload_key(&[8u8; COMMITTED_LEN], &good)
        .is_err());
}

#[test]
fn ciphertext_tampering_truncation_and_appending_fail() {
    let bytes = sealed();
    let mut ct = bytes.clone();
    ct[HEADER_LEN + 3] ^= 0x10;
    assert!(matches!(
        Vault::unlock(&ct, PW, None),
        Err(Error::DecryptionFailed)
    ));
    let mut appended = bytes.clone();
    appended.extend_from_slice(b"junk");
    assert!(matches!(
        Vault::unlock(&appended, PW, None),
        Err(Error::DecryptionFailed)
    ));
    // Every truncation: an error, never a panic, always the generic message.
    for len in 0..bytes.len() {
        let err = Vault::unlock(&bytes[..len], PW, None).unwrap_err();
        assert_generic(&err, &format!("len {len}"));
    }
}

#[test]
fn content_errors_after_a_valid_commitment_are_still_generic_to_the_user() {
    let mut trailing = cbor(&VaultData::new("t"));
    trailing.push(0);
    for (what, payload) in [("garbage", b"\x00\x01".to_vec()), ("trailing", trailing)] {
        let err = Vault::unlock(&encrypt_raw_payload(PW, &payload), PW, None).unwrap_err();
        assert!(matches!(err, Error::Serialization(_)), "{what}: {err:?}");
        assert_generic(&err, what);
    }
}

// ------------------------------------------------------------ v1 downgrade

/// A genuine format-v1 file (78-byte header, no commitment) as the previous
/// release wrote it.
fn genuine_v1_file(password: &str) -> Vec<u8> {
    let salt = crypto::random_bytes::<SALT_LEN>();
    let nonce = crypto::random_bytes::<24>();
    let k = kdf();
    let mut hb = Vec::with_capacity(78);
    hb.extend_from_slice(b"LKAV");
    hb.extend_from_slice(&1u16.to_le_bytes());
    hb.extend_from_slice(&[1, 1]);
    hb.extend_from_slice(&0u16.to_le_bytes());
    hb.extend_from_slice(&k.memory_kib.to_le_bytes());
    hb.extend_from_slice(&k.iterations.to_le_bytes());
    hb.extend_from_slice(&k.parallelism.to_le_bytes());
    hb.extend_from_slice(&salt);
    hb.extend_from_slice(&nonce);
    assert_eq!(hb.len(), 78);
    // v1 key = HKDF(master, "LKAV v1 payload encryption key") = today's payload key.
    let keys = crypto::derive_keys(&CompositeKey::new(password, None), &salt, &k).unwrap();
    let mut out = hb.clone();
    out.extend(
        testing::encrypt(
            &testing::payload_key(&keys),
            &nonce,
            &hb,
            &cbor(&VaultData::new("v1")),
        )
        .unwrap(),
    );
    out
}

#[test]
fn v1_files_are_rejected_with_no_fallback() {
    let v1 = genuine_v1_file(PW);
    let err = Vault::unlock(&v1, PW, None).unwrap_err();
    assert!(matches!(err, Error::UnsupportedVersion(1)), "{err:?}");
    assert_generic(&err, "v1");
    assert!(matches!(
        Vault::peek_header(&v1),
        Err(Error::UnsupportedVersion(1))
    ));
    // Even a tiny v1-looking file is reported as v1, not as something else.
    assert!(matches!(
        Vault::unlock(b"LKAV\x01\x00", PW, None),
        Err(Error::UnsupportedVersion(1))
    ));
}

#[test]
fn v1_file_relabelled_as_v2_does_not_open() {
    let v1 = genuine_v1_file(PW);
    // Attacker bumps the version and inserts a guessed commitment.
    for fill in [0u8, 0xff] {
        let mut f = v1[..78].to_vec();
        f[4] = 2;
        f.extend([fill; COMMITMENT_LEN]);
        f.extend_from_slice(&v1[78..]);
        let err = Vault::unlock(&f, PW, None).unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed), "{err:?}");
    }
    // Only bumping the version (no room for a commitment).
    let mut f = v1.clone();
    f[4] = 2;
    assert!(Vault::unlock(&f, PW, None).is_err());
}

// ------------------------------------------------------------- KAT vectors

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Expected values computed independently with Python's hashlib/hmac.
#[test]
fn kat_hkdf_and_commitment_from_fixed_master() {
    let master: [u8; 32] = core::array::from_fn(|i| i as u8);
    let keys = DerivedKeys::from_master(&master).unwrap();
    assert_eq!(
        hex(&testing::payload_key(&keys)),
        "e69275e9a09417ce5a3c2e315a1f6948bdac75f51e3a991d232608ea30434667"
    );
    let prefix: [u8; COMMITTED_LEN] = core::array::from_fn(|i| i as u8);
    assert_eq!(
        hex(&keys.commitment(&prefix)),
        "e4ac5f3f5293761e18cd65615c44c390d05a55b3fdf84eaaa06afebbcb1d4b19"
    );
}

/// End to end, Argon2id included. Expected values computed independently with
/// argon2-cffi (reference C implementation) + Python hashlib/hmac.
#[test]
fn kat_argon2id_to_payload_key_and_commitment() {
    let keys =
        crypto::derive_keys(&CompositeKey::new("kat password", None), &[7u8; 32], &kdf()).unwrap();
    assert_eq!(
        hex(&testing::payload_key(&keys)),
        "9d610fdfea6019d9697a3676cddf5ed03b99c662171c1723383a6b920941e3e3"
    );
    let prefix: [u8; COMMITTED_LEN] = core::array::from_fn(|i| i as u8);
    assert_eq!(
        hex(&keys.commitment(&prefix)),
        "86b5a8efab0c3556c1d18be70271ac1f5ca464151042f92f2c157b01975eb721"
    );
}

#[test]
fn commitment_depends_on_every_kdf_input() {
    let prefix = [0u8; COMMITTED_LEN];
    let base = |pw: &str, kf: Option<&[u8]>, salt: [u8; 32], k: KdfParams| {
        crypto::derive_keys(&CompositeKey::new(pw, kf), &salt, &k)
            .unwrap()
            .commitment(&prefix)
    };
    let c0 = base(PW, None, [1; 32], kdf());
    assert_ne!(c0, base("other password", None, [1; 32], kdf()));
    assert_ne!(c0, base(PW, Some(b"kf"), [1; 32], kdf()));
    assert_ne!(c0, base(PW, None, [2; 32], kdf()));
    let mut k = kdf();
    k.iterations += 1;
    assert_ne!(c0, base(PW, None, [1; 32], k));
}
