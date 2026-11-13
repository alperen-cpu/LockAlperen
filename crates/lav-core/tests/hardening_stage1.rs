//! Stage 1 hardening (format-neutral), see docs/CRYPTO_REVIEW_R1_R2.md §4 step 1:
//!
//! 1. Trailing bytes after the CBOR payload are rejected.
//! 2. A key file supplied for a vault whose header does not require one is rejected.
//! 3. Every credential / file-content error maps to ONE generic user-facing message.
//!
//! Written before the fix. Expected failures before the fix: (1) unlock returned
//! Ok, (2) unlock silently mixed the key file into the key and returned
//! DecryptionFailed / the variant did not exist, (3) `user_message` did not exist.

mod common;

use common::{encrypt_raw_payload, kdf, PW};
use lav_core::error::UNLOCK_FAILED_MESSAGE;
use lav_core::{Error, Vault, VaultData};

fn cbor(v: &VaultData) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).unwrap();
    out
}

#[test]
fn valid_payload_without_trailing_bytes_still_opens() {
    let payload = cbor(&VaultData::new("ok"));
    let v = Vault::unlock(&encrypt_raw_payload(PW, &payload), PW, None).unwrap();
    assert_eq!(v.data.name, "ok");
}

#[test]
fn trailing_bytes_after_payload_are_rejected() {
    for tail in [
        &[0u8][..],
        b"\x00\x00\x00\x00",
        b"garbage after the map",
        &[0xa0],
    ] {
        let mut payload = cbor(&VaultData::new("t"));
        payload.extend_from_slice(tail);
        let err = Vault::unlock(&encrypt_raw_payload(PW, &payload), PW, None).unwrap_err();
        assert!(
            matches!(err, Error::Serialization(_)),
            "tail {tail:?}: {err:?}"
        );
    }
}

#[test]
fn second_complete_vault_appended_is_rejected() {
    // The R2 PoC relied on exactly this: a valid vault followed by junk.
    let mut payload = cbor(&VaultData::new("first"));
    payload.extend(cbor(&VaultData::new("second")));
    assert!(Vault::unlock(&encrypt_raw_payload(PW, &payload), PW, None).is_err());
}

#[test]
fn unexpected_keyfile_is_rejected() {
    let bytes = Vault::create("v", PW, None, kdf()).unwrap().seal().unwrap();
    assert!(!Vault::peek_header(&bytes).unwrap().requires_keyfile());
    assert!(matches!(
        Vault::unlock(&bytes, PW, Some(b"some key file")),
        Err(Error::UnexpectedKeyFile)
    ));
    // Empty key file is still "a key file was supplied".
    assert!(matches!(
        Vault::unlock(&bytes, PW, Some(b"")),
        Err(Error::UnexpectedKeyFile)
    ));
    assert!(Vault::unlock(&bytes, PW, None).is_ok());
}

/// Every way an unlock can fail because of the credentials or the file's
/// content must look identical to the user (THREAT_MODEL principle 3).
#[test]
fn unlock_failures_share_one_generic_user_message() {
    let good = Vault::create("v", PW, None, kdf()).unwrap().seal().unwrap();
    let kf_bytes = Vault::create("k", "", Some(b"key file"), kdf())
        .unwrap()
        .seal()
        .unwrap();

    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;

    let mut trailing = cbor(&VaultData::new("t"));
    trailing.push(0);
    let mut future = VaultData::new("t");
    future.schema = 99;

    let mut bad_version = good.clone();
    bad_version[4] = 0x7f;

    let errors: Vec<(&str, Error)> = vec![
        (
            "wrong password",
            Vault::unlock(&good, "wrong password!", None).unwrap_err(),
        ),
        (
            "unexpected key file",
            Vault::unlock(&good, PW, Some(b"kf")).unwrap_err(),
        ),
        (
            "missing key file",
            Vault::unlock(&kf_bytes, "", None).unwrap_err(),
        ),
        (
            "wrong key file",
            Vault::unlock(&kf_bytes, "", Some(b"other")).unwrap_err(),
        ),
        (
            "tampered tag",
            Vault::unlock(&tampered, PW, None).unwrap_err(),
        ),
        (
            "garbage payload",
            Vault::unlock(&encrypt_raw_payload(PW, b"\xff\xff"), PW, None).unwrap_err(),
        ),
        (
            "trailing bytes",
            Vault::unlock(&encrypt_raw_payload(PW, &trailing), PW, None).unwrap_err(),
        ),
        (
            "future schema",
            Vault::unlock(&encrypt_raw_payload(PW, &cbor(&future)), PW, None).unwrap_err(),
        ),
        (
            "truncated",
            Vault::unlock(&good[..20], PW, None).unwrap_err(),
        ),
        (
            "not a vault",
            Vault::unlock(b"PK\x03\x04 zip file", PW, None).unwrap_err(),
        ),
        (
            "unknown version",
            Vault::unlock(&bad_version, PW, None).unwrap_err(),
        ),
    ];
    for (what, err) in &errors {
        assert!(err.is_unlock_failure(), "{what}: {err:?}");
        assert_eq!(err.user_message(), UNLOCK_FAILED_MESSAGE, "{what}: {err:?}");
    }

    // Errors unrelated to the credentials / content keep their own message.
    let io = Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "nope"));
    assert!(!io.is_unlock_failure());
    assert_ne!(io.user_message(), UNLOCK_FAILED_MESSAGE);
    assert_ne!(Error::FileTooLarge(1).user_message(), UNLOCK_FAILED_MESSAGE);
}

#[test]
fn generic_message_reveals_no_offsets_or_details() {
    let msg = UNLOCK_FAILED_MESSAGE;
    assert!(!msg.chars().any(|c| c.is_ascii_digit()), "{msg}");
    assert!(!msg.to_lowercase().contains("schema"));
    assert!(!msg.to_lowercase().contains("cbor"));
}

/// Review finding: save-path errors must not be reported as "could not be
/// opened". Encoding failures use their own variant.
#[test]
fn save_path_encode_error_is_not_an_unlock_failure() {
    assert!(!Error::Encode.is_unlock_failure());
    assert_ne!(Error::Encode.user_message(), UNLOCK_FAILED_MESSAGE);
    // Serialization stays an unlock failure (decode path only).
    assert!(Error::Serialization(String::new()).is_unlock_failure());
}
