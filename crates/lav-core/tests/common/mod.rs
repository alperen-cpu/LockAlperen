//! Shared helpers for the hardening / format tests.
#![allow(dead_code)]

use lav_core::crypto::{self, CompositeKey, KdfParams, COMMITMENT_LEN};
use lav_core::format::Header;

pub const PW: &str = "correct horse battery";

pub fn kdf() -> KdfParams {
    KdfParams {
        memory_kib: KdfParams::MIN_MEMORY_KIB,
        iterations: KdfParams::MIN_ITERATIONS,
        parallelism: 1,
    }
}

/// Builds a correctly encrypted file around an arbitrary payload, as only the
/// key holder (or a buggy writer) could.
pub fn encrypt_raw_payload(password: &str, payload: &[u8]) -> Vec<u8> {
    let mut header = Header {
        flags: 0,
        kdf: kdf(),
        salt: crypto::random_bytes(),
        nonce: crypto::random_bytes(),
        commitment: [0; COMMITMENT_LEN],
    };
    let keys = crypto::derive_keys(
        &CompositeKey::new(password, None),
        &header.salt,
        &header.kdf,
    )
    .unwrap();
    header.commitment = keys.commitment(&header.committed_bytes());
    let hb = header.to_bytes();
    let mut out = hb.to_vec();
    out.extend(
        lav_core::testing::encrypt(
            &lav_core::testing::payload_key(&keys),
            &header.nonce,
            &hb,
            payload,
        )
        .unwrap(),
    );
    out
}
