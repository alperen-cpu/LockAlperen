//! Informational measurement (not a pass/fail security test): what does the
//! key-commitment check cost compared to Argon2id and to the AEAD check that
//! already existed? Run with:
//!
//! `cargo test --release -p lav-core --test commitment_cost -- --ignored --nocapture`

use std::time::Instant;

use lav_core::crypto::{self, CompositeKey, DerivedKeys, KdfParams};
use lav_core::format::COMMITTED_LEN;

fn time<F: FnMut()>(n: u32, mut f: F) -> f64 {
    f(); // warm-up
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    t.elapsed().as_secs_f64() / f64::from(n)
}

#[test]
#[ignore]
fn measure_commitment_vs_argon2_vs_aead() {
    let salt = [7u8; 32];
    let comp = CompositeKey::new("measure me", None);
    let argon = time(5, || {
        crypto::derive_keys(&comp, &salt, &KdfParams::default()).unwrap();
    });
    let keys = DerivedKeys::from_master(&[1; 32]).unwrap();
    let prefix = [0u8; COMMITTED_LEN];
    let c = keys.commitment(&prefix);
    let commit = time(100_000, || {
        let _ = keys.verified_payload_key(&prefix, &c).unwrap();
    });
    let nonce = [0u8; 24];
    let pt = vec![0u8; 1 << 20];
    let ct =
        lav_core::testing::encrypt(&lav_core::testing::payload_key(&keys), &nonce, b"aad", &pt)
            .unwrap();
    let aead = time(50, || {
        lav_core::testing::decrypt(&lav_core::testing::payload_key(&keys), &nonce, b"aad", &ct)
            .unwrap();
    });
    // Smallest possible AEAD check an attacker can use today: a 16-byte tag on
    // a 1-byte ciphertext (no known-plaintext tricks needed).
    let tiny =
        lav_core::testing::encrypt(&lav_core::testing::payload_key(&keys), &nonce, b"", b"x")
            .unwrap();
    let aead_min = time(100_000, || {
        lav_core::testing::decrypt(&lav_core::testing::payload_key(&keys), &nonce, b"", &tiny)
            .unwrap();
    });
    println!(
        "Argon2id default (64 MiB, t=3, p=4): {:>12.3} ms",
        argon * 1e3
    );
    println!(
        "commitment HMAC verify:              {:>12.3} us",
        commit * 1e6
    );
    println!(
        "AEAD verify+decrypt 1 MiB:           {:>12.3} us",
        aead * 1e6
    );
    println!(
        "AEAD verify 1-byte message:          {:>12.3} us",
        aead_min * 1e6
    );
    println!(
        "commitment / Argon2 share of one guess: {:.6} %",
        commit / (argon + commit) * 100.0
    );
}
