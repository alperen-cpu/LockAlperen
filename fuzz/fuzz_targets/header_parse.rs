#![no_main]
use libfuzzer_sys::fuzz_target;

// Untrusted .lav header bytes: must never panic; accepted headers must re-serialize identically.
fuzz_target!(|data: &[u8]| {
    if let Ok((h, raw, _ct)) = lav_core::format::Header::parse(data) {
        assert_eq!(&h.to_bytes()[..], raw);
        assert!(h.kdf.validate().is_ok());
    }
    let _ = lav_core::Vault::peek_header(data);
});
