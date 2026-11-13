#![no_main]
use libfuzzer_sys::fuzz_target;

// Untrusted favicon bytes from the network.
fuzz_target!(|data: &[u8]| {
    if let Ok(png) = lav_favicon::sanitize_image(data, 64) {
        assert!(png.starts_with(b"\x89PNG"));
    }
});
