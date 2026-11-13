#![no_main]
use libfuzzer_sys::fuzz_target;

// Untrusted HTML from the network.
fuzz_target!(|data: &[u8]| {
    let html = String::from_utf8_lossy(data);
    let base = url::Url::parse("https://example.com/a/b").unwrap();
    for u in lav_favicon::find_icon_links(&html, &base) {
        assert_eq!(u.scheme(), "https");
    }
});
