#![no_main]
use libfuzzer_sys::fuzz_target;

// Untrusted URL strings (e.g. from an imported KeePass file).
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(u) = lav_favicon::site_origin(s) {
            assert_eq!(u.scheme(), "https");
            assert_eq!(u.path(), "/");
            assert!(u.username().is_empty() && u.password().is_none());
            if let Some(url::Host::Ipv4(ip)) = u.host() {
                assert!(!lav_favicon::is_forbidden_ip(ip.into()));
            }
            if let Some(url::Host::Ipv6(ip)) = u.host() {
                assert!(!lav_favicon::is_forbidden_ip(ip.into()));
            }
        }
    }
});
