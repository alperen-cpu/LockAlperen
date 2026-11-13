//! Regression tests for favicon findings of the 2026-11 audit. Each failed
//! before its fix.

use std::net::{IpAddr, TcpListener};
use std::time::Duration;

use lav_favicon::{fetch, ip_allowed, is_forbidden_ip, sanitize_image, site_origin, Options};

/// LA-16: reqwest honoured HTTPS_PROXY from the environment, sending the
/// hostname to the proxy, which re-resolved it: IP checks and DNS pinning were
/// bypassed. The fetcher must never use an environment proxy.
#[test]
fn la16_environment_proxy_is_ignored() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    // Only this test binary's process is affected.
    unsafe {
        std::env::set_var("HTTPS_PROXY", &proxy);
        std::env::set_var("ALL_PROXY", &proxy);
    }
    let opts = Options {
        timeout: Duration::from_secs(2),
        ..Options::default()
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // A public IP literal: no DNS needed; direct connect may fail offline, fine.
    let _ = rt.block_on(fetch("https://1.1.1.1", &opts));
    assert!(
        listener.accept().is_err(),
        "fetcher connected to the environment proxy"
    );
}

/// LA-17: IPv6 encodings of loopback / local addresses were not recognised.
#[test]
fn la17_ipv6_embeddings_of_local_addresses_are_forbidden() {
    for s in [
        "::127.0.0.1",       // IPv4-compatible
        "64:ff9b::7f00:1",   // NAT64 -> 127.0.0.1
        "2002:7f00:1::1",    // 6to4 -> 127.0.0.1
        "2002:a9fe:a9fe::1", // 6to4 -> 169.254.169.254
        "fec0::1",           // deprecated site-local
    ] {
        let ip: IpAddr = s.parse().unwrap();
        assert!(is_forbidden_ip(ip), "{s} should be forbidden");
    }
    assert!(matches!(
        site_origin("https://[::127.0.0.1]/"),
        Err(lav_favicon::FaviconError::ForbiddenAddress)
    ));
}

/// LA-08: private / intranet ranges are opt-in (an imported, attacker-crafted
/// entry URL must not make the app probe the LAN by default).
#[test]
fn la08_private_networks_are_opt_in() {
    let default = Options::default();
    let intranet = Options {
        allow_private_networks: true,
        ..Options::default()
    };
    for s in [
        "10.0.0.5",
        "172.16.1.1",
        "192.168.1.10",
        "100.64.0.1",
        "fd00::1",
    ] {
        let ip: IpAddr = s.parse().unwrap();
        assert!(!ip_allowed(ip, &default), "{s} allowed by default");
        assert!(ip_allowed(ip, &intranet), "{s} refused with opt-in");
    }
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    assert!(ip_allowed(public, &default));
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(!ip_allowed(lo, &intranet), "loopback is never allowed");
}

/// LA-18: `icon_size = 0` panicked (subtract with overflow); public input.
#[test]
fn la18_degenerate_icon_size_does_not_panic() {
    let img = image::RgbaImage::from_pixel(4, 4, image::Rgba([1, 2, 3, 255]));
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
    for size in [0, 1, 100_000] {
        let _ = sanitize_image(png.get_ref(), size);
    }
}
