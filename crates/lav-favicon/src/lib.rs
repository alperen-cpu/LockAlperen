//! Hardened favicon fetcher.
//!
//! Security / privacy design:
//! * **No third-party icon service** (Google, DuckDuckGo…): the icon is fetched
//!   directly from the entry's own site, so no outside party learns the list
//!   of sites you have accounts on.
//! * **HTTPS only**, `http://` is upgraded; no cookies, no referrer, no
//!   compression (no decompression bombs), strict size limits and timeouts.
//! * **No requests to this machine**: loopback / link-local / unspecified /
//!   multicast addresses are refused (incl. cloud metadata 169.254.169.254).
//!   The resolved address is pinned for the request, which blocks DNS
//!   rebinding. Every redirect hop is re-checked.
//! * **Untrusted images never reach the UI**: they are decoded with a
//!   memory-safe decoder under dimension/allocation limits and re-encoded as a
//!   fresh PNG of fixed size. SVG is never accepted.

#![forbid(unsafe_code)]

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use image::imageops::FilterType;
use image::{DynamicImage, ImageFormat, ImageReader, Limits, RgbaImage};
use reqwest::header::{ACCEPT_ENCODING, LOCATION};
use reqwest::redirect;
use scraper::{Html, Selector};
use thiserror::Error;
use url::{Host, Url};

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LockAlperen-favicon/0.1";
/// Largest source image dimension we are willing to decode.
const MAX_SOURCE_DIM: u32 = 1024;
const MAX_DECODE_ALLOC: u64 = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FaviconError {
    #[error("invalid or unsupported site URL")]
    InvalidUrl,
    #[error("refusing to connect to a local/loopback address")]
    ForbiddenAddress,
    #[error("network error: {0}")]
    Network(String),
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("response exceeds {0} bytes")]
    TooLarge(usize),
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("no usable icon found")]
    NotFound,
    #[error("image rejected: {0}")]
    Image(String),
}

pub type Result<T> = std::result::Result<T, FaviconError>;

#[derive(Clone, Debug)]
pub struct Options {
    pub timeout: Duration,
    pub max_html_bytes: usize,
    pub max_image_bytes: usize,
    /// Output icon is `icon_size` x `icon_size` pixels.
    pub icon_size: u32,
    pub max_redirects: usize,
    pub max_candidates: usize,
    /// Allow private / intranet ranges (10/8, 172.16/12, 192.168/16,
    /// 100.64/10, fc00::/7). Off by default so a crafted entry URL (e.g. from
    /// an imported file) cannot make the app probe the LAN (LA-08).
    pub allow_private_networks: bool,
    /// Hard deadline for one whole `fetch` (all candidates and redirects).
    pub total_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(6),
            max_html_bytes: 512 * 1024,
            max_image_bytes: 512 * 1024,
            icon_size: 64,
            max_redirects: 3,
            max_candidates: 4,
            allow_private_networks: false,
            total_timeout: Duration::from_secs(20),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Favicon {
    /// Sanitized, re-encoded PNG.
    pub png: Vec<u8>,
    /// Where the icon was found (for display/debugging only).
    pub source: Url,
}

/// Fetches and sanitizes the icon for the site an entry URL points to.
pub async fn fetch(site: &str, opts: &Options) -> Result<Favicon> {
    tokio::time::timeout(opts.total_timeout, fetch_inner(site, opts))
        .await
        .map_err(|_| FaviconError::Network("overall timeout".into()))?
}

async fn fetch_inner(site: &str, opts: &Options) -> Result<Favicon> {
    let origin = site_origin(site)?;
    let mut candidates: Vec<Url> = Vec::new();

    match fetch_limited(&origin, opts.max_html_bytes, opts).await {
        Ok((final_url, body)) => {
            let html = String::from_utf8_lossy(&body);
            candidates.extend(find_icon_links(&html, &final_url));
            if let Ok(u) = final_url.join("/favicon.ico") {
                candidates.push(u);
            }
        }
        Err(FaviconError::ForbiddenAddress) => return Err(FaviconError::ForbiddenAddress),
        Err(_) => {} // still try /favicon.ico
    }
    if let Ok(u) = origin.join("/favicon.ico") {
        candidates.push(u);
    }
    dedup(&mut candidates);

    let mut last_err = FaviconError::NotFound;
    for candidate in candidates.into_iter().take(opts.max_candidates) {
        let attempt = fetch_limited(&candidate, opts.max_image_bytes, opts)
            .await
            .and_then(|(url, bytes)| sanitize_image(&bytes, opts.icon_size).map(|png| (url, png)));
        match attempt {
            Ok((source, png)) => return Ok(Favicon { png, source }),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Normalizes user input ("github.com/login", "http://x.com") to an HTTPS origin.
pub fn site_origin(input: &str) -> Result<Url> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(FaviconError::InvalidUrl);
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let mut url = Url::parse(&with_scheme).map_err(|_| FaviconError::InvalidUrl)?;
    match url.scheme() {
        "https" => {}
        "http" => {
            url.set_scheme("https")
                .map_err(|_| FaviconError::InvalidUrl)?;
            if url.port() == Some(80) {
                url.set_port(None).map_err(|_| FaviconError::InvalidUrl)?;
            }
        }
        _ => return Err(FaviconError::InvalidUrl),
    }
    if url.host().is_none() {
        return Err(FaviconError::InvalidUrl);
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    check_host_literal(&url)?;
    Ok(url)
}

/// Addresses that must NEVER be contacted: this machine, link-local (incl.
/// cloud metadata 169.254.169.254), unspecified, multicast, broadcast, the
/// reserved 240/4 — including when embedded in IPv6 (IPv4-mapped,
/// IPv4-compatible, NAT64 64:ff9b::/96, 6to4 2002::/16) (LA-17).
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return is_forbidden_v4(v4);
            }
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xffc0) == 0xfe80 // link-local
                || (seg0 & 0xffc0) == 0xfec0 // deprecated site-local
        }
    }
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240 // reserved 240/4
}

/// Private / intranet ranges: allowed only with `allow_private_networks`.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return is_private_v4(v4);
            }
            (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        }
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64) // + CGNAT 100.64/10
}

/// The IPv4 address an IPv6 address really points at, if any.
fn embedded_v4(v6: std::net::Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let tail = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4); // ::ffff:a.b.c.d
    }
    if s[..6] == [0, 0, 0, 0, 0, 0] && !v6.is_loopback() && !v6.is_unspecified() {
        return Some(tail); // deprecated IPv4-compatible ::a.b.c.d
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(tail); // NAT64 well-known prefix
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    None
}

/// Whether the fetcher may connect to `ip` under `opts`.
pub fn ip_allowed(ip: IpAddr, opts: &Options) -> bool {
    !is_forbidden_ip(ip) && (opts.allow_private_networks || !is_private_ip(ip))
}

fn check_host_literal(url: &Url) -> Result<()> {
    match url.host() {
        Some(Host::Ipv4(ip)) if is_forbidden_ip(ip.into()) => Err(FaviconError::ForbiddenAddress),
        Some(Host::Ipv6(ip)) if is_forbidden_ip(ip.into()) => Err(FaviconError::ForbiddenAddress),
        Some(Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            if d == "localhost" || d.ends_with(".localhost") {
                Err(FaviconError::ForbiddenAddress)
            } else {
                Ok(())
            }
        }
        Some(_) => Ok(()),
        None => Err(FaviconError::InvalidUrl),
    }
}

async fn resolve_checked(url: &Url, opts: &Options) -> Result<SocketAddr> {
    let port = url.port_or_known_default().unwrap_or(443);
    let host = match url.host() {
        Some(Host::Ipv4(ip)) => return checked(SocketAddr::new(ip.into(), port), opts),
        Some(Host::Ipv6(ip)) => return checked(SocketAddr::new(ip.into(), port), opts),
        Some(Host::Domain(d)) => d.to_owned(),
        None => return Err(FaviconError::InvalidUrl),
    };
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(opts.timeout, tokio::net::lookup_host((host.as_str(), port)))
            .await
            .map_err(|_| FaviconError::Network("DNS timeout".into()))?
            .map_err(|e| FaviconError::Network(e.to_string()))?
            .collect();
    // Conservative: if ANY record points somewhere forbidden, refuse.
    if addrs.iter().any(|a| !ip_allowed(a.ip(), opts)) {
        return Err(FaviconError::ForbiddenAddress);
    }
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| FaviconError::Network("host has no addresses".into()))
}

fn checked(addr: SocketAddr, opts: &Options) -> Result<SocketAddr> {
    if !ip_allowed(addr.ip(), opts) {
        Err(FaviconError::ForbiddenAddress)
    } else {
        Ok(addr)
    }
}

/// GET with manual, re-validated redirects and a hard body-size limit.
async fn fetch_limited(url: &Url, max: usize, opts: &Options) -> Result<(Url, Vec<u8>)> {
    let mut current = url.clone();
    for _ in 0..=opts.max_redirects {
        if current.scheme() != "https" {
            return Err(FaviconError::InvalidUrl);
        }
        check_host_literal(&current)?;
        let addr = resolve_checked(&current, opts).await?;

        let mut builder = reqwest::Client::builder()
            .redirect(redirect::Policy::none())
            .timeout(opts.timeout)
            .user_agent(USER_AGENT)
            .https_only(true)
            // Never use HTTP(S)_PROXY / ALL_PROXY from the environment: a proxy
            // re-resolves the host and bypasses our IP checks + pinning (LA-16).
            .no_proxy();
        if let Some(Host::Domain(d)) = current.host() {
            builder = builder.resolve(d, addr); // pin: no DNS rebinding
        }
        let client = builder
            .build()
            .map_err(|e| FaviconError::Network(e.to_string()))?;

        let resp = client
            .get(current.clone())
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|e| FaviconError::Network(e.to_string()))?;

        let status = resp.status();
        if status.is_redirection() {
            let location = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or(FaviconError::Status(status.as_u16()))?;
            current = current
                .join(location)
                .map_err(|_| FaviconError::InvalidUrl)?;
            continue;
        }
        if !status.is_success() {
            return Err(FaviconError::Status(status.as_u16()));
        }
        let body = read_limited(resp, max).await?;
        return Ok((current, body));
    }
    Err(FaviconError::TooManyRedirects)
}

async fn read_limited(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    if resp.content_length().is_some_and(|len| len > max as u64) {
        return Err(FaviconError::TooLarge(max));
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| FaviconError::Network(e.to_string()))?
    {
        if buf.len() + chunk.len() > max {
            return Err(FaviconError::TooLarge(max));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Extracts icon candidates from a page, best first. SVG / mask icons and
/// non-HTTPS links are skipped.
pub fn find_icon_links(html: &str, base: &Url) -> Vec<Url> {
    let doc = Html::parse_document(html);
    let selector = Selector::parse("link[rel][href]").expect("static selector");
    let mut found: Vec<(u32, Url)> = Vec::new();

    for el in doc.select(&selector) {
        let attrs = el.value();
        let rel = attrs.attr("rel").unwrap_or("").to_ascii_lowercase();
        let tokens: Vec<&str> = rel.split_whitespace().collect();
        let is_apple = tokens.iter().any(|t| t.starts_with("apple-touch-icon"));
        let is_icon = tokens.contains(&"icon");
        if !(is_apple || is_icon) || tokens.contains(&"mask-icon") {
            continue;
        }
        if attrs
            .attr("type")
            .is_some_and(|t| t.to_ascii_lowercase().contains("svg"))
        {
            continue;
        }
        let Some(href) = attrs.attr("href") else {
            continue;
        };
        let Ok(url) = base.join(href.trim()) else {
            continue;
        };
        if url.scheme() != "https" || url.path().to_ascii_lowercase().ends_with(".svg") {
            continue;
        }
        let declared = attrs.attr("sizes").and_then(parse_sizes);
        let score = declared.unwrap_or(if is_apple { 180 } else { 32 });
        found.push((score.min(256), url));
    }
    // Stable sort: larger (sharper) icons first, document order as tie-break.
    found.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
    let mut urls: Vec<Url> = found.into_iter().map(|(_, u)| u).collect();
    dedup(&mut urls);
    urls
}

fn parse_sizes(sizes: &str) -> Option<u32> {
    sizes
        .split_whitespace()
        .filter_map(|s| {
            s.to_ascii_lowercase()
                .split_once('x')
                .map(|(w, _)| w.to_owned())
        })
        .filter_map(|w| w.parse::<u32>().ok())
        .max()
}

fn dedup(urls: &mut Vec<Url>) {
    let mut seen = std::collections::HashSet::new();
    urls.retain(|u| seen.insert(u.as_str().to_owned()));
}

/// Decodes an untrusted image under strict limits and re-encodes it as a
/// `size` x `size` PNG (aspect ratio kept, transparent padding).
pub fn sanitize_image(bytes: &[u8], size: u32) -> Result<Vec<u8>> {
    let size = size.clamp(1, 256); // LA-18: 0 panicked; huge sizes waste memory
    let format = image::guess_format(bytes)
        .map_err(|_| FaviconError::Image("unrecognized format".into()))?;
    if !matches!(
        format,
        ImageFormat::Png
            | ImageFormat::Ico
            | ImageFormat::Jpeg
            | ImageFormat::Gif
            | ImageFormat::WebP
            | ImageFormat::Bmp
    ) {
        return Err(FaviconError::Image(format!("{format:?} not allowed")));
    }

    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_DIM);
    limits.max_image_height = Some(MAX_SOURCE_DIM);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);

    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(limits);
    let img = reader
        .decode()
        .map_err(|e| FaviconError::Image(e.to_string()))?;
    if img.width() == 0 || img.height() == 0 {
        return Err(FaviconError::Image("empty image".into()));
    }

    let fitted = img.resize(size, size, FilterType::Lanczos3).to_rgba8();
    let mut canvas = RgbaImage::new(size, size);
    let x = (size - fitted.width()) / 2;
    let y = (size - fitted.height()) / 2;
    image::imageops::overlay(&mut canvas, &fitted, x.into(), y.into());

    let mut out = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(canvas)
        .write_to(&mut out, ImageFormat::Png)
        .map_err(|e| FaviconError::Image(e.to_string()))?;
    Ok(out.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = RgbaImage::from_pixel(w, h, image::Rgba([10, 20, 30, 255]));
        let mut out = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(img)
            .write_to(&mut out, ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    #[test]
    fn origin_normalization() {
        let o = |s: &str| site_origin(s).map(|u| u.to_string());
        assert_eq!(o("github.com").unwrap(), "https://github.com/");
        assert_eq!(
            o("http://example.com/login?x=1#a").unwrap(),
            "https://example.com/"
        );
        assert_eq!(
            o("https://user:pw@example.com/x").unwrap(),
            "https://example.com/"
        );
        assert_eq!(
            o("https://192.168.1.10:8443/app").unwrap(),
            "https://192.168.1.10:8443/"
        );
        assert!(o("").is_err());
        assert!(o("ftp://example.com").is_err());
        assert!(o("javascript:alert(1)").is_err());
        assert!(o("file:///C:/Windows").is_err());
    }

    #[test]
    fn refuses_local_targets() {
        for bad in [
            "localhost",
            "https://foo.localhost",
            "https://127.0.0.1",
            "https://[::1]",
            "https://0.0.0.0",
            "https://169.254.169.254", // cloud metadata
            "https://[fe80::1]",
            "https://[::ffff:127.0.0.1]",
        ] {
            assert!(
                matches!(site_origin(bad), Err(FaviconError::ForbiddenAddress)),
                "{bad} should be refused"
            );
        }
        assert!(!is_forbidden_ip("10.0.0.5".parse().unwrap()));
        assert!(!is_forbidden_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn icon_links_are_ranked_and_filtered() {
        let base = Url::parse("https://example.com/account/").unwrap();
        let html = r#"<html><head>
            <link rel="icon" href="/favicon-16.png" sizes="16x16">
            <link rel="icon" type="image/svg+xml" href="/icon.svg">
            <link rel="mask-icon" href="/mask.png">
            <link rel="shortcut icon" href="http://example.com/insecure.ico">
            <link rel="apple-touch-icon" href="touch.png">
            <link rel="icon" href="/favicon-96.png" sizes="96x96">
            <link rel="stylesheet" href="/style.css">
        </head></html>"#;
        let got: Vec<String> = find_icon_links(html, &base)
            .into_iter()
            .map(|u| u.to_string())
            .collect();
        assert_eq!(
            got,
            vec![
                "https://example.com/account/touch.png",
                "https://example.com/favicon-96.png",
                "https://example.com/favicon-16.png",
            ]
        );
    }

    #[test]
    fn equal_sized_icons_keep_document_order() {
        // Guards the (stable) sort: same score -> first in the page wins.
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"<html><head>
            <link rel="icon" href="/a.png" sizes="32x32">
            <link rel="icon" href="/big.png" sizes="64x64">
            <link rel="icon" href="/b.png" sizes="32x32">
            <link rel="icon" href="/c.png">
            <link rel="icon" href="/d.png" sizes="32x32">
        </head></html>"#;
        let got: Vec<String> = find_icon_links(html, &base)
            .into_iter()
            .map(|u| u.path().to_owned())
            .collect();
        assert_eq!(got, ["/big.png", "/a.png", "/b.png", "/c.png", "/d.png"]);
    }

    #[test]
    fn sanitizes_to_fixed_size_png() {
        let out = sanitize_image(&png(100, 50), 64).unwrap();
        let img = image::load_from_memory_with_format(&out, ImageFormat::Png).unwrap();
        assert_eq!((img.width(), img.height()), (64, 64));
    }

    #[test]
    fn rejects_bad_images() {
        assert!(sanitize_image(b"not an image at all", 64).is_err());
        assert!(sanitize_image(br#"<svg xmlns="http://www.w3.org/2000/svg"></svg>"#, 64).is_err());
        assert!(sanitize_image(&png(MAX_SOURCE_DIM + 1, 1), 64).is_err());
        let mut truncated = png(32, 32);
        truncated.truncate(truncated.len() / 2);
        assert!(sanitize_image(&truncated, 64).is_err());
    }

    /// Real network: `cargo test -p lav-favicon -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn fetches_a_real_icon() {
        let icon = fetch("github.com", &Options::default()).await.unwrap();
        assert!(icon.png.starts_with(b"\x89PNG"));
    }
}
