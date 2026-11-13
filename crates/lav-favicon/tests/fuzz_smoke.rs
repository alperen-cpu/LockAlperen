//! Mutation-based random fuzzing (no coverage guidance; see /fuzz for the
//! cargo-fuzz targets). LAV_FUZZ_ITERS / LAV_FUZZ_SEED control the run.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, RgbaImage};
use lav_favicon::{find_icon_links, is_forbidden_ip, sanitize_image, site_origin};
use url::{Host, Url};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn iters() -> usize {
    std::env::var("LAV_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

fn rng() -> Rng {
    let seed = std::env::var("LAV_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0xFA71_C0DE_u64);
    eprintln!("fuzz seed = {seed}");
    Rng(seed | 1)
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut d = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(5) {
            0 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] ^= 1 << rng.below(8);
            }
            1 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] = [0x00, 0xFF, 0x7F, 0x80][rng.below(4)];
            }
            2 => d.truncate(rng.below(d.len() + 1)),
            3 => {
                for _ in 0..rng.below(32) {
                    d.push(rng.next() as u8);
                }
            }
            _ if !d.is_empty() => {
                let i = rng.below(d.len());
                d.remove(i);
            }
            _ => {}
        }
    }
    d
}

fn encode(fmt: ImageFormat, w: u32, h: u32) -> Vec<u8> {
    let img = DynamicImage::ImageRgba8(RgbaImage::from_fn(w, h, |x, y| {
        image::Rgba([x as u8, y as u8, (x ^ y) as u8, 255])
    }));
    let img = if fmt == ImageFormat::Jpeg {
        DynamicImage::ImageRgb8(img.to_rgb8())
    } else {
        img
    };
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, fmt).unwrap();
    out.into_inner()
}

#[test]
fn fuzz_image_sanitize() {
    let seeds = [
        encode(ImageFormat::Png, 16, 16),
        encode(ImageFormat::Ico, 32, 32),
        encode(ImageFormat::Gif, 8, 8),
        encode(ImageFormat::Bmp, 8, 8),
        encode(ImageFormat::Jpeg, 16, 16),
    ];
    let mut rng = rng();
    let mut accepted = 0;
    for _ in 0..iters() {
        let pick = rng.below(seeds.len());
        let input = mutate(&mut rng, &seeds[pick]);
        if let Ok(png) = sanitize_image(&input, 64) {
            accepted += 1;
            assert!(png.starts_with(b"\x89PNG"));
            let back = image::load_from_memory_with_format(&png, ImageFormat::Png).unwrap();
            assert_eq!((back.width(), back.height()), (64, 64));
        }
    }
    eprintln!("accepted {accepted} mutated images");
}

const URL_TOKENS: &[&str] = &[
    "https://",
    "http://",
    "ftp://",
    "file://",
    "javascript:",
    "data:",
    "//",
    "@",
    ":",
    "/",
    "?",
    "#",
    "%00",
    "%2e",
    "..",
    "localhost",
    "LOCALHOST.",
    "127.0.0.1",
    "0x7f.1",
    "2130706433",
    "[::1]",
    "[::ffff:127.0.0.1]",
    "[fe80::1%25eth0]",
    "169.254.169.254",
    "0.0.0.0",
    "10.0.0.1",
    "example.com",
    "xn--",
    "ş",
    "İ",
    " ",
    "\t",
    "\\",
    ":443",
    ":0",
    ":99999",
    "user:pw@",
];

#[test]
fn fuzz_site_origin_never_yields_forbidden_target() {
    let mut rng = rng();
    for _ in 0..iters() * 2 {
        let mut s = String::new();
        for _ in 0..1 + rng.below(6) {
            s.push_str(URL_TOKENS[rng.below(URL_TOKENS.len())]);
        }
        if let Ok(u) = site_origin(&s) {
            assert_eq!(u.scheme(), "https", "{s}");
            assert_eq!(u.path(), "/");
            assert!(u.username().is_empty() && u.password().is_none());
            match u.host() {
                Some(Host::Ipv4(ip)) => assert!(!is_forbidden_ip(ip.into()), "{s} -> {u}"),
                Some(Host::Ipv6(ip)) => assert!(!is_forbidden_ip(ip.into()), "{s} -> {u}"),
                Some(Host::Domain(d)) => {
                    let d = d.trim_end_matches('.').to_ascii_lowercase();
                    assert!(d != "localhost" && !d.ends_with(".localhost"), "{s} -> {u}");
                }
                None => panic!("no host: {s}"),
            }
        }
    }
}

const HTML_TOKENS: &[&str] = &[
    "<link ",
    "rel=\"icon\" ",
    "rel='apple-touch-icon' ",
    "rel=mask-icon ",
    "rel=\"shortcut icon\" ",
    "href=\"",
    "href=",
    "/a.png",
    "http://x/a.png",
    "https://cdn.example/a.ico",
    "javascript:alert(1)",
    "data:image/png;base64,AAAA",
    "//evil.example/x.png",
    "a.svg",
    "\" ",
    "sizes=\"",
    "999999x1\" ",
    "any",
    "type=\"image/svg+xml\" ",
    ">",
    "<",
    "<!--",
    "-->",
    "<script>",
    "</head>",
    "\u{0}",
];

#[test]
fn fuzz_icon_links_only_https() {
    let base = Url::parse("https://example.com/a/b").unwrap();
    let mut rng = rng();
    for _ in 0..iters() {
        let mut s = String::new();
        for _ in 0..rng.below(40) {
            s.push_str(HTML_TOKENS[rng.below(HTML_TOKENS.len())]);
        }
        for u in find_icon_links(&s, &base) {
            assert_eq!(u.scheme(), "https", "{s}");
            assert!(!u.path().to_ascii_lowercase().ends_with(".svg"));
        }
    }
}
