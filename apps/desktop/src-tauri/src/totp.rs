//! TOTP (RFC 6238) codes. The secret never leaves Rust: the WebView gets only
//! the current code and the seconds left.
//!
//! The HMAC comes from RustCrypto (`hmac` + `sha1`/`sha2`); only the RFC's
//! dynamic truncation and the base32 decoding (RFC 4648) are written here,
//! and both are checked against the RFCs' own test vectors.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed TOTP configuration. The key is wiped on drop.
pub struct Totp {
    key: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("key", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

/// RFC 4648 base32, case-insensitive; spaces, dashes and '=' padding ignored.
pub fn base32_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 5 / 8));
    let (mut buf, mut bits) = (0u64, 0u32);
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u64 - 'A' as u64,
            'a'..='z' => c as u64 - 'a' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            ' ' | '-' | '=' => continue,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// HMAC over `msg` with the given RustCrypto hash; the key may be any length.
macro_rules! mac {
    ($hash:ty, $key:expr, $msg:expr) => {{
        let mut m =
            <Hmac<$hash> as Mac>::new_from_slice($key).expect("HMAC accepts any key length");
        m.update($msg);
        m.finalize().into_bytes().to_vec()
    }};
}

impl Totp {
    /// Accepts an `otpauth://totp/...` URI or a bare base32 secret.
    pub fn parse(input: &str) -> Option<Totp> {
        let input = input.trim();
        if input.len() > 4096 {
            return None;
        }
        let (secret, mut algorithm, mut digits, mut period) =
            (Zeroizing::new(String::new()), Algorithm::Sha1, 6u32, 30u64);
        let mut secret = secret;
        if input.to_ascii_lowercase().starts_with("otpauth://") {
            let url = url::Url::parse(input).ok()?;
            if url.host_str()? != "totp" {
                return None; // HOTP (counter-based) is not supported.
            }
            for (k, v) in url.query_pairs() {
                match k.to_ascii_lowercase().as_str() {
                    "secret" => secret = Zeroizing::new(v.into_owned()),
                    "algorithm" => {
                        algorithm = match v.to_ascii_uppercase().as_str() {
                            "SHA1" => Algorithm::Sha1,
                            "SHA256" => Algorithm::Sha256,
                            "SHA512" => Algorithm::Sha512,
                            _ => return None,
                        }
                    }
                    "digits" => digits = v.parse().ok()?,
                    "period" => period = v.parse().ok()?,
                    _ => {}
                }
            }
        } else {
            secret = Zeroizing::new(input.to_owned());
        }
        if !(6..=8).contains(&digits) || !(1..=300).contains(&period) {
            return None;
        }
        let key = base32_decode(&secret)?;
        Some(Totp {
            key,
            algorithm,
            digits,
            period,
        })
    }

    /// HOTP value for a counter (RFC 4226 §5.3).
    fn hotp(&self, counter: u64) -> u32 {
        let msg = counter.to_be_bytes();
        let mac: Zeroizing<Vec<u8>> = Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => mac!(sha1::Sha1, &self.key, &msg),
            Algorithm::Sha256 => mac!(sha2::Sha256, &self.key, &msg),
            Algorithm::Sha512 => mac!(sha2::Sha512, &self.key, &msg),
        });
        let off = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([mac[off] & 0x7f, mac[off + 1], mac[off + 2], mac[off + 3]]);
        bin % 10u32.pow(self.digits)
    }

    /// The code at Unix time `now`, zero-padded, and the seconds it stays valid.
    pub fn code_at(&self, now: u64) -> (String, u64) {
        let code = self.hotp(now / self.period);
        let left = self.period - now % self.period;
        (
            format!("{code:0width$}", width = self.digits as usize),
            left,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut out, mut buf, mut bits) = (String::new(), 0u64, 0u32);
        for &b in bytes {
            buf = (buf << 8) | b as u64;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(A[((buf >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    #[test]
    fn base32_rfc4648_vectors() {
        for (enc, dec) in [
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("MZXW6YTB", "fooba"),
            ("MZXW6YTBOI======", "foobar"),
        ] {
            assert_eq!(
                base32_decode(enc).unwrap().as_slice(),
                dec.as_bytes(),
                "{enc}"
            );
            assert_eq!(
                base32_decode(&enc.to_lowercase()).unwrap().as_slice(),
                dec.as_bytes()
            );
        }
        assert_eq!(
            base32_decode("JBSW Y3DP EHPK 3PXP").unwrap().as_slice(),
            b"Hello!\xde\xad\xbe\xef"
        );
        assert!(base32_decode("ABC1").is_none(), "1 is not base32");
        assert!(base32_decode("").is_none());
    }

    /// RFC 6238 Appendix B (8 digits; seeds are ASCII repeated to the hash size).
    #[test]
    fn rfc6238_vectors() {
        let seeds = [
            (Algorithm::Sha1, "SHA1", &b"12345678901234567890"[..]),
            (
                Algorithm::Sha256,
                "SHA256",
                &b"12345678901234567890123456789012"[..],
            ),
            (
                Algorithm::Sha512,
                "SHA512",
                &b"1234567890123456789012345678901234567890123456789012345678901234"[..],
            ),
        ];
        let table: [(u64, [&str; 3]); 6] = [
            (59, ["94287082", "46119246", "90693936"]),
            (1111111109, ["07081804", "68084774", "25091201"]),
            (1111111111, ["14050471", "67062674", "99943326"]),
            (1234567890, ["89005924", "91819424", "93441116"]),
            (2000000000, ["69279037", "90698825", "38618901"]),
            (20000000000, ["65353130", "77737706", "47863826"]),
        ];
        for (i, (alg, name, seed)) in seeds.iter().enumerate() {
            let uri = format!(
                "otpauth://totp/Test?secret={}&algorithm={name}&digits=8&period=30",
                b32(seed)
            );
            let t = Totp::parse(&uri).unwrap();
            assert_eq!(t.algorithm, *alg);
            for (time, codes) in table {
                assert_eq!(t.code_at(time).0, codes[i], "{name} at {time}");
            }
        }
    }

    #[test]
    fn defaults_bare_secret_and_countdown() {
        let t = Totp::parse(&b32(b"12345678901234567890")).unwrap();
        assert_eq!((t.digits, t.period, t.algorithm), (6, 30, Algorithm::Sha1));
        // 6-digit form of the RFC's 94287082 at T=59.
        assert_eq!(t.code_at(59), ("287082".to_owned(), 1));
        assert_eq!(t.code_at(60).1, 30);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").is_none());
        assert!(Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4").is_none());
        assert!(Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").is_none());
        assert!(Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0").is_none());
        assert!(Totp::parse("otpauth://totp/x").is_none(), "no secret");
        assert!(Totp::parse("not base32!").is_none());
    }

    #[test]
    fn debug_hides_the_key() {
        let t = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        assert!(!format!("{t:?}").contains("72"), "no key bytes");
    }
}
