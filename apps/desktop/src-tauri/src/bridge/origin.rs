//! Which entries belong to the page the browser extension asks about.
//!
//! The rules come from other password managers' failures
//! (docs/research/rakipler-eklenti-2016-2026.md §3.1):
//! - URLs are parsed with the `url` crate (WHATWG), never with string
//!   splitting (LastPass 2016, Passbolt 2019);
//! - matching is on the exact origin: scheme, host and port. Subdomains and
//!   "same base domain" do not match (Bitwarden, Proton Pass and the 2025
//!   clickjacking study, where every manager filled on any subdomain);
//! - the only widening: `www.` and the bare host are the same site, and an
//!   entry saved for `http://` may fill the same host over `https://` (the
//!   safe direction; an `https://` entry never fills an `http://` page);
//! - IP addresses compare exactly; internationalized names compare in
//!   punycode (what the `url` crate gives).
//!
//! The desktop app decides the match from the origin the extension reports;
//! the extension never gets entries for other sites.

use url::{Host, Url};

/// A web origin: scheme (`http`/`https`), host and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    https: bool,
    host: String,
    is_domain: bool,
    port: u16,
}

impl Origin {
    /// The origin of a page as the extension reports it (`https://host[:port]`,
    /// a path is ignored). Anything else (other schemes, user info, no host)
    /// is refused.
    pub fn of_page(raw: &str) -> Option<Origin> {
        if raw.len() > 2048 || raw.chars().any(char::is_control) {
            return None;
        }
        let u = Url::parse(raw).ok()?;
        if !u.username().is_empty() || u.password().is_some() {
            return None;
        }
        Self::from_url(&u)
    }

    /// The origin of an entry's web address (`site.com/login` means
    /// `https://site.com`), as "Siteyi aç" reads it.
    pub fn of_entry(raw: &str) -> Option<Origin> {
        Self::from_url(&crate::browser::web_address(raw)?)
    }

    fn from_url(u: &Url) -> Option<Origin> {
        let https = match u.scheme() {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        let (host, is_domain) = match u.host()? {
            Host::Domain(d) if !d.is_empty() => (d.trim_end_matches('.').to_owned(), true),
            Host::Domain(_) => return None,
            Host::Ipv4(ip) => (ip.to_string(), false),
            Host::Ipv6(ip) => (format!("[{ip}]"), false),
        };
        if host.is_empty() {
            return None;
        }
        Some(Origin {
            https,
            host,
            is_domain,
            port: u.port_or_known_default()?,
        })
    }

    /// `https://host[:port]` (the port only when it is not the default).
    pub fn serialize(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        let default = if self.https { 443 } else { 80 };
        if self.port == default {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }

    fn site_host(&self) -> &str {
        if self.is_domain {
            self.host.strip_prefix("www.").unwrap_or(&self.host)
        } else {
            &self.host
        }
    }

    /// Whether an entry saved for `self` may be filled into `page`.
    pub fn fills(&self, page: &Origin) -> bool {
        if self.is_domain != page.is_domain || self.site_host() != page.site_host() {
            return false;
        }
        match (self.https, page.https) {
            (true, true) | (false, false) => self.port == page.port,
            // http entry, https page: same host on the default ports only.
            (false, true) => self.port == 80 && page.port == 443,
            // An https entry never fills a page that is not https.
            (true, false) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fills(entry: &str, page: &str) -> bool {
        let e = Origin::of_entry(entry).unwrap_or_else(|| panic!("entry {entry}"));
        let p = Origin::of_page(page).unwrap_or_else(|| panic!("page {page}"));
        e.fills(&p)
    }

    #[test]
    fn exact_origin_and_www_match() {
        assert!(fills("https://github.com/login", "https://github.com"));
        assert!(fills("github.com", "https://github.com/session"));
        assert!(fills("www.github.com", "https://github.com/"));
        assert!(fills("https://github.com", "https://www.github.com/"));
        assert!(fills("HTTPS://GitHub.COM", "https://github.com"));
        assert!(fills("https://intranet:8443/x", "https://intranet:8443"));
        assert!(fills("https://github.com.", "https://github.com"));
    }

    #[test]
    fn subdomains_and_lookalikes_never_match() {
        assert!(!fills("github.com", "https://evil.github.com"));
        assert!(!fills("login.bank.com", "https://bank.com"));
        assert!(!fills("bank.com", "https://bank.com.evil.net"));
        assert!(!fills("bank.com", "https://evilbank.com"));
        assert!(!fills("bank.com", "https://bank.co"));
        // Lookalike in another script: compared in punycode, so different.
        assert!(!fills("apple.com", "https://аpple.com"));
        assert!(!fills("www.www.bank.com", "https://bank.com"));
    }

    #[test]
    fn scheme_and_port_rules() {
        assert!(
            !fills("https://site.com", "http://site.com"),
            "never downgrade"
        );
        assert!(
            fills("http://site.com", "https://site.com"),
            "upgrade is fine"
        );
        assert!(!fills("http://site.com:8080", "https://site.com"));
        assert!(!fills("https://site.com", "https://site.com:8443"));
        assert!(!fills("https://site.com:8443", "https://site.com"));
    }

    #[test]
    fn ip_addresses_compare_exactly() {
        assert!(fills("https://192.168.1.1", "https://192.168.1.1/login"));
        assert!(!fills("https://192.168.1.1", "https://192.168.1.10"));
        assert!(fills("https://[::1]:8443", "https://[::1]:8443"));
        // An IP never matches a name, even "www."-stripped.
        assert!(!fills("https://127.0.0.1", "https://localhost"));
    }

    #[test]
    fn pages_that_are_not_plain_web_origins_are_refused() {
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<form>",
            "blob:https://site.com/123",
            "chrome-extension://abc/popup.html",
            "about:blank",
            "https://user:pass@site.com",
            "https://user@site.com",
            "https://site.com/\nx",
            "not a url",
            "",
        ] {
            assert!(Origin::of_page(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn entries_without_a_web_address_match_nothing() {
        for bad in [
            "",
            "   ",
            "javascript:alert(1)",
            "file:///x",
            "ftp://site.com",
        ] {
            assert!(Origin::of_entry(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn serialize_round_trips() {
        assert_eq!(
            Origin::of_page("https://Site.com:443/x?y")
                .unwrap()
                .serialize(),
            "https://site.com"
        );
        assert_eq!(
            Origin::of_page("http://site.com:8080").unwrap().serialize(),
            "http://site.com:8080"
        );
    }
}
