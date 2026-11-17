//! Opens an entry's web site in the default browser.
//!
//! The one rule that matters: only an `http`/`https` address ever reaches
//! `ShellExecuteW`. Any other scheme (`file:`, `cmd://`, `ms-msdt:`,
//! custom protocol handlers, ...) could start a program instead of a
//! browser, and a vault can be imported from a KeePass file someone else
//! made. Everything else is lenient, so that real addresses open:
//! - without "://" the value is taken as `https://<value>`, so `site.com`,
//!   `localhost:8080`, `intranet:8443/giris` and `192.168.1.1` work;
//! - user info is dropped (`kullanici@site.com` opens `https://site.com/`;
//!   credentials are never put into the address the browser gets).
#![allow(unsafe_code)]

use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub const NOT_A_WEB_ADDRESS: &str =
    "Bu adres tarayıcıda açılamaz: yalnızca web adresleri (http/https) açılır.";
pub const OPEN_FAILED: &str = "Tarayıcı açılamadı.";

/// "javascript:…", "mailto:…": a scheme without "//". "localhost:8080" is not
/// one: what follows the colon is a port.
fn has_non_web_scheme(raw: &str) -> bool {
    let Some((head, rest)) = raw.split_once(':') else {
        return false;
    };
    let scheme_like = head.starts_with(|c: char| c.is_ascii_alphabetic())
        && head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    scheme_like && !rest.starts_with(|c: char| c.is_ascii_digit())
}

/// The address to open, or None if it is not a web address.
pub fn web_address(raw: &str) -> Option<url::Url> {
    let raw = raw.trim();
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return None;
    }
    let mut u = if raw.contains("://") {
        url::Url::parse(raw).ok()?
    } else if has_non_web_scheme(raw) {
        return None;
    } else {
        url::Url::parse(&format!("https://{raw}")).ok()?
    };
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none_or(str::is_empty) {
        return None;
    }
    // Cannot fail for an http(s) URL with a host.
    let _ = u.set_username("");
    let _ = u.set_password(None);
    Some(u)
}

pub fn open(u: &url::Url) -> Result<(), &'static str> {
    // Re-checked here so that no caller can pass anything else.
    if !matches!(u.scheme(), "http" | "https") {
        return Err(NOT_A_WEB_ADDRESS);
    }
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (verb, target) = (wide("open"), wide(u.as_str()));
    // SAFETY: both strings are NUL-terminated and outlive the call; the
    // other pointers may be null.
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW reports success with a value greater than 32.
    if r as isize > 32 {
        Ok(())
    } else {
        Err(OPEN_FAILED)
    }
}

#[cfg(test)]
mod tests {
    use super::web_address;

    fn ok(s: &str) -> Option<String> {
        web_address(s).map(|u| u.to_string())
    }

    #[test]
    fn web_addresses_are_opened() {
        for (raw, opened) in [
            ("https://github.com/login", "https://github.com/login"),
            ("http://example.com", "http://example.com/"),
            ("  github.com/login ", "https://github.com/login"),
            ("www.site.com.tr", "https://www.site.com.tr/"),
            // A host with a port and no scheme (refused before 0.3.1).
            ("localhost:8080", "https://localhost:8080/"),
            ("intranet:8443/giris", "https://intranet:8443/giris"),
            ("site.com:8443/x?a=1", "https://site.com:8443/x?a=1"),
            ("192.168.1.1:8080", "https://192.168.1.1:8080/"),
            // User info is dropped, not refused.
            ("kullanici@mail.example.com", "https://mail.example.com/"),
            ("https://user:pass@example.com/x", "https://example.com/x"),
        ] {
            assert_eq!(ok(raw).as_deref(), Some(opened), "{raw:?}");
        }
    }

    /// Whatever the input, nothing but an http(s) address with a host and
    /// no user info is handed to the shell.
    #[test]
    fn only_http_and_https_reach_the_shell() {
        for raw in [
            "file:///C:/Windows/System32/calc.exe",
            "cmd://calc.exe",
            "vbscript://x",
            "ftp://example.com",
            "ms-msdt:/id PCWDiagnostic",
            "search-ms:query=x",
            "javascript:alert(1)",
            "mailto:a@b.com",
            "\\\\server\\share\\x.exe",
            "C:\\Windows\\System32\\calc.exe",
            "https://bank.com@evil.com/",
            "https://",
            "https://exa\nmple.com",
            "{REF:U@I:46C9B1FFBD4ABC4BBB260C6190BAD20C}",
        ] {
            if let Some(u) = web_address(raw) {
                assert!(matches!(u.scheme(), "http" | "https"), "{raw:?} -> {u}");
                assert!(u.username().is_empty() && u.password().is_none(), "{raw:?}");
                assert!(u.host_str().is_some_and(|h| !h.is_empty()), "{raw:?}");
            }
        }
        for refused in [
            "",
            "   ",
            "file:///C:/x",
            "cmd://calc.exe",
            "ftp://x.com",
            "https://",
            "javascript:alert(1)",
            "mailto:a@b.com",
            "ms-msdt:/id PCWDiagnostic",
        ] {
            assert_eq!(ok(refused), None, "{refused:?}");
        }
    }
}
