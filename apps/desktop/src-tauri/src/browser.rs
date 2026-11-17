//! Opens an entry's web site in the default browser.
//!
//! Only `http`/`https` addresses reach `ShellExecuteW`. Any other scheme
//! (`file:`, `ms-msdt:`, `search-ms:`, custom protocol handlers, ...) could
//! start a program instead of a browser, and a vault can be imported from a
//! KeePass file someone else made. Addresses with user info
//! (`https://bank.com@evil.com`) are refused too: they show one host and
//! open another.
#![allow(unsafe_code)]

use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub const NOT_A_WEB_ADDRESS: &str = "Bu kaydın web sitesi bir http(s) adresi değil; açılmadı.";
pub const OPEN_FAILED: &str = "Tarayıcı açılamadı.";

/// The address to open, or None if it must not be opened. A bare host
/// ("github.com/login") is taken as https.
pub fn web_address(raw: &str) -> Option<url::Url> {
    let raw = raw.trim();
    // Backslashes: a UNC or Windows path, never a web address we wrote.
    if raw.is_empty() || raw.chars().any(char::is_control) || raw.contains('\\') {
        return None;
    }
    let u = match url::Url::parse(raw) {
        Ok(u) => u,
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            url::Url::parse(&format!("https://{raw}")).ok()?
        }
        Err(_) => return None,
    };
    let ok = matches!(u.scheme(), "http" | "https")
        && u.host_str().is_some_and(|h| !h.is_empty())
        && u.username().is_empty()
        && u.password().is_none();
    ok.then_some(u)
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
        assert_eq!(
            ok("https://github.com/login").as_deref(),
            Some("https://github.com/login")
        );
        assert_eq!(
            ok("http://example.com").as_deref(),
            Some("http://example.com/")
        );
        assert_eq!(
            ok("  github.com/login ").as_deref(),
            Some("https://github.com/login")
        );
        assert_eq!(
            ok("mail.example.com").as_deref(),
            Some("https://mail.example.com/")
        );
    }

    #[test]
    fn nothing_else_is_opened() {
        for bad in [
            "",
            "   ",
            "file:///C:/Windows/System32/calc.exe",
            "ms-msdt:/id PCWDiagnostic",
            "search-ms:query=x",
            "javascript:alert(1)",
            "ftp://example.com",
            "\\\\server\\share\\x.exe",
            "C:\\Windows\\System32\\calc.exe",
            "https://bank.com@evil.com/",
            "https://user:pass@example.com/",
            "https://",
            "https://exa\nmple.com",
        ] {
            assert_eq!(ok(bad), None, "{bad:?}");
        }
    }
}
