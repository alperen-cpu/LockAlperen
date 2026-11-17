//! "Windows açılışında başlat" (KeePass Options → Integration → "Run
//! KeePass at Windows startup"). A value named `LockAlperen` under the
//! CURRENT USER's Run key; no administrator rights, nothing machine-wide.
//! The value is the quoted path of the running executable.
#![allow(unsafe_code)]

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "LockAlperen";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The command line stored in the Run key: the quoted executable path.
pub fn command_line(exe: &std::path::Path) -> String {
    format!("\"{}\"", exe.display())
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: a key we opened and own.
        unsafe { RegCloseKey(self.0) };
    }
}

fn open(access: u32) -> Option<Key> {
    let path = wide(RUN_KEY);
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: valid NUL-terminated path; `key` receives the handle.
    let r = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &mut key) };
    (r == ERROR_SUCCESS).then_some(Key(key))
}

/// Whether our value exists in the Run key.
pub fn enabled() -> bool {
    let Some(key) = open(KEY_QUERY_VALUE) else {
        return false;
    };
    let name = wide(VALUE_NAME);
    // SAFETY: only asks whether the value exists (no buffer).
    let r = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    r == ERROR_SUCCESS
}

/// Adds (true) or removes (false) our value. Removing a missing value is
/// not an error.
pub fn set(on: bool) -> Result<(), &'static str> {
    const FAILED: &str = "Windows başlangıç ayarı değiştirilemedi.";
    let key = open(KEY_SET_VALUE).ok_or(FAILED)?;
    let name = wide(VALUE_NAME);
    if on {
        let exe = std::env::current_exe().map_err(|_| FAILED)?;
        let data = wide(&command_line(&exe));
        let bytes = (data.len() * 2) as u32;
        // SAFETY: REG_SZ data is a NUL-terminated UTF-16 buffer of `bytes`.
        let r =
            unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, REG_SZ, data.as_ptr().cast(), bytes) };
        (r == ERROR_SUCCESS).then_some(()).ok_or(FAILED)
    } else {
        // SAFETY: valid key and NUL-terminated name.
        let r = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
        // ERROR_FILE_NOT_FOUND = 2: already absent.
        (r == ERROR_SUCCESS || r == 2).then_some(()).ok_or(FAILED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_is_quoted() {
        let p = std::path::Path::new(r"C:\Program Files\LockAlperen\LockAlperen.exe");
        assert_eq!(
            command_line(p),
            r#""C:\Program Files\LockAlperen\LockAlperen.exe""#
        );
    }

    /// Touches the real registry (HKCU Run): run by hand with --ignored.
    #[test]
    #[ignore]
    fn set_and_clear_in_registry() {
        let was = enabled();
        set(true).unwrap();
        assert!(enabled());
        set(false).unwrap();
        assert!(!enabled());
        set(false).unwrap();
        if was {
            set(true).unwrap();
        }
    }
}
