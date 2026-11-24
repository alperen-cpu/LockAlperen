//! Who owns the window auto-type is about to type into.
//!
//! A window title can be set by any program, so a title match alone cannot
//! tell a real browser from a malicious window that copies its title (the
//! "Vault Raider" class of attack, NDSS 2026). Before anything is typed, the
//! program behind the window must be either
//! - installed where only an administrator can write (the Windows folder or
//!   Program Files), or
//! - signed: its executable carries a valid Authenticode signature (per-user
//!   installs such as Chrome in AppData are signed).
//!
//! Limit: a signed or administrator-installed program that is itself
//! malicious still passes; so does an attacker who is an administrator.
#![cfg_attr(not(windows), allow(dead_code))]

pub const UNTRUSTED_PROGRAM: &str = "Hedef pencerenin programı ne Windows ya da Program Files \
     klasöründe ne de geçerli bir imzaya sahip. Başlığı taklit eden bir pencere olabileceği için \
     hiçbir şey yazılmadı.";

/// Whether `path` is inside one of `dirs` (case-insensitive, whole folder
/// names: "C:\Program Files Evil" is not inside "C:\Program Files").
pub fn inside(path: &str, dirs: &[String]) -> bool {
    let p = path.to_lowercase().replace('/', "\\");
    if p.contains("\\..\\") || p.starts_with("\\\\") {
        return false;
    }
    dirs.iter().any(|d| {
        let mut d = d.trim().to_lowercase().replace('/', "\\");
        if d.len() < 3 {
            return false; // never a bare drive or empty value
        }
        if !d.ends_with('\\') {
            d.push('\\');
        }
        p.starts_with(&d)
    })
}

#[cfg(windows)]
pub use imp::check;

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS};
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Full path of the process's executable.
    fn image_path(pid: u32) -> Option<String> {
        // SAFETY: the handle is closed on every path; the buffer and its
        // length are passed together.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = vec![0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    /// A REG_SZ under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion: the
    /// machine's own value, which no user setting can redirect.
    fn machine_value(name: &str) -> Option<String> {
        let key = wide(r"SOFTWARE\Microsoft\Windows\CurrentVersion");
        let name = wide(name);
        let mut buf = vec![0u16; 512];
        let mut bytes = (buf.len() * 2) as u32;
        // SAFETY: buffer size in bytes is passed with the buffer.
        let r = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if r != ERROR_SUCCESS {
            return None;
        }
        let n = (bytes as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..n]);
        Some(s.trim_end_matches('\0').to_owned())
    }

    /// Folders only an administrator can write to.
    fn protected_dirs() -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = [0u16; 260];
        // SAFETY: buffer and its length are passed together.
        let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if n > 0 && (n as usize) < buf.len() {
            out.push(String::from_utf16_lossy(&buf[..n as usize]));
        }
        for v in [
            "ProgramFilesDir",
            "ProgramFilesDir (x86)",
            "ProgramW6432Dir",
        ] {
            if let Some(d) = machine_value(v) {
                out.push(d);
            }
        }
        out
    }

    /// A valid Authenticode signature, checked offline (no revocation
    /// lookups, no network).
    fn signed(path: &str) -> bool {
        let path = wide(path);
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: `file`, `path` and `action` outlive both calls; the state
        // opened by VERIFY is released by CLOSE.
        unsafe {
            let r = WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            );
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            );
            r == 0
        }
    }

    /// Ok if the process may be typed into (see the module comment).
    pub fn check(pid: u32) -> Result<(), &'static str> {
        let Some(path) = image_path(pid) else {
            return Err(super::UNTRUSTED_PROGRAM);
        };
        if super::inside(&path, &protected_dirs()) || signed(&path) {
            Ok(())
        } else {
            Err(super::UNTRUSTED_PROGRAM)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inside_matches_whole_folders_only() {
        let dirs = vec![r"C:\Windows".to_owned(), r"C:\Program Files\".to_owned()];
        assert!(inside(r"C:\Windows\System32\mstsc.exe", &dirs));
        assert!(inside(r"c:\program files\Google\Chrome\chrome.exe", &dirs));
        assert!(!inside(r"C:\Program Files Evil\chrome.exe", &dirs));
        assert!(!inside(r"C:\WindowsApps2\x.exe", &dirs));
        assert!(!inside(r"C:\Users\a\AppData\Local\chrome.exe", &dirs));
        assert!(!inside(r"C:\Windows\..\Users\a\x.exe", &dirs));
        assert!(!inside(r"\\server\share\Windows\x.exe", &dirs));
        // A bare drive or an empty value never trusts everything.
        assert!(!inside(r"C:\x.exe", &["C:".to_owned(), String::new()]));
    }
}
