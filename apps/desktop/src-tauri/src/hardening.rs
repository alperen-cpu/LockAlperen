//! Process hardening required by SECURITY.md ("Faz 2'de zorunlu
//! sıkılaştırmalar"). Each step is best effort and reports whether Windows
//! accepted it; none of them is a guarantee against an administrator or
//! malware running as the same user (documented in the README).
#![allow(unsafe_code)]

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HWND};
use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    AddAccessAllowedAce, GetLengthSid, GetTokenInformation, InitializeAcl, TokenUser,
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR,
};

/// DLL hijacking: later `LoadLibrary` calls without a full path search only
/// System32 (not the current directory, PATH or the app folder).
pub fn restrict_dll_search() -> bool {
    // SAFETY: plain flag argument.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0 }
}

/// Rights other processes of the same user keep on ours: see that it runs,
/// wait for it, end it (Task Manager). No PROCESS_VM_READ / VM_WRITE /
/// CREATE_THREAD / DUP_HANDLE, so a non-admin program cannot read our memory
/// (the KeeFarce class of attack) through the normal API.
pub const ALLOWED_TO_USER: u32 =
    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE;

/// Replaces our process DACL with one entry: the current user gets only
/// [`ALLOWED_TO_USER`]. Limits: the object owner (the same user) can still
/// rewrite the DACL (WRITE_DAC is implicit for owners); administrators with
/// SeDebugPrivilege bypass DACLs entirely.
pub fn protect_process() -> bool {
    // SAFETY: standard token / ACL APIs. Buffers are sized from the API's own
    // answers, u64-aligned, and outlive every pointer into them; the token
    // handle is closed on every path.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        let got = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        CloseHandle(token);
        if got == 0 {
            return false;
        }
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        let acl_len = std::mem::size_of::<ACL>()
            + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            + GetLengthSid(sid) as usize
            - std::mem::size_of::<u32>();
        let mut acl = vec![0u64; acl_len.div_ceil(8)];
        let pacl = acl.as_mut_ptr() as *mut ACL;
        if InitializeAcl(pacl, acl_len as u32, ACL_REVISION) == 0
            || AddAccessAllowedAce(pacl, ACL_REVISION, ALLOWED_TO_USER, sid) == 0
        {
            return false;
        }
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            pacl,
            std::ptr::null(),
        ) == ERROR_SUCCESS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capture {
    /// Windows 10 2004+: the window is left out of screenshots and sharing.
    Excluded,
    /// Older Windows: the window shows as black in captures.
    Blacked,
    Failed,
}

/// Keeps the window out of screen capture (Teams/Zoom sharing, screenshots).
pub fn exclude_from_capture(hwnd: HWND) -> Capture {
    // SAFETY: hwnd is a live top-level window of this process.
    unsafe {
        if SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) != 0 {
            Capture::Excluded
        } else if SetWindowDisplayAffinity(hwnd, WDA_MONITOR) != 0 {
            Capture::Blacked
        } else {
            Capture::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, PROCESS_VM_READ,
    };

    fn can_open(rights: u32) -> bool {
        // SAFETY: opening our own process id; the handle is closed.
        unsafe {
            let h = OpenProcess(rights, 0, GetCurrentProcessId());
            if h.is_null() {
                false
            } else {
                CloseHandle(h);
                true
            }
        }
    }

    /// Changes the DACL of the TEST process (harmless) and checks that a
    /// same-user OpenProcess for memory reading is now refused.
    #[test]
    fn dacl_blocks_memory_reads_but_not_basic_queries() {
        assert!(protect_process());
        assert!(!can_open(PROCESS_VM_READ), "memory read must be denied");
        assert!(can_open(PROCESS_QUERY_LIMITED_INFORMATION));
    }

    #[test]
    fn dll_search_is_restricted() {
        assert!(restrict_dll_search());
    }
}
