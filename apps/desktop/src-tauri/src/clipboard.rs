//! Copying secrets to the Windows clipboard (SECURITY.md, "Pano").
//!
//! - The text is marked so that Windows keeps it out of clipboard history
//!   (Win+V), cloud clipboard sync and clipboard monitors:
//!   `ExcludeClipboardContentFromMonitorProcessing`,
//!   `CanIncludeInClipboardHistory = 0`, `CanUploadToCloudClipboard = 0`.
//! - Clearing happens only if the clipboard still holds OUR content
//!   (sequence number unchanged), so a later copy by the user is never wiped.
//!
//! Limits (documented, not solvable here): another program may read the
//! clipboard while the secret is on it, and the memory Windows frees on
//! `EmptyClipboard` is not wiped by us.
//!
//! This is the only module with `unsafe` code in the app.
#![allow(unsafe_code)]

use std::{thread, time::Duration};

use windows_sys::Win32::Foundation::GlobalFree;
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use zeroize::Zeroize;

#[derive(Debug, PartialEq, Eq)]
pub struct ClipboardError;

/// Proof that we put something on the clipboard: its sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Copied(u32);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn register(name: &str) -> u32 {
    let w = wide(name);
    // SAFETY: `w` is a NUL-terminated UTF-16 string that outlives the call.
    unsafe { RegisterClipboardFormatW(w.as_ptr()) }
}

/// Holds the clipboard open; closes it on drop.
struct Open;

impl Open {
    fn new() -> Result<Self, ClipboardError> {
        // Another process may hold the clipboard briefly: retry for ~0.5 s.
        for _ in 0..50 {
            // SAFETY: a null owner window is allowed.
            if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                return Ok(Open);
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err(ClipboardError)
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: we opened the clipboard in `Open::new`.
        unsafe { CloseClipboard() };
    }
}

/// Copies `bytes` into a movable global block and hands it to the clipboard.
/// On success the clipboard owns the block; on failure we free it.
fn put(format: u32, bytes: &[u8]) -> Result<(), ClipboardError> {
    if format == 0 {
        return Err(ClipboardError);
    }
    // SAFETY: standard GlobalAlloc / GlobalLock / copy / GlobalUnlock /
    // SetClipboardData sequence; the size matches the copy, the block is
    // freed if the clipboard did not take it.
    unsafe {
        let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1));
        if h.is_null() {
            return Err(ClipboardError);
        }
        let p = GlobalLock(h) as *mut u8;
        if p.is_null() {
            GlobalFree(h);
            return Err(ClipboardError);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        GlobalUnlock(h);
        if SetClipboardData(format, h).is_null() {
            GlobalFree(h);
            return Err(ClipboardError);
        }
    }
    Ok(())
}

/// Puts `text` on the clipboard, hidden from history, cloud sync and monitors.
pub fn copy_secret(text: &str) -> Result<Copied, ClipboardError> {
    let mut utf16 = wide(text);
    let mut bytes: Vec<u8> = utf16.iter().flat_map(|u| u.to_le_bytes()).collect();
    utf16.zeroize();

    let result = (|| {
        let _open = Open::new()?;
        // SAFETY: the clipboard is open.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(ClipboardError);
        }
        let zero = 0u32.to_le_bytes();
        put(
            register("ExcludeClipboardContentFromMonitorProcessing"),
            &zero,
        )?;
        put(register("CanIncludeInClipboardHistory"), &zero)?;
        put(register("CanUploadToCloudClipboard"), &zero)?;
        put(CF_UNICODETEXT as u32, &bytes)?;
        Ok(())
    })();
    bytes.zeroize();
    result?;
    // SAFETY: no preconditions.
    Ok(Copied(unsafe { GetClipboardSequenceNumber() }))
}

/// Empties the clipboard only if it still holds what `copied` put there.
/// Returns true if it was cleared.
pub fn clear_if_ours(copied: Copied) -> bool {
    // SAFETY: no preconditions.
    if unsafe { GetClipboardSequenceNumber() } != copied.0 {
        return false;
    }
    let Ok(_open) = Open::new() else {
        return false;
    };
    // Re-check while holding the clipboard: nobody can change it now.
    // SAFETY: no preconditions; the clipboard is open.
    unsafe { GetClipboardSequenceNumber() == copied.0 && EmptyClipboard() != 0 }
}

#[cfg(test)]
mod tests {
    //! These touch the REAL clipboard of the logged-in user, so they are
    //! ignored by default. Run: `cargo test -- --ignored --test-threads=1`.
    use super::*;
    use windows_sys::Win32::System::DataExchange::{GetClipboardData, IsClipboardFormatAvailable};

    fn read_text() -> Option<String> {
        let _open = Open::new().ok()?;
        // SAFETY: clipboard open; the handle stays valid until it closes.
        unsafe {
            let h = GetClipboardData(CF_UNICODETEXT as u32);
            if h.is_null() {
                return None;
            }
            let p = GlobalLock(h) as *const u16;
            let mut n = 0;
            while *p.add(n) != 0 {
                n += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
            GlobalUnlock(h);
            Some(s)
        }
    }

    fn available(name: &str) -> bool {
        // SAFETY: no preconditions.
        unsafe { IsClipboardFormatAvailable(register(name)) != 0 }
    }

    #[test]
    #[ignore = "uses the real clipboard"]
    fn secret_is_marked_and_cleared() {
        let c = copy_secret("gizli-ğüşİ-123").unwrap();
        assert_eq!(read_text().as_deref(), Some("gizli-ğüşİ-123"));
        assert!(available("ExcludeClipboardContentFromMonitorProcessing"));
        assert!(available("CanIncludeInClipboardHistory"));
        assert!(available("CanUploadToCloudClipboard"));
        assert!(clear_if_ours(c));
        assert_eq!(read_text(), None);
    }

    #[test]
    #[ignore = "uses the real clipboard"]
    fn a_later_copy_by_the_user_is_not_cleared() {
        let ours = copy_secret("bizim").unwrap();
        let _theirs = copy_secret("kullanıcının").unwrap();
        assert!(!clear_if_ours(ours));
        assert_eq!(read_text().as_deref(), Some("kullanıcının"));
    }
}
