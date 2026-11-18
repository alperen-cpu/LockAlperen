//! Automatic locking (SECURITY.md, "Otomatik kilit"). All decisions are made
//! here in Rust; the WebView only displays the countdown and cannot keep the
//! vault open. Below: Windows. Linux: src/linux/autolock.rs.
//!
//! - Idle: system-wide time since the last keyboard/mouse input
//!   (`GetLastInputInfo`), not activity inside the WebView.
//! - Windows events, received by a hidden top-level window of our own:
//!   workstation lock, console/remote disconnect, logoff (`WM_WTSSESSION_CHANGE`)
//!   and suspend (`WM_POWERBROADCAST` / `PBT_APMSUSPEND`).
#![allow(unsafe_code)]

#[cfg(windows)]
use std::sync::OnceLock;
use std::time::Duration;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(windows)]
use windows_sys::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::GetTickCount;
#[cfg(windows)]
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
    TranslateMessage, MSG, PBT_APMSUSPEND, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSW,
    WS_OVERLAPPED,
};

/// The idle timeout in effect. Debug builds accept `LAV_IDLE_SECS` so the
/// idle lock can be tried without waiting; release builds ignore it.
pub fn idle_timeout() -> Duration {
    if cfg!(debug_assertions) {
        if let Some(secs) = std::env::var("LAV_IDLE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            return Duration::from_secs(secs.max(1));
        }
    }
    Duration::from_secs(u64::from(crate::settings::idle_minutes()) * 60)
}

// wParam values of WM_WTSSESSION_CHANGE (WinUser.h).
#[cfg(windows)]
const WTS_CONSOLE_DISCONNECT: usize = 0x2;
#[cfg(windows)]
const WTS_REMOTE_DISCONNECT: usize = 0x4;
#[cfg(windows)]
const WTS_SESSION_LOGOFF: usize = 0x6;
#[cfg(windows)]
const WTS_SESSION_LOCK: usize = 0x7;

/// Why the vault was locked by the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    SessionLocked,
    Disconnected,
    LoggedOff,
    Suspend,
}

/// Maps a window message to a lock reason. Pure, so it can be tested.
#[cfg(windows)]
pub fn reason_for(msg: u32, wparam: usize) -> Option<Reason> {
    match (msg, wparam) {
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK) => Some(Reason::SessionLocked),
        (WM_WTSSESSION_CHANGE, WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT) => {
            Some(Reason::Disconnected)
        }
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOGOFF) => Some(Reason::LoggedOff),
        (WM_POWERBROADCAST, w) if w == PBT_APMSUSPEND as usize => Some(Reason::Suspend),
        _ => None,
    }
}

/// Seconds left before the idle lock, given how long the system has been idle.
pub fn seconds_left(idle: Duration, timeout: Duration) -> u64 {
    timeout.saturating_sub(idle).as_secs()
}

/// System-wide time since the last user input.
#[cfg(windows)]
pub fn system_idle() -> Duration {
    let mut info = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: `info` is a valid, correctly sized LASTINPUTINFO.
    if unsafe { GetLastInputInfo(&mut info) } == 0 {
        // Unknown: treat as fully idle, i.e. fail towards locking.
        return Duration::MAX;
    }
    // SAFETY: no preconditions. Both are 32-bit tick counts; wrapping_sub
    // handles the 49.7-day wrap-around.
    let now = unsafe { GetTickCount() };
    Duration::from_millis(u64::from(now.wrapping_sub(info.dwTime)))
}

#[cfg(windows)]
type Callback = Box<dyn Fn(Reason) + Send + Sync>;
#[cfg(windows)]
static CALLBACK: OnceLock<Callback> = OnceLock::new();

#[cfg(windows)]
unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if let (Some(reason), Some(cb)) = (reason_for(msg, wparam), CALLBACK.get()) {
        cb(reason);
    }
    // SAFETY: forwarding the same arguments we received.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Starts the watcher thread once. Returns the hidden window handle (as an
/// integer, for tests) or None if Windows refused to create it.
#[cfg(windows)]
pub fn watch(on_lock: impl Fn(Reason) + Send + Sync + 'static) -> Option<isize> {
    if CALLBACK.set(Box::new(on_lock)).is_err() {
        return None; // already running
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("lav-autolock".into())
        .spawn(move || {
            let class = wide("LockAlperenSessionWatcher");
            // SAFETY: standard window-class registration and window creation;
            // strings outlive the calls; the message loop runs on the thread
            // that created the window, as Win32 requires.
            unsafe {
                let hinstance = GetModuleHandleW(std::ptr::null());
                let wc = WNDCLASSW {
                    lpfnWndProc: Some(wndproc),
                    hInstance: hinstance,
                    lpszClassName: class.as_ptr(),
                    ..std::mem::zeroed()
                };
                RegisterClassW(&wc);
                // A hidden TOP-LEVEL window (never shown): message-only
                // windows do not receive broadcast messages such as
                // WM_POWERBROADCAST.
                let hwnd = CreateWindowExW(
                    0,
                    class.as_ptr(),
                    class.as_ptr(),
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    hinstance,
                    std::ptr::null(),
                );
                if hwnd.is_null()
                    || WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0
                {
                    let _ = tx.send(None);
                    return;
                }
                let _ = tx.send(Some(hwnd as isize));
                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        })
        .ok()?;
    rx.recv().ok().flatten()
}

// Linux: logind / screensaver D-Bus signals and the desktop's idle time.
#[cfg(target_os = "linux")]
#[path = "linux/autolock.rs"]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{system_idle, watch};

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn lock_reasons() {
        assert_eq!(
            reason_for(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK),
            Some(Reason::SessionLocked)
        );
        assert_eq!(
            reason_for(WM_WTSSESSION_CHANGE, WTS_REMOTE_DISCONNECT),
            Some(Reason::Disconnected)
        );
        assert_eq!(
            reason_for(WM_WTSSESSION_CHANGE, WTS_SESSION_LOGOFF),
            Some(Reason::LoggedOff)
        );
        assert_eq!(
            reason_for(WM_POWERBROADCAST, PBT_APMSUSPEND as usize),
            Some(Reason::Suspend)
        );
        // Unlock (0x8) and resume (PBT_APMRESUMEAUTOMATIC = 0x12) never lock
        // or unlock anything.
        assert_eq!(reason_for(WM_WTSSESSION_CHANGE, 0x8), None);
        assert_eq!(reason_for(WM_POWERBROADCAST, 0x12), None);
    }

    #[test]
    fn countdown() {
        let t = Duration::from_secs(300);
        assert_eq!(seconds_left(Duration::from_secs(0), t), 300);
        assert_eq!(seconds_left(Duration::from_secs(299), t), 1);
        assert_eq!(seconds_left(Duration::from_secs(400), t), 0);
        assert_eq!(seconds_left(Duration::MAX, t), 0);
    }

    #[test]
    fn idle_is_measurable() {
        // Not a timing assertion: only that the API answers sensibly.
        assert!(system_idle() < Duration::from_secs(60 * 60 * 24 * 365));
    }

    /// Delivers real window messages to the real hidden window and checks the
    /// callback fires. Does NOT prove Windows itself sends them on Win+L or
    /// sleep: that was checked by hand (see README).
    #[cfg(windows)]
    #[test]
    fn hidden_window_turns_messages_into_lock_calls() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use windows_sys::Win32::UI::WindowsAndMessaging::SendMessageW;
        static CALLS: AtomicUsize = AtomicUsize::new(0);

        let hwnd = watch(|_| {
            CALLS.fetch_add(1, Ordering::SeqCst);
        })
        .expect("watcher window");
        // SAFETY: hwnd is our live window; SendMessage waits for wndproc.
        unsafe {
            SendMessageW(hwnd as HWND, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK, 0);
            SendMessageW(hwnd as HWND, WM_POWERBROADCAST, PBT_APMSUSPEND as usize, 0);
            SendMessageW(hwnd as HWND, WM_WTSSESSION_CHANGE, 0x8, 0); // unlock: ignored
        }
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
    }
}
