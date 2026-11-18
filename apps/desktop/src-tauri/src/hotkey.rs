//! Global auto-type shortcut (SECURITY.md "Otomatik yazma"), chosen in
//! Settings from a fixed list (default Ctrl+Alt+A, as in KeePass).
//!
//! Registered with `RegisterHotKey` on a thread of our own; WM_HOTKEY arrives
//! in that thread's message queue. The window in front when the keys are
//! pressed is the target; `crate::on_autotype_hotkey` decides what to type
//! (exactly one entry must match its title, as for the button). If another
//! program already owns the combination, registration fails and Settings
//! says so (`active`).
//!
//! Before typing, the user must have released every modifier: characters
//! sent while Ctrl or Alt is still held become shortcuts in the target
//! (Ctrl+W closes a tab). If they are not released in time, nothing is typed.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, RegisterHotKey, UnregisterHotKey, HOT_KEY_MODIFIERS, MOD_ALT, MOD_CONTROL,
    MOD_NOREPEAT, MOD_SHIFT, VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetMessageW, PeekMessageW, PostThreadMessageW, MSG, PM_NOREMOVE, WM_APP,
    WM_HOTKEY,
};

use crate::settings::{Shortcut, ShowShortcut};

const HOTKEY_ID: i32 = 1;
/// The global "show window" shortcut (KeePass Ctrl+Alt+K).
const SHOW_ID: i32 = 2;
/// Posted to the hotkey thread when the setting changes.
const WM_REFRESH: u32 = WM_APP + 1;
pub const RELEASE_WAIT: Duration = Duration::from_secs(3);

pub const KEYS_HELD: &str = "Kısayol tuşları bırakılmadı; güvenlik için hiçbir şey yazılmadı.";

static THREAD: AtomicU32 = AtomicU32::new(0);
/// The shortcut registered right now (`Shortcut as u8`; Off = none).
static CURRENT: AtomicU8 = AtomicU8::new(Shortcut::Off as u8);
static REGISTERED: AtomicBool = AtomicBool::new(false);
/// The letter key of the registered shortcut, for `wait_for_release`.
static LETTER: AtomicU32 = AtomicU32::new(0);
/// The show-window shortcut registered right now (ShowShortcut as u8).
static SHOW_CURRENT: AtomicU8 = AtomicU8::new(ShowShortcut::Off as u8);
static SHOW_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Modifiers and letter of a show-window choice; None for Off.
pub fn show_keys(s: ShowShortcut) -> Option<(HOT_KEY_MODIFIERS, u32)> {
    match s {
        ShowShortcut::Off => None,
        ShowShortcut::CtrlAltK => Some((MOD_CONTROL | MOD_ALT, 0x4B)),
        ShowShortcut::CtrlAltShiftW => Some((MOD_CONTROL | MOD_ALT | MOD_SHIFT, 0x57)),
    }
}

/// Whether the show-window shortcut is registered right now.
pub fn show_active() -> bool {
    SHOW_REGISTERED.load(Ordering::Relaxed)
}

/// Registers the chosen show-window shortcut. Hotkey thread only.
fn apply_show() {
    let want = crate::settings::show_window_shortcut();
    if SHOW_REGISTERED.load(Ordering::Relaxed) && SHOW_CURRENT.load(Ordering::Relaxed) == want as u8
    {
        return;
    }
    if SHOW_REGISTERED.swap(false, Ordering::Relaxed) {
        // SAFETY: same thread and id as the registration.
        unsafe { UnregisterHotKey(std::ptr::null_mut(), SHOW_ID) };
    }
    SHOW_CURRENT.store(ShowShortcut::Off as u8, Ordering::Relaxed);
    if let Some((mods, vk)) = show_keys(want) {
        // SAFETY: null window = post WM_HOTKEY to this thread's queue.
        let ok =
            unsafe { RegisterHotKey(std::ptr::null_mut(), SHOW_ID, mods | MOD_NOREPEAT, vk) } != 0;
        if ok {
            SHOW_CURRENT.store(want as u8, Ordering::Relaxed);
        }
        SHOW_REGISTERED.store(ok, Ordering::Relaxed);
    }
}

/// Modifiers and letter of a choice; None for Off.
pub fn keys(s: Shortcut) -> Option<(HOT_KEY_MODIFIERS, u32)> {
    let cas = MOD_CONTROL | MOD_ALT | MOD_SHIFT;
    match s {
        Shortcut::Off => None,
        Shortcut::CtrlAltA => Some((MOD_CONTROL | MOD_ALT, 0x41)),
        Shortcut::CtrlAltShiftA => Some((cas, 0x41)),
        Shortcut::CtrlAltShiftK => Some((cas, 0x4B)),
        Shortcut::CtrlAltShiftL => Some((cas, 0x4C)),
    }
}

/// Whether the chosen shortcut is registered right now (false if turned
/// off, or if another program already owns that combination).
pub fn active() -> bool {
    REGISTERED.load(Ordering::Relaxed)
}

/// Registers the chosen shortcut, replacing the previous one. Hotkey thread
/// only: a thread-bound hotkey belongs to the thread that registered it.
fn apply() {
    let want = crate::settings::autotype_shortcut();
    let current = CURRENT.load(Ordering::Relaxed);
    if REGISTERED.load(Ordering::Relaxed) && current == want as u8 {
        return;
    }
    if REGISTERED.swap(false, Ordering::Relaxed) {
        // SAFETY: same thread and id as the registration.
        unsafe { UnregisterHotKey(std::ptr::null_mut(), HOTKEY_ID) };
    }
    CURRENT.store(Shortcut::Off as u8, Ordering::Relaxed);
    if let Some((mods, vk)) = keys(want) {
        // SAFETY: null window = post WM_HOTKEY to this thread's queue.
        let ok =
            unsafe { RegisterHotKey(std::ptr::null_mut(), HOTKEY_ID, mods | MOD_NOREPEAT, vk) }
                != 0;
        if ok {
            CURRENT.store(want as u8, Ordering::Relaxed);
            LETTER.store(vk, Ordering::Relaxed);
        }
        REGISTERED.store(ok, Ordering::Relaxed);
    }
}

/// Asks the hotkey thread to follow a changed setting.
pub fn refresh() {
    let t = THREAD.load(Ordering::Relaxed);
    if t != 0 {
        // SAFETY: posting a message with no pointers to a thread id.
        unsafe { PostThreadMessageW(t, WM_REFRESH, 0, 0) };
    }
}

/// Starts the hotkey thread. `on_hotkey` runs on that thread with the
/// window that was in front when the keys were pressed.
pub fn start(on_hotkey: impl Fn(HWND) + Send + 'static, on_show: impl Fn() + Send + 'static) {
    let spawned = std::thread::Builder::new()
        .name("lav-hotkey".into())
        .spawn(move || {
            let mut msg: MSG = unsafe { std::mem::zeroed() };
            // SAFETY: creates this thread's message queue before its id is
            // published, so that no posted message is lost.
            unsafe { PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_NOREMOVE) };
            // SAFETY: no preconditions.
            THREAD.store(unsafe { GetCurrentThreadId() }, Ordering::Relaxed);
            apply();
            apply_show();
            // SAFETY: standard message loop on the thread that owns the hotkey.
            while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
                match msg.message {
                    WM_HOTKEY if msg.wParam == HOTKEY_ID as usize => {
                        // SAFETY: no preconditions.
                        on_hotkey(unsafe { GetForegroundWindow() });
                    }
                    WM_HOTKEY if msg.wParam == SHOW_ID as usize => on_show(),
                    WM_REFRESH => {
                        apply();
                        apply_show();
                    }
                    _ => {}
                }
            }
        });
    if spawned.is_err() {
        eprintln!("LockAlperen: hotkey thread could not start");
    }
}

fn any_held(keys: &[u16]) -> bool {
    // SAFETY: no preconditions. The high bit means "down now".
    keys.iter()
        .any(|&k| unsafe { GetAsyncKeyState(i32::from(k)) } as u16 & 0x8000 != 0)
}

/// Waits until Ctrl, Alt, Shift, Windows and the shortcut's letter are up.
pub fn wait_for_release() -> Result<(), &'static str> {
    let letter = LETTER.load(Ordering::Relaxed) as u16;
    let keys = [VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN, VK_RWIN, letter];
    let start = Instant::now();
    while any_held(&keys) {
        if start.elapsed() > RELEASE_WAIT {
            return Err(KEYS_HELD);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Let the target process the key-up messages first.
    std::thread::sleep(Duration::from_millis(50));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_choice_but_off_has_distinct_keys() {
        let mut seen = Vec::new();
        for s in Shortcut::ALL {
            match keys(s) {
                None => assert_eq!(s, Shortcut::Off),
                Some(k) => {
                    assert!(k.0 & MOD_CONTROL != 0 && k.0 & MOD_ALT != 0, "{s:?}");
                    assert!(!seen.contains(&k), "{s:?} repeats another choice");
                    seen.push(k);
                }
            }
        }
        // The show-window keys never collide with an auto-type choice.
        for s in ShowShortcut::ALL {
            match show_keys(s) {
                None => assert_eq!(s, ShowShortcut::Off),
                Some(k) => assert!(!seen.contains(&k), "{s:?}"),
            }
        }
    }
}
