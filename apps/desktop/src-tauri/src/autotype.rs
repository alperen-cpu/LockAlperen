//! Auto-type (SECURITY.md "Otomatik yazma"): types username, Tab, password,
//! Enter into another window ONLY after that window is verified.
//!
//! Verification: the target is the window the user switches to within
//! WAIT, it must belong to another process, and its title must contain the
//! entry's title or the URL's host. Typing stops at once if the foreground
//! window changes. Limit: a window title can be chosen by any program, so
//! this protects against typing into the WRONG window by mistake, not
//! against a malicious program imitating the right one.
#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    VIRTUAL_KEY, VK_RETURN, VK_TAB,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
};

pub const WAIT: Duration = Duration::from_secs(10);

pub const NO_TARGET: &str = "10 saniye içinde başka bir pencereye geçilmedi; hiçbir şey yazılmadı.";
pub const WRONG_TARGET: &str = "Hedef pencerenin başlığı bu kaydın adını ya da sitesini \
     içermiyor; güvenlik için hiçbir şey yazılmadı.";
pub const INTERRUPTED: &str = "Yazarken pencere değişti; yazma durduruldu.";

pub enum Step<'a> {
    Text(&'a str),
    Tab,
    Enter,
}

/// Lowercased words the target title must contain one of.
pub fn expected_markers(title: &str, url: &str) -> Vec<String> {
    let mut out = Vec::new();
    let t = title.trim().to_lowercase();
    if t.chars().count() >= 3 {
        out.push(t);
    }
    let host = url::Url::parse(url.trim())
        .ok()
        .or_else(|| url::Url::parse(&format!("https://{}", url.trim())).ok())
        .and_then(|u| u.host_str().map(str::to_lowercase));
    if let Some(h) = host {
        let h = h.strip_prefix("www.").unwrap_or(&h).to_owned();
        // "github.com" -> also accept "github" (browsers show page titles).
        if let Some(first) = h.split('.').next() {
            if first.chars().count() >= 3 {
                out.push(first.to_owned());
            }
        }
        if h.chars().count() >= 3 {
            out.push(h);
        }
    }
    out
}

pub fn title_matches(window_title: &str, markers: &[String]) -> bool {
    let w = window_title.to_lowercase();
    !markers.is_empty() && markers.iter().any(|m| w.contains(m.as_str()))
}

pub fn window_title(h: HWND) -> String {
    let mut buf = [0u16; 512];
    // SAFETY: buffer and its length are passed together.
    let n = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

pub fn pid_of(h: HWND) -> u32 {
    let mut pid = 0u32;
    // SAFETY: valid out-pointer.
    unsafe { GetWindowThreadProcessId(h, &mut pid) };
    pid
}

/// Waits for the user to switch to another program's window and verifies
/// it. Returns that window.
pub fn wait_for_target(markers: &[String]) -> Result<HWND, &'static str> {
    let me = std::process::id();
    let start = Instant::now();
    while start.elapsed() < WAIT {
        // SAFETY: no preconditions.
        let fg = unsafe { GetForegroundWindow() };
        if !fg.is_null() && pid_of(fg) != me {
            // Give the window a moment to settle (title of a new tab etc.).
            std::thread::sleep(Duration::from_millis(400));
            // SAFETY: no preconditions.
            if unsafe { GetForegroundWindow() } != fg {
                continue;
            }
            return if title_matches(&window_title(fg), markers) {
                Ok(fg)
            } else {
                Err(WRONG_TARGET)
            };
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(NO_TARGET)
}

fn key(vk: VIRTUAL_KEY, scan: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send(inputs: &[INPUT]) {
    // SAFETY: slice pointer and length passed together; INPUT size given.
    unsafe {
        SendInput(
            inputs.len() as u32,
            inputs.as_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        )
    };
}

/// Types the steps into `target`, checking before every key that it is
/// still the foreground window.
pub fn type_into(target: HWND, steps: &[Step]) -> Result<(), &'static str> {
    let still = || unsafe { GetForegroundWindow() } == target;
    for step in steps {
        match step {
            Step::Text(s) => {
                for unit in s.encode_utf16() {
                    if !still() {
                        return Err(INTERRUPTED);
                    }
                    send(&[
                        key(0, unit, KEYEVENTF_UNICODE),
                        key(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
                    ]);
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Step::Tab | Step::Enter => {
                if !still() {
                    return Err(INTERRUPTED);
                }
                let vk = if matches!(step, Step::Tab) {
                    VK_TAB
                } else {
                    VK_RETURN
                };
                send(&[key(vk, 0, 0), key(vk, 0, KEYEVENTF_KEYUP)]);
                std::thread::sleep(Duration::from_millis(30));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_from_title_and_url() {
        let m = expected_markers("GitHub", "https://www.github.com/login");
        assert!(m.contains(&"github".to_owned()));
        assert!(m.contains(&"github.com".to_owned()));
        assert_eq!(
            expected_markers("ab", ""),
            Vec::<String>::new(),
            "too short"
        );
        assert!(expected_markers("", "mail.example.com").contains(&"mail.example.com".to_owned()));
    }

    #[test]
    fn title_check() {
        let m = expected_markers("GitHub", "https://github.com");
        assert!(title_matches(
            "Sign in to GitHub · GitHub - Microsoft Edge",
            &m
        ));
        assert!(!title_matches("Banka Giriş - Google Chrome", &m));
        assert!(!title_matches("anything", &[]), "no markers: never type");
    }
}
