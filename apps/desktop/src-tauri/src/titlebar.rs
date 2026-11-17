//! Native title bar in the app's colours (Windows 11: DWM caption and text
//! colour; Windows 10 ignores these attributes, which is harmless). The
//! system minimise / maximise / close buttons and Snap layouts stay.
#![allow(unsafe_code)]

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;

// DWMWINDOWATTRIBUTE values (dwmapi.h).
const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
const DWMWA_CAPTION_COLOR: u32 = 35;
const DWMWA_TEXT_COLOR: u32 = 36;

/// COLORREF is 0x00BBGGRR.
const fn colorref(rgb: u32) -> u32 {
    ((rgb & 0xff) << 16) | (rgb & 0xff00) | ((rgb >> 16) & 0xff)
}

/// --bg and --fg of styles.css for the theme in use.
pub fn colors(dark: bool) -> (u32, u32) {
    if dark {
        (colorref(0x0f1115), colorref(0xe8eaed))
    } else {
        (colorref(0xf4f5f7), colorref(0x15181e))
    }
}

fn set(hwnd: HWND, attr: u32, value: u32) {
    // SAFETY: a valid window handle and a 4-byte value with its size.
    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            attr,
            (&value as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
        );
    }
}

pub fn paint(hwnd: HWND, dark: bool) {
    let (caption, text) = colors(dark);
    set(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, u32::from(dark));
    set(hwnd, DWMWA_CAPTION_COLOR, caption);
    set(hwnd, DWMWA_TEXT_COLOR, text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_are_bgr() {
        assert_eq!(colorref(0x112233), 0x332211);
        assert_eq!(colors(false).0, 0xf7f5f4);
        assert_eq!(colors(true).0, 0x15110f);
    }
}
