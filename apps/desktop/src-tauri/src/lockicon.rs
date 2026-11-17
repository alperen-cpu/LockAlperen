//! Window and tray icon that show whether the vault is open (as in KeePass):
//! the normal icon while unlocked; the same icon with a red padlock badge
//! while locked or before a vault is opened.
//!
//! The badge is drawn here from the app's own icon (no extra image files).
//! A watcher polls the lock state, so every way of locking is covered: the
//! button, Ctrl+L, the tray, idle time, Win+L, sleep, logoff.

use std::time::Duration;

use tauri::image::Image;
use tauri::{AppHandle, Manager};

const POLL: Duration = Duration::from_millis(300);
const RED: [f32; 3] = [229.0, 72.0, 77.0];
const WHITE: [f32; 3] = [255.0, 255.0, 255.0];

/// Coverage of a shape over one pixel, from 4×4 samples (anti-aliasing).
fn coverage(px: u32, py: u32, inside: &impl Fn(f32, f32) -> bool) -> f32 {
    let mut hits = 0;
    for sy in 0..4 {
        for sx in 0..4 {
            let x = px as f32 + (sx as f32 + 0.5) / 4.0;
            let y = py as f32 + (sy as f32 + 0.5) / 4.0;
            if inside(x, y) {
                hits += 1;
            }
        }
    }
    hits as f32 / 16.0
}

/// "Over" blend of an opaque color with coverage `a` onto an RGBA pixel.
fn paint(px: &mut [u8], color: [f32; 3], a: f32) {
    if a <= 0.0 {
        return;
    }
    let da = px[3] as f32 / 255.0;
    let out_a = a + da * (1.0 - a);
    for i in 0..3 {
        let c = color[i] * a + px[i] as f32 * da * (1.0 - a);
        px[i] = (c / out_a).round().clamp(0.0, 255.0) as u8;
    }
    px[3] = (out_a * 255.0).round() as u8;
}

/// The icon with a red padlock badge over its bottom-right corner.
pub fn with_lock_badge(rgba: &[u8], w: u32, h: u32) -> Vec<u8> {
    let mut out = rgba.to_vec();
    let s = w.min(h) as f32;
    let r = s * 0.30; // badge radius
    let (cx, cy) = (w as f32 - r - s * 0.02, h as f32 - r - s * 0.02);
    draw_badge(&mut out, w, h, cx, cy, r);
    out
}

/// Only the badge, filling a transparent square: the taskbar overlay
/// (Windows draws it over the corner of the taskbar button).
pub fn lock_badge(size: u32) -> Vec<u8> {
    let mut out = vec![0u8; (size * size * 4) as usize];
    let s = size as f32;
    draw_badge(&mut out, size, size, s / 2.0, s / 2.0, s * 0.42);
    out
}

fn draw_badge(out: &mut [u8], w: u32, h: u32, cx: f32, cy: f32, r: f32) {
    // In badge units (u, v), v down, centred on the badge.
    let unit = |x: f32, y: f32| ((x - cx) / r, (y - cy) / r);
    let ring = |x: f32, y: f32| {
        let (u, v) = unit(x, y);
        u * u + v * v <= 1.12 * 1.12
    };
    let disc = |x: f32, y: f32| {
        let (u, v) = unit(x, y);
        u * u + v * v <= 1.0
    };
    let padlock = |x: f32, y: f32| {
        let (u, v) = unit(x, y);
        let body = u.abs() <= 0.46 && (-0.02..=0.56).contains(&v);
        let d = (u * u + (v + 0.02) * (v + 0.02)).sqrt();
        let shackle = v <= -0.02 && (0.17..=0.33).contains(&d);
        let legs = v > -0.02 && v < 0.05 && (0.17..=0.33).contains(&u.abs());
        body || shackle || legs
    };
    let x0 = (cx - r * 1.2).floor().max(0.0) as u32;
    let y0 = (cy - r * 1.2).floor().max(0.0) as u32;
    for py in y0..h {
        for px in x0..w {
            let i = ((py * w + px) * 4) as usize;
            let p = &mut out[i..i + 4];
            // A white rim keeps the badge readable on any icon colour.
            paint(p, WHITE, coverage(px, py, &ring));
            paint(p, RED, coverage(px, py, &disc));
            paint(p, WHITE, coverage(px, py, &padlock));
        }
    }
}

fn apply(app: &AppHandle, icon: &Image<'static>, overlay: &Image<'static>, unlocked: bool) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_icon(icon.clone());
        // The taskbar button shows the app's own icon (pinned or not), so
        // the lock is shown there as an overlay badge, as KeePass does.
        let _ = w.set_overlay_icon(if unlocked {
            None
        } else {
            Some(overlay.clone())
        });
    }
    if let Some(t) = app.tray_by_id("main") {
        let _ = t.set_icon(Some(icon.clone()));
        let tip = if unlocked {
            "LockAlperen: kasa açık"
        } else {
            "LockAlperen: kilitli"
        };
        let _ = t.set_tooltip(Some(tip));
    }
}

/// Starts the watcher. Call after the tray icon exists.
pub fn watch(app: &AppHandle, is_unlocked: impl Fn() -> bool + Send + 'static) {
    let Some(base) = app.default_window_icon().cloned() else {
        return;
    };
    let normal = base.clone().to_owned();
    let locked = Image::new_owned(
        with_lock_badge(base.rgba(), base.width(), base.height()),
        base.width(),
        base.height(),
    );
    let overlay = Image::new_owned(lock_badge(32), 32, 32);
    let app = app.clone();
    let spawned = std::thread::Builder::new()
        .name("lav-lockicon".into())
        .spawn(move || {
            let mut last = None;
            loop {
                let unlocked = is_unlocked();
                if last != Some(unlocked) {
                    let icon = if unlocked { &normal } else { &locked };
                    apply(&app, icon, &overlay, unlocked);
                    last = Some(unlocked);
                }
                std::thread::sleep(POLL);
            }
        });
    if spawned.is_err() {
        eprintln!("LockAlperen: lock icon watcher could not start");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(img: &[u8], w: u32, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * w + x) * 4) as usize;
        [img[i], img[i + 1], img[i + 2], img[i + 3]]
    }

    #[test]
    fn badge_is_red_with_a_white_padlock_and_leaves_the_rest() {
        let (w, h) = (64u32, 64u32);
        let base: Vec<u8> = [30u8, 60, 90, 255].repeat((w * h) as usize);
        let out = with_lock_badge(&base, w, h);
        assert_eq!(out.len(), base.len());
        let s = 64.0f32;
        let r = s * 0.30;
        let (cx, cy) = (s - r - s * 0.02, s - r - s * 0.02);
        // Top-left: the icon itself, untouched.
        assert_eq!(at(&out, w, 4, 4), [30, 60, 90, 255]);
        // Inside the disc, above the shackle: red.
        let red = at(&out, w, cx as u32, (cy - 0.7 * r) as u32);
        assert!(red[0] > 200 && red[1] < 110 && red[2] < 110, "{red:?}");
        // The padlock body: white.
        let white = at(&out, w, cx as u32, (cy + 0.3 * r) as u32);
        assert!(white.iter().all(|&c| c > 240), "{white:?}");
    }

    #[test]
    fn overlay_badge_fills_its_square() {
        let out = lock_badge(32);
        assert_eq!(out.len(), 32 * 32 * 4);
        assert_eq!(at(&out, 32, 0, 0)[3], 0, "corner stays transparent");
        let red = at(&out, 32, 16, 4);
        assert!(red[0] > 200 && red[1] < 110 && red[3] == 255, "{red:?}");
        let white = at(&out, 32, 16, 20);
        assert!(white.iter().all(|&c| c > 240), "{white:?}");
    }

    #[test]
    fn transparent_corners_become_an_opaque_badge() {
        let (w, h) = (32u32, 32u32);
        let out = with_lock_badge(&vec![0u8; (w * h * 4) as usize], w, h);
        assert_eq!(at(&out, w, 1, 1), [0, 0, 0, 0], "outside the badge");
        let r = 32.0f32 * 0.30;
        let c = (32.0 - r - 0.64) as u32;
        assert_eq!(at(&out, w, c, (c as f32 - 0.7 * r) as u32)[3], 255);
    }

    /// Writes the real app icon with and without the badge, at 128 px and
    /// at taskbar / tray size, for a person to look at:
    /// `LAV_ICON_PREVIEW=<dir> cargo test lock_badge_preview -- --ignored`
    #[test]
    #[ignore]
    fn lock_badge_preview() {
        let dir = std::path::PathBuf::from(std::env::var("LAV_ICON_PREVIEW").unwrap());
        let base = image::open("icons/128x128.png").unwrap().to_rgba8();
        let (w, h) = base.dimensions();
        let locked = with_lock_badge(base.as_raw(), w, h);
        let locked = image::RgbaImage::from_raw(w, h, locked).unwrap();
        locked.save(dir.join("locked-128.png")).unwrap();
        for size in [32u32, 16] {
            let small = image::imageops::resize(&base, size, size, image::imageops::Lanczos3);
            let badge = with_lock_badge(small.as_raw(), size, size);
            image::RgbaImage::from_raw(size, size, badge)
                .unwrap()
                .save(dir.join(format!("locked-{size}.png")))
                .unwrap();
            small.save(dir.join(format!("normal-{size}.png"))).unwrap();
        }
    }
}
