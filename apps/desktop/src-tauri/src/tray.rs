//! System tray icon. Closing the window can hide it here (Settings, default
//! on) so that the app keeps running; locking rules do not change: idle,
//! Win+L, sleep and session end still lock a hidden window's vault.
//!
//! If the tray icon cannot be created, the window is never hidden on close
//! (there would be no way back to it except starting the app again).

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

static TRAY_READY: AtomicBool = AtomicBool::new(false);

/// Whether a close request may hide the window instead of quitting.
pub fn can_hide() -> bool {
    TRAY_READY.load(Ordering::Relaxed)
}

/// Brings the main window back: from the tray, or when the app is started a
/// second time.
pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn lock_and(app: &AppHandle, then_quit: bool) {
    crate::lock_all(
        &app.state::<crate::Shared>(),
        &app.state::<crate::LastCopy>(),
    );
    if then_quit {
        app.exit(0);
    }
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "LockAlperen'i göster", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Kilitle", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Kilitle ve çık", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &lock, &sep, &quit])?;

    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("LockAlperen")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main(app),
            "lock" => lock_and(app, false),
            "quit" => lock_and(app, true),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    TRAY_READY.store(true, Ordering::Relaxed);
    Ok(())
}
