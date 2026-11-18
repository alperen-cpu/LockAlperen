//! Global shortcuts (auto-type, show window) on Linux: not available yet.
//! The Windows twin is src/hotkey.rs.
//!
//! Wayland, Ubuntu's default session, gives no program a system-wide key
//! grab; the desktop portal for it (GlobalShortcuts) is new and not on every
//! supported Ubuntu. Settings hides the shortcut choices on Linux, and the
//! status below reports them as not registered.

/// Whether the auto-type shortcut is registered: never on Linux.
pub fn active() -> bool {
    false
}

/// Whether the show-window shortcut is registered: never on Linux.
pub fn show_active() -> bool {
    false
}

/// Follows a changed setting: nothing to follow on Linux.
pub fn refresh() {}
