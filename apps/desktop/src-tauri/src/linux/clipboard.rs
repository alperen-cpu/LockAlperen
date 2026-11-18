//! Copying secrets to the clipboard on Linux (SECURITY.md, "Pano"). The
//! Windows twin is src/clipboard.rs; the public API is the same.
//!
//! - GTK owns the clipboard for us, on X11 and Wayland alike: the text is
//!   handed out from our memory only while we own the clipboard, and is
//!   never written to disk. The copy is wiped when GTK drops it.
//! - The `x-kde-passwordManagerHint` target says `secret`: the convention
//!   clipboard managers (Klipper, GPaste, CopyQ, ...) use to keep a value out
//!   of their history.
//! - Clearing happens only if we still own the clipboard: when anyone else
//!   copies something, GTK drops our data, so a later copy by the user is
//!   never wiped.
//!
//! Limits (documented): any program of the same user may read the clipboard
//! while the secret is on it, and a clipboard manager that ignores the hint
//! may keep a copy.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use gtk::{gdk, glib};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub struct ClipboardError;

/// Proof that we put something on the clipboard: the number of that copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Copied(u64);

static NEXT: AtomicU64 = AtomicU64::new(1);
/// The copy whose data the clipboard holds right now (0 = none of ours).
static OWNED: AtomicU64 = AtomicU64::new(0);

const HINT_TARGET: &str = "x-kde-passwordManagerHint";
const TEXT_TARGETS: [&str; 5] = [
    "UTF8_STRING",
    "text/plain;charset=utf-8",
    "text/plain",
    "STRING",
    "TEXT",
];
const TEXT_INFO: u32 = 0;
const HINT_INFO: u32 = 1;

/// Lives inside the data GTK holds; dropped when our data leaves the
/// clipboard (someone else copied, or we cleared it).
struct Owned(u64);

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = OWNED.compare_exchange(self.0, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// Runs `f` on the GTK main thread (GTK is not thread-safe) and waits for
/// its answer. Called on the main thread itself, it runs at once.
fn on_main<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    if gtk::is_initialized_main_thread() {
        return Some(f());
    }
    if !gtk::is_initialized() {
        return None;
    }
    let (tx, rx) = mpsc::channel();
    glib::idle_add_once(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(2)).ok()
}

/// Puts `text` on the clipboard, marked as a secret for clipboard managers.
pub fn copy_secret(text: &str) -> Result<Copied, ClipboardError> {
    let id = NEXT.fetch_add(1, Ordering::SeqCst);
    let text = Zeroizing::new(text.to_owned());
    let set = on_main(move || {
        let mut targets: Vec<gtk::TargetEntry> = TEXT_TARGETS
            .iter()
            .map(|t| gtk::TargetEntry::new(t, gtk::TargetFlags::empty(), TEXT_INFO))
            .collect();
        targets.push(gtk::TargetEntry::new(
            HINT_TARGET,
            gtk::TargetFlags::empty(),
            HINT_INFO,
        ));
        let owned = Owned(id);
        let clipboard = gtk::Clipboard::get(&gdk::SELECTION_CLIPBOARD);
        let ok = clipboard.set_with_data(&targets, move |_, data, info| {
            // Keeps `owned` alive exactly as long as GTK keeps the text.
            let _alive: &Owned = &owned;
            if info == HINT_INFO {
                data.set(&data.target(), 8, b"secret");
            } else {
                data.set_text(&text);
            }
        });
        if ok {
            OWNED.store(id, Ordering::SeqCst);
        }
        ok
    });
    match set {
        Some(true) => Ok(Copied(id)),
        _ => Err(ClipboardError),
    }
}

/// Empties the clipboard only if it still holds what `copied` put there.
/// Returns true if it was cleared.
pub fn clear_if_ours(copied: Copied) -> bool {
    if OWNED.load(Ordering::SeqCst) != copied.0 {
        return false;
    }
    on_main(move || {
        // Checked again on the GTK thread, where ownership cannot change
        // under us.
        if OWNED.load(Ordering::SeqCst) != copied.0 {
            return false;
        }
        gtk::Clipboard::get(&gdk::SELECTION_CLIPBOARD).clear();
        true
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_of_ours_is_never_cleared() {
        // No copy was made in this process: nothing to clear, and no GTK
        // call is made (the check happens before touching the clipboard).
        assert!(!clear_if_ours(Copied(u64::MAX)));
    }

    #[test]
    fn ownership_ends_when_the_data_is_dropped() {
        OWNED.store(42, Ordering::SeqCst);
        drop(Owned(41)); // an older copy's data: does not touch the current one
        assert_eq!(OWNED.load(Ordering::SeqCst), 42);
        drop(Owned(42));
        assert_eq!(OWNED.load(Ordering::SeqCst), 0);
    }
}
