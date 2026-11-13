//! LockAlperen desktop shell. The WebView only renders; every decision and
//! every secret stays on the Rust side (`session`).

mod autolock;
mod clipboard;
mod health;
mod recent;
mod session;
mod totp;

use std::sync::{Arc, Mutex};

use std::time::Duration;

use session::{
    EntryForm, EntrySummary, Field, GenOptions, GroupView, SelectedFile, Session, TotpCode,
    VaultInfo,
};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

const INTERNAL: &str = "Beklenmeyen bir hata oluştu.";

/// "Son kasalar": the list and the file it lives in (set at startup).
#[derive(Default, Clone)]
struct Recent(Arc<Mutex<(Option<std::path::PathBuf>, Vec<recent::Item>)>>);

impl Recent {
    fn views(&self) -> Vec<recent::View> {
        self.0
            .lock()
            .map(|g| g.1.iter().map(recent::View::from).collect())
            .unwrap_or_default()
    }

    fn path(&self, index: usize) -> Option<std::path::PathBuf> {
        self.0.lock().ok()?.1.get(index).map(|i| i.path.clone())
    }

    fn update(&self, f: impl FnOnce(&mut Vec<recent::Item>)) {
        if let Ok(mut g) = self.0.lock() {
            f(&mut g.1);
            if let Some(file) = g.0.clone() {
                // Best effort: losing the list must never break unlocking.
                let _ = recent::save(&file, &g.1);
            }
        }
    }

    /// Records the session's open vault, if any. Takes the session lock
    /// first and releases it before touching the list (no nested locks).
    fn record(&self, shared: &Shared) {
        if let Ok(Some(path)) = shared.with(|s| s.open_path()) {
            self.update(|l| recent::touch(l, &path, recent::now()));
        }
    }
}

/// How long a copied secret stays on the clipboard.
const CLIPBOARD_SECONDS: u64 = 12;

#[derive(Default, Clone)]
struct Shared(Arc<Mutex<Session>>);

/// The last thing we put on the clipboard, so that locking can clear it.
#[derive(Default, Clone)]
struct LastCopy(Arc<Mutex<Option<clipboard::Copied>>>);

impl LastCopy {
    fn clear(&self) {
        if let Some(c) = self.0.lock().ok().and_then(|mut g| g.take()) {
            clipboard::clear_if_ours(c);
        }
    }
}

impl Shared {
    fn with<T>(&self, f: impl FnOnce(&mut Session) -> T) -> Result<T, String> {
        let mut guard = self.0.lock().map_err(|_| INTERNAL.to_owned())?;
        Ok(f(&mut guard))
    }
}

/// Shows the native file picker (from Rust, so the WebView gets no dialog or
/// file-system permission) and remembers the choice. Returns what the unlock
/// screen displays; the path itself is never sent back by the WebView.
#[tauri::command]
async fn pick_vault_file(
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<Option<SelectedFile>, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("LockAlperen kasası", &["lav"])
            .blocking_pick_file()
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|_| INTERNAL.to_owned())?;
    state.with(|s| s.select(path)).map(Some)
}

/// Save dialog for a new vault (from Rust, like the open dialog). Returns
/// the file name to display; the path stays in Rust.
#[tauri::command]
async fn pick_new_vault_path(
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<Option<String>, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("LockAlperen kasası", &["lav"])
            .set_file_name("Kasa.lav")
            .blocking_save_file()
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|_| INTERNAL.to_owned())?;
    state.with(|s| s.select_new(path)).map(Some)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Created {
    file: SelectedFile,
    info: VaultInfo,
}

#[tauri::command]
async fn create_vault(
    name: String,
    password: String,
    confirm: String,
    state: State<'_, Shared>,
    recent: State<'_, Recent>,
) -> Result<Created, String> {
    let (password, confirm) = (Zeroizing::new(password), Zeroizing::new(confirm));
    let shared = state.inner().clone();
    let created = tauri::async_runtime::spawn_blocking(move || {
        shared.with(|s| s.create(&name, &password, &confirm))
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?
    .and_then(|r| r)
    .map(|(file, info)| Created { file, info })?;
    recent.record(&state);
    Ok(created)
}

#[tauri::command]
fn list_groups(state: State<'_, Shared>) -> Result<Vec<GroupView>, String> {
    state.with(|s| s.groups()).and_then(|r| r)
}

/// Sends an entry's secrets to the WebView: only when the editor opens.
#[tauri::command]
fn entry_form(id: String, state: State<'_, Shared>) -> Result<EntryForm, String> {
    state.with(|s| s.entry_form(&id)).and_then(|r| r)
}

/// Saves (add or update) and returns the new list and the entry's id.
#[tauri::command]
async fn save_entry(form: EntryForm, state: State<'_, Shared>) -> Result<Saved, String> {
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        shared
            .with(|s| {
                let id = s.save_entry(&form)?;
                Ok(Saved {
                    id,
                    entries: s.entries()?,
                })
            })
            .and_then(|r| r)
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?
}

#[derive(serde::Serialize)]
struct Saved {
    id: String,
    entries: Vec<EntrySummary>,
}

#[tauri::command]
async fn delete_entry(id: String, state: State<'_, Shared>) -> Result<Vec<EntrySummary>, String> {
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        shared
            .with(|s| {
                s.delete_entry(&id)?;
                s.entries()
            })
            .and_then(|r| r)
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?
}

/// Counts and per-entry labels only; never a password.
#[tauri::command]
fn password_health(state: State<'_, Shared>) -> Result<health::Report, String> {
    state
        .with(|s| s.health(recent::now() as i64))
        .and_then(|r| r)
}

/// The current code and its countdown; the TOTP secret stays in Rust.
#[tauri::command]
fn totp_code(id: String, state: State<'_, Shared>) -> Result<TotpCode, String> {
    state
        .with(|s| s.totp_at(&id, recent::now()))
        .and_then(|r| r)
}

#[tauri::command]
fn generate_password(options: GenOptions) -> Result<String, String> {
    session::generate(&options).map(|p| p.as_str().to_owned())
}

#[tauri::command]
fn recent_vaults(recent: State<'_, Recent>) -> Vec<recent::View> {
    recent.views()
}

/// Selects a vault from "Son kasalar" by its position; Rust holds the path.
#[tauri::command]
fn select_recent(
    index: usize,
    state: State<'_, Shared>,
    recent: State<'_, Recent>,
) -> Result<SelectedFile, String> {
    let path = recent.path(index).ok_or(INTERNAL)?;
    state.with(|s| s.select(path))
}

#[tauri::command]
fn forget_recent(index: usize, recent: State<'_, Recent>) -> Vec<recent::View> {
    recent.update(|l| recent::remove(l, index));
    recent.views()
}

/// Argon2id takes about a second, so it runs off the main thread.
#[tauri::command]
async fn unlock(
    password: String,
    state: State<'_, Shared>,
    recent: State<'_, Recent>,
) -> Result<VaultInfo, String> {
    let password = Zeroizing::new(password);
    let shared = state.inner().clone();
    let info = tauri::async_runtime::spawn_blocking(move || shared.with(|s| s.unlock(&password)))
        .await
        .map_err(|_| INTERNAL.to_owned())?
        .and_then(|r| r)?;
    recent.record(&state);
    Ok(info)
}

#[tauri::command]
fn lock(state: State<'_, Shared>, last: State<'_, LastCopy>) -> Result<(), String> {
    lock_all(&state, &last);
    Ok(())
}

/// Copies a field in Rust: the value never passes through the WebView.
/// Returns the number of seconds until the clipboard is cleared.
#[tauri::command]
async fn copy_field(
    id: String,
    field: Field,
    state: State<'_, Shared>,
    last: State<'_, LastCopy>,
) -> Result<u64, String> {
    let value = state.with(|s| s.field(&id, field)).and_then(|r| r)?;
    let copied = clipboard::copy_secret(&value).map_err(|_| "Panoya kopyalanamadı.".to_owned())?;
    drop(value);
    if let Ok(mut g) = last.0.lock() {
        *g = Some(copied);
    }
    let last = last.inner().clone();
    tauri::async_runtime::spawn(async move {
        tokio_sleep(Duration::from_secs(CLIPBOARD_SECONDS)).await;
        clipboard::clear_if_ours(copied);
        if let Ok(mut g) = last.0.lock() {
            if *g == Some(copied) {
                *g = None;
            }
        }
    });
    Ok(CLIPBOARD_SECONDS)
}

/// Locks the vault and clears our clipboard content. Used by the button,
/// Ctrl+L, idle timeout and Windows session/power events alike.
fn lock_all(shared: &Shared, last: &LastCopy) {
    last.clear();
    let _ = shared.with(Session::lock);
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LockStatus {
    unlocked: bool,
    /// Seconds until the idle lock (system-wide input resets it).
    lock_in_secs: u64,
}

/// Polled by the UI for the countdown and to notice an automatic lock.
#[tauri::command]
fn lock_status(state: State<'_, Shared>) -> Result<LockStatus, String> {
    Ok(LockStatus {
        unlocked: state.with(|s| s.is_unlocked())?,
        lock_in_secs: autolock::seconds_left(autolock::system_idle(), autolock::idle_timeout()),
    })
}

/// Sends the password to the WebView for display. Only on an explicit
/// "show" click; the UI hides it again after a few seconds.
#[tauri::command]
fn reveal_password(id: String, state: State<'_, Shared>) -> Result<String, String> {
    state
        .with(|s| s.field(&id, Field::Password))
        .and_then(|r| r)
        .map(|v| v.as_str().to_owned())
}

async fn tokio_sleep(d: Duration) {
    // Tauri's runtime is tokio; a blocking sleep on a worker would stall it.
    let _ = tauri::async_runtime::spawn_blocking(move || std::thread::sleep(d)).await;
}

#[tauri::command]
fn list_entries(state: State<'_, Shared>) -> Result<Vec<EntrySummary>, String> {
    state.with(|s| s.entries()).and_then(|r| r)
}

/// Pages the WebView may show: the bundled app, plus the Vite dev server in
/// debug builds. Everything else (remote sites, `file:`) is refused.
fn navigation_allowed(url: &tauri::Url) -> bool {
    let bundled = url.scheme() == "tauri" || url.host_str() == Some("tauri.localhost");
    let dev = cfg!(debug_assertions)
        && url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port() == Some(5173);
    bundled || dev
}

/// Starts the Windows session/power watcher and the idle check.
fn start_autolock(shared: Shared, last: LastCopy) {
    {
        let (shared, last) = (shared.clone(), last.clone());
        // If the watcher cannot start, idle locking still works; the failure
        // is not hidden from developers.
        if autolock::watch(move |_reason| lock_all(&shared, &last)).is_none() {
            eprintln!("LockAlperen: session/power watcher could not start");
        }
    }
    std::thread::Builder::new()
        .name("lav-idle".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            let unlocked = shared.with(|s| s.is_unlocked()).unwrap_or(false);
            if unlocked && autolock::system_idle() >= autolock::idle_timeout() {
                lock_all(&shared, &last);
            }
        })
        .expect("idle thread");
}

pub fn run() {
    let shared = Shared::default();
    let last = LastCopy::default();
    start_autolock(shared.clone(), last.clone());
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri::plugin::Builder::<tauri::Wry>::new("navigation-guard")
                .on_navigation(|_, url| navigation_allowed(url))
                .build(),
        )
        .manage(shared)
        .manage(last)
        .manage(Recent::default())
        .setup(|app| {
            use tauri::Manager;
            if let Ok(dir) = app.path().app_local_data_dir() {
                let file = dir.join("recent.json");
                let list = recent::load(&file);
                if let Ok(mut g) = app.state::<Recent>().0.lock() {
                    *g = (Some(file), list);
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pick_vault_file,
            unlock,
            lock,
            list_entries,
            copy_field,
            reveal_password,
            lock_status,
            pick_new_vault_path,
            create_vault,
            recent_vaults,
            select_recent,
            forget_recent,
            list_groups,
            entry_form,
            save_entry,
            delete_entry,
            generate_password,
            totp_code,
            password_health
        ])
        .run(tauri::generate_context!())
        .expect("error while running LockAlperen");
}

#[cfg(test)]
mod tests {
    use super::navigation_allowed;

    fn ok(s: &str) -> bool {
        navigation_allowed(&s.parse().unwrap())
    }

    #[test]
    fn only_the_app_itself_can_be_shown() {
        assert!(ok("http://tauri.localhost/index.html"));
        assert!(ok("tauri://localhost/"));
        assert!(!ok("https://example.com/"));
        assert!(!ok("http://tauri.localhost.evil.com/"));
        assert!(!ok("file:///C:/Windows/win.ini"));
        assert!(!ok("http://127.0.0.1:8080/"));
    }
}
