//! LockAlperen desktop shell. The WebView only renders; every decision and
//! every secret stays on the Rust side (`session`).

mod session;

use std::sync::{Arc, Mutex};

use session::{EntrySummary, SelectedFile, Session, VaultInfo};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

const INTERNAL: &str = "Beklenmeyen bir hata oluştu.";

#[derive(Default, Clone)]
struct Shared(Arc<Mutex<Session>>);

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

/// Argon2id takes about a second, so it runs off the main thread.
#[tauri::command]
async fn unlock(password: String, state: State<'_, Shared>) -> Result<VaultInfo, String> {
    let password = Zeroizing::new(password);
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || shared.with(|s| s.unlock(&password)))
        .await
        .map_err(|_| INTERNAL.to_owned())?
        .and_then(|r| r)
}

#[tauri::command]
fn lock(state: State<'_, Shared>) -> Result<(), String> {
    state.with(Session::lock)
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

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri::plugin::Builder::<tauri::Wry>::new("navigation-guard")
                .on_navigation(|_, url| navigation_allowed(url))
                .build(),
        )
        .manage(Shared::default())
        .invoke_handler(tauri::generate_handler![
            pick_vault_file,
            unlock,
            lock,
            list_entries
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
