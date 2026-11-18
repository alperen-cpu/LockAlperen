//! LockAlperen desktop shell. The WebView only renders; every decision and
//! every secret stays on the Rust side (`session`).

mod autolock;
mod autotype;
mod browser;
mod clipboard;
mod export;
mod hardening;
mod health;
mod hotkey;
mod import;
mod lockicon;
mod recent;
mod session;
mod settings;
mod startup;
mod titlebar;
mod totp;
mod tray;
mod update;

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

/// Where settings.json lives (set at startup).
#[derive(Default, Clone)]
struct SettingsFile(Arc<Mutex<Option<std::path::PathBuf>>>);

/// The app, for threads started before Tauri (idle lock) and for locking
/// paths that have no window at hand.
static APP: std::sync::OnceLock<AppHandle> = std::sync::OnceLock::new();

fn main_window() -> Option<tauri::WebviewWindow> {
    use tauri::Manager;
    APP.get()?.get_webview_window("main")
}

/// Until this time (ms since the Unix epoch) a minimize is our own (auto-type,
/// "minimize after copy") and must not lock the vault.
static QUIET_MINIMIZE_UNTIL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Minimizes without triggering "lock when minimized".
fn minimize_quietly(window: &tauri::WebviewWindow) {
    QUIET_MINIMIZE_UNTIL.store(now_ms() + 1500, std::sync::atomic::Ordering::Relaxed);
    let _ = window.minimize();
}

#[tauri::command]
fn get_settings() -> settings::Settings {
    // The Run key is the truth for "start with Windows".
    settings::Settings {
        run_at_startup: startup::enabled(),
        ..settings::current()
    }
}

/// Applies at once (the auto-lock thread reads it every second) and saves.
#[tauri::command]
fn set_settings(
    value: settings::Settings,
    file: State<'_, SettingsFile>,
    window: tauri::WebviewWindow,
) -> Result<settings::Settings, String> {
    let mut value = value.sanitized();
    if value.run_at_startup != startup::enabled() {
        if let Err(e) = startup::set(value.run_at_startup) {
            value.run_at_startup = startup::enabled();
            settings::apply(value);
            return Err(e.to_owned());
        }
    }
    settings::apply(value);
    hotkey::refresh();
    let _ = window.set_always_on_top(value.always_on_top);
    if let Some(path) = file.0.lock().ok().and_then(|g| g.clone()) {
        settings::save(&path, value).map_err(|_| "Ayarlar kaydedilemedi.".to_owned())?;
    }
    Ok(value)
}

/// Colours the native title bar like the app (Windows 11; ignored on 10).
#[tauri::command]
fn set_titlebar(dark: bool, window: tauri::WebviewWindow) {
    if let Ok(hwnd) = window.hwnd() {
        titlebar::paint(hwnd.0 as _, dark);
    }
}

/// Whether the global auto-type shortcut is registered (Settings shows a
/// warning if it is on but another program owns Ctrl+Alt+A).
#[tauri::command]
fn hotkey_active() -> HotkeyStatus {
    HotkeyStatus {
        autotype: hotkey::active(),
        show_window: hotkey::show_active(),
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HotkeyStatus {
    autotype: bool,
    show_window: bool,
}

/// A message for the UI from outside a command (the auto-type shortcut),
/// shown once: `lock_status` hands it over.
#[derive(Default, Clone)]
struct Notice(Arc<Mutex<Option<String>>>);

impl Notice {
    fn set(&self, text: impl Into<String>) {
        if let Ok(mut g) = self.0.lock() {
            *g = Some(text.into());
        }
    }
    fn take(&self) -> Option<String> {
        self.0.lock().ok().and_then(|mut g| g.take())
    }
}

/// Ctrl+Alt+A (src/hotkey.rs), on the hotkey thread. Types into `target`
/// only if exactly one entry matches its title, after the keys are released
/// and while it is still the foreground window.
fn on_autotype_hotkey(app: &AppHandle, target: windows_sys::Win32::Foundation::HWND) {
    use tauri::Manager;
    if target.is_null() || autotype::pid_of(target) == std::process::id() {
        return;
    }
    let (shared, notice) = (app.state::<Shared>(), app.state::<Notice>());
    let title = autotype::window_title(target);
    let found = match shared.with(|s| s.autotype_matches(&title)) {
        Ok(Ok(found)) => found,
        // Locked: bring the window forward to unlock; nothing is typed.
        _ => return tray::show_main(app),
    };
    let tell = |text: String| {
        notice.set(text);
        tray::show_main(app);
    };
    let id = match found.as_slice() {
        [(id, _)] => id.clone(),
        [] => {
            return tell(format!(
                "\"{title}\" penceresine uyan kayıt yok; hiçbir şey yazılmadı."
            ))
        }
        many => {
            let names: Vec<&str> = many.iter().take(5).map(|(_, t)| t.as_str()).collect();
            return tell(format!(
                "{} kayıt bu pencereye uyuyor ({}); hiçbir şey yazılmadı. Kaydı seçip \"Otomatik yaz\" düğmesini kullanın.",
                many.len(),
                names.join(", ")
            ));
        }
    };
    let typed = (|| -> Result<(), String> {
        let (steps, _) = shared.with(|s| s.autotype_data(&id)).and_then(|r| r)?;
        hotkey::wait_for_release()?;
        autotype::type_into(target, &steps)?;
        Ok(())
    })();
    if let Err(e) = typed {
        tell(e);
    }
}

/// The running version, shown in Settings.
#[tauri::command]
fn app_version(app: AppHandle) -> String {
    app.package_info().version.to_string()
}

/// Asks the release endpoint whether a newer, installable version exists.
/// Only the version and notes go to the WebView; the update stays here.
#[tauri::command]
async fn check_update(app: AppHandle) -> Result<Option<update::Available>, String> {
    update::check(&app).await
}

/// Installs the update found by the last check. The vault is locked (and our
/// clipboard value cleared) once the installer has been verified; on success
/// the app exits and the installer restarts it, so this returns only errors.
#[tauri::command]
async fn install_update(
    app: AppHandle,
    state: State<'_, Shared>,
    last: State<'_, LastCopy>,
) -> Result<(), String> {
    let (shared, last) = (state.inner().clone(), last.inner().clone());
    update::install(&app, move || lock_all(&shared, &last)).await
}

/// Opens the entry's web site in the default browser. The WebView sends only
/// the entry id; Rust reads the address and opens nothing but http(s).
#[tauri::command]
fn open_url(id: String, state: State<'_, Shared>) -> Result<(), String> {
    let u = state.with(|s| s.web_address(&id)).and_then(|r| r)?;
    browser::open(&u).map_err(str::to_owned)
}

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

async fn pick_path(
    app: AppHandle,
    save_name: Option<String>,
    title: &'static str,
) -> Result<Option<std::path::PathBuf>, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let d = app.dialog().file().set_title(title);
        match save_name {
            Some(n) => d.set_file_name(&n).blocking_save_file(),
            None => d.blocking_pick_file(),
        }
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?;
    match picked {
        None => Ok(None),
        Some(p) => p.into_path().map(Some).map_err(|_| INTERNAL.to_owned()),
    }
}

/// Runs a session change off the main thread and returns the new list.
async fn change_and_list(
    state: &Shared,
    f: impl FnOnce(&mut Session) -> Result<(), String> + Send + 'static,
) -> Result<Vec<EntrySummary>, String> {
    let shared = state.clone();
    tauri::async_runtime::spawn_blocking(move || {
        shared
            .with(|s| {
                f(s)?;
                s.entries()
            })
            .and_then(|r| r)
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?
}

#[tauri::command]
async fn add_group(
    parent: Option<String>,
    name: String,
    state: State<'_, Shared>,
) -> Result<String, String> {
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        shared
            .with(|s| s.add_group(parent.as_deref(), &name))
            .and_then(|r| r)
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?
}

#[tauri::command]
async fn rename_group(
    id: String,
    name: String,
    state: State<'_, Shared>,
) -> Result<Vec<EntrySummary>, String> {
    change_and_list(&state, move |s| s.rename_group(&id, &name)).await
}

#[tauri::command]
async fn set_group_icon(
    id: String,
    icon: Option<String>,
    state: State<'_, Shared>,
) -> Result<Vec<EntrySummary>, String> {
    change_and_list(&state, move |s| s.set_group_icon(&id, icon.as_deref())).await
}

#[tauri::command]
async fn move_group(
    id: String,
    parent: Option<String>,
    state: State<'_, Shared>,
) -> Result<Vec<EntrySummary>, String> {
    change_and_list(&state, move |s| s.move_group(&id, parent.as_deref())).await
}

#[tauri::command]
async fn move_entry(
    id: String,
    group: String,
    state: State<'_, Shared>,
) -> Result<Vec<EntrySummary>, String> {
    change_and_list(&state, move |s| s.move_entry(&id, &group)).await
}

/// KeePass "Duplicate Entry": a copy in the same folder, without history.
#[tauri::command]
async fn duplicate_entry(id: String, state: State<'_, Shared>) -> Result<Saved, String> {
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        shared
            .with(|s| {
                let id = s.duplicate_entry(&id)?;
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

#[tauri::command]
async fn delete_group(id: String, state: State<'_, Shared>) -> Result<Vec<EntrySummary>, String> {
    change_and_list(&state, move |s| s.delete_group(&id).map(|_| ())).await
}

/// Deletes everything in the recycle bin for good (the UI asks twice).
#[tauri::command]
async fn empty_recycle_bin(state: State<'_, Shared>) -> Result<Vec<EntrySummary>, String> {
    change_and_list(&state, move |s| s.empty_recycle_bin().map(|_| ())).await
}

#[tauri::command]
async fn restore_version(
    id: String,
    index: usize,
    state: State<'_, Shared>,
) -> Result<Vec<EntrySummary>, String> {
    change_and_list(&state, move |s| s.restore_version(&id, index)).await
}

/// File picker in Rust; the file is read and stored encrypted in the vault.
#[tauri::command]
async fn add_attachment(
    id: String,
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<bool, String> {
    let Some(path) = pick_path(app, None, "Eklenecek dosyayı seç").await? else {
        return Ok(false);
    };
    change_and_list(&state, move |s| s.add_attachment(&id, &path)).await?;
    Ok(true)
}

#[tauri::command]
async fn remove_attachment(
    id: String,
    index: usize,
    state: State<'_, Shared>,
) -> Result<(), String> {
    change_and_list(&state, move |s| s.remove_attachment(&id, index)).await?;
    Ok(())
}

#[tauri::command]
async fn change_master(
    current: String,
    new: String,
    confirm: String,
    state: State<'_, Shared>,
) -> Result<(), String> {
    let (current, new, confirm) = (
        Zeroizing::new(current),
        Zeroizing::new(new),
        Zeroizing::new(confirm),
    );
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        shared
            .with(|s| s.change_master(&current, &new, &confirm))
            .and_then(|r| r)
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?
}

/// Re-checks the master password, then writes a PLAIN-TEXT CSV where the
/// user chooses. Returns false if the save dialog was cancelled.
#[tauri::command]
async fn export_csv(
    current: String,
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<bool, String> {
    let current = Zeroizing::new(current);
    let shared = state.inner().clone();
    let csv = tauri::async_runtime::spawn_blocking(move || {
        shared.with(|s| s.export_csv(&current)).and_then(|r| r)
    })
    .await
    .map_err(|_| INTERNAL.to_owned())??;
    let Some(path) = pick_path(
        app,
        Some("LockAlperen-disa-aktarim.csv".into()),
        "Dışa aktarılacak yer",
    )
    .await?
    else {
        return Ok(false);
    };
    // UTF-8 BOM so spreadsheet apps read Turkish characters correctly.
    let mut bytes = Zeroizing::new(Vec::with_capacity(csv.len() + 3));
    bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    bytes.extend_from_slice(csv.as_bytes());
    std::fs::write(&path, bytes.as_slice()).map_err(|_| "Dosya yazılamadı.".to_owned())?;
    Ok(true)
}

/// Runs a session call off the main thread (KDF work, file I/O).
async fn blocking<T: Send + 'static>(
    state: &Shared,
    f: impl FnOnce(&mut Session) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let shared = state.clone();
    tauri::async_runtime::spawn_blocking(move || shared.with(f).and_then(|r| r))
        .await
        .map_err(|_| INTERNAL.to_owned())?
}

/// Ids of entries whose notes or custom fields contain the query.
#[tauri::command]
fn search_hidden(
    query: String,
    scope: session::SearchScope,
    state: State<'_, Shared>,
) -> Result<Vec<String>, String> {
    let query = Zeroizing::new(query);
    state
        .with(|s| s.search_hidden(&query, scope))
        .and_then(|r| r)
}

fn profiles_file(file: &SettingsFile) -> Option<std::path::PathBuf> {
    file.0
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .map(|p| p.with_file_name("generator-profiles.json"))
}

#[tauri::command]
fn get_gen_profiles(file: State<'_, SettingsFile>) -> Vec<settings::GenProfile> {
    profiles_file(&file)
        .map(|p| settings::load_profiles(&p))
        .unwrap_or_default()
}

#[tauri::command]
fn set_gen_profiles(
    list: Vec<settings::GenProfile>,
    file: State<'_, SettingsFile>,
) -> Result<Vec<settings::GenProfile>, String> {
    let list = settings::sanitize_profiles(list);
    if let Some(p) = profiles_file(&file) {
        settings::save_profiles(&p, &list).map_err(|_| "Profiller kaydedilemedi.".to_owned())?;
    }
    Ok(list)
}

#[tauri::command]
fn vault_settings(state: State<'_, Shared>) -> Result<session::VaultSettings, String> {
    state.with(|s| s.vault_settings()).and_then(|r| r)
}

#[tauri::command]
async fn set_vault_settings(
    name: String,
    description: String,
    history_limit: u32,
    state: State<'_, Shared>,
) -> Result<Vec<EntrySummary>, String> {
    change_and_list(&state, move |s| {
        s.set_vault_settings(&name, &description, history_limit)
    })
    .await
}

#[tauri::command]
async fn clear_history(
    older_than_days: Option<u32>,
    state: State<'_, Shared>,
) -> Result<usize, String> {
    blocking(&state, move |s| s.clear_history(older_than_days)).await
}

#[tauri::command]
async fn change_kdf(
    current: String,
    memory_mib: u32,
    iterations: u32,
    parallelism: u32,
    state: State<'_, Shared>,
) -> Result<(), String> {
    let current = Zeroizing::new(current);
    blocking(&state, move |s| {
        s.change_kdf(&current, memory_mib, iterations, parallelism)
    })
    .await
}

/// Picks (create = false) or creates (create = true) the key file to switch
/// to. The path stays in Rust; the file name is returned.
#[tauri::command]
async fn pick_new_keyfile(
    create: bool,
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<Option<String>, String> {
    if create {
        let Some(path) = pick_path(
            app,
            Some("LockAlperen.key".into()),
            "Yeni anahtar dosyasının kaydedileceği yer",
        )
        .await?
        else {
            return Ok(None);
        };
        state
            .with(|s| s.create_keyfile(path))
            .and_then(|r| r)
            .map(Some)
    } else {
        let Some(path) = pick_path(app, None, "Anahtar dosyası seç").await? else {
            return Ok(None);
        };
        state.with(|s| s.set_pending_keyfile(Some(path)))
    }
}

#[tauri::command]
async fn change_keyfile(
    current: String,
    use_pending: bool,
    state: State<'_, Shared>,
) -> Result<(), String> {
    let current = Zeroizing::new(current);
    blocking(&state, move |s| s.change_keyfile(&current, use_pending)).await
}

#[tauri::command]
async fn pick_merge_file(
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<Option<String>, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Birleştirilecek kasa")
            .add_filter("LockAlperen kasası", &["lav"])
            .blocking_pick_file()
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|_| INTERNAL.to_owned())?;
    state.with(|s| s.set_merge_path(path)).map(Some)
}

#[tauri::command]
async fn pick_merge_keyfile(
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<Option<String>, String> {
    let Some(path) = pick_path(app, None, "Diğer kasanın anahtar dosyası").await? else {
        return Ok(None);
    };
    state.with(|s| s.set_merge_keyfile(Some(path)))
}

#[derive(serde::Serialize)]
struct Merged {
    summary: session::MergeSummary,
    entries: Vec<EntrySummary>,
}

#[tauri::command]
async fn merge_vault(password: String, state: State<'_, Shared>) -> Result<Merged, String> {
    let password = Zeroizing::new(password);
    blocking(&state, move |s| {
        let summary = s.merge(&password)?;
        Ok(Merged {
            summary,
            entries: s.entries()?,
        })
    })
    .await
}

/// Re-checks the master password, then writes the vault as a KeePass file
/// with its own password. Returns false if the save dialog was cancelled.
#[tauri::command]
async fn export_kdbx(
    current: String,
    kdbx_password: String,
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<bool, String> {
    let (current, kdbx_password) = (Zeroizing::new(current), Zeroizing::new(kdbx_password));
    let bytes = blocking(&state, move |s| s.export_kdbx(&current, &kdbx_password)).await?;
    let Some(path) = pick_path(
        app,
        Some("LockAlperen.kdbx".into()),
        "KeePass dosyasının yeri",
    )
    .await?
    else {
        return Ok(false);
    };
    std::fs::write(&path, bytes.as_slice()).map_err(|_| "Dosya yazılamadı.".to_owned())?;
    Ok(true)
}

/// Re-checks the master password, then writes a PLAIN-TEXT printable page.
#[tauri::command]
async fn export_html(
    current: String,
    include_passwords: bool,
    generated: String,
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<bool, String> {
    let current = Zeroizing::new(current);
    let page = blocking(&state, move |s| {
        s.export_html(&current, include_passwords, &generated)
    })
    .await?;
    let Some(path) = pick_path(
        app,
        Some("LockAlperen-yazdir.html".into()),
        "Yazdırılabilir sayfanın yeri",
    )
    .await?
    else {
        return Ok(false);
    };
    std::fs::write(&path, page.as_bytes()).map_err(|_| "Dosya yazılamadı.".to_owned())?;
    Ok(true)
}

#[tauri::command]
async fn pick_import_keyfile(
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<Option<String>, String> {
    let Some(path) = pick_path(app, None, "KeePass anahtar dosyası").await? else {
        return Ok(None);
    };
    state.with(|s| s.set_import_keyfile(Some(path)))
}

#[derive(serde::Serialize)]
struct IconsResult {
    fetched: usize,
    failed: usize,
    /// Entries still waiting; the UI calls again until this is 0.
    remaining: usize,
    entries: Vec<EntrySummary>,
}

/// Entry ids already tried in this run, so a site without an icon is not
/// contacted again on every unlock or save.
static ICON_TRIED: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(Default::default);

/// Icons fetched at the same time per call.
const ICON_BATCH: usize = 12;

/// Downloads missing site icons automatically (after unlock and save), one
/// batch per call, the batch in parallel, saved once per batch so icons
/// appear as they arrive. Each icon goes through lav-favicon: direct to the
/// site (no third-party service), public addresses only, size/time limits,
/// re-encoded PNG.
#[tauri::command]
async fn fetch_icons(state: State<'_, Shared>) -> Result<IconsResult, String> {
    let mut todo = state
        .with(|s| s.missing_icons(usize::MAX))
        .and_then(|r| r)?;
    if let Ok(tried) = ICON_TRIED.lock() {
        todo.retain(|(id, _)| !tried.contains(id));
    }
    let remaining = todo.len().saturating_sub(ICON_BATCH);
    todo.truncate(ICON_BATCH);
    if let Ok(mut tried) = ICON_TRIED.lock() {
        tried.extend(todo.iter().map(|(id, _)| id.clone()));
    }
    let handles: Vec<_> = todo
        .into_iter()
        .map(|(id, url)| {
            tauri::async_runtime::spawn(async move {
                let opts = lav_favicon::Options::default();
                (id, lav_favicon::fetch(&url, &opts).await)
            })
        })
        .collect();
    let (mut got, mut failed) = (Vec::new(), 0usize);
    for h in handles {
        match h.await {
            Ok((id, Ok(icon))) => got.push((id, icon.png)),
            _ => failed += 1,
        }
    }
    let fetched = got.len();
    let entries = change_and_list(&state, move |s| s.set_icons(got)).await?;
    Ok(IconsResult {
        fetched,
        failed,
        remaining,
        entries,
    })
}

/// Minimizes the app and finds the target window, verifies it, then types
/// username, Tab, password, Enter. If the entry has a web site, the site is
/// opened in the default browser first (a new tab) and the page that loads
/// is the target; otherwise the user switches to the target window.
#[tauri::command]
async fn auto_type(
    id: String,
    window: tauri::WebviewWindow,
    state: State<'_, Shared>,
) -> Result<(), String> {
    let (steps, target) = state.with(|s| s.autotype_data(&id)).and_then(|r| r)?;
    if matches!(&target, autotype::Target::Markers(m) if m.is_empty()) {
        return Err("Bu kaydın başlığı ya da web sitesi yok; hedef pencere doğrulanamaz.".into());
    }
    let site = state.with(|s| s.web_address(&id).ok())?;
    minimize_quietly(&window);
    if let Some(u) = &site {
        browser::open(u).map_err(str::to_owned)?;
    }
    tauri::async_runtime::spawn_blocking(move || {
        let window = if site.is_some() {
            autotype::wait_for_opened_site(&target)?
        } else {
            autotype::wait_for_target(&target)?
        };
        autotype::type_into(window, &steps)
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?
    .map_err(str::to_owned)
}

#[tauri::command]
fn entry_extras(id: String, state: State<'_, Shared>) -> Result<session::EntryExtras, String> {
    state.with(|s| s.extras(&id)).and_then(|r| r)
}

/// Notes or a custom field value, only on an explicit "show" click.
#[tauri::command]
fn reveal_extra(
    id: String,
    what: session::Extra,
    state: State<'_, Shared>,
) -> Result<String, String> {
    state
        .with(|s| s.extra(&id, what))
        .and_then(|r| r)
        .map(|v| v.as_str().to_owned())
}

/// Copies notes or a custom field in Rust (same clipboard rules as passwords).
#[tauri::command]
async fn copy_extra(
    id: String,
    what: session::Extra,
    state: State<'_, Shared>,
    last: State<'_, LastCopy>,
    window: tauri::WebviewWindow,
) -> Result<u64, String> {
    let value = state.with(|s| s.extra(&id, what)).and_then(|r| r)?;
    let secs = copy_and_schedule_clear(&value, &last)?;
    after_copy(&window);
    Ok(secs)
}

/// KeePass "Drop to background after copying data to the clipboard".
fn after_copy(window: &tauri::WebviewWindow) {
    if settings::minimize_after_copy() {
        minimize_quietly(window);
    }
}

/// Writes an attachment where the user chooses (Rust save dialog). The file
/// on disk is NOT encrypted; the UI says so.
#[tauri::command]
async fn save_attachment(
    id: String,
    index: usize,
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<bool, String> {
    let (name, bytes) = state.with(|s| s.attachment(&id, index)).and_then(|r| r)?;
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_file_name(&name)
            .blocking_save_file()
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?;
    let Some(picked) = picked else {
        return Ok(false);
    };
    let path = picked.into_path().map_err(|_| INTERNAL.to_owned())?;
    std::fs::write(&path, bytes.as_slice()).map_err(|_| "Dosya yazılamadı.".to_owned())?;
    Ok(true)
}

/// Key file picker (Rust; the path stays here). Returns the file name.
#[tauri::command]
async fn pick_keyfile(app: AppHandle, state: State<'_, Shared>) -> Result<Option<String>, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Anahtar dosyası seç")
            .blocking_pick_file()
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|_| INTERNAL.to_owned())?;
    state.with(|s| s.set_keyfile(Some(path)))
}

#[tauri::command]
fn clear_keyfile(state: State<'_, Shared>) -> Result<(), String> {
    state.with(|s| {
        s.set_keyfile(None);
    })
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

/// File picker for a KeePass database (from Rust; the path stays here).
#[tauri::command]
async fn pick_kdbx_file(
    app: AppHandle,
    state: State<'_, Shared>,
) -> Result<Option<String>, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("KeePass veritabanı", &["kdbx"])
            .blocking_pick_file()
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|_| INTERNAL.to_owned())?;
    state.with(|s| s.select_import(path)).map(Some)
}

#[derive(serde::Serialize)]
struct Imported {
    summary: import::Summary,
    entries: Vec<EntrySummary>,
}

/// Decrypts the KeePass file (its KDF runs off the main thread) and adds it
/// to the open vault.
#[tauri::command]
async fn import_kdbx(password: String, state: State<'_, Shared>) -> Result<Imported, String> {
    let password = Zeroizing::new(password);
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        shared
            .with(|s| {
                let summary = s.import_keepass(&password)?;
                Ok(Imported {
                    summary,
                    entries: s.entries()?,
                })
            })
            .and_then(|r| r)
    })
    .await
    .map_err(|_| INTERNAL.to_owned())?
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
    window: tauri::WebviewWindow,
) -> Result<u64, String> {
    let value = state.with(|s| s.field(&id, field)).and_then(|r| r)?;
    let secs = copy_and_schedule_clear(&value, &last)?;
    after_copy(&window);
    Ok(secs)
}

/// Puts `value` on the clipboard (marked private) and clears it after the
/// chosen time (Settings, 5-90 s) if it is still ours.
fn copy_and_schedule_clear(value: &str, last: &LastCopy) -> Result<u64, String> {
    let copied = clipboard::copy_secret(value).map_err(|_| "Panoya kopyalanamadı.".to_owned())?;
    if let Ok(mut g) = last.0.lock() {
        *g = Some(copied);
    }
    let last = last.clone();
    let secs = u64::from(settings::clipboard_seconds());
    tauri::async_runtime::spawn(async move {
        tokio_sleep(Duration::from_secs(secs)).await;
        clipboard::clear_if_ours(copied);
        if let Ok(mut g) = last.0.lock() {
            if *g == Some(copied) {
                *g = None;
            }
        }
    });
    Ok(secs)
}

/// Locks the vault and clears our clipboard content. Used by the button,
/// Ctrl+L, idle timeout and Windows session/power events alike.
fn lock_all(shared: &Shared, last: &LastCopy) {
    last.clear();
    let was_open = shared.with(|s| s.is_unlocked()).unwrap_or(false);
    let _ = shared.with(Session::lock);
    // KeePass "Minimize main window after locking the workspace".
    if was_open && settings::minimize_on_lock() {
        if let Some(w) = main_window() {
            if w.is_visible().unwrap_or(false) {
                let _ = w.minimize();
            }
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LockStatus {
    unlocked: bool,
    /// Seconds until the idle lock (system-wide input resets it).
    lock_in_secs: u64,
    /// One-off message from the auto-type shortcut, if any.
    notice: Option<String>,
}

/// Polled by the UI for the countdown and to notice an automatic lock.
#[tauri::command]
fn lock_status(state: State<'_, Shared>, notice: State<'_, Notice>) -> Result<LockStatus, String> {
    Ok(LockStatus {
        unlocked: state.with(|s| s.is_unlocked())?,
        lock_in_secs: autolock::seconds_left(autolock::system_idle(), autolock::idle_timeout()),
        notice: notice.take(),
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
        // Win+L, sleep, disconnect, logoff: lock unless the owner turned it
        // off in Settings (default on). Idle locking is separate and stays.
        let on_event = move |_reason| {
            if settings::lock_on_system_events() {
                lock_all(&shared, &last)
            }
        };
        if autolock::watch(on_event).is_none() {
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
                // KeePass "Exit instead of locking the workspace after the
                // specified time": locked first, then the app quits.
                if settings::exit_instead_of_lock() {
                    if let Some(app) = APP.get() {
                        app.exit(0);
                    }
                }
            }
        })
        .expect("idle thread");
}

pub fn run() {
    // Before anything else loads a DLL or holds a secret.
    if !hardening::restrict_dll_search() {
        eprintln!("LockAlperen: SetDefaultDllDirectories failed");
    }
    if !hardening::protect_process() {
        eprintln!("LockAlperen: process DACL could not be set");
    }
    let shared = Shared::default();
    let last = LastCopy::default();
    start_autolock(shared.clone(), last.clone());
    tauri::Builder::default()
        // First, so that a second start exits before doing anything else.
        // Its arguments are ignored: it only brings this window forward.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main(app)
        }))
        .plugin(tauri_plugin_dialog::init())
        // Its own JS commands are not granted to the WebView (capabilities);
        // only ours below (check_update, install_update) are.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(
            tauri::plugin::Builder::<tauri::Wry>::new("navigation-guard")
                .on_navigation(|_, url| navigation_allowed(url))
                .build(),
        )
        .manage(shared)
        .manage(last)
        .manage(Recent::default())
        .manage(SettingsFile::default())
        .manage(update::Pending::default())
        .manage(Notice::default())
        .on_window_event(|window, event| {
            // The close button hides the window to the tray (if enabled and
            // the tray icon exists); "Kilitle ve çık" in the tray quits.
            if window.label() != "main" {
                return;
            }
            use tauri::Manager;
            let lock_now = |w: &tauri::Window| {
                let app = w.app_handle();
                lock_all(&app.state::<Shared>(), &app.state::<LastCopy>());
            };
            match event {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    if settings::close_to_tray() && tray::can_hide() {
                        api.prevent_close();
                        let _ = window.hide();
                        // Hiding to the tray counts as minimizing (KeePass).
                        if settings::lock_on_minimize() {
                            lock_now(window);
                        }
                    }
                }
                tauri::WindowEvent::Resized(_) if window.is_minimized().unwrap_or(false) => {
                    let ours =
                        now_ms() < QUIET_MINIMIZE_UNTIL.load(std::sync::atomic::Ordering::Relaxed);
                    // KeePass "Lock workspace when minimizing main window".
                    if settings::lock_on_minimize() && !ours {
                        lock_now(window);
                    }
                    // KeePass "Minimize to tray instead of taskbar".
                    if settings::minimize_to_tray() && tray::can_hide() && !ours {
                        let _ = window.hide();
                    }
                }
                _ => {}
            }
        })
        .setup(|app| {
            use tauri::Manager;
            // Keep the window out of screenshots and screen sharing. Debug
            // builds may opt out with LAV_ALLOW_CAPTURE=1 (for UI testing).
            let allow = cfg!(debug_assertions) && std::env::var_os("LAV_ALLOW_CAPTURE").is_some();
            if !allow {
                if let Some(w) = app.get_webview_window("main") {
                    if let Ok(hwnd) = w.hwnd() {
                        let r = hardening::exclude_from_capture(hwnd.0 as _);
                        if r == hardening::Capture::Failed {
                            eprintln!("LockAlperen: window could not be excluded from capture");
                        }
                    }
                }
            }
            if let Ok(dir) = app.path().app_local_data_dir() {
                let sfile = dir.join("settings.json");
                settings::apply(settings::load(&sfile));
                if let Ok(mut g) = app.state::<SettingsFile>().0.lock() {
                    *g = Some(sfile);
                }
                let file = dir.join("recent.json");
                let list = recent::load(&file);
                if let Ok(mut g) = app.state::<Recent>().0.lock() {
                    *g = (Some(file), list);
                }
            }
            let _ = APP.set(app.handle().clone());
            {
                let handle = app.handle().clone();
                let show = app.handle().clone();
                hotkey::start(
                    move |target| on_autotype_hotkey(&handle, target),
                    move || tray::show_main(&show),
                );
            }
            if tray::create(app.handle()).is_err() {
                eprintln!("LockAlperen: tray icon could not be created");
            }
            if let Some(w) = app.get_webview_window("main") {
                let s = settings::current();
                let _ = w.set_always_on_top(s.always_on_top);
                // KeePass "Start minimized and locked" (it always starts locked).
                if s.start_minimized {
                    if s.minimize_to_tray && tray::can_hide() {
                        let _ = w.hide();
                    } else {
                        minimize_quietly(&w);
                    }
                }
            }
            // Red padlock on the window and tray icon while locked.
            {
                let shared = app.state::<Shared>().inner().clone();
                lockicon::watch(app.handle(), move || {
                    shared.with(|s| s.is_unlocked()).unwrap_or(false)
                });
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
            duplicate_entry,
            generate_password,
            totp_code,
            password_health,
            pick_kdbx_file,
            import_kdbx,
            pick_keyfile,
            clear_keyfile,
            entry_extras,
            reveal_extra,
            copy_extra,
            save_attachment,
            get_settings,
            set_settings,
            add_group,
            rename_group,
            delete_group,
            empty_recycle_bin,
            restore_version,
            add_attachment,
            remove_attachment,
            change_master,
            export_csv,
            pick_import_keyfile,
            fetch_icons,
            auto_type,
            open_url,
            move_group,
            move_entry,
            set_group_icon,
            set_titlebar,
            hotkey_active,
            app_version,
            check_update,
            install_update,
            search_hidden,
            get_gen_profiles,
            set_gen_profiles,
            vault_settings,
            set_vault_settings,
            clear_history,
            change_kdf,
            pick_new_keyfile,
            change_keyfile,
            pick_merge_file,
            pick_merge_keyfile,
            merge_vault,
            export_kdbx,
            export_html,
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
