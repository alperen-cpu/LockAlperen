//! Native confirmation dialogs, for actions the WebView must not be able to
//! approve on its own (an injected script could click any button in the page,
//! but not one in a dialog drawn by the system).

use std::sync::Mutex;

use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

/// One dialog at a time; a second request while one is open gets `None`.
static DIALOG: Mutex<()> = Mutex::new(());

/// Shows the main window, then asks over it. Blocks until answered, so call
/// it off the main thread. `None`: another dialog is already open.
pub fn ask(app: &AppHandle, title: &str, message: &str, yes: &str, no: &str) -> Option<bool> {
    let Ok(_one) = DIALOG.try_lock() else {
        return None;
    };
    crate::tray::show_main(app);
    let mut d = app
        .dialog()
        .message(message)
        .title(title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            yes.to_owned(),
            no.to_owned(),
        ));
    if let Some(w) = app.get_webview_window("main") {
        d = d.parent(&w);
    }
    Some(d.blocking_show())
}

/// [`ask`] from async code.
pub async fn ask_async(
    app: &AppHandle,
    title: String,
    message: String,
    yes: &'static str,
    no: &'static str,
) -> Option<bool> {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || ask(&app, &title, &message, yes, no))
        .await
        .ok()
        .flatten()
}
