//! Browser extension integration (Chromium, fill only).
//!
//! - `origin.rs`: which entries belong to a page (exact origin).
//! - `conn.rs`: one connection (Noise XX, pairing code, requests).
//! - `store.rs`: `bridge.json` (on/off, app key, pairings, approvals).
//! - `linux.rs`: Unix socket, native host relay, browser manifests.
//!
//! Off by default (Settings › Tarayıcı eklentisi). The extension lives in
//! `apps/browser-extension`. Windows transport (named pipe + registry) is
//! not built yet: there the settings page says so.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod conn;
pub mod origin;
pub mod store;

#[cfg(target_os = "linux")]
pub mod linux;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use conn::{Credentials, Login, Refusal};
use origin::Origin;

/// The extension's id, pinned by the `key` in its manifest.json.
pub const EXTENSION_ID: &str = "lfhdblnhdfbfnkknmllnbndblidnlbed";

#[derive(Default)]
pub struct State {
    file: Option<PathBuf>,
    store: store::Store,
    listening: bool,
}

#[derive(Default, Clone)]
pub struct Bridge(Arc<Mutex<State>>);

impl Bridge {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> Option<T> {
        self.0.lock().ok().map(|mut g| f(&mut g))
    }

    pub fn load(&self, settings_file: &std::path::Path) {
        let file = store::path(settings_file);
        let s = store::load(&file);
        self.with(|st| {
            st.store = s;
            st.file = Some(file);
        });
    }

    fn save(st: &State) {
        if let Some(f) = &st.file {
            if store::save(f, &st.store).is_err() {
                eprintln!("LockAlperen: bridge.json could not be saved");
            }
        }
    }

    fn enabled(&self) -> bool {
        self.with(|st| st.store.enabled).unwrap_or(false)
    }
}

fn now() -> u64 {
    crate::recent::now()
}

/// Splits `"<tab>:<entry uuid>"`.
fn split_id(id: &str) -> Option<(usize, &str)> {
    let (tab, entry) = id.split_once(':')?;
    Some((tab.parse().ok()?, entry))
}

struct RealHost {
    app: AppHandle,
    bridge: Bridge,
}

impl RealHost {
    fn shared(&self) -> crate::Shared {
        self.app.state::<crate::Shared>().inner().clone()
    }

    /// The entry, if it is unlocked, not in the recycle bin and its site
    /// matches the page. Returns (title, username) for the dialog.
    fn check(&self, id: &str, page: &Origin) -> Result<(String, String), Refusal> {
        let (tab, entry) = split_id(id).ok_or(Refusal::NoMatch)?;
        self.shared()
            .tabs(|t| {
                let s = t.get(tab).ok_or(Refusal::NoMatch)?;
                if !s.is_unlocked() {
                    return Err(Refusal::Locked);
                }
                let e = s
                    .entries()
                    .map_err(|_| Refusal::Locked)?
                    .into_iter()
                    .find(|e| e.id == entry)
                    .ok_or(Refusal::NoMatch)?;
                let ok =
                    !e.in_recycle_bin && Origin::of_entry(&e.url).is_some_and(|o| o.fills(page));
                if ok {
                    Ok((e.title, e.username))
                } else {
                    Err(Refusal::NoMatch)
                }
            })
            .map_err(|_| Refusal::Locked)?
    }

    /// Asks once per (pairing, entry, site); remembers a yes.
    fn approve(&self, pair: &str, id: &str, page: &Origin, what: &str) -> Result<(), Refusal> {
        let (_, entry) = split_id(id).ok_or(Refusal::NoMatch)?;
        let site = page.serialize();
        if self
            .bridge
            .with(|st| st.store.allowed(pair, entry, &site))
            .unwrap_or(false)
        {
            return Ok(());
        }
        let (title, username) = self.check(id, page)?;
        let shown_user = if username.is_empty() {
            String::new()
        } else {
            format!(" ({})", short(&username))
        };
        let message = format!(
            "Tarayıcı eklentisi bu kaydın {what} istiyor:\n\n{}{}\n\nSite: {site}\n\n\
             İzin verirseniz bu kayıt bu sitede bir daha sorulmadan kullanılır \
             (Ayarlar › Tarayıcı eklentisi'nden eşleştirmeyi kaldırarak geri alınır).",
            short(&title),
            shown_user,
        );
        if !self.ask(
            "LockAlperen: tarayıcı isteği",
            &message,
            "İzin ver",
            "İptal",
        )? {
            return Err(Refusal::Denied);
        }
        self.bridge.with(|st| {
            st.store.allow(pair, entry, &site);
            Bridge::save(st);
        });
        Ok(())
    }

    /// A native dialog over the main window (brought forward first).
    fn ask(&self, title: &str, message: &str, yes: &str, no: &str) -> Result<bool, Refusal> {
        crate::confirm::ask(&self.app, title, message, yes, no).ok_or(Refusal::Busy)
    }
}

/// Long values are cut in the dialog (a page cannot make it unreadable).
fn short(s: &str) -> String {
    let clean: String = s.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() > 80 {
        format!("{}…", clean.chars().take(80).collect::<String>())
    } else {
        clean
    }
}

impl conn::Host for RealHost {
    fn enabled(&self) -> bool {
        self.bridge.enabled()
    }

    fn app_private_key(&self) -> Zeroizing<Vec<u8>> {
        self.bridge
            .with(|st| {
                let had = st.store.pairs.len();
                let k = st.store.app_private_key();
                if had == 0 {
                    Bridge::save(st);
                }
                k
            })
            .unwrap_or_default()
    }

    fn paired(&self, key: &[u8]) -> Option<String> {
        self.bridge.with(|st| {
            let id = st.store.find(key)?.id.clone();
            st.store.touch(&id, now());
            Bridge::save(st);
            Some(id)
        })?
    }

    fn still_paired(&self, id: &str) -> bool {
        self.bridge
            .with(|st| st.store.pairs.iter().any(|p| p.id == id))
            .unwrap_or(false)
    }

    fn confirm_pairing(&self, key: &[u8], code: &str) -> Result<String, Refusal> {
        let message = format!(
            "Bir tarayıcı eklentisi LockAlperen'e bağlanmak istiyor.\n\n\
             Eklentide görünen kod:\n\n        {code}\n\n\
             Kod aynıysa ve bu isteği siz başlattıysanız \"Eşleştir\"e basın. \
             Kod farklıysa ya da isteği siz başlatmadıysanız \"Reddet\"e basın.\n\n\
             Eklenti ana parolanızı hiçbir zaman sormaz; kasa yalnızca bu uygulamada açılır."
        );
        if !self.ask(
            "LockAlperen: tarayıcı eşleştirme",
            &message,
            "Eşleştir",
            "Reddet",
        )? {
            return Err(Refusal::Denied);
        }
        self.bridge
            .with(|st| {
                let r = st.store.add(key, now());
                if r.is_ok() {
                    Bridge::save(st);
                }
                r
            })
            .ok_or(Refusal::Denied)?
            .map_err(|_| Refusal::Denied)
    }

    fn locked(&self) -> bool {
        !self.shared().any_unlocked()
    }

    fn logins(&self, page: &Origin) -> Result<Vec<Login>, Refusal> {
        self.shared()
            .tabs(|t| {
                let mut out = Vec::new();
                let mut any = false;
                for (i, s) in t.all().enumerate() {
                    let Ok(list) = s.entries() else { continue };
                    any = true;
                    for e in list {
                        if !e.in_recycle_bin
                            && Origin::of_entry(&e.url).is_some_and(|o| o.fills(page))
                        {
                            out.push(Login {
                                id: format!("{i}:{}", e.id),
                                title: short(&e.title),
                                username: e.username,
                                has_totp: e.has_totp,
                            });
                        }
                    }
                }
                if any {
                    Ok(out)
                } else {
                    Err(Refusal::Locked)
                }
            })
            .map_err(|_| Refusal::Locked)?
    }

    fn credentials(&self, pair: &str, id: &str, page: &Origin) -> Result<Credentials, Refusal> {
        self.check(id, page)?;
        self.approve(pair, id, page, "kullanıcı adını ve parolasını doldurmak")?;
        let (tab, entry) = split_id(id).ok_or(Refusal::NoMatch)?;
        // Checked again: the vault may have changed while the dialog was open.
        self.check(id, page)?;
        self.shared()
            .tabs(|t| {
                let s = t.get(tab).ok_or(Refusal::NoMatch)?;
                Ok(Credentials {
                    username: s
                        .field(entry, crate::session::Field::Username)
                        .map_err(|_| Refusal::NoMatch)?,
                    password: s
                        .field(entry, crate::session::Field::Password)
                        .map_err(|_| Refusal::NoMatch)?,
                })
            })
            .map_err(|_| Refusal::Locked)?
    }

    fn totp(&self, pair: &str, id: &str, page: &Origin) -> Result<Zeroizing<String>, Refusal> {
        self.check(id, page)?;
        self.approve(pair, id, page, "tek kullanımlık kodunu (TOTP) almak")?;
        let (tab, entry) = split_id(id).ok_or(Refusal::NoMatch)?;
        self.check(id, page)?;
        self.shared()
            .tabs(|t| {
                let s = t.get(tab).ok_or(Refusal::NoMatch)?;
                s.field(entry, crate::session::Field::Totp)
                    .map_err(|_| Refusal::NoTotp)
            })
            .map_err(|_| Refusal::Locked)?
    }
}

/// Starts listening (Linux) if the integration is on. Idempotent.
pub fn start(app: &AppHandle) {
    let bridge = app.state::<Bridge>().inner().clone();
    if bridge.enabled() && !bridge.with(|st| st.listening).unwrap_or(true) {
        #[cfg(target_os = "linux")]
        listen(app, bridge);
    }
}

#[cfg(target_os = "linux")]
fn listen(app: &AppHandle, bridge: Bridge) {
    let Some(path) = linux::socket_path(&app.config().identifier) else {
        return;
    };
    let host = Arc::new(RealHost {
        app: app.clone(),
        bridge: bridge.clone(),
    });
    let r = linux::listen(&path, move |stream| {
        let _ = conn::serve(stream, host.as_ref());
    });
    match r {
        Ok(()) => {
            bridge.with(|st| st.listening = true);
        }
        Err(_) => eprintln!("LockAlperen: browser bridge could not listen"),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairView {
    id: String,
    created: u64,
    last_used: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// False on platforms without a transport yet (Windows).
    supported: bool,
    enabled: bool,
    extension_id: &'static str,
    /// Browsers whose native-messaging manifest is in place.
    browsers: Vec<String>,
    pairs: Vec<PairView>,
}

fn status(app: &AppHandle) -> Status {
    let bridge = app.state::<Bridge>();
    let (enabled, pairs) = bridge
        .with(|st| {
            (
                st.store.enabled,
                st.store
                    .pairs
                    .iter()
                    .map(|p| PairView {
                        id: p.id.clone(),
                        created: p.created,
                        last_used: p.last_used,
                    })
                    .collect(),
            )
        })
        .unwrap_or_default();
    #[cfg(target_os = "linux")]
    let (supported, browsers) = (true, linux::installed(&app.config().identifier));
    #[cfg(not(target_os = "linux"))]
    let (supported, browsers) = (false, Vec::new());
    Status {
        supported,
        enabled,
        extension_id: EXTENSION_ID,
        browsers,
        pairs,
    }
}

#[tauri::command]
pub fn bridge_status(app: AppHandle) -> Status {
    status(&app)
}

#[tauri::command]
pub fn bridge_set_enabled(app: AppHandle, on: bool) -> Result<Status, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (&app, on);
        Err("Tarayıcı eklentisi şimdilik yalnızca Linux'ta destekleniyor.".into())
    }
    #[cfg(target_os = "linux")]
    {
        let data = app
            .path()
            .app_local_data_dir()
            .map_err(|_| crate::INTERNAL.to_owned())?;
        let id = app.config().identifier.clone();
        if on {
            linux::install(&data, &id, EXTENSION_ID)?;
        } else {
            linux::uninstall(&data, &id);
        }
        app.state::<Bridge>().with(|st| {
            st.store.enabled = on;
            Bridge::save(st);
        });
        start(&app);
        Ok(status(&app))
    }
}

#[tauri::command]
pub fn bridge_revoke(app: AppHandle, id: String) -> Status {
    app.state::<Bridge>().with(|st| {
        if st.store.revoke(&id) {
            Bridge::save(st);
        }
    });
    status(&app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_short_text() {
        assert_eq!(split_id("2:abc-def"), Some((2, "abc-def")));
        assert_eq!(split_id("x:abc"), None);
        assert_eq!(split_id("abc"), None);
        assert_eq!(short("a\nb"), "ab");
        assert_eq!(short(&"x".repeat(100)).chars().count(), 81);
    }
}
