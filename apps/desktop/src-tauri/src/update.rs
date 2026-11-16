//! Self-update from this repository's GitHub Releases (docs/UPDATES.md).
//!
//! What has to hold before anything is installed:
//! - `latest.json` is fetched over HTTPS only (the plugin refuses `http`).
//! - The announced version is newer than this one (no downgrades).
//! - The installer's minisign signature verifies against the public key built
//!   into the app (`plugins.updater.pubkey` in tauri.conf.json), and the
//!   signature names exactly the announced version (`requireSignedVersion`),
//!   so a tampered `latest.json` cannot pair a new number with an old build.
//!   The plugin checks this on the downloaded bytes before writing or running
//!   anything.
//! - Ours, on top: the download URL must be a release asset of this repo, and
//!   nothing goes to the network while no release key is configured.
//!
//! Installing locks the vault and clears our clipboard value first; on
//! Windows the plugin then starts the NSIS installer and exits the process.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::{AppHandle, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

/// Release assets must come from here (and the endpoint in tauri.conf.json
/// points here too). Change both together if releases move.
const RELEASE_HOST: &str = "github.com";
const RELEASE_PATH: &str = "/alperen-cpu/LockAlperen/releases/download/";

const CHECK_TIMEOUT: Duration = Duration::from_secs(20);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

pub const NOT_CONFIGURED: &str = "Bu sürümde güncelleme anahtarı yok; güncellemeler denetlenemez.";
const CHECK_FAILED: &str = "Güncelleme denetlenemedi. İnternet bağlantınızı kontrol edin.";
const BAD_SOURCE: &str = "Güncelleme beklenmeyen bir adresten geliyor; kurulmadı.";
const BAD_SIGNATURE: &str = "Güncelleme doğrulanamadı (imza geçersiz); kurulmadı.";
const INSTALL_FAILED: &str = "Güncelleme kurulamadı.";
const NOTHING_PENDING: &str = "Önce güncellemeleri denetleyin.";

/// The update found by the last check, kept on the Rust side: the WebView
/// can only ask to install "the one you found", never name a URL.
#[derive(Default, Clone)]
pub struct Pending(Arc<Mutex<Option<Update>>>);

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Available {
    pub version: String,
    /// Release notes from `latest.json`; shown as plain text.
    pub notes: Option<String>,
}

/// True for `https://github.com/alperen-cpu/LockAlperen/releases/download/...`
/// and nothing else (no other host, port, user info or repository).
pub fn download_url_allowed(url: &tauri::Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(RELEASE_HOST)
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path().starts_with(RELEASE_PATH)
        && url.path().len() > RELEASE_PATH.len()
}

/// A minisign public key is base64 of a two-line text; the placeholder
/// shipped before the owner generates a key is empty.
pub fn key_configured(pubkey: &str) -> bool {
    !pubkey.trim().is_empty()
}

fn configured_pubkey(app: &AppHandle) -> String {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|u| u.get("pubkey"))
        .and_then(|k| k.as_str())
        .unwrap_or_default()
        .to_owned()
}

fn message(e: &tauri_plugin_updater::Error) -> &'static str {
    use tauri_plugin_updater::Error as E;
    match e {
        E::Minisign(_) | E::SignedVersionMismatch { .. } | E::MissingSignedVersion => BAD_SIGNATURE,
        _ => INSTALL_FAILED,
    }
}

pub async fn check(app: &AppHandle) -> Result<Option<Available>, String> {
    if !key_configured(&configured_pubkey(app)) {
        return Err(NOT_CONFIGURED.to_owned());
    }
    let updater = app
        .updater_builder()
        .timeout(CHECK_TIMEOUT)
        .build()
        .map_err(|_| CHECK_FAILED.to_owned())?;
    let found = updater.check().await.map_err(|_| CHECK_FAILED.to_owned())?;
    let pending = app.state::<Pending>();
    let mut slot = pending.0.lock().map_err(|_| crate::INTERNAL.to_owned())?;
    *slot = None;
    let Some(mut update) = found else {
        return Ok(None);
    };
    if !download_url_allowed(&update.download_url) {
        return Err(BAD_SOURCE.to_owned());
    }
    update.timeout = Some(DOWNLOAD_TIMEOUT);
    let available = Available {
        version: update.version.clone(),
        notes: update.body.clone(),
    };
    *slot = Some(update);
    Ok(Some(available))
}

/// Downloads, verifies and starts the installer. `before_install` runs only
/// after the signature has been verified, right before the process exits.
/// Returns only on failure.
pub async fn install(app: &AppHandle, before_install: impl FnOnce()) -> Result<(), String> {
    let update = app
        .state::<Pending>()
        .0
        .lock()
        .map_err(|_| crate::INTERNAL.to_owned())?
        .take()
        .ok_or_else(|| NOTHING_PENDING.to_owned())?;
    // Checked again here: the slot is only ever filled by `check`, but the
    // cost is nothing and the property is the one that matters.
    if !download_url_allowed(&update.download_url) {
        return Err(BAD_SOURCE.to_owned());
    }
    // `download` verifies the signature (and the signed version) of the
    // bytes; `install` verifies them again before running anything.
    let bytes = update
        .download(|_, _| {}, || {})
        .await
        .map_err(|e| message(&e).to_owned())?;
    before_install();
    update.install(bytes).map_err(|e| message(&e).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> bool {
        download_url_allowed(&s.parse().unwrap())
    }

    #[test]
    fn only_this_repos_release_assets_are_downloaded() {
        assert!(ok(
            "https://github.com/alperen-cpu/LockAlperen/releases/download/v0.2.0/LockAlperen_0.2.0_x64-setup.exe"
        ));
        // Plain HTTP, other hosts, look-alike hosts, user info, ports.
        assert!(!ok(
            "http://github.com/alperen-cpu/LockAlperen/releases/download/v0.2.0/a.exe"
        ));
        assert!(!ok(
            "https://github.com.evil.com/alperen-cpu/LockAlperen/releases/download/v0.2.0/a.exe"
        ));
        assert!(!ok(
            "https://github.com@evil.com/alperen-cpu/LockAlperen/releases/download/v0.2.0/a.exe"
        ));
        assert!(!ok(
            "https://x@github.com/alperen-cpu/LockAlperen/releases/download/v0.2.0/a.exe"
        ));
        assert!(!ok(
            "https://github.com:8443/alperen-cpu/LockAlperen/releases/download/v0.2.0/a.exe"
        ));
        // Another repository, or leaving this one with "..".
        assert!(!ok(
            "https://github.com/someone/LockAlperen/releases/download/v0.2.0/a.exe"
        ));
        assert!(!ok(
            "https://github.com/alperen-cpu/LockAlperen/releases/download/../../../evil/x/releases/download/a.exe"
        ));
        assert!(!ok(
            "https://github.com/alperen-cpu/LockAlperen/releases/download/%2e%2e/%2e%2e/%2e%2e/evil/a.exe"
        ));
        assert!(!ok(
            "https://github.com/alperen-cpu/LockAlperen/releases/download/"
        ));
        assert!(!ok(
            "file:///C:/alperen-cpu/LockAlperen/releases/download/a.exe"
        ));
    }

    #[test]
    fn no_network_without_a_release_key() {
        assert!(!key_configured(""));
        assert!(!key_configured("  "));
        assert!(key_configured(
            "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk="
        ));
    }

    /// The shipped configuration is the one the trust argument above relies
    /// on: HTTPS endpoint on this repo, signed versions required, no
    /// downgrades, no "dangerous" switches, passive NSIS install.
    #[test]
    fn shipped_updater_config_is_strict() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let u = &conf["plugins"]["updater"];
        assert_eq!(u["requireSignedVersion"], true);
        assert!(u.get("allowDowngrades").is_none_or(|v| v == false));
        for k in [
            "dangerousInsecureTransportProtocol",
            "dangerousAcceptInvalidCerts",
            "dangerousAcceptInvalidHostnames",
        ] {
            assert!(u.get(k).is_none_or(|v| v == false), "{k}");
        }
        let endpoints = u["endpoints"].as_array().unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0],
            "https://github.com/alperen-cpu/LockAlperen/releases/latest/download/latest.json"
        );
        assert_eq!(u["windows"]["installMode"], "passive");
    }
}
