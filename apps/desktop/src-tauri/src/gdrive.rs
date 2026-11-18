//! Google Drive backup (SECURITY.md "Google Drive yedeği").
//!
//! What goes to Google: only the vault FILE as it is on disk, i.e. already
//! encrypted (XChaCha20-Poly1305, key from the master password). Never the
//! master password, never decrypted content.
//!
//! - Sign-in: OAuth 2.0 for installed apps, as Google recommends: the system
//!   browser, a one-shot redirect to 127.0.0.1 on a random port, PKCE (S256)
//!   and a random `state`. The app never sees the Google password.
//! - Scope: `drive.file` only: the app can see and change only the files it
//!   created itself, nothing else in the user's Drive.
//! - The refresh token is stored encrypted with Windows DPAPI (tied to the
//!   Windows user); the access token lives in memory only.
//! - Only https to accounts.google.com, oauth2.googleapis.com and
//!   www.googleapis.com; rustls with the system's root certificates.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SCOPE: &str = "https://www.googleapis.com/auth/drive.file";
pub const FOLDER_NAME: &str = "LockAlperen yedekleri";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
/// How long the sign-in in the browser may take.
pub const SIGN_IN_WAIT: Duration = Duration::from_secs(180);
/// Downloads are vault files; same limit as opening one.
pub const MAX_DOWNLOAD: u64 = lav_core::vault::MAX_VAULT_FILE_BYTES;

pub const NOT_CONFIGURED: &str =
    "Önce Google OAuth istemci kimliğini ve gizli anahtarını girin (Ayarlar › Google Drive).";
pub const NOT_CONNECTED: &str = "Google hesabı bağlı değil.";
pub const SIGN_IN_TIMEOUT: &str = "Google girişi 3 dakika içinde tamamlanmadı.";
pub const SIGN_IN_DENIED: &str = "Google girişi iptal edildi ya da izin verilmedi.";
pub const SIGN_IN_FAILED: &str = "Google girişi tamamlanamadı.";
pub const NETWORK: &str = "Google Drive'a bağlanılamadı (internet bağlantısını kontrol edin).";
pub const DRIVE_ERROR: &str = "Google Drive isteği reddetti.";
pub const EXPIRED: &str =
    "Google erişimi geçersiz olmuş (izin geri alınmış olabilir). Hesabı yeniden bağlayın.";
pub const NOT_A_VAULT: &str = "İndirilen dosya bir LockAlperen kasası değil.";
pub const TOO_BIG: &str = "Dosya çok büyük.";
pub const STORE_FAILED: &str = "Google Drive ayarları kaydedilemedi.";
#[cfg(windows)]
pub const PROTECT_FAILED: &str = "Erişim anahtarı Windows ile şifrelenemedi.";
#[cfg(target_os = "linux")]
pub const PROTECT_FAILED: &str =
    "Erişim anahtarı sistem anahtarlığına kaydedilemedi (anahtarlık açık mı?).";

// ----- endpoints (tests point them at a local fake server) -----

#[derive(Debug, Clone)]
pub struct Endpoints {
    pub auth: String,
    pub token: String,
    pub revoke: String,
    pub files: String,
    pub upload: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            auth: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token: "https://oauth2.googleapis.com/token".into(),
            revoke: "https://oauth2.googleapis.com/revoke".into(),
            files: "https://www.googleapis.com/drive/v3/files".into(),
            upload: "https://www.googleapis.com/upload/drive/v3/files".into(),
        }
    }
}

// ----- stored state -----

/// `google-drive.json` next to settings.json. The client id and secret of a
/// desktop OAuth client are not confidential (Google says so for installed
/// apps); the refresh token is, so it is kept DPAPI-encrypted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Store {
    pub client_id: String,
    pub client_secret: String,
    /// base64 of the DPAPI blob; None = not connected.
    pub refresh_token: Option<String>,
    pub folder_id: Option<String>,
    /// Vault file (canonical path, lowercase) -> Drive file id.
    pub files: HashMap<String, String>,
    /// Vault file -> (modified time we last uploaded, when).
    pub uploaded: HashMap<String, (u64, i64)>,
    /// Back up open vaults automatically after they change.
    pub auto: bool,
}

impl Store {
    pub fn credentials(&self) -> Option<(String, String)> {
        let id = self
            .client_id
            .trim()
            .to_owned()
            .chars()
            .take(256)
            .collect::<String>();
        let id = if id.is_empty() {
            option_env!("LAV_GOOGLE_CLIENT_ID").unwrap_or("").to_owned()
        } else {
            id
        };
        let secret = if self.client_secret.trim().is_empty() {
            option_env!("LAV_GOOGLE_CLIENT_SECRET")
                .unwrap_or("")
                .to_owned()
        } else {
            self.client_secret.trim().chars().take(256).collect()
        };
        (!id.is_empty()).then_some((id, secret))
    }

    pub fn connected(&self) -> bool {
        self.refresh_token.is_some()
    }
}

pub fn load(file: &Path) -> Store {
    let Ok(f) = std::fs::File::open(file) else {
        return Store::default();
    };
    let mut buf = Vec::new();
    if f.take(1024 * 1024 + 1).read_to_end(&mut buf).is_err() || buf.len() > 1024 * 1024 {
        return Store::default();
    }
    serde_json::from_slice(&buf).unwrap_or_default()
}

pub fn save(file: &Path, s: &Store) -> Result<(), &'static str> {
    (|| -> std::io::Result<()> {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = file.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&serde_json::to_vec_pretty(s).map_err(std::io::Error::other)?)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, file)
    })()
    .map_err(|_| STORE_FAILED)
}

/// The key a vault file is remembered under. Windows paths ignore case;
/// Linux paths do not (`Kasa.lav` and `kasa.lav` are two files).
pub fn file_key(path: &Path) -> String {
    let key = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned();
    if cfg!(windows) {
        key.to_lowercase()
    } else {
        key
    }
}

// ----- DPAPI (Windows) / Secret Service (Linux, src/linux/secret.rs) -----

#[cfg(target_os = "linux")]
#[path = "linux/secret.rs"]
mod secret;
#[cfg(target_os = "linux")]
pub use secret::{protect, unprotect};

#[cfg(windows)]
pub fn protect(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    dpapi(data, true)
}

#[cfg(windows)]
pub fn unprotect(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    dpapi(data, false).map(Zeroizing::new)
}

#[cfg(windows)]
fn dpapi(data: &[u8], encrypt: bool) -> Result<Vec<u8>, &'static str> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| PROTECT_FAILED)?,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: `input` points at `data` for the duration of the call; `out`
    // is filled by the API and freed with LocalFree below. No prompt, no
    // optional entropy.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
    };
    if ok == 0 || out.pbData.is_null() {
        return Err(if encrypt { PROTECT_FAILED } else { EXPIRED });
    }
    // SAFETY: the API returned `cbData` bytes at `pbData`.
    let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    // SAFETY: wipe the API's buffer, then free it as documented.
    unsafe {
        std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
        LocalFree(out.pbData as _);
    }
    Ok(bytes)
}

// ----- OAuth -----

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// PKCE (RFC 7636, S256): (verifier, challenge).
pub fn pkce() -> (Zeroizing<String>, String) {
    let verifier = Zeroizing::new(b64url(&lav_core::crypto::random_bytes::<48>()));
    let challenge = pkce_challenge(&verifier);
    (verifier, challenge)
}

pub fn pkce_challenge(verifier: &str) -> String {
    b64url(&Sha256::digest(verifier.as_bytes()))
}

pub fn random_state() -> String {
    b64url(&lav_core::crypto::random_bytes::<24>())
}

pub fn auth_url(
    ep: &Endpoints,
    client_id: &str,
    redirect: &str,
    challenge: &str,
    state: &str,
) -> String {
    let mut u = url::Url::parse(&ep.auth).expect("constant URL");
    u.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect)
        .append_pair("response_type", "code")
        .append_pair("scope", SCOPE)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent");
    u.to_string()
}

/// What the browser sent to the loopback address.
#[derive(Debug, PartialEq, Eq)]
pub enum Redirect {
    Code(Zeroizing<String>),
    Denied,
    /// Not the sign-in redirect (favicon, wrong state...): keep waiting.
    Other,
}

/// Reads the request line `GET /?code=..&state=.. HTTP/1.1`.
pub fn parse_redirect(request_line: &str, state: &str) -> Redirect {
    let mut parts = request_line.split_whitespace();
    let (Some("GET"), Some(target)) = (parts.next(), parts.next()) else {
        return Redirect::Other;
    };
    let Ok(u) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
        return Redirect::Other;
    };
    if u.path() != "/" {
        return Redirect::Other;
    }
    let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
    // The state must match, or this is not our sign-in (or a forged one).
    if q.get("state").map(String::as_str) != Some(state) {
        return Redirect::Other;
    }
    if q.contains_key("error") {
        return Redirect::Denied;
    }
    match q.get("code") {
        Some(c) if !c.is_empty() && c.len() < 4096 => Redirect::Code(Zeroizing::new(c.clone())),
        _ => Redirect::Denied,
    }
}

const DONE_PAGE: &str = "<!doctype html><html lang=\"tr\"><meta charset=\"utf-8\"><title>LockAlperen</title>\
<body style=\"font-family:Segoe UI,sans-serif;padding:40px\"><h1>Tamam</h1>\
<p>Google hesabı LockAlperen'e bağlandı. Bu sekmeyi kapatıp uygulamaya dönebilirsiniz.</p></body></html>";
const DENIED_PAGE: &str =
    "<!doctype html><html lang=\"tr\"><meta charset=\"utf-8\"><title>LockAlperen</title>\
<body style=\"font-family:Segoe UI,sans-serif;padding:40px\"><h1>Bağlanmadı</h1>\
<p>İzin verilmedi. Bu sekmeyi kapatabilirsiniz.</p></body></html>";

fn reply(mut s: TcpStream, status: &str, body: &str) {
    let _ = write!(
        s,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
}

/// Waits on the loopback listener for the browser's redirect. Only
/// 127.0.0.1 is bound; other requests are answered 404 and ignored.
pub fn wait_for_code(
    listener: &TcpListener,
    state: &str,
    wait: Duration,
) -> Result<Zeroizing<String>, &'static str> {
    listener.set_nonblocking(true).map_err(|_| SIGN_IN_FAILED)?;
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 8192];
                let mut n = 0;
                let mut s = stream;
                while n < buf.len() {
                    match s.read(&mut buf[n..]) {
                        Ok(0) | Err(_) => break,
                        Ok(k) => {
                            n += k;
                            if buf[..n].windows(2).any(|w| w == b"\r\n") {
                                break;
                            }
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf[..n]);
                let line = text.lines().next().unwrap_or("");
                match parse_redirect(line, state) {
                    Redirect::Code(c) => {
                        reply(s, "200 OK", DONE_PAGE);
                        return Ok(c);
                    }
                    Redirect::Denied => {
                        reply(s, "200 OK", DENIED_PAGE);
                        return Err(SIGN_IN_DENIED);
                    }
                    Redirect::Other => reply(s, "404 Not Found", ""),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return Err(SIGN_IN_FAILED),
        }
    }
    Err(SIGN_IN_TIMEOUT)
}

// ----- HTTP -----

pub fn client() -> Result<reqwest::Client, &'static str> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("LockAlperen")
        .build()
        .map_err(|_| NETWORK)
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: Option<String>,
    refresh_token: Option<String>,
}

async fn token_request(
    c: &reqwest::Client,
    ep: &Endpoints,
    form: &[(&str, &str)],
) -> Result<TokenReply, &'static str> {
    let r = c
        .post(&ep.token)
        .form(form)
        .send()
        .await
        .map_err(|_| NETWORK)?;
    let status = r.status();
    let body = r.bytes().await.map_err(|_| NETWORK)?;
    if status.as_u16() == 400 || status.as_u16() == 401 {
        return Err(EXPIRED);
    }
    if !status.is_success() {
        return Err(SIGN_IN_FAILED);
    }
    serde_json::from_slice(&body).map_err(|_| SIGN_IN_FAILED)
}

/// Code -> refresh token (and a first access token).
pub async fn exchange_code(
    c: &reqwest::Client,
    ep: &Endpoints,
    creds: &(String, String),
    code: &str,
    verifier: &str,
    redirect: &str,
) -> Result<(Zeroizing<String>, Zeroizing<String>), &'static str> {
    let t = token_request(
        c,
        ep,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", redirect),
            ("client_id", &creds.0),
            ("client_secret", &creds.1),
        ],
    )
    .await
    .map_err(|e| if e == EXPIRED { SIGN_IN_FAILED } else { e })?;
    match (t.refresh_token, t.access_token) {
        (Some(r), Some(a)) => Ok((Zeroizing::new(r), Zeroizing::new(a))),
        _ => Err(SIGN_IN_FAILED),
    }
}

pub async fn access_token(
    c: &reqwest::Client,
    ep: &Endpoints,
    creds: &(String, String),
    refresh: &str,
) -> Result<Zeroizing<String>, &'static str> {
    let t = token_request(
        c,
        ep,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", &creds.0),
            ("client_secret", &creds.1),
        ],
    )
    .await?;
    t.access_token.map(Zeroizing::new).ok_or(SIGN_IN_FAILED)
}

pub async fn revoke(c: &reqwest::Client, ep: &Endpoints, token: &str) {
    // Best effort: the local token is deleted either way.
    let _ = c.post(&ep.revoke).form(&[("token", token)]).send().await;
}

fn drive_status(s: reqwest::StatusCode) -> Result<(), &'static str> {
    match s.as_u16() {
        200..=299 => Ok(()),
        401 => Err(EXPIRED),
        _ => Err(DRIVE_ERROR),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveFile {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub modified_time: String,
    #[serde(default)]
    pub size: Option<String>,
}

#[derive(Deserialize)]
struct FileList {
    #[serde(default)]
    files: Vec<DriveFile>,
}

/// The app's backup folder, created if missing (we can only see folders
/// we created, so an existing one is found by its stored id).
pub async fn ensure_folder(
    c: &reqwest::Client,
    ep: &Endpoints,
    token: &str,
    known: Option<&str>,
) -> Result<String, &'static str> {
    if let Some(id) = known {
        let r = c
            .get(format!("{}/{}", ep.files, id))
            .query(&[("fields", "id,trashed")])
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| NETWORK)?;
        if r.status().is_success() {
            #[derive(Deserialize)]
            struct F {
                #[serde(default)]
                trashed: bool,
            }
            let f: F = r.json().await.map_err(|_| DRIVE_ERROR)?;
            if !f.trashed {
                return Ok(id.to_owned());
            }
        } else if r.status().as_u16() == 401 {
            return Err(EXPIRED);
        }
    }
    let r = c
        .post(&ep.files)
        .query(&[("fields", "id")])
        .bearer_auth(token)
        .json(&serde_json::json!({ "name": FOLDER_NAME, "mimeType": FOLDER_MIME }))
        .send()
        .await
        .map_err(|_| NETWORK)?;
    drive_status(r.status())?;
    let f: DriveFile = r.json().await.map_err(|_| DRIVE_ERROR)?;
    Ok(f.id)
}

/// `multipart/related` body for a create-with-metadata upload.
pub fn multipart_body(boundary: &str, metadata: &serde_json::Value, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(data.len() + 512);
    b.extend_from_slice(
        format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
    );
    b.extend_from_slice(data);
    b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    b
}

/// Uploads the vault file: replaces the earlier backup of the same file if
/// it is still there, otherwise creates a new one in the folder. Returns the
/// Drive file id.
pub async fn upload(
    c: &reqwest::Client,
    ep: &Endpoints,
    token: &str,
    folder: &str,
    existing: Option<&str>,
    name: &str,
    data: &[u8],
) -> Result<String, &'static str> {
    if let Some(id) = existing {
        let r = c
            .patch(format!("{}/{}", ep.upload, id))
            .query(&[("uploadType", "media"), ("fields", "id")])
            .bearer_auth(token)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|_| NETWORK)?;
        match r.status().as_u16() {
            200..=299 => {
                let f: DriveFile = r.json().await.map_err(|_| DRIVE_ERROR)?;
                return Ok(f.id);
            }
            401 => return Err(EXPIRED),
            // Deleted in Drive: make a new one below.
            404 => {}
            _ => return Err(DRIVE_ERROR),
        }
    }
    let boundary = format!("lav{}", random_state().replace(['-', '_'], ""));
    let meta = serde_json::json!({
        "name": name,
        "parents": [folder],
        "mimeType": "application/octet-stream",
        "description": "LockAlperen kasası (şifreli)",
    });
    let r = c
        .post(&ep.upload)
        .query(&[("uploadType", "multipart"), ("fields", "id")])
        .bearer_auth(token)
        .header(
            "Content-Type",
            format!("multipart/related; boundary={boundary}"),
        )
        .body(multipart_body(&boundary, &meta, data))
        .send()
        .await
        .map_err(|_| NETWORK)?;
    drive_status(r.status())?;
    let f: DriveFile = r.json().await.map_err(|_| DRIVE_ERROR)?;
    Ok(f.id)
}

/// Backups in the app's folder, newest first.
pub async fn list(
    c: &reqwest::Client,
    ep: &Endpoints,
    token: &str,
    folder: &str,
) -> Result<Vec<DriveFile>, &'static str> {
    // The folder id is ours (a Drive id: letters, digits, - and _).
    if !folder
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(DRIVE_ERROR);
    }
    let r = c
        .get(&ep.files)
        .query(&[
            (
                "q",
                format!("'{folder}' in parents and trashed = false").as_str(),
            ),
            ("fields", "files(id,name,modifiedTime,size)"),
            ("orderBy", "modifiedTime desc"),
            ("pageSize", "100"),
        ])
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| NETWORK)?;
    drive_status(r.status())?;
    let l: FileList = r.json().await.map_err(|_| DRIVE_ERROR)?;
    Ok(l.files)
}

/// Downloads a backup; refuses anything that is not a LockAlperen vault.
pub async fn download(
    c: &reqwest::Client,
    ep: &Endpoints,
    token: &str,
    id: &str,
) -> Result<Vec<u8>, &'static str> {
    if id.is_empty()
        || !id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(DRIVE_ERROR);
    }
    let mut r = c
        .get(format!("{}/{}", ep.files, id))
        .query(&[("alt", "media")])
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| NETWORK)?;
    drive_status(r.status())?;
    let mut out = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(|_| NETWORK)? {
        out.extend_from_slice(&chunk);
        if out.len() as u64 > MAX_DOWNLOAD {
            return Err(TOO_BIG);
        }
    }
    lav_core::Vault::peek_header(&out).map_err(|_| NOT_A_VAULT)?;
    Ok(out)
}

/// Binds the loopback listener for the redirect: 127.0.0.1, random port.
pub fn listen() -> Result<(TcpListener, String), &'static str> {
    let l = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| SIGN_IN_FAILED)?;
    let port = l.local_addr().map_err(|_| SIGN_IN_FAILED)?.port();
    Ok((l, format!("http://127.0.0.1:{port}")))
}

/// Paths are kept as given; used by tests and the status view.
pub fn display_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Where the store lives, next to settings.json.
pub fn store_path(settings_file: &Path) -> PathBuf {
    settings_file.with_file_name("google-drive.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_rfc7636() {
        // RFC 7636, Appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let (v, c) = pkce();
        assert!(v.len() >= 43 && v.len() <= 128);
        assert_eq!(pkce_challenge(&v), c);
        assert_ne!(random_state(), random_state());
    }

    #[test]
    fn auth_url_asks_only_for_drive_file() {
        let u = auth_url(
            &Endpoints::default(),
            "id.apps",
            "http://127.0.0.1:5000",
            "ch",
            "st",
        );
        let u = url::Url::parse(&u).unwrap();
        assert_eq!(u.host_str(), Some("accounts.google.com"));
        let q: HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(q["scope"], SCOPE);
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:5000");
        assert_eq!(q["state"], "st");
    }

    #[test]
    fn redirect_needs_the_right_state() {
        assert_eq!(
            parse_redirect("GET /?state=s1&code=abc HTTP/1.1", "s1"),
            Redirect::Code(Zeroizing::new("abc".into()))
        );
        assert_eq!(
            parse_redirect("GET /?state=other&code=abc HTTP/1.1", "s1"),
            Redirect::Other
        );
        assert_eq!(
            parse_redirect("GET /?code=abc HTTP/1.1", "s1"),
            Redirect::Other
        );
        assert_eq!(
            parse_redirect("GET /?state=s1&error=access_denied HTTP/1.1", "s1"),
            Redirect::Denied
        );
        assert_eq!(
            parse_redirect("GET /favicon.ico HTTP/1.1", "s1"),
            Redirect::Other
        );
        assert_eq!(
            parse_redirect("POST /?state=s1&code=x HTTP/1.1", "s1"),
            Redirect::Other
        );
    }

    #[test]
    fn loopback_listener_takes_only_the_real_redirect() {
        let (l, base) = listen().unwrap();
        assert!(base.starts_with("http://127.0.0.1:"));
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let send = |path: &str| {
                let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
                write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
                let mut r = String::new();
                let _ = s.read_to_string(&mut r);
                r
            };
            let a = send("/favicon.ico");
            let b = send("/?state=wrong&code=evil");
            let c = send("/?state=good&code=the-code");
            (a, b, c)
        });
        let code = wait_for_code(&l, "good", Duration::from_secs(10)).unwrap();
        assert_eq!(code.as_str(), "the-code");
        let (a, b, c) = t.join().unwrap();
        assert!(a.starts_with("HTTP/1.1 404") && b.starts_with("HTTP/1.1 404"));
        assert!(c.contains("bağlandı"));
        let (l2, _) = listen().unwrap();
        assert_eq!(
            wait_for_code(&l2, "x", Duration::from_millis(300)).err(),
            Some(SIGN_IN_TIMEOUT)
        );
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip() {
        let blob = protect(b"refresh-token-123").unwrap();
        assert!(!blob.windows(17).any(|w| w == b"refresh-token-123"));
        assert_eq!(unprotect(&blob).unwrap().as_slice(), b"refresh-token-123");
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(unprotect(&bad).is_err());
    }

    #[test]
    fn store_load_and_save() {
        let dir = std::env::temp_dir().join(format!("lav-gd-{}", std::process::id()));
        let file = dir.join("google-drive.json");
        assert_eq!(load(&file), Store::default());
        let mut s = Store {
            client_id: " id.apps.googleusercontent.com ".into(),
            client_secret: "sec".into(),
            auto: true,
            ..Default::default()
        };
        s.files.insert("c:\\kasa.lav".into(), "f1".into());
        save(&file, &s).unwrap();
        assert_eq!(load(&file), s);
        assert_eq!(
            s.credentials(),
            Some(("id.apps.googleusercontent.com".into(), "sec".into()))
        );
        assert!(!s.connected());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn multipart_layout() {
        let b = multipart_body("BB", &serde_json::json!({"name": "a.lav"}), b"\x00\x01");
        let text = String::from_utf8_lossy(&b);
        assert!(text.starts_with("--BB\r\nContent-Type: application/json"));
        assert!(text.contains("{\"name\":\"a.lav\"}"));
        assert!(text.ends_with("\r\n--BB--\r\n"));
    }

    // ----- the whole HTTP flow against a local fake Google -----

    /// A tiny HTTP server answering like Google's endpoints. Records
    /// "METHOD path" of every request.
    fn fake_google(vault: Vec<u8>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let base = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                // Read headers and body (Content-Length).
                let mut buf = Vec::new();
                let mut tmp = [0u8; 65536];
                let (head, body_len) = loop {
                    let n = s.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break (String::new(), 0);
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_string();
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        while buf.len() < p + 4 + len {
                            let n = s.read(&mut tmp).unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            buf.extend_from_slice(&tmp[..n]);
                        }
                        break (head, len);
                    }
                };
                let line = head.lines().next().unwrap_or("").to_owned();
                let mut it = line.split_whitespace();
                let (m, target) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
                let path = target.split('?').next().unwrap_or("");
                log2.lock().unwrap().push(format!("{m} {path}"));
                let auth_ok = head.contains("authorization: Bearer AT")
                    || head.contains("Authorization: Bearer AT");
                let _ = body_len;
                let (status, body): (&str, Vec<u8>) = match (m, path) {
                    ("POST", "/token") => {
                        let b = String::from_utf8_lossy(&buf).to_string();
                        if b.contains("grant_type=authorization_code") && b.contains("code_verifier=") {
                            ("200 OK", br#"{"access_token":"AT","refresh_token":"RT"}"#.to_vec())
                        } else if b.contains("refresh_token=RT") {
                            ("200 OK", br#"{"access_token":"AT"}"#.to_vec())
                        } else {
                            ("400 Bad Request", br#"{"error":"invalid_grant"}"#.to_vec())
                        }
                    }
                    _ if !auth_ok => ("401 Unauthorized", b"{}".to_vec()),
                    ("POST", "/files") => ("200 OK", br#"{"id":"FOLDER1"}"#.to_vec()),
                    ("POST", "/upload") => ("200 OK", br#"{"id":"FILE1"}"#.to_vec()),
                    ("PATCH", "/upload/FILE1") => ("200 OK", br#"{"id":"FILE1"}"#.to_vec()),
                    ("PATCH", _) => ("404 Not Found", b"{}".to_vec()),
                    ("GET", "/files") => (
                        "200 OK",
                        br#"{"files":[{"id":"FILE1","name":"kasa.lav","modifiedTime":"2026-11-18T10:00:00Z","size":"200"}]}"#.to_vec(),
                    ),
                    ("GET", "/files/FOLDER1") => ("200 OK", br#"{"id":"FOLDER1","trashed":false}"#.to_vec()),
                    ("GET", "/files/FILE1") => ("200 OK", vault.clone()),
                    ("GET", "/files/NOTVAULT") => ("200 OK", b"hello".to_vec()),
                    _ => ("404 Not Found", b"{}".to_vec()),
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(&body);
            }
        });
        (base, log)
    }

    #[test]
    fn upload_list_download_against_a_fake_drive() {
        let kdf = lav_core::KdfParams {
            memory_kib: lav_core::KdfParams::MIN_MEMORY_KIB,
            iterations: lav_core::KdfParams::MIN_ITERATIONS,
            parallelism: lav_core::KdfParams::MIN_PARALLELISM,
        };
        let v = lav_core::Vault::create("x", "correct horse battery", None, kdf).unwrap();
        let vault_bytes = v.seal().unwrap();
        let (base, log) = fake_google(vault_bytes.clone());
        let ep = Endpoints {
            auth: format!("{base}/auth"),
            token: format!("{base}/token"),
            revoke: format!("{base}/revoke"),
            files: format!("{base}/files"),
            upload: format!("{base}/upload"),
        };
        let creds = ("cid".to_owned(), "sec".to_owned());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let c = client().unwrap();
            let (refresh, access) =
                exchange_code(&c, &ep, &creds, "code", "verifier", "http://127.0.0.1:1")
                    .await
                    .unwrap();
            assert_eq!((refresh.as_str(), access.as_str()), ("RT", "AT"));
            let at = access_token(&c, &ep, &creds, "RT").await.unwrap();
            assert_eq!(
                access_token(&c, &ep, &creds, "BAD").await.err(),
                Some(EXPIRED)
            );
            let folder = ensure_folder(&c, &ep, &at, None).await.unwrap();
            assert_eq!(folder, "FOLDER1");
            assert_eq!(
                ensure_folder(&c, &ep, &at, Some("FOLDER1")).await.unwrap(),
                "FOLDER1"
            );
            let id = upload(&c, &ep, &at, &folder, None, "kasa.lav", &vault_bytes)
                .await
                .unwrap();
            assert_eq!(id, "FILE1");
            // Replacing the same backup; a vanished one is created again.
            assert_eq!(
                upload(
                    &c,
                    &ep,
                    &at,
                    &folder,
                    Some("FILE1"),
                    "kasa.lav",
                    &vault_bytes
                )
                .await
                .unwrap(),
                "FILE1"
            );
            assert_eq!(
                upload(
                    &c,
                    &ep,
                    &at,
                    &folder,
                    Some("GONE"),
                    "kasa.lav",
                    &vault_bytes
                )
                .await
                .unwrap(),
                "FILE1"
            );
            let files = list(&c, &ep, &at, &folder).await.unwrap();
            assert_eq!(files[0].name, "kasa.lav");
            assert_eq!(download(&c, &ep, &at, "FILE1").await.unwrap(), vault_bytes);
            assert_eq!(
                download(&c, &ep, &at, "NOTVAULT").await.err(),
                Some(NOT_A_VAULT)
            );
            assert_eq!(
                download(&c, &ep, &at, "../x").await.err(),
                Some(DRIVE_ERROR)
            );
            assert_eq!(list(&c, &ep, "WRONG", &folder).await.err(), Some(EXPIRED));
            assert_eq!(
                list(&c, &ep, &at, "x' or '1'='1").await.err(),
                Some(DRIVE_ERROR)
            );
        });
        let log = log.lock().unwrap().clone();
        assert!(log.contains(&"PATCH /upload/FILE1".to_owned()));
        assert!(log.contains(&"POST /upload".to_owned()));
    }
}
