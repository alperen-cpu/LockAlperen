//! Linux transport for the browser extension.
//!
//! Browser -> native host (this same binary, started by the browser through
//! `nm-host.sh`) -> Unix socket -> the running app. Nothing listens on the
//! network (KeePassHttp, KeePassRPC and Trend Micro's local servers were the
//! classic failures). The socket lives in `$XDG_RUNTIME_DIR/<app id>/`
//! (folder 0700, socket 0600) and the app also checks that the peer is the
//! same user (`SO_PEERCRED`). That check is defence in depth only: what
//! authenticates the extension is the Noise pairing (conn.rs).
//!
//! Native messaging manifests are written for the user only (Chrome,
//! Chromium, Brave, Edge under `~/.config`) and allow exactly our extension
//! id. Snap and Flatpak browsers cannot start programs outside their
//! sandbox; that is documented, not worked around.

#[cfg(test)]
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::conn;

const MAX_CONNECTIONS: usize = 8;
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// `$XDG_RUNTIME_DIR/<identifier>/bridge.sock`; None without a runtime dir
/// (then the integration is not available).
pub fn socket_path(identifier: &str) -> Option<PathBuf> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())?;
    Some(dir.join(identifier).join("bridge.sock"))
}

fn peer_is_same_user(s: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid socket fd and a buffer of the size we pass.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    // SAFETY: no arguments, cannot fail.
    r == 0 && cred.uid == unsafe { libc::getuid() }
}

/// Binds the socket and serves connections on their own threads.
pub fn listen(
    path: &Path,
    serve: impl Fn(&mut UnixStream) + Send + Sync + 'static,
) -> std::io::Result<()> {
    let dir = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    crate::private::create_dir(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    // A leftover socket from a crashed run (the app is single-instance).
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let serve = std::sync::Arc::new(serve);
    std::thread::Builder::new()
        .name("lav-bridge".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                if !peer_is_same_user(&stream) {
                    continue;
                }
                if LIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    LIVE.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let serve = serve.clone();
                let spawned = std::thread::Builder::new()
                    .name("lav-bridge-conn".into())
                    .spawn(move || {
                        serve(&mut stream);
                        LIVE.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    LIVE.fetch_sub(1, Ordering::SeqCst);
                }
            }
        })?;
    Ok(())
}

/// Native-host mode (`--lav-nm-host <socket>`): relays frames between the
/// browser (stdin/stdout) and the app's socket. It sees only ciphertext
/// after the handshake and holds no keys.
pub fn run_host(socket: &Path) -> i32 {
    let mut out = std::io::stdout().lock();
    let Ok(sock) = UnixStream::connect(socket) else {
        // The app is not running (or the integration is off).
        let _ = conn::write_frame(&mut out, br#"{"t":"err","e":"not_running"}"#);
        return 0;
    };
    let Ok(mut to_app) = sock.try_clone() else {
        return 1;
    };
    let mut from_app = sock;
    let up = std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        while let Ok(Some(frame)) = conn::read_frame(&mut stdin) {
            if conn::write_frame(&mut to_app, &frame).is_err() {
                break;
            }
        }
        let _ = to_app.shutdown(std::net::Shutdown::Both);
    });
    while let Ok(Some(frame)) = conn::read_frame(&mut from_app) {
        if conn::write_frame(&mut out, &frame).is_err() {
            break;
        }
    }
    // The app closed the connection: exit without waiting for the stdin
    // thread (the browser closes stdin when the extension disconnects).
    drop(up);
    0
}

/// Per-user NativeMessagingHosts folders of Chromium-family browsers whose
/// profile folder exists.
fn browser_dirs() -> Vec<(&'static str, PathBuf)> {
    let Some(config) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    else {
        return vec![];
    };
    [
        ("Google Chrome", "google-chrome"),
        ("Chrome Beta", "google-chrome-beta"),
        ("Chromium", "chromium"),
        ("Brave", "BraveSoftware/Brave-Browser"),
        ("Microsoft Edge", "microsoft-edge"),
    ]
    .into_iter()
    .map(|(name, rel)| (name, config.join(rel)))
    .filter(|(_, profile)| profile.is_dir())
    .map(|(name, profile)| (name, profile.join("NativeMessagingHosts")))
    .collect()
}

/// `'...'` for sh, or None for a path that cannot be written safely.
fn sh_quote(p: &Path) -> Option<String> {
    let s = p.to_str()?;
    if s.chars().any(char::is_control) {
        return None;
    }
    Some(format!("'{}'", s.replace('\'', r"'\''")))
}

/// The wrapper the browser starts: this binary in native-host mode with the
/// socket of this app identity.
pub fn host_script(exe: &Path, socket: &Path) -> Option<String> {
    Some(format!(
        "#!/bin/sh\n# LockAlperen tarayıcı eklentisi köprüsü (otomatik oluşturuldu).\nexec {} --lav-nm-host {} \"$@\"\n",
        sh_quote(exe)?,
        sh_quote(socket)?
    ))
}

pub fn manifest(name: &str, script: &Path, extension_id: &str) -> String {
    serde_json::json!({
        "name": name,
        "description": "LockAlperen",
        "path": script,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")],
    })
    .to_string()
}

/// The program the browser starts (an AppImage names itself, as autostart).
fn program() -> Option<PathBuf> {
    std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::current_exe().ok())
}

/// Writes the wrapper (0700) and a manifest for each browser found. Returns
/// the browsers' names.
pub fn install(
    data_dir: &Path,
    identifier: &str,
    extension_id: &str,
) -> Result<Vec<String>, &'static str> {
    const FAILED: &str = "Tarayıcı bağlantısı kurulamadı.";
    let socket = socket_path(identifier)
        .ok_or("Bu oturumda XDG_RUNTIME_DIR yok; tarayıcı eklentisi kullanılamaz.")?;
    let script_text = host_script(&program().ok_or(FAILED)?, &socket).ok_or(FAILED)?;
    let script = data_dir.join("nm-host.sh");
    (|| -> std::io::Result<()> {
        crate::private::write_atomic(&script, "sh.tmp", script_text.as_bytes())?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
    })()
    .map_err(|_| FAILED)?;
    let text = manifest(identifier, &script, extension_id);
    let mut done = Vec::new();
    for (name, dir) in browser_dirs() {
        let file = dir.join(format!("{identifier}.json"));
        if std::fs::create_dir_all(&dir).is_ok()
            && crate::private::write_atomic(&file, "json.tmp", text.as_bytes()).is_ok()
        {
            done.push(name.to_owned());
        }
    }
    if done.is_empty() {
        return Err("Desteklenen bir tarayıcı bulunamadı (Chrome, Chromium, Brave, Edge). Snap ya da Flatpak tarayıcılar desteklenmez.");
    }
    Ok(done)
}

/// Removes our manifests (the browsers can no longer start the host).
pub fn uninstall(data_dir: &Path, identifier: &str) {
    for (_, dir) in browser_dirs() {
        let _ = std::fs::remove_file(dir.join(format!("{identifier}.json")));
    }
    let _ = std::fs::remove_file(data_dir.join("nm-host.sh"));
}

pub fn installed(identifier: &str) -> Vec<String> {
    browser_dirs()
        .into_iter()
        .filter(|(_, dir)| dir.join(format!("{identifier}.json")).is_file())
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// Reads exactly what a relay test needs from a stream (test helper).
#[cfg(test)]
fn read_all(s: &mut impl Read) -> Vec<u8> {
    let mut v = Vec::new();
    let _ = s.read_to_end(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_quotes_paths_for_sh() {
        let s = host_script(
            Path::new("/opt/it's here/lockalperen"),
            Path::new("/run/user/1000/com.alperen.lockalperen/bridge.sock"),
        )
        .unwrap();
        assert!(s.contains(r"exec '/opt/it'\''s here/lockalperen' --lav-nm-host '/run/user/1000/com.alperen.lockalperen/bridge.sock' "));
        assert!(host_script(Path::new("/a\nb"), Path::new("/s")).is_none());
    }

    #[test]
    fn manifest_allows_only_our_extension() {
        let m: serde_json::Value = serde_json::from_str(&manifest(
            "com.alperen.lockalperen",
            Path::new("/home/u/.local/share/com.alperen.lockalperen/nm-host.sh"),
            "lfhdblnhdfbfnkknmllnbndblidnlbed",
        ))
        .unwrap();
        assert_eq!(m["type"], "stdio");
        assert_eq!(
            m["allowed_origins"],
            serde_json::json!(["chrome-extension://lfhdblnhdfbfnkknmllnbndblidnlbed/"])
        );
    }

    #[test]
    fn socket_is_private_and_relay_passes_frames() {
        let base = std::env::temp_dir().join(format!("lav-bridge-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let path = base.join("app").join("bridge.sock");
        listen(&path, |s| {
            // Echo one frame back.
            if let Ok(Some(f)) = conn::read_frame(s) {
                let _ = conn::write_frame(s, &f);
            }
        })
        .unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        let mut c = UnixStream::connect(&path).unwrap();
        assert!(peer_is_same_user(&c));
        conn::write_frame(&mut c, b"{\"t\":\"hs\"}").unwrap();
        assert_eq!(
            conn::read_frame(&mut c).unwrap().unwrap(),
            b"{\"t\":\"hs\"}"
        );
        c.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(read_all(&mut c).is_empty());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
