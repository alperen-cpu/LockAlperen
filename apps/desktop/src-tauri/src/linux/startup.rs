//! "Oturum açılışında başlat" on Linux: an XDG autostart entry for the
//! current user (`~/.config/autostart/`), which GNOME, KDE and the other
//! desktops read at login. Nothing system-wide, no administrator rights.
//! The Windows twin (HKCU Run key) is src/startup.rs.
//!
//! Started from an AppImage, the entry names the AppImage file itself
//! (`$APPIMAGE`): the running binary lives in a temporary mount.

use std::path::{Path, PathBuf};

const FILE_NAME: &str = "com.alperen.lockalperen.desktop";
const FAILED: &str = "Oturum açılışında başlatma ayarı değiştirilemedi.";

fn autostart_dir() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(config.join("autostart"))
}

/// The program the entry starts.
fn program() -> Option<PathBuf> {
    std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::current_exe().ok())
}

/// The `Exec=` value: the path quoted as the Desktop Entry specification
/// asks, or None for a path that cannot be written there.
pub fn exec_value(exe: &Path) -> Option<String> {
    let path = exe.to_str()?;
    if path.chars().any(char::is_control) {
        return None;
    }
    let mut quoted = String::from("\"");
    for c in path.chars() {
        match c {
            '"' | '`' | '$' | '\\' => {
                quoted.push('\\');
                quoted.push(c);
            }
            '%' => quoted.push_str("%%"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    // String values of a desktop file escape the backslash once more.
    Some(quoted.replace('\\', "\\\\"))
}

/// The whole autostart file for `exe`.
pub fn entry(exe: &Path) -> Option<String> {
    Some(format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=LockAlperen\n\
         Comment=Parola kasası\n\
         Exec={}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        exec_value(exe)?
    ))
}

fn enabled_in(dir: &Path) -> bool {
    dir.join(FILE_NAME).is_file()
}

fn set_in(dir: &Path, on: bool, exe: &Path) -> Result<(), &'static str> {
    let file = dir.join(FILE_NAME);
    if !on {
        return match std::fs::remove_file(&file) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(FAILED),
        };
    }
    let text = entry(exe).ok_or(FAILED)?;
    (|| -> std::io::Result<()> {
        // 0600 like the app's other files: a group-writable autostart
        // entry would let a group member choose what runs at login.
        std::fs::create_dir_all(dir)?;
        crate::private::write_atomic(&file, "desktop.tmp", text.as_bytes())
    })()
    .map_err(|_| FAILED)
}

/// Whether our autostart entry exists.
pub fn enabled() -> bool {
    autostart_dir().is_some_and(|d| enabled_in(&d))
}

/// Writes (true) or removes (false) our entry. Removing a missing entry is
/// not an error.
pub fn set(on: bool) -> Result<(), &'static str> {
    let dir = autostart_dir().ok_or(FAILED)?;
    let exe = program().ok_or(FAILED)?;
    set_in(&dir, on, &exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_is_quoted_by_the_spec() {
        assert_eq!(
            exec_value(Path::new("/usr/bin/lockalperen")).as_deref(),
            Some("\"/usr/bin/lockalperen\"")
        );
        assert_eq!(
            exec_value(Path::new("/home/a b/İndirilenler/Lock$1%.AppImage")).as_deref(),
            Some("\"/home/a b/İndirilenler/Lock\\\\$1%%.AppImage\"")
        );
        assert_eq!(exec_value(Path::new("/tmp/x\ny")), None);
    }

    #[test]
    fn set_and_clear_in_a_directory() {
        let dir = std::env::temp_dir().join(format!("lav-autostart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let exe = Path::new("/opt/LockAlperen/lockalperen");
        assert!(!enabled_in(&dir));
        set_in(&dir, true, exe).unwrap();
        assert!(enabled_in(&dir));
        let text = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(text.contains("\nExec=\"/opt/LockAlperen/lockalperen\"\n"));
        set_in(&dir, false, exe).unwrap();
        assert!(!enabled_in(&dir));
        set_in(&dir, false, exe).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
