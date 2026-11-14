//! App settings, stored next to "Son kasalar" in %LOCALAPPDATA% (JSON). Only
//! non-secret preferences. A missing or invalid file means defaults.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use serde::{Deserialize, Serialize};

/// Allowed auto-lock choices in minutes. There is deliberately no "never".
pub const IDLE_CHOICES: [u32; 7] = [1, 2, 5, 10, 15, 30, 60];
pub const DEFAULT_IDLE_MINUTES: u32 = 5;
const MAX_FILE_BYTES: u64 = 16 * 1024;

/// The idle timeout in effect, read by the auto-lock thread.
static IDLE_MINUTES: AtomicU32 = AtomicU32::new(DEFAULT_IDLE_MINUTES);
static FETCH_ICONS: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub idle_minutes: u32,
    /// Download site icons. Off by default: contacting a site tells it (and
    /// the network) which accounts are in the vault.
    #[serde(default)]
    pub fetch_icons: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            idle_minutes: DEFAULT_IDLE_MINUTES,
            fetch_icons: false,
        }
    }
}

impl Settings {
    /// Unknown values fall back to the default instead of failing.
    pub fn sanitized(self) -> Settings {
        Settings {
            idle_minutes: if IDLE_CHOICES.contains(&self.idle_minutes) {
                self.idle_minutes
            } else {
                DEFAULT_IDLE_MINUTES
            },
            fetch_icons: self.fetch_icons,
        }
    }
}

pub fn idle_minutes() -> u32 {
    IDLE_MINUTES.load(Ordering::Relaxed)
}

pub fn apply(s: Settings) {
    let s = s.sanitized();
    IDLE_MINUTES.store(s.idle_minutes, Ordering::Relaxed);
    FETCH_ICONS.store(s.fetch_icons, Ordering::Relaxed);
}

pub fn fetch_icons() -> bool {
    FETCH_ICONS.load(Ordering::Relaxed)
}

pub fn current() -> Settings {
    Settings {
        idle_minutes: idle_minutes(),
        fetch_icons: fetch_icons(),
    }
}

pub fn load(file: &Path) -> Settings {
    let Ok(f) = fs::File::open(file) else {
        return Settings::default();
    };
    let mut buf = Vec::new();
    if f.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf).is_err()
        || buf.len() as u64 > MAX_FILE_BYTES
    {
        return Settings::default();
    }
    serde_json::from_slice::<Settings>(&buf)
        .unwrap_or_default()
        .sanitized()
}

pub fn save(file: &Path, s: Settings) -> std::io::Result<()> {
    if let Some(dir) = file.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = file.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(&s.sanitized()).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_choices_are_accepted() {
        assert_eq!(
            Settings {
                idle_minutes: 15,
                fetch_icons: false
            }
            .sanitized()
            .idle_minutes,
            15
        );
        assert_eq!(
            Settings {
                idle_minutes: 0,
                fetch_icons: false
            }
            .sanitized()
            .idle_minutes,
            5,
            "no 'never'"
        );
        assert_eq!(
            Settings {
                idle_minutes: 9999,
                fetch_icons: false
            }
            .sanitized()
            .idle_minutes,
            5
        );
    }

    #[test]
    fn roundtrip_and_bad_files() {
        let dir = std::env::temp_dir().join(format!("lav-settings-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let file = dir.join("settings.json");
        assert_eq!(load(&file), Settings::default());
        save(
            &file,
            Settings {
                idle_minutes: 30,
                fetch_icons: true,
            },
        )
        .unwrap();
        assert_eq!(load(&file).idle_minutes, 30);
        assert!(load(&file).fetch_icons);
        fs::write(&file, br#"{"idleMinutes": 0}"#).unwrap();
        assert_eq!(load(&file).idle_minutes, 5);
        fs::write(&file, b"garbage").unwrap();
        assert_eq!(load(&file), Settings::default());
        let _ = fs::remove_dir_all(dir);
    }
}
