//! App settings, stored next to "Son kasalar" in %LOCALAPPDATA% (JSON). Only
//! non-secret preferences. A missing or invalid file means defaults.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use serde::{Deserialize, Deserializer, Serialize};

/// Allowed auto-lock choices in minutes. There is deliberately no "never".
pub const IDLE_CHOICES: [u32; 7] = [1, 2, 5, 10, 15, 30, 60];
pub const DEFAULT_IDLE_MINUTES: u32 = 5;
const MAX_FILE_BYTES: u64 = 16 * 1024;

/// The idle timeout in effect, read by the auto-lock thread.
static IDLE_MINUTES: AtomicU32 = AtomicU32::new(DEFAULT_IDLE_MINUTES);

/// Whether to look for a new version at startup (docs/UPDATES.md).
static CHECK_UPDATES: AtomicBool = AtomicBool::new(true);

/// Whether the window's close button hides it to the tray (src/tray.rs).
static CLOSE_TO_TRAY: AtomicBool = AtomicBool::new(true);

/// The global auto-type shortcut (src/hotkey.rs), as `Shortcut as u8`.
static AUTOTYPE_SHORTCUT: AtomicU8 = AtomicU8::new(Shortcut::CtrlAltA as u8);

/// Choices for the global auto-type shortcut. A fixed list: another program
/// may already own one, so the user picks a free one (Settings warns).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Shortcut {
    Off = 0,
    /// KeePass's default.
    #[default]
    CtrlAltA = 1,
    CtrlAltShiftA = 2,
    CtrlAltShiftK = 3,
    CtrlAltShiftL = 4,
}

impl Shortcut {
    pub const ALL: [Shortcut; 5] = [
        Shortcut::Off,
        Shortcut::CtrlAltA,
        Shortcut::CtrlAltShiftA,
        Shortcut::CtrlAltShiftK,
        Shortcut::CtrlAltShiftL,
    ];

    fn from_u8(v: u8) -> Shortcut {
        Self::ALL
            .into_iter()
            .find(|s| *s as u8 == v)
            .unwrap_or_default()
    }
}

/// Colour theme of the window. `System` follows Windows (light or dark).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System = 0,
    Light = 1,
    Dark = 2,
}

impl Theme {
    fn from_u8(v: u8) -> Theme {
        [Theme::System, Theme::Light, Theme::Dark]
            .into_iter()
            .find(|t| *t as u8 == v)
            .unwrap_or_default()
    }
}

static THEME: AtomicU8 = AtomicU8::new(Theme::System as u8);

/// An unknown value (e.g. from a newer version) means the default for this
/// field only, instead of failing the whole file.
fn lenient<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned + Default,
{
    let v = serde_json::Value::deserialize(d)?;
    Ok(serde_json::from_value(v).unwrap_or_default())
}

/// Missing fields take their default, so a file written by an older version
/// keeps the values it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub idle_minutes: u32,
    pub check_updates: bool,
    pub close_to_tray: bool,
    #[serde(deserialize_with = "lenient")]
    pub autotype_shortcut: Shortcut,
    #[serde(deserialize_with = "lenient")]
    pub theme: Theme,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            idle_minutes: DEFAULT_IDLE_MINUTES,
            check_updates: true,
            close_to_tray: true,
            autotype_shortcut: Shortcut::CtrlAltA,
            theme: Theme::System,
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
            check_updates: self.check_updates,
            close_to_tray: self.close_to_tray,
            autotype_shortcut: self.autotype_shortcut,
            theme: self.theme,
        }
    }
}

pub fn idle_minutes() -> u32 {
    IDLE_MINUTES.load(Ordering::Relaxed)
}

pub fn apply(s: Settings) {
    let s = s.sanitized();
    IDLE_MINUTES.store(s.idle_minutes, Ordering::Relaxed);
    CHECK_UPDATES.store(s.check_updates, Ordering::Relaxed);
    CLOSE_TO_TRAY.store(s.close_to_tray, Ordering::Relaxed);
    AUTOTYPE_SHORTCUT.store(s.autotype_shortcut as u8, Ordering::Relaxed);
    THEME.store(s.theme as u8, Ordering::Relaxed);
}

pub fn autotype_shortcut() -> Shortcut {
    Shortcut::from_u8(AUTOTYPE_SHORTCUT.load(Ordering::Relaxed))
}

pub fn close_to_tray() -> bool {
    CLOSE_TO_TRAY.load(Ordering::Relaxed)
}

pub fn current() -> Settings {
    Settings {
        idle_minutes: idle_minutes(),
        check_updates: CHECK_UPDATES.load(Ordering::Relaxed),
        close_to_tray: close_to_tray(),
        autotype_shortcut: autotype_shortcut(),
        theme: Theme::from_u8(THEME.load(Ordering::Relaxed)),
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
                ..Default::default()
            }
            .sanitized()
            .idle_minutes,
            15
        );
        assert_eq!(
            Settings {
                idle_minutes: 0,
                ..Default::default()
            }
            .sanitized()
            .idle_minutes,
            5,
            "no 'never'"
        );
        assert_eq!(
            Settings {
                idle_minutes: 9999,
                ..Default::default()
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
                check_updates: false,
                close_to_tray: false,
                autotype_shortcut: Shortcut::CtrlAltShiftL,
                theme: Theme::Dark,
            },
        )
        .unwrap();
        assert_eq!(
            load(&file),
            Settings {
                idle_minutes: 30,
                check_updates: false,
                close_to_tray: false,
                autotype_shortcut: Shortcut::CtrlAltShiftL,
                theme: Theme::Dark,
            }
        );
        assert_eq!(load(&file).idle_minutes, 30);
        fs::write(&file, br#"{"idleMinutes": 0}"#).unwrap();
        assert_eq!(load(&file).idle_minutes, 5);
        fs::write(&file, b"garbage").unwrap();
        assert_eq!(load(&file), Settings::default());
        let _ = fs::remove_dir_all(dir);
    }

    /// settings.json written before "checkUpdates" existed: the idle time the
    /// user chose survives, and update checks get their default (on).
    #[test]
    fn older_file_keeps_its_values() {
        let s: Settings = serde_json::from_slice(br#"{"idleMinutes": 30}"#).unwrap();
        assert_eq!(
            s,
            Settings {
                idle_minutes: 30,
                check_updates: true,
                close_to_tray: true,
                autotype_shortcut: Shortcut::CtrlAltA,
                theme: Theme::System,
            }
        );
        let s: Settings = serde_json::from_slice(br#"{"checkUpdates": false}"#).unwrap();
        assert_eq!(s.idle_minutes, DEFAULT_IDLE_MINUTES);
        assert!(!s.check_updates);
        assert!(s.close_to_tray);
        // A file written by 0.2.0 (before "closeToTray").
        let s: Settings =
            serde_json::from_slice(br#"{"idleMinutes": 15, "checkUpdates": false}"#).unwrap();
        assert_eq!(
            (s.idle_minutes, s.check_updates, s.close_to_tray),
            (15, false, true)
        );
        assert_eq!(
            s.autotype_shortcut,
            Shortcut::CtrlAltA,
            "new setting: default"
        );
        // An unknown shortcut (newer version) resets only that field.
        let s: Settings =
            serde_json::from_slice(br#"{"idleMinutes": 30, "autotypeShortcut": "ctrl-f13"}"#)
                .unwrap();
        assert_eq!(
            (s.idle_minutes, s.autotype_shortcut),
            (30, Shortcut::CtrlAltA)
        );
        let s: Settings = serde_json::from_slice(br#"{"autotypeShortcut": "off"}"#).unwrap();
        assert_eq!(s.autotype_shortcut, Shortcut::Off);
        // Theme: missing or unknown = follow Windows; others kept.
        assert_eq!(s.theme, Theme::System);
        let s: Settings =
            serde_json::from_slice(br#"{"idleMinutes": 15, "theme": "sepia"}"#).unwrap();
        assert_eq!((s.idle_minutes, s.theme), (15, Theme::System));
        let s: Settings = serde_json::from_slice(br#"{"theme": "dark"}"#).unwrap();
        assert_eq!(s.theme, Theme::Dark);
        assert_eq!(serde_json::to_value(Theme::Light).unwrap(), "light");
        assert_eq!(
            serde_json::to_value(Shortcut::CtrlAltShiftK).unwrap(),
            "ctrl-alt-shift-k"
        );
    }
}
