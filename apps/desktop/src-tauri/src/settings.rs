//! App settings, stored next to "Son kasalar" in %LOCALAPPDATA% (JSON). Only
//! non-secret preferences. A missing or invalid file means defaults.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use serde::{Deserialize, Deserializer, Serialize};

/// Allowed auto-lock choices in minutes. There is deliberately no "never".
pub const IDLE_CHOICES: [u32; 7] = [1, 2, 5, 10, 15, 30, 60];
pub const DEFAULT_IDLE_MINUTES: u32 = 5;
/// Seconds before a copied value is cleared. There is deliberately no "never".
pub const CLIPBOARD_CHOICES: [u32; 9] = [5, 10, 12, 15, 20, 30, 45, 60, 90];
pub const DEFAULT_CLIPBOARD_SECONDS: u32 = 12;
const MAX_FILE_BYTES: u64 = 16 * 1024;

/// The idle timeout in effect, read by the auto-lock thread.
static IDLE_MINUTES: AtomicU32 = AtomicU32::new(DEFAULT_IDLE_MINUTES);

static CLIPBOARD_SECONDS: AtomicU32 = AtomicU32::new(DEFAULT_CLIPBOARD_SECONDS);

/// Whether Win+L, sleep, disconnect and logoff lock the vault (default on).
static LOCK_ON_SYSTEM_EVENTS: AtomicBool = AtomicBool::new(true);

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

/// How the entry list is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListStyle {
    #[default]
    List = 0,
    Compact = 1,
    Grid = 2,
    Table = 3,
}

impl ListStyle {
    fn from_u8(v: u8) -> ListStyle {
        [
            ListStyle::List,
            ListStyle::Compact,
            ListStyle::Grid,
            ListStyle::Table,
        ]
        .into_iter()
        .find(|t| *t as u8 == v)
        .unwrap_or_default()
    }
}

static LIST_STYLE: AtomicU8 = AtomicU8::new(ListStyle::List as u8);

/// Global shortcut that brings the window forward (KeePass "Show KeePass
/// window", default Ctrl+Alt+K there too).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShowShortcut {
    Off = 0,
    #[default]
    CtrlAltK = 1,
    CtrlAltShiftW = 2,
}

impl ShowShortcut {
    #[cfg(test)]
    pub const ALL: [ShowShortcut; 3] = [
        ShowShortcut::Off,
        ShowShortcut::CtrlAltK,
        ShowShortcut::CtrlAltShiftW,
    ];
}

/// Password generator defaults (KeePass "Auto-generated passwords for new
/// entries" profile). Bounds are the core generator's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Generator {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for Generator {
    fn default() -> Self {
        Generator {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl Generator {
    /// Length within the generator's limits and at least one character set.
    pub fn sanitized(self) -> Generator {
        let mut g = self;
        g.length = g.length.clamp(MIN_GEN_LENGTH, MAX_GEN_LENGTH);
        if !(g.lowercase || g.uppercase || g.digits || g.symbols) {
            g = Generator {
                length: g.length,
                ..Generator::default()
            };
        }
        g
    }
}

pub const MIN_GEN_LENGTH: usize = 8;
pub const MAX_GEN_LENGTH: usize = 128;

/// A saved generator profile (KeePass "Password Generator" profiles):
/// character classes and length, or a pattern (see lav_core PATTERN_HELP).
/// Kept in its own file next to settings.json, because `Settings` is a small
/// `Copy` value read from many threads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GenProfile {
    pub name: String,
    #[serde(flatten)]
    pub classes: Generator,
    /// Non-empty = generate from this pattern instead of the classes.
    pub pattern: String,
}

pub const MAX_PROFILES: usize = 30;
pub const MAX_PATTERN_CHARS: usize = 300;

/// Drops profiles without a name or with a pattern that does not work, cuts
/// names to 64 characters, keeps the first of duplicate names, at most
/// MAX_PROFILES.
pub fn sanitize_profiles(list: Vec<GenProfile>) -> Vec<GenProfile> {
    let mut out: Vec<GenProfile> = Vec::new();
    for mut p in list {
        p.name = p.name.trim().chars().take(64).collect();
        p.pattern = p.pattern.trim().to_owned();
        if p.name.is_empty()
            || out.iter().any(|o| o.name.eq_ignore_ascii_case(&p.name))
            || p.pattern.chars().count() > MAX_PATTERN_CHARS
            || (!p.pattern.is_empty() && lav_core::generate_pattern(&p.pattern).is_err())
        {
            continue;
        }
        p.classes = p.classes.sanitized();
        out.push(p);
        if out.len() == MAX_PROFILES {
            break;
        }
    }
    out
}

pub fn load_profiles(file: &Path) -> Vec<GenProfile> {
    let Ok(f) = fs::File::open(file) else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if f.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf).is_err()
        || buf.len() as u64 > MAX_FILE_BYTES
    {
        return Vec::new();
    }
    sanitize_profiles(serde_json::from_slice::<Vec<GenProfile>>(&buf).unwrap_or_default())
}

pub fn save_profiles(file: &Path, list: &[GenProfile]) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(list).map_err(std::io::Error::other)?;
    crate::private::write_atomic(file, "json.tmp", &bytes)
}

/// The full settings in effect (the atomics above are kept for the hot
/// paths that read single values from other threads).
static CURRENT: std::sync::LazyLock<std::sync::RwLock<Settings>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(Settings::default()));

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
    #[serde(deserialize_with = "lenient")]
    pub list_style: ListStyle,
    pub clipboard_seconds: u32,
    pub lock_on_system_events: bool,
    // ----- From KeePass "Options" (all off unless KeePass has them on by
    // default), so an older settings.json keeps today's behaviour. -----
    /// Security: lock when the window is minimized (taskbar or tray).
    pub lock_on_minimize: bool,
    /// Security: quit instead of locking when the idle time runs out.
    pub exit_instead_of_lock: bool,
    /// Interface: minimize the window after copying a value.
    pub minimize_after_copy: bool,
    /// Interface: minimize the window after locking.
    pub minimize_on_lock: bool,
    /// Interface: the window stays above other windows.
    pub always_on_top: bool,
    /// Interface: the minimize button hides the window to the tray.
    pub minimize_to_tray: bool,
    /// Advanced: start minimized (and locked: it always starts locked).
    pub start_minimized: bool,
    /// Integration: global "show window" shortcut.
    #[serde(deserialize_with = "lenient")]
    pub show_window_shortcut: ShowShortcut,
    /// Integration: start with Windows. The Run key in the registry is the
    /// truth; this mirrors it for the UI.
    pub run_at_startup: bool,
    /// Advanced: after unlocking, show entries that expired or expire soon.
    pub show_expired_on_open: bool,
    /// Generator: new entries start with a generated password (as KeePass).
    pub auto_generate_password: bool,
    #[serde(deserialize_with = "lenient")]
    pub generator: Generator,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            idle_minutes: DEFAULT_IDLE_MINUTES,
            check_updates: true,
            close_to_tray: true,
            autotype_shortcut: Shortcut::CtrlAltA,
            theme: Theme::System,
            list_style: ListStyle::List,
            clipboard_seconds: DEFAULT_CLIPBOARD_SECONDS,
            lock_on_system_events: true,
            lock_on_minimize: false,
            exit_instead_of_lock: false,
            minimize_after_copy: false,
            minimize_on_lock: false,
            always_on_top: false,
            minimize_to_tray: false,
            start_minimized: false,
            show_window_shortcut: ShowShortcut::CtrlAltK,
            run_at_startup: false,
            show_expired_on_open: false,
            auto_generate_password: true,
            generator: Generator::default(),
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
            list_style: self.list_style,
            clipboard_seconds: if CLIPBOARD_CHOICES.contains(&self.clipboard_seconds) {
                self.clipboard_seconds
            } else {
                DEFAULT_CLIPBOARD_SECONDS
            },
            lock_on_system_events: self.lock_on_system_events,
            generator: self.generator.sanitized(),
            ..self
        }
    }
}

fn read() -> Settings {
    CURRENT.read().map(|s| *s).unwrap_or_default()
}

pub fn lock_on_minimize() -> bool {
    read().lock_on_minimize
}
pub fn exit_instead_of_lock() -> bool {
    read().exit_instead_of_lock
}
pub fn minimize_after_copy() -> bool {
    read().minimize_after_copy
}
pub fn minimize_on_lock() -> bool {
    read().minimize_on_lock
}
pub fn minimize_to_tray() -> bool {
    read().minimize_to_tray
}
pub fn show_window_shortcut() -> ShowShortcut {
    read().show_window_shortcut
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
    LIST_STYLE.store(s.list_style as u8, Ordering::Relaxed);
    CLIPBOARD_SECONDS.store(s.clipboard_seconds, Ordering::Relaxed);
    LOCK_ON_SYSTEM_EVENTS.store(s.lock_on_system_events, Ordering::Relaxed);
    if let Ok(mut g) = CURRENT.write() {
        *g = s;
    }
}

pub fn clipboard_seconds() -> u32 {
    CLIPBOARD_SECONDS.load(Ordering::Relaxed)
}

pub fn lock_on_system_events() -> bool {
    LOCK_ON_SYSTEM_EVENTS.load(Ordering::Relaxed)
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
        list_style: ListStyle::from_u8(LIST_STYLE.load(Ordering::Relaxed)),
        clipboard_seconds: clipboard_seconds(),
        lock_on_system_events: lock_on_system_events(),
        ..read()
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
    let bytes = serde_json::to_vec_pretty(&s.sanitized()).map_err(std::io::Error::other)?;
    crate::private::write_atomic(file, "json.tmp", &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_profiles_are_checked_and_saved() {
        let p = |name: &str, pattern: &str| GenProfile {
            name: name.into(),
            pattern: pattern.into(),
            ..Default::default()
        };
        let clean = sanitize_profiles(vec![
            p("  Banka PIN ", "d{6}"),
            p("", "d"),
            p("banka pin", "d{4}"),
            p("Bozuk", "d{0}"),
            GenProfile {
                name: "Uzun".into(),
                classes: Generator {
                    length: 9999,
                    lowercase: false,
                    uppercase: false,
                    digits: false,
                    symbols: false,
                    exclude_ambiguous: false,
                },
                pattern: String::new(),
            },
        ]);
        let names: Vec<&str> = clean.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["Banka PIN", "Uzun"]);
        assert_eq!(clean[1].classes.length, MAX_GEN_LENGTH);
        assert!(clean[1].classes.lowercase, "no class: back to the default");

        let dir = std::env::temp_dir().join(format!("lav-prof-{}", std::process::id()));
        let file = dir.join("generator-profiles.json");
        assert!(load_profiles(&file).is_empty());
        save_profiles(&file, &clean).unwrap();
        assert_eq!(load_profiles(&file), clean);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
                list_style: ListStyle::Grid,
                clipboard_seconds: 30,
                lock_on_system_events: false,
                ..Default::default()
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
                list_style: ListStyle::Grid,
                clipboard_seconds: 30,
                lock_on_system_events: false,
                ..Default::default()
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
                list_style: ListStyle::List,
                clipboard_seconds: DEFAULT_CLIPBOARD_SECONDS,
                lock_on_system_events: true,
                ..Default::default()
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
        // List style: unknown -> the plain list; others kept.
        let s: Settings = serde_json::from_slice(br#"{"listStyle": "mosaic"}"#).unwrap();
        assert_eq!(s.list_style, ListStyle::List);
        let s: Settings = serde_json::from_slice(br#"{"listStyle": "table"}"#).unwrap();
        assert_eq!(s.list_style, ListStyle::Table);
        // Clipboard time: only listed choices, no "never"; older files keep
        // the defaults (12 s, lock on Win+L / sleep / logoff).
        assert_eq!(s.clipboard_seconds, DEFAULT_CLIPBOARD_SECONDS);
        assert!(s.lock_on_system_events);
        for bad in [0u32, 1, 3600, u32::MAX] {
            let s = Settings {
                clipboard_seconds: bad,
                ..Default::default()
            }
            .sanitized();
            assert_eq!(s.clipboard_seconds, DEFAULT_CLIPBOARD_SECONDS, "{bad}");
        }
        let s = Settings {
            clipboard_seconds: 45,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(s.clipboard_seconds, 45);
        assert_eq!(
            serde_json::to_value(Shortcut::CtrlAltShiftK).unwrap(),
            "ctrl-alt-shift-k"
        );
    }

    /// KeePass options: an older file gets today's behaviour, values round
    /// trip, and a bad generator profile is repaired.
    #[test]
    fn keepass_options() {
        let s: Settings = serde_json::from_slice(br#"{"idleMinutes": 30}"#).unwrap();
        assert!(!s.lock_on_minimize && !s.exit_instead_of_lock && !s.minimize_after_copy);
        assert!(!s.minimize_on_lock && !s.always_on_top && !s.minimize_to_tray);
        assert!(!s.start_minimized && !s.run_at_startup && !s.show_expired_on_open);
        assert!(s.auto_generate_password);
        assert_eq!(s.show_window_shortcut, ShowShortcut::CtrlAltK);
        assert_eq!(s.generator, Generator::default());

        let s: Settings = serde_json::from_slice(
            br#"{"minimizeAfterCopy": true, "showWindowShortcut": "ctrl-f9",
                "generator": {"length": 20, "symbols": false}}"#,
        )
        .unwrap();
        assert!(s.minimize_after_copy);
        assert_eq!(
            s.show_window_shortcut,
            ShowShortcut::CtrlAltK,
            "unknown: default"
        );
        assert_eq!(s.generator.length, 20);
        assert!(!s.generator.symbols && s.generator.digits);

        for (len, want) in [(0, MIN_GEN_LENGTH), (9999, MAX_GEN_LENGTH), (32, 32)] {
            let g = Generator {
                length: len,
                ..Generator::default()
            }
            .sanitized();
            assert_eq!(g.length, want);
        }
        let none = Generator {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            length: 30,
            exclude_ambiguous: true,
        }
        .sanitized();
        assert_eq!(
            none,
            Generator {
                length: 30,
                ..Generator::default()
            }
        );

        let v = Settings {
            lock_on_minimize: true,
            always_on_top: true,
            show_window_shortcut: ShowShortcut::Off,
            ..Default::default()
        };
        let back: Settings = serde_json::from_value(serde_json::to_value(v).unwrap()).unwrap();
        assert_eq!(back, v);
        assert_eq!(
            serde_json::to_value(ShowShortcut::CtrlAltShiftW).unwrap(),
            "ctrl-alt-shift-w"
        );
    }
}
