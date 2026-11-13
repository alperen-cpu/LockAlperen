//! UI session state, independent of Tauri so it can be unit-tested.
//!
//! Design rules (see SECURITY.md, "Faz 2"):
//! - The vault path lives here only. The WebView never sends a path, so a
//!   script injected into the WebView cannot make the app open arbitrary files.
//! - Nothing secret leaves this module: entry summaries carry no password,
//!   notes, TOTP, custom fields or attachments.
//! - Every unlock failure (`lav_core::Error::is_unlock_failure`) is reported
//!   with one generic message, so the UI never reveals which check failed.

use std::io::Read;
use std::path::PathBuf;

use lav_core::format::{HEADER_LEN, TAG_LEN};
use lav_core::Vault;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// What the list view may show about an entry. Deliberately excludes every
/// secret field of `lav_core::Entry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub group_id: String,
    pub group: String,
}

/// What the unlock screen shows about the chosen file. The KDF values come
/// from the header BEFORE it is authenticated: display only, never a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedFile {
    pub file_name: String,
    pub folder: String,
    pub kdf: Option<KdfInfo>,
    pub keyfile_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfInfo {
    pub memory_mib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub name: String,
    pub entry_count: usize,
}

#[derive(Default)]
pub struct Session {
    path: Option<PathBuf>,
    vault: Option<Vault>,
}

pub const NO_FILE_SELECTED: &str = "Önce bir kasa dosyası seçin.";
pub const LOCKED: &str = "Kasa kilitli.";
pub const NO_SUCH_ENTRY: &str = "Kayıt bulunamadı.";

/// A field the user can copy. Only these two can leave the vault, and only
/// on an explicit click.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Username,
    Password,
}
/// Turkish counterpart of `lav_core::error::UNLOCK_FAILED_MESSAGE`.
pub const UNLOCK_FAILED: &str =
    "Kasa açılamadı: parola ya da anahtar dosyası yanlış, ya da dosya bozuk veya desteklenmiyor.";
/// Everything that is not an unlock failure (I/O, file too large, ...).
pub const READ_FAILED: &str = "Kasa dosyası okunamadı.";

fn unlock_error(e: &lav_core::Error) -> String {
    if e.is_unlock_failure() {
        UNLOCK_FAILED
    } else {
        READ_FAILED
    }
    .to_owned()
}

impl Session {
    /// Selects the file to unlock. Selecting a file always locks the session
    /// first: an open vault must never be shown under another file's name.
    pub fn select(&mut self, path: PathBuf) -> SelectedFile {
        self.lock();
        let header = read_header(&path);
        let info = SelectedFile {
            file_name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            folder: path
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            kdf: header.as_ref().map(|h| KdfInfo {
                memory_mib: h.kdf.memory_kib / 1024,
                iterations: h.kdf.iterations,
                parallelism: h.kdf.parallelism,
            }),
            keyfile_required: header.is_some_and(|h| h.requires_keyfile()),
        };
        self.path = Some(path);
        info
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    pub fn unlock(&mut self, password: &str) -> Result<VaultInfo, String> {
        // A new attempt always starts from the locked state.
        self.lock();
        let path = self.path.as_deref().ok_or(NO_FILE_SELECTED)?;
        let vault = Vault::open_file(path, password, None).map_err(|e| unlock_error(&e))?;
        let info = VaultInfo {
            name: vault.data.name.clone(),
            entry_count: vault.data.entries.len(),
        };
        self.vault = Some(vault);
        Ok(info)
    }

    /// Drops the vault; `lav_core` wipes keys and contents on drop.
    pub fn lock(&mut self) {
        self.vault = None;
    }

    /// One field of one entry, in a buffer that wipes itself.
    pub fn field(&self, id: &str, field: Field) -> Result<Zeroizing<String>, String> {
        let vault = self.vault.as_ref().ok_or(LOCKED)?;
        let e = vault
            .data
            .entries
            .iter()
            .find(|e| e.id.to_string() == id)
            .ok_or(NO_SUCH_ENTRY)?;
        Ok(Zeroizing::new(match field {
            Field::Username => e.username.clone(),
            Field::Password => e.password.expose().to_owned(),
        }))
    }

    pub fn entries(&self) -> Result<Vec<EntrySummary>, String> {
        let vault = self.vault.as_ref().ok_or(LOCKED)?;
        let data = &vault.data;
        let mut list: Vec<EntrySummary> = data
            .entries
            .iter()
            .map(|e| EntrySummary {
                id: e.id.to_string(),
                group_id: e.group.to_string(),
                title: e.title.clone(),
                username: e.username.clone(),
                url: e.url.clone(),
                group: data
                    .group(e.group)
                    .map(|g| g.name.clone())
                    .unwrap_or_default(),
            })
            .collect();
        list.sort_by_cached_key(|e| e.title.to_lowercase());
        Ok(list)
    }
}

/// Reads just the header. Any failure means "unknown"; the unlock attempt
/// reports the real error with the generic message.
fn read_header(path: &std::path::Path) -> Option<lav_core::format::Header> {
    // The parser also wants room for at least an AEAD tag after the header.
    let mut buf = [0u8; HEADER_LEN + TAG_LEN];
    std::fs::File::open(path).ok()?.read_exact(&mut buf).ok()?;
    Vault::peek_header(&buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lav_core::{Entry, KdfParams};
    use std::path::Path;

    const PASSWORD: &str = "correct horse battery";
    const SECRET: &str = "hunter2-very-secret";
    const NOTE: &str = "recovery code 1234-5678";

    fn fast_kdf() -> KdfParams {
        KdfParams {
            memory_kib: KdfParams::MIN_MEMORY_KIB,
            iterations: KdfParams::MIN_ITERATIONS,
            parallelism: KdfParams::MIN_PARALLELISM,
        }
    }

    fn make_vault(dir: &Path) -> PathBuf {
        let mut v = Vault::create("Kişisel", PASSWORD, None, fast_kdf()).unwrap();
        let mut a = Entry::new(v.data.root, "zeta");
        a.username = "me@example.com".into();
        a.password = SECRET.into();
        a.notes = NOTE.into();
        a.url = "https://example.com".into();
        v.data.add_entry(a).unwrap();
        v.data.add_entry(Entry::new(v.data.root, "Alpha")).unwrap();
        let path = dir.join("kasa.lav");
        v.save_file(&path).unwrap();
        path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lav-desktop-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn unlock_requires_a_selected_file() {
        let mut s = Session::default();
        assert_eq!(s.unlock(PASSWORD), Err(NO_FILE_SELECTED.to_owned()));
        assert!(!s.is_unlocked());
    }

    #[test]
    fn unlock_list_and_lock() {
        let dir = temp_dir("ok");
        let mut s = Session::default();
        s.select(make_vault(&dir));

        let info = s.unlock(PASSWORD).unwrap();
        assert_eq!(info.name, "Kişisel");
        assert_eq!(info.entry_count, 2);

        let list = s.entries().unwrap();
        let titles: Vec<_> = list.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["Alpha", "zeta"], "sorted case-insensitively");
        assert_eq!(list[1].username, "me@example.com");
        assert_eq!(list[1].group, "Kişisel");

        s.lock();
        assert!(!s.is_unlocked());
        assert_eq!(s.entries(), Err(LOCKED.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn summaries_never_contain_secrets() {
        let dir = temp_dir("secrets");
        let mut s = Session::default();
        s.select(make_vault(&dir));
        s.unlock(PASSWORD).unwrap();
        // What actually crosses the IPC boundary is the JSON.
        let json = serde_json::to_string(&s.entries().unwrap()).unwrap();
        assert!(
            json.contains("me@example.com"),
            "sanity: the JSON is the list"
        );
        assert!(!json.contains(SECRET));
        assert!(!json.contains(NOTE));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_password_gives_the_generic_message_and_stays_locked() {
        let dir = temp_dir("wrong");
        let mut s = Session::default();
        s.select(make_vault(&dir));
        assert_eq!(s.unlock("wrong password"), Err(UNLOCK_FAILED.to_owned()));
        assert!(!s.is_unlocked());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_file_gives_the_same_generic_message() {
        let dir = temp_dir("corrupt");
        let path = make_vault(&dir);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let mut s = Session::default();
        s.select(path);
        assert_eq!(s.unlock(PASSWORD), Err(UNLOCK_FAILED.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_attempt_or_new_selection_locks_an_open_vault() {
        let dir = temp_dir("relock");
        let path = make_vault(&dir);
        let mut s = Session::default();
        s.select(path.clone());
        s.unlock(PASSWORD).unwrap();
        assert!(s.unlock("wrong password").is_err());
        assert!(!s.is_unlocked(), "failed retry must not keep the old vault");

        s.unlock(PASSWORD).unwrap();
        s.select(path);
        assert!(!s.is_unlocked(), "selecting a file must lock");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn selecting_shows_the_file_and_its_declared_kdf() {
        let dir = temp_dir("select");
        let mut s = Session::default();
        let info = s.select(make_vault(&dir));
        assert_eq!(info.file_name, "kasa.lav");
        assert_eq!(
            info.kdf,
            Some(KdfInfo {
                memory_mib: KdfParams::MIN_MEMORY_KIB / 1024,
                iterations: KdfParams::MIN_ITERATIONS,
                parallelism: KdfParams::MIN_PARALLELISM,
            })
        );
        assert!(!info.keyfile_required);

        let other = s.select(dir.join("yok.lav"));
        assert_eq!(other.kdf, None, "unreadable file: no KDF shown");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn field_reads_one_value_and_needs_an_open_vault() {
        let dir = temp_dir("field");
        let mut s = Session::default();
        s.select(make_vault(&dir));
        assert_eq!(s.field("x", Field::Password), Err(LOCKED.to_owned()));
        s.unlock(PASSWORD).unwrap();
        let id = s
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.title == "zeta")
            .unwrap()
            .id;
        assert_eq!(s.field(&id, Field::Password).unwrap().as_str(), SECRET);
        assert_eq!(
            s.field(&id, Field::Username).unwrap().as_str(),
            "me@example.com"
        );
        assert_eq!(
            s.field("not-an-id", Field::Password),
            Err(NO_SUCH_ENTRY.to_owned())
        );
        s.lock();
        assert_eq!(s.field(&id, Field::Password), Err(LOCKED.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn field_names_from_the_webview() {
        let f: Field = serde_json::from_str("\"password\"").unwrap();
        assert_eq!(f, Field::Password);
        assert!(serde_json::from_str::<Field>("\"notes\"").is_err());
    }

    #[test]
    fn missing_file_is_a_read_error_not_an_unlock_failure() {
        let dir = temp_dir("missing");
        let mut s = Session::default();
        s.select(dir.join("yok.lav"));
        assert_eq!(s.unlock(PASSWORD), Err(READ_FAILED.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }
}
