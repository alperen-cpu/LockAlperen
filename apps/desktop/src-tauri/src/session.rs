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
use lav_core::{Entry, Error as CoreError, KdfParams, PasswordOptions, Vault, VaultData};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

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
    pub has_totp: bool,
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
    /// Where "Yeni kasa" will be written, chosen in the save dialog.
    new_path: Option<PathBuf>,
}

pub const NO_FILE_SELECTED: &str = "Önce bir kasa dosyası seçin.";
pub const LOCKED: &str = "Kasa kilitli.";
pub const NO_SUCH_ENTRY: &str = "Kayıt bulunamadı.";
pub const NO_NEW_PATH: &str = "Önce yeni kasanın kaydedileceği yeri seçin.";
pub const PASSWORDS_DIFFER: &str = "Parolalar aynı değil.";
pub const EMPTY_NAME: &str = "Kasa adı boş olamaz.";
pub const WEAK_PASSWORD: &str = "Ana parola en az 8 karakter olmalı.";
pub const FILE_EXISTS: &str =
    "Bu adda bir dosya zaten var. Var olan bir dosyanın üzerine yazılmaz; başka bir ad seçin.";
pub const CREATE_FAILED: &str = "Kasa oluşturulamadı.";
pub const SAVE_FAILED: &str = "Kasa kaydedilemedi.";
pub const CHANGED_ON_DISK: &str = "Kasa dosyası başka bir yerde değiştirilmiş (başka bir pencere, \
     OneDrive ya da başka bir program). Üzerine yazılmadı; değişikliğiniz kaydedilmedi. Kasayı \
     kilitleyip yeniden açın.";
pub const EMPTY_TITLE: &str = "Başlık boş olamaz.";
pub const NO_SUCH_GROUP: &str = "Klasör bulunamadı.";
pub const BAD_GENERATOR: &str = "Bu ayarlarla parola üretilemez.";
pub const TOTP_INVALID: &str =
    "TOTP anahtarı geçersiz. Base32 anahtar ya da otpauth://totp/… bağlantısı girin.";
pub const NO_TOTP: &str = "Bu kayıtta TOTP yok.";

/// The current one-time code; the secret stays in Rust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub seconds_left: u64,
    pub period: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub id: String,
    pub name: String,
}

/// What the editor works on. Holds secrets (password, notes): wiped on drop
/// and never printed by `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryForm {
    /// None = new entry.
    pub id: Option<String>,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    /// Base32 secret or otpauth:// URI; empty = none.
    #[serde(default)]
    pub totp: String,
}

impl std::fmt::Debug for EntryForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryForm")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("password", &"<redacted>")
            .field("notes", &"<redacted>")
            .field("totp", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for EntryForm {
    fn drop(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
        self.totp.zeroize();
    }
}

/// Generator settings as the UI sends them.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

pub fn generate(o: &GenOptions) -> Result<Zeroizing<String>, String> {
    lav_core::generate_password(&PasswordOptions {
        length: o.length,
        lowercase: o.lowercase,
        uppercase: o.uppercase,
        digits: o.digits,
        symbols: o.symbols,
        exclude_ambiguous: o.exclude_ambiguous,
    })
    .map_err(|_| BAD_GENERATOR.to_owned())
}

fn tidy_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags.iter().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        if !out.iter().any(|o| o.eq_ignore_ascii_case(t)) {
            out.push(t.to_owned());
        }
    }
    out
}

/// A field the user can copy. Only these two can leave the vault, and only
/// on an explicit click.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Username,
    Password,
    /// The current one-time code (never the TOTP secret).
    Totp,
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

    /// Remembers where a new vault will go. Always adds the `.lav` extension.
    pub fn select_new(&mut self, mut path: PathBuf) -> String {
        if path
            .extension()
            .is_none_or(|e| !e.eq_ignore_ascii_case("lav"))
        {
            let mut name = path.file_name().unwrap_or_default().to_os_string();
            name.push(".lav");
            path.set_file_name(name);
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.new_path = Some(path);
        name
    }

    /// Creates, saves and opens a new vault at the chosen path. Never
    /// overwrites an existing file.
    pub fn create(
        &mut self,
        name: &str,
        password: &str,
        confirm: &str,
    ) -> Result<(SelectedFile, VaultInfo), String> {
        self.create_with(name, password, confirm, KdfParams::default())
    }

    fn create_with(
        &mut self,
        name: &str,
        password: &str,
        confirm: &str,
        kdf: KdfParams,
    ) -> Result<(SelectedFile, VaultInfo), String> {
        self.lock();
        let path = self.new_path.clone().ok_or(NO_NEW_PATH)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(EMPTY_NAME.into());
        }
        if password != confirm {
            return Err(PASSWORDS_DIFFER.into());
        }
        if path.exists() {
            return Err(FILE_EXISTS.into());
        }
        let mut vault = Vault::create(name, password, None, kdf).map_err(|e| match e {
            CoreError::WeakPassword(_) => WEAK_PASSWORD.to_owned(),
            _ => CREATE_FAILED.to_owned(),
        })?;
        vault.save_file(&path).map_err(|e| match e {
            // save_file refuses a path holding a file this vault did not load
            // (e.g. created between the check above and now).
            CoreError::FileChangedOnDisk => FILE_EXISTS.to_owned(),
            _ => SAVE_FAILED.to_owned(),
        })?;
        let info = VaultInfo {
            name: vault.data.name.clone(),
            entry_count: vault.data.entries.len(),
        };
        let file = self.select(path);
        self.vault = Some(vault);
        self.new_path = None;
        Ok((file, info))
    }

    /// The file of the open vault, if any (for "Son kasalar").
    pub fn open_path(&self) -> Option<PathBuf> {
        self.vault.as_ref().and(self.path.clone())
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

    pub fn groups(&self) -> Result<Vec<GroupView>, String> {
        let data = &self.vault.as_ref().ok_or(LOCKED)?.data;
        let mut list: Vec<GroupView> = data
            .groups
            .iter()
            .map(|g| GroupView {
                id: g.id.to_string(),
                name: g.name.clone(),
            })
            .collect();
        list.sort_by_cached_key(|g| g.name.to_lowercase());
        Ok(list)
    }

    /// Everything the editor shows, including secrets. Only for "Düzenle".
    pub fn entry_form(&self, id: &str) -> Result<EntryForm, String> {
        let data = &self.vault.as_ref().ok_or(LOCKED)?.data;
        let e = data
            .entries
            .iter()
            .find(|e| e.id.to_string() == id)
            .ok_or(NO_SUCH_ENTRY)?;
        Ok(EntryForm {
            id: Some(id.to_owned()),
            group_id: e.group.to_string(),
            title: e.title.clone(),
            username: e.username.clone(),
            password: e.password.expose().to_owned(),
            url: e.url.clone(),
            notes: e.notes.expose().to_owned(),
            tags: e.tags.clone(),
            totp: e
                .totp
                .as_ref()
                .map(|t| t.expose().to_owned())
                .unwrap_or_default(),
        })
    }

    /// Applies `change` to a COPY of the data and saves it. Only if the save
    /// succeeds does the copy replace the data in memory, so the screen never
    /// shows a change that is not on disk.
    fn commit<T>(
        &mut self,
        change: impl FnOnce(&mut VaultData) -> Result<T, String>,
    ) -> Result<T, String> {
        let path = self.path.clone().ok_or(NO_FILE_SELECTED)?;
        let vault = self.vault.as_mut().ok_or(LOCKED)?;
        let mut data = vault.data.clone();
        let out = change(&mut data)?;
        let old = std::mem::replace(&mut vault.data, data);
        if let Err(e) = vault.save_file(&path) {
            vault.data = old;
            return Err(match e {
                CoreError::FileChangedOnDisk => CHANGED_ON_DISK.to_owned(),
                _ => SAVE_FAILED.to_owned(),
            });
        }
        Ok(out)
    }

    /// Adds (id None) or updates an entry, then saves. Returns its id.
    pub fn save_entry(&mut self, form: &EntryForm) -> Result<String, String> {
        let title = form.title.trim().to_owned();
        if title.is_empty() {
            return Err(EMPTY_TITLE.into());
        }
        let tags = tidy_tags(&form.tags);
        let totp = form.totp.trim();
        if !totp.is_empty() && crate::totp::Totp::parse(totp).is_none() {
            return Err(TOTP_INVALID.into());
        }
        let totp = (!totp.is_empty()).then(|| lav_core::SecretString::new(totp));
        self.commit(|data| {
            let group = data
                .groups
                .iter()
                .find(|g| g.id.to_string() == form.group_id)
                .map(|g| g.id)
                .ok_or(NO_SUCH_GROUP)?;
            let fill = |e: &mut Entry| {
                e.group = group;
                e.title = title.clone();
                e.username = form.username.clone();
                e.password = form.password.as_str().into();
                e.url = form.url.trim().to_owned();
                e.notes = form.notes.as_str().into();
                e.tags = tags.clone();
                e.totp = totp.clone();
            };
            match &form.id {
                None => {
                    let mut e = Entry::new(group, title.clone());
                    fill(&mut e);
                    data.add_entry(e)
                        .map(|id| id.to_string())
                        .map_err(|_| NO_SUCH_GROUP.to_owned())
                }
                Some(id) => {
                    let uuid = data
                        .entries
                        .iter()
                        .find(|e| e.id.to_string() == *id)
                        .map(|e| e.id)
                        .ok_or(NO_SUCH_ENTRY)?;
                    data.update_entry(uuid, fill)
                        .map(|()| id.clone())
                        .map_err(|_| NO_SUCH_ENTRY.to_owned())
                }
            }
        })
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<(), String> {
        self.commit(|data| {
            let uuid = data
                .entries
                .iter()
                .find(|e| e.id.to_string() == id)
                .map(|e| e.id)
                .ok_or(NO_SUCH_ENTRY)?;
            data.delete_entry(uuid)
                .map_err(|_| NO_SUCH_ENTRY.to_owned())
        })
    }

    /// The entry's current TOTP code at Unix time `now`.
    pub fn totp_at(&self, id: &str, now: u64) -> Result<TotpCode, String> {
        let vault = self.vault.as_ref().ok_or(LOCKED)?;
        let e = vault
            .data
            .entries
            .iter()
            .find(|e| e.id.to_string() == id)
            .ok_or(NO_SUCH_ENTRY)?;
        let t = e
            .totp
            .as_ref()
            .and_then(|s| crate::totp::Totp::parse(s.expose()))
            .ok_or(NO_TOTP)?;
        let (code, seconds_left) = t.code_at(now);
        Ok(TotpCode {
            code,
            seconds_left,
            period: t.period,
        })
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
            Field::Totp => {
                return self
                    .totp_at(id, crate::recent::now())
                    .map(|c| Zeroizing::new(c.code))
            }
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
                has_totp: e.totp.is_some(),
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
        let f: Field = serde_json::from_str("\"totp\"").unwrap();
        assert_eq!(f, Field::Totp);
        assert!(serde_json::from_str::<Field>("\"notes\"").is_err());
    }

    #[test]
    fn create_saves_opens_and_reopens() {
        let dir = temp_dir("create");
        let mut s = Session::default();
        assert_eq!(s.select_new(dir.join("Yeni")), "Yeni.lav");
        let (file, info) = s
            .create_with("İş kasası", PASSWORD, PASSWORD, fast_kdf())
            .unwrap();
        assert_eq!(file.file_name, "Yeni.lav");
        assert_eq!(info.name, "İş kasası");
        assert!(s.is_unlocked());
        assert!(s.entries().unwrap().is_empty());

        // The file on disk opens with the same password.
        s.lock();
        assert_eq!(s.unlock(PASSWORD).unwrap().name, "İş kasası");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn create_checks_name_confirmation_and_length() {
        let dir = temp_dir("create-checks");
        let mut s = Session::default();
        assert_eq!(
            s.create_with("a", PASSWORD, PASSWORD, fast_kdf()),
            Err(NO_NEW_PATH.to_owned())
        );
        s.select_new(dir.join("k.lav"));
        assert_eq!(
            s.create_with("  ", PASSWORD, PASSWORD, fast_kdf()),
            Err(EMPTY_NAME.to_owned())
        );
        assert_eq!(
            s.create_with("a", PASSWORD, "other password", fast_kdf()),
            Err(PASSWORDS_DIFFER.to_owned())
        );
        assert_eq!(
            s.create_with("a", "kisa", "kisa", fast_kdf()),
            Err(WEAK_PASSWORD.to_owned())
        );
        assert!(!dir.join("k.lav").exists(), "nothing written on failure");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn create_never_overwrites_an_existing_file() {
        let dir = temp_dir("create-exists");
        let existing = make_vault(&dir);
        let before = std::fs::read(&existing).unwrap();
        let mut s = Session::default();
        s.select_new(existing.clone());
        assert_eq!(
            s.create_with("x", PASSWORD, PASSWORD, fast_kdf()),
            Err(FILE_EXISTS.to_owned())
        );
        assert_eq!(std::fs::read(&existing).unwrap(), before);
        assert!(!s.is_unlocked());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn opened(name: &str) -> (PathBuf, Session) {
        let dir = temp_dir(name);
        let mut s = Session::default();
        s.select(make_vault(&dir));
        s.unlock(PASSWORD).unwrap();
        (dir, s)
    }

    fn form(s: &Session, id: Option<String>, title: &str) -> EntryForm {
        EntryForm {
            id,
            group_id: s.groups().unwrap()[0].id.clone(),
            title: title.into(),
            username: "kullanici".into(),
            password: "yeni-gizli-parola".into(),
            url: " https://ornek.com ".into(),
            notes: "not".into(),
            tags: vec!["iş".into(), " ".into(), "İŞ".into(), "dev".into()],
            totp: String::new(),
        }
    }

    #[test]
    fn add_entry_is_saved_to_disk() {
        let (dir, mut s) = opened("add");
        let id = s.save_entry(&form(&s, None, "Yeni kayıt")).unwrap();
        // Re-open from disk: the entry is there with its secret.
        s.lock();
        s.unlock(PASSWORD).unwrap();
        let f = s.entry_form(&id).unwrap();
        assert_eq!(f.title, "Yeni kayıt");
        assert_eq!(f.password, "yeni-gizli-parola");
        assert_eq!(f.url, "https://ornek.com", "trimmed");
        assert_eq!(
            f.tags.len(),
            3,
            "empty tag dropped; 'iş'/'İŞ' kept apart only by non-ASCII case"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn edit_and_delete_are_saved() {
        let (dir, mut s) = opened("edit");
        let id = s
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.title == "zeta")
            .unwrap()
            .id;
        let mut f = s.entry_form(&id).unwrap();
        f.title = "zeta 2".into();
        s.save_entry(&f).unwrap();
        s.lock();
        s.unlock(PASSWORD).unwrap();
        assert_eq!(s.entry_form(&id).unwrap().title, "zeta 2");

        s.delete_entry(&id).unwrap();
        s.lock();
        s.unlock(PASSWORD).unwrap();
        assert_eq!(s.entry_form(&id), Err(NO_SUCH_ENTRY.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_save_leaves_memory_and_disk_unchanged() {
        let (dir, mut s) = opened("conflict");
        let path = dir.join("kasa.lav");
        // Someone else writes the file (another window, a sync client).
        let mut other = Vault::open_file(&path, PASSWORD, None).unwrap();
        other
            .data
            .add_entry(Entry::new(other.data.root, "başkası"))
            .unwrap();
        other.save_file(&path).unwrap();
        let on_disk = std::fs::read(&path).unwrap();

        let before = s.entries().unwrap();
        assert_eq!(
            s.save_entry(&form(&s, None, "benim")),
            Err(CHANGED_ON_DISK.to_owned())
        );
        assert_eq!(s.entries().unwrap(), before, "memory rolled back");
        assert_eq!(std::fs::read(&path).unwrap(), on_disk, "disk untouched");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_checks_title_group_and_id() {
        let (dir, mut s) = opened("checks");
        assert_eq!(
            s.save_entry(&form(&s, None, "  ")),
            Err(EMPTY_TITLE.to_owned())
        );
        let mut f = form(&s, None, "x");
        f.group_id = "yok".into();
        assert_eq!(s.save_entry(&f), Err(NO_SUCH_GROUP.to_owned()));
        let f = form(&s, Some("yok".into()), "x");
        assert_eq!(s.save_entry(&f), Err(NO_SUCH_ENTRY.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn entry_form_debug_hides_secrets() {
        let (dir, s) = opened("debug");
        let f = form(&s, None, "x");
        let d = format!("{f:?}");
        assert!(!d.contains("yeni-gizli-parola") && !d.contains("not\""));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn totp_is_saved_validated_and_never_listed() {
        let (dir, mut s) = opened("totp");
        let mut f = form(&s, None, "2FA");
        f.totp = "not base32!".into();
        assert_eq!(s.save_entry(&f), Err(TOTP_INVALID.to_owned()));
        // RFC 6238 SHA1 seed, base32.
        f.totp = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into();
        let id = s.save_entry(&f).unwrap();

        let list = s.entries().unwrap();
        assert!(list.iter().find(|e| e.id == id).unwrap().has_totp);
        let json = serde_json::to_string(&list).unwrap();
        assert!(!json.contains("GEZDGNBV"), "secret never in the list");

        assert_eq!(
            s.totp_at(&id, 59).unwrap(),
            TotpCode {
                code: "287082".into(),
                seconds_left: 1,
                period: 30
            }
        );
        let other = list.iter().find(|e| !e.has_totp).unwrap().id.clone();
        assert_eq!(s.totp_at(&other, 59), Err(NO_TOTP.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn generator_follows_options() {
        let o = GenOptions {
            length: 24,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        let p = generate(&o).unwrap();
        assert_eq!(p.chars().count(), 24);
        assert!(p.chars().all(|c| c.is_ascii_digit()));
        let none = GenOptions { digits: false, ..o };
        assert_eq!(generate(&none), Err(BAD_GENERATOR.to_owned()));
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
