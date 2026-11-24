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
use lav_core::{Entry, Error as CoreError, KdfParams, PasswordOptions, Removal, Vault, VaultData};
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
    /// `data:image/png;base64,...` of the sanitized, re-encoded icon.
    pub icon: Option<String>,
    /// In the recycle bin (left out of "Tüm kayıtlar", TOTP and auto-type).
    pub in_recycle_bin: bool,
    /// Expiry as Unix seconds; None = never.
    pub expires: Option<i64>,
    pub tags: Vec<String>,
    /// List colours, `#rrggbb` (checked when saved).
    pub fg_color: Option<String>,
    pub bg_color: Option<String>,
}

/// `#rrggbb`, nothing else: the value ends up in a style attribute.
pub fn color_ok(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|h| h.is_ascii_hexdigit())
}

pub const BAD_COLOR: &str = "Geçersiz renk.";

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
    /// The KeePass file chosen for import.
    import_path: Option<PathBuf>,
    /// Key file to use with the next unlock (chosen in Rust's dialog).
    keyfile: Option<PathBuf>,
    /// Key file of the KeePass database being imported (never the vault's).
    import_keyfile: Option<PathBuf>,
    /// The other .lav file to merge in, and its key file.
    merge_path: Option<PathBuf>,
    merge_keyfile: Option<PathBuf>,
    /// The key file to switch to ("Anahtar dosyası" in Kasa ayarları).
    pending_keyfile: Option<PathBuf>,
}

/// Which hidden texts a search also looks in (title, username, site and
/// tags are searched in the UI).
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchScope {
    pub notes: bool,
    /// Custom field names, and values that are not protected.
    pub fields: bool,
}

/// "Kasa ayarları" (KeePass "Database Settings").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettings {
    pub name: String,
    pub description: String,
    pub history_limit: u32,
    pub history_versions: usize,
    pub kdf: KdfInfo,
    pub keyfile_required: bool,
    pub keyfile_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeSummary {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub groups_added: usize,
}

pub const BAD_KDF: &str =
    "Bu değerler kabul edilmiyor: bellek 19–1024 MiB, geçiş 2–20, iş parçacığı 1–16.";
pub const SAME_VAULT: &str = "Açık kasa kendisiyle birleştirilemez.";
pub const NO_PENDING_KEYFILE: &str = "Önce yeni anahtar dosyasını seçin ya da oluşturun.";
pub const KEYFILE_WRITE_FAILED: &str = "Anahtar dosyası yazılamadı.";
pub const NAME_TOO_LONG: &str = "Ad en fazla 256, açıklama en fazla 10 000 karakter olabilir.";

fn file_name(p: &std::path::Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The same file (canonical paths), or the same path if one is missing.
pub fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    same_file(a, b)
}

fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Lowercase for searching, with the Turkish i's folded together (İ, I, ı
/// and i all match each other; plain `to_lowercase` turns İ into i + a
/// combining dot). Into a self-wiping buffer.
fn fold(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len() * 3));
    for c in s.chars() {
        match c {
            'İ' | 'I' | 'ı' => out.push('i'),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

fn contains_folded(hay: &str, needle_folded: &str) -> bool {
    fold(hay).contains(needle_folded)
}

pub const NO_FILE_SELECTED: &str = "Önce bir kasa dosyası seçin.";
pub const LOCKED: &str = "Kasa kilitli.";
pub const NO_SUCH_ENTRY: &str = "Kayıt bulunamadı.";
pub const NO_SUCH_ITEM: &str = "Öğe bulunamadı.";
pub const WRONG_CURRENT: &str = "Mevcut ana parola (ya da anahtar dosyası) yanlış.";
pub const CANNOT_DELETE_ROOT: &str = "Ana klasör silinemez.";
pub const CANNOT_MOVE_ROOT: &str = "Ana klasör taşınamaz.";
pub const BAD_ICON: &str = "Geçersiz simge.";

/// A folder icon is a short name the app knows ("briefcase"); anything else
/// in a file (e.g. from another program) is ignored, never shown as markup.
pub fn icon_name_ok(name: &str) -> bool {
    (1..=40).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub const INVALID_MOVE: &str = "Bir klasör kendi içine ya da alt klasörlerinden birine taşınamaz.";
pub const EMPTY_GROUP_NAME: &str = "Klasör adı boş olamaz.";
pub const ATTACHMENT_TOO_LARGE: &str = "Ek en fazla 16 MiB olabilir.";
pub const MAX_ATTACHMENT_BYTES: u64 = 16 * 1024 * 1024;
pub const BAD_FIELD: &str = "Özel alanın adı boş olamaz (en fazla 256 alan).";
pub const KEYFILE_READ_FAILED: &str = "Anahtar dosyası okunamadı (en fazla 16 MiB).";
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
pub const BAD_EXPIRY: &str = "Geçersiz son kullanma tarihi.";
/// Appended to the title of a duplicated entry.
pub const COPY_SUFFIX: &str = " - Kopya";
/// Latest accepted expiry: 9999-12-31 23:59:59 UTC (what a date input allows).
pub const MAX_EXPIRY: i64 = 253_402_300_799;

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
    /// None for the root folder.
    pub parent: Option<String>,
    /// Entries directly in this folder.
    pub entries: usize,
    /// Entries in this folder and all its subfolders (what a delete removes).
    pub total_entries: usize,
    /// Icon name chosen in the app (Font Awesome key), or None.
    pub icon: Option<String>,
    /// This folder is the recycle bin.
    pub recycle_bin: bool,
}

/// CSV cell: always quoted, quotes doubled, and a leading = + - @ tab or CR
/// prefixed with ' so spreadsheet apps do not run it as a formula
/// (CSV/formula injection).
pub fn csv_cell(s: &str) -> String {
    let risky = matches!(s.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r'));
    let body = if risky { format!("'{s}") } else { s.to_owned() };
    format!("\"{}\"", body.replace('"', "\"\""))
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
    /// Custom fields; None = keep the entry's fields unchanged.
    #[serde(default)]
    pub fields: Option<Vec<FormField>>,
    /// Expiry as Unix seconds (KeePass "Expires"); None = never.
    #[serde(default)]
    pub expires: Option<i64>,
    /// Auto-type sequence; empty = the default one.
    #[serde(default)]
    pub autotype_sequence: String,
    /// Window rule (`*`, `?`); empty = the entry's title or site.
    #[serde(default)]
    pub autotype_window: String,
    /// False = this entry never auto-types.
    #[serde(default = "yes")]
    pub autotype_enabled: bool,
    #[serde(default)]
    pub fg_color: Option<String>,
    #[serde(default)]
    pub bg_color: Option<String>,
}

fn yes() -> bool {
    true
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

/// A custom field as the editor sends it. The value is wiped on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FormField {
    pub name: String,
    pub value: String,
    pub protected: bool,
}

impl Drop for FormField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// What the detail view shows besides the summary. Protected values and
/// notes are NOT included; they are revealed one at a time on click.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryExtras {
    pub fields: Vec<FieldView>,
    pub attachments: Vec<AttachmentView>,
    pub history: Vec<VersionView>,
    pub tags: Vec<String>,
    pub has_notes: bool,
    pub created: i64,
    pub modified: i64,
    /// Expiry as Unix seconds; None = never.
    pub expires: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    pub name: String,
    /// None for protected fields.
    pub value: Option<String>,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub name: String,
    pub size: usize,
}

/// One older version: metadata only, never its secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionView {
    pub modified: i64,
    pub title: String,
    pub username: String,
    /// The password of that version differs from the current one.
    pub password_differs: bool,
}

/// A secret the user can reveal or copy besides username/password/TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind", content = "index")]
pub enum Extra {
    Notes,
    Custom(usize),
}

/// The keys to type (values filled in) and the windows they may go to.
pub type AutoTypeData = (Vec<crate::autotype::Step>, crate::autotype::Target);

pub const AUTOTYPE_OFF: &str = "Bu kayıtta otomatik yazma kapalı (Düzenle › Otomatik yazma).";
pub const NO_SUCH_FIELD: &str = "Otomatik yazma dizisindeki özel alan bu kayıtta yok.";

/// Nested references are followed at most this deep (a loop just stops).
pub const MAX_REF_DEPTH: usize = 4;

/// The entry a reference points at: `I` id (with or without dashes), `T`
/// title, `U` username, `A` site; exact match, first hit.
fn ref_target<'a>(data: &'a VaultData, search: char, text: &str) -> Option<&'a Entry> {
    let find = |f: &dyn Fn(&Entry) -> bool| data.entries.iter().find(|e| f(e));
    match search.to_ascii_uppercase() {
        'I' => {
            let want = text.replace('-', "").to_ascii_lowercase();
            find(&|e| e.id.simple().to_string() == want)
        }
        'T' => find(&|e| e.title == text),
        'U' => find(&|e| e.username == text),
        'A' => find(&|e| e.url == text),
        _ => None,
    }
}

/// Replaces KeePass field references, `{REF:<what>@<search>:<text>}`, with
/// the value they point at. `what`: `T` title, `U` username, `P` password,
/// `A` site, `N` notes. Unknown or broken references stay as they are.
pub fn resolve_refs(data: &VaultData, raw: &str) -> Zeroizing<String> {
    resolve_refs_at(data, raw, 0)
}

fn resolve_refs_at(data: &VaultData, raw: &str, depth: usize) -> Zeroizing<String> {
    const OPEN: &str = "{REF:";
    let mut out = Zeroizing::new(String::with_capacity(raw.len()));
    if depth >= MAX_REF_DEPTH || !raw.contains(OPEN) {
        out.push_str(raw);
        return out;
    }
    let mut rest = raw;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let tail = &rest[start + OPEN.len()..];
        let parsed = (|| {
            let mut it = tail.chars();
            let what = it.next()?;
            (it.next()? == '@').then_some(())?;
            let search = it.next()?;
            (it.next()? == ':').then_some(())?;
            let body = &tail[4..];
            let end = body.find('}')?;
            Some((what, search, &body[..end], 4 + end + 1))
        })();
        match parsed.and_then(|(what, search, text, used)| {
            let e = ref_target(data, search, text)?;
            let value: &str = match what.to_ascii_uppercase() {
                'T' => &e.title,
                'U' => &e.username,
                'P' => e.password.expose(),
                'A' => &e.url,
                'N' => e.notes.expose(),
                _ => return None,
            };
            Some((resolve_refs_at(data, value, depth + 1), used))
        }) {
            Some((value, used)) => {
                out.push_str(&value);
                rest = &tail[used..];
            }
            None => {
                out.push_str(OPEN);
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Generator settings as the UI sends them.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    /// Non-empty = use this pattern instead of the classes and length.
    #[serde(default)]
    pub pattern: String,
}

pub fn generate(o: &GenOptions) -> Result<Zeroizing<String>, String> {
    if !o.pattern.trim().is_empty() {
        return lav_core::generate_pattern(o.pattern.trim()).map_err(|_| BAD_GENERATOR.to_owned());
    }
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
        // A key file belongs to one vault; never carry it over silently.
        self.keyfile = None;
        let info = describe(&path);
        self.path = Some(path);
        info
    }

    /// The chosen file, as the unlock screen shows it (after switching tabs).
    pub fn selected_file(&self) -> Option<SelectedFile> {
        self.path.as_deref().map(describe)
    }

    /// Name and size of the open vault; None while locked.
    pub fn info(&self) -> Option<VaultInfo> {
        self.vault.as_ref().map(|v| VaultInfo {
            name: v.data.name.clone(),
            entry_count: v.data.entries.len(),
        })
    }

    /// The selected file is the same file as `other` (one vault must not
    /// be open in two tabs: their saves would refuse each other).
    pub fn has_file(&self, other: &std::path::Path) -> bool {
        self.path.as_deref().is_some_and(|p| same_file(p, other))
    }

    /// The file chosen for unlocking, if any.
    pub fn selected_path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }
}

/// What the unlock screen shows about a file (header values unauthenticated).
fn describe(path: &std::path::Path) -> SelectedFile {
    {
        let header = read_header(path);
        SelectedFile {
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
        }
    }
}

impl Session {
    /// Sets (Some) or clears (None) the key file for the next unlock.
    /// Returns the file name to display.
    pub fn set_keyfile(&mut self, path: Option<PathBuf>) -> Option<String> {
        self.keyfile = path;
        self.keyfile
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
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
        let kf = self.keyfile_bytes()?;
        let mut vault = Vault::create(name, password, kf.as_deref().map(|k| k.as_slice()), kdf)
            .map_err(|e| match e {
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
        let keyfile = self.keyfile.take();
        let file = self.select(path);
        // The key file used to create the vault stays selected for it.
        self.keyfile = keyfile;
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
        let keyfile = match &self.keyfile {
            Some(k) => Some(Vault::read_keyfile(k).map_err(|_| KEYFILE_READ_FAILED.to_owned())?),
            None => None,
        };
        let vault = Vault::open_file(path, password, keyfile.as_deref().map(|k| k.as_slice()))
            .map_err(|e| unlock_error(&e))?;
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
        let direct = |id| data.entries.iter().filter(|e| e.group == id).count();
        let total = |id| {
            let mut n = 0;
            let mut stack = vec![id];
            let mut seen = std::collections::HashSet::new();
            while let Some(g) = stack.pop() {
                if !seen.insert(g) {
                    continue;
                }
                n += direct(g);
                stack.extend(
                    data.groups
                        .iter()
                        .filter(|c| c.parent == Some(g))
                        .map(|c| c.id),
                );
            }
            n
        };
        let mut list: Vec<GroupView> = data
            .groups
            .iter()
            .map(|g| GroupView {
                id: g.id.to_string(),
                name: g.name.clone(),
                parent: g.parent.map(|p| p.to_string()),
                entries: direct(g.id),
                total_entries: total(g.id),
                icon: g.icon.clone().filter(|i| icon_name_ok(i)),
                recycle_bin: data.recycle_bin == Some(g.id),
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
            fields: Some(
                e.fields
                    .iter()
                    .map(|f| FormField {
                        name: f.name.clone(),
                        value: f.value.expose().to_owned(),
                        protected: f.protected,
                    })
                    .collect(),
            ),
            expires: e.expires,
            autotype_sequence: e
                .autotype
                .as_ref()
                .map(|a| a.sequence.clone())
                .unwrap_or_default(),
            autotype_window: e
                .autotype
                .as_ref()
                .map(|a| a.window.clone())
                .unwrap_or_default(),
            autotype_enabled: e.autotype.as_ref().is_none_or(|a| a.enabled),
            fg_color: e.fg_color.clone(),
            bg_color: e.bg_color.clone(),
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
        if form.expires.is_some_and(|t| !(0..=MAX_EXPIRY).contains(&t)) {
            return Err(BAD_EXPIRY.into());
        }
        let expires = form.expires;
        let color = |c: &Option<String>| -> Result<Option<String>, String> {
            match c.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
                None => Ok(None),
                Some(c) if color_ok(c) => Ok(Some(c.to_ascii_lowercase())),
                Some(_) => Err(BAD_COLOR.into()),
            }
        };
        let (fg_color, bg_color) = (color(&form.fg_color)?, color(&form.bg_color)?);
        let sequence = form.autotype_sequence.trim().to_owned();
        crate::autotype::parse_sequence(&sequence).map_err(str::to_owned)?;
        let window = form.autotype_window.trim().to_owned();
        if !window.is_empty() && !crate::autotype::window_rule_ok(&window) {
            return Err(crate::autotype::BAD_WINDOW_RULE.into());
        }
        let autotype =
            (!sequence.is_empty() || !window.is_empty() || !form.autotype_enabled).then(|| {
                lav_core::AutoTypeConfig {
                    sequence,
                    window,
                    enabled: form.autotype_enabled,
                }
            });
        let fields: Option<Vec<lav_core::CustomField>> = match &form.fields {
            None => None,
            Some(fs) => {
                if fs.len() > 256 || fs.iter().any(|f| f.name.trim().is_empty()) {
                    return Err(BAD_FIELD.into());
                }
                Some(
                    fs.iter()
                        .map(|f| lav_core::CustomField {
                            name: f.name.trim().to_owned(),
                            value: lav_core::SecretString::new(f.value.as_str()),
                            protected: f.protected,
                        })
                        .collect(),
                )
            }
        };
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
                e.set_url(form.url.trim());
                e.notes = form.notes.as_str().into();
                e.tags = tags.clone();
                e.totp = totp.clone();
                e.expires = expires;
                e.autotype = autotype.clone();
                e.fg_color = fg_color.clone();
                e.bg_color = bg_color.clone();
                if let Some(fs) = &fields {
                    e.fields = fs.clone();
                }
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

    fn group_uuid(data: &VaultData, id: &str) -> Result<uuid::Uuid, String> {
        data.groups
            .iter()
            .find(|g| g.id.to_string() == id)
            .map(|g| g.id)
            .ok_or_else(|| NO_SUCH_GROUP.to_owned())
    }

    /// New folder under `parent` (None = the root). Returns its id.
    pub fn add_group(&mut self, parent: Option<&str>, name: &str) -> Result<String, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err(EMPTY_GROUP_NAME.into());
        }
        self.commit(|data| {
            let parent = match parent {
                Some(p) => Self::group_uuid(data, p)?,
                None => data.root,
            };
            data.add_group(parent, name)
                .map(|id| id.to_string())
                .map_err(|_| NO_SUCH_GROUP.to_owned())
        })
    }

    pub fn rename_group(&mut self, id: &str, name: &str) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err(EMPTY_GROUP_NAME.into());
        }
        self.commit(|data| {
            let g = Self::group_uuid(data, id)?;
            data.rename_group(g, name)
                .map_err(|_| NO_SUCH_GROUP.to_owned())
        })
    }

    /// Deletes a folder, its subfolders AND their entries (the UI asks twice
    /// and shows the count). The root cannot be deleted.
    /// KeePass-style: moves the folder into the recycle bin; the bin itself
    /// or a folder inside it is deleted for good. Returns true if deleted
    /// for good.
    pub fn delete_group(&mut self, id: &str) -> Result<bool, String> {
        self.commit(|data| {
            let g = Self::group_uuid(data, id)?;
            data.remove_group(g)
                .map(|r| r == Removal::Deleted)
                .map_err(|e| match e {
                    CoreError::CannotDeleteRoot => CANNOT_DELETE_ROOT.to_owned(),
                    _ => NO_SUCH_GROUP.to_owned(),
                })
        })
    }

    /// Deletes everything in the recycle bin for good. Returns the number of
    /// entries deleted.
    pub fn empty_recycle_bin(&mut self) -> Result<usize, String> {
        self.commit(|data| Ok(data.empty_recycle_bin()))
    }

    /// Sets the folder's icon (None = the default folder icon).
    pub fn set_group_icon(&mut self, id: &str, icon: Option<&str>) -> Result<(), String> {
        if icon.is_some_and(|i| !icon_name_ok(i)) {
            return Err(BAD_ICON.into());
        }
        self.commit(|data| {
            let g = Self::group_uuid(data, id)?;
            data.set_group_icon(g, icon.map(str::to_owned))
                .map_err(|_| NO_SUCH_GROUP.to_owned())
        })
    }

    /// Moves a folder (with its subfolders and entries) under `parent`
    /// (None = the root). The core refuses cycles and moving the root.
    pub fn move_group(&mut self, id: &str, parent: Option<&str>) -> Result<(), String> {
        self.commit(|data| {
            let g = Self::group_uuid(data, id)?;
            let p = match parent {
                Some(p) => Self::group_uuid(data, p)?,
                None => data.root,
            };
            data.move_group(g, p).map_err(|e| match e {
                CoreError::CannotMoveRoot => CANNOT_MOVE_ROOT.to_owned(),
                CoreError::InvalidMove => INVALID_MOVE.to_owned(),
                _ => NO_SUCH_GROUP.to_owned(),
            })
        })
    }

    /// Moves an entry to another folder (no history version: not an edit).
    pub fn move_entry(&mut self, id: &str, group: &str) -> Result<(), String> {
        self.commit(|data| {
            let g = Self::group_uuid(data, group)?;
            let e = data
                .entries
                .iter()
                .find(|e| e.id.to_string() == id)
                .map(|e| e.id)
                .ok_or(NO_SUCH_ENTRY)?;
            data.move_entry(e, g).map_err(|_| NO_SUCH_ENTRY.to_owned())
        })
    }

    /// Restores an older version (index in the newest-first list the UI
    /// shows). The current state goes into the history, so nothing is lost.
    pub fn restore_version(&mut self, id: &str, newest_first_index: usize) -> Result<(), String> {
        self.commit(|data| {
            let e = data
                .entries
                .iter()
                .find(|e| e.id.to_string() == id)
                .ok_or(NO_SUCH_ENTRY)?;
            let len = e.history.len();
            if newest_first_index >= len {
                return Err(NO_SUCH_ITEM.into());
            }
            let v = e.history[len - 1 - newest_first_index].clone();
            let uuid = e.id;
            data.update_entry(uuid, |e| {
                e.title = v.title.clone();
                e.username = v.username.clone();
                e.password = v.password.clone();
                e.set_url(&v.url);
                e.notes = v.notes.clone();
                e.totp = v.totp.clone();
                e.fields = v.fields.clone();
            })
            .map_err(|_| NO_SUCH_ENTRY.to_owned())
        })
    }

    pub fn add_attachment(&mut self, id: &str, path: &std::path::Path) -> Result<(), String> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|f| f.take(MAX_ATTACHMENT_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|_| READ_FAILED.to_owned())?;
        if bytes.len() as u64 > MAX_ATTACHMENT_BYTES {
            bytes.zeroize();
            return Err(ATTACHMENT_TOO_LARGE.into());
        }
        let name: String = path
            .file_name()
            .map(|n| n.to_string_lossy().chars().take(255).collect())
            .unwrap_or_else(|| "ek".into());
        let att = lav_core::Attachment {
            name,
            data: lav_core::SecretBytes::new(bytes),
        };
        self.commit(|data| {
            let uuid = data
                .entries
                .iter()
                .find(|e| e.id.to_string() == id)
                .map(|e| e.id)
                .ok_or(NO_SUCH_ENTRY)?;
            data.update_entry(uuid, |e| e.attachments.push(att.clone()))
                .map_err(|_| NO_SUCH_ENTRY.to_owned())
        })
    }

    pub fn remove_attachment(&mut self, id: &str, index: usize) -> Result<(), String> {
        self.commit(|data| {
            let e = data
                .entries
                .iter()
                .find(|e| e.id.to_string() == id)
                .ok_or(NO_SUCH_ENTRY)?;
            if index >= e.attachments.len() {
                return Err(NO_SUCH_ITEM.into());
            }
            let uuid = e.id;
            data.update_entry(uuid, |e| {
                e.attachments.remove(index);
            })
            .map_err(|_| NO_SUCH_ENTRY.to_owned())
        })
    }

    fn keyfile_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        match &self.keyfile {
            Some(k) => Vault::read_keyfile(k)
                .map(Some)
                .map_err(|_| KEYFILE_READ_FAILED.to_owned()),
            None => Ok(None),
        }
    }

    /// Changes the master password (the key file, if any, stays). Needs the
    /// CURRENT password (cf. KeePassXC CVE-2023-35866). Saves; if saving
    /// fails, the old password is put back so memory and disk agree.
    pub fn change_master(&mut self, current: &str, new: &str, confirm: &str) -> Result<(), String> {
        if new != confirm {
            return Err(PASSWORDS_DIFFER.into());
        }
        let path = self.path.clone().ok_or(NO_FILE_SELECTED)?;
        let kf = self.keyfile_bytes()?;
        let kf = kf.as_deref().map(|k| k.as_slice());
        let vault = self.vault.as_mut().ok_or(LOCKED)?;
        vault
            .change_credentials(current, kf, new, kf, None)
            .map_err(|e| match e {
                CoreError::WrongCurrentCredentials => WRONG_CURRENT.to_owned(),
                CoreError::WeakPassword(_) => WEAK_PASSWORD.to_owned(),
                _ => CREATE_FAILED.to_owned(),
            })?;
        if let Err(e) = vault.save_file(&path) {
            let _ = vault.change_credentials(new, kf, current, kf, None);
            return Err(match e {
                CoreError::FileChangedOnDisk => CHANGED_ON_DISK.to_owned(),
                _ => SAVE_FAILED.to_owned(),
            });
        }
        Ok(())
    }

    /// Plain-text CSV of every entry, after re-checking the master password
    /// (SECURITY.md "Dışa aktarma"). Returns the CSV; the caller writes it.
    pub fn export_csv(&self, current: &str) -> Result<Zeroizing<String>, String> {
        let data = &self.verify_current(current)?.data;
        let mut out = Zeroizing::new(String::from(
            "\"Klasör\",\"Başlık\",\"Kullanıcı adı\",\"Parola\",\"Web sitesi\",\"Notlar\",\"TOTP\",\"Etiketler\"\r\n",
        ));
        for e in &data.entries {
            let group = data.group(e.group).map(|g| g.name.as_str()).unwrap_or("");
            let totp = e.totp.as_ref().map(|t| t.expose()).unwrap_or("");
            let cells = [
                csv_cell(group),
                csv_cell(&e.title),
                csv_cell(&e.username),
                csv_cell(e.password.expose()),
                csv_cell(&e.url),
                csv_cell(e.notes.expose()),
                csv_cell(totp),
                csv_cell(&e.tags.join(", ")),
            ];
            out.push_str(&cells.join(","));
            out.push_str("\r\n");
            for mut c in cells {
                c.zeroize();
            }
        }
        Ok(out)
    }

    /// Entries with a URL and no icon yet: (id, url). Imported entries are
    /// included only when the user asked (`on_request`).
    pub fn missing_icons(
        &self,
        limit: usize,
        on_request: bool,
    ) -> Result<Vec<(String, String)>, String> {
        let vault = self.vault.as_ref().ok_or(LOCKED)?;
        Ok(vault
            .data
            .entries
            .iter()
            .filter(|e| e.icon.is_none() && !e.url.trim().is_empty())
            .filter(|e| on_request || !e.icon_on_request)
            .take(limit)
            .map(|e| (e.id.to_string(), e.url.clone()))
            .collect())
    }

    /// Stores already-sanitized PNG icons (from lav-favicon) and saves once.
    /// Not a content edit, so no history version is created.
    pub fn set_icons(&mut self, icons: Vec<(String, Vec<u8>)>) -> Result<(), String> {
        if icons.is_empty() {
            return Ok(());
        }
        let now = crate::recent::now() as i64;
        self.commit(|data| {
            for (id, png) in icons {
                if let Some(e) = data.entries.iter_mut().find(|e| e.id.to_string() == id) {
                    e.icon = Some(lav_core::EntryIcon { png, fetched: now });
                    e.icon_on_request = false;
                }
            }
            Ok(())
        })
    }

    /// The entry's auto-type keys with its values filled in (references
    /// resolved), and the windows they may be typed into.
    pub fn autotype_data(&self, id: &str) -> Result<AutoTypeData, String> {
        use crate::autotype::{SeqField, Step, Token};
        let data = &self.vault.as_ref().ok_or(LOCKED)?.data;
        let e = self.entry_ref(id)?;
        if e.autotype.as_ref().is_some_and(|a| !a.enabled) {
            return Err(AUTOTYPE_OFF.into());
        }
        let seq = e
            .autotype
            .as_ref()
            .map(|a| a.sequence.as_str())
            .unwrap_or("");
        let tokens = crate::autotype::parse_sequence(seq).map_err(str::to_owned)?;
        let mut steps = Vec::with_capacity(tokens.len());
        for t in tokens {
            steps.push(match t {
                Token::Text(s) => Step::Text(Zeroizing::new(s)),
                Token::Tab => Step::Tab,
                Token::Enter => Step::Enter,
                Token::Delay(ms) => Step::Delay(std::time::Duration::from_millis(ms)),
                Token::Field(f) => Step::Text(match f {
                    SeqField::Username => resolve_refs(data, &e.username),
                    SeqField::Password => resolve_refs(data, e.password.expose()),
                    SeqField::Title => Zeroizing::new(e.title.clone()),
                    SeqField::Url => resolve_refs(data, &e.url),
                    SeqField::Notes => resolve_refs(data, e.notes.expose()),
                    SeqField::Totp => self.field(id, Field::Totp)?,
                    SeqField::Custom(name) => e
                        .fields
                        .iter()
                        .find(|f| f.name.eq_ignore_ascii_case(&name))
                        .map(|f| resolve_refs(data, f.value.expose()))
                        .ok_or(NO_SUCH_FIELD)?,
                }),
            });
        }
        Ok((steps, autotype_target(e)))
    }

    /// Entries whose title or site appears in `window_title`, by the same
    /// rule as the auto-type button: (id, entry title).
    pub fn autotype_matches(&self, window_title: &str) -> Result<Vec<(String, String)>, String> {
        let vault = self.vault.as_ref().ok_or(LOCKED)?;
        Ok(vault
            .data
            .entries
            .iter()
            // Deleted entries never auto-type (as in KeePass).
            .filter(|e| !vault.data.in_recycle_bin(e.group))
            .filter(|e| e.autotype.as_ref().is_none_or(|a| a.enabled))
            .filter(|e| autotype_target(e).matches(window_title))
            .map(|e| (e.id.to_string(), e.title.clone()))
            .collect())
    }

    /// The entry's web site, if it is an address that may be opened.
    pub fn web_address(&self, id: &str) -> Result<url::Url, String> {
        let e = self.entry_ref(id)?;
        crate::browser::web_address(&e.url).ok_or_else(|| crate::browser::NOT_A_WEB_ADDRESS.into())
    }

    /// Copies an entry into its folder (KeePass "Duplicate Entry", Ctrl+K)
    /// and saves. The copy has no history. Returns the new id.
    pub fn duplicate_entry(&mut self, id: &str) -> Result<String, String> {
        self.commit(|data| {
            let uuid = data
                .entries
                .iter()
                .find(|e| e.id.to_string() == id)
                .map(|e| e.id)
                .ok_or(NO_SUCH_ENTRY)?;
            data.duplicate_entry(uuid, COPY_SUFFIX)
                .map(|id| id.to_string())
                .map_err(|_| NO_SUCH_ENTRY.to_owned())
        })
    }

    /// KeePass-style: moves the entry into the recycle bin; an entry already
    /// in the bin is deleted for good. Returns true if deleted for good.
    pub fn delete_entry(&mut self, id: &str) -> Result<bool, String> {
        self.commit(|data| {
            let uuid = data
                .entries
                .iter()
                .find(|e| e.id.to_string() == id)
                .map(|e| e.id)
                .ok_or(NO_SUCH_ENTRY)?;
            data.remove_entry(uuid)
                .map(|r| r == Removal::Deleted)
                .map_err(|_| NO_SUCH_ENTRY.to_owned())
        })
    }

    pub fn set_import_keyfile(&mut self, path: Option<PathBuf>) -> Option<String> {
        self.import_keyfile = path;
        self.import_keyfile
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
    }

    pub fn select_import(&mut self, path: PathBuf) -> String {
        self.import_keyfile = None;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.import_path = Some(path);
        name
    }

    /// Imports the chosen KeePass file into the open vault, under a new
    /// top-level folder, and saves. Nothing changes if any step fails.
    pub fn import_keepass(&mut self, password: &str) -> Result<crate::import::Summary, String> {
        if self.vault.is_none() {
            return Err(LOCKED.into());
        }
        let path = self.import_path.clone().ok_or(NO_FILE_SELECTED)?;
        // Read at most one byte more than allowed, so size is checked without
        // trusting the file system's length.
        let mut bytes = Zeroizing::new(Vec::new());
        std::fs::File::open(&path)
            .and_then(|f| {
                f.take(crate::import::MAX_KDBX_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|_| READ_FAILED.to_owned())?;
        let kf = match &self.import_keyfile {
            Some(k) => Some(Vault::read_keyfile(k).map_err(|_| KEYFILE_READ_FAILED.to_owned())?),
            None => None,
        };
        let db = crate::import::open(&bytes, password, kf.as_deref().map(|k| k.as_slice()))
            .map_err(str::to_owned)?;
        let stem = path
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let folder = format!("KeePass: {stem}");
        let summary =
            self.commit(|data| crate::import::convert(&db, data, &folder).map_err(str::to_owned))?;
        self.import_path = None;
        self.import_keyfile = None;
        Ok(summary)
    }

    // ----- search -----

    /// Ids of entries whose notes or custom fields contain `query` (ignoring
    /// case). Protected field values are never searched. Only ids leave.
    pub fn search_hidden(&self, query: &str, scope: SearchScope) -> Result<Vec<String>, String> {
        let data = &self.vault.as_ref().ok_or(LOCKED)?.data;
        let needle = fold(query.trim());
        if needle.is_empty() || !(scope.notes || scope.fields) {
            return Ok(Vec::new());
        }
        Ok(data
            .entries
            .iter()
            .filter(|e| {
                (scope.notes && contains_folded(e.notes.expose(), &needle))
                    || (scope.fields
                        && e.fields.iter().any(|f| {
                            contains_folded(&f.name, &needle)
                                || (!f.protected && contains_folded(f.value.expose(), &needle))
                        }))
            })
            .map(|e| e.id.to_string())
            .collect())
    }

    // ----- vault settings -----

    pub fn vault_settings(&self) -> Result<VaultSettings, String> {
        let vault = self.vault.as_ref().ok_or(LOCKED)?;
        let kdf = vault.kdf();
        Ok(VaultSettings {
            name: vault.data.name.clone(),
            description: vault.data.description.clone(),
            history_limit: vault.data.history_limit() as u32,
            history_versions: vault.data.entries.iter().map(|e| e.history.len()).sum(),
            kdf: KdfInfo {
                memory_mib: kdf.memory_kib / 1024,
                iterations: kdf.iterations,
                parallelism: kdf.parallelism,
            },
            keyfile_required: vault.requires_keyfile(),
            keyfile_name: self.keyfile.as_deref().map(file_name),
        })
    }

    /// Name (also the top folder's), description and versions kept per
    /// entry; extra versions are dropped at once.
    pub fn set_vault_settings(
        &mut self,
        name: &str,
        description: &str,
        history_limit: u32,
    ) -> Result<(), String> {
        let name = name.trim().to_owned();
        if name.is_empty() {
            return Err(EMPTY_NAME.into());
        }
        if name.chars().count() > 256 || description.chars().count() > 10_000 {
            return Err(NAME_TOO_LONG.into());
        }
        let description = description.trim().to_owned();
        let limit = history_limit.min(lav_core::HISTORY_LIMIT_MAX);
        self.commit(|data| {
            data.name = name.clone();
            let root = data.root;
            if let Some(g) = data.groups.iter_mut().find(|g| g.id == root) {
                g.name = name;
            }
            data.description = description;
            data.history_limit = Some(limit);
            data.trim_history(None);
            Ok(())
        })
    }

    /// Deletes old versions: all of them (None) or those older than `days`.
    pub fn clear_history(&mut self, older_than_days: Option<u32>) -> Result<usize, String> {
        let cutoff = match older_than_days {
            None => i64::MAX,
            Some(d) => crate::recent::now() as i64 - i64::from(d) * 86_400,
        };
        self.commit(|data| Ok(data.trim_history(Some(cutoff))))
    }

    /// New Argon2id cost. Needs the current password; a new salt and key are
    /// made. On a failed save the old cost is put back.
    pub fn change_kdf(
        &mut self,
        current: &str,
        memory_mib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<(), String> {
        let kdf = KdfParams {
            memory_kib: memory_mib.saturating_mul(1024),
            iterations,
            parallelism,
        };
        kdf.validate().map_err(|_| BAD_KDF.to_owned())?;
        let path = self.path.clone().ok_or(NO_FILE_SELECTED)?;
        let kf = self.keyfile_bytes()?;
        let kf = kf.as_deref().map(|k| k.as_slice());
        let vault = self.vault.as_mut().ok_or(LOCKED)?;
        let old = vault.kdf();
        vault
            .change_credentials(current, kf, current, kf, Some(kdf))
            .map_err(|e| match e {
                CoreError::WrongCurrentCredentials => WRONG_CURRENT.to_owned(),
                _ => BAD_KDF.to_owned(),
            })?;
        if let Err(e) = vault.save_file(&path) {
            let _ = vault.change_credentials(current, kf, current, kf, Some(old));
            return Err(match e {
                CoreError::FileChangedOnDisk => CHANGED_ON_DISK.to_owned(),
                _ => SAVE_FAILED.to_owned(),
            });
        }
        Ok(())
    }

    /// Remembers the key file to switch to. Returns its name.
    pub fn set_pending_keyfile(&mut self, path: Option<PathBuf>) -> Option<String> {
        self.pending_keyfile = path;
        self.pending_keyfile.as_deref().map(file_name)
    }

    /// Writes a new random key file (32 random bytes as hex text, like
    /// KeePass's own key files carry only random data) and selects it as
    /// the pending one. Refuses to overwrite an existing file.
    pub fn create_keyfile(&mut self, path: PathBuf) -> Result<String, String> {
        let bytes: [u8; 32] = lav_core::crypto::random_bytes();
        let mut hex = Zeroizing::new(String::with_capacity(65));
        for b in bytes {
            hex.push_str(&format!("{b:02X}"));
        }
        hex.push('\n');
        let mut f =
            crate::private::create_new(&path).map_err(|_| KEYFILE_WRITE_FAILED.to_owned())?;
        std::io::Write::write_all(&mut f, hex.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|_| KEYFILE_WRITE_FAILED.to_owned())?;
        Ok(self.set_pending_keyfile(Some(path)).unwrap_or_default())
    }

    /// Adds or replaces the key file (`use_pending`) or removes it. Needs
    /// the current password and key file; the password stays. Removing the
    /// key file needs a password of at least 8 characters.
    pub fn change_keyfile(&mut self, current: &str, use_pending: bool) -> Result<(), String> {
        let path = self.path.clone().ok_or(NO_FILE_SELECTED)?;
        let old = self.keyfile_bytes()?;
        let new_path = if use_pending {
            Some(self.pending_keyfile.clone().ok_or(NO_PENDING_KEYFILE)?)
        } else {
            None
        };
        let new = match &new_path {
            Some(p) => Some(Vault::read_keyfile(p).map_err(|_| KEYFILE_READ_FAILED.to_owned())?),
            None => None,
        };
        let (old_k, new_k) = (
            old.as_deref().map(|k| k.as_slice()),
            new.as_deref().map(|k| k.as_slice()),
        );
        let vault = self.vault.as_mut().ok_or(LOCKED)?;
        vault
            .change_credentials(current, old_k, current, new_k, None)
            .map_err(|e| match e {
                CoreError::WrongCurrentCredentials => WRONG_CURRENT.to_owned(),
                CoreError::WeakPassword(_) => WEAK_PASSWORD.to_owned(),
                _ => CREATE_FAILED.to_owned(),
            })?;
        if let Err(e) = vault.save_file(&path) {
            let _ = vault.change_credentials(current, new_k, current, old_k, None);
            return Err(match e {
                CoreError::FileChangedOnDisk => CHANGED_ON_DISK.to_owned(),
                _ => SAVE_FAILED.to_owned(),
            });
        }
        self.keyfile = new_path;
        self.pending_keyfile = None;
        Ok(())
    }

    // ----- merge -----

    pub fn set_merge_path(&mut self, path: PathBuf) -> String {
        let name = file_name(&path);
        self.merge_path = Some(path);
        self.merge_keyfile = None;
        name
    }

    pub fn set_merge_keyfile(&mut self, path: Option<PathBuf>) -> Option<String> {
        self.merge_keyfile = path;
        self.merge_keyfile.as_deref().map(file_name)
    }

    /// Opens the other .lav file with its own password (and key file) and
    /// merges it into this vault (KeePass "Synchronize"); saves this vault.
    /// The other file is only read.
    pub fn merge(&mut self, password: &str) -> Result<MergeSummary, String> {
        if self.vault.is_none() {
            return Err(LOCKED.into());
        }
        let other_path = self.merge_path.clone().ok_or(NO_FILE_SELECTED)?;
        if self
            .path
            .as_deref()
            .is_some_and(|p| same_file(p, &other_path))
        {
            return Err(SAME_VAULT.into());
        }
        let kf = match &self.merge_keyfile {
            Some(k) => Some(Vault::read_keyfile(k).map_err(|_| KEYFILE_READ_FAILED.to_owned())?),
            None => None,
        };
        let other = Vault::open_file(&other_path, password, kf.as_deref().map(|k| k.as_slice()))
            .map_err(|e| unlock_error(&e))?;
        let r = self.commit(|data| Ok(data.merge_from(&other.data)))?;
        self.merge_path = None;
        self.merge_keyfile = None;
        Ok(MergeSummary {
            added: r.added,
            updated: r.updated,
            removed: r.removed,
            groups_added: r.groups_added,
        })
    }

    // ----- exports -----

    fn verify_current(&self, current: &str) -> Result<&Vault, String> {
        let kf = self.keyfile_bytes()?;
        let vault = self.vault.as_ref().ok_or(LOCKED)?;
        let ok = vault
            .verify_credentials(current, kf.as_deref().map(|k| k.as_slice()))
            .unwrap_or(false);
        if ok {
            Ok(vault)
        } else {
            Err(WRONG_CURRENT.into())
        }
    }

    /// The vault as a KeePass KDBX 4 file with its own password.
    pub fn export_kdbx(
        &self,
        current: &str,
        kdbx_password: &str,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let vault = self.verify_current(current)?;
        crate::export::kdbx(&vault.data, kdbx_password).map_err(str::to_owned)
    }

    /// A printable, plain-text HTML page of the vault.
    pub fn export_html(
        &self,
        current: &str,
        include_passwords: bool,
        generated: &str,
    ) -> Result<Zeroizing<String>, String> {
        let vault = self.verify_current(current)?;
        Ok(crate::export::html(
            &vault.data,
            include_passwords,
            generated,
        ))
    }

    pub fn health(&self, now: i64) -> Result<crate::health::Report, String> {
        let vault = self.vault.as_ref().ok_or(LOCKED)?;
        // Entries in the recycle bin are not counted.
        let live: Vec<&Entry> = vault
            .data
            .entries
            .iter()
            .filter(|e| !vault.data.in_recycle_bin(e.group))
            .collect();
        Ok(crate::health::check_refs(&live, now))
    }

    fn entry_ref(&self, id: &str) -> Result<&Entry, String> {
        let vault = self.vault.as_ref().ok_or(LOCKED)?;
        vault
            .data
            .entries
            .iter()
            .find(|e| e.id.to_string() == id)
            .ok_or_else(|| NO_SUCH_ENTRY.to_owned())
    }

    pub fn extras(&self, id: &str) -> Result<EntryExtras, String> {
        let e = self.entry_ref(id)?;
        let mut history: Vec<VersionView> = e
            .history
            .iter()
            .map(|v| VersionView {
                modified: v.modified,
                title: v.title.clone(),
                username: v.username.clone(),
                password_differs: v.password.expose() != e.password.expose(),
            })
            .collect();
        history.reverse(); // newest first
        Ok(EntryExtras {
            fields: e
                .fields
                .iter()
                .map(|f| FieldView {
                    name: f.name.clone(),
                    value: (!f.protected).then(|| f.value.expose().to_owned()),
                    protected: f.protected,
                })
                .collect(),
            attachments: e
                .attachments
                .iter()
                .map(|a| AttachmentView {
                    name: a.name.clone(),
                    size: a.data.len(),
                })
                .collect(),
            history,
            tags: e.tags.clone(),
            has_notes: !e.notes.is_empty(),
            created: e.created,
            modified: e.modified,
            expires: e.expires,
        })
    }

    /// Notes or one custom field value, in a self-wiping buffer.
    pub fn extra(&self, id: &str, what: Extra) -> Result<Zeroizing<String>, String> {
        let e = self.entry_ref(id)?;
        match what {
            Extra::Notes => Ok(Zeroizing::new(e.notes.expose().to_owned())),
            Extra::Custom(i) => e
                .fields
                .get(i)
                .map(|f| Zeroizing::new(f.value.expose().to_owned()))
                .ok_or_else(|| NO_SUCH_ITEM.to_owned()),
        }
    }

    /// An attachment's name and bytes (for "Kaydet").
    pub fn attachment(
        &self,
        id: &str,
        index: usize,
    ) -> Result<(String, Zeroizing<Vec<u8>>), String> {
        let e = self.entry_ref(id)?;
        let a = e.attachments.get(index).ok_or(NO_SUCH_ITEM)?;
        Ok((a.name.clone(), Zeroizing::new(a.data.expose().to_vec())))
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
        // Field references ({REF:...}) give the value they point at.
        Ok(match field {
            Field::Username => resolve_refs(&vault.data, &e.username),
            Field::Password => resolve_refs(&vault.data, e.password.expose()),
            Field::Totp => {
                return self
                    .totp_at(id, crate::recent::now())
                    .map(|c| Zeroizing::new(c.code))
            }
        })
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
                icon: e.icon.as_ref().map(|i| {
                    use base64::Engine;
                    format!(
                        "data:image/png;base64,{}",
                        base64::engine::general_purpose::STANDARD.encode(&i.png)
                    )
                }),
                in_recycle_bin: data.in_recycle_bin(e.group),
                expires: e.expires,
                tags: e.tags.clone(),
                fg_color: e.fg_color.clone().filter(|c| color_ok(c)),
                bg_color: e.bg_color.clone().filter(|c| color_ok(c)),
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

/// The entry's own window rule, or else its title and site.
pub fn autotype_target(e: &Entry) -> crate::autotype::Target {
    match e
        .autotype
        .as_ref()
        .map(|a| a.window.trim())
        .filter(|w| !w.is_empty())
    {
        Some(w) => crate::autotype::Target::Pattern(w.to_owned()),
        None => {
            crate::autotype::Target::Markers(crate::autotype::expected_markers(&e.title, &e.url))
        }
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
    fn folder_icons_are_validated_and_saved() {
        let dir = temp_dir("icons");
        let path = make_vault(&dir);
        let mut s = Session::default();
        s.select(path.clone());
        s.unlock(PASSWORD).unwrap();
        let g = s.add_group(None, "İş").unwrap();
        for bad in ["", "Briefcase", "<svg>", "a b", "../x", &"a".repeat(41)] {
            assert_eq!(
                s.set_group_icon(&g, Some(bad)),
                Err(BAD_ICON.to_owned()),
                "{bad:?}"
            );
        }
        s.set_group_icon(&g, Some("building-columns")).unwrap();
        s.lock();
        let mut t = Session::default();
        t.select(path);
        t.unlock(PASSWORD).unwrap();
        let icon = |t: &Session| {
            t.groups()
                .unwrap()
                .into_iter()
                .find(|v| v.id == g)
                .unwrap()
                .icon
        };
        assert_eq!(icon(&t).as_deref(), Some("building-columns"));
        t.set_group_icon(&g, None).unwrap();
        assert_eq!(icon(&t), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn folders_and_entries_move_and_are_saved() {
        let dir = temp_dir("move");
        let path = make_vault(&dir);
        let mut s = Session::default();
        s.select(path.clone());
        s.unlock(PASSWORD).unwrap();
        let a = s.add_group(None, "A").unwrap();
        let b = s.add_group(Some(&a), "B").unwrap();
        let x = s.add_group(None, "X").unwrap();
        let root = s
            .groups()
            .unwrap()
            .into_iter()
            .find(|g| g.parent.is_none())
            .unwrap()
            .id;
        let zeta = s
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.title == "zeta")
            .unwrap()
            .id;

        assert_eq!(s.move_group(&a, Some(&b)), Err(INVALID_MOVE.to_owned()));
        assert_eq!(s.move_group(&a, Some(&a)), Err(INVALID_MOVE.to_owned()));
        assert_eq!(
            s.move_group(&root, Some(&x)),
            Err(CANNOT_MOVE_ROOT.to_owned())
        );
        assert_eq!(
            s.move_group(&a, Some("nope")),
            Err(NO_SUCH_GROUP.to_owned())
        );
        assert_eq!(s.move_entry("nope", &x), Err(NO_SUCH_ENTRY.to_owned()));
        assert_eq!(s.move_entry(&zeta, "nope"), Err(NO_SUCH_GROUP.to_owned()));

        s.move_group(&a, Some(&x)).unwrap();
        s.move_entry(&zeta, &b).unwrap();
        s.move_group(&x, None).unwrap(); // already at the top: no-op

        // Saved to disk: a fresh session sees the same tree.
        s.lock();
        let mut t = Session::default();
        t.select(path);
        t.unlock(PASSWORD).unwrap();
        let parent_of = |id: &str| {
            t.groups()
                .unwrap()
                .into_iter()
                .find(|g| g.id == id)
                .unwrap()
                .parent
        };
        assert_eq!(parent_of(&a), Some(x.clone()));
        assert_eq!(parent_of(&b), Some(a.clone()));
        let moved = t
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.id == zeta)
            .unwrap();
        assert_eq!(moved.group_id, b);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn autotype_matches_and_web_address() {
        let dir = temp_dir("hotkey");
        let mut s = Session::default();
        s.select(make_vault(&dir));
        assert_eq!(s.autotype_matches("Example Domain"), Err(LOCKED.to_owned()));
        s.unlock(PASSWORD).unwrap();
        let ids = |title: &str| -> Vec<String> {
            s.autotype_matches(title)
                .unwrap()
                .into_iter()
                .map(|(_, t)| t)
                .collect()
        };
        // "zeta" has https://example.com; "Alpha" has no site.
        assert_eq!(ids("Example Domain - Microsoft Edge"), ["zeta"]);
        assert_eq!(ids("Alpha Bank - Google Chrome"), ["Alpha"]);
        assert_eq!(ids("alpha | example.com"), ["zeta", "Alpha"]);
        assert!(ids("Notepad").is_empty());

        let zeta = s
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.title == "zeta")
            .unwrap();
        let alpha = s
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.title == "Alpha")
            .unwrap();
        assert_eq!(
            s.web_address(&zeta.id).unwrap().as_str(),
            "https://example.com/"
        );
        assert_eq!(
            s.web_address(&alpha.id),
            Err(crate::browser::NOT_A_WEB_ADDRESS.to_owned())
        );
        s.lock();
        assert_eq!(s.web_address(&zeta.id), Err(LOCKED.to_owned()));
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

    fn id_of(s: &Session, title: &str) -> String {
        s.entries()
            .unwrap()
            .into_iter()
            .find(|e| e.title == title)
            .unwrap()
            .id
    }

    #[test]
    fn hidden_search_never_looks_at_protected_values() {
        let (dir, mut s) = opened("search");
        let id = s.save_entry(&form(&s, None, "Arama")).unwrap();
        let both = SearchScope {
            notes: true,
            fields: true,
        };
        assert_eq!(
            s.search_hidden("RECOVERY code", both).unwrap(),
            vec![id_of(&s, "zeta")]
        );
        assert_eq!(
            s.search_hidden("hesap TİPİ", both).unwrap(),
            vec![id.clone()],
            "field name"
        );
        assert_eq!(
            s.search_hidden("pro", both).unwrap(),
            vec![id.clone()],
            "open value"
        );
        assert!(
            s.search_hidden("4321", both).unwrap().is_empty(),
            "protected value"
        );
        assert!(s
            .search_hidden("recovery", SearchScope::default())
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn references_resolve_for_copy_and_auto_type() {
        let (dir, mut s) = opened("refs");
        let zeta = id_of(&s, "zeta");
        let simple = uuid::Uuid::parse_str(&zeta).unwrap().simple().to_string();
        let mut f = form(&s, None, "Ref");
        f.username = format!("{{REF:U@I:{}}}", simple.to_uppercase());
        f.password = "ön-{REF:P@T:zeta}-son {REF:P@I:yok}".into();
        f.autotype_sequence = "{USERNAME}{TAB}{PASSWORD}{DELAY 5}{S:hesap tipi}{ENTER}".into();
        f.autotype_window = "*Örnek*Giriş*".into();
        let id = s.save_entry(&f).unwrap();
        assert_eq!(
            s.field(&id, Field::Username).unwrap().as_str(),
            "me@example.com"
        );
        assert_eq!(
            s.field(&id, Field::Password).unwrap().as_str(),
            format!("ön-{SECRET}-son {{REF:P@I:yok}}"),
            "a broken reference stays as it is"
        );
        let (steps, target) = s.autotype_data(&id).unwrap();
        let typed: Vec<String> = steps
            .iter()
            .map(|st| match st {
                crate::autotype::Step::Text(t) => t.to_string(),
                crate::autotype::Step::Tab => "<TAB>".into(),
                crate::autotype::Step::Enter => "<ENTER>".into(),
                crate::autotype::Step::Delay(_) => "<DELAY>".into(),
            })
            .collect();
        assert_eq!(typed[0], "me@example.com");
        assert_eq!(typed[2], format!("ön-{SECRET}-son {{REF:P@I:yok}}"));
        assert_eq!(&typed[3..], ["<DELAY>", "Pro", "<ENTER>"]);
        assert!(target.matches("örnek sitesi - GİRİŞ - Edge"));
        assert!(
            !target.matches("Ref"),
            "the window rule replaces the title rule"
        );
        assert_eq!(s.autotype_matches("Örnek Giriş").unwrap().len(), 1);
        // A reference to itself does not loop.
        let mut f2 = s.entry_form(&id).unwrap();
        f2.password = format!(
            "{{REF:P@I:{}}}",
            uuid::Uuid::parse_str(&id).unwrap().simple()
        );
        s.save_entry(&f2).unwrap();
        assert!(s.field(&id, Field::Password).unwrap().contains("{REF:"));
        // Auto-type off; bad sequence, window rule and colour are refused.
        f2.autotype_enabled = false;
        s.save_entry(&f2).unwrap();
        assert!(matches!(s.autotype_data(&id), Err(e) if e == AUTOTYPE_OFF));
        assert!(s.autotype_matches("Örnek Giriş").unwrap().is_empty());
        let mut bad = s.entry_form(&id).unwrap();
        bad.autotype_sequence = "{NOPE}".into();
        assert!(s.save_entry(&bad).is_err());
        let mut bad = s.entry_form(&id).unwrap();
        bad.autotype_window = "*".into();
        assert_eq!(
            s.save_entry(&bad),
            Err(crate::autotype::BAD_WINDOW_RULE.into())
        );
        let mut bad = s.entry_form(&id).unwrap();
        bad.fg_color = Some("red;background:url(x)".into());
        assert_eq!(s.save_entry(&bad), Err(BAD_COLOR.into()));
        let mut ok = s.entry_form(&id).unwrap();
        ok.bg_color = Some("#AABBCC".into());
        s.save_entry(&ok).unwrap();
        let e = s
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.id == id)
            .unwrap();
        assert_eq!(e.bg_color.as_deref(), Some("#aabbcc"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vault_settings_history_and_kdf() {
        let (dir, mut s) = opened("vset");
        let zeta = id_of(&s, "zeta");
        for i in 0..4 {
            let mut f = s.entry_form(&zeta).unwrap();
            f.password = format!("p{i}");
            s.save_entry(&f).unwrap();
        }
        assert_eq!(s.vault_settings().unwrap().history_versions, 4);
        s.set_vault_settings("  Yeni ad ", "açıklama", 2).unwrap();
        let v = s.vault_settings().unwrap();
        assert_eq!(
            (v.name.as_str(), v.description.as_str()),
            ("Yeni ad", "açıklama")
        );
        assert_eq!((v.history_limit, v.history_versions), (2, 2));
        assert!(
            s.groups().unwrap().iter().any(|g| g.name == "Yeni ad"),
            "top folder renamed"
        );
        assert_eq!(s.set_vault_settings(" ", "", 2), Err(EMPTY_NAME.into()));
        assert_eq!(s.clear_history(None).unwrap(), 2);

        assert_eq!(s.change_kdf("yanlis", 32, 2, 1), Err(WRONG_CURRENT.into()));
        assert_eq!(s.change_kdf(PASSWORD, 2048, 2, 1), Err(BAD_KDF.into()));
        s.change_kdf(PASSWORD, 32, 3, 2).unwrap();
        let v = s.vault_settings().unwrap();
        assert_eq!(
            (v.kdf.memory_mib, v.kdf.iterations, v.kdf.parallelism),
            (32, 3, 2)
        );
        // The new cost is on disk and the vault still opens.
        let path = s.open_path().unwrap();
        let mut again = Session::default();
        let shown = again.select(path);
        assert_eq!(shown.kdf.unwrap().memory_mib, 32);
        again.unlock(PASSWORD).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn key_file_can_be_added_and_removed() {
        let (dir, mut s) = opened("kfile");
        let kf = dir.join("yeni.key");
        assert_eq!(
            s.change_keyfile(PASSWORD, true),
            Err(NO_PENDING_KEYFILE.into())
        );
        assert_eq!(s.create_keyfile(kf.clone()).unwrap(), "yeni.key");
        assert!(s.create_keyfile(kf.clone()).is_err(), "never overwrites");
        assert_eq!(std::fs::read(&kf).unwrap().len(), 65);
        assert_eq!(s.change_keyfile("yanlis", true), Err(WRONG_CURRENT.into()));
        s.change_keyfile(PASSWORD, true).unwrap();
        assert!(s.vault_settings().unwrap().keyfile_required);
        let path = s.open_path().unwrap();
        let mut other = Session::default();
        other.select(path.clone());
        assert_eq!(
            other.unlock(PASSWORD),
            Err(UNLOCK_FAILED.into()),
            "key file needed"
        );
        other.set_keyfile(Some(kf.clone()));
        other.unlock(PASSWORD).unwrap();
        // And off again.
        s.change_keyfile(PASSWORD, false).unwrap();
        let mut plain = Session::default();
        plain.select(path);
        plain.unlock(PASSWORD).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn merge_with_another_file() {
        let (dir, mut s) = opened("merge");
        // A copy of the file, changed on its own.
        let path = s.open_path().unwrap();
        let copy = dir.join("kopya.lav");
        std::fs::copy(&path, &copy).unwrap();
        let mut other = Session::default();
        other.select(copy.clone());
        other.unlock(PASSWORD).unwrap();
        other
            .save_entry(&form(&other, None, "Diğer cihaz"))
            .unwrap();
        let alpha = id_of(&other, "Alpha");
        other.delete_entry(&alpha).unwrap();
        other.delete_entry(&alpha).unwrap(); // from the bin: for good
        other.lock();

        assert_eq!(s.merge(PASSWORD), Err(NO_FILE_SELECTED.into()));
        s.set_merge_path(path.clone());
        assert_eq!(s.merge(PASSWORD), Err(SAME_VAULT.into()));
        s.set_merge_path(copy.clone());
        assert_eq!(s.merge("yanlis"), Err(UNLOCK_FAILED.into()));
        s.set_merge_path(copy);
        let r = s.merge(PASSWORD).unwrap();
        assert_eq!((r.added, r.removed), (1, 1));
        let titles: Vec<String> = s.entries().unwrap().into_iter().map(|e| e.title).collect();
        assert!(titles.contains(&"Diğer cihaz".into()) && !titles.contains(&"Alpha".into()));
        // Saved: a fresh open sees the merge.
        let mut again = Session::default();
        again.select(path);
        again.unlock(PASSWORD).unwrap();
        assert_eq!(again.entries().unwrap().len(), s.entries().unwrap().len());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn exports_need_the_master_password() {
        let (dir, s) = opened("exports");
        assert_eq!(
            s.export_html("yanlis", true, "x").err(),
            Some(WRONG_CURRENT.into())
        );
        assert_eq!(
            s.export_kdbx("yanlis", "kdbx-parola").err(),
            Some(WRONG_CURRENT.into())
        );
        let page = s.export_html(PASSWORD, true, "x").unwrap();
        assert!(page.contains(SECRET));
        assert!(!s
            .export_html(PASSWORD, false, "x")
            .unwrap()
            .contains(SECRET));
        let _ = std::fs::remove_dir_all(dir);
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
            fields: Some(vec![
                FormField {
                    name: "PIN".into(),
                    value: "4321".into(),
                    protected: true,
                },
                FormField {
                    name: "Hesap tipi".into(),
                    value: "Pro".into(),
                    protected: false,
                },
            ]),
            expires: None,
            autotype_sequence: String::new(),
            autotype_window: String::new(),
            autotype_enabled: true,
            fg_color: None,
            bg_color: None,
        }
    }

    #[test]
    fn expiry_is_saved_cleared_and_checked() {
        let (dir, mut s) = opened("expiry");
        let mut f = form(&s, None, "Süreli");
        f.expires = Some(1_900_000_000);
        let id = s.save_entry(&f).unwrap();
        s.lock();
        s.unlock(PASSWORD).unwrap();
        assert_eq!(s.entry_form(&id).unwrap().expires, Some(1_900_000_000));
        assert_eq!(s.extras(&id).unwrap().expires, Some(1_900_000_000));

        // A past date shows up in the health report as expired.
        let mut f = s.entry_form(&id).unwrap();
        f.expires = Some(1_000);
        s.save_entry(&f).unwrap();
        let h = s.health(2_000).unwrap();
        assert!(h.expired >= 1);

        // Out-of-range values are refused and change nothing.
        for bad in [-1, MAX_EXPIRY + 1, i64::MAX] {
            let mut f = s.entry_form(&id).unwrap();
            f.expires = Some(bad);
            assert_eq!(s.save_entry(&f), Err(BAD_EXPIRY.to_owned()));
        }
        assert_eq!(s.entry_form(&id).unwrap().expires, Some(1_000));

        // Clearing it means "never expires".
        let mut f = s.entry_form(&id).unwrap();
        f.expires = None;
        s.save_entry(&f).unwrap();
        s.lock();
        s.unlock(PASSWORD).unwrap();
        assert_eq!(s.entry_form(&id).unwrap().expires, None);

        // An old client that does not send the field reads as "never".
        let json = r#"{"id":null,"groupId":"x","title":"t","username":"","password":"",
            "url":"","notes":"","tags":[]}"#;
        let old: EntryForm = serde_json::from_str(json).unwrap();
        assert_eq!(old.expires, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn duplicate_is_saved_without_history() {
        let (dir, mut s) = opened("dup");
        let id = s
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.title == "zeta")
            .unwrap()
            .id;
        // Give the original some history.
        let mut f = s.entry_form(&id).unwrap();
        f.password = "ikinci".into();
        s.save_entry(&f).unwrap();
        let before = s.entries().unwrap().len();

        let copy = s.duplicate_entry(&id).unwrap();
        assert_ne!(copy, id);
        s.lock();
        s.unlock(PASSWORD).unwrap();
        assert_eq!(s.entries().unwrap().len(), before + 1);
        let c = s.entry_form(&copy).unwrap();
        assert_eq!(c.title, format!("zeta{COPY_SUFFIX}"));
        assert_eq!(c.password, "ikinci");
        assert_eq!(c.notes, NOTE);
        assert_eq!(c.group_id, s.entry_form(&id).unwrap().group_id);
        assert!(s.extras(&copy).unwrap().history.is_empty());
        assert_eq!(s.extras(&id).unwrap().history.len(), 1);
        assert_eq!(s.duplicate_entry("missing"), Err(NO_SUCH_ENTRY.to_owned()));
        s.lock();
        assert_eq!(s.duplicate_entry(&id), Err(LOCKED.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
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

        // First delete: into the recycle bin (persisted), still there.
        assert_eq!(s.delete_entry(&id), Ok(false));
        s.lock();
        s.unlock(PASSWORD).unwrap();
        let e = s
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.id == id)
            .unwrap();
        assert!(e.in_recycle_bin);
        let bin = s
            .groups()
            .unwrap()
            .into_iter()
            .find(|g| g.recycle_bin)
            .unwrap();
        assert_eq!(e.group_id, bin.id);
        assert_eq!(bin.icon.as_deref(), Some("trash"));

        // Second delete, from the bin: gone for good.
        assert_eq!(s.delete_entry(&id), Ok(true));
        s.lock();
        s.unlock(PASSWORD).unwrap();
        assert_eq!(s.entry_form(&id), Err(NO_SUCH_ENTRY.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recycle_bin_is_left_out_of_health_and_auto_type() {
        let (dir, mut s) = opened("bin-health");
        let id = s
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.title == "zeta")
            .unwrap()
            .id;
        let checked = s.health(0).unwrap().checked;
        assert_eq!(s.autotype_matches("zeta - Chrome").unwrap().len(), 1);
        s.delete_entry(&id).unwrap();
        assert_eq!(s.health(0).unwrap().checked, checked - 1);
        assert!(s.autotype_matches("zeta - Chrome").unwrap().is_empty());

        // Emptying deletes for good and keeps the bin folder.
        let before = s.entries().unwrap().len();
        s.empty_recycle_bin().unwrap();
        s.lock();
        s.unlock(PASSWORD).unwrap();
        assert_eq!(s.entries().unwrap().len(), before - 1);
        assert!(s.groups().unwrap().iter().any(|g| g.recycle_bin));
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
    fn import_needs_open_vault_and_file_and_keeps_vault_on_failure() {
        let (dir, mut s) = opened("import");
        assert_eq!(s.import_keepass("x"), Err(NO_FILE_SELECTED.to_owned()));
        let junk = dir.join("junk.kdbx");
        std::fs::write(&junk, b"not keepass").unwrap();
        s.select_import(junk);
        let before = s.entries().unwrap();
        assert_eq!(
            s.import_keepass("x"),
            Err(crate::import::NOT_KDBX4.to_owned())
        );
        assert_eq!(s.entries().unwrap(), before);
        s.lock();
        assert_eq!(s.import_keepass("x"), Err(LOCKED.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn key_file_is_required_used_and_never_carried_over() {
        let dir = temp_dir("keyfile");
        let key = dir.join("anahtar.bin");
        std::fs::write(&key, b"keyfile-bytes-0123456789").unwrap();
        let path = dir.join("kf.lav");
        let mut v = Vault::create(
            "KF",
            PASSWORD,
            Some(b"keyfile-bytes-0123456789"),
            fast_kdf(),
        )
        .unwrap();
        v.save_file(&path).unwrap();

        let mut s = Session::default();
        let info = s.select(path.clone());
        assert!(info.keyfile_required);
        assert_eq!(
            s.unlock(PASSWORD),
            Err(UNLOCK_FAILED.to_owned()),
            "no key file"
        );
        assert_eq!(
            s.set_keyfile(Some(key.clone())).as_deref(),
            Some("anahtar.bin")
        );
        assert_eq!(s.unlock(PASSWORD).unwrap().name, "KF");

        // Selecting a vault drops the key file; a key file for a vault that
        // has none is refused with the same generic message.
        let plain = make_vault(&dir);
        s.select(plain);
        s.set_keyfile(Some(key));
        assert_eq!(s.unlock(PASSWORD), Err(UNLOCK_FAILED.to_owned()));
        s.set_keyfile(None);
        assert!(s.unlock(PASSWORD).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn custom_fields_history_and_extras() {
        let (dir, mut s) = opened("extras");
        let id = s.save_entry(&form(&s, None, "Alanlı")).unwrap();
        let x = s.extras(&id).unwrap();
        assert_eq!(x.fields.len(), 2);
        assert_eq!(x.fields[0].value, None, "protected value not sent");
        assert_eq!(x.fields[1].value.as_deref(), Some("Pro"));
        assert!(x.has_notes);
        assert!(x.history.is_empty());
        let json = serde_json::to_string(&x).unwrap();
        assert!(!json.contains("4321") && !json.contains("yeni-gizli-parola"));
        assert_eq!(s.extra(&id, Extra::Custom(0)).unwrap().as_str(), "4321");
        assert_eq!(s.extra(&id, Extra::Notes).unwrap().as_str(), "not");
        assert_eq!(s.extra(&id, Extra::Custom(9)), Err(NO_SUCH_ITEM.to_owned()));

        // Editing creates a version; fields None keeps the fields.
        let mut f = s.entry_form(&id).unwrap();
        f.password = "baska".into();
        f.fields = None;
        s.save_entry(&f).unwrap();
        let x = s.extras(&id).unwrap();
        assert_eq!(x.fields.len(), 2, "kept");
        assert_eq!(x.history.len(), 1);
        assert!(x.history[0].password_differs);

        let mut f = s.entry_form(&id).unwrap();
        f.fields = Some(vec![FormField {
            name: " ".into(),
            value: "x".into(),
            protected: false,
        }]);
        assert_eq!(s.save_entry(&f), Err(BAD_FIELD.to_owned()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn extra_names_from_the_webview() {
        let n: Extra = serde_json::from_str(r#"{"kind":"notes"}"#).unwrap();
        assert_eq!(n, Extra::Notes);
        let c: Extra = serde_json::from_str(r#"{"kind":"custom","index":3}"#).unwrap();
        assert_eq!(c, Extra::Custom(3));
    }

    #[test]
    fn folders_add_rename_delete_with_entries() {
        let (dir, mut s) = opened("groups");
        let root = s.groups().unwrap()[0].id.clone();
        let g = s.add_group(None, "  Finans ").unwrap();
        let sub = s.add_group(Some(&g), "Kartlar").unwrap();
        let mut f = form(&s, None, "Kart");
        f.group_id = sub.clone();
        s.save_entry(&f).unwrap();
        let gv = s.groups().unwrap();
        let fin = gv.iter().find(|x| x.id == g).unwrap();
        assert_eq!(
            (fin.name.as_str(), fin.entries, fin.total_entries),
            ("Finans", 0, 1)
        );
        assert_eq!(s.add_group(None, " "), Err(EMPTY_GROUP_NAME.to_owned()));
        s.rename_group(&g, "Banka").unwrap();
        assert_eq!(s.delete_group(&root), Err(CANNOT_DELETE_ROOT.to_owned()));
        let before = s.entries().unwrap().len();
        // First delete: the folder moves into the recycle bin with its entry.
        assert_eq!(s.delete_group(&g), Ok(false));
        s.lock();
        s.unlock(PASSWORD).unwrap();
        let gv = s.groups().unwrap();
        let bin = gv.iter().find(|x| x.recycle_bin).unwrap();
        assert_eq!(
            gv.iter().find(|x| x.id == g).unwrap().parent,
            Some(bin.id.clone())
        );
        assert_eq!(s.entries().unwrap().len(), before);
        // Deleting it again (from the bin): gone with its entry, persisted.
        assert_eq!(s.delete_group(&g), Ok(true));
        s.lock();
        s.unlock(PASSWORD).unwrap();
        assert!(!s.groups().unwrap().iter().any(|x| x.id == g || x.id == sub));
        assert_eq!(s.entries().unwrap().len(), before - 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn change_master_needs_current_and_persists() {
        let (dir, mut s) = opened("master");
        assert_eq!(
            s.change_master("yanlış", "yeni-ana-parola", "yeni-ana-parola"),
            Err(WRONG_CURRENT.to_owned())
        );
        assert_eq!(
            s.change_master(PASSWORD, "yeni-ana-parola", "farklı"),
            Err(PASSWORDS_DIFFER.to_owned())
        );
        assert_eq!(
            s.change_master(PASSWORD, "kisa", "kisa"),
            Err(WEAK_PASSWORD.to_owned())
        );
        s.change_master(PASSWORD, "yeni-ana-parola", "yeni-ana-parola")
            .unwrap();
        s.lock();
        assert_eq!(s.unlock(PASSWORD), Err(UNLOCK_FAILED.to_owned()));
        assert!(s.unlock("yeni-ana-parola").is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn restore_attachments_and_export() {
        let (dir, mut s) = opened("restore");
        let id = s.save_entry(&form(&s, None, "=SUM(A1)")).unwrap();
        let mut f = s.entry_form(&id).unwrap();
        f.password = "ikinci".into();
        s.save_entry(&f).unwrap();
        s.restore_version(&id, 0).unwrap();
        assert_eq!(s.entry_form(&id).unwrap().password, "yeni-gizli-parola");
        assert_eq!(s.extras(&id).unwrap().history.len(), 2, "nothing lost");
        assert_eq!(s.restore_version(&id, 9), Err(NO_SUCH_ITEM.to_owned()));

        let file = dir.join("ek.txt");
        std::fs::write(&file, b"kurtarma kodlari").unwrap();
        s.add_attachment(&id, &file).unwrap();
        assert_eq!(
            s.attachment(&id, 0).unwrap().1.as_slice(),
            b"kurtarma kodlari"
        );
        s.remove_attachment(&id, 0).unwrap();
        assert!(s.extras(&id).unwrap().attachments.is_empty());

        assert_eq!(s.export_csv("yanlış").err(), Some(WRONG_CURRENT.to_owned()));
        let csv = s.export_csv(PASSWORD).unwrap();
        assert!(csv.contains("\"'=SUM(A1)\""), "formula neutralised");
        assert!(csv.contains("yeni-gizli-parola"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn csv_cells_are_quoted_and_safe() {
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_cell("+1"), "\"'+1\"");
        assert_eq!(csv_cell("@x"), "\"'@x\"");
        assert_eq!(csv_cell("-2"), "\"'-2\"");
        assert_eq!(csv_cell("normal"), "\"normal\"");
    }

    #[test]
    fn create_with_key_file() {
        let dir = temp_dir("create-kf");
        let key = dir.join("k.bin");
        std::fs::write(&key, b"0123456789abcdef-key").unwrap();
        let mut s = Session::default();
        s.select_new(dir.join("kf.lav"));
        s.set_keyfile(Some(key.clone()));
        s.create_with("KF", PASSWORD, PASSWORD, fast_kdf()).unwrap();
        s.lock();
        assert!(
            s.unlock(PASSWORD).is_ok(),
            "key file kept for the new vault"
        );
        s.set_keyfile(None);
        assert_eq!(s.unlock(PASSWORD), Err(UNLOCK_FAILED.to_owned()));
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
            pattern: String::new(),
        };
        let p = generate(&o).unwrap();
        assert_eq!(p.chars().count(), 24);
        assert!(p.chars().all(|c| c.is_ascii_digit()));
        let none = GenOptions {
            digits: false,
            ..o.clone()
        };
        assert_eq!(generate(&none), Err(BAD_GENERATOR.to_owned()));
        // A pattern wins over the classes (even with none enabled).
        let pat = GenOptions {
            pattern: "uu-d{3}".into(),
            ..none
        };
        let p = generate(&pat).unwrap();
        assert_eq!(p.len(), 6);
        assert_eq!(&p[2..3], "-");
        let bad = GenOptions {
            pattern: "d{0}".into(),
            ..o
        };
        assert_eq!(generate(&bad), Err(BAD_GENERATOR.to_owned()));
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
