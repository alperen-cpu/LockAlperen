//! KeePass (KDBX 4) import (SECURITY_AUDIT §6, "KDBX içe aktarma").
//!
//! The file is untrusted. Before the `keepass` crate sees it, we read the
//! outer header ourselves and refuse:
//! - anything but KDBX 4 (no KDBX 3.1 / KDB),
//! - files over MAX_KDBX_BYTES,
//! - KDF parameters that would cost unbounded memory or time (the crate does
//!   not limit them: a crafted file could ask for terabytes of Argon2 memory
//!   or billions of AES-KDF rounds before the password is even checked).
//!
//! After decryption every count and length is bounded again, the KeePass
//! recycle bin is skipped, and the result goes through `repair_structure`.
//! The import is added under a new top-level group; nothing existing is
//! changed.

use std::collections::HashMap;

use keepass::{config::DatabaseVersion, Database, DatabaseKey};
use lav_core::{Attachment, CustomField, Entry, SecretBytes, SecretString, VaultData};
use serde::Serialize;

pub const MAX_KDBX_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ARGON2_MEMORY: u64 = 1024 * 1024 * 1024; // 1 GiB
pub const MAX_ARGON2_ITERATIONS: u64 = 100;
pub const MAX_ARGON2_PARALLELISM: u64 = 16;
pub const MAX_AES_ROUNDS: u64 = 300_000_000;
pub const MAX_HEADER_FIELD: usize = 1024 * 1024;
pub const MAX_ENTRIES: usize = 50_000;
pub const MAX_GROUPS: usize = 10_000;
pub const MAX_DEPTH: usize = 64;
/// Per text field (title, password, notes, custom field value...).
pub const MAX_FIELD_BYTES: usize = 1024 * 1024;
pub const MAX_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TOTAL_ATTACHMENT_BYTES: usize = 256 * 1024 * 1024;

pub const NOT_KDBX4: &str = "Bu dosya KDBX 4 biçiminde değil. Yalnızca KeePass 2.35 ve sonrası \
     (KDBX 4) desteklenir; eski bir dosyayı KeePass'te açıp yeniden kaydedin.";
pub const TOO_LARGE: &str = "KeePass dosyası çok büyük (en fazla 64 MiB).";
pub const UNSAFE_KDF: &str = "Dosyanın anahtar türetme ayarları güvenli sınırların dışında \
     (aşırı bellek ya da süre). İçe aktarılmadı.";
pub const OPEN_FAILED: &str = "KeePass dosyası açılamadı: parola yanlış ya da dosya bozuk.";
pub const TOO_MUCH: &str =
    "KeePass dosyası çok fazla kayıt, klasör ya da çok büyük alanlar içeriyor. İçe aktarılmadı.";

const KDBX_SIG1: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const KDBX_SIG2: [u8; 4] = [0x67, 0xfb, 0x4b, 0xb5];
const ARGON2D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const ARGON2ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];
const AES_KDF: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub groups: usize,
    pub entries: usize,
    pub totp: usize,
    pub attachments: usize,
    pub custom_fields: usize,
    /// Entries in the KeePass recycle bin, not imported.
    pub skipped_recycle_bin: usize,
    /// Older versions of entries, not imported.
    pub skipped_history: usize,
    /// The new top-level folder's name.
    pub folder: String,
}

/// Little-endian reader that never reads past the end.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Kdf {
    Argon2 {
        memory: u64,
        iterations: u64,
        parallelism: u64,
    },
    Aes {
        rounds: u64,
    },
}

/// Reads the KDF parameters from a KDBX 4 outer header (header field 11, a
/// "VariantDictionary"). Any malformed structure gives None.
fn kdf_params(file: &[u8]) -> Option<Kdf> {
    let mut c = Cursor { b: file, pos: 12 };
    loop {
        let id = c.u8()?;
        let len = c.u32()? as usize;
        if len > MAX_HEADER_FIELD {
            return None;
        }
        let data = c.take(len)?;
        match id {
            0 => return None, // end of header without KDF parameters
            11 => return parse_kdf_dictionary(data),
            _ => {}
        }
    }
}

fn parse_kdf_dictionary(d: &[u8]) -> Option<Kdf> {
    let mut c = Cursor { b: d, pos: 0 };
    let version = c.u16()?;
    if version >> 8 != 1 {
        return None;
    }
    let mut uuid: Option<&[u8]> = None;
    let mut nums: HashMap<&[u8], u64> = HashMap::new();
    loop {
        let ty = c.u8()?;
        if ty == 0 {
            break;
        }
        let klen = c.u32()? as usize;
        let key = c.take(klen)?;
        let vlen = c.u32()? as usize;
        let val = c.take(vlen)?;
        match (ty, vlen) {
            (0x04, 4) => {
                nums.insert(key, u64::from(u32::from_le_bytes(val.try_into().ok()?)));
            }
            (0x05, 8) => {
                nums.insert(key, u64::from_le_bytes(val.try_into().ok()?));
            }
            (0x42, _) if key == b"$UUID" => uuid = Some(val),
            _ => {}
        }
    }
    let uuid = uuid?;
    if uuid == ARGON2D || uuid == ARGON2ID {
        Some(Kdf::Argon2 {
            memory: *nums.get(&b"M"[..])?,
            iterations: *nums.get(&b"I"[..])?,
            parallelism: *nums.get(&b"P"[..])?,
        })
    } else if uuid == AES_KDF {
        Some(Kdf::Aes {
            rounds: *nums.get(&b"R"[..])?,
        })
    } else {
        None
    }
}

fn kdf_is_safe(k: &Kdf) -> bool {
    match *k {
        Kdf::Argon2 {
            memory,
            iterations,
            parallelism,
        } => {
            memory <= MAX_ARGON2_MEMORY
                && (1..=MAX_ARGON2_ITERATIONS).contains(&iterations)
                && (1..=MAX_ARGON2_PARALLELISM).contains(&parallelism)
        }
        Kdf::Aes { rounds } => rounds <= MAX_AES_ROUNDS,
    }
}

/// Checks everything that can be checked without the password.
pub fn precheck(file: &[u8]) -> Result<(), &'static str> {
    if file.len() > MAX_KDBX_BYTES {
        return Err(TOO_LARGE);
    }
    if file.len() < 12 || file[..4] != KDBX_SIG1 || file[4..8] != KDBX_SIG2 {
        return Err(NOT_KDBX4);
    }
    match DatabaseVersion::parse(file) {
        Ok(DatabaseVersion::KDB4(_)) => {}
        _ => return Err(NOT_KDBX4),
    }
    let kdf = kdf_params(file).ok_or(OPEN_FAILED)?;
    if !kdf_is_safe(&kdf) {
        return Err(UNSAFE_KDF);
    }
    Ok(())
}

/// Decrypts a KDBX 4 file after `precheck`.
pub fn open(file: &[u8], password: &str) -> Result<Database, &'static str> {
    precheck(file)?;
    let db = Database::parse(file, DatabaseKey::new().with_password(password))
        .map_err(|_| OPEN_FAILED)?;
    if db.num_entries() > MAX_ENTRIES || db.num_groups() > MAX_GROUPS {
        return Err(TOO_MUCH);
    }
    Ok(db)
}

const STANDARD: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

fn field<'a>(e: &'a keepass::db::Entry, key: &str) -> Result<&'a str, &'static str> {
    let v = e.get(key).unwrap_or("");
    if v.len() > MAX_FIELD_BYTES {
        return Err(TOO_MUCH);
    }
    Ok(v)
}

/// Adds the KeePass database to `data` under a new top-level folder.
pub fn convert(db: &Database, data: &mut VaultData, folder: &str) -> Result<Summary, &'static str> {
    let top = data.add_group(data.root, folder).map_err(|_| TOO_MUCH)?;
    let recycle = db.meta.recyclebin_uuid;
    let mut s = Summary {
        groups: 0,
        entries: 0,
        totp: 0,
        attachments: 0,
        custom_fields: 0,
        skipped_recycle_bin: 0,
        skipped_history: 0,
        folder: folder.to_owned(),
    };
    let mut attachment_bytes = 0usize;

    // Iterative walk (no recursion on untrusted depth): (keepass group, our group, depth).
    let mut stack = vec![(db.root().id(), top, 0usize)];
    while let Some((kid, ours, depth)) = stack.pop() {
        let Some(g) = db.group(kid) else { continue };
        if depth > MAX_DEPTH {
            return Err(TOO_MUCH);
        }
        for e in g.entries() {
            let title = field(&e, "Title")?;
            let mut n = Entry::new(ours, title);
            n.username = field(&e, "UserName")?.to_owned();
            n.password = SecretString::new(field(&e, "Password")?);
            n.url = field(&e, "URL")?.to_owned();
            n.notes = SecretString::new(field(&e, "Notes")?);
            n.tags = e
                .tags
                .iter()
                .take(64)
                .map(|t| t.chars().take(128).collect())
                .collect();
            if e.times.expires == Some(true) {
                n.expires = Some(e.times.expiry.and_utc().timestamp());
            }
            // TOTP: KeePassXC "otp" (otpauth URI) or KeePass 2 "TimeOtp-Secret-Base32".
            let otp = e
                .get("otp")
                .or_else(|| e.get("TimeOtp-Secret-Base32"))
                .filter(|v| v.len() <= 4096 && crate::totp::Totp::parse(v).is_some());
            if let Some(otp) = otp {
                n.totp = Some(SecretString::new(otp));
                s.totp += 1;
            }
            let mut keys: Vec<&String> = e
                .fields
                .keys()
                .filter(|k| !STANDARD.contains(&k.as_str()))
                .filter(|k| !(otp.is_some() && (*k == "otp" || k.starts_with("TimeOtp-"))))
                .collect();
            keys.sort();
            for k in keys.into_iter().take(256) {
                let v = &e.fields[k];
                let value = v.get();
                if value.len() > MAX_FIELD_BYTES || k.len() > 1024 {
                    return Err(TOO_MUCH);
                }
                n.fields.push(CustomField {
                    name: k.clone(),
                    value: SecretString::new(value.as_str()),
                    protected: v.is_protected(),
                });
                s.custom_fields += 1;
            }
            for (name, a) in e.attachments_named() {
                let bytes = a.data.get();
                attachment_bytes = attachment_bytes.saturating_add(bytes.len());
                if bytes.len() > MAX_ATTACHMENT_BYTES
                    || attachment_bytes > MAX_TOTAL_ATTACHMENT_BYTES
                {
                    return Err(TOO_MUCH);
                }
                n.attachments.push(Attachment {
                    name: name.chars().take(255).collect(),
                    data: SecretBytes::new(bytes.clone()),
                });
                s.attachments += 1;
            }
            s.skipped_history += e.history.as_ref().map_or(0, |h| h.get_entries().len());
            data.add_entry(n).map_err(|_| TOO_MUCH)?;
            s.entries += 1;
        }
        for sub in g.groups() {
            if recycle == Some(sub.id().uuid()) {
                s.skipped_recycle_bin += count_entries(db, sub.id());
                continue;
            }
            let name: String = sub.name.chars().take(255).collect();
            let child = data.add_group(ours, name).map_err(|_| TOO_MUCH)?;
            s.groups += 1;
            stack.push((sub.id(), child, depth + 1));
        }
    }
    data.repair_structure();
    Ok(s)
}

fn count_entries(db: &Database, id: keepass::db::GroupId) -> usize {
    let mut n = 0;
    let mut stack = vec![(id, 0usize)];
    while let Some((g, d)) = stack.pop() {
        if d > MAX_DEPTH {
            break;
        }
        if let Some(g) = db.group(g) {
            n += g.entries().count();
            stack.extend(g.groups().map(|c| (c.id(), d + 1)));
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::config::KdfConfig;

    const PW: &str = "keepass-parolasi";

    /// A small KDBX 4 file written by the keepass crate itself.
    fn fixture(kdf: KdfConfig) -> Vec<u8> {
        let mut db = Database::new();
        db.config.kdf_config = kdf;
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected("Title", "GitHub");
            e.set_unprotected("UserName", "alperen");
            e.set_protected("Password", "gizli-123");
            e.set_unprotected("URL", "https://github.com");
            e.set_protected("Notes", "kurtarma kodu");
            e.set_unprotected("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
            e.set_protected("PIN", "4321");
        }
        {
            let mut root = db.root_mut();
            let mut g = root.add_group();
            g.name = "İş".into();
            let mut e = g.add_entry();
            e.set_unprotected("Title", "Jira");
            e.set_protected("Password", "jira-parola");
        }
        let mut out = Vec::new();
        db.save(&mut out, DatabaseKey::new().with_password(PW))
            .unwrap();
        out
    }

    fn cheap() -> KdfConfig {
        KdfConfig::Argon2id {
            iterations: 2,
            memory: 1024 * 1024,
            parallelism: 1,
            version: kp_argon2::Version::Version13,
        }
    }

    #[test]
    fn imports_entries_groups_totp_and_custom_fields() {
        let file = fixture(cheap());
        let db = open(&file, PW).unwrap();
        let mut data = VaultData::new("Hedef");
        let before_groups = data.groups.len();
        let s = convert(&db, &mut data, "KeePass").unwrap();
        assert_eq!((s.entries, s.groups, s.totp, s.custom_fields), (2, 1, 1, 1));
        assert_eq!(data.groups.len(), before_groups + 2, "top folder + İş");
        let gh = data.entries.iter().find(|e| e.title == "GitHub").unwrap();
        assert_eq!(gh.password.expose(), "gizli-123");
        assert_eq!(gh.notes.expose(), "kurtarma kodu");
        assert!(gh.totp.is_some());
        assert_eq!(gh.fields[0].name, "PIN");
        assert!(gh.fields[0].protected);
        let jira = data.entries.iter().find(|e| e.title == "Jira").unwrap();
        assert_eq!(data.group(jira.group).unwrap().name, "İş");
        assert_eq!(data.repair_structure(), 0, "already consistent");
    }

    #[test]
    fn wrong_password_is_one_generic_error() {
        let file = fixture(cheap());
        assert_eq!(open(&file, "yanlis").err(), Some(OPEN_FAILED));
    }

    #[test]
    fn refuses_kdbx3_and_non_keepass_files() {
        let mut kdbx3 = Vec::new();
        kdbx3.extend_from_slice(&KDBX_SIG1);
        kdbx3.extend_from_slice(&KDBX_SIG2);
        kdbx3.extend_from_slice(&1u16.to_le_bytes()); // minor
        kdbx3.extend_from_slice(&3u16.to_le_bytes()); // major 3
        kdbx3.resize(200, 0);
        assert_eq!(precheck(&kdbx3), Err(NOT_KDBX4));
        assert_eq!(precheck(b"not a keepass file at all"), Err(NOT_KDBX4));
        assert_eq!(precheck(&[]), Err(NOT_KDBX4));
        assert_eq!(precheck(&vec![0u8; MAX_KDBX_BYTES + 1]), Err(TOO_LARGE));
    }

    #[test]
    fn refuses_expensive_kdf_before_any_work() {
        let huge_mem = fixture(KdfConfig::Argon2id {
            iterations: 2,
            memory: MAX_ARGON2_MEMORY + 1024,
            parallelism: 1,
            version: kp_argon2::Version::Version13,
        });
        assert_eq!(precheck(&huge_mem), Err(UNSAFE_KDF));
        let many_rounds = fixture(KdfConfig::Aes {
            rounds: MAX_AES_ROUNDS + 1,
        });
        assert_eq!(precheck(&many_rounds), Err(UNSAFE_KDF));
        let ok = fixture(KdfConfig::Aes { rounds: 1000 });
        assert_eq!(precheck(&ok), Ok(()));
    }

    /// Mutation smoke test (not a coverage-guided fuzzer): random byte flips
    /// in a real file must never panic, only fail cleanly or still open.
    #[test]
    fn corrupted_files_never_panic() {
        let file = fixture(KdfConfig::Aes { rounds: 10 });
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..300 {
            let mut f = file.clone();
            for _ in 0..(1 + rnd() % 4) {
                let i = (rnd() % f.len() as u64) as usize;
                f[i] ^= 1 << (rnd() % 8);
            }
            if rnd() % 5 == 0 {
                let cut = (rnd() % f.len() as u64) as usize;
                f.truncate(cut);
            }
            if let Ok(db) = open(&f, PW) {
                let mut data = VaultData::new("x");
                let _ = convert(&db, &mut data, "k");
            }
        }
    }
}
