//! Exports besides CSV (SECURITY.md "Dışa aktarma"): a KeePass KDBX 4 file
//! (encrypted, with its own password) and a printable HTML page (plain
//! text). Both need the master password again; the caller checks it.

use std::collections::HashMap;

use keepass::config::KdfConfig;
use keepass::db::{AutoType, AutoTypeAssociation, Color, Value};
use keepass::{Database, DatabaseKey};
use lav_core::VaultData;
use zeroize::Zeroizing;

pub const KDBX_WEAK: &str = "KeePass dosyasının parolası en az 8 karakter olmalı.";
pub const KDBX_FAILED: &str = "KeePass dosyası oluşturulamadı.";

/// Argon2id, 64 MiB, 3 passes, 4 lanes: the same cost as a new LockAlperen
/// vault, and within what KeePass and KeePassXC open without complaint.
fn kdbx_kdf() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 3,
        memory: 64 * 1024 * 1024,
        parallelism: 4,
        version: kp_argon2::Version::Version13,
    }
}

fn naive(ts: i64) -> Option<chrono::NaiveDateTime> {
    chrono::DateTime::from_timestamp(ts, 0).map(|d| d.naive_utc())
}

/// The whole vault as a KDBX 4 file, protected by `password` (and nothing
/// else). The recycle bin is written as KeePass's recycle bin. History is
/// not exported. Uses `kdf` in tests only.
pub fn kdbx(data: &VaultData, password: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    kdbx_with(data, password, kdbx_kdf())
}

fn kdbx_with(
    data: &VaultData,
    password: &str,
    kdf: KdfConfig,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if password.chars().count() < lav_core::vault::MIN_PASSWORD_CHARS {
        return Err(KDBX_WEAK);
    }
    let mut db = Database::new();
    db.config.kdf_config = kdf;
    db.meta.database_name = Some(data.name.clone());
    if !data.description.is_empty() {
        db.meta.database_description = Some(data.description.clone());
    }
    let root_id = db.root().id();
    db.root_mut().name = data.name.clone();

    // Folders, parents first (breadth-first from the root).
    let mut ids: HashMap<uuid::Uuid, keepass::db::GroupId> = HashMap::new();
    ids.insert(data.root, root_id);
    let mut queue = vec![data.root];
    let mut i = 0;
    while i < queue.len() {
        let parent = queue[i];
        i += 1;
        for g in data.children(parent) {
            if ids.contains_key(&g.id) {
                continue;
            }
            let pid = ids[&parent];
            let mut pg = db.group_mut(pid).ok_or(KDBX_FAILED)?;
            let mut ng = pg.add_group();
            ng.name = g.name.clone();
            if let Some(t) = naive(g.created) {
                ng.times.creation = Some(t);
            }
            if let Some(t) = naive(g.modified) {
                ng.times.last_modification = Some(t);
            }
            let nid = ng.id();
            ids.insert(g.id, nid);
            if data.recycle_bin == Some(g.id) {
                db.meta.recyclebin_uuid = Some(nid.uuid());
            }
            queue.push(g.id);
        }
    }

    for e in &data.entries {
        let gid = ids.get(&e.group).copied().unwrap_or(root_id);
        let mut g = db.group_mut(gid).ok_or(KDBX_FAILED)?;
        let mut n = g.add_entry();
        n.set_unprotected("Title", e.title.as_str());
        n.set_unprotected("UserName", e.username.as_str());
        n.set_protected("Password", e.password.expose());
        n.set_unprotected("URL", e.url.as_str());
        n.set_protected("Notes", e.notes.expose());
        if let Some(t) = &e.totp {
            n.set_protected("otp", t.expose());
        }
        for f in &e.fields {
            if f.protected {
                n.set_protected(f.name.as_str(), f.value.expose());
            } else {
                n.set_unprotected(f.name.as_str(), f.value.expose());
            }
        }
        n.tags = e.tags.clone();
        if let Some(t) = e.expires.and_then(naive) {
            n.times.expires = Some(true);
            n.times.expiry = t;
        }
        if let Some(t) = naive(e.created) {
            n.times.creation = Some(t);
        }
        if let Some(t) = naive(e.modified) {
            n.times.last_modification = Some(t);
        }
        if let Some(a) = &e.autotype {
            n.autotype = Some(AutoType {
                enabled: a.enabled,
                default_sequence: (!a.sequence.is_empty()).then(|| a.sequence.clone()),
                data_transfer_obfuscation: Default::default(),
                associations: if a.window.is_empty() {
                    Vec::new()
                } else {
                    vec![AutoTypeAssociation {
                        window: a.window.clone(),
                        sequence: String::new(),
                    }]
                },
            });
        }
        n.foreground_color = e.fg_color.as_deref().and_then(|c| c.parse::<Color>().ok());
        n.background_color = e.bg_color.as_deref().and_then(|c| c.parse::<Color>().ok());
        for a in &e.attachments {
            n.add_attachment(a.name.as_str(), Value::protected(a.data.expose().to_vec()));
        }
    }

    let mut out = Zeroizing::new(Vec::new());
    db.save(&mut *out, DatabaseKey::new().with_password(password))
        .map_err(|_| KDBX_FAILED)?;
    Ok(out)
}

/// Escapes text for HTML element content and attribute values.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// A printable page of the vault (KeePass "Print" / emergency sheet). Every
/// value is escaped; the page has no scripts, links or remote content.
/// Entries in the recycle bin are left out.
pub fn html(data: &VaultData, include_passwords: bool, generated: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    let esc = html_escape;
    out.push_str(
        "<!doctype html>\n<html lang=\"tr\"><head><meta charset=\"utf-8\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
         <title>",
    );
    out.push_str(&esc(&data.name));
    out.push_str(
        "</title><style>\
         body{font:13px/1.45 'Segoe UI',system-ui,sans-serif;margin:24px;color:#111}\
         h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:22px 0 6px;border-bottom:1px solid #999}\
         table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}\
         th{background:#eee}.pw{font-family:Consolas,monospace}.warn{color:#a00;font-weight:600}\
         @media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}\
         </style></head><body>\n",
    );
    out.push_str(&format!(
        "<h1>{}</h1><p>{} · {} kayıt</p>",
        esc(&data.name),
        esc(generated),
        data.entries
            .iter()
            .filter(|e| !data.in_recycle_bin(e.group))
            .count()
    ));
    out.push_str(
        "<p class=\"warn\">Bu sayfa şifresizdir. Yazdırdıktan sonra dosyayı silin ve kâğıdı güvenli bir yerde saklayın.</p>\n",
    );
    // Folders in tree order, each with its entries.
    let mut stack = vec![(data.root, String::new())];
    let mut seen = std::collections::HashSet::new();
    while let Some((gid, path)) = stack.pop() {
        if !seen.insert(gid) || data.in_recycle_bin(gid) {
            continue;
        }
        let name = data.group(gid).map(|g| g.name.as_str()).unwrap_or("");
        let here = if path.is_empty() {
            name.to_owned()
        } else {
            format!("{path} › {name}")
        };
        let mut entries: Vec<&lav_core::Entry> = data.entries_in(gid).collect();
        entries.sort_by_cached_key(|e| e.title.to_lowercase());
        if !entries.is_empty() {
            out.push_str(&format!(
                "<h2>{}</h2><table><tr><th>Başlık</th><th>Kullanıcı adı</th>",
                esc(&here)
            ));
            if include_passwords {
                out.push_str("<th>Parola</th>");
            }
            out.push_str("<th>Web sitesi</th><th>Notlar</th></tr>\n");
            for e in entries {
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td>",
                    esc(&e.title),
                    esc(&e.username)
                ));
                if include_passwords {
                    out.push_str(&format!(
                        "<td class=\"pw\">{}</td>",
                        esc(e.password.expose())
                    ));
                }
                out.push_str(&format!(
                    "<td>{}</td><td>{}</td></tr>\n",
                    esc(&e.url),
                    esc(e.notes.expose()).replace('\n', "<br>")
                ));
            }
            out.push_str("</table>\n");
        }
        let mut kids: Vec<&lav_core::Group> = data.children(gid).collect();
        kids.sort_by_cached_key(|g| std::cmp::Reverse(g.name.to_lowercase()));
        for k in kids {
            stack.push((k.id, here.clone()));
        }
    }
    out.push_str("</body></html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use lav_core::{AutoTypeConfig, Entry, SecretString};

    fn sample() -> VaultData {
        let mut v = VaultData::new("Kasa <&>");
        let g = v.add_group(v.root, "İş").unwrap();
        let mut e = Entry::new(g, "GitHub \"x\"");
        e.username = "alperen".into();
        e.password = SecretString::new("gizli<script>");
        e.url = "https://github.com".into();
        e.notes = SecretString::new("satır 1\nsatır 2");
        e.tags = vec!["kod".into()];
        e.expires = Some(1_900_000_000);
        e.autotype = Some(AutoTypeConfig {
            sequence: "{USERNAME}{ENTER}".into(),
            window: "*GitHub*".into(),
            enabled: true,
        });
        e.fg_color = Some("#aa0000".into());
        v.add_entry(e).unwrap();
        let gone = v.add_entry(Entry::new(v.root, "silinmiş")).unwrap();
        v.remove_entry(gone).unwrap();
        v
    }

    fn cheap() -> KdfConfig {
        KdfConfig::Argon2id {
            iterations: 2,
            memory: 1024 * 1024,
            parallelism: 1,
            version: kp_argon2::Version::Version13,
        }
    }

    /// What we write, our own importer (and so KeePass) reads back.
    #[test]
    fn kdbx_round_trip() {
        let v = sample();
        let file = kdbx_with(&v, "dis-aktarim-parolasi", cheap()).unwrap();
        let db = crate::import::open(&file, "dis-aktarim-parolasi", None).unwrap();
        assert!(db.meta.recyclebin_uuid.is_some());
        let mut back = VaultData::new("Hedef");
        let s = crate::import::convert(&db, &mut back, "KeePass").unwrap();
        assert_eq!(s.entries, 1, "the recycle bin is skipped on import");
        let e = back
            .entries
            .iter()
            .find(|e| e.title == "GitHub \"x\"")
            .unwrap();
        assert_eq!(e.password.expose(), "gizli<script>");
        assert_eq!(e.notes.expose(), "satır 1\nsatır 2");
        assert_eq!(e.tags, vec!["kod".to_owned()]);
        assert_eq!(e.expires, Some(1_900_000_000));
        let a = e.autotype.as_ref().expect("auto-type comes back");
        assert_eq!(
            (a.sequence.as_str(), a.window.as_str()),
            ("{USERNAME}{ENTER}", "*GitHub*")
        );
        assert_eq!(e.fg_color.as_deref(), Some("#aa0000"));
        assert_eq!(back.group(e.group).unwrap().name, "İş");
        assert_eq!(
            crate::import::open(&file, "yanlis-parola", None).err(),
            Some(crate::import::OPEN_FAILED)
        );
        assert_eq!(kdbx_with(&v, "kisa", cheap()).err(), Some(KDBX_WEAK));
    }

    #[test]
    fn html_escapes_everything_and_skips_the_bin() {
        let v = sample();
        let page = html(&v, true, "17.11.2026");
        assert!(page.contains("gizli&lt;script&gt;"));
        assert!(!page.contains("<script>"));
        assert!(page.contains("Kasa &lt;&amp;&gt;"));
        assert!(page.contains("GitHub &quot;x&quot;"));
        assert!(page.contains("satır 1<br>satır 2"));
        assert!(!page.contains("silinmiş"), "recycle bin left out");
        assert!(page.contains("default-src 'none'"));
        let no_pw = html(&v, false, "x");
        assert!(!no_pw.contains("gizli"));
    }
}
