//! `bridge.json` next to settings.json (0600, see `private.rs`): whether the
//! browser extension may connect, the app's own Noise key, the paired
//! extensions and which entry the user allowed on which site.
//!
//! Nothing here opens the vault: the app key only proves to a paired
//! extension that it talks to this app (not to another program listening
//! in its place). Same-user malware can read this file, as it can any file
//! of the user; it still cannot read the vault without the master password.
//! A broken or oversized file counts as "off, nothing paired".

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAX_FILE_BYTES: u64 = 256 * 1024;
pub const MAX_PAIRS: usize = 16;
const MAX_APPROVALS: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pair {
    /// Short id shown in Settings (hex of the key's first 6 bytes).
    pub id: String,
    /// The extension's static X25519 public key, base64.
    pub key: String,
    pub created: u64,
    pub last_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub pair: String,
    pub entry: String,
    pub origin: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Store {
    pub enabled: bool,
    /// The app's static X25519 private key, base64 (made on first enable).
    app_key: Option<Secret>,
    pub pairs: Vec<Pair>,
    pub approvals: Vec<Approval>,
}

/// A string wiped when dropped (the app key's base64).
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub fn pair_id(key: &[u8]) -> String {
    key.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

impl Store {
    /// The app's private key; made (and kept) the first time it is needed.
    pub fn app_private_key(&mut self) -> Zeroizing<Vec<u8>> {
        use base64::Engine;
        if let Some(k) = self
            .app_key
            .as_ref()
            .and_then(|s| b64().decode(&s.0).ok())
            .filter(|k| k.len() == 32)
        {
            return Zeroizing::new(k);
        }
        let k: [u8; 32] = lav_core::crypto::random_bytes();
        self.app_key = Some(Secret(b64().encode(k)));
        Zeroizing::new(k.to_vec())
    }

    pub fn find(&self, key: &[u8]) -> Option<&Pair> {
        use base64::Engine;
        let k = b64().encode(key);
        self.pairs.iter().find(|p| p.key == k)
    }

    pub fn add(&mut self, key: &[u8], now: u64) -> Result<String, &'static str> {
        use base64::Engine;
        if let Some(p) = self.find(key) {
            return Ok(p.id.clone());
        }
        if self.pairs.len() >= MAX_PAIRS {
            return Err(TOO_MANY_PAIRS);
        }
        let id = pair_id(key);
        self.pairs.push(Pair {
            id: id.clone(),
            key: b64().encode(key),
            created: now,
            last_used: now,
        });
        Ok(id)
    }

    pub fn touch(&mut self, id: &str, now: u64) {
        if let Some(p) = self.pairs.iter_mut().find(|p| p.id == id) {
            p.last_used = now;
        }
    }

    /// Removes a pairing and everything it was allowed.
    pub fn revoke(&mut self, id: &str) -> bool {
        let before = self.pairs.len();
        self.pairs.retain(|p| p.id != id);
        self.approvals.retain(|a| a.pair != id);
        self.pairs.len() != before
    }

    pub fn allowed(&self, pair: &str, entry: &str, origin: &str) -> bool {
        self.approvals
            .iter()
            .any(|a| a.pair == pair && a.entry == entry && a.origin == origin)
    }

    pub fn allow(&mut self, pair: &str, entry: &str, origin: &str) {
        if self.allowed(pair, entry, origin) {
            return;
        }
        if self.approvals.len() >= MAX_APPROVALS {
            self.approvals.remove(0);
        }
        self.approvals.push(Approval {
            pair: pair.to_owned(),
            entry: entry.to_owned(),
            origin: origin.to_owned(),
        });
    }
}

pub const TOO_MANY_PAIRS: &str =
    "En fazla 16 tarayıcı eşleştirilebilir; Ayarlar'dan birini kaldırın.";

pub fn path(settings_file: &Path) -> PathBuf {
    settings_file.with_file_name("bridge.json")
}

pub fn load(file: &Path) -> Store {
    use std::io::Read;
    let Ok(f) = std::fs::File::open(file) else {
        return Store::default();
    };
    let mut bytes = Vec::new();
    if f.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).is_err()
        || bytes.len() as u64 > MAX_FILE_BYTES
    {
        return Store::default();
    }
    let bytes = Zeroizing::new(bytes);
    let mut s: Store = serde_json::from_slice(&bytes).unwrap_or_default();
    s.pairs.truncate(MAX_PAIRS);
    s.approvals.truncate(MAX_APPROVALS);
    s
}

pub fn save(file: &Path, s: &Store) -> std::io::Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(s).map_err(std::io::Error::other)?);
    crate::private::write_atomic(file, "json.tmp", &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_approvals_and_revoke() {
        let mut s = Store::default();
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let a = s.add(&k1, 10).unwrap();
        assert_eq!(s.add(&k1, 11).unwrap(), a, "same key, same pairing");
        let b = s.add(&k2, 12).unwrap();
        assert_ne!(a, b);
        assert!(s.find(&k1).is_some());
        s.allow(&a, "e1", "https://site.com");
        s.allow(&b, "e1", "https://site.com");
        assert!(s.allowed(&a, "e1", "https://site.com"));
        assert!(!s.allowed(&a, "e1", "https://other.com"));
        assert!(!s.allowed(&a, "e2", "https://site.com"));
        assert!(s.revoke(&a));
        assert!(s.find(&k1).is_none());
        assert!(
            !s.allowed(&a, "e1", "https://site.com"),
            "approvals go with it"
        );
        assert!(s.allowed(&b, "e1", "https://site.com"));
        assert!(!s.revoke(&a));
    }

    #[test]
    fn app_key_is_made_once_and_kept() {
        let mut s = Store::default();
        let k = s.app_private_key();
        assert_eq!(k.len(), 32);
        assert_eq!(*s.app_private_key(), *k);
    }

    #[test]
    fn file_round_trip_and_garbage() {
        let dir = std::env::temp_dir().join(format!("lav-bridge-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join("bridge.json");
        let mut s = Store {
            enabled: true,
            ..Store::default()
        };
        let key = s.app_private_key();
        s.add(&[7u8; 32], 1).unwrap();
        save(&file, &s).unwrap();
        let mut back = load(&file);
        assert!(back.enabled);
        assert_eq!(back.pairs, s.pairs);
        assert_eq!(*back.app_private_key(), *key);
        std::fs::write(&file, b"{ not json").unwrap();
        assert!(!load(&file).enabled);
        std::fs::write(&file, vec![b' '; (MAX_FILE_BYTES + 10) as usize]).unwrap();
        assert!(load(&file).pairs.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pairing_limit() {
        let mut s = Store::default();
        for i in 0..MAX_PAIRS {
            s.add(&[i as u8; 32], 0).unwrap();
        }
        assert_eq!(s.add(&[200u8; 32], 0), Err(TOO_MANY_PAIRS));
    }
}
