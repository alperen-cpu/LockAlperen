//! "Son kasalar": the last vaults opened on this computer.
//!
//! Stored in the app's LOCAL data directory (%LOCALAPPDATA%, not roaming and
//! not next to the vault), as JSON with only a path and a timestamp per
//! vault: no names, no contents, nothing secret. The WebView never sends a
//! path back; it picks an item by its index and Rust resolves it.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const MAX_RECENT: usize = 5;
/// The file is tiny; anything bigger is not ours and is ignored.
const MAX_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub path: PathBuf,
    /// Unix seconds.
    pub opened: u64,
}

/// What the UI may see: no full path is needed to display or choose an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub file_name: String,
    pub folder: String,
    pub opened: u64,
}

impl From<&Item> for View {
    fn from(i: &Item) -> Self {
        View {
            file_name: i
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            folder: i
                .path
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            opened: i.opened,
        }
    }
}

/// Windows paths are case-insensitive.
fn same(a: &Path, b: &Path) -> bool {
    a.as_os_str().to_string_lossy().to_lowercase() == b.as_os_str().to_string_lossy().to_lowercase()
}

/// Moves `path` to the front (or adds it), keeping at most MAX_RECENT.
pub fn touch(list: &mut Vec<Item>, path: &Path, now: u64) {
    list.retain(|i| !same(&i.path, path));
    list.insert(
        0,
        Item {
            path: path.to_path_buf(),
            opened: now,
        },
    );
    list.truncate(MAX_RECENT);
}

pub fn remove(list: &mut Vec<Item>, index: usize) {
    if index < list.len() {
        list.remove(index);
    }
}

/// Reads the list. Missing, too large or invalid files give an empty list:
/// this is a convenience, never a reason to fail.
pub fn load(file: &Path) -> Vec<Item> {
    let Ok(f) = fs::File::open(file) else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if f.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf).is_err()
        || buf.len() as u64 > MAX_FILE_BYTES
    {
        return Vec::new();
    }
    let mut list: Vec<Item> = serde_json::from_slice(&buf).unwrap_or_default();
    list.truncate(MAX_RECENT);
    list
}

/// Writes the list via a temp file and rename, so a crash never leaves a
/// half-written file.
pub fn save(file: &Path, list: &[Item]) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(list).map_err(std::io::Error::other)?;
    crate::private::write_atomic(file, "json.tmp", &bytes)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn newest_first_without_duplicates_and_capped() {
        let mut l = Vec::new();
        for (i, name) in ["a", "b", "c", "d", "e", "f"].iter().enumerate() {
            touch(&mut l, &p(&format!(r"C:\k\{name}.lav")), i as u64);
        }
        assert_eq!(l.len(), MAX_RECENT);
        assert_eq!(l[0].path, p(r"C:\k\f.lav"));
        assert!(
            !l.iter().any(|i| i.path == p(r"C:\k\a.lav")),
            "oldest dropped"
        );

        // Same file with different case moves to the front, no duplicate.
        touch(&mut l, &p(r"c:\K\C.LAV"), 99);
        assert_eq!(l.len(), MAX_RECENT);
        assert_eq!(l[0].opened, 99);
        assert_eq!(
            l.iter()
                .filter(|i| same(&i.path, &p(r"C:\k\c.lav")))
                .count(),
            1
        );
    }

    #[test]
    fn view_has_name_and_folder() {
        // A path in this platform's own syntax.
        let folder = if cfg!(windows) {
            r"C:\Users\x\OneDrive\Kasalar"
        } else {
            "/home/x/Belgeler/Kasalar"
        };
        let v = View::from(&Item {
            path: Path::new(folder).join("Kişisel.lav"),
            opened: 5,
        });
        assert_eq!(v.file_name, "Kişisel.lav");
        assert_eq!(v.folder, folder);
    }

    #[test]
    fn save_load_roundtrip_and_bad_files_are_empty() {
        let dir = std::env::temp_dir().join(format!("lav-recent-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let file = dir.join("sub").join("recent.json");
        assert!(load(&file).is_empty(), "missing file");

        let mut l = Vec::new();
        touch(&mut l, &p(r"C:\k\a.lav"), 1);
        touch(&mut l, &p(r"C:\k\b.lav"), 2);
        save(&file, &l).unwrap();
        assert_eq!(load(&file), l);

        fs::write(&file, b"{ not json").unwrap();
        assert!(load(&file).is_empty(), "invalid json");
        fs::write(&file, vec![b' '; (MAX_FILE_BYTES + 10) as usize]).unwrap();
        assert!(load(&file).is_empty(), "too large");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn remove_ignores_bad_index() {
        let mut l = Vec::new();
        touch(&mut l, &p(r"C:\k\a.lav"), 1);
        remove(&mut l, 5);
        assert_eq!(l.len(), 1);
        remove(&mut l, 0);
        assert!(l.is_empty());
    }
}
