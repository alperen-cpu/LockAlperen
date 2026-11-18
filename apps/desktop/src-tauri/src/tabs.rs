//! Several vaults open at once (KeePass tabs). Each tab is its own
//! [`Session`]: its own file, key, unlock state and pending choices. Every
//! command works on the active tab; locking locks all of them.
//!
//! Rules:
//! - there is always at least one tab, at most [`MAX_TABS`];
//! - one file can be unlocked in only one tab (two copies would refuse each
//!   other's saves and show different contents);
//! - closing a tab locks it first (`lav_core` wipes keys on drop).

use serde::Serialize;

use crate::session::Session;

pub const MAX_TABS: usize = 8;
pub const TOO_MANY_TABS: &str = "En fazla 8 kasa aynı anda açık olabilir.";
pub const OPEN_ELSEWHERE: &str = "Bu kasa başka bir sekmede zaten açık.";
pub const NO_SUCH_TAB: &str = "Sekme bulunamadı.";

pub struct Tabs {
    list: Vec<Session>,
    active: usize,
}

impl Default for Tabs {
    fn default() -> Self {
        Tabs {
            list: vec![Session::default()],
            active: 0,
        }
    }
}

/// What the tab bar shows. No secrets: the vault's name and file name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TabView {
    pub index: usize,
    pub title: String,
    pub unlocked: bool,
    pub active: bool,
}

impl Tabs {
    pub fn active(&mut self) -> &mut Session {
        if self.list.is_empty() {
            self.list.push(Session::default());
        }
        self.active = self.active.min(self.list.len() - 1);
        &mut self.list[self.active]
    }

    pub fn get(&mut self, index: usize) -> Option<&mut Session> {
        self.list.get_mut(index)
    }

    pub fn all(&mut self) -> impl Iterator<Item = &mut Session> {
        self.list.iter_mut()
    }

    pub fn any_unlocked(&self) -> bool {
        self.list.iter().any(Session::is_unlocked)
    }

    pub fn lock_all(&mut self) {
        for s in &mut self.list {
            s.lock();
        }
    }

    pub fn views(&self) -> Vec<TabView> {
        self.list
            .iter()
            .enumerate()
            .map(|(i, s)| TabView {
                index: i,
                title: s
                    .info()
                    .map(|v| v.name)
                    .or_else(|| s.selected_file().map(|f| f.file_name))
                    .unwrap_or_else(|| "Yeni sekme".into()),
                unlocked: s.is_unlocked(),
                active: i == self.active,
            })
            .collect()
    }

    /// Adds an empty tab and makes it active.
    pub fn open_new(&mut self) -> Result<(), &'static str> {
        if self.list.len() >= MAX_TABS {
            return Err(TOO_MANY_TABS);
        }
        self.list.push(Session::default());
        self.active = self.list.len() - 1;
        Ok(())
    }

    pub fn switch(&mut self, index: usize) -> Result<(), &'static str> {
        if index >= self.list.len() {
            return Err(NO_SUCH_TAB);
        }
        self.active = index;
        Ok(())
    }

    /// Locks and removes a tab. The last tab is only emptied.
    pub fn close(&mut self, index: usize) -> Result<(), &'static str> {
        if index >= self.list.len() {
            return Err(NO_SUCH_TAB);
        }
        self.list[index].lock();
        self.list.remove(index);
        if self.list.is_empty() {
            self.list.push(Session::default());
        }
        if self.active > index || self.active >= self.list.len() {
            self.active = self.active.saturating_sub(1).min(self.list.len() - 1);
        }
        Ok(())
    }

    /// Refuses to unlock the active tab's file if another tab has it open.
    pub fn check_not_open_elsewhere(&self) -> Result<(), &'static str> {
        let Some(path) = self.list.get(self.active).and_then(|s| s.selected_path()) else {
            return Ok(());
        };
        let dup = self
            .list
            .iter()
            .enumerate()
            .any(|(i, s)| i != self.active && s.is_unlocked() && s.has_file(path));
        if dup {
            Err(OPEN_ELSEWHERE)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lav_core::{KdfParams, Vault};

    const PW: &str = "correct horse battery";

    fn vault(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let kdf = KdfParams {
            memory_kib: KdfParams::MIN_MEMORY_KIB,
            iterations: KdfParams::MIN_ITERATIONS,
            parallelism: KdfParams::MIN_PARALLELISM,
        };
        let mut v = Vault::create(name, PW, None, kdf).unwrap();
        let p = dir.join(format!("{name}.lav"));
        v.save_file(&p).unwrap();
        p
    }

    #[test]
    fn tabs_open_switch_close_and_lock_all() {
        let dir = std::env::temp_dir().join(format!("lav-tabs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (vault(&dir, "Ev"), vault(&dir, "İş"));

        let mut t = Tabs::default();
        assert_eq!(t.views()[0].title, "Yeni sekme");
        t.active().select(a.clone());
        t.active().unlock(PW).unwrap();
        t.open_new().unwrap();
        t.active().select(b);
        t.active().unlock(PW).unwrap();
        let v = t.views();
        assert_eq!(
            v.iter().map(|x| x.title.as_str()).collect::<Vec<_>>(),
            ["Ev", "İş"]
        );
        assert!(v[1].active && v.iter().all(|x| x.unlocked));

        // The same file cannot be unlocked in a second tab.
        t.open_new().unwrap();
        t.active().select(a);
        assert_eq!(t.check_not_open_elsewhere(), Err(OPEN_ELSEWHERE));

        t.switch(0).unwrap();
        assert!(t.active().is_unlocked());
        assert_eq!(t.switch(9), Err(NO_SUCH_TAB));
        t.lock_all();
        assert!(!t.any_unlocked());

        // Closing: the active index follows; the last tab is only emptied.
        t.close(0).unwrap();
        assert_eq!(t.views().len(), 2);
        t.close(1).unwrap();
        t.close(0).unwrap();
        assert_eq!(t.views().len(), 1);
        assert_eq!(t.views()[0].title, "Yeni sekme");
        for _ in 1..MAX_TABS {
            t.open_new().unwrap();
        }
        assert_eq!(t.open_new(), Err(TOO_MANY_TABS));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
