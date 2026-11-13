//! PR-2 (docs/FIX_DESIGN_2026-11.md §2, §4.4, §4.5): save-path safety.
//! Written BEFORE the fix; see docs/IMPLEMENTATION_REPORT_2026-11.md for
//! which of them failed first.
//!
//! T1 lock file cannot be deleted/replaced while held (Windows)
//! T2 lock lost before commit -> save aborted (Linux/Unix)
//! T3 busy lock -> SaveBusy within a bounded time (no endless wait)
//! T4 backup is fsynced and renamed and the directory flushed BEFORE the vault
//!    file is replaced
//! T5 file changed between verification and commit -> abort; backup holds the
//!    VERIFIED bytes
//! T6 simulated crash at every step -> vault is old or new, never missing;
//!    backup consistent; old-password backup never next to a new-password vault
//! T7' a waiting second instance gets SaveBusy and cannot touch the first
//!    instance's temp file (replaces the age-threshold idea, which would
//!    contradict the existing LA-14 assertion)
//! T8 case-variant path of the same file is not "changed on disk" (Windows)
//! T9 = the existing LA-03/LA-04/LA-11/LA-14 integration tests, unchanged

use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use super::{save_hook, sibling, SaveEvent, SaveLock, Vault};
use crate::crypto::KdfParams;
use crate::error::Error;

const PW: &str = "correct horse battery";
const NEW_PW: &str = "a brand new password";

fn kdf() -> KdfParams {
    KdfParams {
        memory_kib: KdfParams::MIN_MEMORY_KIB,
        iterations: KdfParams::MIN_ITERATIONS,
        parallelism: 1,
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("lav-save-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn file(&self) -> PathBuf {
        self.0.join("vault.lav")
    }
    fn temps(&self) -> Vec<String> {
        fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        save_hook::clear();
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Saved vault named `name` at `path`; returns it (disk state = that file).
fn saved(path: &Path, name: &str) -> Vault {
    let mut v = Vault::create(name, PW, None, kdf()).unwrap();
    v.save_file(path).unwrap();
    v
}

fn name_of(bytes: &[u8], pw: &str) -> Option<String> {
    Vault::unlock(bytes, pw, None)
        .ok()
        .map(|v| v.data.name.clone())
}

fn record_events() -> Rc<RefCell<Vec<SaveEvent>>> {
    let log = Rc::new(RefCell::new(Vec::new()));
    let l = log.clone();
    save_hook::set(move |e| {
        l.borrow_mut().push(e);
        Ok(())
    });
    log
}

// ------------------------------------------------------------------- T1

#[cfg(windows)]
#[test]
fn t1_held_lock_file_cannot_be_deleted_or_replaced() {
    let d = TempDir::new();
    let path = d.file();
    let lock = sibling(&path, "lock");
    let held = SaveLock::acquire(&path).unwrap();
    assert!(
        fs::remove_file(&lock).is_err(),
        "held lock file was deleted"
    );
    let other = d.0.join("other");
    fs::write(&other, b"x").unwrap();
    assert!(
        fs::rename(&other, &lock).is_err(),
        "held lock file was replaced by rename"
    );
    assert!(
        fs::rename(&lock, d.0.join("moved")).is_err(),
        "held lock file was renamed away"
    );
    drop(held);
}

// ------------------------------------------------------------------- T2

#[cfg(unix)]
#[test]
fn t2_lock_lost_before_commit_aborts_the_save() {
    let d = TempDir::new();
    let path = d.file();
    let mut v = saved(&path, "original");
    let original = fs::read(&path).unwrap();

    let lock = sibling(&path, "lock");
    let p2 = path.clone();
    let stolen: Rc<RefCell<Option<SaveLock>>> = Rc::new(RefCell::new(None));
    let s2 = stolen.clone();
    save_hook::set(move |e| {
        if e == SaveEvent::PreCommit && s2.borrow().is_none() {
            // A sync client deletes the lock; a second instance locks anew.
            fs::remove_file(&lock)?;
            *s2.borrow_mut() = Some(SaveLock::acquire(&p2).map_err(io::Error::other)?);
        }
        Ok(())
    });
    v.data.name = "changed".into();
    let r = v.save_file(&path);
    save_hook::clear();
    assert!(stolen.borrow().is_some(), "hook did not run");
    assert!(matches!(r, Err(Error::LockLost)), "{r:?}");
    assert_eq!(fs::read(&path).unwrap(), original, "vault was replaced");
}

// ------------------------------------------------------------------- T3

#[test]
fn t3_busy_lock_gives_save_busy_instead_of_waiting_forever() {
    let d = TempDir::new();
    let path = d.file();
    let mut v = saved(&path, "v");
    let holder = SaveLock::acquire(&path).unwrap();

    let (tx, rx) = mpsc::channel();
    let p = path.clone();
    let t = std::thread::spawn(move || {
        v.data.name = "second".into();
        let _ = tx.send(v.save_file(&p));
    });
    let got = rx.recv_timeout(super::LOCK_WAIT + Duration::from_secs(3));
    drop(holder);
    let _ = t.join();
    match got {
        Ok(Err(Error::SaveBusy)) => {}
        other => panic!("expected SaveBusy within the wait limit, got {other:?}"),
    }
}

// ------------------------------------------------------------------- T4

#[test]
fn t4_backup_is_durable_before_the_vault_is_replaced() {
    use SaveEvent::*;
    let d = TempDir::new();
    let path = d.file();
    let mut v = saved(&path, "v1");
    let log = record_events();
    v.data.name = "v2".into();
    v.save_file(&path).unwrap();
    save_hook::clear();
    assert_eq!(
        *log.borrow(),
        [
            Verified,
            TmpSynced,
            BakTmpWritten,
            BakTmpSynced,
            BakRenamed,
            DirSynced,
            PreCommit,
            MainRenamed,
            DirSynced
        ]
    );
}

#[test]
fn t4_stale_backup_is_removed_durably_before_the_vault_is_replaced() {
    use SaveEvent::*;
    let d = TempDir::new();
    let path = d.file();
    let mut v = saved(&path, "v1");
    v.change_credentials(PW, None, NEW_PW, None, None).unwrap();
    let log = record_events();
    v.save_file(&path).unwrap();
    save_hook::clear();
    assert_eq!(
        *log.borrow(),
        [
            Verified,
            TmpSynced,
            BakRemoved,
            DirSynced,
            PreCommit,
            MainRenamed,
            DirSynced
        ]
    );
}

// ------------------------------------------------------------------- T5

#[test]
fn t5_file_changed_after_verification_aborts_and_backup_holds_verified_bytes() {
    let d = TempDir::new();
    let path = d.file();
    let mut v = saved(&path, "verified");
    let verified = fs::read(&path).unwrap();
    // What "OneDrive" drops in between: another device's version.
    let foreign = Vault::create("foreign", PW, None, kdf())
        .unwrap()
        .seal()
        .unwrap();

    let (p2, f2) = (path.clone(), foreign.clone());
    save_hook::set(move |e| {
        if e == SaveEvent::Verified {
            fs::write(&p2, &f2)?;
        }
        Ok(())
    });
    v.data.name = "mine".into();
    let r = v.save_file(&path);
    save_hook::clear();

    assert!(matches!(r, Err(Error::FileChangedOnDisk)), "{r:?}");
    assert_eq!(
        fs::read(&path).unwrap(),
        foreign,
        "the other device's version was overwritten"
    );
    if let Ok(bak) = fs::read(sibling(&path, "bak")) {
        assert_eq!(bak, verified, "backup is not the verified version");
    }
}

// ------------------------------------------------------------------- T6

const ALL_EVENTS: [SaveEvent; 9] = [
    SaveEvent::Verified,
    SaveEvent::TmpSynced,
    SaveEvent::BakTmpWritten,
    SaveEvent::BakTmpSynced,
    SaveEvent::BakRenamed,
    SaveEvent::BakRemoved,
    SaveEvent::DirSynced,
    SaveEvent::PreCommit,
    SaveEvent::MainRenamed,
];

fn crash_at(e: SaveEvent) {
    save_hook::set(move |now| {
        if now == e {
            Err(io::Error::other("simulated crash"))
        } else {
            Ok(())
        }
    });
}

#[test]
fn t6_crash_at_every_step_leaves_a_consistent_vault_and_backup() {
    for e in ALL_EVENTS {
        let d = TempDir::new();
        let path = d.file();
        let mut v = saved(&path, "v1");
        v.data.name = "v2".into();
        v.save_file(&path).unwrap(); // .bak = v1
        let v1_bak = fs::read(sibling(&path, "bak")).unwrap();
        let v2 = fs::read(&path).unwrap();

        crash_at(e);
        v.data.name = "v3".into();
        let _ = v.save_file(&path);
        save_hook::clear();

        let main = fs::read(&path).expect("vault file missing after crash");
        let n = name_of(&main, PW);
        assert!(
            n.as_deref() == Some("v2") || n.as_deref() == Some("v3"),
            "{e:?}: vault is neither old nor new: {n:?}"
        );
        let bak = fs::read(sibling(&path, "bak")).expect("backup vanished");
        assert!(
            bak == v1_bak || bak == v2,
            "{e:?}: backup is neither the previous backup nor the verified vault"
        );
    }
}

#[test]
fn t6_crash_never_leaves_old_password_backup_next_to_new_password_vault() {
    for e in ALL_EVENTS {
        let d = TempDir::new();
        let path = d.file();
        let mut v = saved(&path, "v1");
        v.data.name = "v2".into();
        v.save_file(&path).unwrap(); // .bak exists (old password)
        v.change_credentials(PW, None, NEW_PW, None, None).unwrap();

        crash_at(e);
        let _ = v.save_file(&path);
        save_hook::clear();

        let main = fs::read(&path).expect("vault file missing after crash");
        let main_new = name_of(&main, NEW_PW).is_some();
        assert!(
            main_new || name_of(&main, PW).is_some(),
            "{e:?}: vault unreadable"
        );
        if main_new {
            if let Ok(bak) = fs::read(sibling(&path, "bak")) {
                assert!(
                    name_of(&bak, PW).is_none(),
                    "{e:?}: old-password backup next to new-password vault"
                );
            }
        }
    }
}

// ------------------------------------------------------------------ T7'

#[test]
fn t7_second_instance_gets_save_busy_and_cannot_touch_the_first_instances_temp() {
    let d = TempDir::new();
    let path = d.file();
    saved(&path, "v1");

    let (paused_tx, paused_rx) = mpsc::channel::<()>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let pa = path.clone();
    let a = std::thread::spawn(move || {
        let mut v = Vault::open_file(&pa, PW, None).unwrap();
        save_hook::set(move |e| {
            if e == SaveEvent::PreCommit {
                let _ = paused_tx.send(());
                let _ = go_rx.recv_timeout(Duration::from_secs(30));
            }
            Ok(())
        });
        v.data.name = "A".into();
        let r = v.save_file(&pa);
        save_hook::clear();
        r
    });
    paused_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("A never reached PreCommit");
    let temps_while_paused = d.temps();

    let (btx, brx) = mpsc::channel();
    let pb = path.clone();
    let b = std::thread::spawn(move || {
        let mut v = Vault::open_file(&pb, PW, None).unwrap();
        v.data.name = "B".into();
        let _ = btx.send(v.save_file(&pb));
    });
    let b_result = brx.recv_timeout(super::LOCK_WAIT + Duration::from_secs(3));
    let temps_after_b = d.temps();
    let _ = go_tx.send(());
    let a_result = a.join().unwrap();
    let _ = b.join();

    assert!(
        matches!(b_result, Ok(Err(Error::SaveBusy))),
        "second instance: {b_result:?}"
    );
    assert!(
        temps_while_paused.iter().all(|t| temps_after_b.contains(t)),
        "first instance's temp file was removed: {temps_while_paused:?} -> {temps_after_b:?}"
    );
    assert!(a_result.is_ok(), "first instance: {a_result:?}");
    assert_eq!(name_of(&fs::read(&path).unwrap(), PW).as_deref(), Some("A"));
}

// ------------------------------------------------------------------- T8

#[cfg(windows)]
#[test]
fn t8_case_variant_path_of_the_same_file_is_not_a_change() {
    let d = TempDir::new();
    let path = d.0.join("Vault.lav");
    saved(&path, "v1");
    let mut v = Vault::open_file(&d.0.join("Vault.lav"), PW, None).unwrap();
    v.data.name = "v2".into();
    let r = v.save_file(&d.0.join("VAULT.LAV"));
    assert!(r.is_ok(), "{r:?}");
}
