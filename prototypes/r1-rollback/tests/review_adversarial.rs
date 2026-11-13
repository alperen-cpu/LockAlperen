//! Independent adversarial review of the R1 prototype (2026-11).
//!
//! Tests marked `#[ignore = "demonstrates finding ..."]` assert the CURRENT,
//! undesired behaviour: they pass with `cargo test -- --ignored` and should be
//! flipped (or deleted) once the finding is fixed. Unmarked tests document a
//! property that holds.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use r1_rollback_proto::vv::VersionVector;
use r1_rollback_proto::{Device, Opened, SaveFault, SimVault, Verdict};

struct World {
    root: PathBuf,
}

impl World {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "r1review-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("sync")).unwrap();
        Self { root }
    }
    fn sync(&self, name: &str) -> PathBuf {
        self.root.join("sync").join(name)
    }
    fn device(&self, name: &str, id: u8) -> Device {
        Device::new(&self.state_dir(name), [id; 16]).unwrap()
    }
    fn state_dir(&self, name: &str) -> PathBuf {
        self.root.join("local").join(name)
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const VID: [u8; 16] = [0xAA; 16];
const SALT1: [u8; 32] = [1; 32];
const SALT2: [u8; 32] = [2; 32];
const A: [u8; 16] = [1; 16];

fn open(d: &Device, p: &Path) -> Opened {
    d.open(p).unwrap()
}

fn save(d: &Device, p: &Path, base: &Opened, content: &str) -> SimVault {
    d.save(p, &base.file, content.as_bytes(), None, None)
        .unwrap()
}

fn put(p: &Path, bytes: &[u8]) {
    fs::write(p, bytes).unwrap();
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

/// FINDING F1. A cloned device id produces two different saves with the same
/// dot (A:2, different tags). Only the device that owns the id compares tags;
/// a third device sees the clone's file as linear progress and silently
/// drops the original's save "Y" (lost update, no warning on B or C).
#[test]
#[ignore = "demonstrates finding F1 (third device ignores tag mismatch on equal counters)"]
fn review_clone_equal_dot_different_tag_silently_accepted_by_third_device() {
    let w = World::new("f1");
    let (a, b, c) = (w.device("A", 1), w.device("B", 2), w.device("C", 3));
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap(); // X = {A:1}
    let x = fs::read(&p).unwrap();
    open(&b, &p);
    open(&c, &p);
    let ax = open(&a, &p);
    copy_dir(&w.state_dir("A"), &w.state_dir("A-clone"));
    let a2 = w.device("A-clone", 9);

    save(&a, &p, &ax, "Y: important edit by A"); // {A:2 tag a}
    assert_eq!(open(&b, &p).verdict, Verdict::Ok);

    // C (offline) edits X; the clone builds on C's file.
    let q = w.sync("vault (conflict).lav");
    put(&q, &x);
    let cx = open(&c, &q);
    save(&c, &q, &cx, "Z by C"); // {A:1, C:1}
    let a2z = open(&a2, &q);
    assert_eq!(a2z.verdict, Verdict::Ok);
    save(&a2, &q, &a2z, "W by clone"); // {A:2 tag b, C:1}

    let ob = open(&b, &q);
    assert_eq!(ob.verdict, Verdict::Ok, "B: silent, Y is lost");
    assert_eq!(ob.file.content, b"W by clone");
    assert_eq!(ob.file.vv.get(&A), 2);
    // Only the original notices.
    assert_eq!(open(&a, &q).verdict, Verdict::DeviceIdReused);
}

/// FINDING F2. With a leaked OLD password the attacker picks a fresh vault id
/// and a fresh salt. On the device that MADE the password change (S1 retired,
/// S2 current) neither RetiredCredential nor CredentialChanged fires: the file
/// is FirstUse and accepted silently (the user still has to type the old
/// password at the unlock prompt).
#[test]
#[ignore = "demonstrates finding F2 (fresh vault_id bypasses credential checks)"]
fn review_forged_fresh_vault_id_bypasses_credential_checks() {
    let w = World::new("f2");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    let created = a.create(&p, VID, SALT1).unwrap();
    let cur = open(&a, &p);
    a.save(&p, &cur.file, b"rekeyed", Some(SALT2), None)
        .unwrap();

    let forged = SimVault {
        vault_id: [0xCC; 16],
        salt: [0xEE; 32],
        vv: created.vv.clone(),
        content: b"attacker".to_vec(),
    };
    put(&p, &forged.encode());
    assert_eq!(a.check_before_unlock(&forged.salt).unwrap(), None);
    let o = open(&a, &p);
    assert_eq!(o.verdict, Verdict::FirstUse);
    assert!(o.verdict.accepted_silently());
}

/// FINDING F3. Counters are never bounded. A file whose vector gives this
/// device u64::MAX (here via FirstUse of a forged vault; also reachable via
/// confirm() of a DeviceIdReused file, see F4) makes every later save panic
/// with "attempt to add with overflow" (the workspace enables
/// overflow-checks in release too).
#[test]
#[ignore = "demonstrates finding F3 (counter overflow panic)"]
fn review_own_counter_at_u64_max_makes_save_panic() {
    let w = World::new("f3");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    open(&a, &p);

    let mut vv = VersionVector::default();
    vv.set(A, u64::MAX); // device ids are readable from any old file
    let forged = SimVault {
        vault_id: [0xCD; 16],
        salt: SALT1,
        vv,
        content: b"x".to_vec(),
    };
    let q = w.sync("other.lav");
    put(&q, &forged.encode());
    let o = open(&a, &q);
    assert_eq!(o.verdict, Verdict::FirstUse);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        a.save(&q, &o.file, b"y", None, None)
    }));
    assert!(r.is_err(), "save must panic on counter overflow");
}

/// FINDING F4. Leaked old password + a device B that has not yet seen the
/// password change: B silently accepts a forged old-salt file carrying
/// A:u64::MAX (known blind spot). The poison then survives B's confirm()
/// (merge keeps the max), travels in B's NEW-password saves, and A raises
/// DeviceIdReused on every one of them; if A's user confirms, A can never
/// save again (overflow, F3). Also: the real new-password file reaches B as
/// Rollback, so the credential change is never surfaced as such (F5).
#[test]
#[ignore = "demonstrates finding F4 (counter poisoning persists after confirm)"]
fn review_poisoned_counter_from_lagging_device_breaks_the_changing_device() {
    let w = World::new("f4");
    let (a, b) = (w.device("A", 1), w.device("B", 2));
    let p = w.sync("vault.lav");
    let created = a.create(&p, VID, SALT1).unwrap();
    open(&b, &p);
    let cur = open(&a, &p);
    a.save(&p, &cur.file, b"rekeyed", Some(SALT2), None)
        .unwrap();

    let mut vv = created.vv.clone();
    vv.set(A, u64::MAX);
    let forged = SimVault {
        vault_id: VID,
        salt: SALT1,
        vv,
        content: b"attacker".to_vec(),
    };
    let r = w.sync("replay.lav");
    put(&r, &forged.encode());
    assert_eq!(open(&b, &r).verdict, Verdict::Ok); // known blind spot

    let ob = open(&b, &p);
    assert_eq!(ob.verdict, Verdict::Rollback, "not CredentialChanged");
    b.confirm(&ob).unwrap();
    save(&b, &p, &ob, "B edits the real vault");
    let after = SimVault::decode(&fs::read(&p).unwrap()).unwrap();
    assert_eq!(after.salt, SALT2);
    assert_eq!(
        after.vv.get(&A),
        u64::MAX,
        "poison propagated under the new password"
    );

    let oa = open(&a, &p);
    assert_eq!(oa.verdict, Verdict::DeviceIdReused);
    a.confirm(&oa).unwrap();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        a.save(&p, &oa.file, b"A edits", None, None)
    }));
    assert!(res.is_err(), "A can no longer save");
}

/// FINDING F5. CredentialChanged is only produced for relation Ahead. A file
/// with an unknown salt that is Concurrent is reported as a plain Fork; when
/// the user resolves the "fork" with confirm(), the REAL current salt is
/// retired, so the legitimate vault is then refused before unlock.
#[test]
#[ignore = "demonstrates finding F5 (Fork hides credential change; confirm retires the real salt)"]
fn review_fork_hides_credential_change_and_confirm_retires_real_salt() {
    let w = World::new("f5");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    let created = a.create(&p, VID, SALT1).unwrap();
    let cur = open(&a, &p);
    a.save(&p, &cur.file, b"rekeyed", Some(SALT2), None)
        .unwrap();
    let real = fs::read(&p).unwrap();

    let mut vv = created.vv.clone();
    vv.set([0xEE; 16], 1000);
    let forged = SimVault {
        vault_id: VID,
        salt: [0xEE; 32],
        vv,
        content: b"attacker".to_vec(),
    };
    let q = w.sync("vault (conflict).lav");
    put(&q, &forged.encode());
    let o = open(&a, &q);
    assert_eq!(o.verdict, Verdict::Fork);
    a.confirm(&o).unwrap();

    assert_eq!(
        a.check_before_unlock(&SALT2).unwrap(),
        Some(Verdict::RetiredCredential)
    );
    put(&p, &real);
    assert_eq!(open(&a, &p).verdict, Verdict::RetiredCredential);
}

/// FINDING F6. A crashes after writing the vault (pending intent recorded).
/// An attacker without any password puts the previous file back before A
/// restarts. A accepts it silently and discards the pending intent: the
/// user's last edit is gone without any notice, although the device KNOWS a
/// save was in flight.
#[test]
#[ignore = "demonstrates finding F6 (rolled-back interrupted save is dropped silently)"]
fn review_rolled_back_interrupted_save_is_silently_dropped() {
    let w = World::new("f6");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    let o = open(&a, &p);
    let before = fs::read(&p).unwrap();
    assert!(a
        .save(
            &p,
            &o.file,
            b"important",
            None,
            Some(SaveFault::AfterVaultWrite)
        )
        .is_err());
    put(&p, &before);
    let o2 = open(&a, &p);
    assert_eq!(o2.verdict, Verdict::Ok);
    assert_eq!(o2.file.content, b"new");
}

/// FINDING F7. Two app instances share the state dir. Instance 1 writes the
/// vault and crashes; instance 2 recorded its own intent in between and then
/// aborted (e.g. lav-core's FileChangedOnDisk). The single `pending` slot was
/// overwritten, so instance 1's save is now reported as a CLONED device id.
#[test]
#[ignore = "demonstrates finding F7 (single pending slot, intent/write/commit not under one lock)"]
fn review_second_instance_overwrites_pending_and_causes_false_clone_alarm() {
    let w = World::new("f7");
    let a1 = w.device("A", 1);
    let a2 = w.device("A", 1); // second process, same state dir
    let p = w.sync("vault.lav");
    a1.create(&p, VID, SALT1).unwrap();
    let o1 = open(&a1, &p);
    let o2 = open(&a2, &p);
    assert!(a1
        .save(
            &p,
            &o1.file,
            b"inst1",
            None,
            Some(SaveFault::AfterVaultWrite)
        )
        .is_err());
    assert!(a2
        .save(&p, &o2.file, b"inst2", None, Some(SaveFault::AfterIntent))
        .is_err());
    assert_eq!(open(&a1, &p).verdict, Verdict::DeviceIdReused);
}

/// FINDING F8. State temp names are `state.<pid>-<n>.tmp` with create_new and
/// are never cleaned up. A leftover from a crashed process whose PID is later
/// reused makes the update fail (Windows recycles PIDs quickly).
#[test]
#[ignore = "demonstrates finding F8 (leftover state temp + PID reuse fails the update)"]
fn review_leftover_state_temp_with_reused_pid_fails_update() {
    let w = World::new("f8");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    let dir = w.state_dir("A");
    fs::create_dir_all(&dir).unwrap();
    for n in 0..500 {
        put(
            &dir.join(format!("state.{}-{n}.tmp", std::process::id())),
            b"crash leftover",
        );
    }
    let r = a.create(&p, VID, SALT1);
    assert!(
        matches!(r, Err(r1_rollback_proto::ProtoError::Store(_))),
        "{:?}",
        r.err()
    );
}

/// PROPERTY (holds). The state lock really excludes a second process-level
/// handle on Windows (LockFileEx), so concurrent updates serialise.
#[test]
fn review_state_lock_blocks_second_instance() {
    let w = World::new("lock-ok");
    let dir = w.state_dir("A");
    let a1 = Device::new(&dir, A).unwrap();
    a1.store()
        .update(A, None, |_| {
            let (tx, rx) = mpsc::channel();
            let d = dir.clone();
            let h = std::thread::spawn(move || {
                let a2 = Device::new(&d, A).unwrap();
                a2.store().update(A, None, |_| ()).unwrap();
                tx.send(()).unwrap();
            });
            assert!(
                rx.recv_timeout(Duration::from_millis(500)).is_err(),
                "second update must wait for the lock"
            );
            (h, rx)
        })
        .map(|(h, rx)| {
            rx.recv_timeout(Duration::from_secs(5)).unwrap();
            h.join().unwrap();
        })
        .unwrap();
}

/// FINDING F9. ...but the lock FILE can be deleted (or replaced by rename)
/// while held, because std opens it with FILE_SHARE_DELETE. The next instance
/// then creates and locks a NEW `state.lock`: both run their read-modify-write
/// concurrently and one update is lost. Here instance 2 retires a salt; the
/// retirement disappears.
#[test]
#[ignore = "demonstrates finding F9 (deleting a held lock file breaks mutual exclusion)"]
fn review_deleting_held_state_lock_loses_an_update() {
    let w = World::new("lock-bad");
    let dir = w.state_dir("A");
    let a1 = Device::new(&dir, A).unwrap();
    a1.store().update(A, None, |_| ()).unwrap(); // gen 1
    let lock = dir.join("state.lock");
    a1.store()
        .update(A, None, |_| {
            fs::remove_file(&lock).expect("held lock file is deletable");
            let d = dir.clone();
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let a2 = Device::new(&d, A).unwrap();
                a2.store()
                    .update(A, None, |s| {
                        s.retired_salts.insert([0x77; 32]);
                    })
                    .unwrap();
                tx.send(()).unwrap();
            });
            rx.recv_timeout(Duration::from_secs(5))
                .expect("second instance got the lock while the first holds it");
        })
        .unwrap();
    assert_eq!(
        a1.check_before_unlock(&[0x77; 32]).unwrap(),
        None,
        "update lost"
    );
}
