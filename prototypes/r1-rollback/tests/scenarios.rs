//! R1 prototype scenarios: rollback, concurrent saves, OneDrive conflict
//! copies, cloned device ids, crashes, local state corruption. Each test
//! states whether it shows a PROTECTION or documents a LIMITATION.

use std::fs;
use std::path::{Path, PathBuf};

use r1_rollback_proto::store::{Loaded, StoreFault, VaultRecord};
use r1_rollback_proto::vv::VersionVector;
use r1_rollback_proto::{
    evaluate, Device, Opened, ProtoError, SaveFault, SimVault, StateNote, Verdict,
};

struct World {
    root: PathBuf,
}

impl World {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "r1proto-{tag}-{}-{}",
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
        Device::new(&self.root.join("local").join(name), [id; 16]).unwrap()
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

// =========================================================== rollback

/// PROTECTION. Three saves, the middle version's bytes are put back.
#[test]
fn rollback_to_middle_version_is_detected() {
    let w = World::new("rb");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    let v1 = open(&a, &p);
    save(&a, &p, &v1, "v2");
    let v2_bytes = fs::read(&p).unwrap();
    let v2 = open(&a, &p);
    save(&a, &p, &v2, "v3");
    let v3_bytes = fs::read(&p).unwrap();

    put(&p, &v2_bytes);
    assert_eq!(open(&a, &p).verdict, Verdict::Rollback);
    // A rejected file does not move the reference: v3 is still accepted.
    put(&p, &v3_bytes);
    assert_eq!(open(&a, &p).verdict, Verdict::Ok);
}

/// PROTECTION. Opening an old `.bak` is a rollback; a deliberate restore
/// (save on top of the old content) is a forward step for every device that
/// has not seen anything newer than the restoring device.
#[test]
fn bak_is_rollback_and_deliberate_restore_moves_forward() {
    let w = World::new("bak");
    let (a, b) = (w.device("A", 1), w.device("B", 2));
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    let base = open(&a, &p);
    let bak = fs::read(&p).unwrap();
    save(&a, &p, &base, "newer");
    assert_eq!(open(&b, &p).verdict, Verdict::FirstUse);

    let bak_path = w.sync("vault.lav.bak");
    put(&bak_path, &bak);
    let old = open(&a, &bak_path);
    assert_eq!(old.verdict, Verdict::Rollback);

    // Deliberate restore: the user saves the old content as the new version.
    let restored = a
        .save(&p, &old.file, &old.file.content, None, None)
        .unwrap();
    assert!(restored.vv.get(&[1; 16]) == 3);
    assert_eq!(open(&a, &p).verdict, Verdict::Ok);
    assert_eq!(open(&b, &p).verdict, Verdict::Ok);
}

// ============================================ concurrent / OneDrive conflicts

/// PROTECTION. Two offline edits from the same base are a fork; after an
/// explicit merge every device accepts the merged file.
#[test]
fn concurrent_offline_edits_are_a_fork_and_merge_converges() {
    let w = World::new("fork");
    let (a, b) = (w.device("A", 1), w.device("B", 2));
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    assert_eq!(open(&b, &p).verdict, Verdict::FirstUse);

    // Both go offline with their own copy.
    let pa = w.root.join("A-offline.lav");
    let pb = w.root.join("B-offline.lav");
    fs::copy(&p, &pa).unwrap();
    fs::copy(&p, &pb).unwrap();
    let ba = open(&a, &pa);
    let bb = open(&b, &pb);
    save(&a, &pa, &ba, "edit by A");
    save(&b, &pb, &bb, "edit by B");

    let theirs = open(&b, &pa);
    assert_eq!(theirs.verdict, Verdict::Fork);
    // B merges (content merge is out of scope here) and confirms.
    b.confirm(&theirs).unwrap();
    let merged = b.save(&p, &theirs.file, b"A+B", None, None).unwrap();
    assert!(merged.vv.get(&[1; 16]) >= 2 && merged.vv.get(&[2; 16]) >= 2);
    assert_eq!(open(&a, &p).verdict, Verdict::Ok);
    assert_eq!(open(&b, &p).verdict, Verdict::Ok);
}

/// PROTECTION. OneDrive keeps both sides of a conflict ("vault-PC2.lav").
/// A third device recognises the second one as a fork, not as an update.
#[test]
fn onedrive_conflict_copy_is_recognised() {
    let w = World::new("od");
    let (a, b, c) = (w.device("A", 1), w.device("B", 2), w.device("C", 3));
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    let base_bytes = fs::read(&p).unwrap();
    open(&b, &p);
    open(&c, &p);

    let pb_local = w.root.join("B-local.lav");
    put(&pb_local, &base_bytes);
    let ba = open(&a, &p);
    let bb = open(&b, &pb_local);
    save(&a, &p, &ba, "A wins the upload");
    save(&b, &pb_local, &bb, "B uploaded second");
    // OneDrive renames the loser.
    let conflict = w.sync("vault-PC2.lav");
    fs::copy(&pb_local, &conflict).unwrap();

    assert_eq!(open(&c, &p).verdict, Verdict::Ok);
    let copy = open(&c, &conflict);
    assert_eq!(copy.verdict, Verdict::Fork);
    c.confirm(&copy).unwrap();
    c.save(&p, &copy.file, b"merged", None, None).unwrap();
    for d in [&a, &b, &c] {
        assert_eq!(open(d, &p).verdict, Verdict::Ok);
    }
}

/// Two app instances on ONE device saving the same vault: the vault file
/// itself is protected by lav-core's save lock + FileChangedOnDisk; here we
/// check that the LOCAL STATE never loses updates under concurrency.
#[test]
fn concurrent_state_updates_are_not_lost() {
    let w = World::new("conc");
    let dir = w.state_dir("A");
    let threads: Vec<_> = (0..8u8)
        .map(|t| {
            let dir = dir.clone();
            let sync = w.root.join("sync");
            std::thread::spawn(move || {
                let d = Device::new(&dir, [1; 16]).unwrap();
                for i in 0..10u8 {
                    let p = sync.join(format!("v-{t}-{i}.lav"));
                    d.create(&p, [t * 16 + i; 16], SALT1).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let d = Device::new(&dir, [1; 16]).unwrap();
    match d.store().load().unwrap() {
        Loaded::Ok(s) => assert_eq!(s.vaults.len(), 80, "lost state updates"),
        other => panic!("{other:?}"),
    }
}

// =========================================================== device ids

/// PROTECTION (partial). A copied profile / disk image gives two machines the
/// same device id. The original notices as soon as it sees a save it never made.
#[test]
fn cloned_device_id_is_detected() {
    let w = World::new("clone");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    open(&a, &p);
    copy_dir(&w.state_dir("A"), &w.state_dir("A-clone"));
    let clone = w.device("A-clone", 9); // fresh id unused: state exists
    assert_eq!(clone.id().unwrap(), [1; 16]);

    let base = open(&clone, &p);
    save(&clone, &p, &base, "by the clone");
    assert_eq!(open(&a, &p).verdict, Verdict::DeviceIdReused);
}

/// PROTECTION. Both clones save from the same base: identical counters,
/// different bytes and save tags.
#[test]
fn cloned_device_saving_concurrently_gives_same_version_fork() {
    let w = World::new("clone2");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    open(&a, &p);
    copy_dir(&w.state_dir("A"), &w.state_dir("A-clone"));
    let clone = w.device("A-clone", 9);
    let pc = w.root.join("clone-local.lav");
    fs::copy(&p, &pc).unwrap();
    let bc = open(&clone, &pc);
    let ba = open(&a, &p);
    save(&clone, &pc, &bc, "clone");
    save(&a, &p, &ba, "original");
    // Same counter, different save tag: identified as a reused device id
    // (without tags this was only visible as ForkSameVersion).
    assert_eq!(open(&a, &pc).verdict, Verdict::DeviceIdReused);
}

/// After losing its state a device gets a NEW id, so it can never reuse a
/// counter of its previous identity.
#[test]
fn lost_state_means_new_device_id() {
    let w = World::new("newid");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    fs::remove_dir_all(w.state_dir("A")).unwrap();
    let a2 = w.device("A", 7);
    assert_eq!(a2.id().unwrap(), [7; 16]);
    let o = open(&a2, &p);
    assert_eq!((o.verdict, o.state), (Verdict::FirstUse, StateNote::Fresh));
}

// ======================================================= credentials

/// PROTECTION. After a password change, the old file is stopped BEFORE unlock
/// on the device that made (or confirmed) the change.
#[test]
fn retired_password_file_is_stopped_before_unlock() {
    let w = World::new("ret");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    let old_bytes = fs::read(&p).unwrap();
    let cur = open(&a, &p);
    a.save(&p, &cur.file, b"rekeyed", Some(SALT2), None)
        .unwrap();

    put(&p, &old_bytes);
    let header_salt = SimVault::decode(&old_bytes).unwrap().salt;
    assert_eq!(
        a.check_before_unlock(&header_salt).unwrap(),
        Some(Verdict::RetiredCredential)
    );
    assert_eq!(open(&a, &p).verdict, Verdict::RetiredCredential);
}

/// LIMITATION + PROTECTION. Another device sees the legitimate change as
/// CredentialChanged (needs confirmation, not silent). A device that never
/// saw the change accepts a replay of the old file (blind spot).
#[test]
fn password_change_seen_from_another_device() {
    let w = World::new("ret2");
    let (a, b) = (w.device("A", 1), w.device("B", 2));
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    open(&b, &p);
    let old_bytes = fs::read(&p).unwrap();
    let cur = open(&a, &p);
    a.save(&p, &cur.file, b"rekeyed", Some(SALT2), None)
        .unwrap();

    // Blind spot: replay to B before B ever saw the new file.
    let replay = w.sync("replay.lav");
    put(&replay, &old_bytes);
    assert_eq!(open(&b, &replay).verdict, Verdict::Ok);

    let new = open(&b, &p);
    assert_eq!(new.verdict, Verdict::CredentialChanged);
    b.confirm(&new).unwrap();
    assert_eq!(
        b.check_before_unlock(&SALT1).unwrap(),
        Some(Verdict::RetiredCredential)
    );
}

/// FINDING. Someone who knows a LEAKED old password can write a perfectly
/// valid file: any vector, any salt. The R1 design can only force a
/// confirmation, and only on devices whose reference already differs.
#[test]
fn forged_file_with_leaked_old_password() {
    let w = World::new("forge");
    let (a, b) = (w.device("A", 1), w.device("B", 2));
    let p = w.sync("vault.lav");
    let created = a.create(&p, VID, SALT1).unwrap();
    open(&b, &p);
    let cur = open(&a, &p);
    a.save(&p, &cur.file, b"rekeyed", Some(SALT2), None)
        .unwrap();

    // The attacker can decrypt only OLD files, so the best vector available
    // is an old one plus whatever fake devices they like. They cannot see
    // the save tags of anything written under the new password.
    let mut vv = created.vv.clone();
    vv.set([0xEE; 16], 1_000);
    // (a) fresh salt.
    let fresh = SimVault {
        vault_id: VID,
        salt: [0xEE; 32],
        vv,
        content: b"attacker".to_vec(),
    };
    put(&p, &fresh.encode());
    // A has seen newer saves of its own: incomparable -> alarm.
    assert!(!open(&a, &p).verdict.accepted_silently());
    // B is behind: the file looks like progress, but the credential epoch is
    // unknown -> confirmation required, never silent.
    assert_eq!(open(&b, &p).verdict, Verdict::CredentialChanged);
    // (b) OLD salt: retired on A (stopped before unlock) but still CURRENT on
    // B, which never saw the change -> silently accepted. LIMITATION.
    let old_salt = SimVault {
        salt: SALT1,
        ..fresh
    };
    put(&p, &old_salt.encode());
    assert_eq!(open(&a, &p).verdict, Verdict::RetiredCredential);
    assert_eq!(open(&b, &p).verdict, Verdict::Ok);
}

// ============================================================ limitations

/// LIMITATION. A version vector only compares against versions THIS device
/// has seen: a rollback to something newer than B's reference is accepted.
#[test]
fn rollback_newer_than_devices_reference_is_not_detected() {
    let w = World::new("blind");
    let (a, b) = (w.device("A", 1), w.device("B", 2));
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    open(&b, &p); // B saw v1 only
    let o = open(&a, &p);
    save(&a, &p, &o, "v2");
    let v2 = fs::read(&p).unwrap();
    let o = open(&a, &p);
    save(&a, &p, &o, "v3");

    put(&p, &v2);
    assert_eq!(open(&b, &p).verdict, Verdict::Ok, "blind spot (by design)");
    assert_eq!(open(&a, &p).verdict, Verdict::Rollback);
}

/// No false alarm: another vault at the same path is a different record.
#[test]
fn different_vault_id_at_same_path_is_first_use() {
    let w = World::new("vid");
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    open(&a, &p);
    let mut vv = VersionVector::default();
    vv.set([5; 16], 1);
    let other = SimVault {
        vault_id: [0xBB; 16],
        salt: [3; 32],
        vv,
        content: vec![],
    };
    put(&p, &other.encode());
    assert_eq!(open(&a, &p).verdict, Verdict::FirstUse);
}

// ================================================================ crashes

fn crash_setup(tag: &str) -> (World, Device, PathBuf, Opened) {
    let w = World::new(tag);
    let a = w.device("A", 1);
    let p = w.sync("vault.lav");
    a.create(&p, VID, SALT1).unwrap();
    let o = open(&a, &p);
    (w, a, p, o)
}

#[test]
fn crash_after_intent_vault_unchanged_no_alarm_no_counter_reuse() {
    let (w, a, p, o) = crash_setup("c1");
    let before = fs::read(&p).unwrap();
    assert!(matches!(
        a.save(&p, &o.file, b"x", None, Some(SaveFault::AfterIntent)),
        Err(ProtoError::Crashed)
    ));
    assert_eq!(fs::read(&p).unwrap(), before);
    let o = open(&a, &p);
    assert_eq!(o.verdict, Verdict::Ok);
    let next = save(&a, &p, &o, "retry");
    assert_eq!(next.vv.get(&[1; 16]), 3, "counter 2 must not be reused");
    let b = w.device("B", 2);
    assert_eq!(open(&b, &p).verdict, Verdict::FirstUse);
}

#[test]
fn crash_after_vault_write_is_recognised_as_own_save() {
    let (_w, a, p, o) = crash_setup("c2");
    assert!(a
        .save(&p, &o.file, b"x", None, Some(SaveFault::AfterVaultWrite))
        .is_err());
    assert_eq!(open(&a, &p).verdict, Verdict::OwnInterruptedSave);
    assert_eq!(open(&a, &p).verdict, Verdict::Ok);
}

#[test]
fn crash_during_state_commit_keeps_old_or_new_state_never_older() {
    for fault in [StoreFault::CrashBeforeRename, StoreFault::TornSlot] {
        let (_w, a, p, o) = crash_setup("c3");
        assert!(a
            .save(
                &p,
                &o.file,
                b"x",
                None,
                Some(SaveFault::DuringCommit(fault))
            )
            .is_err());
        let o2 = open(&a, &p);
        assert_eq!(o2.verdict, Verdict::OwnInterruptedSave, "{fault:?}");
        if fault == StoreFault::TornSlot {
            assert_eq!(o2.state, StateNote::Degraded);
        }
        // The state now knows the save: an older file is a rollback.
        put(&p, &o.file.encode());
        assert_eq!(open(&a, &p).verdict, Verdict::Rollback, "{fault:?}");
    }
}

#[test]
fn crashed_password_change_completes_on_reopen() {
    let (_w, a, p, o) = crash_setup("c4");
    let _ = a.save(
        &p,
        &o.file,
        b"x",
        Some(SALT2),
        Some(SaveFault::AfterVaultWrite),
    );
    assert_eq!(open(&a, &p).verdict, Verdict::OwnInterruptedSave);
    assert_eq!(
        a.check_before_unlock(&SALT1).unwrap(),
        Some(Verdict::RetiredCredential)
    );
}

/// FINDING. Without the write-ahead intent, "vault first, then state" turns
/// every crash in between into a false cloned-device alarm.
#[test]
fn without_intent_record_a_crash_looks_like_a_cloned_device() {
    let me = [1u8; 16];
    let mut vv = VersionVector::default();
    vv.set(me, 1);
    let rec = VaultRecord {
        last_vv: vv.clone(),
        last_hash: [0; 32],
        own_last: 1,
        own_tag: 0,
        pending: None,
        current_salt: SALT1,
    };
    vv.set(me, 2);
    let file = SimVault {
        vault_id: VID,
        salt: SALT1,
        vv,
        content: vec![],
    };
    let v = evaluate(&me, &Default::default(), Some(&rec), &file, &[1; 32]);
    assert_eq!(v, Verdict::DeviceIdReused);
}

/// A recorded intent must not let an OLD file through: the reference may
/// have moved on since the intent was written.
#[test]
fn own_interrupted_save_is_still_compared_with_the_reference() {
    let me = [1u8; 16];
    let other = [2u8; 16];
    let mut file_vv = VersionVector::default();
    file_vv.set_tagged(me, 2, 77);
    let mut l = VersionVector::default();
    l.set(me, 1);
    l.set(other, 5); // seen after the intent
    let file = SimVault {
        vault_id: VID,
        salt: SALT1,
        vv: file_vv,
        content: vec![],
    };
    let h = r1_rollback_proto::store::sha256(&file.encode());
    let rec = VaultRecord {
        last_vv: l,
        last_hash: [0; 32],
        own_last: 1,
        own_tag: 0,
        pending: Some((2, 77)),
        current_salt: SALT1,
    };
    let v = evaluate(&me, &Default::default(), Some(&rec), &file, &h);
    assert_eq!(v, Verdict::Fork);
}

// ======================================================= state corruption

#[test]
fn corrupted_state_is_never_silently_treated_as_fresh() {
    let (w, a, p, _) = crash_setup("corrupt");
    let dir = w.state_dir("A");
    for i in 0..2 {
        let sp = dir.join(format!("state.{i}"));
        if sp.exists() {
            let mut b = fs::read(&sp).unwrap();
            let n = b.len() / 2;
            b[n] ^= 0xff;
            fs::write(&sp, b).unwrap();
        }
    }
    assert!(matches!(a.open(&p), Err(ProtoError::StateUntrusted)));
    assert!(matches!(
        a.check_before_unlock(&SALT1),
        Err(ProtoError::StateUntrusted)
    ));
    // Explicit reset -> visible first use.
    a.store().reset().unwrap();
    let o = a.open(&p).unwrap();
    assert_eq!((o.verdict, o.state), (Verdict::FirstUse, StateNote::Fresh));
}

#[test]
fn one_corrupted_slot_falls_back_to_previous_state_and_says_so() {
    let (w, a, p, o) = crash_setup("slot");
    save(&a, &p, &o, "v2");
    let _ = &w;
    let newest = a.store().newest_valid_slot().unwrap();
    fs::write(&newest, b"garbage").unwrap();
    let o = a.open(&p).unwrap();
    assert_eq!(o.state, StateNote::Degraded);
    assert!(o.verdict.accepted_silently(), "{:?}", o.verdict);
}

#[test]
fn state_is_never_written_next_to_the_vault() {
    let (w, a, p, o) = crash_setup("loc");
    save(&a, &p, &o, "v2");
    let names: Vec<_> = fs::read_dir(w.root.join("sync"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec!["vault.lav".to_string()], "{names:?}");
    assert!(!a.store().dir().starts_with(w.root.join("sync")));
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// FINDING (found by the property test). A crashes after writing the vault;
/// B builds on top of it; A must recognise its own save inside B's file
/// (by the save tag, not the file hash) and not raise a clone alarm.
#[test]
fn own_crashed_save_superseded_by_another_device_is_not_a_clone_alarm() {
    let (w, a, p, o) = crash_setup("c5");
    let b = w.device("B", 2);
    open(&b, &p);
    let _ = a.save(&p, &o.file, b"A", None, Some(SaveFault::AfterVaultWrite));
    let ob = open(&b, &p);
    save(&b, &p, &ob, "B on top of A");
    assert_eq!(open(&a, &p).verdict, Verdict::OwnInterruptedSave);
    assert_eq!(open(&a, &p).verdict, Verdict::Ok);
}
