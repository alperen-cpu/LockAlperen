//! Regression tests for findings of the INDEPENDENT review (second pass of the
//! 2026-11 audit). Each was run before the fix and failed or timed out.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use lav_core::crypto::{self, CompositeKey, KdfParams};
use lav_core::format::Header;
use lav_core::{Entry, Error, Group, Vault, VaultData};

const PW: &str = "correct horse battery";

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
        let p = std::env::temp_dir().join(format!("lav-rev-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn file(&self) -> PathBuf {
        self.0.join("vault.lav")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn encrypt_raw_payload(password: &str, payload: &[u8]) -> Vec<u8> {
    let header = Header {
        flags: 0,
        kdf: kdf(),
        salt: crypto::random_bytes(),
        nonce: crypto::random_bytes(),
    };
    let key = crypto::derive_payload_key(
        &CompositeKey::new(password, None),
        &header.salt,
        &header.kdf,
    )
    .unwrap();
    let hb = header.to_bytes();
    let mut out = hb.to_vec();
    out.extend(crypto::encrypt(&key, &header.nonce, &hb, payload).unwrap());
    out
}

fn with_timeout<F: FnOnce() + Send + 'static>(secs: u64, f: F) -> bool {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(secs)).is_ok()
}

fn group(id: uuid::Uuid, parent: Option<uuid::Uuid>, name: &str) -> Group {
    Group {
        id,
        parent,
        name: name.into(),
        icon: None,
        created: 0,
        modified: 0,
    }
}

/// LA-09: a second group carrying the ROOT's id, placed under a normal
/// subgroup, made delete_group(subgroup) wipe the whole vault.
#[test]
fn la09_duplicate_root_id_cannot_wipe_vault() {
    let mut v = VaultData::new("t");
    let root = v.root;
    let child = v.add_group(root, "Child").unwrap();
    v.add_entry(Entry::new(root, "keep me")).unwrap();
    v.groups.push(group(root, Some(child), "evil"));
    let mut cbor = Vec::new();
    ciborium::into_writer(&v, &mut cbor).unwrap();
    let mut opened = Vault::unlock(&encrypt_raw_payload(PW, &cbor), PW, None).unwrap();

    opened.data.delete_group(child).unwrap();
    let d = &opened.data;
    assert!(d.group(d.root).is_some(), "root was deleted");
    assert!(
        d.entries.iter().any(|e| e.title == "keep me"),
        "entries wiped"
    );
    let mut ids: Vec<_> = d.groups.iter().map(|g| g.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), d.groups.len(), "duplicate group ids survived");
}

/// LA-09b: even on unrepaired in-memory data, delete_group never removes root.
#[test]
fn la09_delete_group_never_removes_root() {
    let mut v = VaultData::new("t");
    let root = v.root;
    let child = v.add_group(root, "Child").unwrap();
    v.groups.push(group(root, Some(child), "evil"));
    v.add_entry(Entry::new(root, "keep me")).unwrap();
    v.delete_group(child).unwrap();
    assert!(v.group(root).is_some());
    assert_eq!(v.entries.len(), 1);
}

/// LA-10: repair/delete were quadratic; a ~1.6 MB file with a 20k-deep group
/// chain froze unlock for over a minute.
#[test]
fn la10_structure_repair_and_delete_are_linear() {
    let mut v = VaultData::new("t");
    let mut parent = v.root;
    let mut first = None;
    for _ in 0..20_000 {
        let id = uuid::Uuid::new_v4();
        v.groups.push(group(id, Some(parent), ""));
        first.get_or_insert(id);
        parent = id;
    }
    let first = first.unwrap();
    assert!(
        with_timeout(5, move || {
            v.repair_structure();
            v.delete_group(first).unwrap();
            assert_eq!(v.groups.len(), 1);
        }),
        "repair/delete on a 20k chain took > 5 s"
    );
}

/// LA-11: the on-disk check and the rename were not atomic, so two writers
/// saving at the same moment could both "succeed" (silent lost update).
#[test]
fn la11_simultaneous_saves_never_both_succeed() {
    let dir = TempDir::new();
    let path = dir.file();
    Vault::create("v", PW, None, kdf())
        .unwrap()
        .save_file(&path)
        .unwrap();
    for round in 0..15 {
        let a = Vault::open_file(&path, PW, None).unwrap();
        let b = Vault::open_file(&path, PW, None).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let spawn = |mut v: Vault, tag: &'static str| {
            let (p, bar) = (path.clone(), barrier.clone());
            std::thread::spawn(move || {
                v.data.add_entry(Entry::new(v.data.root, tag)).unwrap();
                bar.wait();
                v.save_file(&p).is_ok()
            })
        };
        let ta = spawn(a, "A");
        let tb = spawn(b, "B");
        let (ra, rb) = (ta.join().unwrap(), tb.join().unwrap());
        assert!(
            !(ra && rb),
            "round {round}: both writers succeeded (lost update)"
        );
        assert!(ra || rb, "round {round}: neither writer succeeded");
    }
}

/// LA-12: a hostile header could demand 4 GiB x 100 passes of Argon2 before
/// authentication fails (local DoS / abort on OOM).
#[test]
fn la12_hostile_kdf_cost_is_refused_before_any_work() {
    let mut h = Header {
        flags: 0,
        kdf: kdf(),
        salt: [0; 32],
        nonce: [0; 24],
    };
    h.kdf.memory_kib = 4 * 1024 * 1024;
    h.kdf.iterations = 100;
    let mut file = h.to_bytes().to_vec();
    file.extend([0u8; 32]);
    assert!(matches!(
        Vault::peek_header(&file),
        Err(Error::InvalidKdfParams)
    ));
    assert!(KdfParams::default().validate().is_ok());
}

/// LA-13: schema numbers were truncated to u16 in errors.
#[test]
fn la13_future_schema_is_reported_exactly() {
    let mut v = VaultData::new("t");
    v.schema = 65_537;
    let mut cbor = Vec::new();
    ciborium::into_writer(&v, &mut cbor).unwrap();
    let err = Vault::unlock(&encrypt_raw_payload(PW, &cbor), PW, None).unwrap_err();
    assert!(matches!(err, Error::UnsupportedSchema(65_537)), "{err:?}");
}

/// LA-14: crash-leftover temp files (possibly encrypted with an OLD password)
/// are cleaned up by the next successful save.
#[test]
fn la14_stale_temp_files_are_removed_on_save() {
    let dir = TempDir::new();
    let path = dir.file();
    let mut v = Vault::create("v", PW, None, kdf()).unwrap();
    v.save_file(&path).unwrap();
    let stale = dir.0.join("vault.lav.0123456789abcdef.tmp");
    std::fs::write(&stale, b"old ciphertext").unwrap();
    let unrelated = dir.0.join("notes.tmp");
    std::fs::write(&unrelated, b"not ours").unwrap();
    v.save_file(&path).unwrap();
    assert!(!stale.exists(), "stale temp file left behind");
    assert!(unrelated.exists(), "must not touch unrelated files");
}
