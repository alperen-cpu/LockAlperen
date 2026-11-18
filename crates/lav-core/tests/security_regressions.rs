//! One regression test per finding of the 2026-11 security audit (see
//! docs/SECURITY_AUDIT_2026-11.md). Each test except LA-02 was run BEFORE the
//! fix and failed (or hung), demonstrating the issue; all must pass from now on.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use lav_core::crypto::{self, CompositeKey, KdfParams, COMMITMENT_LEN};
use lav_core::format::Header;
use lav_core::{Entry, Error, Group, SecretString, Vault, VaultData};

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
        let p = std::env::temp_dir().join(format!("lav-sec-{}", uuid::Uuid::new_v4()));
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

/// Builds a correctly encrypted file around an arbitrary CBOR payload, as only
/// the key holder (or a buggy/older app version) could.
fn encrypt_raw_payload(password: &str, payload: &[u8]) -> Vec<u8> {
    let mut header = Header {
        flags: 0,
        kdf: kdf(),
        salt: crypto::random_bytes(),
        nonce: crypto::random_bytes(),
        commitment: [0; COMMITMENT_LEN],
    };
    let keys = crypto::derive_keys(
        &CompositeKey::new(password, None),
        &header.salt,
        &header.kdf,
    )
    .unwrap();
    header.commitment = keys.commitment(&header.committed_bytes());
    let hb = header.to_bytes();
    let mut out = hb.to_vec();
    out.extend(
        lav_core::testing::encrypt(
            &lav_core::testing::payload_key(&keys),
            &header.nonce,
            &hb,
            payload,
        )
        .unwrap(),
    );
    out
}

/// LA-02 (defense in depth, NOT a reproduced leak): ciborium 0.2.2 currently
/// reports only the *type* ("invalid type: string"), but serde errors in
/// general may quote values (unknown variants, uuid parse errors…). Our error
/// type must never carry decoded content, whatever the library does.
#[test]
fn la02_decode_errors_do_not_quote_vault_content() {
    let secret = "TOPSECRET-recovery-code-1234";
    let mut cbor = Vec::new();
    ciborium::into_writer(
        &ciborium::Value::Map(vec![(
            ciborium::Value::Text("schema".into()),
            ciborium::Value::Text(secret.into()),
        )]),
        &mut cbor,
    )
    .unwrap();

    let file = encrypt_raw_payload(PW, &cbor);
    let err = Vault::unlock(&file, PW, None).unwrap_err();
    let shown = format!("{err} {err:?}");
    assert!(matches!(err, Error::Serialization(_)));
    assert!(!shown.contains(secret), "secret leaked into error: {shown}");
}

/// LA-03a: saving a NEW vault onto an existing file must not silently replace it.
#[test]
fn la03_new_vault_does_not_overwrite_existing_file() {
    let dir = TempDir::new();
    let path = dir.file();
    let mut original = Vault::create("original", PW, None, kdf()).unwrap();
    original.save_file(&path).unwrap();

    let mut other = Vault::create("other", PW, None, kdf()).unwrap();
    assert!(matches!(
        other.save_file(&path),
        Err(Error::FileChangedOnDisk)
    ));
    assert_eq!(
        Vault::open_file(&path, PW, None).unwrap().data.name,
        "original"
    );
    // Explicit, user-confirmed overwrite still works.
    other.save_file_overwrite(&path).unwrap();
    assert_eq!(
        Vault::open_file(&path, PW, None).unwrap().data.name,
        "other"
    );
}

/// LA-03b: two app instances (or a sync client) editing the same file: the
/// second writer must be told instead of silently discarding the first's work.
#[test]
fn la03_concurrent_modification_is_detected() {
    let dir = TempDir::new();
    let path = dir.file();
    Vault::create("v", PW, None, kdf())
        .unwrap()
        .save_file(&path)
        .unwrap();

    let mut a = Vault::open_file(&path, PW, None).unwrap();
    let mut b = Vault::open_file(&path, PW, None).unwrap();

    a.data
        .add_entry(Entry::new(a.data.root, "added by A"))
        .unwrap();
    a.save_file(&path).unwrap();

    b.data
        .add_entry(Entry::new(b.data.root, "added by B"))
        .unwrap();
    assert!(matches!(b.save_file(&path), Err(Error::FileChangedOnDisk)));

    let on_disk = Vault::open_file(&path, PW, None).unwrap();
    assert_eq!(on_disk.data.entries[0].title, "added by A");
}

/// LA-04: the temp file must not be a predictable, pre-creatable name that we
/// would blindly truncate/follow; and no temp file may be left behind.
#[test]
fn la04_pre_existing_tmp_file_is_not_reused_or_clobbered() {
    let dir = TempDir::new();
    let path = dir.file();
    let decoy = PathBuf::from(format!("{}.tmp", path.display()));
    std::fs::write(&decoy, b"attacker-controlled decoy").unwrap();

    let mut v = Vault::create("v", PW, None, kdf()).unwrap();
    v.save_file(&path).unwrap();

    assert_eq!(std::fs::read(&decoy).unwrap(), b"attacker-controlled decoy");
    let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp") && n != "vault.lav.tmp")
        .collect();
    assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
}

fn with_timeout<F: FnOnce() + Send + 'static>(f: F) -> bool {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(5)).is_ok()
}

fn cyclic_vault() -> (VaultData, uuid::Uuid) {
    let mut v = VaultData::new("t");
    let a = v.add_group(v.root, "A").unwrap();
    let b = v.add_group(a, "B").unwrap();
    // Corrupt structure: A's parent becomes B  ->  A <-> B cycle.
    v.groups.iter_mut().find(|g| g.id == a).unwrap().parent = Some(b);
    (v, a)
}

/// LA-05a: a parent cycle in the group tree made delete_group loop forever.
#[test]
fn la05_delete_group_terminates_on_cycles() {
    assert!(
        with_timeout(|| {
            let (mut v, a) = cyclic_vault();
            v.delete_group(a).unwrap();
        }),
        "delete_group did not terminate (infinite loop)"
    );
}

/// LA-05b: structurally broken data from a file (cycles, orphans, missing root)
/// is repaired on unlock WITHOUT deleting anything.
#[test]
fn la05_unlock_repairs_structure_without_data_loss() {
    let (mut v, _) = cyclic_vault();
    let orphan_group = Group {
        id: uuid::Uuid::new_v4(),
        parent: Some(uuid::Uuid::new_v4()),
        name: "orphan".into(),
        icon: None,
        created: 0,
        modified: 0,
        moved: 0,
    };
    let orphan_entry = Entry::new(uuid::Uuid::new_v4(), "orphan entry");
    v.groups.push(orphan_group);
    v.entries.push(orphan_entry);
    let groups_before = v.groups.len();

    let mut cbor = Vec::new();
    ciborium::into_writer(&v, &mut cbor).unwrap();
    let file = encrypt_raw_payload(PW, &cbor);

    let opened = Vault::unlock(&file, PW, None).unwrap();
    let d = &opened.data;
    assert_eq!(d.groups.len(), groups_before);
    assert_eq!(d.entries.len(), 1);
    assert!(d.group(d.entries[0].group).is_some());
    for g in &d.groups {
        if g.id == d.root {
            assert!(g.parent.is_none());
            continue;
        }
        // every chain reaches the root
        let mut cur = g.parent;
        let mut steps = 0;
        while let Some(p) = cur {
            if p == d.root {
                break;
            }
            cur = d.group(p).unwrap().parent;
            steps += 1;
            assert!(steps <= d.groups.len(), "cycle survived repair");
        }
        assert!(cur.is_some(), "group {} not attached to root", g.name);
    }
}

/// LA-06: `{:?}` of entries / vault data exposed titles, usernames and URLs
/// (account metadata) to logs and panic messages.
#[test]
fn la06_debug_output_hides_account_metadata() {
    let mut v = VaultData::new("t");
    let mut e = Entry::new(v.root, "Bank of Secrets");
    e.username = "alice.private".into();
    e.url = "https://secret-bank.example".into();
    e.password = SecretString::from("pw");
    v.add_entry(e).unwrap();
    let shown = format!("{:?} {:?}", v, v.entries[0]);
    for needle in ["Bank of Secrets", "alice.private", "secret-bank.example"] {
        assert!(
            !shown.contains(needle),
            "{needle} leaked via Debug: {shown}"
        );
    }
}

/// LA-07: creating/rekeying a vault with a KDF below the OWASP minimum
/// (19 MiB, 2 passes) must be refused.
#[test]
fn la07_weak_kdf_is_refused_for_new_vaults() {
    let weak = KdfParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    };
    assert!(matches!(
        Vault::create("v", PW, None, weak),
        Err(Error::InvalidKdfParams)
    ));
    let mut v = Vault::create("v", PW, None, kdf()).unwrap();
    assert!(matches!(
        v.change_credentials(PW, None, "another long password", None, Some(weak)),
        Err(Error::InvalidKdfParams)
    ));
}

#[allow(dead_code)]
fn _assert_paths(_: &Path) {}
