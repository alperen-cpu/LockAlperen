use std::path::PathBuf;

use lav_core::format::HEADER_LEN;
use lav_core::{Attachment, CustomField, Entry, Error, KdfParams, SecretBytes, Vault};

const PW: &str = "doğru-at-pil-zımba";

fn fast() -> KdfParams {
    KdfParams {
        memory_kib: KdfParams::MIN_MEMORY_KIB,
        iterations: KdfParams::MIN_ITERATIONS,
        parallelism: 1,
    }
}

fn sample_vault() -> Vault {
    let mut v = Vault::create("Kişisel", "doğru-at-pil-zımba", None, fast()).unwrap();
    let work = v.data.add_group(v.data.root, "İş").unwrap();
    let mut e = Entry::new(work, "GitHub");
    e.username = "alperen".into();
    e.password = "s3cr3t!".into();
    e.url = "https://github.com".into();
    e.totp = Some("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP".into());
    e.tags = vec!["dev".into()];
    e.fields.push(CustomField {
        name: "PIN".into(),
        value: "1234".into(),
        protected: true,
    });
    e.attachments.push(Attachment {
        name: "recovery.txt".into(),
        data: SecretBytes::new(vec![0, 1, 2, 255]),
    });
    v.data.add_entry(e).unwrap();
    v
}

struct TempFile(PathBuf);

impl TempFile {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("lav-test-{}.lav", uuid::Uuid::new_v4())))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        for ext in ["", ".bak", ".tmp"] {
            let mut p = self.0.as_os_str().to_owned();
            p.push(ext);
            let _ = std::fs::remove_file(PathBuf::from(p));
        }
    }
}

#[test]
fn seal_unlock_roundtrip_preserves_everything() {
    let v = sample_vault();
    let bytes = v.seal().unwrap();
    let back = Vault::unlock(&bytes, "doğru-at-pil-zımba", None).unwrap();

    assert_eq!(back.data.name, "Kişisel");
    assert_eq!(back.data.groups.len(), 2);
    let e = &back.data.entries[0];
    assert_eq!(e.password.expose(), "s3cr3t!");
    assert_eq!(e.fields[0].value.expose(), "1234");
    assert_eq!(e.attachments[0].data.expose(), &[0, 1, 2, 255]);
    assert!(e.totp.as_ref().unwrap().expose().contains("JBSWY3DP"));
    assert!(!format!("{back:?} {:?}", back.data).contains("s3cr3t!"));
}

#[test]
fn every_seal_uses_a_fresh_nonce() {
    let v = sample_vault();
    assert_ne!(v.seal().unwrap(), v.seal().unwrap());
}

#[test]
fn wrong_password_fails() {
    let bytes = sample_vault().seal().unwrap();
    assert!(matches!(
        Vault::unlock(&bytes, "wrong", None),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn tampering_with_header_or_body_fails() {
    let bytes = sample_vault().seal().unwrap();

    // Flip a salt byte (header, authenticated as AAD).
    let mut h = bytes.clone();
    h[30] ^= 0x01;
    assert!(Vault::unlock(&h, "doğru-at-pil-zımba", None).is_err());

    // Raise iterations 2 -> 3: still a *valid* header, but AAD no longer matches.
    let mut it = bytes.clone();
    it[14] = 3;
    assert!(matches!(
        Vault::unlock(&it, "doğru-at-pil-zımba", None),
        Err(Error::DecryptionFailed)
    ));

    // Flip a ciphertext byte.
    let mut b = bytes.clone();
    b[HEADER_LEN + 5] ^= 0x01;
    assert!(matches!(
        Vault::unlock(&b, "doğru-at-pil-zımba", None),
        Err(Error::DecryptionFailed)
    ));

    // Truncation.
    assert!(Vault::unlock(&bytes[..bytes.len() - 1], "doğru-at-pil-zımba", None).is_err());
}

#[test]
fn keyfile_is_enforced() {
    let mut v = sample_vault();
    v.change_credentials(PW, None, "", Some(b"key file bytes"), None)
        .unwrap();
    let bytes = v.seal().unwrap();

    assert!(Vault::peek_header(&bytes).unwrap().requires_keyfile());
    assert!(matches!(
        Vault::unlock(&bytes, "", None),
        Err(Error::KeyFileRequired)
    ));
    assert!(Vault::unlock(&bytes, "", Some(b"other key file")).is_err());
    assert!(Vault::unlock(&bytes, "", Some(b"key file bytes")).is_ok());
}

#[test]
fn change_credentials_invalidates_old_password() {
    let mut v = sample_vault();
    assert!(matches!(
        v.change_credentials("not the password", None, "new password", None, None),
        Err(Error::WrongCurrentCredentials)
    ));
    assert!(matches!(
        v.change_credentials(PW, None, "short", None, None),
        Err(Error::WeakPassword(_))
    ));
    v.change_credentials(PW, None, "new password", None, None)
        .unwrap();
    let bytes = v.seal().unwrap();
    assert!(Vault::unlock(&bytes, "doğru-at-pil-zımba", None).is_err());
    assert!(Vault::unlock(&bytes, "new password", None).is_ok());
}

#[test]
fn file_save_is_atomic_and_keeps_backup() {
    let tmp = TempFile::new();
    let mut v = sample_vault();
    v.save_file(&tmp.0).unwrap();

    v.data.name = "Renamed".into();
    v.save_file(&tmp.0).unwrap();

    let current = Vault::open_file(&tmp.0, "doğru-at-pil-zımba", None).unwrap();
    assert_eq!(current.data.name, "Renamed");

    let mut bak = tmp.0.as_os_str().to_owned();
    bak.push(".bak");
    let previous = Vault::open_file(bak.as_ref(), "doğru-at-pil-zımba", None).unwrap();
    assert_eq!(previous.data.name, "Kişisel");

    let mut leftover = tmp.0.as_os_str().to_owned();
    leftover.push(".tmp");
    assert!(!PathBuf::from(leftover).exists());
}

#[test]
fn rejects_non_vault_files() {
    assert!(matches!(
        Vault::unlock(b"hello world", "x", None),
        Err(Error::NotAVault)
    ));
}

#[test]
fn rejects_weak_new_vault_password() {
    assert!(matches!(
        Vault::create("x", "1234567", None, fast()),
        Err(Error::WeakPassword(_))
    ));
    assert!(matches!(
        Vault::create("x", "", Some(b""), fast()),
        Err(Error::EmptyKeyFile)
    ));
    assert!(Vault::create("x", "", Some(b"kf"), fast()).is_ok());
}

#[test]
fn backup_with_old_password_is_destroyed_after_credential_change() {
    let tmp = TempFile::new();
    let mut bak = tmp.0.as_os_str().to_owned();
    bak.push(".bak");
    let bak = PathBuf::from(bak);

    let mut v = sample_vault();
    v.save_file(&tmp.0).unwrap();
    v.save_file(&tmp.0).unwrap();
    assert!(bak.exists());

    v.change_credentials(PW, None, "a brand new password", None, None)
        .unwrap();
    v.save_file(&tmp.0).unwrap();
    assert!(!bak.exists(), "old-password backup must be gone");

    // The next save creates a fresh backup with the NEW password.
    v.save_file(&tmp.0).unwrap();
    assert!(Vault::open_file(&bak, PW, None).is_err());
    assert!(Vault::open_file(&bak, "a brand new password", None).is_ok());
}

#[test]
fn verify_credentials_matches_only_current() {
    let v = sample_vault();
    assert!(v.verify_credentials(PW, None).unwrap());
    assert!(!v.verify_credentials("nope", None).unwrap());
    assert!(!v.verify_credentials(PW, Some(b"kf")).unwrap());
}
