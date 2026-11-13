//! An unlocked vault: decrypted content plus the derived key needed to re-save it.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::{self, CompositeKey, KdfParams, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{Error, Result};
use crate::format::{Header, FLAG_KEYFILE};
use crate::model::VaultData;

/// Minimum master password length when no key file is used.
pub const MIN_PASSWORD_CHARS: usize = 8;
/// Refuse to read vault files larger than this (protects against a hostile file).
pub const MAX_VAULT_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// Key files are hashed whole; anything bigger than this is almost certainly a mistake.
pub const MAX_KEYFILE_BYTES: u64 = 16 * 1024 * 1024;

pub struct Vault {
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    keyfile_required: bool,
    key: Zeroizing<[u8; KEY_LEN]>,
    /// Set after a credential change: the existing `.bak` is still encrypted with
    /// the OLD password and must be destroyed instead of kept.
    backup_is_stale: bool,
    /// Path + SHA-256 of the file as we last read or wrote it. Used to refuse
    /// silently overwriting a file we did not load, or one that changed on
    /// disk since (another instance, a sync client, an attacker).
    disk_state: Option<(PathBuf, [u8; 32])>,
    pub data: VaultData,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("name", &self.data.name)
            .field("kdf", &self.kdf)
            .field("keyfile_required", &self.keyfile_required)
            .finish_non_exhaustive()
    }
}

fn check_new_credentials(password: &str, keyfile: Option<&[u8]>) -> Result<()> {
    if keyfile.is_none() && password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Error::WeakPassword(MIN_PASSWORD_CHARS));
    }
    if keyfile.is_some_and(|k| k.is_empty()) {
        return Err(Error::EmptyKeyFile);
    }
    Ok(())
}

impl Vault {
    /// Creates a new, empty vault. Runs the KDF once.
    pub fn create(
        name: &str,
        password: &str,
        keyfile: Option<&[u8]>,
        kdf: KdfParams,
    ) -> Result<Self> {
        check_new_credentials(password, keyfile)?;
        let salt = crypto::random_bytes::<SALT_LEN>();
        let key = crypto::derive_payload_key(&CompositeKey::new(password, keyfile), &salt, &kdf)?;
        Ok(Self {
            kdf,
            salt,
            keyfile_required: keyfile.is_some(),
            key,
            backup_is_stale: false,
            disk_state: None,
            data: VaultData::new(name),
        })
    }

    /// Reads only the (unauthenticated) header, e.g. to know whether to ask for a key file.
    pub fn peek_header(bytes: &[u8]) -> Result<Header> {
        Header::parse(bytes).map(|(h, _, _)| h)
    }

    /// Decrypts a vault from its file bytes.
    pub fn unlock(bytes: &[u8], password: &str, keyfile: Option<&[u8]>) -> Result<Self> {
        let (header, aad, ciphertext) = Header::parse(bytes)?;
        if header.requires_keyfile() && keyfile.is_none() {
            return Err(Error::KeyFileRequired);
        }
        let key = crypto::derive_payload_key(
            &CompositeKey::new(password, keyfile),
            &header.salt,
            &header.kdf,
        )?;
        let plaintext = crypto::decrypt(&key, &header.nonce, aad, ciphertext)?;

        // ciborium decodes any string/byte field LONGER than its scratch buffer
        // into a growing Vec whose freed copies are never wiped (verified by
        // lav-memtest: >4 KiB notes survived "lock"). A scratch buffer as large
        // as the whole plaintext means every field fits, so each one is copied
        // exactly once into its final, self-wiping allocation.
        let mut scratch = Zeroizing::new(vec![0u8; plaintext.len().max(16)]);
        let data: VaultData =
            ciborium::de::from_reader_with_buffer(plaintext.as_slice(), &mut scratch[..])
                .map_err(sanitize_decode_error)?;
        if data.schema > VaultData::SCHEMA {
            return Err(Error::UnsupportedSchema(data.schema));
        }
        let mut data = data;
        // Never trust structure, even authenticated: re-attach orphans and
        // break cycles (moves to root, never deletes anything).
        data.repair_structure();
        Ok(Self {
            kdf: header.kdf,
            salt: header.salt,
            keyfile_required: header.requires_keyfile(),
            key,
            backup_is_stale: false,
            disk_state: None,
            data,
        })
    }

    /// Encrypts the vault into file bytes. A fresh random nonce is used every time.
    pub fn seal(&self) -> Result<Vec<u8>> {
        let header = Header {
            flags: if self.keyfile_required {
                FLAG_KEYFILE
            } else {
                0
            },
            kdf: self.kdf,
            salt: self.salt,
            nonce: crypto::random_bytes::<NONCE_LEN>(),
        };
        let header_bytes = header.to_bytes();

        // Two passes: measure first, then serialize into an exactly-sized buffer.
        // A growing Vec would realloc and leave un-wiped plaintext copies behind.
        let mut counter = CountingWriter(0);
        ciborium::into_writer(&self.data, &mut counter)
            .map_err(|_| Error::Serialization("could not encode vault".into()))?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(counter.0));
        ciborium::into_writer(&self.data, &mut *plaintext)
            .map_err(|_| Error::Serialization("could not encode vault".into()))?;
        debug_assert_eq!(plaintext.len(), counter.0);

        let ciphertext = crypto::encrypt(&self.key, &header.nonce, &header_bytes, &plaintext)?;

        let mut out = Vec::with_capacity(header_bytes.len() + ciphertext.len());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Returns true if the given credentials are the vault's current ones.
    /// Re-runs the KDF, so it costs as much as unlocking.
    pub fn verify_credentials(&self, password: &str, keyfile: Option<&[u8]>) -> Result<bool> {
        if self.keyfile_required != keyfile.is_some() {
            return Ok(false);
        }
        let candidate = crypto::derive_payload_key(
            &CompositeKey::new(password, keyfile),
            &self.salt,
            &self.kdf,
        )?;
        Ok(crypto::ct_eq(&candidate[..], &self.key[..]))
    }

    /// Replaces the password / key file (and optionally the KDF cost).
    ///
    /// The CURRENT credentials are required even though the vault is already
    /// unlocked, so someone at an unattended, unlocked session cannot take the
    /// vault over (cf. KeePassXC CVE-2023-35866). Generates a new salt and key.
    pub fn change_credentials(
        &mut self,
        current_password: &str,
        current_keyfile: Option<&[u8]>,
        new_password: &str,
        new_keyfile: Option<&[u8]>,
        kdf: Option<KdfParams>,
    ) -> Result<()> {
        if !self.verify_credentials(current_password, current_keyfile)? {
            return Err(Error::WrongCurrentCredentials);
        }
        check_new_credentials(new_password, new_keyfile)?;
        let kdf = kdf.unwrap_or(self.kdf);
        let salt = crypto::random_bytes::<SALT_LEN>();
        self.key =
            crypto::derive_payload_key(&CompositeKey::new(new_password, new_keyfile), &salt, &kdf)?;
        self.kdf = kdf;
        self.salt = salt;
        self.keyfile_required = new_keyfile.is_some();
        self.backup_is_stale = true;
        Ok(())
    }

    pub fn kdf(&self) -> KdfParams {
        self.kdf
    }

    pub fn requires_keyfile(&self) -> bool {
        self.keyfile_required
    }

    pub fn open_file(path: &Path, password: &str, keyfile: Option<&[u8]>) -> Result<Self> {
        let bytes = read_limited(path, MAX_VAULT_FILE_BYTES)?;
        let mut vault = Self::unlock(&bytes, password, keyfile)?;
        vault.disk_state = Some((path.to_path_buf(), fingerprint(&bytes)));
        Ok(vault)
    }

    /// Reads a key file with a size limit; the returned buffer wipes itself.
    pub fn read_keyfile(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        read_limited(path, MAX_KEYFILE_BYTES).map(Zeroizing::new)
    }

    /// Crash-safe save: write a fresh randomly-named temp file, fsync, back up
    /// the old file to `<file>.bak`, then atomically rename over the original.
    ///
    /// Refuses with [`Error::FileChangedOnDisk`] if `path` exists but is not
    /// the file this vault was opened from / last saved to, or if it changed
    /// since. The UI should then ask the user and call [`Vault::save_file_overwrite`].
    ///
    /// After a credential change the old `.bak` (still openable with the OLD
    /// password) is deleted instead of refreshed.
    pub fn save_file(&mut self, path: &Path) -> Result<()> {
        // Check-then-replace runs under an exclusive OS lock, so two writers
        // can never both pass the check (LA-11).
        let _lock = SaveLock::acquire(path)?;
        if path.exists() {
            let current = fingerprint(&read_limited(path, MAX_VAULT_FILE_BYTES)?);
            match &self.disk_state {
                Some((p, fp)) if p == path && crypto::ct_eq(fp, &current) => {}
                _ => return Err(Error::FileChangedOnDisk),
            }
        }
        self.write_file(path)
    }

    /// Like [`Vault::save_file`] but overwrites whatever is at `path`. Only call
    /// this after the user explicitly confirmed (e.g. "Save as" over a file,
    /// or "keep my version" after a conflict).
    pub fn save_file_overwrite(&mut self, path: &Path) -> Result<()> {
        let _lock = SaveLock::acquire(path)?;
        self.write_file(path)
    }

    /// Caller must hold the [`SaveLock`].
    fn write_file(&mut self, path: &Path) -> Result<()> {
        let bytes = self.seal()?;
        let bak = sibling(path, "bak");
        // Unpredictable name + create_new: never follows or truncates a file
        // (or link) someone pre-created at a guessable path.
        let tmp = sibling(path, &format!("{}.tmp", hex(&crypto::random_bytes::<8>())));
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            let written = f.write_all(&bytes).and_then(|_| f.sync_all());
            if let Err(e) = written {
                drop(f);
                let _ = fs::remove_file(&tmp);
                return Err(e.into());
            }
        }
        let result = (|| -> io::Result<()> {
            if self.backup_is_stale {
                match fs::remove_file(&bak) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            } else if path.exists() {
                // Copy to a fresh temp, then rename: replaces a planted `.bak`
                // link itself instead of writing through it.
                let bak_tmp = sibling(
                    path,
                    &format!("bak.{}.tmp", hex(&crypto::random_bytes::<8>())),
                );
                fs::copy(path, &bak_tmp)?;
                if let Err(e) = rename_with_retry(&bak_tmp, &bak) {
                    let _ = fs::remove_file(&bak_tmp);
                    return Err(e);
                }
            }
            rename_with_retry(&tmp, path)
        })();
        if let Err(e) = result {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        self.backup_is_stale = false;
        self.disk_state = Some((path.to_path_buf(), fingerprint(&bytes)));
        // Crash leftovers may hold an older vault (maybe under an old password).
        remove_stale_temps(path);
        Ok(())
    }
}

/// Exclusive advisory lock on `<vault>.lock`, held for the duration of a save.
struct SaveLock {
    _file: fs::File,
}

impl SaveLock {
    fn acquire(path: &Path) -> Result<Self> {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(sibling(path, "lock"))?;
        f.lock()?; // blocks until other writers are done; released on drop
        Ok(Self { _file: f })
    }
}

/// OneDrive / antivirus briefly hold files open on Windows; retry a sharing
/// violation a few times instead of failing the save.
fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    let mut attempt = 0;
    loop {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 5 && is_transient(&e) => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(100 * attempt));
            }
            Err(e) => return Err(e),
        }
    }
}

fn is_transient(e: &io::Error) -> bool {
    // 5 = ERROR_ACCESS_DENIED, 32 = ERROR_SHARING_VIOLATION, 33 = ERROR_LOCK_VIOLATION
    matches!(e.raw_os_error(), Some(5) | Some(32) | Some(33))
}

/// Removes `<name>.<16 hex>.tmp` and `<name>.bak.<16 hex>.tmp` siblings.
fn remove_stale_temps(path: &Path) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let prefix = format!("{}.", name.to_string_lossy());
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let Some(middle) = file
            .strip_prefix(&prefix)
            .and_then(|r| r.strip_suffix(".tmp"))
        else {
            continue;
        };
        let middle = middle.strip_prefix("bak.").unwrap_or(middle);
        if middle.len() == 16 && middle.bytes().all(|b| b.is_ascii_hexdigit()) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    *crypto::sha256(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Maps decoder errors to messages that never contain decoded content.
fn sanitize_decode_error(e: ciborium::de::Error<io::Error>) -> Error {
    use ciborium::de::Error as De;
    Error::Serialization(match e {
        De::Io(_) => "I/O error while decoding".into(),
        De::Syntax(off) => format!("malformed payload at byte {off}"),
        De::Semantic(off, _) => match off {
            Some(off) => format!("payload does not match the expected schema (byte {off})"),
            None => "payload does not match the expected schema".into(),
        },
        De::RecursionLimitExceeded => "payload nesting too deep".into(),
    })
}

fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>> {
    let f = fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > max {
        return Err(Error::FileTooLarge(max));
    }
    let mut buf = Vec::with_capacity(len as usize);
    // `take` guards against the file growing between metadata() and read().
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(Error::FileTooLarge(max));
    }
    Ok(buf)
}

struct CountingWriter(usize);

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn sibling(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}
