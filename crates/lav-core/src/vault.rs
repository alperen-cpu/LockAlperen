//! An unlocked vault: decrypted content plus the derived key needed to re-save it.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::{
    self, CompositeKey, DerivedKeys, KdfParams, COMMITMENT_LEN, NONCE_LEN, SALT_LEN,
};
use crate::error::{Error, Result};
use crate::format::{Header, COMMITTED_LEN, FLAG_KEYFILE};
use crate::model::VaultData;

/// How long a save waits for another instance holding the save lock.
#[cfg(not(test))]
pub(crate) const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
pub(crate) const LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

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
    keys: DerivedKeys,
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
        let keys = crypto::derive_keys(&CompositeKey::new(password, keyfile), &salt, &kdf)?;
        Ok(Self {
            kdf,
            salt,
            keyfile_required: keyfile.is_some(),
            keys,
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
        // Best-effort stack scrub after decrypt + decode (docs/FIX_DESIGN §4.1).
        crypto::scrubbed(|| Self::unlock_inner(bytes, password, keyfile))
    }

    fn unlock_inner(bytes: &[u8], password: &str, keyfile: Option<&[u8]>) -> Result<Self> {
        let (header, aad, ciphertext) = Header::parse(bytes)?;
        match (header.requires_keyfile(), keyfile.is_some()) {
            (true, false) => return Err(Error::KeyFileRequired),
            (false, true) => return Err(Error::UnexpectedKeyFile),
            _ => {}
        }
        let keys = crypto::derive_keys(
            &CompositeKey::new(password, keyfile),
            &header.salt,
            &header.kdf,
        )?;
        // Key commitment (format v2): verified in constant time BEFORE any
        // decryption; the payload key is only released on a match. A
        // mismatch is indistinguishable from a wrong password.
        let payload_key = keys.verified_payload_key(&aad[..COMMITTED_LEN], &header.commitment)?;
        let plaintext = crypto::decrypt(&payload_key, &header.nonce, aad, ciphertext)?;

        // ciborium decodes any string/byte field LONGER than its scratch buffer
        // into a growing Vec whose freed copies are never wiped (verified by
        // lav-memtest: >4 KiB notes survived "lock"). A scratch buffer as large
        // as the whole plaintext means every field fits, so each one is copied
        // exactly once into its final, self-wiping allocation.
        let mut scratch = Zeroizing::new(vec![0u8; plaintext.len().max(16)]);
        let mut rest: &[u8] = plaintext.as_slice();
        let data: VaultData = ciborium::de::from_reader_with_buffer(&mut rest, &mut scratch[..])
            .map_err(sanitize_decode_error)?;
        // The payload must be exactly one CBOR value: trailing bytes are never
        // produced by `seal` and were what made the R2 multi-key PoC open.
        if !rest.is_empty() {
            return Err(Error::Serialization(
                "trailing data after the payload".into(),
            ));
        }
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
            keys,
            backup_is_stale: false,
            disk_state: None,
            data,
        })
    }

    /// Encrypts the vault into file bytes. A fresh random nonce is used every time.
    pub fn seal(&self) -> Result<Vec<u8>> {
        crypto::scrubbed(|| self.seal_inner())
    }

    fn seal_inner(&self) -> Result<Vec<u8>> {
        let mut header = Header {
            flags: if self.keyfile_required {
                FLAG_KEYFILE
            } else {
                0
            },
            kdf: self.kdf,
            salt: self.salt,
            nonce: crypto::random_bytes::<NONCE_LEN>(),
            commitment: [0u8; COMMITMENT_LEN],
        };
        header.commitment = self.keys.commitment(&header.committed_bytes());
        let header_bytes = header.to_bytes();

        // Two passes: measure first, then serialize into an exactly-sized buffer.
        // A growing Vec would realloc and leave un-wiped plaintext copies behind.
        let mut counter = CountingWriter(0);
        ciborium::into_writer(&self.data, &mut counter).map_err(|_| Error::Encode)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(counter.0));
        ciborium::into_writer(&self.data, &mut *plaintext).map_err(|_| Error::Encode)?;
        debug_assert_eq!(plaintext.len(), counter.0);

        let ciphertext = crypto::encrypt(
            self.keys.payload_key(),
            &header.nonce,
            &header_bytes,
            &plaintext,
        )?;

        let mut out = Vec::with_capacity(header_bytes.len() + ciphertext.len());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Returns true if the given credentials are the vault's current ones.
    /// Re-runs the KDF, so it costs as much as unlocking.
    pub fn verify_credentials(&self, password: &str, keyfile: Option<&[u8]>) -> Result<bool> {
        crypto::scrubbed(|| self.verify_credentials_inner(password, keyfile))
    }

    fn verify_credentials_inner(&self, password: &str, keyfile: Option<&[u8]>) -> Result<bool> {
        if self.keyfile_required != keyfile.is_some() {
            return Ok(false);
        }
        let candidate =
            crypto::derive_keys(&CompositeKey::new(password, keyfile), &self.salt, &self.kdf)?;
        Ok(candidate.ct_eq(&self.keys))
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
        self.keys =
            crypto::derive_keys(&CompositeKey::new(new_password, new_keyfile), &salt, &kdf)?;
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
        vault.disk_state = Some((canonical_or_raw(path), fingerprint(&bytes)));
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
        let lock = SaveLock::acquire(path)?;
        let current = if path.exists() {
            let cur = read_limited(path, MAX_VAULT_FILE_BYTES)?;
            match &self.disk_state {
                Some((p, fp))
                    if *p == canonical_or_raw(path) && crypto::ct_eq(fp, &fingerprint(&cur)) => {}
                _ => return Err(Error::FileChangedOnDisk),
            }
            Some(cur)
        } else {
            None
        };
        save_event(SaveEvent::Verified)?;
        self.write_file(path, &lock, current, true)
    }

    /// Like [`Vault::save_file`] but overwrites whatever is at `path`. Only call
    /// this after the user explicitly confirmed (e.g. "Save as" over a file,
    /// or "keep my version" after a conflict).
    pub fn save_file_overwrite(&mut self, path: &Path) -> Result<()> {
        let lock = SaveLock::acquire(path)?;
        let current = if path.exists() {
            Some(read_limited(path, MAX_VAULT_FILE_BYTES)?)
        } else {
            None
        };
        self.write_file(path, &lock, current, false)
    }

    /// Caller holds `lock`. `current` = the bytes at `path` read under the
    /// lock (the version being replaced). With `verify`, the save is aborted
    /// if `path` no longer holds exactly those bytes right before the commit.
    ///
    /// Order (docs/FIX_DESIGN_2026-11.md §2.3, B1):
    /// temp (fsync) -> backup temp from `current` (fsync) -> rename to .bak ->
    /// flush dir -> lock + fingerprint re-check -> rename temp over vault ->
    /// flush dir. Nothing before the commit touches the vault file.
    fn write_file(
        &mut self,
        path: &Path,
        lock: &SaveLock,
        current: Option<Vec<u8>>,
        verify: bool,
    ) -> Result<()> {
        let bytes = self.seal()?;
        let dir = parent_dir(path);
        let bak = sibling(path, "bak");
        // Unpredictable name + create_new: never follows or truncates a file
        // (or link) someone pre-created at a guessable path.
        let tmp = sibling(path, &format!("{}.tmp", hex(&crypto::random_bytes::<8>())));
        write_new_synced(&tmp, &bytes, None, SaveEvent::TmpSynced)?;

        let prepared = (|| -> Result<()> {
            if self.backup_is_stale {
                // The old .bak is still encrypted with the OLD credentials:
                // destroy it (durably) before the new-password vault appears.
                match fs::remove_file(&bak) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                save_event(SaveEvent::BakRemoved)?;
                sync_dir(&dir)?;
                save_event(SaveEvent::DirSynced)?;
            } else if let Some(cur) = &current {
                // Backup = the bytes verified above, not a fresh re-read: a
                // file swapped in meanwhile never becomes the "backup".
                // Fresh temp + rename replaces a planted `.bak` link itself
                // instead of writing through it.
                let bak_tmp = sibling(
                    path,
                    &format!("bak.{}.tmp", hex(&crypto::random_bytes::<8>())),
                );
                write_new_synced(
                    &bak_tmp,
                    cur,
                    Some(SaveEvent::BakTmpWritten),
                    SaveEvent::BakTmpSynced,
                )?;
                if let Err(e) = rename_with_retry(&bak_tmp, &bak) {
                    let _ = fs::remove_file(&bak_tmp);
                    return Err(e.into());
                }
                save_event(SaveEvent::BakRenamed)?;
                sync_dir(&dir)?;
                save_event(SaveEvent::DirSynced)?;
            }
            save_event(SaveEvent::PreCommit)?;
            lock.ensure_held()?;
            if verify {
                let now = if path.exists() {
                    Some(fingerprint(&read_limited(path, MAX_VAULT_FILE_BYTES)?))
                } else {
                    None
                };
                let expected = current.as_deref().map(fingerprint);
                let same = match (now, expected) {
                    (None, None) => true,
                    (Some(a), Some(b)) => crypto::ct_eq(&a, &b),
                    _ => false,
                };
                if !same {
                    return Err(Error::FileChangedOnDisk);
                }
            }
            rename_with_retry(&tmp, path)?;
            Ok(())
        })();
        if let Err(e) = prepared {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }

        // Committed: the vault file IS the new version from here on, even if
        // a later step fails, so record that first.
        self.backup_is_stale = false;
        self.disk_state = Some((canonical_or_raw(path), fingerprint(&bytes)));
        save_event(SaveEvent::MainRenamed)?;
        sync_dir(&dir)?;
        save_event(SaveEvent::DirSynced)?;
        // Crash leftovers may hold an older vault (maybe under an old password).
        remove_stale_temps(path);
        Ok(())
    }
}

/// Points in the save path. Test builds report each one to a per-thread
/// hook (to record the order or simulate a crash); normal builds compile the
/// calls away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum SaveEvent {
    /// The on-disk file was read and its fingerprint checked.
    Verified,
    /// New vault bytes written to the temp file and fsynced.
    TmpSynced,
    /// Backup bytes written to the backup temp file.
    BakTmpWritten,
    /// Backup temp file fsynced.
    BakTmpSynced,
    /// Backup temp renamed to `<vault>.bak`.
    BakRenamed,
    /// Stale (old-password) backup removed.
    BakRemoved,
    /// Directory flushed.
    DirSynced,
    /// Last point before the vault file is replaced.
    PreCommit,
    /// Temp renamed over the vault file.
    MainRenamed,
}

#[cfg(test)]
pub(crate) mod save_hook {
    use std::cell::RefCell;
    use std::io;

    use super::SaveEvent;

    type Hook = Box<dyn FnMut(SaveEvent) -> io::Result<()>>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
    }

    pub fn set(f: impl FnMut(SaveEvent) -> io::Result<()> + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub fn clear() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }

    pub fn fire(e: SaveEvent) -> io::Result<()> {
        // Take the hook out while it runs, so it may itself save/lock.
        let hook = HOOK.with(|h| h.borrow_mut().take());
        let Some(mut hook) = hook else {
            return Ok(());
        };
        let r = hook(e);
        HOOK.with(|h| {
            let mut slot = h.borrow_mut();
            if slot.is_none() {
                *slot = Some(hook);
            }
        });
        r
    }
}

#[inline(always)]
fn save_event(_e: SaveEvent) -> io::Result<()> {
    #[cfg(test)]
    {
        save_hook::fire(_e)
    }
    #[cfg(not(test))]
    {
        Ok(())
    }
}

/// Exclusive lock on `<vault>.lock`, held for the duration of a save.
///
/// - Windows: opened WITHOUT `FILE_SHARE_DELETE`, so while it is held nobody
///   (another process, a sync client) can delete or rename over it (T1).
/// - Unix: `flock` is advisory and the file can always be unlinked. After
///   locking, and again right before the commit, we check that the path
///   still names the locked file (dev, ino); if not -> `LockLost` (T2). This
///   DETECTS a stolen lock, it cannot prevent one: a small window remains
///   between that check and the rename (docs/FIX_DESIGN_2026-11.md §4.4).
/// - Never waits more than [`LOCK_WAIT`]: then `SaveBusy` (T3).
pub(crate) struct SaveLock {
    /// Holding the handle IS the lock (released on drop). Only read on Unix.
    #[cfg_attr(not(unix), allow(dead_code))]
    file: fs::File,
    path: PathBuf,
}

impl SaveLock {
    pub(crate) fn acquire(vault: &Path) -> Result<Self> {
        let path = sibling(vault, "lock");
        let mut opts = fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x1;
            const FILE_SHARE_WRITE: u32 = 0x2;
            opts.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        let start = std::time::Instant::now();
        let retry = |e: Error| -> Result<()> {
            if start.elapsed() >= LOCK_WAIT {
                return Err(e);
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
            Ok(())
        };
        loop {
            let file = match opts.open(&path) {
                Ok(f) => f,
                // AV / sync client briefly holding the lock file.
                Err(e) if is_transient(&e) => {
                    retry(Error::SaveBusy)?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            match file.try_lock() {
                Ok(()) => {
                    let lock = Self {
                        file,
                        path: path.clone(),
                    };
                    // The path may have been replaced between open and lock.
                    match lock.ensure_held() {
                        Ok(()) => return Ok(lock),
                        Err(_) => retry(Error::SaveBusy)?,
                    }
                }
                Err(std::fs::TryLockError::WouldBlock) => retry(Error::SaveBusy)?,
                Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
            }
        }
    }

    /// Fails with `LockLost` if `<vault>.lock` no longer names the file we
    /// hold the lock on.
    pub(crate) fn ensure_held(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let held = self.file.metadata()?;
            match fs::metadata(&self.path) {
                Ok(now) if now.dev() == held.dev() && now.ino() == held.ino() => Ok(()),
                _ => Err(Error::LockLost),
            }
        }
        #[cfg(not(unix))]
        {
            // Windows: the share mode forbids deleting / replacing the held
            // file (T1), so the name can only be gone if something is badly
            // wrong; still check, as defence in depth.
            match fs::metadata(&self.path) {
                Ok(_) => Ok(()),
                Err(_) => Err(Error::LockLost),
            }
        }
    }
}

/// `create_new` + write + fsync. Removes the file again on any failure.
fn write_new_synced(
    path: &Path,
    bytes: &[u8],
    after_write: Option<SaveEvent>,
    after_sync: SaveEvent,
) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    // The vault (and its .bak, made by rename) is only the user's: 0600
    // whatever the umask (0002 would let a group member replace it).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    let r = f
        .write_all(bytes)
        .and_then(|_| after_write.map_or(Ok(()), save_event))
        // A failed fsync is final for this save: never retried
        // (pages may already be marked clean, docs/FIX_DESIGN §4.5).
        .and_then(|_| f.sync_all())
        .and_then(|_| save_event(after_sync));
    if let Err(e) = r {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    Ok(())
}

/// Makes renames / creations / deletions in `dir` durable.
/// Unix: `fsync(dir)` (required; errors are fatal).
/// Windows: `FlushFileBuffers` on a directory handle (BACKUP_SEMANTICS +
/// write access). Returns Ok on this machine (probe P3); whether it really
/// persists the rename is NOT documented or verified. "Not supported" errors
/// (file systems without it) are tolerated; others are fatal.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const ERROR_INVALID_FUNCTION: i32 = 1;
        const ERROR_NOT_SUPPORTED: i32 = 50;
        let r = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)
            .and_then(|d| d.sync_all());
        match r {
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(ERROR_INVALID_FUNCTION) | Some(ERROR_NOT_SUPPORTED)
                ) =>
            {
                Ok(())
            }
            r => r,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Ok(())
    }
}

fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Canonical form for "is this the file we opened?" (case, 8.3 names and
/// symlinks on Windows; symlinks on Unix). Falls back to the raw path.
fn canonical_or_raw(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
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

#[cfg(test)]
#[path = "vault_save_tests.rs"]
mod save_tests;
