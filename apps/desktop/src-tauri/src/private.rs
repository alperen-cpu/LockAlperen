//! Files that only the user may read: app data (settings, recent list, Google
//! Drive store), exports (CSV, KDBX, HTML), saved attachments and key files.
//!
//! Unix: files are created 0600 and their folder 0700, whatever the umask
//! (Ubuntu's default 0002 would give 0664: group-writable, world-readable).
//! A file that already exists is set to 0600 too (an export over an old
//! file). Windows: the default ACL of the user's folders already applies.

use std::fs;
use std::io::Write;
use std::path::Path;

/// Creates (or truncates) `path` readable and writable only by the user.
pub fn create(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

/// Like [`create`], but fails if `path` exists.
pub fn create_new(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// `fs::write` with [`create`]'s permissions.
pub fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Writes via a temp file and rename (a crash never leaves a half-written
/// file); the app-data folder is created 0700 on Unix.
pub fn write_atomic(file: &Path, tmp_ext: &str, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = file.parent() {
        create_dir(dir)?;
    }
    let tmp = file.with_extension(tmp_ext);
    write(&tmp, bytes)?;
    fs::rename(&tmp, file)
}

/// Creates the app's own data folder; on Unix a new one is 0700.
pub fn create_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn files_and_folder_are_private_whatever_the_umask() {
        let base = std::env::temp_dir().join(format!("lav-private-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let dir = base.join("data");
        let file = dir.join("settings.json");
        write_atomic(&file, "json.tmp", b"{}").unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&file), 0o600);

        // An existing, group-writable file is tightened when overwritten.
        let old = base.join("export.csv");
        fs::write(&old, b"x").unwrap();
        fs::set_permissions(&old, fs::Permissions::from_mode(0o664)).unwrap();
        write(&old, b"secret").unwrap();
        assert_eq!(mode(&old), 0o600);
        assert_eq!(fs::read(&old).unwrap(), b"secret");

        let new = base.join("key.keyx");
        create_new(&new).unwrap();
        assert_eq!(mode(&new), 0o600);
        assert!(create_new(&new).is_err(), "never overwrites");
        fs::remove_dir_all(&base).unwrap();
    }
}
