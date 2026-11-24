//! Process hardening on Linux (SECURITY.md, "Faz 2'de zorunlu
//! sıkılaştırmalar"; the Windows twin is src/hardening.rs).
//!
//! - Not dumpable (`PR_SET_DUMPABLE` = 0): other processes of the same user
//!   can no longer attach with ptrace or read `/proc/<pid>/mem`, and the
//!   kernel writes no core dump. Ubuntu's Yama setting (ptrace_scope 1)
//!   already limits ptrace to parent processes; this closes the rest.
//! - Core dump size limit 0, for systems where a dump would still be made.
//!
//! - WebKitGTK's helper processes (the page, the network) are started with
//!   exec, which makes a process dumpable again. `nodump/nodump.c`, preloaded
//!   into them through LD_PRELOAD, turns it off again from inside
//!   ([`preload_nodump`]).
//!
//! Limits (documented): root bypasses both; the window cannot be kept out
//! of screenshots or screen sharing (neither X11 nor Wayland has a flag for
//! it).
#![allow(unsafe_code)]

/// Makes the process non-dumpable and turns off core dumps. True if both
/// were accepted.
pub fn protect_process() -> bool {
    // SAFETY: prctl with integer arguments only.
    let dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid rlimit that outlives the call.
    let no_core = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } == 0;
    dumpable && no_core
}

/// File name of the library built from nodump/nodump.c.
const NODUMP: &str = "liblav_nodump.so";

/// Where the bundle puts the library: the resource folder next to the
/// program (.deb: /usr/lib/LockAlperen, root-owned; AppImage: inside the
/// read-only image). Development builds also look next to the program
/// (target/debug), where `tauri dev` copies resources.
fn nodump_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let mut candidates = vec![dir.join("../lib/LockAlperen").join(NODUMP)];
    if cfg!(debug_assertions) {
        candidates.push(dir.join(NODUMP));
    }
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .and_then(|p| p.canonicalize().ok())
}

/// The LD_PRELOAD value: what was there, minus any earlier copy of ours (an
/// AppImage restarted after an update had another path), plus `ours`.
pub fn preload_value(existing: &str, ours: &str) -> String {
    let mut parts: Vec<&str> = existing
        .split([':', ' '])
        .filter(|p| !p.is_empty() && !p.ends_with(NODUMP))
        .collect();
    parts.push(ours);
    parts.join(":")
}

/// Puts the library into LD_PRELOAD, for the WebKit processes started
/// later. Call first in `run`, while only one thread exists. False: the
/// library was not found (then those processes stay dumpable).
pub fn preload_nodump() -> bool {
    let Some(path) = nodump_path() else {
        return false;
    };
    let Some(path) = path.to_str() else {
        return false; // LD_PRELOAD cannot carry such a path
    };
    if path.contains([':', ' ']) {
        return false;
    }
    let original = std::env::var_os("LD_PRELOAD");
    let existing = original
        .as_deref()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_owned();
    let _ = ORIGINAL_PRELOAD.set(original);
    std::env::set_var("LD_PRELOAD", preload_value(&existing, path));
    true
}

static ORIGINAL_PRELOAD: std::sync::OnceLock<Option<std::ffi::OsString>> =
    std::sync::OnceLock::new();

/// Gives a program we start (the browser) the user's own LD_PRELOAD, without
/// our library.
pub fn restore_preload(cmd: &mut std::process::Command) {
    match ORIGINAL_PRELOAD.get() {
        None => {} // never changed
        Some(Some(v)) => {
            cmd.env("LD_PRELOAD", v);
        }
        Some(None) => {
            cmd.env_remove("LD_PRELOAD");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn preload_keeps_others_and_replaces_ours() {
        let ours = "/usr/lib/LockAlperen/liblav_nodump.so";
        assert_eq!(preload_value("", ours), ours);
        assert_eq!(
            preload_value(
                "/a/x.so /tmp/.mount_old/usr/lib/LockAlperen/liblav_nodump.so",
                ours
            ),
            format!("/a/x.so:{ours}")
        );
    }

    use super::*;

    /// Changes the TEST process (harmless) and reads the result back.
    #[test]
    fn process_is_not_dumpable_and_dumps_no_core() {
        assert!(protect_process());
        // SAFETY: integer arguments only.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
        let mut got = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: valid out-pointer.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut got) }, 0);
        assert_eq!((got.rlim_cur, got.rlim_max), (0, 0));
    }
}
