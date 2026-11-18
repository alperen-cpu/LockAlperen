//! Process hardening on Linux (SECURITY.md, "Faz 2'de zorunlu
//! sıkılaştırmalar"; the Windows twin is src/hardening.rs).
//!
//! - Not dumpable (`PR_SET_DUMPABLE` = 0): other processes of the same user
//!   can no longer attach with ptrace or read `/proc/<pid>/mem`, and the
//!   kernel writes no core dump. Ubuntu's Yama setting (ptrace_scope 1)
//!   already limits ptrace to parent processes; this closes the rest.
//! - Core dump size limit 0, for systems where a dump would still be made.
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

#[cfg(test)]
mod tests {
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
