//! The derived-key allocation is locked in RAM (VirtualLock / mlock) so the
//! keys are not paged to disk. Windows gives every process a lock quota, so
//! there it must succeed; on Unix it depends on RLIMIT_MEMLOCK and is only
//! reported.

#[test]
fn derived_key_pages_are_locked_in_ram() {
    let keys = lav_core::crypto::DerivedKeys::from_master(&[7u8; 32]).unwrap();
    #[cfg(windows)]
    assert!(keys.pages_locked(), "VirtualLock refused");
    #[cfg(not(windows))]
    eprintln!("mlock accepted: {}", keys.pages_locked());
}
