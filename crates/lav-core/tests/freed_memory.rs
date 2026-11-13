//! Deterministic memory-hygiene test: a global allocator that, on every free
//! (and on every realloc, which it forces to MOVE), scans the released block
//! for secret markers. Any hit means a secret copy was released without being
//! wiped. Stronger than the process scan in lav-memtest because nothing can be
//! overwritten before we look.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use lav_core::{Entry, KdfParams, SecretString, Vault};

// Markers are lowercase+digits so they also match lowercased copies (search).
// They live in .rodata only; secrets are built from them directly into
// their final allocation.
const NOTE_MARKER: &[u8] = b"q7vx2mk9pl4wz8nb";
const PW_MARKER: &[u8] = b"r3ty6ui1op5as0df";
// Turkish capitals grow when lowercased (dotted I: 2 bytes -> 3 bytes).
const TURKISH_NOTE: &str =
    "\u{130}STANBUL-\u{130}ZM\u{130}R q7vx2mk9pl4wz8nb \u{130}\u{130}\u{130}\u{130}\u{130}\u{130}\u{130}\u{130}";

static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);

struct ScanningAlloc;

unsafe fn scan(ptr: *mut u8, len: usize) {
    if !ARMED.load(Ordering::Relaxed) || len < NOTE_MARKER.len() {
        return;
    }
    let block = std::slice::from_raw_parts(ptr, len);
    for m in [NOTE_MARKER, PW_MARKER] {
        if block.windows(m.len()).any(|w| w == m) {
            HITS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

unsafe impl GlobalAlloc for ScanningAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        scan(ptr, layout.size());
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Always move, so every growth leaves an old block behind (worst case).
        let new = System.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
        if !new.is_null() {
            std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
            scan(ptr, layout.size());
            System.dealloc(ptr, layout);
        }
        new
    }
}

#[global_allocator]
static A: ScanningAlloc = ScanningAlloc;

fn secret(head: &str, repeat_tail: usize) -> SecretString {
    let mut s = String::with_capacity(head.len() + repeat_tail);
    s.push_str(head);
    s.extend(std::iter::repeat_n('x', repeat_tail));
    SecretString::from(s)
}

#[test]
fn no_secret_is_freed_unwiped_during_a_full_session() {
    let kdf = KdfParams {
        memory_kib: KdfParams::MIN_MEMORY_KIB,
        iterations: KdfParams::MIN_ITERATIONS,
        parallelism: 1,
    };
    let pw = std::str::from_utf8(PW_MARKER).unwrap();
    ARMED.store(true, Ordering::SeqCst);
    {
        let mut v = Vault::create("m", "master password!", None, kdf).unwrap();
        let mut e = Entry::new(v.data.root, "t");
        e.password = secret(pw, 0);
        e.notes = secret(TURKISH_NOTE, 6000); // > 4 KiB
        let id = v.data.add_entry(e).unwrap();
        let _ = v.data.search("istanbul");
        let sealed = v.seal().unwrap();
        drop(v);

        let mut v = Vault::unlock(&sealed, "master password!", None).unwrap();
        let _ = v.data.search("izmir");
        v.data.update_entry(id, |e| e.title.push('!')).unwrap();
        let _ = v.seal().unwrap();
        drop(v);
    }
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(
        HITS.load(Ordering::SeqCst),
        0,
        "a block containing a secret was freed without being wiped"
    );
}
