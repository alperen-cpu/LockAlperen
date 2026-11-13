//! M5 (PR-1): Unicode normalization of the master password must not free
//! heap blocks that still contain password characters.
//!
//! `unicode-normalization` buffers a combining sequence in a TinyVec that
//! spills to the heap above 4 characters and is freed unwiped. Combining marks
//! are mostly NFC_QC=Maybe, so a quick-check shortcut alone does not avoid it.
//!
//! Detection: a freed block that holds, as aligned little-endian u32 values
//! (how `char` is stored), at least 4 distinct code points of the password's
//! combining marks. A control allocation proves the detector works.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use lav_core::crypto::CompositeKey;

const MARKS: [u32; 7] = [0x0300, 0x0301, 0x0302, 0x0303, 0x0304, 0x0306, 0x0323];

static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);

struct ScanningAlloc;

unsafe fn scan(ptr: *mut u8, len: usize) {
    if !ARMED.load(Ordering::Relaxed) || len < 16 || !(ptr as usize).is_multiple_of(4) {
        return;
    }
    let block = std::slice::from_raw_parts(ptr, len);
    let mut seen = [false; MARKS.len()];
    for w in block.as_chunks::<4>().0 {
        let v = u32::from_le_bytes(*w);
        if let Some(i) = MARKS.iter().position(|m| *m == v) {
            seen[i] = true;
        }
    }
    if seen.iter().filter(|s| **s).count() >= 4 {
        HITS.fetch_add(1, Ordering::Relaxed);
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

fn hits_during(f: impl FnOnce()) -> usize {
    HITS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    HITS.load(Ordering::SeqCst)
}

/// One test function: the allocator is global, sub-cases must not overlap.
#[test]
fn password_normalization_frees_no_unwiped_characters() {
    // Control: a plain Vec<char> with the marks, freed unwiped, MUST be seen.
    let control = hits_during(|| {
        let v: Vec<char> = MARKS.iter().map(|c| char::from_u32(*c).unwrap()).collect();
        std::hint::black_box(&v);
        drop(v);
    });
    assert!(control > 0, "detector sanity check failed");

    let cases: [(&str, String); 3] = [
        // Already NFC, but quick-check says Maybe (combining marks).
        (
            "Q + 6 marks (NFC_QC=Maybe)",
            "Q\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}\u{0306}pass".to_string(),
        ),
        // Not NFC (needs reordering + composition), long cluster.
        (
            "a + 5 marks, non-canonical order",
            "x\u{0301}a\u{0302}\u{0301}\u{0323}\u{0300}\u{0303}word".to_string(),
        ),
        // Plain ASCII: quick-check Yes.
        ("ascii", "correct horse battery staple".to_string()),
    ];
    for (what, pw) in &cases {
        let n = hits_during(|| {
            let k = CompositeKey::new(pw, None);
            std::hint::black_box(&k);
            drop(k);
        });
        assert_eq!(n, 0, "{what}: password characters freed unwiped");
    }
}
