#![no_main]
use libfuzzer_sys::fuzz_target;

// Decrypted payload (CBOR) decoding + structural repair + model operations.
// Normally authenticated, but a buggy/older writer or the future KDBX importer
// feeds the same code: it must never panic or hang.
fuzz_target!(|data: &[u8]| {
    let mut scratch = vec![0u8; data.len().max(16)];
    if let Ok(mut v) =
        ciborium::de::from_reader_with_buffer::<lav_core::VaultData, _>(data, &mut scratch[..])
    {
        v.repair_structure();
        assert_eq!(v.repair_structure(), 0, "repair must be idempotent");
        let _ = v.search("a");
        if let Some(g) = v.groups.iter().map(|g| g.id).find(|id| *id != v.root) {
            let _ = v.delete_group(g);
        }
        if let Some(e) = v.entries.first().map(|e| e.id) {
            let _ = v.update_entry(e, |e| e.title.push('x'));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&v, &mut out).unwrap();
    }
});
