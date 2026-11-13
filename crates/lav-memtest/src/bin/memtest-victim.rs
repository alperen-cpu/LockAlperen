//! Victim process for the memory-forensics test.
//!
//! Runs a realistic vault session (generate master password, create vault, add
//! secrets incl. a >4 KiB note, seal, unlock, edit, re-seal, lock), drops
//! everything, then waits so the test can scan this process' memory.
//!
//! Secrets are reported to the test only in XOR-masked hex form, so the
//! plaintext never passes through stdout buffers itself.

use std::io::{BufRead, Write};

use lav_core::{generate_password, Entry, KdfParams, PasswordOptions, SecretString, Vault};
use zeroize::Zeroizing;

const MASK: u8 = 0x5A;
const HEX: &[u8; 16] = b"0123456789abcdef";

fn emit(label: &str, secret: &str) {
    let mut line = String::with_capacity(label.len() + 2 + secret.len() * 2);
    line.push_str(label);
    line.push('=');
    for b in secret.bytes() {
        let m = b ^ MASK;
        line.push(HEX[(m >> 4) as usize] as char);
        line.push(HEX[(m & 15) as usize] as char);
    }
    println!("{line}");
}

fn alnum(len: usize) -> Zeroizing<String> {
    let opts = PasswordOptions {
        length: len,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: false,
        exclude_ambiguous: false,
    };
    generate_password(&opts).expect("generator")
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_default();
    let master = alnum(28);
    let entry_pw = alnum(24);
    let new_entry_pw = alnum(24);
    let note_marker = alnum(32);
    emit("MASTER", &master);
    emit("ENTRY_PW", &entry_pw);
    emit("NEW_ENTRY_PW", &new_entry_pw);
    emit("NOTE", &note_marker);
    let freed = alnum(30);
    emit("FREED_CANARY", &freed);

    // Control: a secret we deliberately leak, proving the scanner can see heap data.
    let canary = alnum(30);
    emit("CANARY", &canary);
    std::mem::forget(String::from(canary.as_str()));
    drop(canary);

    if scenario == "unlock-last" {
        // Worst case for decode-path leaks: unlock is the LAST thing before the dump.
        let sealed = {
            let mut vault = Vault::create("mem", &master, None, KdfParams::default()).unwrap();
            let mut e = Entry::new(vault.data.root, "target");
            e.password = SecretString::from(entry_pw.as_str());
            let mut note = String::with_capacity(note_marker.len() * 300);
            for _ in 0..300 {
                note.push_str(&note_marker); // marker everywhere, incl. past 4 KiB
            }
            e.notes = SecretString::from(note);
            vault.data.add_entry(e).unwrap();
            vault.seal().unwrap()
        };
        let vault = Vault::unlock(&sealed, &master, None).unwrap();
        drop(vault);
    } else {
        let mut vault = Vault::create("mem", &master, None, KdfParams::default()).unwrap();
        let mut e = Entry::new(vault.data.root, "target");
        e.password = SecretString::from(entry_pw.as_str());
        // > 4 KiB so it exercises the long-string decoding path.
        let mut note = String::with_capacity(note_marker.len() + 6000);
        note.push_str(&note_marker);
        note.extend(std::iter::repeat_n('x', 6000));
        e.notes = SecretString::from(note);
        let id = vault.data.add_entry(e).unwrap();
        let sealed = vault.seal().unwrap();
        drop(vault);

        let mut vault = Vault::unlock(&sealed, &master, None).unwrap();
        assert_eq!(
            vault.data.entry(id).unwrap().password.expose(),
            entry_pw.as_str()
        );
        let _ = vault.data.search("target");
        vault
            .data
            .update_entry(id, |e| {
                e.password = SecretString::from(new_entry_pw.as_str())
            })
            .unwrap();
        let _resealed = vault.seal().unwrap();
        drop(vault); // "lock"
    }
    drop((master, entry_pw, new_entry_pw, note_marker));

    // Control 2: a secret copy that is freed WITHOUT wiping (what a plain String
    // does). If the scanner finds this, it can detect freed-heap residue, so a
    // zero result for the real secrets means they were actually wiped.
    let mut plain = String::new();
    for c in freed.chars() {
        plain.push(c); // grows + reallocs like ordinary code would
    }
    std::hint::black_box(&plain); // stop the optimizer from eliding it
    drop(plain);
    drop(freed);

    println!("READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
}
