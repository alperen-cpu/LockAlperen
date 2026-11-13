//! Attack simulation for the CVE-2023-32784 class: after the vault is locked,
//! an attacker reads the process memory (as a same-user process, a crash dump,
//! the pagefile or a hibernation file would expose it) and searches for the
//! master password and entry secrets.
//!
//! The victim leaks a CANARY on purpose; finding it proves the scanner works,
//! so "0 hits" for the real secrets is a meaningful result.
#![cfg(windows)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

const MASK: u8 = 0x5A;

fn unmask(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap() ^ MASK)
        .collect()
}

fn utf16(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| [*b, 0]).collect()
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    let first = needle[0];
    let mut n = 0;
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if hay[i] == first && &hay[i..i + needle.len()] == needle {
            n += 1;
        }
        i += 1;
    }
    n
}

/// Minimum fragment length searched. Random alphanumerics: 62^12 ≈ 3e21, so a
/// 12-char fragment match is not a coincidence. Fragments matter because the
/// Windows heap overwrites the first bytes of a freed block with metadata.
const FRAGMENT: usize = 12;

fn fragments(secret: &[u8]) -> Vec<Vec<u8>> {
    if secret.len() <= FRAGMENT {
        return vec![secret.to_vec()];
    }
    secret.windows(FRAGMENT).map(|w| w.to_vec()).collect()
}

/// Returns, per secret, how many of its fragments occur in memory (UTF-8 or UTF-16LE).
fn scan_process(pid: u32, needles: &[(String, Vec<u8>)]) -> Vec<(String, usize)> {
    let mut hits: Vec<(String, usize)> = needles.iter().map(|(n, _)| (n.clone(), 0)).collect();
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        assert!(!h.is_null(), "OpenProcess failed");
        let mut addr: usize = 0;
        let mut scanned: usize = 0;
        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let r = VirtualQueryEx(
                h,
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if r == 0 {
                break;
            }
            let base = mbi.BaseAddress as usize;
            let size = mbi.RegionSize;
            if mbi.State == MEM_COMMIT && mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS) == 0 {
                let mut buf = vec![0u8; size];
                let mut read = 0usize;
                ReadProcessMemory(
                    h,
                    base as *const _,
                    buf.as_mut_ptr() as *mut _,
                    size,
                    &mut read,
                );
                if read > 0 {
                    scanned += read;
                    for (i, (_, secret)) in needles.iter().enumerate() {
                        for frag in fragments(secret) {
                            hits[i].1 +=
                                count(&buf[..read], &frag) + count(&buf[..read], &utf16(&frag));
                        }
                    }
                }
            }
            match base.checked_add(size) {
                Some(next) if next > addr => addr = next,
                _ => break,
            }
        }
        CloseHandle(h);
        eprintln!(
            "scanned {} MiB of committed memory",
            scanned / (1024 * 1024)
        );
    }
    hits
}

#[test]
fn secrets_do_not_survive_in_process_memory_after_lock() {
    run_scenario("full");
}

/// Unlock (decrypt + CBOR decode of a >4 KiB note) is the last operation
/// before the memory dump: the worst case for decode-path leaks.
#[test]
fn secrets_do_not_survive_after_unlock_then_lock() {
    run_scenario("unlock-last");
}

fn run_scenario(scenario: &str) {
    eprintln!("--- scenario: {scenario}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_memtest-victim"))
        .arg(scenario)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn victim");
    let stdout = BufReader::new(child.stdout.take().unwrap());

    let mut needles: Vec<(String, Vec<u8>)> = Vec::new();
    for line in stdout.lines() {
        let line = line.unwrap();
        if line == "READY" {
            break;
        }
        let (label, hex) = line.split_once('=').unwrap();
        needles.push((label.to_owned(), unmask(hex)));
    }

    let hits = scan_process(child.id(), &needles);
    let _ = child.stdin.take().unwrap().write_all(b"\n");
    let _ = child.wait();

    for (label, n) in &hits {
        eprintln!("{label:>14}: {n} hit(s)");
    }
    let get = |l: &str| hits.iter().find(|(n, _)| n == l).unwrap().1;
    assert!(
        get("CANARY") > 0,
        "scanner sanity check failed: canary not found"
    );
    assert!(
        get("FREED_CANARY") > 0,
        "scanner cannot see freed-heap residue; a zero result would be meaningless"
    );
    let leaked: Vec<_> = hits
        .iter()
        .filter(|(l, n)| !l.ends_with("CANARY") && *n > 0)
        .collect();
    assert!(
        leaked.is_empty(),
        "secrets still in memory after lock: {leaked:?}"
    );
}
