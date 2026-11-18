//! Mutation-based random fuzzing on stable Rust (NO coverage guidance — that is
//! what the cargo-fuzz targets in /fuzz do on Linux CI). Seeds are valid
//! inputs; each iteration applies random bit flips, "interesting" byte values,
//! truncation, extension and splicing, then checks invariants.
//!
//! Iterations: LAV_FUZZ_ITERS (default 20_000 per target). Seed: LAV_FUZZ_SEED.

use lav_core::format::{Header, HEADER_LEN};
use lav_core::{Entry, Group, KdfParams, SecretBytes, Vault, VaultData};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn iters() -> usize {
    std::env::var("LAV_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

fn rng() -> Rng {
    let seed = std::env::var("LAV_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5EED_1A57_u64);
    eprintln!("fuzz seed = {seed}");
    Rng(seed | 1)
}

const INTERESTING: [u8; 8] = [0x00, 0x01, 0x7F, 0x80, 0xFF, 0xFE, 0x18, 0x1B];

fn mutate(rng: &mut Rng, seed: &[u8], other: &[u8]) -> Vec<u8> {
    let mut d = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(6) {
            0 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] ^= 1 << rng.below(8);
            }
            1 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            2 => d.truncate(rng.below(d.len() + 1)),
            3 => {
                for _ in 0..rng.below(64) {
                    d.push(rng.next() as u8);
                }
            }
            4 if !other.is_empty() && !d.is_empty() => {
                let at = rng.below(d.len());
                let from = rng.below(other.len());
                let n = rng.below(other.len() - from);
                d.splice(at..at, other[from..from + n].iter().copied());
            }
            _ if !d.is_empty() => {
                let i = rng.below(d.len());
                d.remove(i);
            }
            _ => {}
        }
    }
    d
}

fn sample_data() -> VaultData {
    let mut v = VaultData::new("fuzz");
    let g = v.add_group(v.root, "g").unwrap();
    let mut e = Entry::new(g, "title");
    e.username = "user".into();
    e.password = "pw".into();
    e.notes = "n".repeat(300).into();
    e.totp = Some("otpauth://totp/x?secret=AAAA".into());
    e.tags = vec!["t".into()];
    e.attachments.push(lav_core::Attachment {
        name: "a".into(),
        data: SecretBytes::new(vec![1, 2, 3]),
    });
    let id = v.add_entry(e).unwrap();
    v.update_entry(id, |e| e.password = "pw2".into()).unwrap();
    v
}

#[test]
fn fuzz_header_parse() {
    let vault = Vault::create(
        "f",
        "fuzz password 1",
        None,
        KdfParams {
            memory_kib: KdfParams::MIN_MEMORY_KIB,
            iterations: KdfParams::MIN_ITERATIONS,
            parallelism: 1,
        },
    )
    .unwrap();
    let seed = vault.seal().unwrap();
    let mut rng = rng();
    for _ in 0..iters() * 5 {
        let input = mutate(&mut rng, &seed[..HEADER_LEN + 32], &seed);
        if let Ok((h, raw, _)) = Header::parse(&input) {
            assert_eq!(&h.to_bytes()[..], raw);
            assert!(h.kdf.validate().is_ok());
        }
    }
}

#[test]
fn fuzz_payload_decode_repair_and_ops() {
    let mut seed = Vec::new();
    ciborium::into_writer(&sample_data(), &mut seed).unwrap();
    let mut rng = rng();
    let mut decoded = 0usize;
    for _ in 0..iters() {
        let input = mutate(&mut rng, &seed, &seed);
        let mut scratch = vec![0u8; input.len().max(16)];
        if let Ok(mut v) = ciborium::de::from_reader_with_buffer::<VaultData, _>(
            input.as_slice(),
            &mut scratch[..],
        ) {
            decoded += 1;
            v.repair_structure();
            assert_eq!(v.repair_structure(), 0, "repair must be idempotent");
            let _ = v.search("t");
            if let Some(g) = v.groups.iter().map(|g| g.id).find(|id| *id != v.root) {
                let _ = v.delete_group(g);
            }
            let mut out = Vec::new();
            ciborium::into_writer(&v, &mut out).unwrap();
        }
    }
    eprintln!("decoded {decoded} mutated payloads");
}

/// Property test: random group forests with arbitrary (cyclic, dangling)
/// parent links. After repair every group reaches the root and nothing is lost.
#[test]
fn property_repair_structure_on_random_graphs() {
    let mut rng = rng();
    for _ in 0..iters() / 4 {
        let mut v = VaultData::new("p");
        let n = rng.below(12);
        let mut ids = vec![v.root];
        for _ in 0..n {
            ids.push(uuid::Uuid::new_v4());
        }
        if rng.below(10) == 0 {
            v.groups.clear(); // even the root may be missing
        }
        for id in ids.iter().skip(1) {
            let parent = match rng.below(4) {
                0 => None,
                1 => Some(uuid::Uuid::new_v4()),      // dangling
                _ => Some(ids[rng.below(ids.len())]), // may form cycles / self-loops
            };
            v.groups.push(Group {
                id: *id,
                parent,
                name: String::new(),
                icon: None,
                created: 0,
                modified: 0,
                moved: 0,
            });
        }
        for _ in 0..rng.below(6) {
            let g = if rng.below(3) == 0 {
                uuid::Uuid::new_v4()
            } else {
                ids[rng.below(ids.len())]
            };
            v.entries.push(Entry::new(g, "e"));
        }
        let (groups_before, entries_before) = (v.groups.len(), v.entries.len());
        v.repair_structure();

        assert!(v.group(v.root).is_some());
        assert!(v.groups.len() >= groups_before);
        assert_eq!(v.entries.len(), entries_before);
        for e in &v.entries {
            assert!(v.group(e.group).is_some());
        }
        for g in &v.groups {
            let mut cur = Some(g.id);
            let mut steps = 0;
            while let Some(c) = cur {
                if c == v.root {
                    break;
                }
                cur = v.group(c).and_then(|g| g.parent);
                steps += 1;
                assert!(steps <= v.groups.len() + 1, "cycle after repair");
            }
            assert_eq!(cur, Some(v.root));
        }
        // and deleting any group terminates
        if let Some(g) = v.groups.iter().map(|g| g.id).find(|id| *id != v.root) {
            v.delete_group(g).unwrap();
        }
    }
}
