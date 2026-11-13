//! Randomised properties of the R1 prototype (dependency-free PRNG, fixed
//! seeds so failures are reproducible). Iterations: R1_PROP_STEPS (default 300).

use std::fs;
use std::path::PathBuf;

use r1_rollback_proto::store::{sha256, Loaded, StoreFault};
use r1_rollback_proto::vv::{Relation, VersionVector};
use r1_rollback_proto::{Device, SaveFault, Verdict};

const VID: [u8; 16] = [0xAA; 16];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn steps() -> usize {
    std::env::var("R1_PROP_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
}

fn root(tag: &str, seed: u64) -> PathBuf {
    let r = std::env::temp_dir().join(format!("r1prop-{tag}-{}-{seed}", std::process::id()));
    let _ = fs::remove_dir_all(&r);
    fs::create_dir_all(&r).unwrap();
    r
}

fn reference(d: &Device) -> Option<(VersionVector, [u8; 32])> {
    match d.store().load().unwrap() {
        Loaded::Ok(s) | Loaded::Degraded(s) => {
            s.vaults.get(&VID).map(|r| (r.last_vv.clone(), r.last_hash))
        }
        _ => None,
    }
}

fn random_fault(rng: &mut Rng) -> Option<SaveFault> {
    match rng.below(10) {
        0 => Some(SaveFault::AfterIntent),
        1 => Some(SaveFault::AfterVaultWrite),
        2 => Some(SaveFault::DuringCommit(StoreFault::CrashBeforeRename)),
        3 => Some(SaveFault::DuringCommit(StoreFault::TornSlot)),
        _ => None,
    }
}

/// SAFETY: under arbitrary saves, crashes, honest syncs and attacker replays
/// of ANY historical file, a device never silently accepts a file whose
/// vector is below (or incomparable to) its reference, and its reference
/// never moves backwards.
#[test]
fn never_silently_accepts_anything_below_the_reference() {
    for seed in [1u64, 7, 42, 1234, 99_999] {
        let r = root("safety", seed);
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let devs: Vec<Device> = (0..3u8)
            .map(|i| Device::new(&r.join(format!("state{i}")), [i + 1; 16]).unwrap())
            .collect();
        let copies: Vec<PathBuf> = (0..3).map(|i| r.join(format!("copy{i}.lav"))).collect();
        devs[0].create(&copies[0], VID, [1; 32]).unwrap();
        let mut history = vec![fs::read(&copies[0]).unwrap()];
        for c in &copies[1..] {
            fs::copy(&copies[0], c).unwrap();
        }

        let mut silent = 0;
        let mut alarms = 0;
        for step in 0..steps() {
            let d = rng.below(3);
            match rng.below(4) {
                // open (+ maybe save) own copy
                0 | 1 => {
                    let before = reference(&devs[d]);
                    let o = devs[d].open(&copies[d]).unwrap();
                    let after = reference(&devs[d]);
                    if let (Some((l, lh)), true) = (&before, o.verdict.accepted_silently()) {
                        let rel = o.file.vv.relation_to(l);
                        assert!(
                            rel == Relation::Ahead || (rel == Relation::Equal && o.hash == *lh),
                            "seed {seed} step {step}: accepted {:?} with {rel:?}",
                            o.verdict
                        );
                    }
                    if let (Some((l0, _)), Some((l1, _))) = (&before, &after) {
                        assert!(
                            l1.dominates(l0),
                            "seed {seed} step {step}: reference went back"
                        );
                    }
                    if o.verdict.accepted_silently() {
                        silent += 1;
                        let content = format!("d{d} s{step}");
                        let fault = random_fault(&mut rng);
                        let _ = devs[d].save(&copies[d], &o.file, content.as_bytes(), None, fault);
                        history.push(fs::read(&copies[d]).unwrap());
                    } else {
                        alarms += 1;
                        if matches!(o.verdict, Verdict::Fork | Verdict::ForkSameVersion) {
                            // user merges explicitly
                            devs[d].confirm(&o).unwrap();
                            let _ = devs[d].save(&copies[d], &o.file, b"merged", None, None);
                            history.push(fs::read(&copies[d]).unwrap());
                        }
                    }
                }
                // honest sync from another device's copy
                2 => {
                    let from = rng.below(3);
                    if from != d {
                        fs::copy(&copies[from], &copies[d]).unwrap();
                    }
                }
                // attacker replays any historical file
                _ => {
                    let h = &history[rng.below(history.len())];
                    fs::write(&copies[d], h).unwrap();
                }
            }
        }
        assert!(silent > 0 && alarms > 0, "seed {seed}: degenerate run");
        let _ = sha256(b"");
        let _ = fs::remove_dir_all(&r);
    }
}

/// LIVENESS / no false alarms: honest devices taking turns on ONE shared
/// file, with random crashes, never see an alarm.
#[test]
fn honest_sequential_use_with_crashes_never_alarms() {
    for seed in [3u64, 5, 77] {
        let r = root("honest", seed);
        let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
        let devs: Vec<Device> = (0..3u8)
            .map(|i| Device::new(&r.join(format!("state{i}")), [i + 1; 16]).unwrap())
            .collect();
        let p = r.join("vault.lav");
        devs[0].create(&p, VID, [1; 32]).unwrap();
        for step in 0..steps() {
            let d = rng.below(3);
            let o = devs[d].open(&p).unwrap();
            assert!(
                o.verdict.accepted_silently(),
                "seed {seed} step {step} dev {d}: false alarm {:?}",
                o.verdict
            );
            let fault = random_fault(&mut rng);
            let _ = devs[d].save(&p, &o.file, format!("{step}").as_bytes(), None, fault);
        }
        let _ = fs::remove_dir_all(&r);
    }
}
