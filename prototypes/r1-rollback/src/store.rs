//! Device-local state (`%LOCALAPPDATA%\LockAlperen\state\` in a real app) and
//! its crash-safe, atomic persistence.
//!
//! Design under evaluation:
//! - Two slots (`state.0`, `state.1`), written alternately. Each slot holds a
//!   generation number and a SHA-256 checksum. Loading picks the newest VALID
//!   slot, so a torn / lost write of the newest slot falls back to the
//!   previous state, never to anything older than that.
//! - Each slot is written as `tmp` + fsync + rename (atomic replace on NTFS).
//! - Read-modify-write runs under an exclusive OS lock (`state.lock`), so two
//!   app instances cannot lose each other's updates.
//! - The checksum only detects accidental corruption. Anyone who can write
//!   this directory can also delete it (-> first use), so a MAC would not
//!   add protection against a local attacker; that attacker is out of scope.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use sha2::{Digest, Sha256};

use crate::vv::{DeviceId, Dot, VersionVector};

pub type VaultId = [u8; 16];
pub type Hash = [u8; 32];
pub type Salt = [u8; 32];

const MAGIC: &[u8; 8] = b"LKAVST02";

/// What this device knows about one vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRecord {
    /// Last version vector this device accepted or wrote.
    pub last_vv: VersionVector,
    /// SHA-256 of that file.
    pub last_hash: Hash,
    /// Highest counter this device has COMMITTED for itself, and the random
    /// save tag it used for it.
    pub own_last: u64,
    pub own_tag: u64,
    /// Write-ahead intent: (counter, save tag) of a save that was started but
    /// not yet confirmed. Lets a crash between "vault written" and "state
    /// written" be recognised as our own save (even after other devices built
    /// on it) instead of as a cloned device id.
    pub pending: Option<(u64, u64)>,
    /// Header salt = credential epoch currently accepted for this vault.
    pub current_salt: Salt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceState {
    pub device_id: DeviceId,
    pub vaults: BTreeMap<VaultId, VaultRecord>,
    /// Salts of credentials this device changed away from (or saw replaced).
    /// Kept globally: salts are random and unique, and the vault id is only
    /// known AFTER unlocking, while this check must run BEFORE it.
    pub retired_salts: BTreeSet<Salt>,
}

impl DeviceState {
    pub fn new(device_id: DeviceId) -> Self {
        Self {
            device_id,
            vaults: BTreeMap::new(),
            retired_salts: BTreeSet::new(),
        }
    }
}

#[derive(Debug)]
pub enum Loaded {
    /// No state at all: first use on this device (TOFU). Must be shown.
    Fresh,
    Ok(DeviceState),
    /// The newest slot was unreadable; the previous state was used. Must be
    /// shown: protection is one save weaker than it could be.
    Degraded(DeviceState),
    /// State files exist but none is valid. Never treated as "fresh"
    /// silently; the user must explicitly reset.
    Untrusted,
}

/// Simulated crash points for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreFault {
    /// Temp file written, process dies before the rename.
    CrashBeforeRename,
    /// Rename "happened" but the data never reached the disk (e.g. power loss
    /// without write-through): the slot holds half the bytes.
    TornSlot,
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Crashed,
    Untrusted,
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

pub struct StateStore {
    dir: PathBuf,
}

impl StateStore {
    pub fn new(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn slot_path(&self, i: usize) -> PathBuf {
        self.dir.join(format!("state.{i}"))
    }

    /// Path of the valid slot with the highest generation (for tests).
    pub fn newest_valid_slot(&self) -> Option<PathBuf> {
        (0..2)
            .filter_map(|i| {
                let p = self.slot_path(i);
                let (g, _) = decode(&fs::read(&p).ok()?)?;
                Some((g, p))
            })
            .max_by_key(|(g, _)| *g)
            .map(|(_, p)| p)
    }

    pub fn load(&self) -> io::Result<Loaded> {
        Ok(self.load_with_gen()?.0)
    }

    fn load_with_gen(&self) -> io::Result<(Loaded, u64)> {
        let mut best: Option<(u64, DeviceState)> = None;
        let mut any_file = false;
        let mut any_bad = false;
        for i in 0..2 {
            match fs::read(self.slot_path(i)) {
                Ok(bytes) => {
                    any_file = true;
                    match decode(&bytes) {
                        Some((g, s)) => {
                            if best.as_ref().is_none_or(|(bg, _)| g > *bg) {
                                best = Some((g, s));
                            }
                        }
                        None => any_bad = true,
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(match (best, any_file, any_bad) {
            (None, false, _) => (Loaded::Fresh, 0),
            (None, true, _) => (Loaded::Untrusted, 0),
            (Some((g, s)), _, true) => (Loaded::Degraded(s), g),
            (Some((g, s)), _, false) => (Loaded::Ok(s), g),
        })
    }

    /// Atomic read-modify-write under the exclusive state lock. `f` receives
    /// the current state (a new one for a fresh store). Untrusted state is
    /// refused: call [`StateStore::reset`] after the user confirmed.
    pub fn update<R>(
        &self,
        device_id_if_fresh: DeviceId,
        fault: Option<StoreFault>,
        f: impl FnOnce(&mut DeviceState) -> R,
    ) -> Result<R, StoreError> {
        let _lock = self.lock()?;
        let (loaded, gen) = self.load_with_gen()?;
        let mut state = match loaded {
            Loaded::Fresh => DeviceState::new(device_id_if_fresh),
            Loaded::Ok(s) | Loaded::Degraded(s) => s,
            Loaded::Untrusted => return Err(StoreError::Untrusted),
        };
        let r = f(&mut state);
        self.write_slot(gen + 1, &state, fault)?;
        Ok(r)
    }

    /// Explicit, user-confirmed reset of untrusted state.
    pub fn reset(&self) -> io::Result<()> {
        let _lock = self.lock()?;
        for i in 0..2 {
            match fs::remove_file(self.slot_path(i)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn lock(&self) -> io::Result<fs::File> {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.dir.join("state.lock"))?;
        f.lock()?;
        Ok(f)
    }

    fn write_slot(
        &self,
        gen: u64,
        state: &DeviceState,
        fault: Option<StoreFault>,
    ) -> Result<(), StoreError> {
        let bytes = encode(gen, state);
        let slot = self.slot_path((gen % 2) as usize);
        if fault == Some(StoreFault::TornSlot) {
            fs::write(&slot, &bytes[..bytes.len() / 2])?;
            return Err(StoreError::Crashed);
        }
        let tmp = self.dir.join(format!("state.{}.tmp", unique()));
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        if fault == Some(StoreFault::CrashBeforeRename) {
            return Err(StoreError::Crashed);
        }
        fs::rename(&tmp, &slot)?;
        Ok(())
    }
}

fn unique() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        N.fetch_add(1, AtomicOrdering::Relaxed)
    )
}

// ------------------------------------------------------------- encoding

pub fn sha256(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}

pub(crate) fn put_vv(out: &mut Vec<u8>, vv: &VersionVector) {
    out.extend((vv.0.len() as u32).to_le_bytes());
    for (d, dot) in &vv.0 {
        out.extend(d);
        out.extend(dot.counter.to_le_bytes());
        out.extend(dot.tag.to_le_bytes());
    }
}

pub(crate) struct Rd<'a>(pub &'a [u8]);

impl Rd<'_> {
    pub fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        if self.0.len() < N {
            return None;
        }
        let (a, b) = self.0.split_at(N);
        self.0 = b;
        a.try_into().ok()
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }
    pub fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_le_bytes)
    }
    pub fn vv(&mut self) -> Option<VersionVector> {
        let n = self.u32()?;
        let mut vv = VersionVector::default();
        for _ in 0..n {
            let d = self.take::<16>()?;
            let counter = self.u64()?;
            let tag = self.u64()?;
            if counter == 0 || vv.0.insert(d, Dot { counter, tag }).is_some() {
                return None;
            }
        }
        Some(vv)
    }
}

fn encode(gen: u64, s: &DeviceState) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(MAGIC);
    out.extend(gen.to_le_bytes());
    out.extend(s.device_id);
    out.extend((s.retired_salts.len() as u32).to_le_bytes());
    for salt in &s.retired_salts {
        out.extend(salt);
    }
    out.extend((s.vaults.len() as u32).to_le_bytes());
    for (id, r) in &s.vaults {
        out.extend(id);
        put_vv(&mut out, &r.last_vv);
        out.extend(r.last_hash);
        out.extend(r.own_last.to_le_bytes());
        out.extend(r.own_tag.to_le_bytes());
        match r.pending {
            None => out.push(0),
            Some((c, t)) => {
                out.push(1);
                out.extend(c.to_le_bytes());
                out.extend(t.to_le_bytes());
            }
        }
        out.extend(r.current_salt);
    }
    let sum = sha256(&out);
    out.extend(sum);
    out
}

fn decode(bytes: &[u8]) -> Option<(u64, DeviceState)> {
    if bytes.len() < 32 {
        return None;
    }
    let (body, sum) = bytes.split_at(bytes.len() - 32);
    if sha256(body)[..] != *sum {
        return None;
    }
    let mut r = Rd(body);
    if &r.take::<8>()? != MAGIC {
        return None;
    }
    let gen = r.u64()?;
    let mut s = DeviceState::new(r.take()?);
    for _ in 0..r.u32()? {
        s.retired_salts.insert(r.take()?);
    }
    for _ in 0..r.u32()? {
        let id = r.take()?;
        let last_vv = r.vv()?;
        let last_hash = r.take()?;
        let own_last = r.u64()?;
        let own_tag = r.u64()?;
        let pending = match r.take::<1>()?[0] {
            0 => None,
            1 => Some((r.u64()?, r.u64()?)),
            _ => return None,
        };
        let current_salt = r.take()?;
        s.vaults.insert(
            id,
            VaultRecord {
                last_vv,
                last_hash,
                own_last,
                own_tag,
                pending,
                current_salt,
            },
        );
    }
    r.0.is_empty().then_some((gen, s))
}
