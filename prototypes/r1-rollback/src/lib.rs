//! PROTOTYPE for R1 (rollback / fork detection). NOT production code and not
//! used by `lav-core`. See `prototypes/r1-rollback/README.md` for the findings.
//!
//! A "vault" here is a simulated file: no encryption, only the fields the R1
//! design would put in the authenticated payload (`vault_id`, version vector)
//! plus the header salt (credential epoch) and opaque content. In the real
//! format these would be authenticated by the AEAD; here the tests simply
//! assume an attacker can only replay / reorder / copy files written by
//! honest devices (or by someone who knows a leaked old password, see
//! `forged_file_with_leaked_old_password_*`).

pub mod store;
pub mod vv;

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use store::{
    sha256, Hash, Loaded, Rd, Salt, StateStore, StoreError, StoreFault, VaultId, VaultRecord,
};
use vv::{DeviceId, Relation, VersionVector};

// ------------------------------------------------------------ sim vault

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimVault {
    pub vault_id: VaultId,
    /// Header salt: changes only when the password changes.
    pub salt: Salt,
    pub vv: VersionVector,
    pub content: Vec<u8>,
}

impl SimVault {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"SIMV".to_vec();
        out.extend(self.vault_id);
        out.extend(self.salt);
        store::put_vv(&mut out, &self.vv);
        out.extend((self.content.len() as u32).to_le_bytes());
        out.extend(&self.content);
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Rd(b);
        if &r.take::<4>()? != b"SIMV" {
            return None;
        }
        let vault_id = r.take()?;
        let salt = r.take()?;
        let vv = r.vv()?;
        let n = r.u32()? as usize;
        if r.0.len() != n {
            return None;
        }
        Some(Self {
            vault_id,
            salt,
            vv,
            content: r.0.to_vec(),
        })
    }
}

// --------------------------------------------------------------- verdicts

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No record for this vault on this device (TOFU). Accepted, shown to user.
    FirstUse,
    /// Linear progress (or the exact file we last saw).
    Ok,
    /// The file is our own save whose state update was interrupted (crash
    /// between "vault written" and "state committed"). Accepted.
    OwnInterruptedSave,
    /// Older than what this device has seen.
    Rollback,
    /// Histories diverged (concurrent offline edits, sync conflict, attack).
    Fork,
    /// Same version vector, different bytes: honest devices never do this.
    ForkSameVersion,
    /// The file has a save attributed to THIS device that this device never
    /// made: cloned device id (copied profile / disk image) or rolled-back
    /// local state.
    DeviceIdReused,
    /// Unknown, newer credential epoch (password changed elsewhere, or a file
    /// forged by someone holding a leaked old key). Needs confirmation.
    CredentialChanged,
    /// File uses a password this device knows was retired. Checked BEFORE
    /// unlocking (no KDF needed).
    RetiredCredential,
}

impl Verdict {
    pub fn accepted_silently(self) -> bool {
        matches!(
            self,
            Verdict::FirstUse | Verdict::Ok | Verdict::OwnInterruptedSave
        )
    }
}

/// How trustworthy the local reference was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateNote {
    Normal,
    /// No state existed: everything is first use.
    Fresh,
    /// Newest state slot was unreadable; the previous one was used.
    Degraded,
}

#[derive(Debug)]
pub enum ProtoError {
    Io(io::Error),
    Store(StoreError),
    NotAVault,
    /// Local state exists but is corrupt: refuse until the user resets it.
    StateUntrusted,
    /// Simulated process crash.
    Crashed,
    /// Save attempted on a vault this device never opened.
    NotOpened,
}

impl From<io::Error> for ProtoError {
    fn from(e: io::Error) -> Self {
        ProtoError::Io(e)
    }
}

impl From<StoreError> for ProtoError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Crashed => ProtoError::Crashed,
            StoreError::Untrusted => ProtoError::StateUntrusted,
            e => ProtoError::Store(e),
        }
    }
}

type Result<T> = std::result::Result<T, ProtoError>;

/// Pure decision function. `state` is the device's local view.
pub fn evaluate(
    device_id: &DeviceId,
    retired: &std::collections::BTreeSet<Salt>,
    rec: Option<&VaultRecord>,
    file: &SimVault,
    hash: &Hash,
) -> Verdict {
    if retired.contains(&file.salt) {
        return Verdict::RetiredCredential;
    }
    let Some(rec) = rec else {
        return Verdict::FirstUse;
    };
    let f_me = file.vv.get(device_id);
    let f_tag = file.vv.tag(device_id);
    let own_interrupted = match rec.pending {
        Some((c, t)) if f_me == c => {
            if f_tag != Some(t) {
                return Verdict::DeviceIdReused;
            }
            true
        }
        _ => false,
    };
    if !own_interrupted {
        // A save attributed to us that we never committed: higher counter, or
        // our latest counter with someone else's tag.
        if f_me > rec.own_last || (f_me == rec.own_last && f_me > 0 && f_tag != Some(rec.own_tag)) {
            return Verdict::DeviceIdReused;
        }
    }
    // Even our own interrupted save goes through the comparison: the local
    // reference may have moved on since the intent was recorded.
    let v = match file.vv.relation_to(&rec.last_vv) {
        Relation::Behind => Verdict::Rollback,
        Relation::Concurrent => Verdict::Fork,
        Relation::Equal if *hash != rec.last_hash => Verdict::ForkSameVersion,
        Relation::Equal | Relation::Ahead if own_interrupted => Verdict::OwnInterruptedSave,
        Relation::Equal | Relation::Ahead => Verdict::Ok,
    };
    if v == Verdict::Ok && file.salt != rec.current_salt {
        return Verdict::CredentialChanged;
    }
    v
}

// ----------------------------------------------------------------- device

/// Simulated crash points during a save.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveFault {
    /// Intent recorded, vault not written.
    AfterIntent,
    /// Vault written, state not yet committed.
    AfterVaultWrite,
    /// Crash inside the final state write.
    DuringCommit(StoreFault),
}

pub struct Device {
    store: StateStore,
    fresh_id: DeviceId,
}

pub struct Opened {
    pub file: SimVault,
    pub hash: Hash,
    pub verdict: Verdict,
    pub state: StateNote,
}

impl Device {
    /// `fresh_id` is used only if the state directory is empty: a device whose
    /// state was lost always gets a NEW id, so it can never reuse counters.
    pub fn new(state_dir: &Path, fresh_id: DeviceId) -> io::Result<Self> {
        Ok(Self {
            store: StateStore::new(state_dir)?,
            fresh_id,
        })
    }

    pub fn store(&self) -> &StateStore {
        &self.store
    }

    /// The id this device would use now.
    pub fn id(&self) -> Result<DeviceId> {
        Ok(match self.store.load()? {
            Loaded::Ok(s) | Loaded::Degraded(s) => s.device_id,
            Loaded::Fresh => self.fresh_id,
            Loaded::Untrusted => return Err(ProtoError::StateUntrusted),
        })
    }

    /// Runs before any KDF work: only the header salt is needed.
    pub fn check_before_unlock(&self, header_salt: &Salt) -> Result<Option<Verdict>> {
        Ok(match self.store.load()? {
            Loaded::Ok(s) | Loaded::Degraded(s) => s
                .retired_salts
                .contains(header_salt)
                .then_some(Verdict::RetiredCredential),
            Loaded::Fresh => None,
            Loaded::Untrusted => return Err(ProtoError::StateUntrusted),
        })
    }

    /// Opens a file. Silently-acceptable verdicts update the local state;
    /// anything else leaves it untouched (UI would open read-only).
    pub fn open(&self, path: &Path) -> Result<Opened> {
        let bytes = fs::read(path)?;
        let file = SimVault::decode(&bytes).ok_or(ProtoError::NotAVault)?;
        let hash = sha256(&bytes);
        let fresh = self.fresh_id;
        let (verdict, note) = {
            let note = match self.store.load()? {
                Loaded::Fresh => StateNote::Fresh,
                Loaded::Ok(_) => StateNote::Normal,
                Loaded::Degraded(_) => StateNote::Degraded,
                Loaded::Untrusted => return Err(ProtoError::StateUntrusted),
            };
            let v = self.store.update(fresh, None, |s| {
                let v = evaluate(
                    &s.device_id,
                    &s.retired_salts,
                    s.vaults.get(&file.vault_id),
                    &file,
                    &hash,
                );
                if v.accepted_silently() {
                    let me = s.device_id;
                    if let Some(r) = record(me, s.vaults.get_mut(&file.vault_id), &file, &hash) {
                        s.vaults.insert(file.vault_id, r);
                    }
                    // Only reachable for our own interrupted password change.
                    let rec = s.vaults.get_mut(&file.vault_id).expect("just recorded");
                    if rec.current_salt != file.salt {
                        s.retired_salts.insert(rec.current_salt);
                        rec.current_salt = file.salt;
                    }
                }
                v
            })?;
            (v, note)
        };
        Ok(Opened {
            file,
            hash,
            verdict,
            state: note,
        })
    }

    /// The user reviewed a non-silent verdict and explicitly accepts this
    /// file as the new reference (after a merge / confirmed password change).
    pub fn confirm(&self, opened: &Opened) -> Result<()> {
        let f = &opened.file;
        self.store.update(self.fresh_id, None, |s| {
            let me = s.device_id;
            let entry = s.vaults.entry(f.vault_id).or_insert_with(|| VaultRecord {
                last_vv: VersionVector::default(),
                last_hash: [0; 32],
                own_last: 0,
                own_tag: 0,
                pending: None,
                current_salt: f.salt,
            });
            entry.last_vv = entry.last_vv.merged(&f.vv);
            entry.last_hash = opened.hash;
            // A confirmed file never lowers what we know about our own saves.
            if f.vv.get(&me) > entry.own_last {
                entry.own_last = f.vv.get(&me);
                entry.own_tag = f.vv.tag(&me).unwrap_or(0);
            }
            if entry.current_salt != f.salt {
                s.retired_salts.insert(entry.current_salt);
                entry.current_salt = f.salt;
            }
        })?;
        Ok(())
    }

    /// Saves `content` on top of `base` (the file the user had open).
    /// Protocol: (1) record intent (counter, hash) in local state,
    /// (2) write the vault atomically, (3) commit local state.
    pub fn save(
        &self,
        path: &Path,
        base: &SimVault,
        content: &[u8],
        new_salt: Option<Salt>,
        fault: Option<SaveFault>,
    ) -> Result<SimVault> {
        let fresh = self.fresh_id;
        // (1) intent
        let prepared = self.store.update(fresh, None, |s| {
            let me = s.device_id;
            let rec = s.vaults.get_mut(&base.vault_id)?;
            let counter = rec
                .own_last
                .max(rec.pending.map_or(0, |p| p.0))
                .max(base.vv.get(&me))
                + 1;
            let tag = random_tag();
            let mut vv = rec.last_vv.merged(&base.vv);
            vv.set_tagged(me, counter, tag);
            let file = SimVault {
                vault_id: base.vault_id,
                salt: new_salt.unwrap_or(base.salt),
                vv,
                content: content.to_vec(),
            };
            let bytes = file.encode();
            rec.pending = Some((counter, tag));
            Some((file, bytes, counter, tag))
        })?;
        let (file, bytes, counter, tag) = prepared.ok_or(ProtoError::NotOpened)?;
        if fault == Some(SaveFault::AfterIntent) {
            return Err(ProtoError::Crashed);
        }
        // (2) vault
        write_atomic(path, &bytes)?;
        if fault == Some(SaveFault::AfterVaultWrite) {
            return Err(ProtoError::Crashed);
        }
        // (3) commit
        let store_fault = match fault {
            Some(SaveFault::DuringCommit(f)) => Some(f),
            _ => None,
        };
        let hash = sha256(&bytes);
        self.store.update(fresh, store_fault, |s| {
            let rec = s.vaults.get_mut(&file.vault_id).expect("recorded in (1)");
            if counter > rec.own_last {
                rec.own_last = counter;
                rec.own_tag = tag;
            }
            if rec.pending.is_some_and(|p| p.0 == counter) {
                rec.pending = None;
            }
            rec.last_vv = rec.last_vv.merged(&file.vv);
            rec.last_hash = hash;
            if rec.current_salt != file.salt {
                s.retired_salts.insert(rec.current_salt);
                rec.current_salt = file.salt;
            }
        })?;
        Ok(file)
    }

    /// Creates a new vault file (first save on this device).
    pub fn create(&self, path: &Path, vault_id: VaultId, salt: Salt) -> Result<SimVault> {
        let me = self.id()?;
        let tag = random_tag();
        let mut vv = VersionVector::default();
        vv.set_tagged(me, 1, tag);
        let file = SimVault {
            vault_id,
            salt,
            vv,
            content: b"new".to_vec(),
        };
        let bytes = file.encode();
        write_atomic(path, &bytes)?;
        let hash = sha256(&bytes);
        self.store.update(self.fresh_id, None, |s| {
            s.vaults.insert(
                vault_id,
                VaultRecord {
                    last_vv: file.vv.clone(),
                    last_hash: hash,
                    own_last: 1,
                    own_tag: tag,
                    pending: None,
                    current_salt: salt,
                },
            );
        })?;
        Ok(file)
    }
}

/// Builds the record after a silently-accepted open.
fn record(
    me: DeviceId,
    existing: Option<&mut VaultRecord>,
    file: &SimVault,
    hash: &Hash,
) -> Option<VaultRecord> {
    let f_me = file.vv.get(&me);
    let f_tag = file.vv.tag(&me).unwrap_or(0);
    match existing {
        Some(rec) => {
            rec.last_vv = rec.last_vv.merged(&file.vv);
            rec.last_hash = *hash;
            if let Some((c, t)) = rec.pending.take() {
                // Our interrupted save landed (f_me == c) or never did
                // (f_me < c). Either way counter c is never reused.
                if c > rec.own_last {
                    rec.own_last = c;
                    rec.own_tag = t;
                }
            }
            if f_me > rec.own_last {
                rec.own_last = f_me;
                rec.own_tag = f_tag;
            }
            None
        }
        None => Some(VaultRecord {
            last_vv: file.vv.clone(),
            last_hash: *hash,
            own_last: f_me,
            own_tag: f_tag,
            pending: None,
            current_salt: file.salt,
        }),
    }
}

/// Random 64-bit save tag (std only; a real implementation would use OsRng).
fn random_tag() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(N.fetch_add(1, Ordering::Relaxed));
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    h.finish()
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}
