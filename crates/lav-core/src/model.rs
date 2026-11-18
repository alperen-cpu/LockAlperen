//! In-memory vault content. This whole structure is serialized to CBOR and
//! encrypted as the `.lav` payload. Secret-bearing types wipe themselves on drop.

use std::time::{SystemTime, UNIX_EPOCH};

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::secret::{SecretBytes, SecretString};

/// Unix time in seconds.
pub type Timestamp = i64;

/// Maximum number of previous versions kept per entry.
pub const MAX_HISTORY: usize = 20;

fn fresh_id(taken: &HashSet<Uuid>) -> Uuid {
    loop {
        let id = Uuid::new_v4();
        if !taken.contains(&id) {
            return id;
        }
    }
}

pub fn now() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    /// Schema version of the payload, independent of the header version.
    pub schema: u32,
    pub name: String,
    #[zeroize(skip)]
    pub root: Uuid,
    pub groups: Vec<Group>,
    pub entries: Vec<Entry>,
    pub created: Timestamp,
    pub modified: Timestamp,
    /// The recycle bin folder (KeePass "Recycle Bin"), created on the first
    /// delete. Optional field added later: older files read as None, and
    /// older app versions ignore it (the bin is then an ordinary folder).
    #[serde(default)]
    #[zeroize(skip)]
    pub recycle_bin: Option<Uuid>,
    /// Free text about the vault (KeePass "Database description").
    #[serde(default)]
    pub description: String,
    /// Versions kept per entry; None = [`MAX_HISTORY`]. Clamped to
    /// 0..=[`HISTORY_LIMIT_MAX`] when used.
    #[serde(default)]
    pub history_limit: Option<u32>,
    /// Ids of entries and folders deleted for good, so that merging with
    /// another copy does not bring them back (KeePass "DeletedObjects").
    #[serde(default)]
    #[zeroize(skip)]
    pub deleted: Vec<Tombstone>,
}

/// Upper bound for [`VaultData::history_limit`].
pub const HISTORY_LIMIT_MAX: u32 = 100;
/// At most this many tombstones are kept (oldest dropped first).
pub const MAX_TOMBSTONES: usize = 5000;

/// An entry or folder that was deleted for good, and when.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    pub id: Uuid,
    pub at: Timestamp,
}

/// Per-entry auto-type settings (KeePass "Auto-Type" tab).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AutoTypeConfig {
    /// Key sequence such as `{USERNAME}{TAB}{PASSWORD}{ENTER}`; empty = the
    /// default sequence.
    #[serde(default)]
    pub sequence: String,
    /// Window title pattern (`*` = any text); empty = the entry's title or
    /// site, as before.
    #[serde(default)]
    pub window: String,
    /// False = this entry never auto-types.
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

/// What merging another copy of a vault changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub groups_added: usize,
}

/// Name of the recycle bin folder when it is created.
pub const RECYCLE_BIN_NAME: &str = "Geri Dönüşüm Kutusu";
/// Folder icon of the recycle bin (an app icon name).
pub const RECYCLE_BIN_ICON: &str = "trash";

/// What a delete did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// Moved into the recycle bin; can be restored.
    Recycled,
    /// Gone for good (it was already in the bin).
    Deleted,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Group {
    #[zeroize(skip)]
    pub id: Uuid,
    #[zeroize(skip)]
    pub parent: Option<Uuid>,
    pub name: String,
    pub icon: Option<String>,
    pub created: Timestamp,
    pub modified: Timestamp,
    /// When the folder was last moved (merge uses it to decide the parent).
    #[serde(default)]
    pub moved: Timestamp,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    #[zeroize(skip)]
    pub id: Uuid,
    #[zeroize(skip)]
    pub group: Uuid,
    pub title: String,
    pub username: String,
    pub password: SecretString,
    pub url: String,
    /// Notes often hold recovery codes, so they are treated as secret.
    pub notes: SecretString,
    /// `otpauth://` URI or bare base32 secret.
    pub totp: Option<SecretString>,
    pub tags: Vec<String>,
    pub fields: Vec<CustomField>,
    pub attachments: Vec<Attachment>,
    pub favorite: bool,
    pub expires: Option<Timestamp>,
    /// Sanitized site icon (re-encoded PNG), cached so it is fetched only once.
    #[serde(default)]
    pub icon: Option<EntryIcon>,
    pub created: Timestamp,
    pub modified: Timestamp,
    pub history: Vec<EntryVersion>,
    /// Auto-type sequence and window rule; None = defaults.
    #[serde(default)]
    pub autotype: Option<AutoTypeConfig>,
    /// Text and background colour in the list, `#rrggbb` (KeePass entry
    /// colours). Checked by the app before it is stored.
    #[serde(default)]
    pub fg_color: Option<String>,
    #[serde(default)]
    pub bg_color: Option<String>,
    /// When the entry was last moved to another folder (merge uses it).
    #[serde(default)]
    pub moved: Timestamp,
}

/// A site favicon. Only ever stores a PNG that *we* re-encoded, never the raw
/// downloaded bytes, so the UI never renders untrusted image data.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntryIcon {
    #[serde(with = "serde_bytes")]
    pub png: Vec<u8>,
    pub fetched: Timestamp,
}

impl std::fmt::Debug for EntryIcon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EntryIcon({} bytes)", self.png.len())
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    pub name: String,
    pub value: SecretString,
    /// Hidden in the UI by default (like a password).
    pub protected: bool,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Attachment {
    pub name: String,
    pub data: SecretBytes,
}

/// A snapshot of an entry before it was edited.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntryVersion {
    pub title: String,
    pub username: String,
    pub password: SecretString,
    pub url: String,
    pub notes: SecretString,
    pub totp: Option<SecretString>,
    pub fields: Vec<CustomField>,
    pub modified: Timestamp,
}

// ----- Debug: never print secrets OR account metadata (titles, usernames,
// URLs, names) into logs / panic messages. Only structure is shown. -----

impl std::fmt::Debug for VaultData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultData")
            .field("schema", &self.schema)
            .field("groups", &self.groups.len())
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("id", &self.id)
            .field("parent", &self.parent)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("group", &self.group)
            .field("fields", &self.fields.len())
            .field("attachments", &self.attachments.len())
            .field("history", &self.history.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for CustomField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustomField(***)")
    }
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Attachment({} bytes)", self.data.len())
    }
}

impl std::fmt::Debug for EntryVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntryVersion(***)")
    }
}

impl Entry {
    pub fn new(group: Uuid, title: impl Into<String>) -> Self {
        let t = now();
        Self {
            id: Uuid::new_v4(),
            group,
            title: title.into(),
            username: String::new(),
            password: SecretString::default(),
            url: String::new(),
            notes: SecretString::default(),
            totp: None,
            tags: Vec::new(),
            fields: Vec::new(),
            attachments: Vec::new(),
            favorite: false,
            expires: None,
            icon: None,
            created: t,
            modified: t,
            history: Vec::new(),
            autotype: None,
            fg_color: None,
            bg_color: None,
            moved: 0,
        }
    }

    fn snapshot(&self) -> EntryVersion {
        EntryVersion {
            title: self.title.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            url: self.url.clone(),
            notes: self.notes.clone(),
            totp: self.totp.clone(),
            fields: self.fields.clone(),
            modified: self.modified,
        }
    }

    fn matches(&self, needle_lower: &str) -> bool {
        let hit = |s: &str| lower_wiped(s).contains(needle_lower);
        hit(&self.title)
            || hit(&self.username)
            || hit(&self.url)
            || hit(self.notes.expose())
            || self.tags.iter().any(|t| hit(t))
    }
}

/// Both sides' versions, oldest first, without duplicates (same save time
/// and same password), cut to `limit`.
fn combine_history(mut versions: Vec<EntryVersion>, limit: usize) -> Vec<EntryVersion> {
    versions.sort_by_key(|v| v.modified);
    let mut out: Vec<EntryVersion> = Vec::with_capacity(versions.len());
    for v in versions {
        let dup = out.iter().any(|o| {
            o.modified == v.modified
                && o.title == v.title
                && o.password.expose() == v.password.expose()
        });
        if !dup {
            out.push(v);
        }
    }
    if out.len() > limit {
        let excess = out.len() - limit;
        out.drain(..excess);
    }
    out
}

/// Lowercases into a pre-sized, self-wiping buffer. `str::to_lowercase` grows
/// its buffer when text expands (Turkish dotted I: 2 -> 3 bytes) and frees the
/// old copies unwiped; that leaked note fragments during search (LA-15).
fn lower_wiped(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len() * 3));
    for c in s.chars() {
        out.extend(c.to_lowercase());
    }
    out
}

impl VaultData {
    pub const SCHEMA: u32 = 1;

    pub fn new(name: impl Into<String>) -> Self {
        let t = now();
        let name = name.into();
        let root = Group {
            id: Uuid::new_v4(),
            parent: None,
            name: name.clone(),
            icon: None,
            created: t,
            modified: t,
            moved: 0,
        };
        Self {
            schema: Self::SCHEMA,
            name,
            root: root.id,
            groups: vec![root],
            entries: Vec::new(),
            created: t,
            modified: t,
            recycle_bin: None,
            description: String::new(),
            history_limit: None,
            deleted: Vec::new(),
        }
    }

    /// Versions kept per entry.
    pub fn history_limit(&self) -> usize {
        self.history_limit
            .map(|n| n.min(HISTORY_LIMIT_MAX) as usize)
            .unwrap_or(MAX_HISTORY)
    }

    /// Cuts every entry's history to [`Self::history_limit`] and, if
    /// `older_than` is set, drops versions saved before it. Returns the
    /// number of versions removed.
    pub fn trim_history(&mut self, older_than: Option<Timestamp>) -> usize {
        let limit = self.history_limit();
        let mut removed = 0;
        for e in &mut self.entries {
            let before = e.history.len();
            if let Some(t) = older_than {
                e.history.retain(|v| v.modified >= t);
            }
            if e.history.len() > limit {
                let excess = e.history.len() - limit;
                e.history.drain(..excess);
            }
            removed += before - e.history.len();
        }
        if removed > 0 {
            self.touch();
        }
        removed
    }

    fn bury(&mut self, ids: impl IntoIterator<Item = Uuid>) {
        let t = now();
        for id in ids {
            match self.deleted.iter_mut().find(|d| d.id == id) {
                Some(d) => d.at = d.at.max(t),
                None => self.deleted.push(Tombstone { id, at: t }),
            }
        }
        if self.deleted.len() > MAX_TOMBSTONES {
            self.deleted.sort_by_key(|d| d.at);
            let excess = self.deleted.len() - MAX_TOMBSTONES;
            self.deleted.drain(..excess);
        }
    }

    fn touch(&mut self) {
        self.modified = now();
    }

    // ----- groups -----

    pub fn group(&self, id: Uuid) -> Option<&Group> {
        self.groups.iter().find(|g| g.id == id)
    }

    pub fn children(&self, parent: Uuid) -> impl Iterator<Item = &Group> {
        self.groups.iter().filter(move |g| g.parent == Some(parent))
    }

    pub fn add_group(&mut self, parent: Uuid, name: impl Into<String>) -> Result<Uuid> {
        if self.group(parent).is_none() {
            return Err(Error::NotFound);
        }
        let t = now();
        let id = Uuid::new_v4();
        self.groups.push(Group {
            id,
            parent: Some(parent),
            name: name.into(),
            icon: None,
            created: t,
            modified: t,
            moved: 0,
        });
        self.touch();
        Ok(id)
    }

    pub fn rename_group(&mut self, id: Uuid, name: impl Into<String>) -> Result<()> {
        let g = self
            .groups
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or(Error::NotFound)?;
        g.name = name.into();
        g.modified = now();
        self.touch();
        Ok(())
    }

    /// Sets or clears a group's icon (an icon name chosen in the app; the
    /// field has been in the format from the start).
    pub fn set_group_icon(&mut self, id: Uuid, icon: Option<String>) -> Result<()> {
        let g = self
            .groups
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or(Error::NotFound)?;
        if g.icon != icon {
            g.icon = icon;
            g.modified = now();
            self.touch();
        }
        Ok(())
    }

    /// Moves a group, with its subgroups and entries, under `new_parent`.
    ///
    /// Refused: the root, a missing group or parent, and a parent that is the
    /// group itself or below it (that would form a cycle and detach the
    /// subtree from the root). The ancestor walk is bounded, so it also ends
    /// on corrupted (cyclic) data; anything that is not a clean path to the
    /// root is refused.
    pub fn move_group(&mut self, id: Uuid, new_parent: Uuid) -> Result<()> {
        if id == self.root {
            return Err(Error::CannotMoveRoot);
        }
        if self.group(id).is_none() || self.group(new_parent).is_none() {
            return Err(Error::NotFound);
        }
        let mut cur = new_parent;
        let mut steps = 0;
        while cur != self.root {
            if cur == id || steps > self.groups.len() {
                return Err(Error::InvalidMove);
            }
            steps += 1;
            cur = match self.group(cur).and_then(|g| g.parent) {
                Some(p) => p,
                None => return Err(Error::InvalidMove),
            };
        }
        let g = self
            .groups
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or(Error::NotFound)?;
        if g.parent != Some(new_parent) {
            g.parent = Some(new_parent);
            g.modified = now();
            g.moved = g.modified;
            self.touch();
        }
        Ok(())
    }

    /// Moves an entry to another group. Not an edit of its content: no
    /// history version is added and `modified` is kept.
    pub fn move_entry(&mut self, id: Uuid, group: Uuid) -> Result<()> {
        if self.group(group).is_none() {
            return Err(Error::NotFound);
        }
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::NotFound)?;
        if e.group != group {
            e.group = group;
            e.moved = now();
            self.touch();
        }
        Ok(())
    }

    /// Deletes a group together with all of its subgroups and entries.
    ///
    /// Linear time; terminates on corrupted (cyclic) data and NEVER deletes
    /// the root, even if broken data links a root-id group below `id` (LA-09).
    pub fn delete_group(&mut self, id: Uuid) -> Result<()> {
        if id == self.root {
            return Err(Error::CannotDeleteRoot);
        }
        if self.group(id).is_none() {
            return Err(Error::NotFound);
        }
        let mut children: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for g in &self.groups {
            if let Some(p) = g.parent {
                children.entry(p).or_default().push(g.id);
            }
        }
        let mut doomed: HashSet<Uuid> = HashSet::new();
        let mut stack = vec![id];
        while let Some(cur) = stack.pop() {
            if cur == self.root || !doomed.insert(cur) {
                continue;
            }
            if let Some(kids) = children.get(&cur) {
                stack.extend(kids.iter().copied());
            }
        }
        let gone_entries: Vec<Uuid> = self
            .entries
            .iter()
            .filter(|e| doomed.contains(&e.group))
            .map(|e| e.id)
            .collect();
        self.groups.retain(|g| !doomed.contains(&g.id));
        self.entries.retain(|e| !doomed.contains(&e.group));
        self.bury(doomed.iter().copied().chain(gone_entries));
        if self.recycle_bin.is_some_and(|b| doomed.contains(&b)) {
            self.recycle_bin = None;
        }
        self.touch();
        Ok(())
    }

    // ----- recycle bin -----

    /// True if `group` is the recycle bin or a folder inside it. Bounded
    /// walk, so it also ends on corrupted (cyclic) data.
    pub fn in_recycle_bin(&self, group: Uuid) -> bool {
        let Some(bin) = self.recycle_bin else {
            return false;
        };
        let mut cur = Some(group);
        let mut steps = 0;
        while let Some(g) = cur {
            if g == bin {
                return true;
            }
            if steps > self.groups.len() {
                return false;
            }
            steps += 1;
            cur = self.group(g).and_then(|g| g.parent);
        }
        false
    }

    /// The recycle bin, created under the root if it does not exist yet.
    pub fn ensure_recycle_bin(&mut self) -> Uuid {
        if let Some(b) = self.recycle_bin.filter(|b| self.group(*b).is_some()) {
            return b;
        }
        let root = self.root;
        let id = self
            .add_group(root, RECYCLE_BIN_NAME)
            .expect("the root group always exists");
        if let Some(g) = self.groups.iter_mut().find(|g| g.id == id) {
            g.icon = Some(RECYCLE_BIN_ICON.into());
        }
        self.recycle_bin = Some(id);
        id
    }

    /// KeePass-style delete: an entry outside the bin moves into it; an
    /// entry already in the bin is deleted for good. Moving is not an edit
    /// (no history version, `modified` kept).
    pub fn remove_entry(&mut self, id: Uuid) -> Result<Removal> {
        let group = self.entry(id).ok_or(Error::NotFound)?.group;
        if self.in_recycle_bin(group) {
            self.delete_entry(id)?;
            return Ok(Removal::Deleted);
        }
        let bin = self.ensure_recycle_bin();
        self.move_entry(id, bin)?;
        Ok(Removal::Recycled)
    }

    /// KeePass-style folder delete: a folder outside the bin moves into it
    /// with everything below it; the bin itself or a folder inside it is
    /// deleted for good. The root is never removed.
    pub fn remove_group(&mut self, id: Uuid) -> Result<Removal> {
        if id == self.root {
            return Err(Error::CannotDeleteRoot);
        }
        if self.group(id).is_none() {
            return Err(Error::NotFound);
        }
        if self.in_recycle_bin(id) {
            self.delete_group(id)?;
            return Ok(Removal::Deleted);
        }
        let bin = self.ensure_recycle_bin();
        self.move_group(id, bin)?;
        Ok(Removal::Recycled)
    }

    /// Deletes everything inside the recycle bin for good; the bin folder
    /// itself stays. Returns the number of entries deleted.
    pub fn empty_recycle_bin(&mut self) -> usize {
        let Some(bin) = self.recycle_bin.filter(|b| self.group(*b).is_some()) else {
            return 0;
        };
        let before = self.entries.len();
        let kids: Vec<Uuid> = self.children(bin).map(|g| g.id).collect();
        for k in kids {
            let _ = self.delete_group(k);
        }
        let gone: Vec<Uuid> = self.entries_in(bin).map(|e| e.id).collect();
        self.entries.retain(|e| e.group != bin);
        self.bury(gone);
        self.touch();
        before - self.entries.len()
    }

    /// Restores structural invariants on data read from disk WITHOUT deleting
    /// anything (linear time):
    /// * duplicate group / entry ids get fresh ids (the genuine root keeps its id),
    /// * a missing root is recreated and the root never has a parent,
    /// * groups not reachable from the root (dangling parent, cycle) are
    ///   re-attached under the root, keeping their own subtrees,
    /// * entries pointing at a missing group move to the root.
    ///
    /// Returns the number of repairs made (0 on already-valid data).
    pub fn repair_structure(&mut self) -> usize {
        let mut fixes = 0;
        let root = self.root;

        // 1. Unique ids. Prefer a parentless root-id group as the real root.
        let keeper = self
            .groups
            .iter()
            .position(|g| g.id == root && g.parent.is_none())
            .or_else(|| self.groups.iter().position(|g| g.id == root));
        let mut seen: HashSet<Uuid> = HashSet::new();
        seen.insert(root);
        for (i, g) in self.groups.iter_mut().enumerate() {
            if Some(i) == keeper {
                continue;
            }
            if !seen.insert(g.id) {
                g.id = fresh_id(&seen);
                seen.insert(g.id);
                fixes += 1;
            }
        }
        let mut seen_entries: HashSet<Uuid> = HashSet::new();
        for e in self.entries.iter_mut() {
            if !seen_entries.insert(e.id) {
                e.id = fresh_id(&seen_entries);
                seen_entries.insert(e.id);
                fixes += 1;
            }
        }

        // 2. Root exists and has no parent.
        match keeper {
            Some(i) => {
                if self.groups[i].parent.take().is_some() {
                    fixes += 1;
                }
            }
            None => {
                let t = now();
                self.groups.push(Group {
                    id: root,
                    parent: None,
                    name: self.name.clone(),
                    icon: None,
                    created: t,
                    modified: t,
                    moved: 0,
                });
                fixes += 1;
            }
        }

        // 3. Everything reachable from the root (one BFS per detached subtree).
        let mut children: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for g in &self.groups {
            if let Some(p) = g.parent {
                if p != g.id {
                    children.entry(p).or_default().push(g.id);
                }
            }
        }
        let mut reached: HashSet<Uuid> = HashSet::new();
        let visit = |start: Uuid, reached: &mut HashSet<Uuid>| {
            let mut stack = vec![start];
            while let Some(cur) = stack.pop() {
                if reached.insert(cur) {
                    if let Some(kids) = children.get(&cur) {
                        stack.extend(kids.iter().copied());
                    }
                }
            }
        };
        visit(root, &mut reached);
        for i in 0..self.groups.len() {
            let id = self.groups[i].id;
            if !reached.contains(&id) {
                self.groups[i].parent = Some(root);
                fixes += 1;
                visit(id, &mut reached);
            }
        }

        // 4. The recycle bin must be an existing group other than the root.
        if self
            .recycle_bin
            .is_some_and(|b| b == root || !reached.contains(&b))
        {
            self.recycle_bin = None;
            fixes += 1;
        }

        // 5. Entries must live in an existing group.
        for e in self
            .entries
            .iter_mut()
            .filter(|e| !reached.contains(&e.group))
        {
            e.group = root;
            fixes += 1;
        }
        fixes
    }

    // ----- entries -----

    pub fn entry(&self, id: Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn entries_in(&self, group: Uuid) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(move |e| e.group == group)
    }

    pub fn add_entry(&mut self, entry: Entry) -> Result<Uuid> {
        if self.group(entry.group).is_none() {
            return Err(Error::NotFound);
        }
        let id = entry.id;
        self.entries.push(entry);
        self.touch();
        Ok(id)
    }

    /// Applies `edit` to an entry, saving the previous version into its history.
    pub fn update_entry(&mut self, id: Uuid, edit: impl FnOnce(&mut Entry)) -> Result<()> {
        let limit = self.history_limit();
        let groups: Vec<Uuid> = self.groups.iter().map(|g| g.id).collect();
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::NotFound)?;
        let before = e.snapshot();
        let original_group = e.group;
        edit(e);
        if !groups.contains(&e.group) {
            e.group = original_group;
        }
        e.id = id;
        e.history.push(before);
        if e.history.len() > limit {
            let excess = e.history.len() - limit;
            e.history.drain(..excess);
        }
        e.modified = now();
        self.touch();
        Ok(())
    }

    /// Copies an entry into the same group (KeePass "Duplicate Entry"). The
    /// copy gets a fresh id, `title_suffix` appended to its title, fresh
    /// timestamps and NO history (old passwords are not copied along).
    pub fn duplicate_entry(&mut self, id: Uuid, title_suffix: &str) -> Result<Uuid> {
        let src = self.entry(id).ok_or(Error::NotFound)?;
        let taken: HashSet<Uuid> = self.entries.iter().map(|e| e.id).collect();
        let mut copy = src.clone();
        copy.id = fresh_id(&taken);
        copy.title.push_str(title_suffix);
        copy.history.clear();
        let t = now();
        copy.created = t;
        copy.modified = t;
        let new_id = copy.id;
        self.entries.push(copy);
        self.touch();
        Ok(new_id)
    }

    pub fn delete_entry(&mut self, id: Uuid) -> Result<()> {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        if self.entries.len() == before {
            return Err(Error::NotFound);
        }
        self.bury([id]);
        self.touch();
        Ok(())
    }

    /// Merges another copy of this vault into this one (KeePass
    /// "Synchronize"), matching entries and folders by id:
    /// * only on one side: added, unless the other side deleted it for good
    ///   after its last change (tombstone);
    /// * on both sides: the newer content wins, the older one goes into the
    ///   history (histories are combined); the later move decides the folder;
    /// * tombstones of both sides are combined and applied: an entry is
    ///   removed if it was not changed after it was deleted elsewhere. A
    ///   folder is removed only if it is empty by then.
    ///
    /// The other copy's root and recycle bin are treated as ours. Ends with
    /// [`Self::repair_structure`], so the result is always a valid tree.
    pub fn merge_from(&mut self, other: &VaultData) -> MergeReport {
        let mut report = MergeReport::default();
        let root = self.root;
        let other_root = other.root;
        let my_bin = self.recycle_bin.filter(|b| self.group(*b).is_some());
        let bin_map = match (other.recycle_bin, my_bin) {
            (Some(o), Some(m)) if o != m => Some((o, m)),
            _ => None,
        };
        let map = move |id: Uuid| -> Uuid {
            if id == other_root {
                root
            } else {
                match bin_map {
                    Some((o, m)) if o == id => m,
                    _ => id,
                }
            }
        };

        let mut tomb: HashMap<Uuid, Timestamp> = HashMap::new();
        for d in self.deleted.iter().chain(other.deleted.iter()) {
            let at = tomb.entry(d.id).or_insert(d.at);
            *at = (*at).max(d.at);
        }
        let buried = |tomb: &HashMap<Uuid, Timestamp>, id: Uuid, t: Timestamp| {
            tomb.get(&id).is_some_and(|&at| at >= t)
        };

        // Folders.
        for og in &other.groups {
            let id = map(og.id);
            if id == root {
                continue;
            }
            let parent = og.parent.map(map).unwrap_or(root);
            match self.groups.iter_mut().find(|g| g.id == id) {
                Some(g) => {
                    if og.modified > g.modified {
                        g.name = og.name.clone();
                        g.icon = og.icon.clone();
                        g.modified = og.modified;
                    }
                    if og.moved > g.moved {
                        g.parent = Some(parent);
                        g.moved = og.moved;
                    }
                }
                None => {
                    if buried(&tomb, id, og.modified.max(og.moved)) {
                        continue;
                    }
                    let mut g = og.clone();
                    g.id = id;
                    g.parent = Some(parent);
                    self.groups.push(g);
                    report.groups_added += 1;
                }
            }
        }
        if my_bin.is_none() {
            if let Some(b) = other.recycle_bin.filter(|b| self.group(*b).is_some()) {
                self.recycle_bin = Some(b);
            }
        }

        // Entries.
        let limit = self.history_limit();
        for oe in &other.entries {
            let group = map(oe.group);
            match self.entries.iter_mut().find(|e| e.id == oe.id) {
                Some(e) => {
                    let mut changed = false;
                    let mut versions: Vec<EntryVersion> = Vec::new();
                    versions.extend(e.history.iter().cloned());
                    versions.extend(oe.history.iter().cloned());
                    if oe.modified > e.modified {
                        versions.push(e.snapshot());
                        let (keep_group, keep_moved) = (e.group, e.moved);
                        *e = oe.clone();
                        e.group = keep_group;
                        e.moved = keep_moved;
                        changed = true;
                    } else if oe.modified < e.modified {
                        versions.push(oe.snapshot());
                    }
                    e.history = combine_history(versions, limit);
                    if oe.moved > e.moved {
                        e.group = group;
                        e.moved = oe.moved;
                        changed = true;
                    }
                    if changed {
                        report.updated += 1;
                    }
                }
                None => {
                    if buried(&tomb, oe.id, oe.modified.max(oe.moved)) {
                        continue;
                    }
                    let mut e = oe.clone();
                    e.group = group;
                    self.entries.push(e);
                    report.added += 1;
                }
            }
        }

        // Deletions from either side.
        let before = self.entries.len();
        self.entries
            .retain(|e| !buried(&tomb, e.id, e.modified.max(e.moved)));
        report.removed = before - self.entries.len();
        let bin = self.recycle_bin;
        loop {
            let doomed: Option<usize> = self.groups.iter().position(|g| {
                g.id != root
                    && Some(g.id) != bin
                    && buried(&tomb, g.id, g.modified.max(g.moved))
                    && !self.entries.iter().any(|e| e.group == g.id)
                    && !self.groups.iter().any(|c| c.parent == Some(g.id))
            });
            match doomed {
                Some(i) => {
                    self.groups.remove(i);
                }
                None => break,
            }
        }

        self.deleted = tomb
            .into_iter()
            .map(|(id, at)| Tombstone { id, at })
            .collect();
        self.deleted.sort_by_key(|d| d.at);
        if self.deleted.len() > MAX_TOMBSTONES {
            let excess = self.deleted.len() - MAX_TOMBSTONES;
            self.deleted.drain(..excess);
        }
        self.repair_structure();
        self.touch();
        report
    }

    /// Case-insensitive search over title, username, URL, notes and tags.
    /// Passwords are deliberately never searched.
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let needle = lower_wiped(query.trim());
        if needle.is_empty() {
            return self.entries.iter().collect();
        }
        self.entries
            .iter()
            .filter(|e| e.matches(needle.as_str()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_and_cascading_delete() {
        let mut v = VaultData::new("Test");
        let root = v.root;
        let a = v.add_group(root, "A").unwrap();
        let b = v.add_group(a, "B").unwrap();
        v.add_entry(Entry::new(b, "deep")).unwrap();
        v.add_entry(Entry::new(root, "top")).unwrap();

        v.delete_group(a).unwrap();
        assert!(v.group(a).is_none() && v.group(b).is_none());
        assert_eq!(v.entries.len(), 1);
        assert!(matches!(v.delete_group(root), Err(Error::CannotDeleteRoot)));
    }

    #[test]
    fn move_group_keeps_the_tree_connected() {
        let mut v = VaultData::new("Test");
        let root = v.root;
        let a = v.add_group(root, "A").unwrap();
        let b = v.add_group(a, "B").unwrap();
        let c = v.add_group(b, "C").unwrap();
        let x = v.add_group(root, "X").unwrap();
        v.add_entry(Entry::new(c, "deep")).unwrap();

        // Into itself or anywhere below itself: refused, nothing changes.
        for target in [a, b, c] {
            assert!(matches!(v.move_group(a, target), Err(Error::InvalidMove)));
        }
        assert!(matches!(v.move_group(b, c), Err(Error::InvalidMove)));
        assert!(matches!(v.move_group(root, x), Err(Error::CannotMoveRoot)));
        assert!(matches!(
            v.move_group(a, Uuid::new_v4()),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            v.move_group(Uuid::new_v4(), x),
            Err(Error::NotFound)
        ));
        assert_eq!(v.group(a).unwrap().parent, Some(root));

        // A real move takes the whole subtree along.
        v.move_group(a, x).unwrap();
        assert_eq!(v.group(a).unwrap().parent, Some(x));
        assert_eq!(v.group(c).unwrap().parent, Some(b));
        // Back to the top level.
        v.move_group(a, root).unwrap();
        assert_eq!(v.group(a).unwrap().parent, Some(root));
        assert_eq!(v.repair_structure(), 0, "still a valid tree");
    }

    #[test]
    fn move_group_terminates_on_cyclic_data() {
        let mut v = VaultData::new("Test");
        let root = v.root;
        let a = v.add_group(root, "A").unwrap();
        let p = v.add_group(root, "P").unwrap();
        let q = v.add_group(root, "Q").unwrap();
        // Corrupted: P and Q are each other's parent (detached from root).
        v.groups.iter_mut().find(|g| g.id == p).unwrap().parent = Some(q);
        v.groups.iter_mut().find(|g| g.id == q).unwrap().parent = Some(p);
        assert!(matches!(v.move_group(a, p), Err(Error::InvalidMove)));
        assert_eq!(v.group(a).unwrap().parent, Some(root));
    }

    #[test]
    fn group_icon_is_set_and_cleared() {
        let mut v = VaultData::new("Test");
        let g = v.add_group(v.root, "G").unwrap();
        v.set_group_icon(g, Some("briefcase".into())).unwrap();
        assert_eq!(v.group(g).unwrap().icon.as_deref(), Some("briefcase"));
        v.set_group_icon(g, None).unwrap();
        assert_eq!(v.group(g).unwrap().icon, None);
        assert!(matches!(
            v.set_group_icon(Uuid::new_v4(), None),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn move_entry_is_not_an_edit() {
        let mut v = VaultData::new("Test");
        let g = v.add_group(v.root, "G").unwrap();
        let id = v.add_entry(Entry::new(v.root, "x")).unwrap();
        let before = v.entry(id).unwrap().modified;
        v.move_entry(id, g).unwrap();
        let e = v.entry(id).unwrap();
        assert_eq!(e.group, g);
        assert!(e.history.is_empty(), "no history version for a move");
        assert_eq!(e.modified, before);
        assert!(matches!(
            v.move_entry(id, Uuid::new_v4()),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            v.move_entry(Uuid::new_v4(), g),
            Err(Error::NotFound)
        ));
        assert_eq!(v.entry(id).unwrap().group, g);
    }

    #[test]
    fn update_keeps_bounded_history() {
        let mut v = VaultData::new("Test");
        let id = v.add_entry(Entry::new(v.root, "mail")).unwrap();
        for i in 0..(MAX_HISTORY + 5) {
            v.update_entry(id, |e| e.password = format!("pw{i}").into())
                .unwrap();
        }
        let e = v.entry(id).unwrap();
        assert_eq!(e.history.len(), MAX_HISTORY);
        assert_eq!(e.password.expose(), format!("pw{}", MAX_HISTORY + 4));
        assert_eq!(
            e.history.last().unwrap().password.expose(),
            format!("pw{}", MAX_HISTORY + 3)
        );
    }

    #[test]
    fn duplicate_copies_content_but_not_history() {
        let mut v = VaultData::new("Test");
        let g = v.add_group(v.root, "G").unwrap();
        let mut e = Entry::new(g, "mail");
        e.password = "pw".into();
        e.tags = vec!["iş".into()];
        e.expires = Some(1_900_000_000);
        e.fields.push(CustomField {
            name: "PIN".into(),
            value: "1234".into(),
            protected: true,
        });
        let id = v.add_entry(e).unwrap();
        v.update_entry(id, |e| e.password = "pw2".into()).unwrap();

        let copy = v.duplicate_entry(id, " - Kopya").unwrap();
        assert_ne!(copy, id);
        let (a, b) = (v.entry(id).unwrap(), v.entry(copy).unwrap());
        assert_eq!(b.title, "mail - Kopya");
        assert_eq!(b.group, g);
        assert_eq!(b.password.expose(), "pw2");
        assert_eq!(b.tags, a.tags);
        assert_eq!(b.expires, Some(1_900_000_000));
        assert_eq!(b.fields[0].value.expose(), "1234");
        assert!(b.history.is_empty(), "old passwords are not copied");
        assert_eq!(a.history.len(), 1, "original untouched");
        assert_eq!(v.entries.len(), 2);
        assert_eq!(v.repair_structure(), 0);
        assert!(matches!(
            v.duplicate_entry(Uuid::new_v4(), ""),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn recycle_bin_moves_then_deletes() {
        let mut v = VaultData::new("Test");
        let root = v.root;
        let a = v.add_group(root, "A").unwrap();
        let sub = v.add_group(a, "Sub").unwrap();
        let e1 = v.add_entry(Entry::new(root, "one")).unwrap();
        let e2 = v.add_entry(Entry::new(sub, "two")).unwrap();
        assert!(v.recycle_bin.is_none(), "created lazily");

        // First delete: into the bin, no history, created on demand.
        let before = v.entry(e1).unwrap().modified;
        assert_eq!(v.remove_entry(e1).unwrap(), Removal::Recycled);
        let bin = v.recycle_bin.unwrap();
        assert_eq!(v.group(bin).unwrap().name, RECYCLE_BIN_NAME);
        assert_eq!(v.group(bin).unwrap().parent, Some(root));
        assert_eq!(v.entry(e1).unwrap().group, bin);
        assert!(v.entry(e1).unwrap().history.is_empty());
        assert_eq!(v.entry(e1).unwrap().modified, before);

        // A folder goes in with its subtree; still one bin.
        assert_eq!(v.remove_group(a).unwrap(), Removal::Recycled);
        assert_eq!(v.group(a).unwrap().parent, Some(bin));
        assert!(v.in_recycle_bin(sub));
        assert_eq!(v.entry(e2).unwrap().group, sub);
        assert_eq!(
            v.groups.iter().filter(|g| g.parent == Some(root)).count(),
            1
        );

        // Deleting from inside the bin is permanent.
        assert_eq!(v.remove_entry(e1).unwrap(), Removal::Deleted);
        assert!(v.entry(e1).is_none());
        assert_eq!(v.remove_group(sub).unwrap(), Removal::Deleted);
        assert!(v.entry(e2).is_none() && v.group(sub).is_none());

        // Emptying keeps the bin; deleting the bin itself forgets it.
        let e3 = v.add_entry(Entry::new(root, "three")).unwrap();
        v.remove_entry(e3).unwrap();
        assert_eq!(v.empty_recycle_bin(), 1);
        assert!(v.group(bin).is_some() && v.group(a).is_none());
        assert_eq!(v.remove_group(bin).unwrap(), Removal::Deleted);
        assert!(v.recycle_bin.is_none());
        assert!(matches!(v.remove_group(root), Err(Error::CannotDeleteRoot)));
        assert_eq!(v.repair_structure(), 0);
    }

    /// A payload written before `recycle_bin` existed still decodes (None),
    /// and a new payload keeps the bin.
    #[test]
    fn recycle_bin_field_is_optional_in_cbor() {
        let mut v = VaultData::new("Test");
        let e = v.add_entry(Entry::new(v.root, "x")).unwrap();
        v.remove_entry(e).unwrap();
        let bin = v.recycle_bin;
        let mut buf = Vec::new();
        ciborium::into_writer(&v, &mut buf).unwrap();
        let back: VaultData = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.recycle_bin, bin);

        let mut value: ciborium::Value = ciborium::from_reader(buf.as_slice()).unwrap();
        if let ciborium::Value::Map(m) = &mut value {
            m.retain(|(k, _)| k.as_text() != Some("recycle_bin"));
        }
        let mut old = Vec::new();
        ciborium::into_writer(&value, &mut old).unwrap();
        let back: VaultData = ciborium::from_reader(old.as_slice()).unwrap();
        assert!(back.recycle_bin.is_none());
        assert_eq!(back.entries.len(), 1);
    }

    /// A file written before 0.7 (no description, history limit, tombstones,
    /// auto-type, colours or move times) still opens, with defaults.
    #[test]
    fn new_optional_fields_are_optional_in_cbor() {
        let mut v = VaultData::new("Test");
        let id = v.add_entry(Entry::new(v.root, "x")).unwrap();
        v.update_entry(id, |e| {
            e.autotype = Some(AutoTypeConfig {
                sequence: "{PASSWORD}{ENTER}".into(),
                window: "*Bank*".into(),
                enabled: true,
            });
            e.fg_color = Some("#aa0000".into());
        })
        .unwrap();
        v.description = "notlar".into();
        v.history_limit = Some(5);
        let mut buf = Vec::new();
        ciborium::into_writer(&v, &mut buf).unwrap();
        let back: VaultData = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.description, "notlar");
        assert_eq!(back.history_limit, Some(5));
        let e = back.entry(id).unwrap();
        assert_eq!(e.autotype.as_ref().unwrap().window, "*Bank*");
        assert_eq!(e.fg_color.as_deref(), Some("#aa0000"));

        let mut value: ciborium::Value = ciborium::from_reader(buf.as_slice()).unwrap();
        let strip = |m: &mut Vec<(ciborium::Value, ciborium::Value)>, keys: &[&str]| {
            m.retain(|(k, _)| !keys.contains(&k.as_text().unwrap_or("")));
        };
        if let ciborium::Value::Map(m) = &mut value {
            strip(m, &["description", "history_limit", "deleted"]);
            for (k, val) in m.iter_mut() {
                if let (Some("entries" | "groups"), ciborium::Value::Array(items)) =
                    (k.as_text(), val)
                {
                    for item in items {
                        if let ciborium::Value::Map(f) = item {
                            strip(f, &["autotype", "fg_color", "bg_color", "moved"]);
                        }
                    }
                }
            }
        }
        let mut old = Vec::new();
        ciborium::into_writer(&value, &mut old).unwrap();
        let back: VaultData = ciborium::from_reader(old.as_slice()).unwrap();
        assert_eq!(back.description, "");
        assert_eq!(back.history_limit(), MAX_HISTORY);
        assert!(back.deleted.is_empty());
        let e = back.entry(id).unwrap();
        assert!(e.autotype.is_none() && e.fg_color.is_none() && e.moved == 0);
    }

    #[test]
    fn history_limit_and_trim() {
        let mut v = VaultData::new("Test");
        let id = v.add_entry(Entry::new(v.root, "x")).unwrap();
        v.history_limit = Some(3);
        for i in 0..6 {
            v.update_entry(id, |e| e.password = format!("p{i}").as_str().into())
                .unwrap();
        }
        assert_eq!(v.entry(id).unwrap().history.len(), 3);
        v.history_limit = Some(1);
        assert_eq!(v.trim_history(None), 2);
        assert_eq!(v.entry(id).unwrap().history.len(), 1);
        assert_eq!(v.trim_history(Some(i64::MAX)), 1, "older than: all");
        assert!(v.entry(id).unwrap().history.is_empty());
        v.history_limit = Some(10_000);
        assert_eq!(v.history_limit(), HISTORY_LIMIT_MAX as usize);
    }

    #[test]
    fn permanent_deletes_leave_tombstones() {
        let mut v = VaultData::new("Test");
        let g = v.add_group(v.root, "g").unwrap();
        let a = v.add_entry(Entry::new(g, "a")).unwrap();
        let b = v.add_entry(Entry::new(v.root, "b")).unwrap();
        v.remove_entry(b).unwrap(); // to the bin: no tombstone yet
        assert!(v.deleted.is_empty());
        v.empty_recycle_bin();
        v.delete_group(g).unwrap();
        let ids: HashSet<Uuid> = v.deleted.iter().map(|d| d.id).collect();
        assert!(ids.contains(&a) && ids.contains(&b) && ids.contains(&g));
    }

    /// Two copies of one vault edited apart, then merged both ways.
    #[test]
    fn merge_takes_the_newer_side_and_keeps_deletions() {
        let mut base = VaultData::new("Test");
        let g = base.add_group(base.root, "İş").unwrap();
        let shared = base.add_entry(Entry::new(g, "shared")).unwrap();
        let gone = base.add_entry(Entry::new(g, "gone")).unwrap();
        let moved = base.add_entry(Entry::new(g, "moved")).unwrap();

        let mut mine = base.clone();
        let mut theirs = base.clone();
        // Theirs: newer password, a new entry, a permanent delete, a move.
        theirs
            .update_entry(shared, |e| e.password = "new".into())
            .unwrap();
        theirs
            .entries
            .iter_mut()
            .find(|e| e.id == shared)
            .unwrap()
            .modified += 10;
        let fresh = theirs.add_entry(Entry::new(g, "fresh")).unwrap();
        theirs.delete_entry(gone).unwrap();
        let other_group = theirs.add_group(theirs.root, "Özel").unwrap();
        theirs.move_entry(moved, other_group).unwrap();
        theirs
            .entries
            .iter_mut()
            .find(|e| e.id == moved)
            .unwrap()
            .moved += 10;
        // Mine: a local entry only I have.
        let local = mine.add_entry(Entry::new(mine.root, "local")).unwrap();

        let r = mine.merge_from(&theirs);
        assert_eq!((r.added, r.removed, r.groups_added), (1, 1, 1));
        let e = mine.entry(shared).unwrap();
        assert_eq!(e.password.expose(), "new");
        assert!(
            e.history.iter().any(|v| v.password.expose().is_empty()),
            "my older version is kept in the history"
        );
        assert!(mine.entry(fresh).is_some());
        assert!(mine.entry(gone).is_none(), "deleted on the other side");
        assert!(mine.entry(local).is_some(), "my own entry stays");
        assert_eq!(mine.entry(moved).unwrap().group, other_group);
        assert!(mine.deleted.iter().any(|d| d.id == gone));

        // Merging again changes nothing; merging back gives the same entries.
        let again = mine.merge_from(&theirs);
        assert_eq!((again.added, again.updated, again.removed), (0, 0, 0));
        theirs.merge_from(&mine);
        let ids = |v: &VaultData| {
            let mut x: Vec<Uuid> = v.entries.iter().map(|e| e.id).collect();
            x.sort();
            x
        };
        assert_eq!(ids(&theirs), ids(&mine));
        assert_eq!(theirs.repair_structure(), 0);
        assert_eq!(mine.repair_structure(), 0);
    }

    /// An entry edited after it was deleted elsewhere survives the merge.
    #[test]
    fn merge_keeps_an_entry_edited_after_the_delete() {
        let mut base = VaultData::new("Test");
        let id = base.add_entry(Entry::new(base.root, "x")).unwrap();
        let mut mine = base.clone();
        let mut theirs = base.clone();
        theirs.delete_entry(id).unwrap();
        theirs.deleted[0].at = 100;
        mine.entries[0].modified = 200;
        mine.merge_from(&theirs);
        assert!(mine.entry(id).is_some());
    }

    /// Two separate vaults (different roots and bins) merge into one tree.
    #[test]
    fn merge_of_unrelated_vaults_maps_root_and_bin() {
        let mut a = VaultData::new("A");
        let mut b = VaultData::new("B");
        let ea = a.add_entry(Entry::new(a.root, "a")).unwrap();
        a.remove_entry(ea).unwrap();
        let eb = b.add_entry(Entry::new(b.root, "b")).unwrap();
        b.remove_entry(eb).unwrap();
        let bin = a.recycle_bin.unwrap();
        a.merge_from(&b);
        assert_eq!(a.entry(eb).unwrap().group, bin, "their bin is our bin");
        assert_eq!(a.groups.iter().filter(|g| g.parent.is_none()).count(), 1);
        assert_eq!(a.repair_structure(), 0);
    }

    #[test]
    fn repair_drops_a_bad_recycle_bin() {
        let mut v = VaultData::new("Test");
        v.recycle_bin = Some(Uuid::new_v4());
        assert_eq!(v.repair_structure(), 1);
        assert!(v.recycle_bin.is_none());
        v.recycle_bin = Some(v.root);
        assert_eq!(v.repair_structure(), 1);
        assert!(v.recycle_bin.is_none());
        assert!(!v.in_recycle_bin(v.root));
    }

    #[test]
    fn update_cannot_move_entry_into_missing_group() {
        let mut v = VaultData::new("Test");
        let id = v.add_entry(Entry::new(v.root, "x")).unwrap();
        v.update_entry(id, |e| e.group = Uuid::new_v4()).unwrap();
        assert_eq!(v.entry(id).unwrap().group, v.root);
    }

    #[test]
    fn search_ignores_case_and_passwords() {
        let mut v = VaultData::new("Test");
        let mut e = Entry::new(v.root, "GitHub");
        e.username = "alperen".into();
        e.password = "findme".into();
        e.notes = "Recovery".into();
        e.tags = vec!["Work".into()];
        v.add_entry(e).unwrap();

        assert_eq!(v.search("github").len(), 1);
        assert_eq!(v.search("work").len(), 1);
        assert_eq!(v.search("findme").len(), 0);
        assert_eq!(v.search("recovery").len(), 1);
        assert!(!format!("{:?}", v).contains("findme"));
        assert_eq!(v.search("  ").len(), 1);
    }
}
