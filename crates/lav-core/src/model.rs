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
        };
        Self {
            schema: Self::SCHEMA,
            name,
            root: root.id,
            groups: vec![root],
            entries: Vec::new(),
            created: t,
            modified: t,
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
        self.groups.retain(|g| !doomed.contains(&g.id));
        self.entries.retain(|e| !doomed.contains(&e.group));
        self.touch();
        Ok(())
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

        // 4. Entries must live in an existing group.
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
        if e.history.len() > MAX_HISTORY {
            let excess = e.history.len() - MAX_HISTORY;
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
        self.touch();
        Ok(())
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
