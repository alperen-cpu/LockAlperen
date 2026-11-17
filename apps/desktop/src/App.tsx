import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import * as api from "./api";
import { Editor } from "./Editor";
import { ImportDialog } from "./Import";
import { ExtrasView } from "./Extras";
import { SettingsPage } from "./Settings";
import { FOLDER_ICONS, FaIcon, folderIconDef } from "./folderIcons";
import { UpdateBanner } from "./Update";
import type { EntrySummary, SelectedFile, VaultInfo } from "./api";
import {
  CheckIcon,
  EyeIcon,
  GearIcon,
  EyeOffIcon,
  FileIcon,
  FolderIcon,
  ListIcon,
  MenuIcon,
  RowsIcon,
  CompactIcon,
  GridIcon,
  TableIcon,
  PaletteIcon,
  BackIcon,
  MoveIcon,
  LockIcon,
  PencilIcon,
  PlusIcon,
  SearchIcon,
  ShieldIcon,
  XIcon,
} from "./icons";

type Open = { info: VaultInfo; entries: EntrySummary[] };

export function App() {
  // The saved colour theme; until it arrives, styles.css follows Windows.
  useEffect(() => {
    api.getSettings().then(
      (s) => api.applyTheme(s.theme),
      () => {},
    );
  }, []);
  return (
    <>
      <Screens />
      <UpdateBanner />
    </>
  );
}

function Screens() {
  const [file, setFile] = useState<SelectedFile | null>(null);
  const [open, setOpen] = useState<Open | null>(null);
  const [error, setError] = useState<string | null>(null);
  // File name chosen for a new vault: shows the create form.
  const [newName, setNewName] = useState<string | null>(null);
  const [recents, setRecents] = useState<api.RecentVault[]>([]);

  async function refreshRecents(autoSelect: boolean) {
    try {
      const list = await api.recentVaults();
      setRecents(list);
      if (autoSelect && list.length > 0) setFile(await api.selectRecent(0));
    } catch {
      /* the list is a convenience; ignore */
    }
  }

  // On start, offer the most recently opened vault.
  useEffect(() => {
    void refreshRecents(true);
  }, []);

  // After unlocking or creating, Rust has updated the list.
  useEffect(() => {
    if (open) void refreshRecents(false);
  }, [open]);

  async function pickRecent(i: number) {
    setError(null);
    setNewName(null);
    try {
      setFile(await api.selectRecent(i));
    } catch (e) {
      setError(api.errorText(e));
    }
  }

  async function forget(i: number) {
    try {
      setRecents(await api.forgetRecent(i));
    } catch {
      /* ignore */
    }
  }

  const side = (busy: boolean) => (
    <Side
      busy={busy}
      hasFile={file !== null}
      current={file}
      recents={recents}
      onPickRecent={pickRecent}
      onForget={forget}
      onChoose={choose}
      onCreate={startCreate}
    />
  );

  async function choose() {
    setError(null);
    try {
      const picked = await api.pickVaultFile();
      if (picked !== null) {
        // Choosing a file locks any open vault on the Rust side.
        setFile(picked);
        setOpen(null);
        setNewName(null);
      }
    } catch (e) {
      setError(api.errorText(e));
    }
  }

  async function startCreate() {
    setError(null);
    try {
      const name = await api.pickNewVaultPath();
      if (name !== null) setNewName(name);
    } catch (e) {
      setError(api.errorText(e));
    }
  }

  async function doLock() {
    // Clear the UI copy first, even if the call fails.
    setOpen(null);
    try {
      await api.lock();
    } catch (e) {
      setError(api.errorText(e));
    }
  }

  function autoLocked() {
    setOpen(null);
    setError("Kasa otomatik olarak kilitlendi.");
  }

  if (open && file) {
    return (
      <VaultScreen
        file={file}
        open={open}
        onLock={doLock}
        onAutoLocked={autoLocked}
        onEntries={(entries) => setOpen((o) => (o ? { ...o, entries } : o))}
      />
    );
  }
  if (newName !== null) {
    return (
      <CreateScreen
        fileName={newName}
        side={side(false)}
        onCancel={() => setNewName(null)}
        onCreated={(f, info) => {
          setFile(f);
          setNewName(null);
          setError(null);
          setOpen({ info, entries: [] });
        }}
      />
    );
  }
  return (
    <UnlockScreen
      file={file}
      error={error}
      setError={setError}
      side={side}
      onOpened={setOpen}
    />
  );
}

/** Display hint only (link look, button enabled); Rust decides what is
 *  opened (src-tauri/src/browser.rs: http/https only). */
function looksLikeWeb(url: string) {
  const t = url.trim();
  // http(s)://…, or no scheme: site.com, localhost:8080 ("name:" + digits is
  // a port). "javascript:", "mailto:" etc. are not web addresses.
  if (t === "") return false;
  if (/^https?:\/\//i.test(t)) return true;
  return !t.includes("://") && !/^[a-z][a-z0-9+.-]*:(?!\d)/i.test(t);
}

/** "C:\\Users\\a\\Belgeler" -> "Belgeler". */
function folderName(folder: string) {
  const parts = folder.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? folder;
}

function timeAgo(unix: number) {
  const days = Math.floor((Date.now() / 1000 - unix) / 86400);
  if (days <= 0) return "bugün";
  if (days === 1) return "dün";
  if (days < 7) return `${days} gün önce`;
  if (days < 30) return `${Math.floor(days / 7)} hafta önce`;
  return `${Math.floor(days / 30)} ay önce`;
}

function Side(props: {
  busy: boolean;
  hasFile: boolean;
  current: SelectedFile | null;
  recents: api.RecentVault[];
  onPickRecent: (i: number) => void;
  onForget: (i: number) => void;
  onChoose: () => void;
  onCreate: () => void;
}) {
  const isCurrent = (r: api.RecentVault) =>
    props.current !== null &&
    r.fileName === props.current.fileName &&
    r.folder === props.current.folder;
  return (
    <section className="unlock-side" aria-label="Kasalar">
      {props.recents.length > 0 && (
        <>
          <div className="recent-lbl muted small">Son kasalar</div>
          <ul className="recents">
            {props.recents.map((r, i) => (
              <li key={`${r.folder}\\${r.fileName}`} className={isCurrent(r) ? "active" : ""}>
                <button
                  type="button"
                  className="recent"
                  onClick={() => props.onPickRecent(i)}
                  disabled={props.busy}
                  title={`${r.folder}\\${r.fileName} · ${timeAgo(r.opened)}`}
                >
                  <LockIcon size={16} />
                  <span className="recent-name ellipsis">{r.fileName}</span>
                </button>
                <button
                  type="button"
                  className="ghost-icon forget"
                  aria-label={`${r.fileName} kasasını listeden kaldır`}
                  title="Listeden kaldır (dosya silinmez)"
                  onClick={() => props.onForget(i)}
                  disabled={props.busy}
                >
                  <XIcon />
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      <div className="side-actions">
        <button type="button" className="link" onClick={props.onChoose} disabled={props.busy}>
          {props.hasFile ? "Başka bir kasa aç" : "Kasa dosyası aç"}
        </button>
        <button type="button" className="link" onClick={props.onCreate} disabled={props.busy}>
          Yeni kasa oluştur
        </button>
      </div>
    </section>
  );
}

function CreateScreen(props: {
  fileName: string;
  side: ReactNode;
  onCancel: () => void;
  onCreated: (file: SelectedFile, info: VaultInfo) => void;
}) {
  const [name, setName] = useState(props.fileName.replace(/\.lav$/i, ""));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Both passwords are uncontrolled and cleared on submit, never React state.
  const pwRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);
  const [keyName, setKeyName] = useState<string | null>(null);

  async function submit(ev: FormEvent) {
    ev.preventDefault();
    const pw = pwRef.current;
    const cf = confirmRef.current;
    if (!pw || !cf || busy) return;
    const password = pw.value;
    const confirm = cf.value;
    pw.value = "";
    cf.value = "";
    setBusy(true);
    setError(null);
    try {
      const r = await api.createVault(name, password, confirm);
      props.onCreated(r.file, r.info);
    } catch (e) {
      setError(api.errorText(e));
      pw.focus();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="unlock">
      <main className="unlock-main">
        <form className="unlock-form" onSubmit={submit}>
          <div className="center">
            <h1>Yeni kasa</h1>
            <p className="muted">{props.fileName}</p>
          </div>
          <div className="field">
            <label className="lbl" htmlFor="vname">
              Kasa adı
            </label>
            <input
              id="vname"
              className="text-input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              readOnly={busy}
              autoComplete="off"
            />
          </div>
          <div className="field">
            <label className="lbl" htmlFor="npw">
              Ana parola
            </label>
            <input
              id="npw"
              ref={pwRef}
              className="text-input"
              type="password"
              autoComplete="new-password"
              spellCheck={false}
              readOnly={busy}
              autoFocus
            />
          </div>
          <div className="field">
            <label className="lbl" htmlFor="npw2">
              Ana parola (tekrar)
            </label>
            <input
              id="npw2"
              ref={confirmRef}
              className="text-input"
              type="password"
              autoComplete="new-password"
              spellCheck={false}
              readOnly={busy}
            />
          </div>
          <button
            type="button"
            className="btn btn-left"
            disabled={busy}
            onClick={async () => {
              try {
                const n = keyName ? (await api.clearKeyfile(), null) : await api.pickKeyfile();
                setKeyName(n);
              } catch (e) {
                setError(api.errorText(e));
              }
            }}
          >
            <FileIcon />
            <span className="ellipsis">
              {keyName ? `Anahtar dosyası: ${keyName} (kaldır)` : "Anahtar dosyası ekle (isteğe bağlı)…"}
            </span>
          </button>
          {error ? (
            <p className="error" role="alert">
              {error}
            </p>
          ) : (
            <p className="muted small">
              En az 8 karakter. Uzun bir parola cümlesi önerilir. Ana parola unutulursa kasa
              açılamaz; kurtarma yolu yoktur.
            </p>
          )}
          <div className="form-buttons">
            <button type="button" className="btn wide" onClick={props.onCancel} disabled={busy}>
              Vazgeç
            </button>
            <button type="submit" className="btn btn-accent wide" disabled={busy}>
              {busy ? "Oluşturuluyor…" : "Kasayı oluştur"}
            </button>
          </div>
        </form>
      </main>
      {props.side}
    </div>
  );
}

function UnlockScreen(props: {
  file: SelectedFile | null;
  error: string | null;
  setError: (e: string | null) => void;
  side: (busy: boolean) => ReactNode;
  onOpened: (o: Open) => void;
}) {
  const { file, error, setError, side, onOpened } = props;
  const [busy, setBusy] = useState(false);
  const [show, setShow] = useState(false);
  const [caps, setCaps] = useState(false);
  // Key file chosen for this vault (name only; Rust holds the path).
  const [keyName, setKeyName] = useState<string | null>(null);
  const [useKey, setUseKey] = useState(false);

  // New file selected: Rust dropped the key file; follow the header's hint.
  useEffect(() => {
    setKeyName(null);
    setUseKey(file?.keyfileRequired ?? false);
  }, [file]);

  async function toggleKey(on: boolean) {
    setUseKey(on);
    if (!on) {
      setKeyName(null);
      await api.clearKeyfile().catch(() => undefined);
    }
  }

  async function chooseKey() {
    try {
      const name = await api.pickKeyfile();
      if (name !== null) setKeyName(name);
    } catch (e) {
      setError(api.errorText(e));
    }
  }
  // The master password is NEVER React state (CVE-2023-32784 lesson): the
  // input is uncontrolled, read once on submit and cleared at once.
  const passwordRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (file) passwordRef.current?.focus();
  }, [file]);

  async function submit(ev: FormEvent) {
    ev.preventDefault();
    const input = passwordRef.current;
    if (!input || busy) return;
    const password = input.value;
    input.value = "";
    setShow(false);
    if (password === "") return;
    setBusy(true);
    setError(null);
    try {
      const info = await api.unlock(password);
      const entries = await api.listEntries();
      onOpened({ info, entries });
    } catch (e) {
      setError(api.errorText(e));
      input.focus();
    } finally {
      setBusy(false);
    }
  }

  const capsCheck = (e: KeyboardEvent<HTMLInputElement>) =>
    setCaps(e.getModifierState("CapsLock"));

  return (
    <div className="unlock">
      <main className="unlock-main">
        <form className="unlock-form" onSubmit={submit}>
          <span className="unlock-badge">
            <LockIcon size={30} />
          </span>
          <div className="center">
            <h1>{file ? file.fileName : "Kasa seçilmedi"}</h1>
            <p className="muted ellipsis" title={file?.folder}>
              {file
                ? `${folderName(file.folder)} klasöründe`
                : "Başlamak için aşağıdan bir kasa dosyası açın"}
            </p>
          </div>

          <div className="field">
            <label className="lbl" htmlFor="pw">
              Ana parola
            </label>
            <div className="pw-box">
              <input
                id="pw"
                ref={passwordRef}
                type={show ? "text" : "password"}
                autoComplete="off"
                spellCheck={false}
                disabled={!file}
                // readOnly, not disabled, while busy: a disabled input cannot
                // take focus back after a failed attempt.
                readOnly={busy}
                onKeyDown={capsCheck}
                onKeyUp={capsCheck}
              />
              <button
                type="button"
                className="ghost-icon"
                aria-label={show ? "Parolayı gizle" : "Parolayı göster"}
                onClick={() => setShow((v) => !v)}
                disabled={!file || busy}
              >
                {show ? <EyeOffIcon /> : <EyeIcon />}
              </button>
            </div>
            {caps && <div className="warn">Caps Lock açık</div>}
          </div>

          <button type="submit" className="btn btn-accent wide" disabled={!file || busy}>
            {busy ? "Açılıyor…" : "Kilidi aç"}
          </button>

          <label className="check center-check">
            <input
              type="checkbox"
              checked={useKey}
              disabled={!file || busy}
              onChange={(e) => void toggleKey(e.target.checked)}
            />
            Anahtar dosyası kullan
          </label>
          {useKey && (
            <button type="button" className="btn btn-left" onClick={chooseKey} disabled={busy}>
              <FileIcon />
              <span className="ellipsis">{keyName ?? "Anahtar dosyası seç…"}</span>
            </button>
          )}
          {file?.keyfileRequired && !keyName && (
            <p className="warn">Bu kasa bir anahtar dosyası istiyor.</p>
          )}

          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}

        </form>
      </main>
      {side(busy)}
    </div>
  );
}

const AVATAR_COLORS = ["#8FB0FF", "#7FC8F8", "#3DD68C", "#F5B54A", "#F28FAD", "#B79CFF"];

function avatarColor(s: string) {
  let h = 0;
  for (const ch of s) h = (h * 31 + ch.codePointAt(0)!) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

function Avatar({ title, size, icon }: { title: string; size: number; icon?: string | null }) {
  const initial = Array.from(title.trim())[0]?.toLocaleUpperCase("tr") ?? "?";
  if (icon) {
    // A PNG we re-encoded ourselves (lav-favicon), never the downloaded bytes.
    return (
      <img className="avatar img" src={icon} width={size} height={size} alt="" aria-hidden="true" />
    );
  }
  return (
    <span
      className="avatar"
      style={{ width: size, height: size, background: avatarColor(title), fontSize: size * 0.42 }}
      aria-hidden="true"
    >
      {initial}
    </span>
  );
}

const AVATAR_SIZE: Record<api.ListStyle, number> = { list: 42, compact: 28, grid: 56, table: 28 };

const ISSUE_LABEL: Record<api.Issue, string> = {
  weak: "Zayıf",
  reused: "Tekrar",
  expired: "Süresi dolmuş",
};

function formatClock(secs: number) {
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function VaultScreen({
  file,
  open,
  onLock,
  onAutoLocked,
  onEntries,
}: {
  file: SelectedFile;
  open: Open;
  onLock: () => void;
  onAutoLocked: () => void;
  onEntries: (entries: EntrySummary[]) => void;
}) {
  const [lockIn, setLockIn] = useState<number | null>(null);
  // undefined = not editing; null = new entry; string = entry id.
  const [editing, setEditing] = useState<string | null | undefined>(undefined);
  const [importing, setImporting] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  // Narrow windows (styles.css): the folder list is a drawer, and either the
  // list or the detail is shown.
  const [navOpen, setNavOpen] = useState(false);
  const [view, setView] = useState<"list" | "detail">("list");

  async function startImport() {
    try {
      const name = await api.pickKdbxFile();
      if (name !== null) setImporting(name);
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  // Site icons are fetched automatically in the background after unlocking
  // and after a save; the list updates when they arrive.
  const [iconTick, setIconTick] = useState(0);
  useEffect(() => {
    let alive = true;
    (async () => {
      // One batch per call; icons show up batch by batch.
      for (let round = 0; alive && round < 100; round++) {
        let r;
        try {
          r = await api.fetchIcons();
        } catch {
          return; // locked or save failed: try again next time
        }
        if (!alive) return;
        if (r.fetched > 0) onEntries(r.entries);
        if (r.remaining === 0) return;
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [iconTick]);

  // Rust locks on its own (idle, Win+L, sleep); here we only notice it.
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const st = await api.lockStatus();
        if (!alive) return;
        if (!st.unlocked) onAutoLocked();
        else setLockIn(st.lockInSecs);
        if (st.notice) setToast(st.notice);
      } catch {
        /* next tick retries */
      }
    };
    void tick();
    const t = window.setInterval(tick, 1000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [onAutoLocked]);

  const [query, setQuery] = useState("");
  // null = all; "totp" / "health" = special filters; otherwise a group id.
  const [group, setGroup] = useState<string | null>(null);
  const [health, setHealth] = useState<api.HealthReport | null>(null);

  // Recomputed whenever the list changes (add, edit, delete).
  useEffect(() => {
    api.passwordHealth().then(setHealth, () => setHealth(null));
  }, [open.entries]);

  const issuesOf = useMemo(() => {
    const m = new Map<string, api.Issue[]>();
    for (const e of health?.entries ?? []) m.set(e.id, e.issues);
    return m;
  }, [health]);
  const [selected, setSelected] = useState<string | null>(open.entries[0]?.id ?? null);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (!e.ctrlKey || e.altKey) return;
      const k = e.key.toLowerCase();
      if (k === "l") {
        e.preventDefault();
        onLock();
      } else if (k === "f") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onLock]);

  // Esc closes the folder drawer (narrow windows).
  useEffect(() => {
    if (!navOpen) return;
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navOpen]);

  // Ctrl+N: new entry. Ctrl+K: duplicate the selected entry (as in KeePass).
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (!e.ctrlKey || e.altKey || editing !== undefined) return;
      const k = e.key.toLowerCase();
      if (k === "n") {
        e.preventDefault();
        setEditing(null);
      } else if (k === "k" && selected !== null) {
        e.preventDefault();
        void duplicate(selected);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  async function duplicate(id: string) {
    try {
      const r = await api.duplicateEntry(id);
      onEntries(r.entries);
      setSelected(r.id);
      setView("detail");
      const t = r.entries.find((e) => e.id === r.id)?.title ?? "";
      setToast(`"${t}" oluşturuldu.`);
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  // All folders (also empty ones), refreshed whenever the list changes.
  const [allGroups, setAllGroups] = useState<api.GroupView[]>([]);
  const [groupTick, setGroupTick] = useState(0);
  useEffect(() => {
    api.listGroups().then(setAllGroups, () => setAllGroups([]));
  }, [open.entries, groupTick]);
  // The folder tree in display order (parents before children, siblings by
  // name), with each folder's depth for indentation.
  type GroupRow = {
    name: string;
    count: number;
    total: number;
    root: boolean;
    depth: number;
    parent: string | null;
    icon: string | null;
  };
  const groups = useMemo(() => {
    const kids = new Map<string | null, api.GroupView[]>();
    for (const g of allGroups) kids.set(g.parent, [...(kids.get(g.parent) ?? []), g]);
    const out: (readonly [string, GroupRow])[] = [];
    const seen = new Set<string>();
    const walk = (parent: string | null, depth: number) => {
      const list = (kids.get(parent) ?? [])
        .slice()
        .sort((a, b) => a.name.localeCompare(b.name, "tr"));
      for (const g of list) {
        if (seen.has(g.id)) continue; // Rust repairs cycles; never loop here
        seen.add(g.id);
        out.push([
          g.id,
          {
            name: g.name,
            count: g.entries,
            total: g.totalEntries,
            root: g.parent === null,
            depth,
            parent: g.parent,
            icon: g.icon,
          },
        ] as const);
        walk(g.id, depth + 1);
      }
    };
    walk(null, 0);
    return out;
  }, [allGroups]);

  /** The folder and everything below it (not valid move targets for it). */
  function subtree(id: string): Set<string> {
    const out = new Set([id]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const g of allGroups) {
        if (g.parent !== null && out.has(g.parent) && !out.has(g.id)) {
          out.add(g.id);
          grew = true;
        }
      }
    }
    return out;
  }

  // Drag and drop: an entry or a folder onto a folder. Rust checks again.
  type Drag = { kind: "entry" | "group"; id: string };
  const [drag, setDrag] = useState<Drag | null>(null);
  const [dropOn, setDropOn] = useState<string | null>(null);
  const [moving, setMoving] = useState<string | null>(null);
  // Folder whose icon picker is open.
  const [iconFor, setIconFor] = useState<string | null>(null);

  async function chooseIcon(id: string, key: string | null) {
    setIconFor(null);
    try {
      onEntries(await api.setGroupIcon(id, key));
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  // Entry list style (Settings: listStyle), remembered across starts.
  const [listStyle, setListStyle] = useState<api.ListStyle>("list");
  useEffect(() => {
    api.getSettings().then((s) => setListStyle(s.listStyle), () => {});
  }, []);
  async function changeListStyle(style: api.ListStyle) {
    setListStyle(style);
    try {
      const s = await api.getSettings();
      await api.setSettings({ ...s, listStyle: style });
    } catch {
      /* the choice still applies until the app restarts */
    }
  }

  // Table sorting (table style only).
  type SortKey = "title" | "username" | "url" | "group";
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "title", dir: 1 });
  function sortBy(key: SortKey) {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: 1 }));
  }

  function canDrop(d: Drag | null, target: string): boolean {
    if (!d) return false;
    if (d.kind === "entry") return open.entries.find((e) => e.id === d.id)?.groupId !== target;
    const me = allGroups.find((g) => g.id === d.id);
    return !!me && me.parent !== null && me.parent !== target && !subtree(d.id).has(target);
  }

  async function moveTo(d: Drag, target: string) {
    setDrag(null);
    setDropOn(null);
    setMoving(null);
    if (!canDrop(d, target)) return;
    const name = groups.find(([i]) => i === target)?.[1].name ?? "";
    try {
      if (d.kind === "entry") {
        onEntries(await api.moveEntry(d.id, target));
        const title = open.entries.find((e) => e.id === d.id)?.title || "(başlıksız)";
        setToast(`"${title}" → "${name}" klasörüne taşındı.`);
      } else {
        const root = allGroups.find((g) => g.parent === null)?.id;
        const own = allGroups.find((g) => g.id === d.id)?.name ?? "";
        onEntries(await api.moveGroup(d.id, target === root ? null : target));
        setToast(`"${own}" klasörü → "${name}" içine taşındı.`);
      }
    } catch (e) {
      setToast(api.errorText(e));
    }
  }
  const [newFolder, setNewFolder] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const [confirmDel, setConfirmDel] = useState<string | null>(null);

  async function createFolder(ev: React.FormEvent) {
    ev.preventDefault();
    if (newFolder === null) return;
    try {
      await api.addGroup(null, newFolder);
      setNewFolder(null);
      setGroupTick((t) => t + 1);
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  async function saveRename(ev: React.FormEvent) {
    ev.preventDefault();
    if (!renaming) return;
    try {
      onEntries(await api.renameGroup(renaming.id, renaming.name));
      setRenaming(null);
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  async function removeFolder(id: string) {
    if (confirmDel !== id) {
      setConfirmDel(id);
      return;
    }
    try {
      onEntries(await api.deleteGroup(id));
      setConfirmDel(null);
      setGroup(null);
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  async function openSite() {
    if (!current) return;
    try {
      await api.openUrl(current.id);
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  async function autoType() {
    if (!current) return;
    setToast("Hedef pencereye geçin (10 sn). Pencere başlığı doğrulanınca yazılacak.");
    try {
      await api.autoType(current.id);
      setToast("Otomatik yazma tamamlandı.");
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  const listTitle =
    group === null
      ? "Tüm kayıtlar"
      : group === "totp"
        ? "TOTP kodları"
        : group === "health"
          ? "Parola sağlığı"
          : (allGroups.find((g) => g.id === group)?.name ?? "Klasör");

  /** "İş › Geliştirme": the folder and its parents, without the root. */
  function groupPath(id: string) {
    const names: string[] = [];
    const seen = new Set<string>();
    let cur = allGroups.find((g) => g.id === id);
    while (cur && cur.parent !== null && !seen.has(cur.id)) {
      seen.add(cur.id);
      names.unshift(cur.name);
      cur = allGroups.find((g) => g.id === cur!.parent);
    }
    return names.length ? names.join(" › ") : (cur?.name ?? "");
  }

  const shown = useMemo(() => {
    const q = query.trim().toLocaleLowerCase("tr");
    return open.entries.filter(
      (e) =>
        (group === null ||
          (group === "totp"
            ? e.hasTotp
            : group === "health"
              ? issuesOf.has(e.id)
              : e.groupId === group)) &&
        (!q || [e.title, e.username, e.url].some((f) => f.toLocaleLowerCase("tr").includes(q))),
    );
  }, [open.entries, query, group, issuesOf]);

  const sortedShown = useMemo(() => {
    const list = shown.slice();
    list.sort((a, b) => sort.dir * a[sort.key].localeCompare(b[sort.key], "tr"));
    return list;
  }, [shown, sort]);

  const current = open.entries.find((e) => e.id === selected) ?? null;

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 4000);
    return () => window.clearTimeout(t);
  }, [toast]);

  async function copy(field: api.CopyField) {
    if (!current) return;
    try {
      const secs = await api.copyField(current.id, field);
      const what =
        field === "password" ? "Parola" : field === "totp" ? "Kod" : "Kullanıcı adı";
      setToast(`${what} kopyalandı · pano ${secs} sn sonra temizlenecek`);
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  return (
    <div className={"app" + (navOpen ? " nav-open" : "")} data-view={view} data-list={listStyle}>
      {settingsOpen ? (
        <SettingsPage
          onClose={() => setSettingsOpen(false)}
          onImport={() => {
            setSettingsOpen(false);
            void startImport();
          }}
        />
      ) : (
      <>
      <header className="topbar">
        <button
          type="button"
          className="icon-btn menu-btn"
          aria-label="Klasörler"
          aria-expanded={navOpen}
          onClick={() => setNavOpen((o) => !o)}
        >
          <MenuIcon />
        </button>
        <div className="brand">
          <span className="brand-mark" style={{ width: 40, height: 40 }}>
            <LockIcon />
          </span>
          <span className="brand-text">
            <span className="brand-name">LockAlperen</span>
            <span className="muted small ellipsis" title={`${file.folder}\\${file.fileName}`}>
              {file.fileName}
            </span>
          </span>
        </div>
        <label className="search top-search">
          <SearchIcon />
          <input
            ref={searchRef}
            type="search"
            placeholder="Kayıtlarda ara"
            aria-label="Kayıtlarda ara"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            spellCheck={false}
            autoComplete="off"
          />
          <span className="kbd">Ctrl+F</span>
        </label>
        <div className="topbar-right">
          {lockIn !== null && (
            <span className="autolock muted" title="Klavye ya da fare kullanılınca sıfırlanır">
              Kilit {formatClock(lockIn)}
            </span>
          )}
          <button
            type="button"
            className="icon-btn"
            aria-label="Ayarlar"
            title="Ayarlar"
            onClick={() => setSettingsOpen(true)}
          >
            <GearIcon />
          </button>
          <button type="button" className="btn btn-dark" onClick={onLock} title="Ctrl+L">
            <LockIcon />
            Kilitle
          </button>
        </div>
      </header>

      {importing !== null && (
        <ImportDialog
          fileName={importing}
          onDone={(entries) => onEntries(entries)}
          onClose={() => setImporting(null)}
        />
      )}
      {editing !== undefined ? (
        <Editor
          id={editing}
          defaultGroupId={group}
          onClose={(saved) => {
            if (saved) {
              onEntries(saved.entries);
              setSelected(saved.id);
              setIconTick((t) => t + 1);
            }
            setEditing(undefined);
          }}
          onDeleted={(entries) => {
            onEntries(entries);
            setSelected(entries[0]?.id ?? null);
            setEditing(undefined);
          }}
        />
      ) : (
      <div className="panes">
        <div className="nav-backdrop" aria-hidden="true" onClick={() => setNavOpen(false)} />
        <nav
          className="nav-pane"
          aria-label="Klasörler"
          onClick={(e) => {
            // In the drawer, picking a folder closes it.
            if ((e.target as HTMLElement).closest("button.nav")) setNavOpen(false);
          }}
        >
          <button
            type="button"
            className={"nav" + (group === null ? " active" : "")}
            onClick={() => setGroup(null)}
          >
            <ListIcon />
            Tüm kayıtlar<span className="count">{open.entries.length}</span>
          </button>
          <button
            type="button"
            className={"nav" + (group === "totp" ? " active" : "")}
            onClick={() => setGroup("totp")}
          >
            <ShieldIcon />
            TOTP kodları
            <span className="count">{open.entries.filter((e) => e.hasTotp).length}</span>
          </button>
          {groups.length > 0 && <div className="lbl section">Klasörler</div>}
          {groups.map(([id, g]) =>
            renaming?.id === id ? (
              <form key={id} onSubmit={saveRename} className="nav-form">
                <input
                  className="text-input small-input"
                  value={renaming.name}
                  onChange={(e) => setRenaming({ id, name: e.target.value })}
                  onKeyDown={(e) => e.key === "Escape" && setRenaming(null)}
                  aria-label="Klasörün yeni adı"
                  autoFocus
                />
              </form>
            ) : (
              <div
                key={id}
                className={
                  "nav-item" + (group === id ? " active" : "") + (dropOn === id ? " drop-on" : "")
                }
                style={{ paddingLeft: g.depth * 14 }}
                onDragOver={(e) => {
                  if (!canDrop(drag, id)) return;
                  e.preventDefault();
                  e.dataTransfer.dropEffect = "move";
                  setDropOn(id);
                }}
                onDragLeave={() => setDropOn((d) => (d === id ? null : d))}
                onDrop={(e) => {
                  e.preventDefault();
                  if (drag) void moveTo(drag, id);
                }}
              >
                <button
                  type="button"
                  className="nav"
                  onClick={() => setGroup(id)}
                  draggable={!g.root}
                  onDragStart={(e) => {
                    e.dataTransfer.effectAllowed = "move";
                    e.dataTransfer.setData("text/plain", g.name);
                    setDrag({ kind: "group", id });
                  }}
                  onDragEnd={() => {
                    setDrag(null);
                    setDropOn(null);
                  }}
                  title={g.root ? undefined : "Başka bir klasörün üzerine sürükleyerek taşıyın"}
                >
                  {folderIconDef(g.icon) ? <FaIcon def={folderIconDef(g.icon)!} /> : <FolderIcon />}
                  <span className="ellipsis">{g.name}</span>
                  <span className="count">{g.count}</span>
                </button>
                {group === id && (
                  <span className="nav-tools">
                    <button
                      type="button"
                      className="ghost-icon tiny"
                      aria-label="Klasör simgesi seç"
                      title="Simge"
                      aria-expanded={iconFor === id}
                      onClick={() => setIconFor(iconFor === id ? null : id)}
                    >
                      <PaletteIcon />
                    </button>
                    <button
                      type="button"
                      className="ghost-icon tiny"
                      aria-label="Klasörü yeniden adlandır"
                      title="Yeniden adlandır"
                      onClick={() => setRenaming({ id, name: g.name })}
                    >
                      <PencilIcon />
                    </button>
                    {!g.root && (
                      <button
                        type="button"
                        className="ghost-icon tiny"
                        aria-label="Klasörü taşı"
                        title="Taşı"
                        onClick={() => setMoving(moving === id ? null : id)}
                      >
                        <MoveIcon />
                      </button>
                    )}
                    {!g.root && (
                      <button
                        type="button"
                        className={"ghost-icon tiny" + (confirmDel === id ? " danger-bg" : "")}
                        aria-label="Klasörü sil"
                        title={
                          confirmDel === id
                            ? `Emin misiniz? Klasör, alt klasörleri ve ${g.total} kayıt silinecek. Silmek için tekrar tıklayın.`
                            : "Sil"
                        }
                        onClick={() => removeFolder(id)}
                        onBlur={() => setConfirmDel(null)}
                      >
                        <XIcon />
                      </button>
                    )}
                  </span>
                )}
              </div>
            ),
          )}
          {iconFor && (
            <div
              className="icon-picker"
              role="group"
              aria-label="Klasör simgesi"
              onKeyDown={(e) => e.key === "Escape" && setIconFor(null)}
            >
              <button
                type="button"
                className="icon-choice"
                title="Varsayılan"
                aria-label="Varsayılan klasör simgesi"
                onClick={() => void chooseIcon(iconFor, null)}
                autoFocus
              >
                <FolderIcon />
              </button>
              {FOLDER_ICONS.map((i) => (
                <button
                  key={i.key}
                  type="button"
                  className={
                    "icon-choice" +
                    (groups.find(([gid]) => gid === iconFor)?.[1].icon === i.key ? " on" : "")
                  }
                  title={i.label}
                  aria-label={i.label}
                  onClick={() => void chooseIcon(iconFor, i.key)}
                >
                  <FaIcon def={i.def} size={18} />
                </button>
              ))}
            </div>
          )}
          {moving && (
            <div className="nav-form">
              <select
                className="text-input small-input"
                aria-label="Klasörün taşınacağı yer"
                value=""
                autoFocus
                onChange={(e) =>
                  e.target.value && void moveTo({ kind: "group", id: moving }, e.target.value)
                }
                onKeyDown={(e) => e.key === "Escape" && setMoving(null)}
              >
                <option value="">Şuraya taşı…</option>
                {groups
                  .filter(([t]) => canDrop({ kind: "group", id: moving }, t))
                  .map(([t, tg]) => (
                    <option key={t} value={t}>
                      {"\u00a0\u00a0".repeat(tg.depth) + tg.name}
                    </option>
                  ))}
              </select>
            </div>
          )}
          {confirmDel && (
            <p className="warn small del-warn">
              Klasör, alt klasörleri ve içindeki{" "}
              {groups.find(([i]) => i === confirmDel)?.[1].total ?? 0} kayıt silinecek. Onaylamak
              için × düğmesine tekrar basın.
            </p>
          )}
          {newFolder === null ? (
            <button type="button" className="nav muted-nav" onClick={() => setNewFolder("")}>
              <PlusIcon />
              Yeni klasör
            </button>
          ) : (
            <form onSubmit={createFolder} className="nav-form">
              <input
                className="text-input small-input"
                placeholder="Klasör adı"
                value={newFolder}
                onChange={(e) => setNewFolder(e.target.value)}
                onKeyDown={(e) => e.key === "Escape" && setNewFolder(null)}
                aria-label="Yeni klasör adı"
                autoFocus
              />
            </form>
          )}
          {health && health.checked > 0 && (
            <button
              type="button"
              className={"health-card" + (group === "health" ? " active" : "")}
              onClick={() => setGroup(group === "health" ? null : "health")}
              title="Zayıflık tahmini yalnızca uzunluğa ve karakter türlerine bakar; sözlük kelimelerini ve kalıpları tanımaz."
            >
              <span className="muted small">Parola sağlığı</span>
              <span className="health-score">%{health.okPercent}</span>
              <span className="health-bar">
                <span style={{ width: `${health.okPercent}%` }} />
              </span>
              <span className="muted small">
                {health.weak} zayıf · {health.reused} tekrar · {health.expired} eski
              </span>
            </button>
          )}
        </nav>

        <section className="list-pane" aria-label="Kayıt listesi">
          <div className="list-head">
            <div className="list-title">
              <h2 className="ellipsis">{listTitle}</h2>
            </div>
            <button
              type="button"
              className="btn btn-accent new-btn"
              onClick={() => setEditing(null)}
              title="Ctrl+N"
            >
              <PlusIcon />
              Yeni kayıt
            </button>
          </div>
          <div className="list-toolbar">
            <span className="muted small">{shown.length} kayıt</span>
              <div className="view-switch" role="group" aria-label="Görünüm">
                {(
                  [
                    ["list", "Liste", <RowsIcon key="l" />],
                    ["compact", "Kompakt liste", <CompactIcon key="c" />],
                    ["grid", "Kartlar", <GridIcon key="g" />],
                    ["table", "Tablo", <TableIcon key="t" />],
                  ] as [api.ListStyle, string, ReactNode][]
                ).map(([style, label, icon]) => (
                  <button
                    key={style}
                    type="button"
                    className={"view-btn" + (listStyle === style ? " on" : "")}
                    aria-label={label}
                    title={label}
                    aria-pressed={listStyle === style}
                    onClick={() => void changeListStyle(style)}
                  >
                    {icon}
                  </button>
                ))}
              </div>
          </div>
          <div className="chips list-chips" role="group" aria-label="Göster">
            <button
              type="button"
              className={"chip-btn" + (group === null ? " on" : "")}
              aria-pressed={group === null}
              onClick={() => setGroup(null)}
            >
              Tümü
            </button>
            {groups
              .filter(([, g]) => !g.root)
              .map(([id, g]) => (
                <button
                  key={id}
                  type="button"
                  className={"chip-btn" + (group === id ? " on" : "")}
                  aria-pressed={group === id}
                  onClick={() => setGroup(id)}
                >
                  {folderIconDef(g.icon) && <FaIcon def={folderIconDef(g.icon)!} size={13} />}
                  {g.name}
                </button>
              ))}
            <button
              type="button"
              className={"chip-btn" + (group === "totp" ? " on" : "")}
              aria-pressed={group === "totp"}
              onClick={() => setGroup("totp")}
            >
              TOTP
            </button>
          </div>
          {shown.length === 0 ? (
            <p className="empty muted">
              {open.entries.length === 0 ? "Kasada kayıt yok." : "Sonuç yok."}
            </p>
          ) : (
            listStyle === "table" ? (
              <div className="table-box">
                <table className="entry-table">
                  <thead>
                    <tr>
                      {(
                        [
                          ["title", "Başlık"],
                          ["username", "Kullanıcı adı"],
                          ["url", "Web sitesi"],
                          ["group", "Klasör"],
                        ] as [SortKey, string][]
                      ).map(([key, label]) => (
                        <th
                          key={key}
                          scope="col"
                          aria-sort={
                            sort.key === key ? (sort.dir === 1 ? "ascending" : "descending") : "none"
                          }
                        >
                          <button type="button" className="th-btn" onClick={() => sortBy(key)}>
                            {label}
                            {sort.key === key && <span aria-hidden="true">{sort.dir === 1 ? " ↑" : " ↓"}</span>}
                          </button>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sortedShown.map((e) => (
                      <tr
                        key={e.id}
                        className={e.id === selected ? "active" : ""}
                        onClick={() => {
                          setSelected(e.id);
                          setView("detail");
                        }}
                        draggable
                        onDragStart={(ev) => {
                          ev.dataTransfer.effectAllowed = "move";
                          ev.dataTransfer.setData("text/plain", e.title);
                          setDrag({ kind: "entry", id: e.id });
                        }}
                        onDragEnd={() => {
                          setDrag(null);
                          setDropOn(null);
                        }}
                      >
                        <td>
                          <button
                            type="button"
                            className="cell-btn"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setSelected(e.id);
                              setView("detail");
                            }}
                          >
                            <Avatar title={e.title} size={28} icon={e.icon} />
                            <span className="ellipsis">{e.title || "(başlıksız)"}</span>
                          </button>
                        </td>
                        <td className="ellipsis">{e.username}</td>
                        <td className="ellipsis muted">{e.url}</td>
                        <td className="ellipsis muted">{e.group}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
            <ul className={"entries style-" + listStyle}>
              {shown.map((e) => (
                // Text only: React escapes it; no innerHTML anywhere.
                <li key={e.id}>
                  <button
                    type="button"
                    className={"row" + (e.id === selected ? " active" : "")}
                    onClick={() => {
                      setSelected(e.id);
                      setView("detail");
                    }}
                    draggable
                    onDragStart={(ev) => {
                      ev.dataTransfer.effectAllowed = "move";
                      ev.dataTransfer.setData("text/plain", e.title);
                      setDrag({ kind: "entry", id: e.id });
                    }}
                    onDragEnd={() => {
                      setDrag(null);
                      setDropOn(null);
                    }}
                  >
                    <Avatar title={e.title} size={AVATAR_SIZE[listStyle]} icon={e.icon} />
                    <span className="row-text">
                      <span className="row-title ellipsis">{e.title || "(başlıksız)"}</span>
                      <span className="row-sub ellipsis muted">{e.username}</span>
                    </span>
                    {(issuesOf.get(e.id) ?? []).map((i) => (
                      <span key={i} className="badge">
                        {ISSUE_LABEL[i]}
                      </span>
                    ))}
                  </button>
                </li>
              ))}
            </ul>
            )
          )}
        </section>

        <main className="detail-pane">
          {current ? (
            <>
              <div className="detail-head">
                <button
                  type="button"
                  className="icon-btn back-btn"
                  aria-label="Listeye dön"
                  onClick={() => setView("list")}
                >
                  <BackIcon />
                </button>
                <Avatar title={current.title} size={72} icon={current.icon} />
                <div className="detail-title">
                  <h1 className="ellipsis">{current.title || "(başlıksız)"}</h1>
                  <div className="muted">{groupPath(current.groupId)}</div>
                </div>
                <button
                  type="button"
                  className="btn"
                  onClick={autoType}
                  title="Uygulama küçülür; 10 sn içinde hedef pencereye geçin. Başlığı doğrulanmayan pencereye yazılmaz."
                >
                  Otomatik yaz
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() => void duplicate(current.id)}
                  title="Aynı klasörde bir kopyasını oluşturur (Ctrl+K). Geçmiş kopyalanmaz."
                >
                  Çoğalt
                </button>
                <button
                  type="button"
                  className="btn btn-accent"
                  onClick={() => setEditing(current.id)}
                >
                  Düzenle
                </button>
              </div>
              <div className="card">
                <div className="card-row">
                  <div className="card-text">
                    <div className="lbl">Kullanıcı adı</div>
                    <div className="value ellipsis">{current.username || "—"}</div>
                  </div>
                  <button
                    type="button"
                    className="btn pill-btn"
                    aria-label="Kullanıcı adını kopyala"
                    disabled={!current.username}
                    onClick={() => copy("username")}
                  >
                    Kopyala
                  </button>
                </div>
                {/* key: a new entry always starts hidden. */}
                <PasswordRow key={current.id} id={current.id} onCopy={() => copy("password")} />
                {current.hasTotp && (
                  <TotpRow key={`t-${current.id}`} id={current.id} onCopy={() => copy("totp")} />
                )}
                <div className="card-row">
                  <div className="card-text">
                    <div className="lbl">Web sitesi</div>
                    {/* Not an <a href>: the WebView never navigates; Rust opens
                        the entry's own address, http/https only. */}
                    {looksLikeWeb(current.url) ? (
                      <button
                        type="button"
                        className="value link-value ellipsis"
                        title="Tarayıcıda aç"
                        onClick={() => void openSite()}
                      >
                        {current.url}
                      </button>
                    ) : (
                      <div className="value ellipsis">{current.url || "—"}</div>
                    )}
                  </div>
                  <button
                    type="button"
                    className="btn pill-btn"
                    aria-label="Web sitesini tarayıcıda aç"
                    disabled={!looksLikeWeb(current.url)}
                    onClick={() => void openSite()}
                  >
                    Aç
                  </button>
                </div>
              </div>
              <ExtrasView id={current.id} version={open.entries} onToast={setToast} onEntries={onEntries} />
            </>
          ) : (
            <p className="empty muted">Bir kayıt seçin.</p>
          )}
          {toast && (
            <div className="toast" role="status">
              <CheckIcon />
              {toast}
            </div>
          )}
        </main>
      </div>
      )}
      </>
      )}
    </div>
  );
}

function TotpRow({ id, onCopy }: { id: string; onCopy: () => void }) {
  const [code, setCode] = useState<api.TotpCode | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const c = await api.totpCode(id);
        if (alive) {
          setCode(c);
          setFailed(false);
        }
      } catch {
        if (alive) setFailed(true);
      }
    };
    void tick();
    const t = window.setInterval(tick, 1000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [id]);

  const pretty = code ? code.code.replace(/^(\d{3,4})(\d{3,4})$/, "$1 $2") : "";
  return (
    <div className="card-row">
      <div className="card-text">
        <div className="lbl">Doğrulama kodu</div>
        <div className="value mono totp-code">{failed ? "Kod üretilemedi" : pretty || "…"}</div>
      </div>
      {code && (
        <span className="muted small totp-left" aria-label={`${code.secondsLeft} saniye kaldı`}>
          {code.secondsLeft} sn
        </span>
      )}
      <button
        type="button"
        className="btn pill-btn"
        aria-label="Kodu kopyala"
        disabled={!code}
        onClick={onCopy}
      >
        Kopyala
      </button>
    </div>
  );
}

/** Seconds a revealed password stays visible. */
const REVEAL_SECONDS = 15;

function PasswordRow({ id, onCopy }: { id: string; onCopy: () => void }) {
  // Shown only on request, dropped from state after REVEAL_SECONDS and when
  // the row unmounts (other entry selected, vault locked).
  const [shown, setShown] = useState<string | null>(null);

  useEffect(() => {
    if (shown === null) return;
    const t = window.setTimeout(() => setShown(null), REVEAL_SECONDS * 1000);
    return () => window.clearTimeout(t);
  }, [shown]);

  async function toggle() {
    if (shown !== null) {
      setShown(null);
      return;
    }
    try {
      setShown(await api.revealPassword(id));
    } catch {
      setShown(null);
    }
  }

  return (
    <div className="card-row">
      <div className="card-text">
        <div className="lbl">Parola</div>
        <div className={"value mono" + (shown === null ? " dots" : " revealed")}>
          {shown ?? "••••••••••••"}
        </div>
      </div>
      <div className="pill-group">
        <button
          type="button"
          className="btn pill-btn"
          aria-label={shown === null ? "Parolayı göster" : "Parolayı gizle"}
          onClick={toggle}
        >
          {shown === null ? "Göster" : "Gizle"}
        </button>
        <button
          type="button"
          className="btn btn-accent pill-btn"
          aria-label="Parolayı kopyala"
          onClick={onCopy}
        >
          Kopyala
        </button>
      </div>
    </div>
  );
}
