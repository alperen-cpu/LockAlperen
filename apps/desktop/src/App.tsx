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
import { SettingsDialog } from "./Settings";
import type { EntrySummary, SelectedFile, VaultInfo } from "./api";
import {
  CheckIcon,
  ClockIcon,
  CopyIcon,
  DownloadIcon,
  EyeIcon,
  GearIcon,
  EyeOffIcon,
  FileIcon,
  FolderIcon,
  ListIcon,
  LockIcon,
  PencilIcon,
  PlusIcon,
  SearchIcon,
  ShieldIcon,
  XIcon,
} from "./icons";

type Open = { info: VaultInfo; entries: EntrySummary[] };

export function App() {
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
    <aside className="unlock-side">
      <Brand />
      {props.recents.length > 0 && (
        <>
          <div className="lbl recent-lbl">Son kasalar</div>
          <ul className="recents">
            {props.recents.map((r, i) => (
              <li key={`${r.folder}\\${r.fileName}`} className={isCurrent(r) ? "active" : ""}>
                <button
                  type="button"
                  className="recent"
                  onClick={() => props.onPickRecent(i)}
                  disabled={props.busy}
                  title={`${r.folder}\\${r.fileName}`}
                >
                  <LockIcon size={18} />
                  <span className="recent-text">
                    <span className="recent-name ellipsis">{r.fileName}</span>
                    <span className="recent-sub ellipsis muted">
                      {r.folder} · {timeAgo(r.opened)}
                    </span>
                  </span>
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
        <button type="button" className="btn btn-left" onClick={props.onCreate} disabled={props.busy}>
          <PlusIcon />
          Yeni kasa oluştur
        </button>
        <button type="button" className="btn btn-left" onClick={props.onChoose} disabled={props.busy}>
          <FileIcon />
          {props.hasFile ? "Başka bir kasa aç…" : "Kasa dosyası aç…"}
        </button>
      </div>
    </aside>
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
      {props.side}
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
    </div>
  );
}

function Brand({ size = 32 }: { size?: number }) {
  return (
    <div className="brand">
      <span className="brand-mark" style={{ width: size, height: size }}>
        <LockIcon />
      </span>
      <span className="brand-name">LockAlperen</span>
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
      {side(busy)}

      <main className="unlock-main">
        <form className="unlock-form" onSubmit={submit}>
          <span className="unlock-badge">
            <LockIcon size={30} />
          </span>
          <div className="center">
            <h1>{file ? file.fileName : "Kasa seçilmedi"}</h1>
            <p className="muted">
              {file
                ? "Kasanın kilidini açmak için ana parolanızı girin"
                : "Başlamak için soldan bir kasa dosyası açın"}
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

          <label className="check">
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

          <button type="submit" className="btn btn-accent wide" disabled={!file || busy}>
            {busy ? "Açılıyor…" : "Kilidi aç"}
            {!busy && <span className="kbd">Enter</span>}
          </button>

          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}

          {file?.kdf && (
            <p className="muted small center">
              Argon2id · {file.kdf.memoryMib} MiB · {file.kdf.iterations} geçiş
            </p>
          )}
        </form>
      </main>
    </div>
  );
}

const AVATAR_COLORS = ["#8FB0FF", "#7FC8F8", "#3DD68C", "#F5B54A", "#F28FAD", "#B79CFF"];

function avatarColor(s: string) {
  let h = 0;
  for (const ch of s) h = (h * 31 + ch.codePointAt(0)!) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

function Avatar({ title, size }: { title: string; size: number }) {
  const initial = Array.from(title.trim())[0]?.toLocaleUpperCase("tr") ?? "?";
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

  async function startImport() {
    try {
      const name = await api.pickKdbxFile();
      if (name !== null) setImporting(name);
    } catch (e) {
      setToast(api.errorText(e));
    }
  }

  // Rust locks on its own (idle, Win+L, sleep); here we only notice it.
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const st = await api.lockStatus();
        if (!alive) return;
        if (!st.unlocked) onAutoLocked();
        else setLockIn(st.lockInSecs);
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

  // Ctrl+N: new entry.
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.ctrlKey && !e.altKey && e.key.toLowerCase() === "n" && editing === undefined) {
        e.preventDefault();
        setEditing(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [editing]);

  const groups = useMemo(() => {
    const m = new Map<string, { name: string; count: number }>();
    for (const e of open.entries) {
      const g = m.get(e.groupId) ?? { name: e.group, count: 0 };
      g.count++;
      m.set(e.groupId, g);
    }
    return [...m.entries()].sort((a, b) => a[1].name.localeCompare(b[1].name, "tr"));
  }, [open.entries]);

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
    <div className="app">
      <header className="topbar">
        <Brand size={28} />
        <div className="crumb">
          <span className="muted">{file.folder} ›</span>
          <strong>{file.fileName}</strong>
        </div>
        <div className="topbar-right">
          <button
            type="button"
            className="btn"
            onClick={startImport}
            disabled={editing !== undefined}
            title="KeePass'ten içe aktar (KDBX 4)"
          >
            <DownloadIcon />
            İçe aktar
          </button>
          {lockIn !== null && (
            <span className="autolock muted" title="Klavye ya da fare kullanılınca sıfırlanır">
              <ClockIcon />
              Otomatik kilit {formatClock(lockIn)}
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
          <button type="button" className="btn" onClick={onLock}>
            <LockIcon />
            Kilitle <span className="kbd">Ctrl+L</span>
          </button>
        </div>
      </header>

      {settingsOpen && <SettingsDialog onClose={() => setSettingsOpen(false)} />}
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
        <nav className="nav-pane" aria-label="Klasörler">
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
          {groups.map(([id, g]) => (
            <button
              type="button"
              key={id}
              className={"nav" + (group === id ? " active" : "")}
              onClick={() => setGroup(id)}
            >
              <FolderIcon />
              <span className="ellipsis">{g.name}</span>
              <span className="count">{g.count}</span>
            </button>
          ))}
          {health && health.checked > 0 && (
            <button
              type="button"
              className={"health-card" + (group === "health" ? " active" : "")}
              onClick={() => setGroup(group === "health" ? null : "health")}
              title="Zayıflık tahmini yalnızca uzunluğa ve karakter türlerine bakar; sözlük kelimelerini ve kalıpları tanımaz."
            >
              <span className="health-title">
                <ShieldIcon />
                Parola sağlığı
                <span className="count">%{health.okPercent}</span>
              </span>
              <span className="health-bar">
                <span style={{ width: `${health.okPercent}%` }} />
              </span>
              <span className="muted small">
                {health.weak} zayıf · {health.reused} tekrar eden · {health.expired} süresi dolmuş
              </span>
            </button>
          )}
        </nav>

        <section className="list-pane" aria-label="Kayıt listesi">
          <div className="list-tools">
            <label className="search">
              <SearchIcon />
              <input
                ref={searchRef}
                type="search"
                placeholder="Ara…  (Ctrl+F)"
                aria-label="Kayıtlarda ara"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                spellCheck={false}
                autoComplete="off"
              />
            </label>
            <button type="button" className="btn btn-accent" onClick={() => setEditing(null)}>
              <PlusIcon />
              Yeni
            </button>
          </div>
          <div className="list-meta muted">{shown.length} kayıt</div>
          {shown.length === 0 ? (
            <p className="empty muted">
              {open.entries.length === 0 ? "Kasada kayıt yok." : "Sonuç yok."}
            </p>
          ) : (
            <ul className="entries">
              {shown.map((e) => (
                // Text only: React escapes it; no innerHTML anywhere.
                <li key={e.id}>
                  <button
                    type="button"
                    className={"row" + (e.id === selected ? " active" : "")}
                    onClick={() => setSelected(e.id)}
                  >
                    <Avatar title={e.title} size={36} />
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
          )}
        </section>

        <main className="detail-pane">
          {current ? (
            <>
              <div className="detail-head">
                <Avatar title={current.title} size={52} />
                <div className="detail-title">
                  <h1 className="ellipsis">{current.title || "(başlıksız)"}</h1>
                  <div className="muted">{current.group}</div>
                </div>
                <button
                  type="button"
                  className="btn btn-accent"
                  onClick={() => setEditing(current.id)}
                >
                  <PencilIcon />
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
                    className="icon-btn"
                    aria-label="Kullanıcı adını kopyala"
                    title="Kopyala"
                    disabled={!current.username}
                    onClick={() => copy("username")}
                  >
                    <CopyIcon />
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
                    {/* Plain text, not a link: opening URLs is not enabled yet. */}
                    <div className="value ellipsis">{current.url || "—"}</div>
                  </div>
                </div>
              </div>
              <ExtrasView id={current.id} version={open.entries} onToast={setToast} />
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
        <div className="lbl">Tek kullanımlık kod (TOTP)</div>
        <div className="value mono totp-code">{failed ? "Kod üretilemedi" : pretty || "…"}</div>
      </div>
      {code && (
        <span className="muted small totp-left" aria-label={`${code.secondsLeft} saniye kaldı`}>
          <ClockIcon />
          {code.secondsLeft} sn
        </span>
      )}
      <button
        type="button"
        className="icon-btn"
        aria-label="Kodu kopyala"
        title="Kopyala"
        disabled={!code}
        onClick={onCopy}
      >
        <CopyIcon />
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
      <button
        type="button"
        className="icon-btn"
        aria-label={shown === null ? "Parolayı göster" : "Parolayı gizle"}
        title={shown === null ? "Göster" : "Gizle"}
        onClick={toggle}
      >
        {shown === null ? <EyeIcon /> : <EyeOffIcon />}
      </button>
      <button
        type="button"
        className="icon-btn accent"
        aria-label="Parolayı kopyala"
        title="Kopyala"
        onClick={onCopy}
      >
        <CopyIcon />
      </button>
    </div>
  );
}
