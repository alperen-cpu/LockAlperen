import { useEffect, useMemo, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import * as api from "./api";
import type { EntrySummary, SelectedFile, VaultInfo } from "./api";
import {
  CheckIcon,
  ClockIcon,
  CopyIcon,
  EyeIcon,
  EyeOffIcon,
  FileIcon,
  FolderIcon,
  ListIcon,
  LockIcon,
  SearchIcon,
} from "./icons";

type Open = { info: VaultInfo; entries: EntrySummary[] };

export function App() {
  const [file, setFile] = useState<SelectedFile | null>(null);
  const [open, setOpen] = useState<Open | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function choose() {
    setError(null);
    try {
      const picked = await api.pickVaultFile();
      if (picked !== null) {
        // Choosing a file locks any open vault on the Rust side.
        setFile(picked);
        setOpen(null);
      }
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
    return <VaultScreen file={file} open={open} onLock={doLock} onAutoLocked={autoLocked} />;
  }
  return (
    <UnlockScreen
      file={file}
      error={error}
      setError={setError}
      onChoose={choose}
      onOpened={setOpen}
    />
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
  onChoose: () => void;
  onOpened: (o: Open) => void;
}) {
  const { file, error, setError, onChoose, onOpened } = props;
  const [busy, setBusy] = useState(false);
  const [show, setShow] = useState(false);
  const [caps, setCaps] = useState(false);
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
      <aside className="unlock-side">
        <Brand />
        <div className="side-actions">
          <button type="button" className="btn btn-left" onClick={onChoose} disabled={busy}>
            <FileIcon />
            {file ? "Başka bir kasa aç…" : "Kasa dosyası aç…"}
          </button>
        </div>
      </aside>

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

          {file?.keyfileRequired && (
            <p className="warn">
              Bu kasa bir anahtar dosyası istiyor. Anahtar dosyası desteği bu sürümde henüz yok.
            </p>
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
}: {
  file: SelectedFile;
  open: Open;
  onLock: () => void;
  onAutoLocked: () => void;
}) {
  const [lockIn, setLockIn] = useState<number | null>(null);

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
  const [group, setGroup] = useState<string | null>(null);
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
        (group === null || e.groupId === group) &&
        (!q || [e.title, e.username, e.url].some((f) => f.toLocaleLowerCase("tr").includes(q))),
    );
  }, [open.entries, query, group]);

  const current = open.entries.find((e) => e.id === selected) ?? null;
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 4000);
    return () => window.clearTimeout(t);
  }, [toast]);

  async function copy(field: api.CopyField) {
    if (!current) return;
    try {
      const secs = await api.copyField(current.id, field);
      const what = field === "password" ? "Parola" : "Kullanıcı adı";
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
          {lockIn !== null && (
            <span className="autolock muted" title="Klavye ya da fare kullanılınca sıfırlanır">
              <ClockIcon />
              Otomatik kilit {formatClock(lockIn)}
            </span>
          )}
          <button type="button" className="btn" onClick={onLock}>
            <LockIcon />
            Kilitle <span className="kbd">Ctrl+L</span>
          </button>
        </div>
      </header>

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
                <div className="card-row">
                  <div className="card-text">
                    <div className="lbl">Web sitesi</div>
                    {/* Plain text, not a link: opening URLs is not enabled yet. */}
                    <div className="value ellipsis">{current.url || "—"}</div>
                  </div>
                </div>
              </div>
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
