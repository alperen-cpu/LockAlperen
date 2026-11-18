// "Kaydı düzenle + parola üretici" screen (design board 3).
//
// The editor necessarily holds the entry's password and notes in React state
// while it is open (that is what editing is). The state is dropped when the
// editor closes or the vault locks; WebView strings cannot be wiped
// (documented limit in SECURITY.md).
import { useEffect, useState, type FormEvent } from "react";
import * as api from "./api";
import { ConfirmDialog } from "./Confirm";
import type { EntryForm, EntrySummary, FormField, GenOptions, GroupView } from "./api";
import { dateInputValue, expiryAfterMonths, fromDateInput } from "./api";
import { EyeIcon, EyeOffIcon, KeyIcon, PlusIcon, RefreshIcon, XIcon } from "./icons";

const DEFAULT_GEN: GenOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

/** log2(pool^length) for a uniformly random password from these sets. */
function entropyBits(o: GenOptions) {
  // Set sizes of lav-core's generator (src/generator.rs): 26/26/10/27; with
  // "exclude ambiguous" l,o / I,O / 1,0 go. The generator forces one char
  // from each set, which lowers entropy slightly: the figure is approximate.
  let pool = 0;
  if (o.lowercase) pool += o.excludeAmbiguous ? 24 : 26;
  if (o.uppercase) pool += o.excludeAmbiguous ? 24 : 26;
  if (o.digits) pool += o.excludeAmbiguous ? 8 : 10;
  if (o.symbols) pool += 27;
  return pool > 0 ? Math.floor(o.length * Math.log2(pool)) : 0;
}

export function Editor(props: {
  /** null = new entry. */
  id: string | null;
  defaultGroupId: string | null;
  onClose: (saved?: { id: string; entries: EntrySummary[] }) => void;
  onDeleted: (entries: EntrySummary[]) => void;
}) {
  const [groups, setGroups] = useState<GroupView[]>([]);
  const [form, setForm] = useState<EntryForm | null>(null);
  const [tagsText, setTagsText] = useState("");
  const [show, setShow] = useState(props.id === null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [gen, setGen] = useState<GenOptions>(DEFAULT_GEN);
  const [generated, setGenerated] = useState<string>("");

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const gs = await api.listGroups();
        // KeePass "auto-generated passwords for new entries": the saved
        // generator profile, and a ready password for a new entry.
        const s = await api.getSettings().catch(() => null);
        if (s && alive) setGen(s.generator);
        const fresh =
          props.id === null && s?.autoGeneratePassword
            ? await api.generatePassword(s.generator).catch(() => "")
            : "";
        const f: EntryForm =
          props.id !== null
            ? await api.entryForm(props.id)
            : {
                id: null,
                groupId: props.defaultGroupId ?? gs[0]?.id ?? "",
                title: "",
                username: "",
                password: fresh,
                url: "",
                notes: "",
                tags: [],
                totp: "",
                fields: [],
                expires: null,
              };
        if (!alive) return;
        setGroups(gs);
        setForm(f);
        setTagsText(f.tags.join(", "));
      } catch (e) {
        if (alive) setError(api.errorText(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [props.id, props.defaultGroupId]);

  async function regenerate(o: GenOptions = gen) {
    try {
      setGenerated(await api.generatePassword(o));
      setError(null);
    } catch (e) {
      setGenerated("");
      setError(api.errorText(e));
    }
  }

  useEffect(() => {
    void regenerate(gen);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gen]);

  // Esc closes, Ctrl+S saves.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") props.onClose();
      else if (e.ctrlKey && e.key.toLowerCase() === "s") {
        e.preventDefault();
        void save();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const set = (patch: Partial<EntryForm>) => setForm((f) => (f ? { ...f, ...patch } : f));

  async function save(ev?: FormEvent) {
    ev?.preventDefault();
    if (!form || busy) return;
    setBusy(true);
    setError(null);
    try {
      const tags = tagsText.split(",").map((t) => t.trim()).filter(Boolean);
      const saved = await api.saveEntry({ ...form, tags });
      props.onClose(saved);
    } catch (e) {
      setError(api.errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!form?.id || busy) return;
    setBusy(true);
    try {
      props.onDeleted(await api.deleteEntry(form.id));
    } catch (e) {
      setError(api.errorText(e));
      setBusy(false);
      setConfirmDelete(false);
    }
  }

  if (!form) {
    return <div className="editor">{error ? <p className="error">{error}</p> : null}</div>;
  }
  const groupName = groups.find((g) => g.id === form.groupId)?.name ?? "";
  // Deleting from the recycle bin is permanent; elsewhere it moves there.
  const binned = form.id !== null && api.inRecycleBin(form.groupId, groups);
  const bits = entropyBits(gen);

  return (
    <div className="editor">
      <header className="editor-head">
        <h1>{form.id ? "Kaydı düzenle" : "Yeni kayıt"}</h1>
        <span className="muted">
          {groupName}
          {form.title ? ` › ${form.title}` : ""}
        </span>
        <div className="editor-actions">
          {form.id && (
            <button
              type="button"
              className="btn danger"
              onClick={() => setConfirmDelete(true)}
              disabled={busy}
              title={
                binned
                  ? "Geri Dönüşüm Kutusu'ndaki kayıt kalıcı olarak silinir."
                  : "Kayıt Geri Dönüşüm Kutusu'na taşınır; oradan geri alınabilir."
              }
            >
              {binned ? "Kalıcı olarak sil" : "Sil"}
            </button>
          )}
          {confirmDelete && (
            <ConfirmDialog
              title={binned ? "Kayıt kalıcı olarak silinsin mi?" : "Kayıt silinsin mi?"}
              confirmLabel={binned ? "Kalıcı olarak sil" : "Çöpe taşı"}
              danger={binned}
              busy={busy}
              onConfirm={() => void remove()}
              onCancel={() => setConfirmDelete(false)}
            >
              <p>
                <strong>"{form.title || "(başlıksız)"}"</strong>{" "}
                {binned ? "kalıcı olarak silinecek." : "Geri Dönüşüm Kutusu'na taşınacak."}
              </p>
              {binned ? (
                <p className="warn">Bu işlem geri alınamaz.</p>
              ) : (
                <p className="muted">Kutudan "Geri yükle" ile geri alabilirsiniz.</p>
              )}
            </ConfirmDialog>
          )}
          <button type="button" className="btn" onClick={() => props.onClose()} disabled={busy}>
            Vazgeç <span className="kbd">Esc</span>
          </button>
          <button type="submit" form="entry-form" className="btn btn-accent" disabled={busy}>
            {busy ? "Kaydediliyor…" : "Kaydet"} <span className="kbd">Ctrl+S</span>
          </button>
        </div>
      </header>

      {error && (
        <p className="error editor-error" role="alert">
          {error}
        </p>
      )}

      <div className="editor-body">
        <form id="entry-form" className="editor-form" onSubmit={save}>
          <div className="grid2">
            <div className="field">
              <label className="lbl" htmlFor="e-title">
                Başlık
              </label>
              <input
                id="e-title"
                className="text-input"
                value={form.title}
                onChange={(e) => set({ title: e.target.value })}
                autoFocus
                autoComplete="off"
              />
            </div>
            <div className="field">
              <label className="lbl" htmlFor="e-group">
                Klasör
              </label>
              <select
                id="e-group"
                className="text-input"
                value={form.groupId}
                onChange={(e) => set({ groupId: e.target.value })}
              >
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label className="lbl" htmlFor="e-user">
                Kullanıcı adı
              </label>
              <input
                id="e-user"
                className="text-input"
                value={form.username}
                onChange={(e) => set({ username: e.target.value })}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <div className="field">
              <label className="lbl" htmlFor="e-url">
                Web sitesi
              </label>
              <input
                id="e-url"
                className="text-input"
                value={form.url}
                onChange={(e) => set({ url: e.target.value })}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
          </div>

          <div className="field">
            <label className="lbl" htmlFor="e-pw">
              Parola
            </label>
            <div className="pw-box">
              <input
                id="e-pw"
                className="mono"
                type={show ? "text" : "password"}
                value={form.password}
                onChange={(e) => set({ password: e.target.value })}
                autoComplete="off"
                spellCheck={false}
              />
              <button
                type="button"
                className="ghost-icon"
                aria-label={show ? "Parolayı gizle" : "Parolayı göster"}
                onClick={() => setShow((v) => !v)}
              >
                {show ? <EyeOffIcon /> : <EyeIcon />}
              </button>
              <button
                type="button"
                className="ghost-icon accent-text"
                aria-label="Üreticideki parolayı kullan"
                title="Üreticideki parolayı kullan"
                onClick={() => generated && set({ password: generated })}
              >
                <RefreshIcon />
              </button>
            </div>
          </div>

          <div className="field">
            <label className="lbl" htmlFor="e-totp">
              TOTP (iki adımlı doğrulama)
            </label>
            <input
              id="e-totp"
              className="text-input mono"
              placeholder="Base32 anahtar ya da otpauth://totp/… bağlantısı"
              value={form.totp}
              onChange={(e) => set({ totp: e.target.value })}
              autoComplete="off"
              spellCheck={false}
            />
          </div>

          <div className="field">
            <span className="lbl">Özel alanlar</span>
            {(form.fields ?? []).map((f, i) => {
              const update = (patch: Partial<FormField>) =>
                set({
                  fields: (form.fields ?? []).map((x, j) => (j === i ? { ...x, ...patch } : x)),
                });
              return (
                <div className="field-row" key={i}>
                  <input
                    className="text-input"
                    placeholder="Alan adı"
                    aria-label="Alan adı"
                    value={f.name}
                    onChange={(e) => update({ name: e.target.value })}
                  />
                  <input
                    className="text-input mono"
                    placeholder="Değer"
                    aria-label="Alan değeri"
                    type={f.protected ? "password" : "text"}
                    value={f.value}
                    onChange={(e) => update({ value: e.target.value })}
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={f.protected}
                      onChange={(e) => update({ protected: e.target.checked })}
                    />
                    Gizli
                  </label>
                  <button
                    type="button"
                    className="ghost-icon"
                    aria-label="Alanı kaldır"
                    onClick={() => set({ fields: (form.fields ?? []).filter((_, j) => j !== i) })}
                  >
                    <XIcon />
                  </button>
                </div>
              );
            })}
            <button
              type="button"
              className="btn add-field"
              onClick={() =>
                set({ fields: [...(form.fields ?? []), { name: "", value: "", protected: true }] })
              }
            >
              <PlusIcon />
              Alan ekle
            </button>
          </div>

          <div className="field">
            <label className="lbl" htmlFor="e-tags">
              Etiketler (virgülle ayırın)
            </label>
            <input
              id="e-tags"
              className="text-input"
              value={tagsText}
              onChange={(e) => setTagsText(e.target.value)}
              autoComplete="off"
            />
          </div>

          <div className="field">
            <label className="check">
              <input
                type="checkbox"
                checked={form.expires != null}
                onChange={(e) =>
                  set({ expires: e.target.checked ? expiryAfterMonths(3) : null })
                }
              />
              Son kullanma tarihi
            </label>
            {form.expires != null && (
              <div className="field-row">
                <input
                  type="date"
                  className="text-input"
                  aria-label="Son kullanma tarihi"
                  value={dateInputValue(form.expires)}
                  min="1970-01-01"
                  max="9999-12-31"
                  onChange={(e) => {
                    const t = fromDateInput(e.target.value);
                    if (t !== null) set({ expires: t });
                  }}
                />
                <select
                  className="text-input"
                  aria-label="Hızlı seç"
                  value=""
                  onChange={(e) => {
                    const m = Number(e.target.value);
                    if (m > 0) set({ expires: expiryAfterMonths(m) });
                  }}
                >
                  <option value="">Hızlı seç…</option>
                  <option value="1">1 ay sonra</option>
                  <option value="3">3 ay sonra</option>
                  <option value="6">6 ay sonra</option>
                  <option value="12">1 yıl sonra</option>
                </select>
              </div>
            )}
          </div>

          <div className="field">
            <label className="lbl" htmlFor="e-notes">
              Notlar
            </label>
            <textarea
              id="e-notes"
              className="text-input textarea"
              value={form.notes}
              onChange={(e) => set({ notes: e.target.value })}
              spellCheck={false}
            />
          </div>
        </form>

        <aside className="generator" aria-label="Parola üretici">
          <div className="gen-title">
            <KeyIcon />
            <h2>Parola üretici</h2>
          </div>
          <div className="gen-out mono" aria-live="polite">
            {generated || "—"}
          </div>
          <div className="form-buttons">
            <button type="button" className="btn wide" onClick={() => regenerate()}>
              <RefreshIcon />
              Yeniden üret
            </button>
            <button
              type="button"
              className="btn btn-accent wide"
              disabled={!generated}
              onClick={() => {
                set({ password: generated });
                setShow(true);
              }}
            >
              Bu parolayı kullan
            </button>
          </div>
          <div className="field">
            <div className="row-between">
              <label className="lbl" htmlFor="g-len">
                Uzunluk
              </label>
              <span className="mono">{gen.length}</span>
            </div>
            <input
              id="g-len"
              type="range"
              min={8}
              max={64}
              value={gen.length}
              onChange={(e) => setGen({ ...gen, length: Number(e.target.value) })}
            />
          </div>
          <div className="grid2 checks">
            {(
              [
                ["lowercase", "a–z"],
                ["uppercase", "A–Z"],
                ["digits", "0–9"],
                ["symbols", "!@#$%"],
              ] as const
            ).map(([k, label]) => (
              <label key={k} className="check">
                <input
                  type="checkbox"
                  checked={gen[k]}
                  onChange={(e) => setGen({ ...gen, [k]: e.target.checked })}
                />
                {label}
              </label>
            ))}
          </div>
          <label className="check">
            <input
              type="checkbox"
              checked={gen.excludeAmbiguous}
              onChange={(e) => setGen({ ...gen, excludeAmbiguous: e.target.checked })}
            />
            Karışan karakterleri çıkar (I l 1 O 0)
          </label>
          <p className="muted small gen-note">
            Entropi ≈ {bits} bit (rastgele üretilen parola için).
          </p>
        </aside>
      </div>
    </div>
  );
}
