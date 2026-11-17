// Settings dialog. Only non-secret preferences; applied and saved by Rust.
import { useEffect, useRef, useState, type FormEvent } from "react";
import * as api from "./api";
import type { EntrySummary } from "./api";
import { UpdateSettings } from "./Update";

export function SettingsDialog(props: {
  onClose: () => void;
  onEntries?: (entries: EntrySummary[]) => void;
}) {
  // All settings travel together, so changing one never resets another.
  const [settings, setSettingsState] = useState<api.Settings | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Passwords: uncontrolled inputs, cleared on submit, never React state.
  const cur = useRef<HTMLInputElement>(null);
  const nw = useRef<HTMLInputElement>(null);
  const cf = useRef<HTMLInputElement>(null);
  const exp = useRef<HTMLInputElement>(null);

  function take(r: React.RefObject<HTMLInputElement | null>) {
    const v = r.current?.value ?? "";
    if (r.current) r.current.value = "";
    return v;
  }

  async function changeMaster(ev: FormEvent) {
    ev.preventDefault();
    const [c, n, k] = [take(cur), take(nw), take(cf)];
    setBusy(true);
    setMsg(null);
    try {
      await api.changeMaster(c, n, k);
      setMsg("Ana parola değiştirildi ve kasa kaydedildi. Eski yedek (.bak) silindi.");
    } catch (e) {
      setMsg(api.errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function exportCsv(ev: FormEvent) {
    ev.preventDefault();
    const c = take(exp);
    setBusy(true);
    setMsg(null);
    try {
      if (await api.exportCsv(c)) {
        setMsg("Dışa aktarıldı. Bu dosya ŞİFRESİZDİR: işiniz bitince güvenli biçimde silin.");
      }
    } catch (e) {
      setMsg(api.errorText(e));
    } finally {
      setBusy(false);
    }
  }

  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (settings !== null) return;
    api.getSettings().then(
      (s) => {
        setSettingsState(s);
      },
      (e) => setError(api.errorText(e)),
    );
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) props.onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  // null = not known yet.
  const [hotkeyOk, setHotkeyOk] = useState<boolean | null>(null);
  const refreshHotkey = () =>
    // The hotkey thread applies the setting asynchronously.
    window.setTimeout(() => api.hotkeyActive().then(setHotkeyOk, () => setHotkeyOk(null)), 300);
  useEffect(() => {
    refreshHotkey();
  }, []);

  async function change(patch: Partial<api.Settings>) {
    if (settings === null) return;
    const next = { ...settings, ...patch };
    setSettingsState(next);
    try {
      setSettingsState(await api.setSettings(next));
      refreshHotkey();
      setError(null);
    } catch (e) {
      setError(api.errorText(e));
    }
  }

  return (
    <div className="modal-back" role="dialog" aria-modal="true" aria-labelledby="set-title">
      <div className="modal">
        <h2 id="set-title">Ayarlar</h2>
        <div className="field">
          <label className="lbl" htmlFor="s-theme">
            Görünüm
          </label>
          <select
            id="s-theme"
            className="text-input"
            value={settings?.theme ?? "system"}
            disabled={settings === null}
            onChange={(e) => {
              const theme = e.target.value as api.Theme;
              api.applyTheme(theme);
              void change({ theme });
            }}
          >
            <option value="system">Windows ile aynı</option>
            <option value="light">Açık</option>
            <option value="dark">Koyu</option>
          </select>
        </div>
        <div className="field">
          <label className="lbl" htmlFor="s-idle">
            Otomatik kilit (klavye ve fare kullanılmazsa)
          </label>
          <select
            id="s-idle"
            className="text-input"
            value={settings?.idleMinutes ?? ""}
            disabled={settings === null}
            onChange={(e) => void change({ idleMinutes: Number(e.target.value) })}
          >
            {api.IDLE_CHOICES.map((m) => (
              <option key={m} value={m}>
                {m} dakika
              </option>
            ))}
          </select>
        </div>
        <label className="check">
          <input
            type="checkbox"
            checked={settings?.closeToTray ?? true}
            disabled={settings === null}
            onChange={(e) => void change({ closeToTray: e.target.checked })}
          />
          Kapat düğmesi uygulamayı sistem tepsisine gizlesin
        </label>
        <div className="field">
          <label className="lbl" htmlFor="s-hotkey">
            Otomatik yazma kısayolu (öndeki pencereye)
          </label>
          <select
            id="s-hotkey"
            className="text-input"
            value={settings?.autotypeShortcut ?? ""}
            disabled={settings === null}
            onChange={(e) => void change({ autotypeShortcut: e.target.value as api.Shortcut })}
          >
            {api.SHORTCUTS.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
          {settings !== null && settings.autotypeShortcut !== "off" && hotkeyOk === false && (
            <p className="warn small">
              Bu kısayol başka bir program tarafından kullanılıyor, bu yüzden çalışmıyor. Başka
              bir kısayol seçin.
            </p>
          )}
        </div>
        <p className="muted small">
          Kısayol, öndeki pencerenin başlığına uyan tek kaydın kullanıcı adını ve parolasını
          yazar. Birden fazla kayıt uyarsa ya da hiç uymazsa hiçbir şey yazılmaz.
          Tepsideyken de kilit kuralları geçerlidir. Tamamen çıkmak için tepsi simgesinde
          "Kilitle ve çık". Windows kilitlenince, oturum kapanınca ya da uyku moduna geçilince kasa her zaman hemen
          kilitlenir. Kopyalanan değerler 12 saniye sonra panodan silinir.
        </p>
        <form className="field" onSubmit={changeMaster}>
          <span className="lbl">Ana parolayı değiştir</span>
          <input ref={cur} className="text-input" type="password" placeholder="Mevcut ana parola" aria-label="Mevcut ana parola" autoComplete="off" />
          <input ref={nw} className="text-input" type="password" placeholder="Yeni ana parola" aria-label="Yeni ana parola" autoComplete="new-password" />
          <input ref={cf} className="text-input" type="password" placeholder="Yeni ana parola (tekrar)" aria-label="Yeni ana parola tekrar" autoComplete="new-password" />
          <button type="submit" className="btn" disabled={busy}>
            Ana parolayı değiştir
          </button>
        </form>

        <form className="field" onSubmit={exportCsv}>
          <span className="lbl">Dışa aktar (CSV)</span>
          <p className="muted small">
            Bütün kayıtlar parolalarıyla birlikte <strong>şifresiz</strong> bir dosyaya yazılır. Onay
            için ana parolanızı girin.
          </p>
          <input ref={exp} className="text-input" type="password" placeholder="Ana parola" aria-label="Dışa aktarma için ana parola" autoComplete="off" />
          <button type="submit" className="btn" disabled={busy}>
            Dışa aktar…
          </button>
        </form>

        {settings !== null && (
          <UpdateSettings
            checkUpdates={settings.checkUpdates}
            onCheckUpdates={(on) => void change({ checkUpdates: on })}
          />
        )}

        {msg && <p className="muted small" role="status">{msg}</p>}
        {error && <p className="error">{error}</p>}
        <div className="form-buttons">
          <button type="button" className="btn btn-accent wide" onClick={props.onClose} autoFocus>
            Kapat
          </button>
        </div>
      </div>
    </div>
  );
}
