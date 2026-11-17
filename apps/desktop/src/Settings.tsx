// Settings page (design: "Ayarlar"). Only non-secret preferences; applied and
// saved by Rust. Master-password and export inputs are uncontrolled and
// cleared on submit: passwords never become React state.
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import * as api from "./api";
import { UpdateSettings } from "./Update";
import { BackIcon, DownloadIcon } from "./icons";

type Category = "security" | "autotype" | "look" | "window" | "updates" | "data";

const CATEGORIES: { id: Category; label: string; intro: string }[] = [
  {
    id: "security",
    label: "Güvenlik",
    intro: "Bu ayarlar bilgisayarınızda saklanır; kasanın içeriğini değiştirmez.",
  },
  {
    id: "autotype",
    label: "Otomatik yazma",
    intro: "Kullanıcı adını ve parolayı başka bir pencereye yazma.",
  },
  { id: "look", label: "Görünüm", intro: "Renk teması." },
  { id: "window", label: "Pencere", intro: "Pencereyi kapattığınızda ne olacağı." },
  { id: "updates", label: "Güncellemeler", intro: "Yeni sürümler GitHub'dan imzası doğrulanarak kurulur." },
  {
    id: "data",
    label: "İçe ve dışa aktarma",
    intro: "KeePass kasalarını alın ya da kayıtlarınızı dışa aktarın.",
  },
];

/** One line of a settings card: text on the left, the control on the right. */
function Row(props: { title: ReactNode; text?: ReactNode; children?: ReactNode }) {
  return (
    <div className="set-row">
      <div className="set-text">
        <span className="set-title">{props.title}</span>
        {props.text && <span className="muted small">{props.text}</span>}
      </div>
      {props.children}
    </div>
  );
}

export function SettingsPage(props: { onClose: () => void; onImport: () => void }) {
  const [category, setCategory] = useState<Category>("security");
  // All settings travel together, so changing one never resets another.
  const [settings, setSettingsState] = useState<api.Settings | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
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

  useEffect(() => {
    api.getSettings().then(setSettingsState, (e) => setError(api.errorText(e)));
  }, []);

  // Esc goes back to the vault (not while a password change is running).
  useEffect(() => {
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

  const current = CATEGORIES.find((c) => c.id === category)!;
  const off = settings === null;

  return (
    <div className="settings-page">
      <nav className="settings-nav" aria-label="Ayar kategorileri">
        <button type="button" className="back-link" onClick={props.onClose}>
          <BackIcon />
          Kasaya dön
        </button>
        <h1>Ayarlar</h1>
        {CATEGORIES.map((c) => (
          <button
            key={c.id}
            type="button"
            className={"nav" + (c.id === category ? " active" : "")}
            aria-current={c.id === category ? "page" : undefined}
            onClick={() => {
              setCategory(c.id);
              setMsg(null);
            }}
          >
            {c.label}
          </button>
        ))}
      </nav>

      <main className="settings-main">
        <div className="settings-head">
          <h2>{current.label}</h2>
          <p className="muted">{current.intro}</p>
        </div>

        {category === "security" && (
          <>
            <section className="set-card">
              <Row
                title={<label htmlFor="s-idle">Otomatik kilit</label>}
                text="Klavye ve fare bu süre kullanılmazsa kasa kilitlenir."
              >
                <select
                  id="s-idle"
                  className="text-input set-select"
                  value={settings?.idleMinutes ?? ""}
                  disabled={off}
                  onChange={(e) => void change({ idleMinutes: Number(e.target.value) })}
                >
                  {api.IDLE_CHOICES.map((m) => (
                    <option key={m} value={m}>
                      {m} dakika
                    </option>
                  ))}
                </select>
              </Row>
              <Row
                title={<label htmlFor="s-sys">Bilgisayar kilitlenince kasayı da kilitle</label>}
                text="Win+L'ye basınca, uyku moduna geçince ya da oturum kapanınca kasa kilitlenir. Kilitliyken görev çubuğu simgesinde kırmızı kilit görünür."
              >
                <input
                  id="s-sys"
                  type="checkbox"
                  className="switch"
                  checked={settings?.lockOnSystemEvents ?? true}
                  disabled={off}
                  onChange={(e) => void change({ lockOnSystemEvents: e.target.checked })}
                />
              </Row>
              {settings !== null && !settings.lockOnSystemEvents && (
                <p className="warn set-note">
                  Kapalıyken bilgisayarı kilitleyip başından kalksanız da kasa açık kalır; yalnızca
                  otomatik kilit süresi dolunca kilitlenir. Açık tutmanız önerilir.
                </p>
              )}
              <Row
                title={<label htmlFor="s-clip">Panoyu temizle</label>}
                text="Kopyalanan parola ya da kod bu süre sonunda ve kasa kilitlenince panodan silinir; pano geçmişine alınmaz."
              >
                <select
                  id="s-clip"
                  className="text-input set-select"
                  value={settings?.clipboardSeconds ?? ""}
                  disabled={off}
                  onChange={(e) => void change({ clipboardSeconds: Number(e.target.value) })}
                >
                  {api.CLIPBOARD_CHOICES.map((s) => (
                    <option key={s} value={s}>
                      {s} saniye
                    </option>
                  ))}
                </select>
              </Row>
            </section>

            <form className="set-card pad" onSubmit={changeMaster}>
              <div className="set-text">
                <span className="set-title">Ana parolayı değiştir</span>
                <span className="muted small">
                  Yeni tuz ve anahtar üretilir, eski yedek (.bak) silinir.
                </span>
              </div>
              <div className="set-fields">
                <label className="set-field">
                  Mevcut parola
                  <input ref={cur} className="text-input" type="password" autoComplete="off" />
                </label>
                <label className="set-field">
                  Yeni parola
                  <input ref={nw} className="text-input" type="password" autoComplete="new-password" />
                </label>
                <label className="set-field">
                  Yeni parola (tekrar)
                  <input ref={cf} className="text-input" type="password" autoComplete="new-password" />
                </label>
              </div>
              <div className="set-actions">
                <button type="submit" className="btn btn-accent" disabled={busy}>
                  Parolayı değiştir
                </button>
              </div>
            </form>
          </>
        )}

        {category === "autotype" && (
          <section className="set-card">
            <Row
              title={<label htmlFor="s-hotkey">Otomatik yazma kısayolu</label>}
              text="Öndeki pencerenin başlığına uyan tek kaydın kullanıcı adını ve parolasını yazar. Birden fazla kayıt uyarsa ya da hiç uymazsa hiçbir şey yazılmaz."
            >
              <select
                id="s-hotkey"
                className="text-input set-select"
                value={settings?.autotypeShortcut ?? ""}
                disabled={off}
                onChange={(e) => void change({ autotypeShortcut: e.target.value as api.Shortcut })}
              >
                {api.SHORTCUTS.map((s) => (
                  <option key={s.value} value={s.value}>
                    {s.label}
                  </option>
                ))}
              </select>
            </Row>
            {settings !== null && settings.autotypeShortcut !== "off" && hotkeyOk === false && (
              <p className="warn set-note">
                Bu kısayol başka bir program tarafından kullanılıyor, bu yüzden çalışmıyor. Başka
                bir kısayol seçin.
              </p>
            )}
          </section>
        )}

        {category === "look" && (
          <section className="set-card">
            <Row title={<label htmlFor="s-theme">Tema</label>} text="“Windows ile aynı” seçiliyken Windows’un açık ya da koyu ayarına uyar.">
              <select
                id="s-theme"
                className="text-input set-select"
                value={settings?.theme ?? "system"}
                disabled={off}
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
            </Row>
          </section>
        )}

        {category === "window" && (
          <section className="set-card">
            <Row
              title={<label htmlFor="s-tray">Kapatınca arka planda çalışmaya devam etsin</label>}
              text="Pencereyi kapattığınızda LockAlperen kapanmaz; görev çubuğunun sağında, saatin yanındaki simgelerin arasında çalışır. Oradan tıklayarak yeniden açabilirsiniz. Tamamen kapatmak için o simgeye sağ tıklayıp “Kilitle ve çık”ı seçin. Arka plandayken de otomatik kilit çalışır."
            >
              <input
                id="s-tray"
                type="checkbox"
                className="switch"
                checked={settings?.closeToTray ?? true}
                disabled={off}
                onChange={(e) => void change({ closeToTray: e.target.checked })}
              />
            </Row>
          </section>
        )}

        {category === "updates" && settings !== null && (
          <section className="set-card pad">
            <UpdateSettings
              checkUpdates={settings.checkUpdates}
              onCheckUpdates={(on) => void change({ checkUpdates: on })}
            />
          </section>
        )}

        {category === "data" && (
          <>
            <section className="set-card">
              <Row
                title="KeePass'ten içe aktar"
                text="KDBX 4 kasası. Kayıtlar yeni bir klasöre eklenir; KeePass dosyası değişmez."
              >
                <button type="button" className="btn" onClick={props.onImport}>
                  <DownloadIcon />
                  İçe aktar…
                </button>
              </Row>
            </section>
            <form className="set-card pad" onSubmit={exportCsv}>
              <div className="set-text">
                <span className="set-title">Dışa aktar (CSV)</span>
                <span className="muted small">
                  Bütün kayıtlar parolalarıyla birlikte <strong>şifresiz</strong> bir dosyaya
                  yazılır. Onay için ana parolanızı girin.
                </span>
              </div>
              <div className="set-fields">
                <label className="set-field">
                  Ana parola
                  <input ref={exp} className="text-input" type="password" autoComplete="off" />
                </label>
              </div>
              <div className="set-actions">
                <button type="submit" className="btn" disabled={busy}>
                  Dışa aktar…
                </button>
              </div>
            </form>
          </>
        )}

        {msg && (
          <p className="muted small" role="status">
            {msg}
          </p>
        )}
        {error && <p className="error">{error}</p>}
      </main>
    </div>
  );
}
