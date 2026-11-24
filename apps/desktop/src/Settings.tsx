// Settings page (design: "Ayarlar"). Only non-secret preferences; applied and
// saved by Rust. Master-password and export inputs are uncontrolled and
// cleared on submit: passwords never become React state.
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import * as api from "./api";
import { UpdateSettings } from "./Update";
import { DataTools, DrivePanel, VaultSettingsPanel } from "./VaultTools";
import { BackIcon, DownloadIcon } from "./icons";

type Category =
  | "security"
  | "vault"
  | "autotype"
  | "generator"
  | "look"
  | "window"
  | "keys"
  | "drive"
  | "browser"
  | "updates"
  | "data";

/** Keyboard shortcuts of the vault screen (App.tsx and Editor.tsx). */
const KEYS: [string, string][] = [
  ["Ctrl+C", "Farenin üzerinde durduğu kullanıcı adını ya da parolayı kopyalar. Fare bir değerin üzerinde değilse seçili kaydın parolasını kopyalar. Metin seçiliyse seçili metni kopyalar."],
  ["Ctrl+B", "Seçili kaydın kullanıcı adını kopyalar."],
  ["Ctrl+U", "Seçili kaydın web sitesini tarayıcıda açar."],
  ["Ctrl+E ya da Enter", "Seçili kaydı düzenler."],
  ["Delete", "Seçili kaydı siler (önce sorar; Geri Dönüşüm Kutusu'ndaysa kalıcı olarak)."],
  ["Ctrl+K", "Seçili kaydı çoğaltır."],
  ["Ctrl+N", "Yeni kayıt."],
  ["Ctrl+F", "Aramaya geçer."],
  ["Ctrl+L", "Kasayı kilitler."],
  ["Ctrl+S", "Düzenlerken kaydeder."],
  ["Esc", "Düzenleyiciyi ya da açık pencereyi kapatır."],
  ["← / →", "Liste ile ayrıntı paneli arasındaki çubuk seçiliyken paneli genişletir ya da daraltır (Shift ile daha hızlı)."],
];

const CATEGORIES: { id: Category; label: string; intro: string }[] = [
  {
    id: "security",
    label: "Güvenlik",
    intro: "Bu ayarlar bilgisayarınızda saklanır; kasanın içeriğini değiştirmez.",
  },
  {
    id: "vault",
    label: "Kasa",
    intro:
      "Açık kasanın kendi ayarları (KeePass “Veritabanı ayarları”): kasanın içinde saklanır, kasayla birlikte taşınır.",
  },
  // Not on Linux yet (src-tauri/src/linux/hotkey.rs).
  ...(api.IS_LINUX
    ? []
    : [
        {
          id: "autotype" as const,
          label: "Otomatik yazma",
          intro: "Kullanıcı adını ve parolayı başka bir pencereye yazma.",
        },
      ]),
  {
    id: "generator",
    label: "Parola üretici",
    intro: "Yeni kayıtlar için üretilen parolanın ayarları (KeePass'teki otomatik üretilen parola profili).",
  },
  { id: "look", label: "Görünüm", intro: "Renk teması." },
  {
    id: "window",
    label: "Pencere",
    intro: api.IS_LINUX
      ? "Pencerenin nasıl davranacağı ve oturum açılışında başlatma."
      : "Pencerenin nasıl davranacağı, kısayol ve Windows ile başlatma.",
  },
  {
    id: "keys",
    label: "Klavye kısayolları",
    intro: "Kasa açıkken çalışan kısayollar. Bir yazı alanındayken çalışmazlar.",
  },
  {
    id: "drive",
    label: "Google Drive",
    intro: "Kasanızı Google Drive'a yedekleyin. Yalnızca şifreli kasa dosyası yüklenir.",
  },
  {
    id: "browser",
    label: "Tarayıcı eklentisi",
    intro:
      "Chrome, Chromium, Brave ve Edge'de giriş bilgilerini doldurur. Eklenti ana parolanızı hiçbir zaman sormaz; kasa yalnızca bu uygulamada açılır.",
  },
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

export function SettingsPage(props: {
  onClose: () => void;
  onImport: () => void;
  onEntries: (entries: api.EntrySummary[]) => void;
}) {
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
  const [showKeyOk, setShowKeyOk] = useState<boolean | null>(null);
  const refreshHotkey = () =>
    // The hotkey thread applies the setting asynchronously.
    window.setTimeout(
      () =>
        api.hotkeyActive().then(
          (r) => {
            setHotkeyOk(r.autotype);
            setShowKeyOk(r.showWindow);
          },
          () => {
            setHotkeyOk(null);
            setShowKeyOk(null);
          },
        ),
      300,
    );
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

  type BoolKey = {
    [K in keyof api.Settings]: api.Settings[K] extends boolean ? K : never;
  }[keyof api.Settings];
  /** One on/off setting row. */
  function toggle(key: BoolKey, title: string, text: string) {
    const id = `s-${key}`;
    return (
      <Row title={<label htmlFor={id}>{title}</label>} text={text}>
        <input
          id={id}
          type="checkbox"
          className="switch"
          checked={settings?.[key] ?? false}
          disabled={off}
          onChange={(e) => void change({ [key]: e.target.checked } as Partial<api.Settings>)}
        />
      </Row>
    );
  }

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
                text={
                  api.IS_LINUX
                    ? "Ekran kilitlenince (Super+L), uyku moduna geçince, oturum kapanınca ya da başka bir kullanıcıya geçilince kasa kilitlenir. Kilitliyken pencere simgesinde kırmızı kilit görünür."
                    : "Win+L'ye basınca, uyku moduna geçince ya da oturum kapanınca kasa kilitlenir. Kilitliyken görev çubuğu simgesinde kırmızı kilit görünür."
                }
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
              {toggle(
                "lockOnMinimize",
                "Pencere küçültülünce kilitle",
                "Pencereyi küçültünce kasa kilitlenir. Otomatik yazma ve “kopyalayınca küçült” bunu tetiklemez.",
              )}
              {toggle(
                "exitInsteadOfLock",
                "Süre dolunca kilitlemek yerine kapat",
                "Otomatik kilit süresi dolunca kasa kilitlenir ve uygulama tamamen kapanır.",
              )}
              {toggle(
                "showExpiredOnOpen",
                "Açınca süresi dolan kayıtları göster",
                "Kilidi açınca süresi dolmuş ya da 7 gün içinde dolacak kayıt varsa bildirir ve Parola sağlığı listesini açar.",
              )}
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
              text="Öndeki pencerenin başlığına uyan tek kaydın kullanıcı adını ve parolasını yazar. Birden fazla kayıt uyarsa ya da hiç uymazsa hiçbir şey yazılmaz. Kayıttaki “Otomatik yaz” düğmesi ise kaydın web sitesi varsa önce siteyi tarayıcıda yeni sekmede açar, sayfa yüklenip başlığı doğrulanınca yazar."
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
            <Row
              title={<label htmlFor="s-theme">Tema</label>}
              text={
                api.IS_LINUX
                  ? "“Sistemle aynı” seçiliyken masaüstünün açık ya da koyu ayarına uyar."
                  : "“Windows ile aynı” seçiliyken Windows’un açık ya da koyu ayarına uyar."
              }
            >
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
                <option value="system">{api.IS_LINUX ? "Sistemle aynı" : "Windows ile aynı"}</option>
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
              text={
                api.IS_LINUX
                  ? "Pencereyi kapattığınızda LockAlperen kapanmaz; üst çubuğun sağındaki simgelerin arasında çalışır. O simgenin menüsünden “LockAlperen'i göster” ile yeniden açabilir, “Kilitle ve çık” ile tamamen kapatabilirsiniz. Arka plandayken de otomatik kilit çalışır."
                  : "Pencereyi kapattığınızda LockAlperen kapanmaz; görev çubuğunun sağında, saatin yanındaki simgelerin arasında çalışır. Oradan tıklayarak yeniden açabilirsiniz. Tamamen kapatmak için o simgeye sağ tıklayıp “Kilitle ve çık”ı seçin. Arka plandayken de otomatik kilit çalışır."
              }
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
            {toggle(
              "minimizeToTray",
              "Küçültünce görev çubuğunda gösterme",
              api.IS_LINUX
                ? "Küçült düğmesine basınca pencere görev çubuğundan da kaybolur; LockAlperen üst çubuktaki simgesinde çalışmaya devam eder. O simgenin menüsünden geri açabilirsiniz."
                : "Küçült düğmesine basınca pencere görev çubuğundan da kaybolur; LockAlperen saatin yanındaki simgelerin arasında çalışmaya devam eder. Oradaki simgeye tıklayarak geri açabilirsiniz.",
            )}
            {toggle(
              "minimizeAfterCopy",
              "Kopyaladıktan sonra pencereyi küçült",
              "Kullanıcı adı, parola ya da kod kopyalanınca pencere küçülür; yapıştıracağınız pencere öne gelir.",
            )}
            {toggle(
              "minimizeOnLock",
              "Kilitleyince pencereyi küçült",
              "Kasa elle ya da otomatik kilitlenince pencere küçülür.",
            )}
            {toggle("alwaysOnTop", "Her zaman üstte", "Pencere diğer pencerelerin üzerinde kalır.")}
            {toggle(
              "startMinimized",
              "Küçültülmüş başlat",
              "Uygulama açılınca pencere açılmaz, görev çubuğunda küçük başlar (yukarıdaki ayar açıksa yalnızca saatin yanındaki simgede durur). Kasa her zaman kilitli başlar.",
            )}
            {toggle(
              "runAtStartup",
              api.IS_LINUX ? "Oturum açılışında başlat" : "Windows açılışında başlat",
              "Oturum açınca LockAlperen kendiliğinden başlar (yalnızca sizin kullanıcı hesabınız için; yönetici izni gerekmez).",
            )}
            {/* Global shortcuts: Windows only for now (src-tauri/src/linux/hotkey.rs). */}
            {!api.IS_LINUX && (
              <Row
                title={<label htmlFor="s-show">Pencereyi gösterme kısayolu</label>}
                text="Her yerden basınca LockAlperen penceresi öne gelir."
              >
                <select
                  id="s-show"
                  className="text-input set-select"
                  value={settings?.showWindowShortcut ?? ""}
                  disabled={off}
                  onChange={(e) =>
                    void change({ showWindowShortcut: e.target.value as api.ShowShortcut })
                  }
                >
                  {api.SHOW_SHORTCUTS.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </Row>
            )}
            {!api.IS_LINUX && settings !== null && settings.showWindowShortcut !== "off" && showKeyOk === false && (
              <p className="warn set-note">
                Bu kısayol başka bir program tarafından kullanılıyor (ör. açık olan KeePass), bu
                yüzden çalışmıyor. KeePass'i kapatın ya da başka bir kısayol seçin.
              </p>
            )}
          </section>
        )}

        {category === "generator" && settings !== null && (
          <section className="set-card">
            {toggle(
              "autoGeneratePassword",
              "Yeni kayda otomatik parola üret",
              "Yeni kayıt açılınca parola alanı aşağıdaki ayarlarla üretilmiş bir parolayla dolu gelir.",
            )}
            <Row
              title={<label htmlFor="s-len">Uzunluk</label>}
              text={`${api.GEN_MIN_LENGTH}–${api.GEN_MAX_LENGTH} karakter.`}
            >
              <input
                id="s-len"
                type="number"
                className="text-input set-select"
                min={api.GEN_MIN_LENGTH}
                max={api.GEN_MAX_LENGTH}
                value={settings.generator.length}
                onChange={(e) => {
                  const n = Number(e.target.value);
                  if (Number.isFinite(n) && n >= api.GEN_MIN_LENGTH && n <= api.GEN_MAX_LENGTH) {
                    void change({ generator: { ...settings.generator, length: n } });
                  }
                }}
              />
            </Row>
            {(
              [
                ["uppercase", "Büyük harf (A–Z)"],
                ["lowercase", "Küçük harf (a–z)"],
                ["digits", "Rakam (0–9)"],
                ["symbols", "Sembol (!@#…)"],
                ["excludeAmbiguous", "Karışabilen karakterleri çıkar (I, l, 1, O, 0…)"],
              ] as const
            ).map(([k, label]) => (
              <Row key={k} title={<label htmlFor={`s-g-${k}`}>{label}</label>}>
                <input
                  id={`s-g-${k}`}
                  type="checkbox"
                  className="switch"
                  checked={settings.generator[k]}
                  onChange={(e) =>
                    void change({ generator: { ...settings.generator, [k]: e.target.checked } })
                  }
                />
              </Row>
            ))}
          </section>
        )}

        {category === "keys" && (
          <section className="set-card">
            {KEYS.map(([k, text]) => (
              <Row key={k} title={<span className="kbd">{k}</span>} text={text} />
            ))}
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
            <DataTools busy={busy} setBusy={setBusy} onMsg={setMsg} onEntries={props.onEntries} />
          </>
        )}

        {category === "drive" && <DrivePanel busy={busy} setBusy={setBusy} onMsg={setMsg} />}

        {category === "browser" && <BrowserPanel busy={busy} setBusy={setBusy} onMsg={setMsg} />}

        {category === "vault" && (
          <VaultSettingsPanel
            busy={busy}
            setBusy={setBusy}
            onMsg={setMsg}
            onEntries={props.onEntries}
          />
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

function when(sec: number): string {
  return new Date(sec * 1000).toLocaleString("tr-TR", { dateStyle: "medium", timeStyle: "short" });
}

/** Settings › Tarayıcı eklentisi (src-tauri/src/bridge/). */
function BrowserPanel(props: {
  busy: boolean;
  setBusy: (b: boolean) => void;
  onMsg: (m: string | null) => void;
}) {
  const { busy, setBusy, onMsg } = props;
  const [st, setSt] = useState<api.BridgeStatus | null>(null);

  useEffect(() => {
    api.bridgeStatus().then(setSt, (e) => onMsg(api.errorText(e)));
    // Pairings and "last used" change while this page is open.
    const t = window.setInterval(() => {
      api.bridgeStatus().then(setSt, () => {});
    }, 3000);
    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function run(work: () => Promise<api.BridgeStatus>, done: string | null) {
    setBusy(true);
    onMsg(null);
    try {
      setSt(await work());
      onMsg(done);
    } catch (e) {
      onMsg(api.errorText(e));
    } finally {
      setBusy(false);
    }
  }

  if (!st) return null;
  if (!st.supported) {
    return (
      <section className="set-card pad">
        <p className="muted small">Tarayıcı eklentisi şimdilik yalnızca Linux sürümünde var.</p>
      </section>
    );
  }

  return (
    <>
      <section className="set-card">
        <Row
          title={<label htmlFor="s-bridge">Tarayıcı eklentisine izin ver</label>}
          text={
            st.enabled
              ? st.browsers.length
                ? `Bağlantı kurulu: ${st.browsers.join(", ")}. Yeni kurulan bir tarayıcı için kapatıp yeniden açın.`
                : "Açık, ama desteklenen bir tarayıcı bulunamadı."
              : "Kapalıyken tarayıcılar uygulamaya hiç bağlanamaz."
          }
        >
          <input
            id="s-bridge"
            type="checkbox"
            className="switch"
            checked={st.enabled}
            disabled={busy}
            onChange={(e) => {
              const on = e.target.checked;
              void run(
                () => api.bridgeSetEnabled(on),
                on ? "Bağlantı kuruldu. Tarayıcıyı yeniden başlatın." : "Bağlantı kaldırıldı.",
              );
            }}
          />
        </Row>
      </section>

      <section className="set-card pad">
        <div className="set-text">
          <span className="set-title">Eklentiyi kurma</span>
          <span className="muted small">
            1. Tarayıcıda <span className="kbd">chrome://extensions</span> sayfasını açın ve
            “Geliştirici modu”nu açın. 2. “Paketlenmemiş öğe yükle” ile LockAlperen klasöründeki{" "}
            <span className="kbd">apps/browser-extension</span> klasörünü seçin. 3. Eklenti
            simgesine tıklayıp “Masaüstü uygulamasıyla eşleştir” deyin; iki tarafta görünen kod
            aynıysa burada açılan pencerede “Eşleştir”e basın.
          </span>
          <span className="muted small">
            Eklenti kimliği: <span className="kbd">{st.extensionId}</span>. Snap ve Flatpak
            tarayıcılar desteklenmez (uygulamayı başlatamazlar).
          </span>
        </div>
      </section>

      <section className="set-card">
        {st.pairs.length === 0 ? (
          <Row title="Eşleştirilmiş tarayıcı yok" />
        ) : (
          st.pairs.map((p) => (
            <Row
              key={p.id}
              title={`Tarayıcı ${p.id}`}
              text={`Eşleştirildi: ${when(p.created)} · Son kullanım: ${when(p.lastUsed)}`}
            >
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={() => void run(() => api.bridgeRevoke(p.id), "Eşleştirme kaldırıldı.")}
              >
                Kaldır
              </button>
            </Row>
          ))
        )}
      </section>
    </>
  );
}
