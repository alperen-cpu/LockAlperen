// "Kasa" settings page (KeePass "Database Settings") and the extra
// import/export tools (merge, KeePass export, printable page). Passwords are
// uncontrolled inputs, read once and cleared on submit: never React state.
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import * as api from "./api";
import type { EntrySummary } from "./api";
import { ConfirmDialog } from "./Confirm";

function take(r: React.RefObject<HTMLInputElement | null>) {
  const v = r.current?.value ?? "";
  if (r.current) r.current.value = "";
  return v;
}

function Card(props: { title: string; text: ReactNode; children: ReactNode; onSubmit?: (e: FormEvent) => void }) {
  return (
    <form className="set-card pad" onSubmit={props.onSubmit ?? ((e) => e.preventDefault())}>
      <div className="set-text">
        <span className="set-title">{props.title}</span>
        <span className="muted small">{props.text}</span>
      </div>
      {props.children}
    </form>
  );
}

function PasswordField(props: { label: string; inputRef: React.RefObject<HTMLInputElement | null>; autoComplete?: string }) {
  return (
    <label className="set-field">
      {props.label}
      <input
        ref={props.inputRef}
        className="text-input"
        type="password"
        autoComplete={props.autoComplete ?? "off"}
      />
    </label>
  );
}

export function VaultSettingsPanel(props: {
  busy: boolean;
  setBusy: (b: boolean) => void;
  onMsg: (m: string | null) => void;
  onEntries: (entries: EntrySummary[]) => void;
}) {
  const [v, setV] = useState<api.VaultSettings | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [historyLimit, setHistoryLimit] = useState(20);
  const [kdf, setKdf] = useState({ memoryMib: 64, iterations: 3, parallelism: 4 });
  const [keyfileName, setKeyfileName] = useState<string | null>(null);
  const [askClear, setAskClear] = useState<number | null | undefined>(undefined);
  const kdfPw = useRef<HTMLInputElement>(null);
  const kfPw = useRef<HTMLInputElement>(null);
  const { busy, setBusy, onMsg } = props;

  async function reload() {
    try {
      const s = await api.vaultSettings();
      setV(s);
      setName(s.name);
      setDescription(s.description);
      setHistoryLimit(s.historyLimit);
      setKdf(s.kdf);
    } catch (e) {
      onMsg(api.errorText(e));
    }
  }
  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function run(work: () => Promise<string | null>) {
    setBusy(true);
    onMsg(null);
    try {
      onMsg(await work());
      await reload();
    } catch (e) {
      onMsg(api.errorText(e));
    } finally {
      setBusy(false);
    }
  }

  const general = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      props.onEntries(await api.setVaultSettings(name, description, historyLimit));
      return "Kasa ayarları kaydedildi.";
    });
  };

  const changeKdf = (e: FormEvent) => {
    e.preventDefault();
    const pw = take(kdfPw);
    void run(async () => {
      await api.changeKdf(pw, kdf.memoryMib, kdf.iterations, kdf.parallelism);
      return "Şifreleme gücü değiştirildi; yeni tuz ve anahtar üretildi, eski yedek (.bak) silindi.";
    });
  };

  const changeKeyfile = (usePending: boolean) => {
    const pw = take(kfPw);
    void run(async () => {
      await api.changeKeyfile(pw, usePending);
      setKeyfileName(null);
      return usePending
        ? "Anahtar dosyası ayarlandı. Kasayı açmak için artık bu dosya da gerekiyor: bir kopyasını güvenli bir yerde saklayın."
        : "Anahtar dosyası kaldırıldı. Kasa artık yalnızca ana parolayla açılıyor.";
    });
  };

  if (!v) return null;
  const preset = api.KDF_PRESETS.find(
    (p) =>
      p.memoryMib === kdf.memoryMib && p.iterations === kdf.iterations && p.parallelism === kdf.parallelism,
  );

  return (
    <>
      <Card title="Genel" text="Kasanın adı ana klasörde de görünür." onSubmit={general}>
        <div className="set-fields">
          <label className="set-field">
            Kasa adı
            <input
              className="text-input"
              value={name}
              maxLength={256}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <label className="set-field wide-field">
            Açıklama
            <textarea
              className="text-input textarea"
              value={description}
              maxLength={10000}
              onChange={(e) => setDescription(e.target.value)}
            />
          </label>
          <label className="set-field">
            Kayıt başına geçmiş sürüm
            <input
              className="text-input"
              type="number"
              min={0}
              max={100}
              value={historyLimit}
              onChange={(e) => setHistoryLimit(Math.max(0, Math.min(100, Number(e.target.value) || 0)))}
            />
          </label>
        </div>
        <div className="set-actions">
          <button type="submit" className="btn btn-accent" disabled={busy}>
            Kaydet
          </button>
        </div>
      </Card>

      <Card
        title="Geçmişi temizle"
        text={`Kayıtların eski sürümleri (eski parolalar dahil). Şu an ${v.historyVersions} sürüm var.`}
      >
        <div className="set-actions">
          <button type="button" className="btn" disabled={busy || v.historyVersions === 0} onClick={() => setAskClear(365)}>
            1 yıldan eskileri sil
          </button>
          <button type="button" className="btn" disabled={busy || v.historyVersions === 0} onClick={() => setAskClear(90)}>
            90 günden eskileri sil
          </button>
          <button type="button" className="btn danger" disabled={busy || v.historyVersions === 0} onClick={() => setAskClear(null)}>
            Hepsini sil
          </button>
        </div>
      </Card>
      {askClear !== undefined && (
        <ConfirmDialog
          title="Geçmiş silinsin mi?"
          confirmLabel="Kalıcı olarak sil"
          danger
          busy={busy}
          onCancel={() => setAskClear(undefined)}
          onConfirm={() => {
            const days = askClear;
            setAskClear(undefined);
            void run(async () => {
              const n = await api.clearHistory(days);
              return `${n} eski sürüm silindi.`;
            });
          }}
        >
          <p>
            {askClear === null
              ? "Bütün kayıtların bütün eski sürümleri"
              : `${askClear} günden eski sürümler`}{" "}
            kalıcı olarak silinecek. Şimdiki değerler değişmez.
          </p>
          <p className="warn">Bu işlem geri alınamaz.</p>
        </ConfirmDialog>
      )}

      <Card
        title="Şifreleme gücü (Argon2id)"
        text={
          <>
            Şu an: {v.kdf.memoryMib} MiB bellek, {v.kdf.iterations} geçiş, {v.kdf.parallelism} iş
            parçacığı. Daha yüksek değerler parola tahminini zorlaştırır ama kilidi açmayı da
            yavaşlatır. Bu bilgisayarda birkaç saniyeyi geçmeyecek bir değer seçin.
          </>
        }
        onSubmit={changeKdf}
      >
        <div className="set-fields">
          <label className="set-field">
            Hazır ayar
            <select
              className="text-input"
              value={preset?.label ?? ""}
              onChange={(e) => {
                const p = api.KDF_PRESETS.find((x) => x.label === e.target.value);
                if (p) setKdf({ memoryMib: p.memoryMib, iterations: p.iterations, parallelism: p.parallelism });
              }}
            >
              <option value="">Özel</option>
              {api.KDF_PRESETS.map((p) => (
                <option key={p.label} value={p.label}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>
          <label className="set-field">
            Bellek (MiB, 19–1024)
            <input
              className="text-input"
              type="number"
              min={19}
              max={1024}
              value={kdf.memoryMib}
              onChange={(e) => setKdf({ ...kdf, memoryMib: Number(e.target.value) })}
            />
          </label>
          <label className="set-field">
            Geçiş (2–20)
            <input
              className="text-input"
              type="number"
              min={2}
              max={20}
              value={kdf.iterations}
              onChange={(e) => setKdf({ ...kdf, iterations: Number(e.target.value) })}
            />
          </label>
          <label className="set-field">
            İş parçacığı (1–16)
            <input
              className="text-input"
              type="number"
              min={1}
              max={16}
              value={kdf.parallelism}
              onChange={(e) => setKdf({ ...kdf, parallelism: Number(e.target.value) })}
            />
          </label>
          <PasswordField label="Ana parola" inputRef={kdfPw} />
        </div>
        <div className="set-actions">
          <button type="submit" className="btn btn-accent" disabled={busy}>
            {busy ? "Uygulanıyor…" : "Uygula"}
          </button>
        </div>
      </Card>

      <Card
        title="Anahtar dosyası"
        text={
          v.keyfileRequired
            ? `Kasa ana parola ve anahtar dosyasıyla açılıyor${v.keyfileName ? ` (${v.keyfileName})` : ""}.`
            : "Kasa yalnızca ana parolayla açılıyor. Anahtar dosyası eklerseniz kasayı açmak için ikisi de gerekir."
        }
      >
        <div className="set-actions">
          <button
            type="button"
            className="btn"
            disabled={busy}
            onClick={async () => {
              try {
                const n = await api.pickNewKeyfile(true);
                if (n) setKeyfileName(n);
              } catch (e) {
                onMsg(api.errorText(e));
              }
            }}
          >
            Yeni anahtar dosyası oluştur…
          </button>
          <button
            type="button"
            className="btn"
            disabled={busy}
            onClick={async () => {
              try {
                const n = await api.pickNewKeyfile(false);
                if (n) setKeyfileName(n);
              } catch (e) {
                onMsg(api.errorText(e));
              }
            }}
          >
            Var olan dosyayı seç…
          </button>
        </div>
        <div className="set-fields">
          <PasswordField label="Ana parola" inputRef={kfPw} />
        </div>
        <div className="set-actions">
          {keyfileName && (
            <button type="button" className="btn btn-accent" disabled={busy} onClick={() => changeKeyfile(true)}>
              {v.keyfileRequired ? "Anahtar dosyasını değiştir" : "Anahtar dosyasını ekle"} ({keyfileName})
            </button>
          )}
          {v.keyfileRequired && (
            <button type="button" className="btn danger" disabled={busy} onClick={() => changeKeyfile(false)}>
              Anahtar dosyasını kaldır
            </button>
          )}
        </div>
      </Card>
    </>
  );
}

export function DataTools(props: {
  busy: boolean;
  setBusy: (b: boolean) => void;
  onMsg: (m: string | null) => void;
  onEntries: (entries: EntrySummary[]) => void;
}) {
  const { busy, setBusy, onMsg } = props;
  const [mergeFile, setMergeFile] = useState<string | null>(null);
  const [mergeKey, setMergeKey] = useState<string | null>(null);
  const [withPasswords, setWithPasswords] = useState(true);
  const mergePw = useRef<HTMLInputElement>(null);
  const kdbxCur = useRef<HTMLInputElement>(null);
  const kdbxNew = useRef<HTMLInputElement>(null);
  const kdbxNew2 = useRef<HTMLInputElement>(null);
  const htmlCur = useRef<HTMLInputElement>(null);

  async function run(work: () => Promise<string | null>) {
    setBusy(true);
    onMsg(null);
    try {
      onMsg(await work());
    } catch (e) {
      onMsg(api.errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Card
        title="Başka bir kasayla birleştir"
        text="Başka bir cihazdaki ya da yedekteki .lav dosyasını bu kasaya katar (KeePass “Synchronize”). Aynı kayıt iki yerde değiştiyse yenisi kalır, eskisi geçmişe girer; bir tarafta kalıcı silinenler silinir. Diğer dosya değiştirilmez."
        onSubmit={(e) => {
          e.preventDefault();
          const pw = take(mergePw);
          void run(async () => {
            const r = await api.mergeVault(pw);
            props.onEntries(r.entries);
            setMergeFile(null);
            setMergeKey(null);
            const s = r.summary;
            return `Birleştirildi: ${s.added} yeni, ${s.updated} güncellenen, ${s.removed} silinen kayıt; ${s.groupsAdded} yeni klasör. Kasa kaydedildi.`;
          });
        }}
      >
        <div className="set-actions">
          <button
            type="button"
            className="btn"
            disabled={busy}
            onClick={async () => {
              try {
                const n = await api.pickMergeFile();
                if (n) {
                  setMergeFile(n);
                  setMergeKey(null);
                }
              } catch (e) {
                onMsg(api.errorText(e));
              }
            }}
          >
            {mergeFile ? `Dosya: ${mergeFile}` : "Kasa dosyası seç…"}
          </button>
          {mergeFile && (
            <button
              type="button"
              className="btn"
              disabled={busy}
              onClick={async () => {
                try {
                  setMergeKey(await api.pickMergeKeyfile());
                } catch (e) {
                  onMsg(api.errorText(e));
                }
              }}
            >
              {mergeKey ? `Anahtar dosyası: ${mergeKey}` : "Anahtar dosyası (varsa)…"}
            </button>
          )}
        </div>
        {mergeFile && (
          <>
            <div className="set-fields">
              <PasswordField label="O kasanın ana parolası" inputRef={mergePw} />
            </div>
            <div className="set-actions">
              <button type="submit" className="btn btn-accent" disabled={busy}>
                {busy ? "Birleştiriliyor…" : "Birleştir"}
              </button>
            </div>
          </>
        )}
      </Card>

      <Card
        title="KeePass olarak dışa aktar (KDBX 4)"
        text="Bütün kayıtlar, klasörler, ekler, etiketler, son kullanma tarihleri, otomatik yazma ayarları ve renkler KeePass'in açabildiği şifreli bir dosyaya yazılır. Dosyaya ayrı bir parola verin. Geçmiş sürümler aktarılmaz."
        onSubmit={(e) => {
          e.preventDefault();
          const [c, n, n2] = [take(kdbxCur), take(kdbxNew), take(kdbxNew2)];
          if (n !== n2) {
            onMsg("KeePass dosyasının parolaları aynı değil.");
            return;
          }
          void run(async () =>
            (await api.exportKdbx(c, n))
              ? "KeePass dosyası yazıldı. Bu dosya kendi parolasıyla şifreli."
              : null,
          );
        }}
      >
        <div className="set-fields">
          <PasswordField label="Bu kasanın ana parolası" inputRef={kdbxCur} />
          <PasswordField label="KeePass dosyasının parolası" inputRef={kdbxNew} autoComplete="new-password" />
          <PasswordField label="KeePass dosyasının parolası (tekrar)" inputRef={kdbxNew2} autoComplete="new-password" />
        </div>
        <div className="set-actions">
          <button type="submit" className="btn" disabled={busy}>
            {busy ? "Yazılıyor…" : "Dışa aktar…"}
          </button>
        </div>
      </Card>

      <Card
        title="Yazdırılabilir sayfa (acil durum)"
        text={
          <>
            Kayıtlar klasörlere göre bir HTML sayfasına yazılır; tarayıcıda açıp yazdırabilirsiniz.
            Sayfa <strong>şifresizdir</strong>: yazdırdıktan sonra dosyayı silin. Geri Dönüşüm
            Kutusu'ndakiler dahil edilmez.
          </>
        }
        onSubmit={(e) => {
          e.preventDefault();
          const c = take(htmlCur);
          const when = new Date().toLocaleString("tr-TR");
          void run(async () =>
            (await api.exportHtml(c, withPasswords, when))
              ? "Sayfa yazıldı. Bu dosya ŞİFRESİZDİR: yazdırdıktan sonra güvenli biçimde silin."
              : null,
          );
        }}
      >
        <div className="set-fields">
          <label className="check">
            <input type="checkbox" checked={withPasswords} onChange={(e) => setWithPasswords(e.target.checked)} />
            Parolaları da yaz
          </label>
          <PasswordField label="Ana parola" inputRef={htmlCur} />
        </div>
        <div className="set-actions">
          <button type="submit" className="btn" disabled={busy}>
            Sayfayı oluştur…
          </button>
        </div>
      </Card>
    </>
  );
}
