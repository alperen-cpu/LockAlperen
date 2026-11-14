// "KeePass'ten içe aktar" (design board 4), simplified: the import goes into
// the open vault under a new folder; the summary is shown afterwards.
import { useEffect, useRef, useState, type FormEvent } from "react";
import * as api from "./api";
import type { EntrySummary, ImportSummary } from "./api";
import { FileIcon } from "./icons";

export function ImportDialog(props: {
  fileName: string;
  onDone: (entries: EntrySummary[]) => void;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportSummary | null>(null);
  const [keyName, setKeyName] = useState<string | null>(null);
  // KeePass master password: uncontrolled, cleared on submit, never state.
  const pwRef = useRef<HTMLInputElement>(null);

  // Esc closes (not while the import runs).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) props.onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  async function submit(ev: FormEvent) {
    ev.preventDefault();
    const input = pwRef.current;
    if (!input || busy) return;
    const password = input.value;
    input.value = "";
    setBusy(true);
    setError(null);
    try {
      const r = await api.importKdbx(password);
      setResult(r.summary);
      props.onDone(r.entries);
    } catch (e) {
      setError(api.errorText(e));
      input.focus();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-back" role="dialog" aria-modal="true" aria-labelledby="imp-title">
      <div className="modal">
        <h2 id="imp-title">KeePass'ten içe aktar</h2>
        <div className="imp-file">
          <FileIcon />
          <span className="ellipsis">{props.fileName}</span>
        </div>

        {result ? (
          <>
            <p className="muted small">
              Kayıtlar <strong>{result.folder}</strong> klasörüne eklendi ve kasa kaydedildi.
              KeePass dosyanız değiştirilmedi.
            </p>
            <div className="stats">
              <div>
                <b>{result.entries}</b>
                <span>kayıt</span>
              </div>
              <div>
                <b>{result.groups}</b>
                <span>klasör</span>
              </div>
              <div>
                <b>{result.totp}</b>
                <span>TOTP</span>
              </div>
              <div>
                <b>{result.attachments}</b>
                <span>ek dosya</span>
              </div>
              <div>
                <b>{result.customFields}</b>
                <span>özel alan</span>
              </div>
            </div>
            {(result.skippedRecycleBin > 0 || result.skippedHistory > 0) && (
              <p className="muted small">
                Aktarılmayanlar: Geri Dönüşüm Kutusu'ndaki {result.skippedRecycleBin} kayıt,{" "}
                {result.skippedHistory} eski sürüm (geçmiş henüz aktarılmıyor).
              </p>
            )}
            <div className="form-buttons">
              <button type="button" className="btn btn-accent wide" onClick={props.onClose} autoFocus>
                Tamam
              </button>
            </div>
          </>
        ) : (
          <form onSubmit={submit} className="modal-form">
            <p className="muted small">
              Dosya bu bilgisayarda çözülür ve kayıtlar açık kasaya yeni bir klasör olarak eklenir.
              Yalnızca KDBX 4 (KeePass 2.35+) desteklenir.
            </p>
            <button
              type="button"
              className="btn btn-left"
              disabled={busy}
              onClick={async () => {
                try {
                  const n = await api.pickImportKeyfile();
                  if (n !== null) setKeyName(n);
                } catch (e) {
                  setError(api.errorText(e));
                }
              }}
            >
              <FileIcon />
              <span className="ellipsis">{keyName ? `Anahtar dosyası: ${keyName}` : "KeePass anahtar dosyası (isteğe bağlı)…"}</span>
            </button>
            <div className="field">
              <label className="lbl" htmlFor="kp-pw">
                KeePass ana parolası
              </label>
              <input
                id="kp-pw"
                ref={pwRef}
                className="text-input"
                type="password"
                autoComplete="off"
                spellCheck={false}
                readOnly={busy}
                autoFocus
              />
            </div>
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            <div className="form-buttons">
              <button type="button" className="btn wide" onClick={props.onClose} disabled={busy}>
                Vazgeç
              </button>
              <button type="submit" className="btn btn-accent wide" disabled={busy}>
                {busy ? "Aktarılıyor…" : "İçe aktar"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
