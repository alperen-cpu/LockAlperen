// Detail-view sections below the main card: notes, custom fields, tags,
// attachments, history. Protected values and notes are fetched from Rust
// only when the user clicks "show", and dropped again after 15 s.
import { useEffect, useState } from "react";
import * as api from "./api";
import type { EntryExtras, Extra } from "./api";
import { CopyIcon, EyeIcon, EyeOffIcon, FileIcon } from "./icons";

const REVEAL_MS = 15_000;

function fmtDate(unix: number) {
  return new Date(unix * 1000).toLocaleString("tr-TR", {
    day: "numeric",
    month: "long",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmtSize(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** A value that is hidden until clicked; copy goes through Rust. */
function SecretValue(props: {
  id: string;
  what: Extra;
  label: string;
  onCopied: (msg: string) => void;
  multiline?: boolean;
}) {
  const [shown, setShown] = useState<string | null>(null);
  useEffect(() => {
    if (shown === null) return;
    const t = window.setTimeout(() => setShown(null), REVEAL_MS);
    return () => window.clearTimeout(t);
  }, [shown]);

  async function toggle() {
    if (shown !== null) return setShown(null);
    try {
      setShown(await api.revealExtra(props.id, props.what));
    } catch (e) {
      props.onCopied(api.errorText(e));
    }
  }
  async function copy() {
    try {
      const secs = await api.copyExtra(props.id, props.what);
      props.onCopied(`${props.label} kopyalandı · pano ${secs} sn sonra temizlenecek`);
    } catch (e) {
      props.onCopied(api.errorText(e));
    }
  }
  return (
    <>
      <span className={"value mono" + (props.multiline ? " notes" : "") + (shown === null ? " dots" : "")}>
        {shown ?? "••••••"}
      </span>
      <button
        type="button"
        className="icon-btn small-btn"
        aria-label={shown === null ? `${props.label} göster` : `${props.label} gizle`}
        onClick={toggle}
      >
        {shown === null ? <EyeIcon /> : <EyeOffIcon />}
      </button>
      <button type="button" className="icon-btn small-btn" aria-label={`${props.label} kopyala`} onClick={copy}>
        <CopyIcon />
      </button>
    </>
  );
}

export function ExtrasView(props: {
  id: string;
  /** Changes when the entry is saved, to refetch. */
  version: unknown;
  onToast: (msg: string) => void;
}) {
  const [x, setX] = useState<EntryExtras | null>(null);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    let alive = true;
    setX(null);
    setShowHistory(false);
    api.entryExtras(props.id).then(
      (v) => alive && setX(v),
      () => alive && setX(null),
    );
    return () => {
      alive = false;
    };
  }, [props.id, props.version]);

  if (!x) return null;

  async function saveAttachment(i: number) {
    try {
      if (await api.saveAttachment(props.id, i)) {
        props.onToast("Ek kaydedildi. Diske yazılan dosya şifreli DEĞİLDİR.");
      }
    } catch (e) {
      props.onToast(api.errorText(e));
    }
  }

  const hasBoxes = x.fields.length > 0 || x.tags.length > 0 || x.hasNotes || x.attachments.length > 0;

  return (
    <>
      {hasBoxes && (
        <div className="extras-grid">
          {(x.fields.length > 0 || x.tags.length > 0) && (
            <div className="card pad">
              {x.fields.length > 0 && <div className="lbl">Özel alanlar</div>}
              {x.fields.map((f, i) => (
                <div className="kv" key={i}>
                  <span className="muted ellipsis">{f.name}</span>
                  {f.protected ? (
                    <SecretValue id={props.id} what={{ kind: "custom", index: i }} label={f.name} onCopied={props.onToast} />
                  ) : (
                    <>
                      <span className="value ellipsis">{f.value}</span>
                      <button
                        type="button"
                        className="icon-btn small-btn"
                        aria-label={`${f.name} kopyala`}
                        onClick={async () => {
                          try {
                            const secs = await api.copyExtra(props.id, { kind: "custom", index: i });
                            props.onToast(`${f.name} kopyalandı · pano ${secs} sn sonra temizlenecek`);
                          } catch (e) {
                            props.onToast(api.errorText(e));
                          }
                        }}
                      >
                        <CopyIcon />
                      </button>
                    </>
                  )}
                </div>
              ))}
              {x.tags.length > 0 && <div className="lbl">Etiketler</div>}
              {x.tags.length > 0 && (
                <div className="chips">
                  {x.tags.map((t) => (
                    <span key={t} className="chip">
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
          {(x.hasNotes || x.attachments.length > 0) && (
            <div className="card pad">
              {x.hasNotes && (
                <>
                  <div className="lbl">Notlar</div>
                  <div className="kv">
                    <SecretValue id={props.id} what={{ kind: "notes" }} label="Notlar" onCopied={props.onToast} multiline />
                  </div>
                </>
              )}
              {x.attachments.length > 0 && <div className="lbl">Ekler</div>}
              {x.attachments.map((a, i) => (
                <div className="kv" key={i}>
                  <FileIcon />
                  <span className="value ellipsis">{a.name}</span>
                  <span className="muted small">{fmtSize(a.size)}</span>
                  <button
                    type="button"
                    className="btn small-text"
                    title="Diske şifresiz olarak kaydedilir"
                    onClick={() => saveAttachment(i)}
                  >
                    Kaydet…
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="meta-line muted small">
        <span>Oluşturuldu: {fmtDate(x.created)}</span>
        <span>Değiştirildi: {fmtDate(x.modified)}</span>
        {x.history.length > 0 && (
          <button type="button" className="link" onClick={() => setShowHistory((v) => !v)}>
            Geçmiş ({x.history.length} sürüm)
          </button>
        )}
      </div>
      {showHistory && (
        <ul className="history card pad">
          {x.history.map((v, i) => (
            <li key={i}>
              <span className="muted">{fmtDate(v.modified)}</span>
              <span className="ellipsis">{v.title}</span>
              <span className="muted ellipsis">{v.username}</span>
              {v.passwordDiffers && <span className="badge">Farklı parola</span>}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
