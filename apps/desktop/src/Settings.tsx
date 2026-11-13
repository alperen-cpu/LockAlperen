// Settings dialog. Only non-secret preferences; applied and saved by Rust.
import { useEffect, useState } from "react";
import * as api from "./api";

export function SettingsDialog(props: { onClose: () => void }) {
  const [idle, setIdle] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getSettings().then(
      (s) => setIdle(s.idleMinutes),
      (e) => setError(api.errorText(e)),
    );
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") props.onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  async function change(v: number) {
    setIdle(v);
    try {
      const s = await api.setSettings({ idleMinutes: v });
      setIdle(s.idleMinutes);
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
          <label className="lbl" htmlFor="s-idle">
            Otomatik kilit (klavye ve fare kullanılmazsa)
          </label>
          <select
            id="s-idle"
            className="text-input"
            value={idle ?? ""}
            onChange={(e) => void change(Number(e.target.value))}
          >
            {api.IDLE_CHOICES.map((m) => (
              <option key={m} value={m}>
                {m} dakika
              </option>
            ))}
          </select>
        </div>
        <p className="muted small">
          Windows kilitlenince, oturum kapanınca ya da uyku moduna geçilince kasa her zaman hemen
          kilitlenir. Kopyalanan değerler 12 saniye sonra panodan silinir.
        </p>
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
