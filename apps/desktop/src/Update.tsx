// New-version notice and install flow. Rust finds, verifies and installs the
// update; the WebView only shows the version and asks the user.
import { useEffect, useState } from "react";
import * as api from "./api";
import type { AvailableUpdate } from "./api";

/** "Install?" with the consequences spelled out, then the install itself. */
export function UpdateOffer(props: { update: AvailableUpdate; onLater?: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function install() {
    setBusy(true);
    setError(null);
    try {
      // Rust asks for approval in a native dialog (false: declined). On
      // success the app exits and the installer restarts it.
      await api.installUpdate();
    } catch (e) {
      setError(api.errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="update-offer">
      <div>
        <strong>LockAlperen {props.update.version}</strong> yayınlandı.
      </div>
      {props.update.notes && <p className="update-notes muted small">{props.update.notes}</p>}
      {busy ? (
        <p className="muted small" role="status">
          Açılan pencerede onaylayın; ardından indirilip imzası doğrulanır…
        </p>
      ) : (
        <div className="update-buttons">
          <button type="button" className="btn btn-accent" onClick={install}>
            Güncelle
          </button>
          {props.onLater && (
            <button type="button" className="btn" onClick={props.onLater}>
              Sonra
            </button>
          )}
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

/** Checks once at startup (if enabled in Settings) and offers what it finds.
 *  Failures at startup are silent: offline is a normal state. */
export function UpdateBanner() {
  const [update, setUpdate] = useState<AvailableUpdate | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const s = await api.getSettings();
        if (!s.checkUpdates) return;
        const u = await api.checkUpdate();
        if (alive) setUpdate(u);
      } catch {
        /* offline, no key in this build, ...: try again next start */
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  if (!update) return null;
  return (
    <div className="update-banner" role="status">
      <UpdateOffer update={update} onLater={() => setUpdate(null)} />
    </div>
  );
}

/** The "Güncellemeler" part of the Settings dialog. */
export function UpdateSettings(props: {
  checkUpdates: boolean;
  onCheckUpdates: (on: boolean) => void;
}) {
  const [version, setVersion] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AvailableUpdate | "none" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.appVersion().then(setVersion, () => setVersion(null));
  }, []);

  async function checkNow() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult((await api.checkUpdate()) ?? "none");
    } catch (e) {
      setError(api.errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="field">
      <span className="lbl">Güncellemeler</span>
      <p className="muted small">
        Kullandığınız sürüm: <strong>{version ?? "?"}</strong>. Güncellemeler GitHub'dan indirilir
        ve kurulmadan önce imzası doğrulanır.
      </p>
      <label className="check">
        <input
          type="checkbox"
          checked={props.checkUpdates}
          onChange={(e) => props.onCheckUpdates(e.target.checked)}
        />
        Açılışta yeni sürümü denetle
      </label>
      <button type="button" className="btn" onClick={checkNow} disabled={busy}>
        {busy ? "Denetleniyor…" : "Şimdi denetle"}
      </button>
      {result === "none" && (
        <p className="muted small" role="status">
          En son sürümü kullanıyorsunuz.
        </p>
      )}
      {result !== null && result !== "none" && <UpdateOffer update={result} />}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
