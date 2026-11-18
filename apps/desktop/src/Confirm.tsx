import { useEffect, useRef, type ReactNode } from "react";

/** A question that needs a clear yes before something is deleted or moved
 *  to the recycle bin. Esc or the backdrop cancels; the safe button
 *  ("Vazgeç") has the focus, so Enter alone never deletes. */
export function ConfirmDialog(props: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  /** Red confirm button (permanent deletes). */
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    cancelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        props.onCancel();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      className="modal-back"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="confirm-title"
      aria-describedby="confirm-text"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !props.busy) props.onCancel();
      }}
    >
      <div className="modal confirm-modal">
        <h2 id="confirm-title">{props.title}</h2>
        <div id="confirm-text" className="confirm-text">
          {props.children}
        </div>
        <div className="confirm-buttons">
          <button
            ref={cancelRef}
            type="button"
            className="btn"
            onClick={props.onCancel}
            disabled={props.busy}
          >
            Vazgeç
          </button>
          <button
            type="button"
            className={"btn " + (props.danger ? "btn-danger" : "btn-accent")}
            onClick={props.onConfirm}
            disabled={props.busy}
          >
            {props.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
