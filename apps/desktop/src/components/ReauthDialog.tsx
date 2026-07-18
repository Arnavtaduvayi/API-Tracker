// Reauthentication prompt used before revealing, copying, replacing, or
// deleting sensitive values. The password is passed straight to the backend
// command and never kept in component state longer than the dialog lives.

import { useState } from "react";
import { isApiError } from "../api";

export function ReauthDialog(props: {
  title: string;
  actionLabel: string;
  onConfirm: (password: string) => Promise<void>;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await props.onConfirm(password);
      setPassword("");
      props.onClose();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <dialog open>
      <h2>{props.title}</h2>
      <p className="muted">Confirm your master password to continue.</p>
      <form className="stack" onSubmit={(e) => void submit(e)}>
        <label className="field">
          Master password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
            required
          />
        </label>
        {error && <p className="error">{error}</p>}
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button type="submit" disabled={busy}>
            {busy ? "Working…" : props.actionLabel}
          </button>
          <button type="button" onClick={props.onClose}>
            Cancel
          </button>
        </div>
      </form>
    </dialog>
  );
}
