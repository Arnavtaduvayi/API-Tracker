import { useState } from "react";
import { api, isApiError } from "../api";

export function VaultUnlock(props: { dataDir: string; onUnlocked: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.vaultUnlock(password);
      setPassword("");
      props.onUnlocked();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1>Unlock vault</h1>
      <p className="muted">
        Vault location: <span className="mono">{props.dataDir}</span>
      </p>
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
        <button type="submit" disabled={busy}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </form>
    </div>
  );
}
