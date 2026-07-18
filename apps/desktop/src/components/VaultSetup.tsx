import { useState } from "react";
import { api, isApiError } from "../api";

export function VaultSetup(props: { dataDir: string; onCreated: () => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("The passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await api.vaultCreate(password);
      props.onCreated();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1>Create your vault</h1>
      <p>
        API Tracker stores all data encrypted on this computer at{" "}
        <span className="mono">{props.dataDir}</span>. No account, no cloud.
      </p>
      <form className="stack" onSubmit={(e) => void submit(e)}>
        <label className="field">
          Master password (at least 12 characters; a long multi-word passphrase is best)
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
            required
          />
        </label>
        <label className="field">
          Confirm master password
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
        </label>
        {error && <p className="error">{error}</p>}
        <button type="submit" disabled={busy}>
          {busy ? "Creating…" : "Create encrypted vault"}
        </button>
      </form>
      <p className="warnbox">
        The master password is never stored and cannot be recovered. If you lose it, the vault
        contents are unrecoverable by design. Create encrypted backups regularly from the Backup
        screen.
      </p>
    </div>
  );
}
