import { useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { VaultSettings } from "../types";

const FIELDS: { key: keyof VaultSettings; label: string; hint: string }[] = [
  {
    key: "auto_lock_minutes",
    label: "Auto-lock after inactivity (minutes, 0 disables)",
    hint: "Locks the desktop app and expires CLI sessions.",
  },
  {
    key: "expiring_soon_days",
    label: "Warn this many days before expiration",
    hint: "Controls the 'expiring soon' status.",
  },
  {
    key: "unused_days",
    label: "Days before a never-used credential counts as unused",
    hint: "",
  },
  {
    key: "stale_days",
    label: "Days without use/validation before a credential counts as stale",
    hint: "",
  },
  {
    key: "clipboard_clear_seconds",
    label: "Clear the clipboard after copying (seconds, 0 disables)",
    hint: "Best-effort: other apps may have read the clipboard meanwhile.",
  },
  {
    key: "monitor_interval_minutes",
    label: "Background monitor interval (minutes, 0 disables)",
    hint: "Runs the alert checks, due documentation checks, and webhook delivery while the vault is unlocked.",
  },
  {
    key: "docwatch_interval_hours",
    label: "Documentation check interval (hours, 0 disables)",
    hint: "How often watched documentation pages are re-checked when monitoring runs with network access.",
  },
];

export function SettingsView(props: { dataDir: string; onSaved?: () => void }) {
  const [settings, setSettings] = useState<VaultSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwNotice, setPwNotice] = useState<string | null>(null);

  useEffect(() => {
    api
      .settingsGet()
      .then(setSettings)
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
  }, []);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!settings) return;
    setError(null);
    setNotice(null);
    try {
      await api.settingsSet(settings);
      setNotice("Settings saved.");
      props.onSaved?.();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    }
  };

  if (!settings) return <p>{error ?? "Loading…"}</p>;

  return (
    <div>
      <h1>Settings</h1>
      <p className="muted">
        Vault location: <span className="mono">{props.dataDir}</span>. All data stays on this
        computer.
      </p>
      <form className="stack" onSubmit={(e) => void save(e)}>
        {FIELDS.map((f) => (
          <label key={f.key} className="field">
            {f.label}
            <input
              type="number"
              min={0}
              value={settings[f.key]}
              onChange={(e) =>
                setSettings({ ...settings, [f.key]: Number(e.target.value) || 0 })
              }
            />
            {f.hint && <span className="muted">{f.hint}</span>}
          </label>
        ))}
        {error && <p className="error">{error}</p>}
        {notice && <p className="notice">{notice}</p>}
        <button type="submit">Save settings</button>
      </form>

      <h2>Change master password</h2>
      <p className="muted">
        Re-wraps the vault key under the new password; no data is re-encrypted. Backups made
        before the change still open with the old password — consider creating a fresh backup
        afterwards.
      </p>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          setPwError(null);
          setPwNotice(null);
          if (newPw !== newPw2) {
            setPwError("The new passwords do not match.");
            return;
          }
          void (async () => {
            try {
              await api.vaultChangePassword(currentPw, newPw);
              setPwNotice("Master password changed. Create a fresh backup when convenient.");
              setCurrentPw("");
              setNewPw("");
              setNewPw2("");
            } catch (err) {
              setPwError(isApiError(err) ? err.message : String(err));
            }
          })();
        }}
      >
        <label className="field">
          Current master password
          <input
            type="password"
            value={currentPw}
            onChange={(e) => setCurrentPw(e.target.value)}
            required
          />
        </label>
        <label className="field">
          New master password (12+ characters; a long passphrase is strongest)
          <input
            type="password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            required
          />
        </label>
        <label className="field">
          Confirm new master password
          <input
            type="password"
            value={newPw2}
            onChange={(e) => setNewPw2(e.target.value)}
            required
          />
        </label>
        {pwError && <p className="error">{pwError}</p>}
        {pwNotice && <p className="notice">{pwNotice}</p>}
        <button type="submit" disabled={!currentPw || !newPw}>
          Change master password
        </button>
      </form>
    </div>
  );
}
