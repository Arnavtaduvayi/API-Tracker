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
];

export function SettingsView(props: { dataDir: string }) {
  const [settings, setSettings] = useState<VaultSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

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
    </div>
  );
}
