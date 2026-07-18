// Notification channels: optional user-configured webhooks that receive
// alert METADATA (kind, severity, title, detail, timestamps) — never secret
// values. The webhook URL may embed a token, so it is entered masked,
// stored encrypted in the vault, and only ever displayed in masked form.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { NotificationChannel } from "../types";
import { formatTimestamp } from "../utils";
import { ConfirmDialog } from "./ConfirmDialog";

const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

export function NotifyView() {
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [minSeverity, setMinSeverity] = useState("high");
  const [removing, setRemoving] = useState<NotificationChannel | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setChannels(await api.notificationChannels());
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const channel = await api.notificationChannelAdd(name.trim(), url, minSeverity);
      setName("");
      setUrl("");
      setMinSeverity("high");
      setShowAdd(false);
      setNotice(
        `Channel '${channel.name}' added (${channel.url_masked}; floor ${channel.min_severity}). Use "test" to verify delivery.`,
      );
      await reload();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    setNotice(null);
    try {
      await fn();
      await reload();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
      await reload(); // a failed test still updates last_error
    }
  };

  const test = async (channel: NotificationChannel) => {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const detail = await api.notificationChannelTest(channel.id);
      setNotice(`Test through '${channel.name}': ${detail}`);
    } catch (e) {
      setError(
        `Test through '${channel.name}' failed: ${isApiError(e) ? e.message : String(e)}`,
      );
    } finally {
      setBusy(false);
      await reload();
    }
  };

  return (
    <div>
      <h1>Notifications</h1>
      <p className="muted">
        Webhooks you configure receive open alerts at or above their severity floor whenever
        monitoring runs. The URL is stored encrypted (it may embed a token) and payloads are
        metadata-only — alert kind, severity, title, detail, and timestamps. Secret values are
        never sent, and no API Tracker service is involved.
      </p>
      <p>
        <button onClick={() => setShowAdd((v) => !v)}>
          {showAdd ? "Cancel" : "Add webhook channel…"}
        </button>
      </p>

      {showAdd && (
        <form className="stack" style={{ maxWidth: "32rem" }} onSubmit={(e) => void add(e)}>
          <label className="field">
            Name
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              autoFocus
            />
          </label>
          <label className="field">
            Webhook URL (https; stored encrypted, shown masked afterwards)
            <input
              type="password"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://…"
              required
            />
            <span className="muted">
              Stored encrypted — it may embed a token. Delivery payloads are metadata-only;
              secret values are never included.
            </span>
          </label>
          <label className="field">
            Minimum severity delivered
            <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <div>
            <button type="submit" disabled={busy}>
              {busy ? "Working…" : "Add channel"}
            </button>
          </div>
        </form>
      )}

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      {channels.length === 0 ? (
        <p className="muted">No channels configured. Notifications are entirely optional.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>URL (masked)</th>
              <th>Floor</th>
              <th>State</th>
              <th>Last delivery</th>
              <th>Last error</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {channels.map((c) => (
              <tr key={c.id}>
                <td>{c.name}</td>
                <td className="mono">{c.url_masked}</td>
                <td>{c.min_severity}</td>
                <td>{c.enabled ? "enabled" : <span className="muted">disabled</span>}</td>
                <td>{c.last_delivery_at ? formatTimestamp(c.last_delivery_at) : "never"}</td>
                <td className={c.last_error ? "error" : undefined}>{c.last_error || "—"}</td>
                <td>
                  <button
                    className="link"
                    onClick={() =>
                      void act(() => api.notificationChannelEnable(c.id, !c.enabled))
                    }
                  >
                    {c.enabled ? "disable" : "enable"}
                  </button>{" "}
                  <button className="link" disabled={busy} onClick={() => void test(c)}>
                    test
                  </button>{" "}
                  <button className="link danger" onClick={() => setRemoving(c)}>
                    remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {removing && (
        <ConfirmDialog
          title={`Remove channel '${removing.name}'?`}
          body="The stored (encrypted) webhook URL is deleted and deliveries stop. This cannot be undone."
          confirmLabel="Remove channel"
          danger
          onConfirm={() => {
            const target = removing;
            setRemoving(null);
            void act(() => api.notificationChannelRemove(target.id));
          }}
          onCancel={() => setRemoving(null)}
        />
      )}
    </div>
  );
}
