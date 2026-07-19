// Administrative provider connection: connect/replace/remove the admin key,
// run synchronization, and review provider-side keys/projects with honest
// attribution. The admin key is write-only: it can be stored, replaced, or
// removed, but never displayed. Sensitive changes reauthenticate first.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type {
  Credential,
  ProviderConnection,
  ProviderKeyOverview,
  ProviderProjectOverview,
  SyncReport,
} from "../types";
import { formatMicros } from "../utils";
import { ReauthDialog } from "./ReauthDialog";

type Period = "auto" | "7" | "30" | "90";

export function ProviderConnectionPanel(props: { provider: string }) {
  const [status, setStatus] = useState<ProviderConnection | null>(null);
  const [keys, setKeys] = useState<ProviderKeyOverview[]>([]);
  const [providerProjects, setProviderProjects] = useState<ProviderProjectOverview[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [showConnect, setShowConnect] = useState(false);
  const [adminKey, setAdminKey] = useState("");
  const [org, setOrg] = useState("");
  const [replacePassword, setReplacePassword] = useState("");
  const [period, setPeriod] = useState<Period>("auto");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [lastReport, setLastReport] = useState<SyncReport | null>(null);
  const [reauth, setReauth] = useState<"disconnect" | "test" | null>(null);
  const [linkSelection, setLinkSelection] = useState<Record<string, string>>({});

  const reload = useCallback(async () => {
    try {
      const [s, k, p, c] = await Promise.all([
        api.providerConnectionStatus(props.provider),
        api.providerKeys(props.provider),
        api.providerProjects(props.provider),
        api.credentialList(),
      ]);
      setStatus(s);
      setKeys(k);
      setProviderProjects(p);
      setCredentials(c.filter((cr) => cr.provider === props.provider));
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  }, [props.provider]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const connect = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const detail = await api.providerAdminConnect(
        props.provider,
        adminKey,
        org.trim() === "" ? null : org.trim(),
        status?.connected ? replacePassword : null,
      );
      setAdminKey("");
      setReplacePassword("");
      setShowConnect(false);
      setNotice(`Connected: ${detail}`);
      await reload();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const sync = async () => {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const days = period === "auto" ? null : Number(period);
      const report = await api.providerSync(props.provider, days);
      setLastReport(report);
      setNotice(
        `Synced ${report.usage_rows} usage row(s) and ${report.cost_rows} provider-reported cost row(s).`,
      );
      await reload();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
      await reload();
    } finally {
      setBusy(false);
    }
  };

  const linkKey = async (apiKeyId: string, credentialSelector: string) => {
    setError(null);
    setNotice(null);
    try {
      const updated = await api.providerLinkKey(props.provider, apiKeyId, credentialSelector);
      setNotice(`Linked ${apiKeyId}: ${updated} record(s) re-attributed as exact-credential.`);
      await reload();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    }
  };

  const unlinkKey = async (apiKeyId: string) => {
    setError(null);
    setNotice(null);
    try {
      await api.providerUnlinkKey(props.provider, apiKeyId);
      setNotice(
        `Unlinked ${apiKeyId}; its records honestly show provider-key attribution again.`,
      );
      await reload();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    }
  };

  if (!status) return null;

  return (
    <div>
      <h2>Administrative connection</h2>
      <p className="muted">
        An administrative (organization) key lets API Tracker read usage, costs, and key
        metadata for your whole organization — it is more powerful than an ordinary API key. It
        is stored encrypted in this vault, used only for direct requests to the provider, never
        displayed once stored, and can be removed at any time. All synced data stays on this
        computer.
      </p>

      {status.connected ? (
        <dl className="detail-grid">
          <dt>Admin key</dt>
          <dd className="mono">
            {status.admin_key_masked ?? `vault credential ${status.admin_credential_id ?? ""}`}{" "}
            <span className="muted">(administrative; encrypted at rest)</span>
          </dd>
          {status.org_label && (
            <>
              <dt>Organization</dt>
              <dd>
                {status.org_label}{" "}
                <span className="muted">(user-entered label, not provider-verified)</span>
              </dd>
            </>
          )}
          {status.account_synced_at && (
            <>
              <dt>Account (provider-reported)</dt>
              <dd>
                {status.account_name ?? "—"}
                {status.account_email ? ` <${status.account_email}>` : ""}
                {status.account_id ? ` · id ${status.account_id}` : ""}
                {status.account_plan ? ` · plan ${status.account_plan}` : ""}
                <br />
                <span className="muted">
                  via {status.account_source ?? "?"} at {status.account_synced_at}
                </span>
              </dd>
            </>
          )}
          <dt>Connected at</dt>
          <dd>{status.connected_at ?? "—"}</dd>
          <dt>Last successful sync</dt>
          <dd>{status.last_success_at ?? "never"}</dd>
          <dt>Last failed sync</dt>
          <dd>{status.last_failure_at ?? "never"}</dd>
          <dt>Status</dt>
          <dd>
            {status.last_status}
            {status.stale && (
              <>
                {" "}
                <span className="badge bad">stale data</span>
              </>
            )}
          </dd>
          {status.last_error && (
            <>
              <dt>Last error</dt>
              <dd className="error">{status.last_error}</dd>
            </>
          )}
        </dl>
      ) : (
        <p className="muted">Not connected.</p>
      )}

      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", alignItems: "flex-end" }}>
        <button onClick={() => setShowConnect((v) => !v)}>
          {status.connected ? "Replace admin key…" : "Connect…"}
        </button>
        {status.connected && (
          <>
            <label className="field">
              Sync period
              <select value={period} onChange={(e) => setPeriod(e.target.value as Period)}>
                <option value="auto">since last sync (default)</option>
                <option value="7">last 7 days</option>
                <option value="30">last 30 days</option>
                <option value="90">last 90 days</option>
              </select>
            </label>
            <button onClick={() => void sync()} disabled={busy}>
              {busy ? "Working…" : "Sync now"}
            </button>
            <button
              disabled={busy}
              onClick={() =>
                void (async () => {
                  setError(null);
                  setNotice(null);
                  try {
                    const info = await api.providerAccountSync(props.provider);
                    setNotice(`Account identity synced from ${info.source}.`);
                    await reload();
                  } catch (err) {
                    if (isApiError(err)) setError(err.message);
                  }
                })()
              }
            >
              Sync account identity
            </button>
            <button onClick={() => setReauth("test")}>Test connection</button>
            <button className="danger" onClick={() => setReauth("disconnect")}>
              Disconnect
            </button>
          </>
        )}
      </div>

      {showConnect && (
        <form className="stack" style={{ maxWidth: "32rem" }} onSubmit={(e) => void connect(e)}>
          <label className="field">
            Admin API key (never displayed after saving)
            <input
              type="password"
              value={adminKey}
              onChange={(e) => setAdminKey(e.target.value)}
              required
              autoFocus
            />
          </label>
          <label className="field">
            Organization label (optional, for your reference)
            <input type="text" value={org} onChange={(e) => setOrg(e.target.value)} />
          </label>
          {status.connected && (
            <label className="field">
              Master password (required to replace the stored key)
              <input
                type="password"
                value={replacePassword}
                onChange={(e) => setReplacePassword(e.target.value)}
                required
              />
            </label>
          )}
          <p className="muted">
            The key is validated against the provider before it is stored, then encrypted under
            your vault key.
          </p>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button type="submit" disabled={busy}>
              {busy ? "Working…" : "Save connection"}
            </button>
            <button type="button" onClick={() => setShowConnect(false)}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}
      {lastReport && lastReport.notes.length > 0 && (
        <ul className="muted">
          {lastReport.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}

      {keys.length > 0 && (
        <>
          <h3>Provider-side API keys</h3>
          <p className="muted">
            Keys the provider reports for your organization. Usage is attributed to a local
            credential only after you confirm the association — suggestions are evidence, not
            proof, and nothing links automatically. Not every provider key must map to a local
            credential.
          </p>
          <table>
            <thead>
              <tr>
                <th>Key id</th>
                <th>Name</th>
                <th>Project</th>
                <th>Records</th>
                <th>Linked credential</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.api_key_id}>
                  <td className="mono">{k.api_key_id}</td>
                  <td>
                    {k.name || "—"}
                    {k.redacted_value && (
                      <span className="muted mono"> {k.redacted_value}</span>
                    )}
                  </td>
                  <td>{k.provider_project_name ?? k.provider_project_id ?? "—"}</td>
                  <td>{k.usage_rows}</td>
                  <td>
                    {k.linked_credential ? (
                      <>
                        {k.linked_credential}{" "}
                        <span className="muted">({k.link_source ?? "linked"})</span>
                      </>
                    ) : (
                      <span className="muted">not linked</span>
                    )}
                    {k.note && <div className="muted">{k.note}</div>}
                  </td>
                  <td>
                    {k.linked_credential ? (
                      <button
                        className="link danger"
                        onClick={() => void unlinkKey(k.api_key_id)}
                      >
                        unlink
                      </button>
                    ) : (
                      <span style={{ display: "flex", gap: "0.25rem" }}>
                        <select
                          value={linkSelection[k.api_key_id] ?? k.suggested_credential ?? ""}
                          onChange={(e) =>
                            setLinkSelection((s) => ({ ...s, [k.api_key_id]: e.target.value }))
                          }
                        >
                          <option value="">choose credential…</option>
                          {credentials.map((c) => (
                            <option
                              key={c.id}
                              value={`${c.project_name}/${c.name}`}
                            >{`${c.project_name}/${c.name}`}</option>
                          ))}
                        </select>
                        <button
                          className="link"
                          disabled={!(linkSelection[k.api_key_id] ?? k.suggested_credential)}
                          onClick={() =>
                            void linkKey(
                              k.api_key_id,
                              linkSelection[k.api_key_id] ?? k.suggested_credential ?? "",
                            )
                          }
                        >
                          confirm link
                        </button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {providerProjects.length > 0 && (
        <>
          <h3>Provider-side projects</h3>
          <p className="muted">
            Month-to-date provider-reported cost per provider project. Projects without any
            linked usage stay visible — their cost is never divided among local keys.
          </p>
          <table>
            <thead>
              <tr>
                <th>Project</th>
                <th>Reported cost (month)</th>
                <th>Linked usage</th>
              </tr>
            </thead>
            <tbody>
              {providerProjects.map((p) => (
                <tr key={p.provider_project_id}>
                  <td>
                    {p.name || p.provider_project_id}{" "}
                    <span className="muted mono">{p.name ? p.provider_project_id : ""}</span>
                  </td>
                  <td>{formatMicros(p.reported_cost_micros_month)}</td>
                  <td>{p.has_linked_usage ? "yes" : <span className="muted">none</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {reauth === "disconnect" && (
        <ReauthDialog
          title="Remove the administrative connection"
          actionLabel="Disconnect"
          onConfirm={async (password) => {
            await api.providerAdminDisconnect(props.provider, password);
            setNotice("Disconnected. Previously synced data remains viewable offline.");
            await reload();
          }}
          onClose={() => setReauth(null)}
        />
      )}
      {reauth === "test" && (
        <ReauthDialog
          title="Run a live connection test"
          actionLabel="Test connection"
          onConfirm={async (password) => {
            const detail = await api.providerAdminTest(props.provider, password);
            setNotice(`Connection test: ${detail}`);
            await reload();
          }}
          onClose={() => setReauth(null)}
        />
      )}
    </div>
  );
}
