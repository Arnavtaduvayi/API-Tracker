// Provider details: official links (opened in the system browser), the
// honest capability matrix, and documentation-watch controls.

import { useCallback, useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api, isApiError } from "../api";
import type {
  CapabilityEntry,
  DocHistoryEntry,
  DocWatch,
  ProviderManifest,
  SupportLevel,
} from "../types";
import { formatTimestamp } from "../utils";
import { ProviderConnectionPanel } from "./ProviderConnectionPanel";

/** Providers with a dedicated administrative connection + usage sync. */
const ADMIN_CONNECTION_PROVIDERS = ["openai", "anthropic"];

const SUPPORT_LABEL: Record<SupportLevel, string> = {
  implemented: "implemented",
  supported_not_implemented: "supported, not implemented",
  unsupported: "unsupported",
  manual_only: "manual action required",
};

const CAPABILITY_ORDER: [keyof ProviderManifest["capabilities"], string][] = [
  ["validate_credential", "validate credential"],
  ["fetch_metadata", "fetch metadata"],
  ["fetch_usage", "fetch usage"],
  ["read_permissions", "read permissions"],
  ["change_permissions", "change permissions"],
  ["create_credential", "create credential"],
  ["disable_credential", "disable credential"],
  ["revoke_credential", "revoke credential"],
  ["rotate_credential", "rotate credential"],
  ["fetch_pricing", "fetch pricing"],
];

function statusText(entry: CapabilityEntry): string {
  const parts = [SUPPORT_LABEL[entry.support]];
  if (entry.requires_admin_credential) parts.push("admin credential");
  if (entry.attribution !== "not_applicable") {
    parts.push(entry.attribution.replace(/_/g, " "));
  }
  return parts.join(" · ");
}

export function ProviderDetail(props: { id: string; onBack: () => void }) {
  const [manifest, setManifest] = useState<ProviderManifest | null>(null);
  const [watches, setWatches] = useState<DocWatch[]>([]);
  const [history, setHistory] = useState<DocHistoryEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const reloadWatches = useCallback(async () => {
    try {
      const all = await api.docWatchList();
      setWatches(all.filter((w) => w.provider === props.id));
      // Check history is stored per URL; the provider column lets us
      // filter client-side without a dedicated backend query.
      const entries = await api.docWatchHistory(null, 500);
      setHistory(entries.filter((h) => h.provider === props.id).slice(0, 50));
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  }, [props.id]);

  useEffect(() => {
    api
      .providerGet(props.id)
      .then(setManifest)
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
    void reloadWatches();
  }, [props.id, reloadWatches]);

  const open = (url: string) => {
    void openUrl(url).catch((e) => setError(isApiError(e) ? e.message : String(e)));
  };

  const watchAll = async () => {
    if (!manifest) return;
    setError(null);
    setNotice(null);
    try {
      for (const url of manifest.watch_docs) {
        await api.docWatchAdd(manifest.id, url);
      }
      setNotice("Now watching the official documentation pages.");
      await reloadWatches();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  };

  const checkNow = async (url: string) => {
    setError(null);
    setNotice(null);
    try {
      const w = await api.docWatchCheck(url);
      setNotice(
        `Checked: ${w.last_status}. A page change does not necessarily mean a breaking API change.`,
      );
      await reloadWatches();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  };

  if (!manifest) return <p>{error ?? "Loading…"}</p>;
  const m = manifest;

  return (
    <div>
      <p>
        <button className="link" onClick={props.onBack}>
          ← Provider catalog
        </button>
      </p>
      <h1>{m.name}</h1>
      <p>{m.description}</p>
      <dl className="detail-grid">
        <dt>Website</dt>
        <dd>
          <button className="link" onClick={() => open(m.website)}>
            {m.website}
          </button>
        </dd>
        <dt>API docs</dt>
        <dd>
          <button className="link" onClick={() => open(m.api_docs_url)}>
            {m.api_docs_url}
          </button>
        </dd>
        <dt>Manage keys</dt>
        <dd>
          <button className="link" onClick={() => open(m.manage_url)}>
            {m.manage_url}
          </button>
        </dd>
        {m.changelog_url && (
          <>
            <dt>Changelog</dt>
            <dd>
              <button className="link" onClick={() => open(m.changelog_url)}>
                {m.changelog_url}
              </button>
            </dd>
          </>
        )}
        {m.pricing_url && (
          <>
            <dt>Pricing docs</dt>
            <dd>
              <button className="link" onClick={() => open(m.pricing_url)}>
                {m.pricing_url}
              </button>
            </dd>
          </>
        )}
        {m.permissions_docs_url && (
          <>
            <dt>Permissions docs</dt>
            <dd>
              <button className="link" onClick={() => open(m.permissions_docs_url)}>
                {m.permissions_docs_url}
              </button>
            </dd>
          </>
        )}
        {m.login_url && (
          <>
            <dt>Console login</dt>
            <dd>
              <button className="link" onClick={() => open(m.login_url)}>
                {m.login_url}
              </button>
            </dd>
          </>
        )}
        {m.billing_url && (
          <>
            <dt>Billing portal</dt>
            <dd>
              <button className="link" onClick={() => open(m.billing_url)}>
                {m.billing_url}
              </button>
            </dd>
          </>
        )}
        <dt>Secret env vars</dt>
        <dd className="mono">{m.env_vars.join(", ") || "—"}</dd>
        <dt>Key types</dt>
        <dd>{m.credential_types.join(", ") || "—"}</dd>
        <dt>Expiration</dt>
        <dd>{m.expiration || "—"}</dd>
      </dl>

      {ADMIN_CONNECTION_PROVIDERS.includes(m.id) && <ProviderConnectionPanel provider={m.id} />}

      <h2>Capabilities</h2>
      <p className="muted">Honest support declarations for this provider.</p>
      <table>
        <thead>
          <tr>
            <th>Capability</th>
            <th>Status</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {CAPABILITY_ORDER.map(([key, label]) => {
            const entry = m.capabilities[key];
            return (
              <tr key={key}>
                <td>{label}</td>
                <td>{statusText(entry)}</td>
                <td className="muted">{entry.note}</td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <h2>Documentation watches</h2>
      {m.watch_docs.length > 0 && (
        <p>
          <button onClick={() => void watchAll()}>Watch official pages</button>
        </p>
      )}
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}
      {watches.length === 0 ? (
        <p className="muted">No pages watched yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>URL</th>
              <th>Status</th>
              <th>Last checked</th>
              <th>Last changed</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {watches.map((w) => (
              <tr key={w.id}>
                <td>
                  <button className="link" onClick={() => open(w.url)}>
                    {w.url}
                  </button>
                </td>
                <td>{w.last_status}</td>
                <td>{w.last_checked_at ?? "never"}</td>
                <td>{w.last_changed_at ?? "no change seen"}</td>
                <td>
                  <button className="link" onClick={() => void checkNow(w.url)}>
                    check now
                  </button>{" "}
                  <button
                    className="link danger"
                    onClick={() =>
                      void api
                        .docWatchRemove(w.url)
                        .then(() => reloadWatches())
                        .catch((e) => setError(isApiError(e) ? e.message : String(e)))
                    }
                  >
                    unwatch
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Docs change history</h2>
      <p className="muted">
        Recorded outcomes of documentation checks for this provider&apos;s watched pages
        (validators and outcomes only — page content is never stored). A change does not
        necessarily mean a breaking API change.
      </p>
      {history.length === 0 ? (
        <p className="muted">No checks recorded yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>URL</th>
              <th>Outcome</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {history.map((h, i) => (
              <tr key={`${h.url}-${h.at}-${i}`}>
                <td>{formatTimestamp(h.at)}</td>
                <td>
                  <button className="link" onClick={() => open(h.url)}>
                    {h.url}
                  </button>
                </td>
                <td>{h.outcome}</td>
                <td className="muted">{h.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
