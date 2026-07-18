// Provider details: official links (opened in the system browser), the
// honest capability matrix, and documentation-watch controls.

import { useCallback, useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api, isApiError } from "../api";
import type { CapabilityEntry, DocWatch, ProviderManifest, SupportLevel } from "../types";

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
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const reloadWatches = useCallback(async () => {
    try {
      const all = await api.docWatchList();
      setWatches(all.filter((w) => w.provider === props.id));
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
        <dt>Secret env vars</dt>
        <dd className="mono">{m.env_vars.join(", ") || "—"}</dd>
        <dt>Key types</dt>
        <dd>{m.credential_types.join(", ") || "—"}</dd>
        <dt>Expiration</dt>
        <dd>{m.expiration || "—"}</dd>
      </dl>

      <h2>Capabilities</h2>
      <p className="muted">Nothing is implemented yet; these are honest declarations.</p>
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
    </div>
  );
}
