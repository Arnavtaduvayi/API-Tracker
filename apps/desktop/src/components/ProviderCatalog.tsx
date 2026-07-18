import { useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { ProviderManifest } from "../types";

export function ProviderCatalog(props: { onOpen: (id: string) => void }) {
  const [providers, setProviders] = useState<ProviderManifest[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .providersList()
      .then(setProviders)
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
  }, []);

  return (
    <div>
      <h1>Provider catalog</h1>
      <p className="muted">
        Informational catalog with an honest capability matrix. Provider API connectors
        (validation, usage, permissions) are not implemented yet — every capability is labeled.
      </p>
      {error && <p className="error">{error}</p>}
      {providers && (
        <table>
          <thead>
            <tr>
              <th>Provider</th>
              <th>Secret env vars</th>
              <th>Detection patterns</th>
              <th>Expiration</th>
            </tr>
          </thead>
          <tbody>
            {providers.map((p) => (
              <tr key={p.id}>
                <td>
                  <button className="link" onClick={() => props.onOpen(p.id)}>
                    {p.name}
                  </button>
                </td>
                <td className="mono">{p.env_vars.join(", ") || "—"}</td>
                <td>{p.detection.length}</td>
                <td>{p.expiration || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
