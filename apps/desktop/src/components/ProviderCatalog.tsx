// The provider library, as a card grid.
//
// Previously a four-column table of env-var lists and regex counts — accurate,
// and unreadable as a library. The card leads with the provider's mark and
// name, then answers the question a user opens this screen with: do I have a
// key for this, and does Tethra do anything useful with it.
//
// The capability caveat is NOT softened here. Tethra's rule is that provider
// capabilities are represented honestly, so each card states whether Tethra
// can validate and sync for that provider, and the detail screen keeps the
// full capability matrix. A card that implied a capability the manifest does
// not declare would be a product bug, not a cosmetic one.

import { useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { Credential, ProviderManifest } from "../types";
import { ProviderMark } from "./visuals/ProviderMarks";

function errText(e: unknown): string {
  return isApiError(e) ? e.message : String(e);
}

export function ProviderCatalog(props: { onOpen: (id: string) => void }) {
  const [providers, setProviders] = useState<ProviderManifest[] | null>(null);
  const [heldByProvider, setHeldByProvider] = useState<Map<string, number>>(new Map());
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    api
      .providersList()
      .then(setProviders)
      .catch((e) => setError(errText(e)));

    // How many credentials the user already holds per provider. Additive: a
    // failure leaves the counts off the cards, not the cards off the screen.
    api
      .credentialList()
      .then((creds: Credential[]) => {
        const counts = new Map<string, number>();
        for (const c of creds) counts.set(c.provider, (counts.get(c.provider) ?? 0) + 1);
        setHeldByProvider(counts);
      })
      .catch(() => setHeldByProvider(new Map()));
  }, []);

  const needle = query.trim().toLowerCase();
  const shown = (providers ?? []).filter(
    (p) =>
      needle.length === 0 ||
      p.name.toLowerCase().includes(needle) ||
      p.id.toLowerCase().includes(needle) ||
      p.env_vars.some((v) => v.toLowerCase().includes(needle)),
  );

  return (
    <section className="stack">
      <div className="screen-heading">
        <div>
          <p className="screen-kicker">Vault</p>
          <h1>Providers</h1>
        </div>
      </div>

      <p className="muted">
        Credential validation, metadata, permissions and usage sync are implemented where each
        provider supports them. Open a provider for the live support level of every operation.
      </p>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {providers && (
        <div className="dashboard-toolbar">
          <input
            type="search"
            placeholder="Search providers or variables"
            aria-label="Search providers"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ minWidth: "16rem" }}
          />
          <span className="dashboard-signal">
            {shown.length} of {providers.length} providers
          </span>
        </div>
      )}

      {providers && shown.length === 0 && (
        <div className="empty-state">
          <h2>No provider matches “{query}”</h2>
          <p>
            Tethra ships {providers.length} provider manifests. Try the provider&apos;s name, or
            the environment variable its key is stored in.
          </p>
        </div>
      )}

      {shown.length > 0 && (
        <div className="entity-grid" data-testid="provider-cards">
          {shown.map((p) => {
            const held = heldByProvider.get(p.id) ?? 0;
            return (
              <button className="entity-card" key={p.id} onClick={() => props.onOpen(p.id)}>
                <div className="entity-head">
                  <ProviderMark id={p.id} name={p.name} />
                  <div style={{ minWidth: 0 }}>
                    <p className="entity-title">{p.name}</p>
                    <p className="entity-sub">
                      {held > 0
                        ? `${held} credential${held === 1 ? "" : "s"} in your vault`
                        : "No credentials stored yet"}
                    </p>
                  </div>
                </div>

                <p className="entity-meta">
                  <span>
                    <b>{p.env_vars.length}</b> secret variable
                    {p.env_vars.length === 1 ? "" : "s"}
                  </span>
                  <span>
                    <b>{p.detection.length}</b> detection pattern
                    {p.detection.length === 1 ? "" : "s"}
                  </span>
                </p>

                {p.env_vars.length > 0 && (
                  <p className="entity-meta mono">{p.env_vars.slice(0, 2).join(", ")}</p>
                )}

                <p className="entity-foot">
                  {p.expiration
                    ? "Expiry documented"
                    : "No documented expiry — Tethra cannot warn on age alone"}
                </p>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}
