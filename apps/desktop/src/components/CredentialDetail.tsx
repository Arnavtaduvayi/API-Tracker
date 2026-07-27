// Credential details: masked value, explainable status findings, manual
// marks, lifecycle timeline, permission diffs, provider-side key lifecycle
// (test keys, revocation), and the sensitive actions (reveal / copy /
// replace / delete) — each gated behind master-password reauthentication.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, isApiError } from "../api";
import type {
  Credential,
  CredentialActivitySources,
  CredentialVersionInfo,
  PermissionsPreview,
  ProviderManifest,
  StoredPermissions,
  TimelineEvent,
} from "../types";
import { formatTimestamp, safeExternalUrl, statusLabel, statusSeverity } from "../utils";
import { ReauthDialog } from "./ReauthDialog";
import { ConfirmDialog, PromptDialog } from "./ConfirmDialog";

function activitySourceLabel(source: string): string {
  switch (source) {
    case "local_gateway":
      return "locally observed by gateway";
    case "interception_proxy":
      return "locally observed by proxy";
    case "provider_reported":
      return "provider-reported";
    case "manually_marked":
      return "manually marked";
    case "validated":
      return "validated against the provider";
    default:
      return source;
  }
}

type SensitiveAction =
  "reveal" | "copy" | "delete" | "versions" | "provider-revoke" | "test-key";

export function CredentialDetail(props: {
  id: string;
  onBack: (projectIdent: string | null) => void;
  onEdit: () => void;
}) {
  const [credential, setCredential] = useState<Credential | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [action, setAction] = useState<SensitiveAction | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [replaceOpen, setReplaceOpen] = useState(false);
  const [newValue, setNewValue] = useState("");
  const [replacePassword, setReplacePassword] = useState("");
  const [exposurePromptOpen, setExposurePromptOpen] = useState(false);
  const [permissions, setPermissions] = useState<StoredPermissions | null>(null);
  const [manifest, setManifest] = useState<ProviderManifest | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[] | null>(null);
  const [versions, setVersions] = useState<CredentialVersionInfo[] | null>(null);
  const [permPreview, setPermPreview] = useState<PermissionsPreview | null>(null);
  const [revokeConfirmOpen, setRevokeConfirmOpen] = useState(false);
  const [testKeyOpen, setTestKeyOpen] = useState(false);
  const [tkProviderProject, setTkProviderProject] = useState("");
  const [tkName, setTkName] = useState("");
  const [tkTtl, setTkTtl] = useState("60");
  const [testKeyNotes, setTestKeyNotes] = useState<string[] | null>(null);
  const [activity, setActivity] = useState<CredentialActivitySources | null>(null);
  const revealTimer = useRef<number | null>(null);

  // A small async wrapper that surfaces errors and a success notice.
  const run = async (fn: () => Promise<void>) => {
    setError(null);
    setNotice(null);
    try {
      await fn();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  };

  const reload = useCallback(async () => {
    try {
      setCredential(await api.credentialGet(props.id));
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
    // Source-labeled activity is supplementary; its absence never blocks
    // the detail view. Wrapped in Promise.resolve so even a synchronous
    // throw (e.g. an older backend without the command) becomes a handled
    // rejection rather than an unhandled one.
    void Promise.resolve()
      .then(() => api.credentialActivitySources(props.id))
      .then(setActivity, () => setActivity(null));
  }, [props.id]);

  useEffect(() => {
    void reload();
    // Load any previously-synced permissions (no network request).
    api
      .credentialPermissions(props.id, false)
      .then(setPermissions)
      .catch(() => setPermissions(null));
    return () => {
      if (revealTimer.current !== null) window.clearTimeout(revealTimer.current);
    };
  }, [reload, props.id]);

  // The provider manifest gates the provider-side lifecycle actions so only
  // truly implemented capabilities get buttons (honest representation).
  useEffect(() => {
    if (!credential) return;
    api
      .providerGet(credential.provider)
      .then(setManifest)
      .catch(() => setManifest(null));
  }, [credential]);

  const hideRevealed = useCallback(() => {
    setRevealed(null);
    if (revealTimer.current !== null) {
      window.clearTimeout(revealTimer.current);
      revealTimer.current = null;
    }
  }, []);

  const mark = async (args: Parameters<typeof api.credentialMark>[1], done: string) => {
    setError(null);
    setNotice(null);
    try {
      await api.credentialMark(props.id, args);
      setNotice(done);
      await reload();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  };

  const confirmAction = async (password: string) => {
    setError(null);
    setNotice(null);
    if (action === "reveal") {
      const value = await api.credentialReveal(props.id, password);
      // Cancel any previous auto-hide timer before starting a new one.
      if (revealTimer.current !== null) window.clearTimeout(revealTimer.current);
      setRevealed(value);
      // Hide the plaintext automatically after 30 seconds.
      revealTimer.current = window.setTimeout(hideRevealed, 30_000);
    } else if (action === "copy") {
      const clearAfter = await api.credentialCopy(props.id, password);
      setNotice(
        clearAfter > 0
          ? `Copied. The clipboard will be cleared in about ${clearAfter} seconds.`
          : "Copied to the clipboard.",
      );
    } else if (action === "delete") {
      // The master password is re-verified in core (IPC-02) — this dialog is
      // UX, not the authorization. Pass it through; a wrong password throws
      // and aborts the delete.
      const projectId = credential?.project_id ?? null;
      await api.credentialDelete(props.id, password);
      props.onBack(projectId);
    } else if (action === "versions") {
      setVersions(await api.credentialVersions(props.id, password));
    } else if (action === "provider-revoke") {
      const detail = await api.credentialProviderRevoke(props.id, password);
      setNotice(
        `Revoked at the provider: ${detail}. The vault record is marked revoked (kept for history).`,
      );
      await reload();
    } else if (action === "test-key") {
      if (!credential) return;
      const result = await api.testKeyCreate({
        project: credential.project_id,
        provider: credential.provider,
        providerProject: tkProviderProject.trim() || null,
        name: tkName.trim(),
        ttlMinutes: Number(tkTtl),
        password,
      });
      setTestKeyNotes(result.notes);
      setNotice(
        `Created test key '${result.credential.project_name}/${result.credential.name}' ` +
          `(${result.credential.masked_value}).`,
      );
    }
  };

  if (!credential) return <p>{error ?? "Loading…"}</p>;

  const c = credential;

  return (
    <div>
      <p>
        <button className="link" onClick={() => props.onBack(c.project_id)}>
          ← {c.project_name}
        </button>
      </p>
      <h1>
        {c.project_name}/{c.name}
      </h1>
      <dl className="detail-grid">
        <dt>Provider</dt>
        <dd>{c.provider}</dd>
        <dt>Environment</dt>
        <dd>{c.environment}</dd>
        <dt>Value</dt>
        <dd className="mono">
          {c.is_reference ? `reference to ${c.linked_target ?? "(missing)"}` : c.masked_value}
          {revealed !== null && (
            <>
              {" "}
              <span className="warnbox mono">{revealed}</span>{" "}
              <button className="link" onClick={hideRevealed}>
                hide
              </button>
            </>
          )}
        </dd>
        <dt>Status</dt>
        <dd>
          <span className={`badge ${statusSeverity(c.status.primary)}`}>
            {statusLabel(c.status.primary)}
          </span>
        </dd>
        <dt>Key created</dt>
        <dd>{formatTimestamp(c.key_created_at)}</dd>
        <dt>Expires</dt>
        <dd>
          {c.expires_at_invalid ? (
            <span className="badge bad" title={c.expires_at ?? ""}>
              invalid date
            </span>
          ) : (
            formatTimestamp(c.expires_at)
          )}
          {c.expires_at && !c.expires_at_invalid && (
            <>
              {" "}
              <span className="muted">(entered by you — a local reminder)</span>
            </>
          )}
        </dd>
        <dt>Expires (provider-reported)</dt>
        <dd>
          {c.provider_expires_at_invalid ? (
            <span className="badge bad" title={c.provider_expires_at ?? ""}>
              invalid value reported by provider (ignored)
            </span>
          ) : c.provider_expires_at ? (
            formatTimestamp(c.provider_expires_at)
          ) : (
            "not reported by the provider"
          )}
        </dd>
        <dt>Last validated</dt>
        <dd>{formatTimestamp(c.last_validated_at)}</dd>
        <dt>Activity</dt>
        <dd>
          {/* Source-labeled, never a single ambiguous "last used" (SI-19):
              each line names its evidence class, and none of them is
              summed or substituted for another. */}
          <div className="stack" style={{ gap: "0.15rem" }}>
            <span>
              Most recent known:{" "}
              {activity?.most_recent
                ? `${formatTimestamp(activity.most_recent.at)} (${activitySourceLabel(
                    activity.most_recent.source,
                  )})`
                : "none recorded"}
            </span>
            <span className="muted">
              Locally observed by gateway: {formatTimestamp(activity?.last_gateway_observed)}
            </span>
            <span className="muted">
              Locally observed by proxy: {formatTimestamp(activity?.last_proxy_observed)}
            </span>
            <span className="muted">
              Provider-reported (synced): {formatTimestamp(activity?.last_provider_reported)}
            </span>
            <span className="muted">
              Manually marked used: {formatTimestamp(c.last_used_at)}
            </span>
            <span className="muted">
              Local observation covers only traffic routed through Tethra; absence here is not
              evidence the key is unused.
            </span>
          </div>
        </dd>
        <dt>Documentation</dt>
        <dd>
          {(() => {
            // Only render an anchor for an explicitly-safe external scheme
            // (http/https/mailto). A javascript:/file:/data: docs_url is
            // shown as inert text, never a clickable href (IPC-05).
            const safe = safeExternalUrl(c.docs_url);
            if (safe) {
              return (
                <a href={safe} target="_blank" rel="noreferrer">
                  {safe}
                </a>
              );
            }
            if (c.docs_url) {
              return (
                <span className="muted" title="unsupported or unsafe URL scheme — not linked">
                  {c.docs_url} (not a safe link)
                </span>
              );
            }
            return "—";
          })()}
        </dd>
        <dt>Notes</dt>
        <dd>{c.notes || "—"}</dd>
        <dt>Added</dt>
        <dd>{formatTimestamp(c.created_at)}</dd>
      </dl>

      <h2>Sensitive actions</h2>
      <p className="muted">Each of these asks for your master password again.</p>
      <p style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button onClick={() => setAction("reveal")}>Reveal value</button>
        <button onClick={() => setAction("copy")}>Copy value</button>
        {!c.is_reference && (
          <button onClick={() => setReplaceOpen(true)}>Replace value…</button>
        )}
        <button onClick={props.onEdit}>Edit metadata</button>
        <button className="danger" onClick={() => setAction("delete")}>
          Delete…
        </button>
      </p>

      <h2>Provider</h2>
      <p className="muted">These make a direct request to the provider from this device.</p>
      <p style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button
          onClick={() =>
            void run(async () => {
              const r = await api.credentialValidate(props.id);
              setNotice(`${r.valid ? "Valid" : "Invalid"}: ${r.detail}`);
            })
          }
        >
          Validate
        </button>
        <button
          onClick={() =>
            void run(async () => {
              const m = await api.credentialMetadata(props.id);
              setNotice(
                `Metadata (${m.source}): ${m.fields.map(([k, v]) => `${k}=${v}`).join(", ")}`,
              );
            })
          }
        >
          Fetch metadata
        </button>
        <button
          onClick={() =>
            void run(async () => {
              const p = await api.credentialPermissions(props.id, true);
              setPermissions(p);
              setNotice(p ? "Permissions synced." : "No permissions available.");
            })
          }
        >
          Sync permissions
        </button>
        <button
          onClick={() =>
            void run(async () => {
              setPermPreview(await api.permissionsPreview(props.id));
            })
          }
        >
          Permissions diff
        </button>
      </p>
      {permissions && (
        <div className="finding ok">
          <div>
            <strong>Permissions</strong>{" "}
            <span className="muted">
              ({permissions.source}, {permissions.confidence} confidence)
            </span>
          </div>
          <div>{permissions.normalized.summary}</div>
          {permissions.raw_scopes.length > 0 && (
            <div className="muted mono">scopes: {permissions.raw_scopes.join(", ")}</div>
          )}
          {permissions.normalized.sensitive.length > 0 && (
            <div className="muted">
              production-sensitive: {permissions.normalized.sensitive.join(", ")}
            </div>
          )}
        </div>
      )}
      {permPreview && (
        <div className="finding warn">
          <div>
            <strong>Permissions diff</strong>{" "}
            <span className="muted">
              (fresh from {permPreview.fetched.source}, {permPreview.fetched.confidence}{" "}
              confidence — NOT stored)
            </span>
          </div>
          <div>
            Before (stored):{" "}
            {permPreview.stored
              ? `${permPreview.stored.normalized.summary} (synced ${formatTimestamp(
                  permPreview.stored.synced_at,
                )})`
              : "no stored permission snapshot"}
          </div>
          <div>After (fresh): {permPreview.normalized.summary}</div>
          {(() => {
            const storedScopes = permPreview.stored?.raw_scopes ?? [];
            const added = permPreview.fetched.raw_scopes.filter(
              (s) => !storedScopes.includes(s),
            );
            const removed = storedScopes.filter(
              (s) => !permPreview.fetched.raw_scopes.includes(s),
            );
            if (added.length === 0 && removed.length === 0) {
              return <div>No scope changes.</div>;
            }
            return (
              <div className="mono">
                {added.map((s) => (
                  <div key={`+${s}`}>+ {s}</div>
                ))}
                {removed.map((s) => (
                  <div key={`-${s}`}>− {s}</div>
                ))}
              </div>
            );
          })()}
          <div className="muted">
            Store the fresh scopes with &quot;Sync permissions&quot;. To CHANGE permissions: no
            current provider supports editing a key&apos;s scopes via API — change them in the
            provider dashboard where supported, or create a replacement key with the desired
            scope and rotate this credential (Rotation view).
          </div>
        </div>
      )}

      <h2>Lifecycle</h2>
      <p className="muted">
        A merged, chronological record of this credential&apos;s lifecycle (metadata only —
        never values). Version history additionally asks for your master password because it
        reveals rotation cadence.
      </p>
      <p style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button
          onClick={() =>
            void run(async () => {
              setTimeline(await api.credentialTimeline(props.id));
            })
          }
        >
          Load timeline
        </button>
        <button onClick={() => setAction("versions")}>Version history…</button>
      </p>
      {timeline !== null &&
        (timeline.length === 0 ? (
          <p className="muted">No recorded lifecycle events.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>At</th>
                <th>Event</th>
                <th>Detail</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {timeline.map((e, i) => (
                <tr key={i}>
                  <td>{formatTimestamp(e.at)}</td>
                  <td className="mono">{e.kind}</td>
                  <td>{e.detail || "—"}</td>
                  <td className="muted">{e.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ))}
      {versions !== null && (
        <>
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>Value (masked)</th>
                <th>At</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {versions.map((v) => (
                <tr key={v.version}>
                  <td className="mono">v{v.version}</td>
                  <td className="mono">{v.masked_value}</td>
                  <td>{formatTimestamp(v.created_at)}</td>
                  <td>{v.current ? "current" : v.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted">
            Old versions exist so destination rollback works; they are encrypted like current
            values and pruned automatically.
          </p>
        </>
      )}

      {!c.is_reference && (
        <>
          <h2>Provider-side lifecycle</h2>
          <p className="muted">
            These act on REAL provider-side keys through the provider&apos;s administrative
            connection.
          </p>
          <p style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
            {manifest?.capabilities.create_credential.support === "implemented" ? (
              <button onClick={() => setTestKeyOpen(true)}>Create test key…</button>
            ) : (
              <span className="muted">
                This provider has no API key creation — create keys in its dashboard
                {manifest?.manage_url ? ` (${manifest.manage_url})` : ""}.
              </span>
            )}
            {manifest?.capabilities.revoke_credential.support === "implemented" ? (
              <button className="danger" onClick={() => setRevokeConfirmOpen(true)}>
                Revoke at provider…
              </button>
            ) : (
              <span className="muted">
                This provider has no API revocation — revoke keys in its dashboard
                {manifest?.manage_url ? ` (${manifest.manage_url})` : ""}.
              </span>
            )}
          </p>
          {c.provider === "anthropic" &&
            manifest?.capabilities.revoke_credential.support === "implemented" && (
              <p className="muted">
                Anthropic has no hard delete — revocation archives the key (soft revoke).
              </p>
            )}
          {testKeyNotes && (
            <div className="warnbox">
              <strong>What is actually enforced:</strong>
              <ul>
                {testKeyNotes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}

      <h2>Manual tracking</h2>
      <p style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button onClick={() => void mark({ markUsedNow: true }, "Recorded a use just now.")}>
          Mark used now
        </button>
        <button onClick={() => void mark({ markValidated: true }, "Recorded: validation OK.")}>
          Mark validated OK
        </button>
        <button
          onClick={() => void mark({ markValidated: false }, "Recorded: validation failed.")}
        >
          Mark validation failed
        </button>
        {c.manually_disabled ? (
          <button onClick={() => void mark({ disabled: false }, "Re-enabled.")}>Enable</button>
        ) : (
          <button onClick={() => void mark({ disabled: true }, "Marked disabled.")}>
            Mark disabled
          </button>
        )}
        {c.revoked ? (
          <button onClick={() => void mark({ revoked: false }, "Unmarked revoked.")}>
            Unmark revoked
          </button>
        ) : (
          <button onClick={() => void mark({ revoked: true }, "Marked revoked.")}>
            Mark revoked
          </button>
        )}
        {c.possibly_exposed ? (
          <button
            onClick={() => void mark({ possiblyExposed: false }, "Exposure flag cleared.")}
          >
            Clear exposure flag
          </button>
        ) : (
          <button onClick={() => setExposurePromptOpen(true)}>Flag possibly exposed</button>
        )}
      </p>

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      <h2>Status findings</h2>
      {c.status.findings.map((f, i) => (
        <div key={i} className={`finding ${statusSeverity(f.status)}`}>
          <strong>{statusLabel(f.status)}</strong>{" "}
          <span className="muted">({f.confidence} confidence)</span>
          <div>{f.reason}</div>
          <div className="muted">Source: {f.source}</div>
          <div className="muted">Recommended: {f.recommended_action}</div>
        </div>
      ))}

      {replaceOpen && (
        <dialog open>
          <h2>Replace value</h2>
          <p className="muted">
            Replacing re-encrypts the new value and updates the reuse fingerprint. Requires your
            master password.
          </p>
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              void (async () => {
                setError(null);
                try {
                  const warnings = await api.credentialReplaceValue(
                    props.id,
                    replacePassword,
                    newValue,
                  );
                  setNotice(
                    warnings.length > 0
                      ? "Value replaced. Note: the new value also exists elsewhere in the vault."
                      : "Value replaced.",
                  );
                  setReplaceOpen(false);
                  setNewValue("");
                  setReplacePassword("");
                  await reload();
                } catch (err) {
                  setError(isApiError(err) ? err.message : String(err));
                }
              })();
            }}
          >
            <label className="field">
              New secret value
              <input
                type="password"
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                autoFocus
                required
                autoComplete="off"
              />
            </label>
            <label className="field">
              Master password
              <input
                type="password"
                value={replacePassword}
                onChange={(e) => setReplacePassword(e.target.value)}
                required
              />
            </label>
            {error && <p className="error">{error}</p>}
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button type="submit">Replace</button>
              <button
                type="button"
                onClick={() => {
                  setReplaceOpen(false);
                  setNewValue("");
                  setReplacePassword("");
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        </dialog>
      )}

      {action && (
        <ReauthDialog
          title={
            action === "reveal"
              ? "Reveal credential value"
              : action === "copy"
                ? "Copy credential value"
                : action === "delete"
                  ? "Delete credential"
                  : action === "versions"
                    ? "View version history"
                    : action === "provider-revoke"
                      ? "Revoke at the provider"
                      : "Create a real provider-side key"
          }
          actionLabel={
            action === "delete"
              ? "Delete permanently"
              : action === "provider-revoke"
                ? "Revoke at provider"
                : action === "test-key"
                  ? "Create real key"
                  : "Confirm"
          }
          onConfirm={confirmAction}
          onClose={() => setAction(null)}
        />
      )}

      {revokeConfirmOpen && (
        <ConfirmDialog
          title="Revoke at the provider"
          body={
            `REVOKE '${c.project_name}/${c.name}' at ${c.provider}? This is usually ` +
            `irreversible and anything still using the key will break.` +
            (c.provider === "anthropic"
              ? " (Anthropic has no hard delete — this archives the key, a soft revoke.)"
              : "")
          }
          confirmLabel="Continue to password"
          danger
          onConfirm={() => {
            setRevokeConfirmOpen(false);
            setAction("provider-revoke");
          }}
          onCancel={() => setRevokeConfirmOpen(false)}
        />
      )}

      {testKeyOpen && (
        <dialog open>
          <h2>Create a test key</h2>
          <p className="muted">
            This creates a REAL key at {c.provider} via the administrative connection and stores
            it encrypted in project &apos;{c.project_name}&apos;. The expiry below is a LOCAL
            reminder only — the provider key stays valid until you revoke it.
          </p>
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              const ttl = Number(tkTtl);
              if (!Number.isFinite(ttl) || ttl <= 0) {
                setError("The reminder lifetime must be a positive number of minutes.");
                return;
              }
              if (!tkName.trim()) {
                setError("Give the test key a name.");
                return;
              }
              setError(null);
              setTestKeyOpen(false);
              setAction("test-key");
            }}
          >
            <label className="field">
              Provider-side project (OpenAI project id / Supabase project ref — optional)
              <input
                value={tkProviderProject}
                onChange={(e) => setTkProviderProject(e.target.value)}
              />
            </label>
            <label className="field">
              Key name
              <input
                value={tkName}
                onChange={(e) => setTkName(e.target.value)}
                autoFocus
                required
              />
            </label>
            <label className="field">
              Local reminder lifetime (minutes — not enforced by the provider)
              <input
                type="number"
                min={1}
                value={tkTtl}
                onChange={(e) => setTkTtl(e.target.value)}
              />
            </label>
            {error && <p className="error">{error}</p>}
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button type="submit">Continue to password</button>
              <button type="button" onClick={() => setTestKeyOpen(false)}>
                Cancel
              </button>
            </div>
          </form>
        </dialog>
      )}

      {exposurePromptOpen && (
        <PromptDialog
          title="Flag as possibly exposed"
          body="Optionally note where it may have been exposed (e.g. 'found in an old gist')."
          placeholder="optional note"
          confirmLabel="Flag"
          onConfirm={(note) => {
            setExposurePromptOpen(false);
            void mark(
              { possiblyExposed: true, exposureNote: note },
              "Flagged as possibly exposed.",
            );
          }}
          onCancel={() => setExposurePromptOpen(false)}
        />
      )}
    </div>
  );
}
