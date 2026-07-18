// Credential details: masked value, explainable status findings, manual
// marks, and the sensitive actions (reveal / copy / replace / delete) —
// each gated behind master-password reauthentication.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, isApiError } from "../api";
import type { Credential, StoredPermissions } from "../types";
import { formatTimestamp, statusLabel, statusSeverity } from "../utils";
import { ReauthDialog } from "./ReauthDialog";
import { PromptDialog } from "./ConfirmDialog";

type SensitiveAction = "reveal" | "copy" | "delete";

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
      // Verify the master password before the destructive action — the core
      // delete command itself does not re-check, so the reauth must happen
      // here (throws on a wrong password, aborting the delete).
      await api.reauth(password);
      const projectId = credential?.project_id ?? null;
      await api.credentialDelete(props.id);
      props.onBack(projectId);
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
        <dd>{formatTimestamp(c.expires_at)}</dd>
        <dt>Last validated</dt>
        <dd>{formatTimestamp(c.last_validated_at)}</dd>
        <dt>Last used</dt>
        <dd>{formatTimestamp(c.last_used_at)}</dd>
        <dt>Documentation</dt>
        <dd>
          {c.docs_url ? (
            <a href={c.docs_url} target="_blank" rel="noreferrer">
              {c.docs_url}
            </a>
          ) : (
            "—"
          )}
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
                : "Delete credential"
          }
          actionLabel={action === "delete" ? "Delete permanently" : "Confirm"}
          onConfirm={confirmAction}
          onClose={() => setAction(null)}
        />
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
