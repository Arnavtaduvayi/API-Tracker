// Add a credential (with reuse detection and the reference option) or edit
// an existing credential's metadata. The secret value is only present in
// add mode, kept in local state until submit, then discarded.

import { useEffect, useState } from "react";
import { api, isApiError } from "../api";
import {
  ENVIRONMENTS,
  type Environment,
  type ProviderManifest,
  type ReuseWarning,
} from "../types";
import { emptyToNull, toDateInput } from "../utils";

export function CredentialForm(props: {
  project?: string;
  editId?: string;
  onDone: (id: string | null) => void;
}) {
  const editing = props.editId !== undefined;
  const [providers, setProviders] = useState<ProviderManifest[]>([]);
  const [name, setName] = useState("");
  const [provider, setProvider] = useState("other");
  const [environment, setEnvironment] = useState<Environment>("development");
  const [value, setValue] = useState("");
  const [keyCreated, setKeyCreated] = useState("");
  const [expires, setExpires] = useState("");
  const [docsUrl, setDocsUrl] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(!editing);
  const [reuseWarnings, setReuseWarnings] = useState<ReuseWarning[] | null>(null);

  useEffect(() => {
    api
      .providersList()
      .then(setProviders)
      .catch(() => setProviders([]));
    if (props.editId) {
      api
        .credentialGet(props.editId)
        .then((c) => {
          setName(c.name);
          setProvider(c.provider);
          setEnvironment(c.environment);
          setKeyCreated(toDateInput(c.key_created_at));
          setExpires(toDateInput(c.expires_at));
          setDocsUrl(c.docs_url);
          setNotes(c.notes);
          setLoaded(true);
        })
        .catch((e) => setError(isApiError(e) ? e.message : String(e)));
    }
  }, [props.editId]);

  const saveEdit = async () => {
    const updated = await api.credentialUpdate(props.editId!, {
      name,
      provider,
      environment,
      keyCreatedAt: emptyToNull(keyCreated),
      expiresAt: emptyToNull(expires),
      docsUrl,
      notes,
    });
    props.onDone(updated.id);
  };

  const storeCopy = async () => {
    const created = await api.credentialAdd({
      project: props.project!,
      provider,
      name,
      environment,
      value,
      keyCreatedAt: emptyToNull(keyCreated),
      expiresAt: emptyToNull(expires),
      docsUrl,
      notes,
    });
    setValue("");
    props.onDone(created.id);
  };

  const storeReference = async (source: string) => {
    const created = await api.credentialAddReference({
      project: props.project!,
      source,
      name,
      environment,
      docsUrl,
      notes,
    });
    setValue("");
    props.onDone(created.id);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (editing) {
        await saveEdit();
        return;
      }
      // Check for reuse first so the user can choose copy/reference/cancel.
      const warnings = await api.credentialCheckReuse(props.project!, environment, value);
      if (warnings.length > 0) {
        setReuseWarnings(warnings);
        return;
      }
      await storeCopy();
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!loaded) return <p>Loading…</p>;

  const knownProvider = providers.some((p) => p.id === provider);

  return (
    <div>
      <h1>{editing ? "Edit credential" : "Add credential"}</h1>
      <form className="stack" onSubmit={(e) => void submit(e)}>
        <label className="field">
          Name (unique within the project)
          <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
        </label>
        <label className="field">
          Provider
          <select
            value={knownProvider ? provider : "__custom"}
            onChange={(e) => setProvider(e.target.value === "__custom" ? "" : e.target.value)}
          >
            {providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
            <option value="__custom">Custom…</option>
          </select>
        </label>
        {!knownProvider && (
          <label className="field">
            Custom provider name
            <input value={provider} onChange={(e) => setProvider(e.target.value)} required />
          </label>
        )}
        <label className="field">
          Environment
          <select
            value={environment}
            onChange={(e) => setEnvironment(e.target.value as Environment)}
          >
            {ENVIRONMENTS.map((env) => (
              <option key={env} value={env}>
                {env}
              </option>
            ))}
          </select>
        </label>
        {!editing && (
          <label className="field">
            Secret value (encrypted at rest; shown masked afterwards)
            <input
              type="password"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              required
              autoComplete="off"
            />
          </label>
        )}
        <label className="field">
          Key created on (optional)
          <input
            type="date"
            value={keyCreated}
            onChange={(e) => setKeyCreated(e.target.value)}
          />
        </label>
        <label className="field">
          Expires on (optional)
          <input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
        </label>
        <label className="field">
          Documentation link (optional)
          <input type="url" value={docsUrl} onChange={(e) => setDocsUrl(e.target.value)} />
        </label>
        <label className="field">
          Notes (never encrypted; do not put secrets here)
          <textarea rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} />
        </label>
        {error && <p className="error">{error}</p>}
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button type="submit" disabled={busy}>
            {busy ? "Saving…" : editing ? "Save changes" : "Add credential"}
          </button>
          <button type="button" onClick={() => props.onDone(props.editId ?? null)}>
            Cancel
          </button>
        </div>
      </form>

      {reuseWarnings && (
        <dialog open>
          <h2>This value is already in your vault</h2>
          {reuseWarnings.map((w, i) => (
            <div key={i} className="warnbox">
              <p>{w.message}</p>
              <p className="muted">Recommendation: {w.recommendation}</p>
            </div>
          ))}
          <p>
            Referencing the existing credential keeps one encrypted source of truth instead of a
            second copy. Creating separate provider credentials per project is safer still.
          </p>
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
            <button
              onClick={() => {
                const source = reuseWarnings[0].other.credential_id;
                setReuseWarnings(null);
                void storeReference(source).catch((e) =>
                  setError(isApiError(e) ? e.message : String(e)),
                );
              }}
            >
              Reference the existing credential
            </button>
            <button
              onClick={() => {
                setReuseWarnings(null);
                void storeCopy().catch((e) => setError(isApiError(e) ? e.message : String(e)));
              }}
            >
              Store a duplicate copy anyway
            </button>
            <button onClick={() => setReuseWarnings(null)}>Cancel</button>
          </div>
        </dialog>
      )}
    </div>
  );
}
