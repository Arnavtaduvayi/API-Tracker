import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { Credential, Project } from "../types";
import { formatTimestamp, statusLabel, statusSeverity } from "../utils";

export function ProjectDetail(props: {
  ident: string;
  onBack: () => void;
  onEdit: () => void;
  onOpenCredential: (id: string) => void;
  onAddCredential: () => void;
}) {
  const [project, setProject] = useState<Project | null>(null);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [passwordPrompt, setPasswordPrompt] = useState<"set" | "unlock" | "remove" | null>(
    null,
  );
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const reload = useCallback(async () => {
    try {
      const p = await api.projectGet(props.ident);
      setProject(p);
      setCredentials(await api.credentialList(p.id));
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  }, [props.ident]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const run = async (action: () => Promise<unknown>, done?: string) => {
    setError(null);
    setNotice(null);
    try {
      await action();
      if (done) setNotice(done);
      await reload();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  };

  const submitPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    const mode = passwordPrompt;
    setPasswordPrompt(null);
    const entered = password;
    setPassword("");
    setConfirmPassword("");
    if (mode === "set") {
      if (entered !== confirmPassword) {
        setError("The passwords do not match.");
        return;
      }
      await run(
        () => api.projectSetPassword(props.ident, entered),
        "Project password set. Keep it safe: losing it makes this project's credential values unrecoverable.",
      );
    } else if (mode === "unlock") {
      await run(() => api.projectUnlock(props.ident, entered), "Project unlocked.");
    } else if (mode === "remove") {
      await run(
        () => api.projectRemovePassword(props.ident, entered),
        "Project password removed; the vault lock still protects it.",
      );
    }
  };

  if (!project) return <p>{error ?? "Loading…"}</p>;

  return (
    <div>
      <p>
        <button className="link" onClick={props.onBack}>
          ← All projects
        </button>
      </p>
      <h1>
        {project.name}
        {project.archived && " (archived)"}
      </h1>
      {project.description && <p>{project.description}</p>}
      <dl className="detail-grid">
        <dt>Environments</dt>
        <dd>{project.environments.join(", ") || "—"}</dd>
        <dt>Repositories</dt>
        <dd>
          {project.repo_paths.length > 0
            ? project.repo_paths.map((r) => (
                <div key={r} className="mono">
                  {r}
                </div>
              ))
            : "—"}
        </dd>
        <dt>Password lock</dt>
        <dd>
          {!project.password_locked
            ? "not set"
            : project.unlocked
              ? "set (unlocked this session)"
              : "set (locked)"}
        </dd>
        <dt>Created</dt>
        <dd>{formatTimestamp(project.created_at)}</dd>
        <dt>Notes</dt>
        <dd>{project.notes || "—"}</dd>
      </dl>

      <p style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button onClick={props.onEdit}>Edit</button>
        {!project.password_locked && (
          <button onClick={() => setPasswordPrompt("set")}>Set project password</button>
        )}
        {project.password_locked && project.unlocked && (
          <>
            <button
              onClick={() => void run(() => api.projectLock(props.ident), "Project locked.")}
            >
              Lock project
            </button>
            <button onClick={() => setPasswordPrompt("remove")}>Remove password</button>
          </>
        )}
        {project.password_locked && !project.unlocked && (
          <button onClick={() => setPasswordPrompt("unlock")}>Unlock project</button>
        )}
        {!project.archived ? (
          <button
            className="danger"
            onClick={() =>
              void run(() => api.projectSetArchived(props.ident, true), "Project archived.")
            }
          >
            Archive
          </button>
        ) : (
          <button
            onClick={() =>
              void run(() => api.projectSetArchived(props.ident, false), "Project restored.")
            }
          >
            Restore
          </button>
        )}
      </p>

      {passwordPrompt && (
        <dialog open>
          <h2>
            {passwordPrompt === "set"
              ? "Set project password"
              : passwordPrompt === "unlock"
                ? "Unlock project"
                : "Remove project password"}
          </h2>
          {passwordPrompt === "set" && (
            <p className="warnbox">
              This adds a second lock on top of the vault. If you lose this password, the
              credential values in this project are unrecoverable.
            </p>
          )}
          <form className="stack" onSubmit={(e) => void submitPassword(e)}>
            <label className="field">
              Project password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoFocus
                required
              />
            </label>
            {passwordPrompt === "set" && (
              <label className="field">
                Confirm project password
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                />
              </label>
            )}
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button type="submit">Confirm</button>
              <button type="button" onClick={() => setPasswordPrompt(null)}>
                Cancel
              </button>
            </div>
          </form>
        </dialog>
      )}

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      <h2>Credentials</h2>
      <p>
        <button onClick={props.onAddCredential} disabled={project.archived}>
          Add credential
        </button>
        {project.archived && <span className="muted"> (restore the project first)</span>}
      </p>
      {credentials.length === 0 ? (
        <p>No credentials in this project yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Provider</th>
              <th>Environment</th>
              <th>Value</th>
              <th>Status</th>
              <th>Last used</th>
            </tr>
          </thead>
          <tbody>
            {credentials.map((c) => (
              <tr key={c.id}>
                <td>
                  <button className="link" onClick={() => props.onOpenCredential(c.id)}>
                    {c.name}
                  </button>
                </td>
                <td>{c.provider}</td>
                <td>{c.environment}</td>
                <td className="mono">
                  {c.is_reference ? `→ ${c.linked_target ?? "?"}` : c.masked_value}
                </td>
                <td>
                  <span className={`badge ${statusSeverity(c.status.primary)}`}>
                    {statusLabel(c.status.primary)}
                  </span>
                </td>
                <td>{formatTimestamp(c.last_used_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
