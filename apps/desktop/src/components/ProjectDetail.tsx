import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { Credential, DetectedCredential, Project, ProjectOverview } from "../types";
import { formatTimestamp, statusLabel, statusSeverity } from "../utils";
import { ProjectActivity } from "./ProjectActivity";
import { ProjectTracking } from "./ProjectTracking";
import { ProviderMark } from "./visuals/ProviderMarks";

export function ProjectDetail(props: {
  ident: string;
  onBack: () => void;
  onEdit: () => void;
  onOpenCredential: (id: string) => void;
  onAddCredential: () => void;
  onOpenAdvanced: () => void;
  /** Open the credential form seeded from a detection row. */
  onStoreDetected: (row: DetectedCredential) => void;
}) {
  const [project, setProject] = useState<Project | null>(null);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [overview, setOverview] = useState<ProjectOverview | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(true);
  const [overviewFailed, setOverviewFailed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [passwordPrompt, setPasswordPrompt] = useState<"set" | "unlock" | "remove" | null>(
    null,
  );
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [master, setMaster] = useState("");

  const reload = useCallback(async () => {
    try {
      const p = await api.projectGet(props.ident);
      setProject(p);
      setCredentials(await api.credentialList(p.id));
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  }, [props.ident]);

  /**
   * Configuration and health. Separate from `reload` because this one resolves
   * present-tense health, which performs guarded writes on the Rust side — it
   * belongs on page open, an explicit refresh, and after a change. Never on the
   * activity timer, which calls the read-only snapshot command instead.
   *
   * A failure here leaves the tracking panel absent rather than claiming the
   * project is untracked, which is a different and much worse thing to say.
   */
  const reloadOverview = useCallback(async () => {
    setOverviewLoading(true);
    try {
      setOverview(await api.projectTrackingOverview(props.ident));
      setOverviewFailed(false);
    } catch (e) {
      // `overview` is left as it was rather than nulled. Nulling it renders the
      // "Select project folder" call to action for a project that may well BE
      // linked, which is a claim about the project's state derived from a failed
      // read — the opposite of what this catch is for.
      setOverviewFailed(true);
      setError(isApiError(e) ? e.message : String(e));
    } finally {
      setOverviewLoading(false);
    }
  }, [props.ident]);

  useEffect(() => {
    void reload();
    void reloadOverview();
  }, [reload, reloadOverview]);

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
    const masterPassword = master;
    setMaster("");
    if (mode === "set") {
      if (entered !== confirmPassword) {
        setError("The passwords do not match.");
        return;
      }
      await run(
        () => api.projectSetPassword(props.ident, entered, masterPassword),
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
            {passwordPrompt === "set" && (
              <label className="field">
                Master password (reauthentication)
                <input
                  type="password"
                  value={master}
                  onChange={(e) => setMaster(e.target.value)}
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

      {overviewFailed && (
        <p className="error">
          Tethra could not read this project&apos;s tracking state, so what is shown below may
          be incomplete. It is not a statement that tracking is off.
        </p>
      )}
      <ProjectTracking
        projectIdent={props.ident}
        overview={overview}
        reloading={overviewLoading}
        onChanged={() => {
          void reloadOverview();
          void reload();
        }}
        onOpenAdvanced={props.onOpenAdvanced}
        onStoreDetected={props.onStoreDetected}
      />

      {overview?.link && overview.link.tracking_enabled && (
        <ProjectActivity
          projectIdent={props.ident}
          enabled={!project.archived}
          // Manual Refresh re-resolves health as well as re-reading
          // observations, which is what ADR 0029 always said it did (AUD-08).
          // `reloadOverview` calls `project_tracking_overview` and nothing
          // else — no detection, no file write, no service install, no apply.
          onRefreshHealth={() => void reloadOverview()}
        />
      )}

      <h2>Credentials</h2>
      <p>
        <button onClick={props.onAddCredential} disabled={project.archived}>
          Add credential
        </button>
        {project.archived && <span className="muted"> (restore the project first)</span>}
      </p>
      {credentials.length === 0 ? (
        <div className="empty-state">
          <h2>No credentials in this project yet</h2>
          <p>
            Add the keys this project uses and Tethra can tell you which requests each one made,
            when it was last used, and when it needs rotating.
          </p>
          <button
            className="primary"
            onClick={props.onAddCredential}
            disabled={project.archived}
          >
            Add credential
          </button>
        </div>
      ) : (
        <div className="entity-grid" data-testid="credential-cards">
          {credentials.map((c) => (
            <button
              className="entity-card"
              key={c.id}
              onClick={() => props.onOpenCredential(c.id)}
            >
              <div className="entity-head">
                <ProviderMark id={c.provider} name={c.provider} />
                <div style={{ minWidth: 0 }}>
                  <p className="entity-title">{c.name}</p>
                  <p className="entity-sub">
                    {c.provider} · {c.environment}
                  </p>
                </div>
              </div>

              <p className="entity-meta">
                {/* The status label and its tone are both resolved by the
                    shared helpers, so this card and the credential page
                    cannot disagree about what a status means. */}
                <span className={`badge ${statusSeverity(c.status.primary)}`}>
                  {statusLabel(c.status.primary)}
                </span>
              </p>

              <p className="entity-meta mono">
                {c.is_reference ? `→ ${c.linked_target ?? "?"}` : c.masked_value}
              </p>

              <p className="entity-foot">Marked used {formatTimestamp(c.last_used_at)}</p>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
