// Folder selection and tracking setup, inside the project page (ADR 0029).
//
// This replaces the standalone multi-screen flow for the normal path. Selecting
// the folder IS the tracking action: one picker, one disclosure, one
// confirmation, then tracking. There is no separate "Track API activity" step
// to find afterwards.
//
// The disclosure comes from the backend's `preview.disclosure`, which is derived
// from the plan itself, so this screen cannot describe less than the plan will
// do. Paraphrasing it here would let the two drift, which is exactly what the
// existing flow's comments warn about for destination approvals.
//
// Scope is stated BEFORE the picker opens, not after. That ordering is a fixed
// requirement of this product (ZFT-009): a user must know what will be read
// before they choose what to expose to it.

import { useCallback, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, isApiError } from "../api";
import type { DetectedCredential, FolderLinkPreview, ProjectOverview } from "../types";

function errText(e: unknown): string {
  return isApiError(e) ? e.message : String(e);
}

export function ProjectTracking(props: {
  projectIdent: string;
  overview: ProjectOverview | null;
  reloading: boolean;
  onChanged: () => void;
  onOpenAdvanced: () => void;
  /** Open the credential form seeded from a detection row. */
  onStoreDetected: (row: DetectedCredential) => void;
}) {
  const { overview } = props;
  const [preview, setPreview] = useState<FolderLinkPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [confirmUnlink, setConfirmUnlink] = useState(false);

  const link = overview?.link ?? null;
  // The projected status. Always present on a real overview — a project with no
  // link or no setup is a STATE, not a missing field — so the only `null` here
  // is "the overview has not loaded yet".
  const tracking = overview?.tracking ?? null;

  const pickFolder = useCallback(async () => {
    setError(null);
    setNotice(null);
    try {
      const picked = await open({
        directory: true,
        multiple: false,
        title: "Select the project folder",
      });
      if (typeof picked !== "string") return; // cancelled
      setBusy(true);
      const result = await api.projectFolderPreview(props.projectIdent, picked);
      setPreview(result);
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }, [props.projectIdent]);

  const confirm = useCallback(async () => {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      const outcome = await api.projectFolderLink(
        props.projectIdent,
        preview.folder,
        preview.digest,
        password.length > 0 ? password : null,
      );
      setPreview(null);
      setPassword("");
      // `failed_step` is the orchestrator's own verdict, computed in Rust.
      // Comparing `step.outcome` to a string here would never match, because the
      // raw report's outcome is a nested enum — and a partial failure would then
      // have reported "Tracking is on".
      const failed = outcome.report.failed_step;
      setNotice(
        failed
          ? `Tracking setup stopped at "${failed}"${
              outcome.report.failed_detail ? `: ${outcome.report.failed_detail}` : ""
            }. The steps that completed are still in place — open advanced tracking diagnostics to review them.`
          : outcome.report.install_blocked
            ? "Tracking is configured, but this computer blocked the background helper. Open advanced tracking diagnostics for the foreground fallback."
            : "Tracking is on. Activity appears below as soon as your project makes a request.",
      );
      props.onChanged();
    } catch (e) {
      setError(errText(e));
      // A refused digest means the folder changed under us. Re-preview so the
      // user is looking at what is true now rather than what they saw before.
      try {
        setPreview(await api.projectFolderPreview(props.projectIdent, preview.folder));
      } catch {
        setPreview(null);
      }
    } finally {
      setBusy(false);
    }
  }, [preview, password, props]);

  const run = useCallback(
    async (action: () => Promise<unknown>, done: string) => {
      setBusy(true);
      setError(null);
      setNotice(null);
      try {
        await action();
        setNotice(done);
        props.onChanged();
      } catch (e) {
        setError(errText(e));
      } finally {
        setBusy(false);
      }
    },
    [props],
  );

  // NOTE: there is deliberately no effect discarding a preview whose path
  // differs from the linked one. That condition is exactly the "Change folder"
  // case, and clearing on it destroyed the disclosure in the same commit it
  // appeared in — a silent dead button, with the backend fully able to move the
  // link. The preview is cleared where it is actually finished with: on a
  // successful confirm, and on Cancel.

  return (
    <section aria-labelledby="project-tracking-heading">
      <h2 id="project-tracking-heading">Project folder</h2>

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      {!link && !preview && (
        <div data-testid="select-folder-cta">
          {/* Scope BEFORE the picker (ZFT-009). */}
          <p>
            Tethra reads dependency and environment files in the folder you choose, to find
            which APIs the project uses. It reads variable <em>names</em>, never their values,
            never runs your code, and never looks outside the folder you pick. Nothing is
            uploaded.
          </p>
          <p>
            <button onClick={() => void pickFolder()} disabled={busy || props.reloading}>
              Select project folder
            </button>
          </p>
        </div>
      )}

      {link && (
        <>
          <dl className="detail-grid">
            <dt>Folder</dt>
            <dd className="mono">{link.folder_path}</dd>
            <dt>Tracking</dt>
            {/*
              One field, resolved in Rust. This used to read
              `overview.status.health.currently_working`, a path
              `project_tracking_overview` cannot emit — so it was `undefined`
              for every setup and a verified, actively tracked project rendered
              "needs attention" permanently (AUD-05). Nothing here interprets a
              Rust enum; `tracking.label` and `tracking.is_working` come from
              `CurrentHealth::describe` and `CurrentHealth::is_currently_working`
              through one projection.
            */}
            <dd data-testid="tracking-state" data-state={tracking?.state}>
              {tracking?.label ?? "unknown"}
            </dd>
            <dt>Last scanned</dt>
            <dd>{link.last_scan_at ?? "never"}</dd>
          </dl>

          {/*
            Shown for everything except the one case with nothing to say —
            tracking working, no fault, no action. `tracking_off` reaches this
            through `action`, which matters: a project the user disabled still
            has a live route and a rewritten `.env`, so `is_working` can be true
            and the explanation is exactly what they need.
          */}
          {tracking && (!tracking.is_working || tracking.is_fault || tracking.action) && (
            <p
              // `is_fault` is resolved in Rust. Testing the state token here
              // would put a second reading of "is this a problem?" in
              // TypeScript, which is the class of thing AUD-05 was — and
              // `!is_working` is not the same question: an idle project and one
              // waiting for its first request are neither working nor faults.
              className={tracking.is_fault ? "warnbox" : "notice"}
              data-testid="tracking-detail"
            >
              {tracking.sentence}
              {tracking.action && ` ${tracking.action}`}
            </p>
          )}
          {/* Attribution rides BESIDE health: a gateway forwarding without a
              matching key is still tracking, so this never contradicts an
              "on" state above (SI-11/SI-12). */}
          {tracking?.attribution === "paused" && (
            <p className="warnbox" data-testid="attribution-paused">
              Requests are still being recorded, but credential attribution is paused until the
              vault is unlocked for it.
            </p>
          )}
          {/* A missing folder is reported as a missing folder. The stale-scan
              notice below is suppressed for it: an unreadable folder
              fingerprints differently from a real one, which used to make
              "your files changed" the sentence for a folder that is not there
              — and offer a Rescan that fails (AUD-06). */}
          {overview?.folder_available === false && (
            <p className="warnbox" data-testid="folder-missing">
              Tethra cannot find <span className="mono">{link.folder_path}</span>. Choose the
              folder again if it moved, or unlink it. Your recorded activity is kept either way.
            </p>
          )}
          {overview?.scan_stale && overview.folder_available && (
            <p className="notice" data-testid="scan-stale">
              This project&apos;s dependency or environment files changed since the last scan.
              Rescanning updates what Tethra knows; it does not change your files.
            </p>
          )}
          {overview?.configuration_behind && (
            <p className="notice">
              The applied configuration is behind this project&apos;s current setup. Selecting
              the folder again re-applies it.
            </p>
          )}

          <p className="actionrow">
            <button onClick={() => void pickFolder()} disabled={busy}>
              Change folder
            </button>
            <button
              onClick={() =>
                void run(() => api.projectRescan(props.projectIdent), "Rescan complete.")
              }
              disabled={busy || overview?.folder_available === false}
            >
              Rescan project
            </button>
            <button
              onClick={() =>
                void run(
                  () =>
                    api.projectSetTrackingEnabled(props.projectIdent, !link.tracking_enabled),
                  link.tracking_enabled
                    ? "Tracking disabled. The folder stays linked and your recorded activity is kept."
                    : "Tracking enabled.",
                )
              }
              disabled={busy}
            >
              {link.tracking_enabled ? "Disable tracking" : "Enable tracking"}
            </button>
            <button className="danger" onClick={() => setConfirmUnlink(true)} disabled={busy}>
              Unlink folder
            </button>
            <button className="link" onClick={props.onOpenAdvanced}>
              Advanced tracking diagnostics
            </button>
          </p>

          {confirmUnlink && (
            <dialog open>
              <h3>Unlink this folder?</h3>
              <ul>
                <li>The folder association is forgotten.</li>
                <li>This project, its credentials and its recorded activity are kept.</li>
                <li>Your folder and its files on disk are not touched.</li>
                <li>
                  Configuration Tethra wrote into your <code>.env</code> files stays until you
                  undo it from advanced tracking diagnostics.
                </li>
              </ul>
              <p className="actionrow">
                <button
                  className="danger"
                  onClick={() => {
                    setConfirmUnlink(false);
                    void run(
                      () => api.projectUnlinkFolder(props.projectIdent),
                      "Folder unlinked. The project and its history are unchanged.",
                    );
                  }}
                >
                  Unlink folder
                </button>
                <button onClick={() => setConfirmUnlink(false)}>Cancel</button>
              </p>
            </dialog>
          )}
        </>
      )}

      {preview && (
        <div className="warnbox" data-testid="link-disclosure">
          <h3>Review before Tethra changes anything</h3>
          <p className="mono">{preview.folder}</p>

          <p>
            {preview.detection.coverage
              ? `${preview.detection.providers.length} API integration(s) detected.`
              : "Scan complete."}
          </p>

          {/* The backend's own disclosure, verbatim in substance. */}
          <ul>
            {preview.disclosure.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>

          {preview.pending_origin_approvals.length > 0 && (
            <div data-testid="pending-origins">
              <p>
                <strong>
                  {preview.pending_origin_approvals.length} destination(s) came from this
                  project&apos;s own files.
                </strong>{" "}
                Tethra will not route traffic to a destination it read out of your project.
                These are left out of the setup below, and stay left out however many times you
                select this folder.
              </p>
              <ul>
                {preview.pending_origin_approvals.map((o) => (
                  <li key={`${o.provider_id}-${o.origin}`} className="mono">
                    {o.origin} ({o.provider_id})
                  </li>
                ))}
              </ul>
              <p className="muted">
                Approve destinations from advanced tracking diagnostics, where the full
                disclosure for forwarding a credential to a custom destination is shown.
              </p>
            </div>
          )}

          {preview.detected_credentials.length > 0 && (
            <details>
              <summary>
                {preview.detected_credentials.filter((d) => !d.already_have_credential).length}{" "}
                credential record(s) will be created for review
              </summary>
              <ul>
                {preview.detected_credentials.map((d) => (
                  <li key={`${d.env_var}-${d.source_file}`}>
                    <span className="mono">{d.env_var}</span> in{" "}
                    <span className="mono">{d.source_file || "the project"}</span>
                    {d.already_have_credential
                      ? " — you already have a credential for this provider"
                      : " — value not read, not saved"}
                  </li>
                ))}
              </ul>
            </details>
          )}

          {preview.summary === null ? (
            <p data-testid="nothing-to-configure">
              There is nothing Tethra can configure automatically for this folder. Selecting it
              again will not change that — use <strong>Tracking setup (advanced)</strong> for
              the destinations listed above.
            </p>
          ) : (
            <>
              {preview.summary.attribution_requested && (
                <>
                  <p>
                    To attribute requests to a specific credential, Tethra needs your master
                    password once now. It derives a matching key the local helper keeps in
                    memory. That key lets the helper confirm whether a credential it sees
                    matches one of yours — so anything able to reach the helper could use it to
                    test guesses against your credentials. Tracking works without this; only the
                    per-credential attribution does not.
                  </p>
                  <label className="field">
                    Master password (optional)
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </label>
                </>
              )}
              <p className="actionrow">
                <button onClick={() => void confirm()} disabled={busy}>
                  {busy ? "Setting up…" : "Start tracking this folder"}
                </button>
                <button onClick={() => setPreview(null)} disabled={busy}>
                  Cancel
                </button>
              </p>
            </>
          )}
        </div>
      )}

      {overview && overview.detected_credentials.length > 0 && (
        <DetectedCredentials
          rows={overview.detected_credentials}
          onChanged={props.onChanged}
          onStore={props.onStoreDetected}
          needing={overview.credentials_needing_details}
        />
      )}
    </section>
  );
}

function DetectedCredentials(props: {
  rows: DetectedCredential[];
  needing: number;
  onChanged: () => void;
  onStore: (row: DetectedCredential) => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const act = async (id: string, action: () => Promise<unknown>) => {
    setBusy(id);
    setError(null);
    try {
      await action();
      props.onChanged();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <h3>Detected credentials</h3>
      <p className={props.needing > 0 ? "notice" : "muted"} data-testid="credential-summary">
        {props.needing > 0
          ? `${props.needing} credential(s) need details. Tracking is already running — completing them only adds per-credential attribution.`
          : "Every detected credential has been reviewed."}
      </p>
      {error && <p className="error">{error}</p>}
      <table data-testid="detected-credentials">
        <thead>
          <tr>
            <th scope="col">Variable</th>
            <th scope="col">Suggested provider</th>
            <th scope="col">Environment</th>
            <th scope="col">Source</th>
            <th scope="col">Value</th>
            <th scope="col">Attribution</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {props.rows.map((r) => (
            <tr key={r.id}>
              <td className="mono">{r.env_var}</td>
              <td>{r.suggested_provider ?? <span className="muted">unknown</span>}</td>
              <td>{r.suggested_environment ?? <span className="muted">unknown</span>}</td>
              <td className="mono">{r.source_file || "—"}</td>
              <td>{valueStatus(r)}</td>
              <td>{attributionStatus(r)}</td>
              <td>
                {r.status === "pending" ? (
                  <>
                    {/* Tethra found the key; storing it should not mean going
                        away and re-entering it from memory somewhere else. */}
                    <button
                      className="link"
                      disabled={busy === r.id}
                      onClick={() => props.onStore(r)}
                    >
                      Store this key
                    </button>{" "}
                    <button
                      className="link"
                      disabled={busy === r.id}
                      onClick={() =>
                        void act(r.id, () => api.projectResolveDetection(r.id, "ignored", null))
                      }
                    >
                      Ignore
                    </button>{" "}
                    <button
                      className="link"
                      disabled={busy === r.id}
                      onClick={() =>
                        void act(r.id, () =>
                          api.projectResolveDetection(r.id, "external", null),
                        )
                      }
                    >
                      Managed elsewhere
                    </button>
                  </>
                ) : (
                  <span className="muted">{statusSentence(r.status)}</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted">
        Tethra never saved a value for these. <strong>Store this key</strong> opens the normal
        credential form with the provider and name filled in — you paste the value there, the
        same secure path every other credential uses.
      </p>
    </>
  );
}

/** Mirrors `DetectedCredential::value_status` on the Rust side. */
function valueStatus(r: DetectedCredential): string {
  if (r.status === "completed") return "Saved in Tethra";
  if (r.status === "external") return "Managed outside Tethra";
  return "Not saved in Tethra";
}

/** Mirrors `DetectedCredential::attribution_status`. */
function attributionStatus(r: DetectedCredential): string {
  switch (r.status) {
    case "completed":
    case "merged":
      return "Exact key available";
    case "external":
      return "Not attributed (external)";
    case "ignored":
      return "Not attributed (ignored)";
    case "pending":
      return "Pending exact key";
    default:
      return "Not recognized";
  }
}

/** Never prints a bare enum token. */
function statusSentence(status: DetectedCredential["status"]): string {
  switch (status) {
    case "completed":
      return "completed";
    case "ignored":
      return "ignored";
    case "external":
      return "managed elsewhere";
    case "merged":
      return "merged with an existing credential";
    case "pending":
      return "needs details";
    default:
      return "not recognized";
  }
}
