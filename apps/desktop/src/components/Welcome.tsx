// First run: one folder, nothing else.
//
// Before this screen existed, a new user was dropped on an empty dashboard and
// had to work out on their own that the path forward was: create a project →
// type a repository path into a plain text field → open the project → pick the
// folder again → add credentials by hand. Four screens and a guess.
//
// This collapses that into one: pick a folder, and Tethra names the project
// after it, scans it, shows what it found, and turns tracking on.
//
// What this screen must NOT do:
//
//   * Paraphrase the disclosure. `preview.disclosure` is authored in Rust and
//     derived from the plan itself, so the screen cannot promise less than the
//     plan will do (the same rule ProjectTracking.tsx documents). It is moved
//     into an expander that starts OPEN — progressive disclosure, not hidden
//     disclosure.
//   * State scope after the picker. A user must know what will be read before
//     choosing what to expose to it (ZFT-009), so the scope paragraph sits
//     above the button, not in the result.
//   * Drop the digest. `projectFolderLink` is passed the digest the user was
//     shown; the backend refuses a mismatch rather than reconciling it.
//
// Cancelling after the scan keeps the project that was created and sends the
// user to its page, where the same picker is offered again. Nothing is
// orphaned and nothing is silently deleted.

import { useCallback, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, isApiError } from "../api";
import type { FolderLinkPreview, Project } from "../types";
import { ProviderMark } from "./visuals/ProviderMarks";

function errText(e: unknown): string {
  return isApiError(e) ? e.message : String(e);
}

/** The trailing path segment, on either separator. Empty for a filesystem root. */
export function folderName(path: string): string {
  const parts = path.split(/[/\\]/).filter((p) => p.length > 0);
  return parts.length > 0 ? parts[parts.length - 1] : path;
}

/**
 * A folder name as a project name: `my-api_server` → `My api server`.
 * Purely cosmetic — the folder path itself is what the backend binds to.
 */
export function projectNameFor(path: string): string {
  const base = folderName(path)
    .replace(/[-_.]+/g, " ")
    .trim();
  if (base.length === 0) return "My project";
  return base.charAt(0).toUpperCase() + base.slice(1);
}

/**
 * A name that does not collide with one already in the vault. `project_create`
 * rejects a duplicate, and a first-run screen must not dead-end on it.
 */
export function uniqueProjectName(base: string, taken: string[]): string {
  const lower = new Set(taken.map((t) => t.toLowerCase()));
  if (!lower.has(base.toLowerCase())) return base;
  for (let i = 2; i < 100; i += 1) {
    const candidate = `${base} ${i}`;
    if (!lower.has(candidate.toLowerCase())) return candidate;
  }
  return `${base} ${Date.now()}`;
}

type Phase =
  | { name: "idle" }
  | { name: "scanning"; folder: string }
  | { name: "review"; project: Project; preview: FolderLinkPreview }
  | { name: "applying" };

export function Welcome(props: {
  /** Open the project page, where live activity mounts. */
  onOpenProject: (ident: string) => void;
  /** Leave onboarding without picking a folder. */
  onSkip: () => void;
}) {
  const [phase, setPhase] = useState<Phase>({ name: "idle" });
  const [error, setError] = useState<string | null>(null);
  const [password, setPassword] = useState("");

  const busy = phase.name === "scanning" || phase.name === "applying";

  const pickFolder = useCallback(async () => {
    setError(null);
    let picked: string | null = null;
    try {
      const chosen = await open({
        directory: true,
        multiple: false,
        title: "Choose the project folder to track",
      });
      if (typeof chosen !== "string") return; // cancelled
      picked = chosen;
      setPhase({ name: "scanning", folder: chosen });

      // Reuse a project already bound to this folder rather than creating a
      // second one for the same code.
      const existing = await api.projectList(false);
      const match = existing.find((p) => p.repo_paths.includes(chosen));
      const project =
        match ??
        (await api.projectCreate({
          name: uniqueProjectName(
            projectNameFor(chosen),
            existing.map((p) => p.name),
          ),
          description: "",
          notes: "",
          environments: ["development"],
          repoPaths: [chosen],
        }));

      const preview = await api.projectFolderPreview(project.id, chosen);
      setPhase({ name: "review", project, preview });
    } catch (e) {
      setError(errText(e));
      setPhase({ name: "idle" });
      void picked;
    }
  }, []);

  const startTracking = useCallback(async () => {
    if (phase.name !== "review") return;
    const { project, preview } = phase;
    setPhase({ name: "applying" });
    setError(null);
    try {
      await api.projectFolderLink(
        project.id,
        preview.folder,
        preview.digest,
        password.length > 0 ? password : null,
      );
      setPassword("");
      props.onOpenProject(project.id);
    } catch (e) {
      setError(errText(e));
      // A refused digest means the folder changed under us. Show what is true
      // now rather than what was on screen before.
      try {
        setPhase({
          name: "review",
          project,
          preview: await api.projectFolderPreview(project.id, preview.folder),
        });
      } catch {
        setPhase({ name: "idle" });
      }
    }
  }, [phase, password, props]);

  return (
    <section className="stack" aria-labelledby="welcome-heading">
      <div className="empty-state">
        <p className="screen-kicker">Welcome to Tethra</p>
        <h2 id="welcome-heading">
          {phase.name === "review"
            ? `Here is what is in ${folderName(phase.preview.folder)}`
            : "Show Tethra a project folder"}
        </h2>

        {phase.name !== "review" && (
          <>
            {/* Scope BEFORE the picker (ZFT-009). */}
            <p>
              Tethra reads the dependency and environment files in the folder you choose to work
              out which APIs your project uses. It reads variable <em>names</em>, never their
              values, never runs your code, and never looks outside the folder you pick. Nothing
              is uploaded.
            </p>
            <p className="actionrow">
              <button className="primary" onClick={() => void pickFolder()} disabled={busy}>
                {phase.name === "scanning" ? "Scanning…" : "Choose a project folder"}
              </button>
              <button className="secondary" onClick={props.onSkip} disabled={busy}>
                I&apos;ll do this later
              </button>
            </p>
          </>
        )}

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </div>

      {phase.name === "review" && (
        <ReviewCard
          preview={phase.preview}
          password={password}
          onPassword={setPassword}
          busy={busy}
          onConfirm={() => void startTracking()}
          onCancel={() => props.onOpenProject(phase.project.id)}
        />
      )}
    </section>
  );
}

function ReviewCard(props: {
  preview: FolderLinkPreview;
  password: string;
  onPassword: (v: string) => void;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const { preview } = props;
  const providers = preview.detection.providers;
  const newCredentials = preview.detected_credentials.filter((d) => !d.already_have_credential);

  return (
    <div className="card">
      <p className="mono muted">{preview.folder}</p>

      {providers.length > 0 ? (
        <div className="entity-grid" data-testid="welcome-providers">
          {providers.map((p) => (
            <div className="entity-card" key={p.provider_id}>
              <div className="entity-head">
                <ProviderMark id={p.provider_id} name={p.display_name} />
                <div style={{ minWidth: 0 }}>
                  <p className="entity-title">{p.display_name}</p>
                  <p className="entity-sub">{bucketSentence(p.bucket)}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p data-testid="welcome-no-providers">
          Tethra did not recognise any API integrations in this folder yet. Linking it still
          records the folder, and a rescan picks up integrations you add later.
        </p>
      )}

      {newCredentials.length > 0 && (
        <p className="muted">
          {newCredentials.length} credential record(s) will be created for review. Tethra reads
          the variable names only — no value is read or saved.
        </p>
      )}

      {/*
        The backend's own disclosure, verbatim. Open by default: this is
        progressive disclosure of a long list, not a way to hide it.
      */}
      <details open data-testid="welcome-disclosure">
        <summary>What Tethra will change</summary>
        <ul>
          {preview.disclosure.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>

        {preview.pending_origin_approvals.length > 0 && (
          <div data-testid="welcome-pending-origins">
            <p>
              <strong>
                {preview.pending_origin_approvals.length} destination(s) came from this
                project&apos;s own files.
              </strong>{" "}
              Tethra will not route traffic to a destination it read out of your project. These
              are left out of the setup, and stay left out however many times you select this
              folder. Approve them from Settings → Tracking setup, where the full disclosure for
              forwarding a credential to a custom destination is shown.
            </p>
            <ul>
              {preview.pending_origin_approvals.map((o) => (
                <li key={`${o.provider_id}-${o.origin}`} className="mono">
                  {o.origin} ({o.provider_id})
                </li>
              ))}
            </ul>
          </div>
        )}
      </details>

      {preview.summary === null ? (
        <p className="warnbox" data-testid="welcome-nothing-to-configure">
          There is nothing Tethra can configure automatically for this folder. Selecting it
          again will not change that — use Settings → Tracking setup for the destinations listed
          above.
        </p>
      ) : (
        <>
          {preview.summary.attribution_requested && (
            <>
              <p className="muted">
                To attribute requests to a specific credential, Tethra needs your master
                password once now. It derives a matching key the local helper keeps in memory.
                That key lets the helper confirm whether a credential it sees matches one of
                yours — so anything able to reach the helper could use it to test guesses
                against your credentials. Tracking works without this; only the per-credential
                attribution does not.
              </p>
              <label className="field">
                Master password (optional)
                <input
                  type="password"
                  value={props.password}
                  onChange={(e) => props.onPassword(e.target.value)}
                />
              </label>
            </>
          )}
          <p className="actionrow">
            <button className="primary" onClick={props.onConfirm} disabled={props.busy}>
              {props.busy ? "Setting up…" : "Start tracking"}
            </button>
            <button className="secondary" onClick={props.onCancel} disabled={props.busy}>
              Not now
            </button>
          </p>
        </>
      )}
    </div>
  );
}

/** The headline bucket as a sentence. No enum token reaches the screen. */
function bucketSentence(bucket: string): string {
  switch (bucket) {
    case "tracked_automatically":
      return "Tethra knows where this goes";
    case "needs_origin_confirmation":
      return "Needs your approval first";
    case "detected_unsupported":
      return "Detected, not trackable yet";
    case "low_confidence":
      return "Possible match — low confidence";
    default:
      return "Detected";
  }
}
