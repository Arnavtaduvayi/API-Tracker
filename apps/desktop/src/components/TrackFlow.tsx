// The "Track API activity" flow (ADR 0022 D6): folder picker → bounded
// scan → ONE review screen (detections + exact diff + disclosure +
// optional password) → orchestrated apply with per-step honest reporting
// → restart guidance only when needed → first-request verification.
//
// Every state distinguishes loading / empty / error / unsupported: no
// promise chain here discards an error, and no empty list renders without
// saying why and what to do next.
import { useCallback, useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, isApiError } from "../api";
import type {
  TrackingApplyReport,
  TrackingDiagnosis,
  TrackingPlan,
  TrackingScan,
  TrackingStatus,
} from "../types";

type Phase =
  | { name: "idle" }
  | { name: "scanning"; folder: string }
  | { name: "review"; scan: TrackingScan }
  | { name: "applying" }
  | { name: "waiting"; report: TrackingApplyReport }
  | { name: "verified"; status: TrackingStatus }
  | { name: "attention"; report: TrackingApplyReport | null };

function errText(e: unknown): string {
  return isApiError(e) ? e.message : String(e);
}

/** 2 s while waiting for the first request (ADR 0022, O-22-4). */
const POLL_MS = 2000;
/** Show the restart instruction after this long with no traffic. */
const RESTART_HINT_MS = 10_000;
/** Auto-diagnose after this long with no traffic. */
const DIAGNOSE_MS = 120_000;

export function TrackFlow({ onDone }: { onDone: () => void }) {
  const [phase, setPhase] = useState<Phase>({ name: "idle" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Review-screen state.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [origins, setOrigins] = useState<Record<string, string>>({});
  const [plan, setPlan] = useState<TrackingPlan | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [password, setPassword] = useState("");

  // Waiting-state bookkeeping.
  const [waitedMs, setWaitedMs] = useState(0);
  const [diagnoses, setDiagnoses] = useState<TrackingDiagnosis[] | null>(null);
  const [diagnosing, setDiagnosing] = useState(false);
  const pollRef = useRef<number | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  async function pickFolder() {
    setError(null);
    try {
      const picked = await open({
        directory: true,
        multiple: false,
        title: "Select the project folder to track",
      });
      if (typeof picked !== "string") return; // cancelled
      await scan(picked);
    } catch (e) {
      setError(`The folder picker could not open: ${errText(e)}`);
    }
  }

  async function scan(folder: string) {
    setPhase({ name: "scanning", folder });
    setError(null);
    setPlan(null);
    setPlanError(null);
    try {
      const result = await api.trackingScan(folder);
      setSelected(
        new Set(
          result.providers.filter((p) => p.selected_by_default).map((p) => p.provider_id),
        ),
      );
      const seeded: Record<string, string> = {};
      for (const p of result.providers) {
        if (p.inferred_origin) seeded[p.provider_id] = p.inferred_origin;
      }
      setOrigins(seeded);
      setPhase({ name: "review", scan: result });
    } catch (e) {
      setError(errText(e));
      setPhase({ name: "idle" });
    }
  }

  // Rebuild the plan whenever the selection changes — the diff on screen
  // is always the diff that would be applied.
  useEffect(() => {
    if (phase.name !== "review") return;
    if (selected.size === 0) {
      setPlan(null);
      setPlanError(null);
      return;
    }
    let cancelled = false;
    const originPairs: [string, string][] = Object.entries(origins).filter(([id]) =>
      selected.has(id),
    );
    api
      .trackingPlanBuild([...selected], originPairs)
      .then((p) => {
        if (!cancelled) {
          setPlan(p);
          setPlanError(null);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setPlan(null);
          setPlanError(errText(e));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [phase.name, selected, origins]);

  async function startTracking() {
    setBusy(true);
    setError(null);
    setPhase({ name: "applying" });
    try {
      const report = await api.trackingApply(password.length > 0 ? password : null);
      setPassword("");
      if (report.failed) {
        setPhase({ name: "attention", report });
        return;
      }
      setWaitedMs(0);
      setDiagnoses(null);
      setPhase({ name: "waiting", report });
    } catch (e) {
      setError(errText(e));
      setPhase({ name: "attention", report: null });
    } finally {
      setBusy(false);
    }
  }

  // Poll for the first observed request.
  useEffect(() => {
    if (phase.name !== "waiting") return;
    const setupId = phase.report.setup_id;
    if (!setupId) return;
    const started = Date.now();
    const tick = async () => {
      try {
        const status = await api.trackingStatus(setupId);
        setWaitedMs(Date.now() - started);
        if (status.watch === "observed" || status.watch === "partial") {
          stopPolling();
          setPhase({ name: "verified", status });
        } else if (Date.now() - started >= DIAGNOSE_MS) {
          stopPolling();
          void runDiagnosis(setupId);
        }
      } catch (e) {
        stopPolling();
        setError(`Could not read the tracking state: ${errText(e)}`);
      }
    };
    pollRef.current = window.setInterval(() => void tick(), POLL_MS);
    void tick();
    return stopPolling;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase.name]);

  async function runDiagnosis(setupId: string) {
    setDiagnosing(true);
    try {
      const found = await api.trackingDiagnose(setupId);
      setDiagnoses(found);
    } catch (e) {
      setError(`Diagnostics could not run: ${errText(e)}`);
    } finally {
      setDiagnosing(false);
    }
  }

  async function startForegroundFallback() {
    setBusy(true);
    try {
      await api.trackingForegroundStart();
      setError(null);
      setPhase({ name: "idle" });
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  // ---- render ---------------------------------------------------------

  if (phase.name === "idle") {
    return (
      <section className="stack">
        <h1>Track API activity</h1>
        <p>
          Tethra can watch a project&apos;s API traffic locally and show requests, errors,
          latency, tokens, and estimated cost — metadata only, never prompts, keys, or bodies.
        </p>
        {error && (
          <p className="error" role="alert">
            {error}{" "}
            <button className="link" onClick={() => void pickFolder()}>
              Try again
            </button>
          </p>
        )}
        <div>
          <button onClick={() => void pickFolder()}>Select project folder</button>{" "}
          <button className="link" onClick={onDone}>
            Cancel
          </button>
        </div>
      </section>
    );
  }

  if (phase.name === "scanning") {
    return (
      <section className="stack">
        <h1>Track API activity</h1>
        <p>Scanning {phase.folder}…</p>
        <p className="muted">Only this folder is read. Nothing is uploaded or executed.</p>
      </section>
    );
  }

  if (phase.name === "review") {
    const scan = phase.scan;
    const configurable = scan.providers.filter((p) => p.configurability !== "unsupported");
    const automatic = configurable.filter((p) => p.configurability === "automatic");
    const needsConfirm = configurable.filter((p) => p.configurability !== "automatic");
    const unsupported = scan.providers.filter((p) => p.configurability === "unsupported");

    if (scan.providers.length === 0) {
      return (
        <section className="stack">
          <h1>No trackable APIs detected in this folder.</h1>
          <p>
            Tethra looked at .env files, package manifests, and lockfiles in {scan.folder} (
            {scan.scanned_files} file(s) read, 6 levels deep, nothing executed or uploaded).
          </p>
          {scan.skipped_oversized > 0 && (
            <p className="muted">
              {scan.skipped_oversized} file(s) were larger than the read limit and were skipped.
            </p>
          )}
          <ul>
            <li>Using a provider Tethra doesn&apos;t support yet? See Providers.</li>
            <li>
              Know the provider and its base URL? Advanced → Gateway internals has the manual
              route form.
            </li>
          </ul>
          <div>
            <button onClick={() => void pickFolder()}>Choose a different folder</button>{" "}
            <button className="link" onClick={onDone}>
              Cancel
            </button>
          </div>
        </section>
      );
    }

    return (
      <section className="stack">
        <h1>
          Tethra detected {scan.providers.length} API{scan.providers.length === 1 ? "" : "s"} in{" "}
          {scan.folder}
        </h1>
        <p>
          {automatic.length} can be configured automatically
          {needsConfirm.length > 0 && `, ${needsConfirm.length} need confirmation`}
          {unsupported.length > 0 && `, ${unsupported.length} not currently supported`}.
        </p>
        {scan.already_tracking && (
          <p className="notice">
            This folder is already tracked. Re-running setup is safe: existing routes and links
            are reused, not duplicated.
          </p>
        )}

        <h2>Detected APIs</h2>
        <ul className="stack">
          {scan.providers.map((p) => {
            const isUnsupported = p.configurability === "unsupported";
            const needsOrigin =
              p.configurability === "needs_origin_confirm" ||
              p.configurability === "needs_origin_input";
            return (
              <li key={p.provider_id}>
                <label>
                  <input
                    type="checkbox"
                    disabled={isUnsupported}
                    checked={selected.has(p.provider_id)}
                    onChange={(e) => {
                      const next = new Set(selected);
                      if (e.target.checked) next.add(p.provider_id);
                      else next.delete(p.provider_id);
                      setSelected(next);
                    }}
                  />{" "}
                  <strong>{p.display_name}</strong>{" "}
                  <span className="muted">
                    {isUnsupported ? "detected, not currently supported" : p.confidence}
                  </span>
                </label>
                <div className="muted">
                  {p.evidence.map((line, i) => (
                    <div key={i}>{line}</div>
                  ))}
                  {p.limitations.map((line, i) => (
                    <div key={`lim-${i}`}>{line}</div>
                  ))}
                </div>
                {needsOrigin && selected.has(p.provider_id) && (
                  <div className="field">
                    <label htmlFor={`origin-${p.provider_id}`}>
                      Its project URL (traffic will be forwarded only to this exact address)
                    </label>
                    <input
                      id={`origin-${p.provider_id}`}
                      className="mono"
                      value={origins[p.provider_id] ?? ""}
                      placeholder="https://your-project.example.com"
                      onChange={(e) =>
                        setOrigins({ ...origins, [p.provider_id]: e.target.value })
                      }
                    />
                  </div>
                )}
              </li>
            );
          })}
        </ul>

        <h2>Changes to your files</h2>
        {planError && (
          <p className="error" role="alert">
            The changes could not be prepared: {planError}
          </p>
        )}
        {!plan && !planError && selected.size > 0 && (
          <p className="muted">Preparing the diff…</p>
        )}
        {selected.size === 0 && (
          <p className="muted">Select at least one API above to see what would change.</p>
        )}
        {plan?.files.map((f) => (
          <div key={f.path}>
            <p className="mono">
              {f.path} {f.exists ? "" : "(will be created)"} {f.changed ? "" : "— no change"}
            </p>
            {f.changed && (
              <pre style={{ overflowX: "auto", background: "#f6f6f6", padding: "0.5rem" }}>
                {f.diff}
              </pre>
            )}
          </div>
        ))}
        {plan && plan.warnings.length > 0 && (
          <div className="warnbox">
            {plan.warnings.map((w, i) => (
              <div key={i}>! {w}</div>
            ))}
          </div>
        )}

        <h2>Starting tracking will</h2>
        <ul>
          {plan?.service_actions.map((a, i) => (
            <li key={i}>{a}</li>
          ))}
          <li>
            run a local background service on 127.0.0.1 (starts at login; on macOS it appears in
            System Settings → Login Items)
          </li>
          <li>create the provider routes shown above and apply the file changes shown above</li>
          <li>
            record request metadata: provider, endpoint template, status, latency, sizes, and
            token counts and model names when responses carry them
          </li>
        </ul>
        <p>
          It will never record API keys, authorization headers, cookies, query values, prompts,
          request bodies, or response bodies. Only the project you selected is configured; local
          or remote traffic that bypasses Tethra is not observed.
        </p>
        <p className="muted">
          Note: any local program can send traffic to the loopback port; the service is a
          standing local relay to the providers listed above.
        </p>

        <div className="field">
          <label htmlFor="track-password">
            Label traffic with which stored credential was used (recommended)
          </label>
          <input
            id="track-password"
            type="password"
            placeholder="Master password — leave empty to skip"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <small className="muted">
            You can enable this later from the dashboard. Tracking works either way.
          </small>
        </div>

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div>
          <button disabled={!plan || busy} onClick={() => void startTracking()}>
            Start tracking
          </button>{" "}
          <button className="link" onClick={onDone}>
            Cancel
          </button>
        </div>
        {!plan && selected.size > 0 && !planError && (
          <p className="muted">Start tracking is disabled until the changes are prepared.</p>
        )}
        {selected.size === 0 && (
          <p className="muted">
            Start tracking is disabled: nothing is selected, so there is nothing to configure.
          </p>
        )}
      </section>
    );
  }

  if (phase.name === "applying") {
    return (
      <section className="stack">
        <h1>Setting up tracking…</h1>
        <p className="muted">
          Installing the local service, creating routes, applying changes.
        </p>
      </section>
    );
  }

  if (phase.name === "waiting") {
    const report = phase.report;
    return (
      <section className="stack">
        <h1>Configuration applied</h1>
        <ul>
          {report.steps.map((s, i) => (
            <li key={i}>
              {s.outcome === "done" ? "✓" : s.outcome === "skipped" ? "•" : "✗"} {s.title}
              {s.detail && <span className="muted"> — {s.detail}</span>}
            </li>
          ))}
        </ul>
        {!report.attribution_enabled && (
          <p className="muted">
            Credential attribution is off — traffic is still recorded. You can enable it from
            the dashboard.
          </p>
        )}
        <h2>Almost done — one step left, in your project</h2>
        <p>
          {report.restart_expected
            ? "Restart your app, then make one API request."
            : "Make one API request from your app."}
        </p>
        <p className="muted">
          {waitedMs < RESTART_HINT_MS
            ? "Waiting for traffic…"
            : "Waiting for traffic… Tracking is not marked verified until a real request arrives."}
        </p>
        {diagnoses && (
          <div>
            <h2>No traffic has reached Tethra yet. Most likely causes, checked in order:</h2>
            <ol>
              {diagnoses.map((d, i) => (
                <li key={i}>{d.message}</li>
              ))}
            </ol>
          </div>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div>
          <button
            disabled={diagnosing || !report.setup_id}
            onClick={() => report.setup_id && void runDiagnosis(report.setup_id)}
          >
            {diagnosing ? "Checking…" : "Run diagnostics"}
          </button>{" "}
          <button className="link" onClick={onDone}>
            Open dashboard
          </button>
        </div>
      </section>
    );
  }

  if (phase.name === "verified") {
    const status = phase.status;
    const unseen = status.providers.filter((p) => !p.last_observed_at);
    return (
      <section className="stack">
        <h1>Tracking verified</h1>
        {status.observed_provider && (
          <p>
            Observed {status.observed_provider} from {status.folder}
            {status.observed_latency_ms !== null && ` (${status.observed_latency_ms} ms`}
            {status.observed_model && `, ${status.observed_model}`}
            {status.observed_latency_ms !== null && ")"}
          </p>
        )}
        {status.watch === "partial" && unseen.length > 0 && (
          <p className="muted">
            No {unseen.map((p) => p.provider_id).join(", ")} traffic observed yet — this is
            normal if the app hasn&apos;t called it. Tethra keeps watching.
          </p>
        )}
        <div>
          <button onClick={onDone}>Open dashboard</button>
        </div>
      </section>
    );
  }

  // attention
  const report = phase.report;
  const failed = report?.steps.find((s) => s.outcome === "failed");
  return (
    <section className="stack">
      <h1>Tracking is partially configured</h1>
      {report && (
        <ul>
          {report.steps.map((s, i) => (
            <li key={i}>
              {s.outcome === "done" ? "✓" : s.outcome === "skipped" ? "•" : "✗"} {s.title}
              {s.detail && <span className="muted"> — {s.detail}</span>}
            </li>
          ))}
        </ul>
      )}
      {failed && (
        <p className="error" role="alert">
          Setup stopped at “{failed.title}”: {failed.detail}. Completed steps are left in place.
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {report?.install_blocked && (
        <div className="warnbox">
          <p>macOS blocked the background service (this build is unsigned).</p>
          <button disabled={busy} onClick={() => void startForegroundFallback()}>
            Track while the app is open
          </button>
          <p className="muted">
            Tracking then runs only while Tethra is open. To allow the background service:
            System Settings → Privacy &amp; Security.
          </p>
        </div>
      )}
      <div>
        <button onClick={() => void pickFolder()}>Try again</button>{" "}
        <button className="link" onClick={onDone}>
          Back to dashboard
        </button>
      </div>
    </section>
  );
}
