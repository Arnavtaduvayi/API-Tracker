// The Activity dashboard: the product's home surface (ADR 0022).
//
// Locally observed gateway traffic is the headline. Provider-reported
// usage is never summed with it (KNOWN_CONFLICTS C8) and lives in its own
// labeled section under Usage. Every panel distinguishes loading, empty,
// and error — a failed fetch renders the error and a retry, never an
// empty chart presented as "no data".
//
// Two things this file is deliberately careful about:
//
// * Present tense and past tense are separate headings. `CurrentHealth`
//   answers "is this working now"; `VerificationHistory` answers "was it
//   ever". Collapsing the two is how "verified previously, gateway down"
//   rendered as a success (ZFT-005).
// * No internal enum token reaches the screen. Every state, including the
//   attribution labels the gateway writes, is mapped to a sentence
//   (ZFT-030).
import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type {
  ForegroundStatus,
  GatewayActivitySummary,
  ProjectActivity,
  TrackingStatus,
} from "../types";
import {
  GATEWAY_ESTIMATED_COST,
  GATEWAY_TOKENS,
  type UsageAvailability,
  formatCostMicros,
  formatTokenPair,
  gatewayCostAvailability,
  gatewayTokenAvailability,
  hasValue,
} from "../usage";
import { ReauthDialog } from "./ReauthDialog";

function errText(e: unknown): string {
  return isApiError(e) ? e.message : String(e);
}

const RANGES: { label: string; days: number }[] = [
  { label: "Today", days: 1 },
  { label: "7 days", days: 7 },
  { label: "30 days", days: 30 },
];

function sinceIso(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}

/**
 * The attribution labels the gateway and the runtime store write, as
 * sentences.
 *
 * The dashboard used to print the raw column values — "matched_fingerprint
 * — 12", "unavailable — 4" — which are internal identifiers, not English,
 * and which a user cannot act on or even reliably guess at (ZFT-030). An
 * unknown label (a newer service writing a value this build predates) is
 * reported as unknown rather than shown bare.
 */
function attributionSentence(state: string): string {
  switch (state) {
    case "matched_fingerprint":
      return "Matched a stored credential by its fingerprint";
    case "confirmed":
      return "Matched the credential Tethra itself injected";
    case "high":
      return "Very likely the credential Tethra injected";
    case "possible":
      return "Possibly one of several stored credentials";
    case "ambiguous":
      return "Matched more than one stored credential, so none can be named";
    case "unattributed":
      return "No stored credential matched this request";
    case "unavailable":
      return "Attribution was not running when these requests were recorded";
    default:
      return `Recorded with a label this version of Tethra does not know (“${state}”)`;
  }
}

/**
 * The persisted `TrackingState` as a sentence. Kept as a fallback only, and
 * only for the PAST-tense section: present-tense truth comes from
 * `status.health.sentence`, which is derived from live evidence rather than
 * from a cached row.
 */
function stateLabel(state: string): string {
  switch (state) {
    case "traffic_observed":
      return "Traffic observed in this configuration";
    case "partially_observed":
      return "Some configured APIs observed, others not yet";
    case "awaiting_restart":
      return "Applied; waiting for the project to restart";
    case "awaiting_first_request":
      return "Applied; waiting for the first request";
    case "needs_attention":
      return "Needs attention";
    case "applying":
      return "Setting up — this setup never finished applying";
    case "unsupported":
      return "Nothing trackable detected";
    default:
      return "Not configured";
  }
}

export function DashboardView({ onTrack }: { onTrack: () => void }) {
  const [days, setDays] = useState(1);
  const [summary, setSummary] = useState<GatewayActivitySummary | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);
  const [byProject, setByProject] = useState<ProjectActivity[] | null>(null);
  const [byProjectError, setByProjectError] = useState<string | null>(null);
  const [setups, setSetups] = useState<TrackingStatus[] | null>(null);
  const [setupsError, setSetupsError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [foreground, setForeground] = useState<ForegroundStatus | null>(null);
  const [foregroundError, setForegroundError] = useState<string | null>(null);
  const [resume, setResume] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    // Each fetch is independent: one failing must not blank the others,
    // and every failure is rendered rather than swallowed. `await` inside
    // try/catch (not a .catch chain) so a synchronous throw is caught too.
    const activity = (async () => {
      try {
        setSummary(await api.gatewayActivity(sinceIso(days)));
        setSummaryError(null);
      } catch (e) {
        setSummary(null);
        setSummaryError(errText(e));
      }
    })();
    const perProject = (async () => {
      try {
        setByProject(await api.gatewayActivityByProject(sinceIso(days)));
        setByProjectError(null);
      } catch (e) {
        setByProject(null);
        setByProjectError(errText(e));
      }
    })();
    const tracking = (async () => {
      try {
        setSetups(await api.trackingList());
        setSetupsError(null);
      } catch (e) {
        setSetups(null);
        setSetupsError(errText(e));
      }
    })();
    // A failed foreground check is NOT "the background service is running".
    // Swallowing it into `false` rendered exactly like the healthy case, so
    // a user whose foreground helper had died believed tracking continued
    // after closing the app (ZFT-031).
    const fg = (async () => {
      try {
        setForeground(await api.trackingForegroundActive());
        setForegroundError(null);
      } catch (e) {
        setForeground(null);
        setForegroundError(errText(e));
      }
    })();
    await Promise.all([activity, perProject, tracking, fg]);
    setLoading(false);
  }, [days]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const attributionPaused = (setups ?? []).some((s) => s.attribution_paused);
  const notWorking = (setups ?? []).filter((s) => !s.health.currently_working);
  // Whether these numbers are knowable at all is a separate question from
  // whether the fetch succeeded. A successful fetch of a window in which no
  // response carried usage yields 0/0/$0 — the arithmetic identity of a
  // measured zero — so the guard is coverage, not `summary != null` (NEW-37).
  const unread: UsageAvailability = {
    kind: "unavailable",
    reason: "the activity summary could not be read",
  };
  const tokenAvailability = summary ? gatewayTokenAvailability(summary) : unread;
  const costAvailability = summary ? gatewayCostAvailability(summary) : unread;
  const successRate =
    summary && summary.total_requests > 0
      ? Math.round((summary.success_count / summary.total_requests) * 100)
      : null;
  const multiProject = (byProject ?? []).length > 1 || (setups ?? []).length > 1;

  return (
    <section className="stack dashboard-view">
      <div className="screen-heading">
        <div>
          <p className="screen-kicker">Local request telemetry</p>
          <h1>API activity</h1>
        </div>
        <button className="primary" onClick={onTrack}>
          Track API activity
        </button>
      </div>

      <div className="dashboard-toolbar">
        <div className="segmented" role="group" aria-label="Activity range">
          {RANGES.map((r) => (
            <button
              key={r.days}
              className={days === r.days ? "segment active" : "segment"}
              aria-pressed={days === r.days}
              onClick={() => setDays(r.days)}
            >
              {r.label}
            </button>
          ))}
        </div>
        <span className="dashboard-signal">Observing locally</span>
      </div>

      {foreground?.active && (
        <div className="notice">
          <p>
            Tracking pauses when Tethra closes (running in the foreground). Tethra stops that
            helper when it quits.
          </p>
          <button
            className="link"
            onClick={() => {
              void api
                .trackingForegroundStop()
                .then(() => {
                  setNotice("The foreground tracking helper was stopped.");
                  return reload();
                })
                .catch((e) => setNotice(`The helper could not be stopped: ${errText(e)}`));
            }}
          >
            Stop it now
          </button>
        </div>
      )}
      {foreground?.stopped && (
        <div className="warnbox" role="alert">
          <p>
            {foreground.detail ??
              "The helper that was tracking while Tethra is open is no longer running."}
          </p>
          <p className="muted">
            Traffic is not being recorded through it. Start tracking again, or allow the
            background service in System Settings → Privacy &amp; Security.
          </p>
        </div>
      )}
      {foregroundError && (
        <p className="error" role="alert">
          Whether tracking is running in the foreground could not be checked: {foregroundError}.
          Treat the tracking state below as unconfirmed.{" "}
          <button className="link" onClick={() => void reload()}>
            Retry
          </button>
        </p>
      )}
      {attributionPaused && (
        <div className="warnbox">
          <p>Credential attribution paused — traffic is still recorded.</p>
          <button onClick={() => setResume(true)}>Resume attribution</button>
        </div>
      )}
      {notice && <p className="notice">{notice}</p>}

      {/* --- locally observed traffic ---------------------------------- */}
      <h2>Observed locally (through Tethra)</h2>
      <p className="muted">
        {multiProject
          ? "These totals cover every tracked project on this machine. The per-project split is below."
          : "These totals cover every tracked project on this machine."}
      </p>
      {loading && !summary && !summaryError && <p className="muted">Loading activity…</p>}
      {summaryError && (
        <p className="error" role="alert">
          Activity could not be loaded: {summaryError}{" "}
          <button className="link" onClick={() => void reload()}>
            Retry
          </button>
        </p>
      )}
      {summary && summary.total_requests === 0 && (
        <div>
          <p>No activity observed yet.</p>
          <p className="muted">
            {setups && setups.length > 0
              ? "Restart the project and make one API request."
              : "Select a project folder and turn on tracking to see requests here."}
          </p>
          {setups && setups.length === 0 && (
            <button onClick={onTrack}>Track API activity</button>
          )}
        </div>
      )}
      {summary && summary.total_requests > 0 && (
        <dl className="metric-grid">
          <div>
            <dt>Requests</dt>
            <dd>{summary.total_requests}</dd>
          </div>
          <div>
            <dt>Success rate</dt>
            <dd>{successRate !== null ? `${successRate}%` : "—"}</dd>
          </div>
          <div>
            <dt>Errors</dt>
            <dd>
              {summary.error_count}
              {summary.transport_error_count > 0 &&
                ` (+${summary.transport_error_count} transport)`}
            </dd>
          </div>
          <div>
            <dt>Latency p50 / p95 / p99</dt>
            <dd>
              {summary.p50_latency_ms ?? "—"} / {summary.p95_latency_ms ?? "—"} /{" "}
              {summary.p99_latency_ms ?? "—"} ms
            </dd>
          </div>
          <div>
            <dt>Tokens in / out</dt>
            <dd>
              {formatTokenPair(
                summary.input_tokens,
                summary.output_tokens,
                tokenAvailability,
                GATEWAY_TOKENS,
              )}
            </dd>
          </div>
          <div>
            <dt>Estimated cost</dt>
            <dd>
              {formatCostMicros(
                summary.estimated_cost_micros,
                costAvailability,
                GATEWAY_ESTIMATED_COST,
                4,
              )}{" "}
              {/* The lower-bound caveat describes a figure. Printing it beside
                  "not reported" would attach an estimate's disclaimer to an
                  estimate that does not exist. */}
              {hasValue(costAvailability) && (
                <span className="muted">(lower bound; cache reads excluded)</span>
              )}
            </dd>
          </div>
          <div className="metric-wide">
            <dt>Observation window</dt>
            <dd>
              {summary.first_event_at ?? "—"} / {summary.last_event_at ?? "—"}
            </dd>
          </div>
        </dl>
      )}

      {/* --- which project generated it (ZFT-029) ---------------------- */}
      <h2>By project</h2>
      {byProjectError && (
        <p className="error" role="alert">
          The per-project split could not be loaded: {byProjectError}. The totals above are
          across all projects.{" "}
          <button className="link" onClick={() => void reload()}>
            Retry
          </button>
        </p>
      )}
      {byProject && byProject.length === 0 && !byProjectError && (
        <p className="muted">No requests in this window, so there is nothing to attribute.</p>
      )}
      {byProject && byProject.length > 0 && (
        <ul className="project-activity-list">
          {byProject.map((p) => (
            <li key={p.project_id}>
              <strong>{p.project_name ?? "A project that has since been removed"}</strong> —{" "}
              {p.total_requests} request(s), {p.error_count} error(s)
              {p.transport_error_count > 0 &&
                `, ${p.transport_error_count} transport failure(s)`}
              {p.last_event_at && <span className="muted"> · last {p.last_event_at}</span>}
            </li>
          ))}
        </ul>
      )}

      {summary && summary.top_endpoints.length > 0 && (
        <>
          <h2>Endpoints</h2>
          <ul>
            {summary.top_endpoints.map(([template, n]) => (
              <li key={template}>
                <span className="mono">{template}</span> — {n}
              </li>
            ))}
          </ul>
        </>
      )}
      {summary && summary.top_models.length > 0 && (
        <>
          <h2>Models</h2>
          <ul>
            {summary.top_models.map(([model, n]) => (
              <li key={model}>
                {model} — {n}
              </li>
            ))}
          </ul>
        </>
      )}
      {summary && summary.attribution.length > 0 && (
        <>
          <h2>Credential attribution</h2>
          <ul>
            {summary.attribution.map(([state, n]) => (
              <li key={state}>
                {attributionSentence(state)} — {n} request(s)
              </li>
            ))}
          </ul>
        </>
      )}

      {/* --- tracked projects ------------------------------------------ */}
      <h2>Tracked projects</h2>
      {loading && !setups && !setupsError && <p className="muted">Loading projects…</p>}
      {setupsError && (
        <p className="error" role="alert">
          Tracked projects could not be loaded: {setupsError}{" "}
          <button className="link" onClick={() => void reload()}>
            Retry
          </button>
        </p>
      )}
      {setups && setups.length === 0 && (
        <p className="muted">
          No project is tracked yet. Select a folder to start — it takes one screen.
        </p>
      )}
      {setups?.map((s) => (
        <div key={s.setup_id} className="stack tracked-project">
          <div>
            <strong className="mono">{s.folder}</strong>
          </div>
          <div>
            <h3>Right now</h3>
            {/* Verbatim from `CurrentHealth::describe`, for every state.
                This screen used to special-case `state === "applying"` with a
                sentence of its own, because a half-applied setup came back as
                "waiting for the first request" — advice that only makes sense
                for a setup that finished. `CurrentHealth::ApplyIncomplete`
                now answers that case at the source, so the rule lives in one
                place and the CLI states it identically (NEW-35). */}
            <p
              className={s.health.currently_working ? undefined : "warnbox"}
              role={s.health.currently_working ? undefined : "status"}
            >
              {s.health.sentence}
            </p>
          </div>
          <div>
            <h3>Previously</h3>
            <p className="muted">
              {s.history.sentence ??
                `This setup has never been verified. Recorded state: ${stateLabel(s.state)}.`}
            </p>
          </div>
          <div className="muted">
            {s.providers.length === 0
              ? "No APIs recorded for this setup."
              : s.providers
                  .map((p) =>
                    p.last_observed_at
                      ? `${p.provider_id}: last seen ${p.last_observed_at}`
                      : `${p.provider_id}: no traffic yet`,
                  )
                  .join(" · ")}
          </div>
          <div>
            <button
              className="link"
              onClick={() => {
                void api
                  .trackingDiagnose(s.setup_id)
                  .then((d) =>
                    setNotice(
                      d.length > 0
                        ? d.map((x) => x.message).join(" — ")
                        : "No diagnosis available.",
                    ),
                  )
                  .catch((e) => setNotice(`Diagnostics failed: ${errText(e)}`));
              }}
            >
              Run tracking check
            </button>{" "}
            <button
              className="link"
              onClick={() => {
                void api
                  .trackingUndo(s.setup_id)
                  .then((r) => {
                    setNotice(
                      r.complete
                        ? "Tracking stopped and files restored."
                        : "Some files could not be restored; the link was kept so you can retry.",
                    );
                    void reload();
                  })
                  .catch((e) => setNotice(`Stop tracking failed: ${errText(e)}`));
              }}
            >
              Stop tracking…
            </button>
          </div>
        </div>
      ))}

      {notWorking.length > 0 && (
        <p className="warnbox">
          {notWorking.length} project(s) are not tracking right now — see &ldquo;Right
          now&rdquo; above for each.
        </p>
      )}

      <p className="muted">
        Only traffic whose base URL points at Tethra is observed; some traffic may bypass
        Tethra. Provider-reported usage is shown separately under Usage and is never added to
        these numbers.
      </p>

      {resume && (
        <ReauthDialog
          title="Resume credential attribution"
          actionLabel="Resume"
          /* The same ADR-0020 disclosure as the Advanced push-key dialog and
             the Start-tracking screen. Resuming re-installs the same key, so
             it must state the same consequence (ZFT-013). */
          body={
            "This hands the local gateway a derived matching-only key so it can label " +
            "observed requests with the stored credential that made them. The key cannot " +
            "decrypt anything, but while it is resident, a process that can read the " +
            "gateway's memory (or its database) gains an oracle for testing whether a " +
            "value matches one of your credentials. It covers only credentials in linked, " +
            "non-password-locked projects. The key is dropped when the service stops, when " +
            "you revoke it, and when the vault locks (keep-while-locked defaults OFF; with " +
            "it ON a locked vault keeps matching for at most your auto-lock duration, 8 h " +
            "cap). Traffic is recorded either way."
          }
          onConfirm={async (password) => {
            await api.trackingResumeAttribution(password);
            setResume(false);
            setNotice("Credential attribution resumed.");
            await reload();
          }}
          onClose={() => setResume(false)}
        />
      )}
    </section>
  );
}
