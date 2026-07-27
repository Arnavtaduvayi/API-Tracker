// The Activity dashboard: the product's home surface (ADR 0022).
//
// Locally observed gateway traffic is the headline. Provider-reported
// usage is never summed with it (KNOWN_CONFLICTS C8) and lives in its own
// labeled section under Usage. Every panel distinguishes loading, empty,
// and error — a failed fetch renders the error and a retry, never an
// empty chart presented as "no data".
import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { GatewayActivitySummary, TrackingStatus } from "../types";
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

function stateLabel(state: string): string {
  switch (state) {
    case "traffic_observed":
      return "Tracking verified";
    case "partially_observed":
      return "Tracking verified — some APIs not yet observed";
    case "awaiting_restart":
      return "Project needs restart";
    case "awaiting_first_request":
      return "Waiting for first request";
    case "needs_attention":
      return "Needs attention";
    case "applying":
      return "Setting up…";
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
  const [setups, setSetups] = useState<TrackingStatus[] | null>(null);
  const [setupsError, setSetupsError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [foreground, setForeground] = useState(false);
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
    const tracking = (async () => {
      try {
        setSetups(await api.trackingList());
        setSetupsError(null);
      } catch (e) {
        setSetups(null);
        setSetupsError(errText(e));
      }
    })();
    const fg = (async () => {
      try {
        setForeground(await api.trackingForegroundActive());
      } catch {
        setForeground(false);
      }
    })();
    await Promise.all([activity, tracking, fg]);
    setLoading(false);
  }, [days]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const attributionPaused = (setups ?? []).some((s) => s.attribution_paused);
  const needsAttention = (setups ?? []).filter(
    (s) => s.state === "needs_attention" || s.state === "awaiting_restart",
  );
  const cost = summary ? (summary.estimated_cost_micros / 1_000_000).toFixed(4) : null;
  const successRate =
    summary && summary.total_requests > 0
      ? Math.round((summary.success_count / summary.total_requests) * 100)
      : null;

  return (
    <section className="stack">
      <h1>API activity</h1>

      <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
        {RANGES.map((r) => (
          <button
            key={r.days}
            className={days === r.days ? undefined : "link"}
            onClick={() => setDays(r.days)}
          >
            {r.label}
          </button>
        ))}
        <span className="spacer" />
        <button onClick={onTrack}>Track API activity</button>
      </div>

      {foreground && (
        <p className="notice">
          Tracking pauses when Tethra closes (running in the foreground).
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
        <dl className="detail-grid">
          <dt>Requests</dt>
          <dd>{summary.total_requests}</dd>
          <dt>Success rate</dt>
          <dd>{successRate !== null ? `${successRate}%` : "—"}</dd>
          <dt>Errors</dt>
          <dd>
            {summary.error_count}
            {summary.transport_error_count > 0 &&
              ` (+${summary.transport_error_count} transport)`}
          </dd>
          <dt>Latency p50 / p95 / p99</dt>
          <dd>
            {summary.p50_latency_ms ?? "—"} / {summary.p95_latency_ms ?? "—"} /{" "}
            {summary.p99_latency_ms ?? "—"} ms
          </dd>
          <dt>Tokens in / out</dt>
          <dd>
            {summary.input_tokens} / {summary.output_tokens}
          </dd>
          <dt>Estimated cost</dt>
          <dd>
            ${cost} <span className="muted">(lower bound; cache reads excluded)</span>
          </dd>
          <dt>First / last observed</dt>
          <dd>
            {summary.first_event_at ?? "—"} / {summary.last_event_at ?? "—"}
          </dd>
        </dl>
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
                {state} — {n}
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
        <div key={s.setup_id} className="stack">
          <div>
            <strong className="mono">{s.folder}</strong> — {stateLabel(s.state)}
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

      {needsAttention.length > 0 && (
        <p className="warnbox">
          {needsAttention.length} project(s) need attention — see the states above.
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
          body="Tethra will label observed requests with the stored credential that made them. Traffic is recorded either way."
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
