// The live half of a project page (ADR 0029).
//
// One shared refresh loop feeds every card, the chart and the table — see
// useLiveRefresh. No card owns a timer.
//
// Every token and cost figure goes through usage.ts rather than being formatted
// here. That module owns the one predicate that decides whether a number may be
// shown at all, and a surface that formatted its own would be free to render an
// unknown cost as "$0.00", which is the single thing this panel must never do.

import { useCallback, useMemo, useState } from "react";
import { api } from "../api";
import type {
  ObservedIntegration,
  ProjectActivityFilter,
  ProjectActivityRow,
  ProjectActivitySnapshot,
  ProjectCostCoverage,
} from "../types";
import {
  PROJECT_ESTIMATED_COST,
  PROJECT_TOKENS,
  availabilityNote,
  formatCostMicros,
  formatCount,
  hasValue,
  projectCostAvailability,
  projectTokenAvailability,
  tokenCoverageSentence,
  unpricedReasonSentence,
} from "../usage";
import { relativeTime, useLiveRefresh } from "../useLiveRefresh";
import { ActivityChart, CHART_METRIC_LABELS, type ChartMetric } from "./ActivityChart";

const RANGES: { id: string; label: string }[] = [
  { id: "1h", label: "Last hour" },
  { id: "24h", label: "24 hours" },
  { id: "7d", label: "7 days" },
  { id: "30d", label: "30 days" },
];

const METRICS: ChartMetric[] = [
  "requests",
  "input_tokens",
  "output_tokens",
  "total_tokens",
  "latency",
  "errors",
  "cost",
];

export function ProjectActivity(props: { projectIdent: string; enabled: boolean }) {
  const [range, setRange] = useState("24h");
  const [metric, setMetric] = useState<ChartMetric>("requests");
  const [filter, setFilter] = useState<ProjectActivityFilter>({});
  const [showCostDetail, setShowCostDetail] = useState(false);

  // The fetcher identity is what the loop keys on, so a changed range or filter
  // refetches rather than waiting for the next tick with stale arguments.
  const fetcher = useCallback(
    () => api.projectActivity(props.projectIdent, range, filter, 50),
    [props.projectIdent, range, filter],
  );

  const live = useLiveRefresh<ProjectActivitySnapshot>(fetcher, { enabled: props.enabled });
  const snap = live.data;

  const onFilterChange = useCallback((key: keyof ProjectActivityFilter, value: string) => {
    setFilter((prev) => ({ ...prev, [key]: value === "" ? null : value }));
  }, []);

  const activeFilters = useMemo(
    () => Object.values(filter).filter((v) => v !== null && v !== undefined && v !== "").length,
    [filter],
  );

  return (
    <section aria-labelledby="project-activity-heading">
      <h2 id="project-activity-heading">Live activity</h2>

      <div className="activitybar">
        <label className="field inline">
          Period
          <select
            value={range}
            onChange={(e) => setRange(e.target.value)}
            aria-label="Activity time range"
          >
            {RANGES.map((r) => (
              <option key={r.id} value={r.id}>
                {r.label}
              </option>
            ))}
          </select>
        </label>
        <button onClick={() => void live.refresh()} disabled={live.refreshing}>
          {live.refreshing ? "Refreshing…" : "Refresh"}
        </button>
        <span className="muted" aria-live="polite">
          {live.lastSuccessAt
            ? `Last updated ${relativeTime(live.lastSuccessAt)}`
            : "Not yet updated"}
          {live.failures > 0 && ` — retrying (${live.failures} failed)`}
        </span>
      </div>

      {live.error && (
        <p className="error" role="status">
          Could not refresh activity: {live.error}
          {snap && " The figures below are from the last successful refresh."}
        </p>
      )}

      {live.loading && !snap && <p>Loading activity…</p>}

      {snap && snap.no_observations && (
        <p className="notice" data-testid="awaiting-first-request">
          Waiting for the first request. Tethra is watching this project; run it and activity
          appears here automatically.
        </p>
      )}

      {snap && !snap.no_observations && (
        <>
          <SummaryCards snap={snap} />

          <div className="activitybar">
            <label className="field inline">
              Chart
              <select
                value={metric}
                onChange={(e) => setMetric(e.target.value as ChartMetric)}
                aria-label="Chart metric"
              >
                {METRICS.map((m) => (
                  <option key={m} value={m}>
                    {CHART_METRIC_LABELS[m]}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <ActivityChart
            points={snap.series}
            metric={metric}
            granularity={snap.granularity}
            unknownNote={
              metric === "cost"
                ? "No request in this period had a model, tokens and local pricing all known, so there is no cost to chart."
                : null
            }
          />

          <CostCoverage
            cost={snap.cost}
            expanded={showCostDetail}
            onToggle={() => setShowCostDetail((v) => !v)}
          />

          <Integrations
            integrations={snap.integrations}
            onRefresh={() => void live.refresh()}
          />

          <h3>Recent activity</h3>
          <Filters
            snap={snap}
            filter={filter}
            activeFilters={activeFilters}
            onChange={onFilterChange}
            onClear={() => setFilter({})}
          />
          <RecentTable rows={snap.recent} />
        </>
      )}
    </section>
  );
}

function SummaryCards(props: { snap: ProjectActivitySnapshot }) {
  const { snap } = props;
  const tokens = projectTokenAvailability(snap.cost);
  const cost = projectCostAvailability(snap.cost);
  const m = snap.metrics;
  const inputTokens = snap.cost.priced_input_tokens;
  const outputTokens = snap.cost.priced_output_tokens;

  return (
    <dl className="cards" data-testid="summary-cards">
      <div className="card">
        <dt>Requests</dt>
        <dd>{m.total.toLocaleString()}</dd>
      </div>
      <div className="card">
        <dt>Input tokens</dt>
        <dd>{formatCount(hasValue(tokens) ? inputTokens : null, tokens, PROJECT_TOKENS)}</dd>
      </div>
      <div className="card">
        <dt>Output tokens</dt>
        <dd>{formatCount(hasValue(tokens) ? outputTokens : null, tokens, PROJECT_TOKENS)}</dd>
      </div>
      <div className="card">
        <dt>Error rate</dt>
        <dd>{m.total > 0 ? `${(m.error_rate * 100).toFixed(1)}%` : "no requests yet"}</dd>
      </div>
      <div className="card">
        <dt>Average latency</dt>
        <dd>
          {m.p50_ms === null ? "not reported" : `${m.p50_ms.toLocaleString()} ms (p50)`}
          {m.latency_approximate && m.p50_ms !== null && (
            <span className="muted"> approx.</span>
          )}
        </dd>
      </div>
      <div className="card">
        <dt>Estimated known cost</dt>
        <dd>
          {formatCostMicros(
            // `micros_if_complete`'s rule, on this side of IPC: a floor is
            // never presented as a total. `formatCostMicros` renders the
            // sentence for a null instead of a dollar figure.
            hasValue(cost) ? snap.cost.estimated_micros : null,
            cost,
            PROJECT_ESTIMATED_COST,
            4,
          )}
        </dd>
      </div>
    </dl>
  );
}

function CostCoverage(props: {
  cost: ProjectCostCoverage;
  expanded: boolean;
  onToggle: () => void;
}) {
  const { cost } = props;
  const availability = projectCostAvailability(cost);
  const note = availabilityNote(availability, PROJECT_ESTIMATED_COST);
  const coverage = tokenCoverageSentence(cost);

  if (cost.complete && cost.unpriced.length === 0) {
    return (
      <p className="muted" data-testid="cost-complete">
        Every request in this period was priced from local pricing records.
        {coverage && ` ${coverage}.`}
      </p>
    );
  }

  return (
    <div className="warnbox" data-testid="cost-coverage">
      <p>
        <strong>Cost is partial for this period.</strong>{" "}
        {coverage
          ? `${coverage}.`
          : "No token usage was reported, so there is no ratio to state."}
      </p>
      {note && <p className="muted">{note}</p>}
      {cost.unpriced_requests > 0 && (
        <p>
          Unpriced usage: {cost.unpriced_requests.toLocaleString()} request(s) /{" "}
          {cost.unpriced_tokens.toLocaleString()} tokens.
        </p>
      )}
      {cost.requests_with_unknown_usage > 0 && (
        <p>
          {cost.requests_with_unknown_usage.toLocaleString()} request(s) reported no token
          usage, so their tokens are unknown — not zero.
        </p>
      )}
      {cost.any_stale_pricing && (
        <p>A pricing record used here is past its verification date.</p>
      )}
      {cost.truncated && (
        <p>This period had more usage groups than one refresh prices; totals are truncated.</p>
      )}
      <p>
        <button className="link" onClick={props.onToggle} aria-expanded={props.expanded}>
          {props.expanded ? "Hide" : "Review model pricing"}
        </button>
      </p>
      {props.expanded && (
        <table>
          <caption>Models without a usable local price</caption>
          <thead>
            <tr>
              <th scope="col">Provider</th>
              <th scope="col">Model</th>
              <th scope="col">Requests</th>
              <th scope="col">Tokens</th>
              <th scope="col">Why</th>
            </tr>
          </thead>
          <tbody>
            {cost.unpriced.map((u, i) => (
              <tr key={`${u.provider}-${u.model ?? "none"}-${i}`}>
                <td>{u.provider}</td>
                <td className="mono">{u.model ?? "not reported"}</td>
                <td>{u.requests.toLocaleString()}</td>
                <td>
                  {u.input_tokens === null || u.output_tokens === null
                    ? "not reported"
                    : (u.input_tokens + u.output_tokens).toLocaleString()}
                </td>
                <td>{unpricedReasonSentence(u.reason)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Integrations(props: { integrations: ObservedIntegration[]; onRefresh: () => void }) {
  const [naming, setNaming] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = async (host: string) => {
    setError(null);
    try {
      await api.projectNameUnknownApi(host, null, name.trim() || null);
      setNaming(null);
      setName("");
      props.onRefresh();
    } catch (e) {
      setError(e && typeof e === "object" && "message" in e ? String(e.message) : String(e));
    }
  };

  if (props.integrations.length === 0) return null;

  return (
    <>
      <h3>Detected APIs</h3>
      {error && <p className="error">{error}</p>}
      <table data-testid="integrations">
        <thead>
          <tr>
            <th scope="col">API</th>
            <th scope="col">Host</th>
            <th scope="col">Requests</th>
            <th scope="col">Errors</th>
            <th scope="col">Average latency</th>
            <th scope="col">Cost</th>
          </tr>
        </thead>
        <tbody>
          {props.integrations.map((it) => {
            const known = it.provider !== null;
            const display =
              it.user_api_name ?? it.provider ?? it.user_provider ?? "Unknown API";
            return (
              <tr key={it.host}>
                <td>
                  {display}
                  {!known && !it.user_api_name && (
                    <>
                      {" "}
                      <button
                        className="link"
                        onClick={() => {
                          setNaming(it.host);
                          setName("");
                        }}
                      >
                        Name it
                      </button>
                    </>
                  )}
                  {naming === it.host && (
                    <form
                      className="inlineform"
                      onSubmit={(e) => {
                        e.preventDefault();
                        void submit(it.host);
                      }}
                    >
                      <label className="field inline">
                        Name for {it.host}
                        <input
                          value={name}
                          onChange={(e) => setName(e.target.value)}
                          autoFocus
                        />
                      </label>
                      <button type="submit">Save</button>
                      <button type="button" onClick={() => setNaming(null)}>
                        Cancel
                      </button>
                    </form>
                  )}
                </td>
                <td className="mono">{it.host}</td>
                <td>{it.requests.toLocaleString()}</td>
                <td>{it.errors.toLocaleString()}</td>
                <td>
                  {it.avg_latency_ms === null
                    ? "not reported"
                    : `${it.avg_latency_ms.toLocaleString()} ms`}
                </td>
                <td>
                  {known ? (
                    "estimated where priced"
                  ) : (
                    <span className="muted">
                      Cost estimation unavailable
                      {it.internal ? " (internal address)" : ""}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {props.integrations.some((i) => i.provider === null) && (
        <p className="muted">
          An API Tethra does not recognise still reports requests, status, endpoint and latency.
          Credential attribution and cost estimation are unavailable for it, and naming it here
          does not change where any traffic goes.
        </p>
      )}
    </>
  );
}

function Filters(props: {
  snap: ProjectActivitySnapshot;
  filter: ProjectActivityFilter;
  activeFilters: number;
  onChange: (key: keyof ProjectActivityFilter, value: string) => void;
  onClear: () => void;
}) {
  const f = props.snap.facets;
  const selects: { key: keyof ProjectActivityFilter; label: string; values: string[] }[] = [
    { key: "provider", label: "Provider", values: f.providers },
    { key: "host", label: "Host", values: f.hosts },
    { key: "model", label: "Model", values: f.models },
    { key: "status_class", label: "Status", values: f.status_classes },
    { key: "endpoint", label: "Endpoint", values: f.endpoints },
    { key: "observation_source", label: "Source", values: f.observation_sources },
  ];
  return (
    <div className="activitybar" data-testid="activity-filters">
      {selects.map((s) => (
        <label key={s.key} className="field inline">
          {s.label}
          <select
            value={(props.filter[s.key] as string | null) ?? ""}
            onChange={(e) => props.onChange(s.key, e.target.value)}
            aria-label={`Filter by ${s.label.toLowerCase()}`}
          >
            <option value="">Any</option>
            {s.values.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
      ))}
      {props.activeFilters > 0 && (
        <button className="link" onClick={props.onClear}>
          Clear {props.activeFilters} filter(s)
        </button>
      )}
    </div>
  );
}

function RecentTable(props: { rows: ProjectActivityRow[] }) {
  if (props.rows.length === 0) {
    return <p className="muted">No requests match the current filters in this period.</p>;
  }
  return (
    <table data-testid="recent-activity">
      <thead>
        <tr>
          <th scope="col">Time</th>
          <th scope="col">API</th>
          <th scope="col">Endpoint</th>
          <th scope="col">Model</th>
          <th scope="col">Status</th>
          <th scope="col">Latency</th>
          <th scope="col">Tokens</th>
          <th scope="col">Est. cost</th>
        </tr>
      </thead>
      <tbody>
        {props.rows.map((r) => (
          <tr key={r.id}>
            <td>{new Date(r.at).toLocaleTimeString()}</td>
            <td>
              {r.provider ?? <span className="muted">Unknown API</span>}
              <div className="mono muted">{r.host}</div>
            </td>
            <td className="mono">
              {r.method} {r.endpoint}
            </td>
            <td className="mono">{r.model ?? "—"}</td>
            <td>
              <span className={`badge ${statusTone(r.status_class)}`}>
                {r.status_code ?? r.outcome}
              </span>
            </td>
            <td>{r.latency_ms === null ? "—" : `${r.latency_ms.toLocaleString()} ms`}</td>
            <td>
              {r.input_tokens === null || r.output_tokens === null
                ? "not reported"
                : `${r.input_tokens.toLocaleString()} in / ${r.output_tokens.toLocaleString()} out`}
            </td>
            <td>
              {r.estimated_micros === null ? (
                <span className="muted">unavailable</span>
              ) : (
                <>
                  ${(r.estimated_micros / 1_000_000).toFixed(4)}
                  {!r.cost_complete && <span className="muted"> (floor)</span>}
                </>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Map a status class to an existing badge tone. Never prints the raw class. */
function statusTone(statusClass: string): string {
  switch (statusClass) {
    case "2xx":
    case "3xx":
      return "ok";
    case "4xx":
      return "warn";
    case "5xx":
      return "bad";
    default:
      return "muted";
  }
}
