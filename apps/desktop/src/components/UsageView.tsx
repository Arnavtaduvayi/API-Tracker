// Usage, cost, and budget for a chosen project or credential, plus the local
// activity log. Attribution precision is always shown; estimated costs are
// labeled and never presented as provider-reported.

import { useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type {
  ActivityEvent,
  BudgetReport,
  Credential,
  Project,
  ProviderConnection,
  UsageSnapshot,
  UsageTotals,
} from "../types";
import {
  RECORD_ESTIMATED_COST,
  RECORD_REPORTED_COST,
  RECORD_TOKENS,
  type UsageAvailability,
  availabilityNote,
  availabilitySentence,
  formatCostMicros,
  formatCount,
  hasValue,
  markStale,
  snapshotCostAvailability,
  snapshotTokenAvailability,
} from "../usage";
import { formatMicros } from "../utils";

type Target = { kind: "project"; id: string } | { kind: "credential"; id: string };
type SourceChoice = "all" | "provider" | "manual";

export function UsageView() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [target, setTarget] = useState<Target | null>(null);
  const [usage, setUsage] = useState<UsageTotals | null>(null);
  const [report, setReport] = useState<BudgetReport | null>(null);
  const [records, setRecords] = useState<UsageSnapshot[]>([]);
  // The rows the monthly totals were folded over — every source, not just the
  // one the table is filtered to. `UsageTotals` sums each Option with
  // `unwrap_or(0)` and keeps no count of the rows that carried nothing, so
  // this is the only place the completeness of those sums can be measured
  // (NEW-37). `usage_records` with source=all is the same scope and period
  // the totals query uses.
  const [totalsBasis, setTotalsBasis] = useState<UsageSnapshot[] | null>(null);
  const [source, setSource] = useState<SourceChoice>("all");
  const [connections, setConnections] = useState<ProviderConnection[]>([]);
  const [costSource, setCostSource] = useState<string>("best_available");
  const [activity, setActivity] = useState<ActivityEvent[]>([]);
  const [budgetInput, setBudgetInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.projectList(false), api.credentialList(), api.budgetCostSourceGet()])
      .then(([p, c, cs]) => {
        setProjects(p);
        setCredentials(c);
        setCostSource(cs);
        if (p.length > 0) setTarget({ kind: "project", id: p[0].id });
      })
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
    // Connection freshness for connected providers (stale-data warnings).
    Promise.all(
      ["openai", "anthropic"].map((p) => api.providerConnectionStatus(p).catch(() => null)),
    )
      .then((list) =>
        setConnections(list.filter((s): s is ProviderConnection => s !== null && s.connected)),
      )
      .catch(() => setConnections([]));
  }, []);

  useEffect(() => {
    if (!target) return;
    const project = target.kind === "project" ? target.id : undefined;
    const credential = target.kind === "credential" ? target.id : undefined;
    setError(null);
    Promise.all([
      api.usageReport(project, credential),
      api.budgetReport(project, credential),
      api.usageRecords({ project, credential, source }),
      api.activityList(credential ?? null, 25),
      source === "all"
        ? Promise.resolve(null)
        : api.usageRecords({ project, credential, source: "all" }),
    ])
      .then(([u, r, rec, a, all]) => {
        setUsage(u);
        setReport(r);
        setRecords(rec);
        setTotalsBasis(all ?? rec);
        setActivity(a);
        setBudgetInput(r.budget_micros != null ? (r.budget_micros / 1_000_000).toFixed(2) : "");
      })
      .catch((e) => {
        setTotalsBasis(null);
        setError(isApiError(e) ? e.message : String(e));
      });
  }, [target, source]);

  const changeCostSource = async (value: string) => {
    setError(null);
    try {
      await api.budgetCostSourceSet(value);
      setCostSource(value);
      setNotice(`Budgets now use the '${value}' cost source.`);
      if (target) {
        const project = target.kind === "project" ? target.id : undefined;
        const credential = target.kind === "credential" ? target.id : undefined;
        setReport(await api.budgetReport(project, credential));
      }
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  };

  const saveBudget = async () => {
    if (!target) return;
    setError(null);
    setNotice(null);
    try {
      const project = target.kind === "project" ? target.id : null;
      const credential = target.kind === "credential" ? target.id : null;
      await api.budgetSet(
        project,
        credential,
        budgetInput.trim() === "" ? null : budgetInput.trim(),
      );
      setNotice("Budget saved.");
      const r = await api.budgetReport(project ?? undefined, credential ?? undefined);
      setReport(r);
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  };

  const onSelect = (value: string) => {
    const [kind, id] = value.split(":");
    setTarget({ kind: kind as "project" | "credential", id });
  };

  /**
   * How complete one column of the monthly totals is. A sum that silently
   * absorbed NULLs is a floor, and a stale connection means even the known
   * rows stop short of now — neither may be rendered as a plain number
   * (NEW-37). The stale mark applies only when synced rows actually
   * contributed; a scope of hand-entered records is not made stale by an
   * unrelated connection.
   */
  const staleConnection = connections.find((c) => c.stale) ?? null;
  const columnAvailability = (
    of: (rows: UsageSnapshot[]) => UsageAvailability,
  ): UsageAvailability => {
    if (totalsBasis === null) {
      return {
        kind: "unavailable",
        reason: "the usage records these totals are folded over could not be read",
      };
    }
    const availability = of(totalsBasis);
    const syncedContributed = totalsBasis.some((r) => r.source !== "manual");
    return staleConnection && syncedContributed
      ? markStale(availability, staleConnection.last_success_at)
      : availability;
  };
  const inputTokens = columnAvailability((r) => snapshotTokenAvailability(r, "input_tokens"));
  const outputTokens = columnAvailability((r) => snapshotTokenAvailability(r, "output_tokens"));
  const reportedCost = columnAvailability((r) =>
    snapshotCostAvailability(r, "reported_cost_micros"),
  );
  const estimatedCost = columnAvailability((r) =>
    snapshotCostAvailability(r, "estimated_cost_micros"),
  );
  // The budget's "used" figure is folded from the same snapshots and inherits
  // their gaps, so an under-counted month can silently sit under a threshold
  // it has really crossed. The number stays (it is a floor, and a floor is
  // useful) but it is never presented as the whole spend.
  const usedIsEstimated = report?.used_is_estimated ?? false;
  const usedBasis = usedIsEstimated ? estimatedCost : reportedCost;
  const usedSubject = usedIsEstimated ? RECORD_ESTIMATED_COST : RECORD_REPORTED_COST;
  const usedCaveat = hasValue(usedBasis)
    ? availabilityNote(usedBasis, usedSubject)
    : availabilitySentence(usedBasis, usedSubject);

  return (
    <div>
      <h1>Usage &amp; cost</h1>
      <label className="field" style={{ maxWidth: "32rem" }}>
        Scope
        <select
          value={target ? `${target.kind}:${target.id}` : ""}
          onChange={(e) => onSelect(e.target.value)}
        >
          <optgroup label="Projects">
            {projects.map((p) => (
              <option key={p.id} value={`project:${p.id}`}>
                {p.name}
              </option>
            ))}
          </optgroup>
          <optgroup label="Credentials">
            {credentials.map((c) => (
              <option key={c.id} value={`credential:${c.id}`}>
                {c.project_name}/{c.name}
              </option>
            ))}
          </optgroup>
        </select>
      </label>

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      {connections.map(
        (c) =>
          c.stale && (
            <p className="error" key={c.provider}>
              {c.provider} data is stale — the last successful sync was{" "}
              {c.last_success_at ?? "never"}. Open the provider page to sync.
            </p>
          ),
      )}

      {usage && (
        <>
          <h2>This month</h2>
          <dl className="detail-grid">
            <dt>Requests</dt>
            <dd>{usage.request_count}</dd>
            <dt>Input tokens</dt>
            <dd>{formatCount(usage.input_tokens, inputTokens, RECORD_TOKENS)}</dd>
            <dt>Output tokens</dt>
            <dd>{formatCount(usage.output_tokens, outputTokens, RECORD_TOKENS)}</dd>
            <dt>Reported cost</dt>
            <dd>
              {formatCostMicros(usage.reported_cost_micros, reportedCost, RECORD_REPORTED_COST)}{" "}
              {hasValue(reportedCost) && <span className="muted">(provider-reported)</span>}
            </dd>
            <dt>Estimated cost</dt>
            <dd>
              {formatCostMicros(
                usage.estimated_cost_micros,
                estimatedCost,
                RECORD_ESTIMATED_COST,
              )}{" "}
              {hasValue(estimatedCost) && (
                <span className="muted">
                  (estimated locally from token counts and a bundled price table — may differ
                  from the provider&apos;s bill)
                </span>
              )}
            </dd>
            <dt>Attribution</dt>
            <dd>{usage.coarsest_attribution ?? "—"}</dd>
          </dl>
          {usage.has_non_usd_reported && (
            <p className="muted">
              Non-USD provider costs exist ({usage.reported_currencies.join(", ")}) and are
              excluded from the USD total above.
            </p>
          )}
          {usage.has_inexact_attribution && (
            <p className="muted">
              Some usage is not exact per-key and is not charged to a single credential.
            </p>
          )}
        </>
      )}

      <h2>Records</h2>
      <label className="field" style={{ maxWidth: "20rem" }}>
        Source
        <select value={source} onChange={(e) => setSource(e.target.value as SourceChoice)}>
          <option value="all">all</option>
          <option value="provider">provider-synced</option>
          <option value="manual">manual</option>
        </select>
      </label>
      {records.length === 0 ? (
        <p className="muted">No usage records for this scope and source.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Window</th>
              <th>Model / line item</th>
              <th>Amount</th>
              <th>Reported</th>
              <th>Estimated</th>
              <th>Attribution</th>
              <th>Provider key/project</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {records.slice(0, 30).map((r) => (
              <tr key={r.id}>
                <td>{r.window_start.slice(0, 10)}</td>
                <td>{r.model ?? r.line_item ?? "—"}</td>
                <td>
                  {/* Non-token units are shown verbatim, never as tokens. */}
                  {r.quantity != null && r.unit != null
                    ? `${r.quantity.toLocaleString()} ${r.unit}`
                    : r.total_tokens != null
                      ? `${r.total_tokens.toLocaleString()} tokens`
                      : "—"}
                </td>
                <td>
                  {r.reported_cost_micros != null
                    ? `${formatMicros(r.reported_cost_micros)} ${r.currency !== "USD" ? r.currency : ""}`
                    : "—"}
                </td>
                <td>
                  {r.estimated_cost_micros != null
                    ? `${formatMicros(r.estimated_cost_micros)} (est.)`
                    : "—"}
                </td>
                <td>{r.attribution.replace(/_/g, " ")}</td>
                <td className="mono">
                  {r.provider_api_key_id ?? r.provider_project_id ?? "—"}
                </td>
                <td>{r.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {records.length > 30 && (
        <p className="muted">Showing the 30 most recent of {records.length} records.</p>
      )}

      {report && (
        <>
          <h2>Budget</h2>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "flex-end" }}>
            <label className="field">
              Monthly budget (USD)
              <input
                type="text"
                placeholder="e.g. 25.00"
                value={budgetInput}
                onChange={(e) => setBudgetInput(e.target.value)}
              />
            </label>
            <button onClick={() => void saveBudget()}>Save budget</button>
          </div>
          <label className="field" style={{ maxWidth: "24rem" }}>
            Budget cost source
            <select value={costSource} onChange={(e) => void changeCostSource(e.target.value)}>
              <option value="best_available">best available (reported, else estimated)</option>
              <option value="provider_reported">provider-reported only</option>
              <option value="estimated">estimated only</option>
            </select>
          </label>
          <p>
            Used {formatMicros(report.used_micros)}{" "}
            <span className="muted">
              ({report.used_is_estimated ? "estimated" : "provider-reported"})
            </span>{" "}
            · projected month-end {formatMicros(report.projected_period_end_micros)}
            {report.over_budget && (
              <>
                {" "}
                · <span className="badge bad">over budget</span>
              </>
            )}
          </p>
          {usedCaveat && (
            <p className="muted">
              This is a lower bound, not the month&apos;s whole spend: {usedCaveat}
            </p>
          )}
        </>
      )}

      <h2>Recent activity</h2>
      {activity.length === 0 ? (
        <p className="muted">No activity recorded for this scope.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Source</th>
              <th>Kind</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {activity.map((a) => (
              <tr key={a.id}>
                <td>{a.at}</td>
                <td>{a.source}</td>
                <td>{a.kind}</td>
                <td>{a.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
