// Synchronization plans: reviewable, per-destination rollouts of a
// credential value change. A plan is generated as a dry run, reviewed here,
// and only executed after explicit confirmation plus master-password
// reauthentication. Only masked values and version numbers are ever shown.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { Credential, SyncPlan, SyncStep } from "../types";
import { formatTimestamp } from "../utils";
import { ConfirmDialog } from "./ConfirmDialog";
import { ReauthDialog } from "./ReauthDialog";

type Action = { kind: "execute" | "rollback"; plan: SyncPlan; onlyDestination: string | null };

function planStatusBadge(status: string) {
  const cls =
    status === "executed"
      ? "badge ok"
      : status === "partially_failed"
        ? "badge bad"
        : status === "rolled_back" || status === "stale"
          ? "badge warn"
          : "badge";
  return <span className={cls}>{status.replaceAll("_", " ")}</span>;
}

function stepStatusBadge(status: string) {
  const cls =
    status === "executed"
      ? "badge ok"
      : status === "failed"
        ? "badge bad"
        : status === "rolled_back"
          ? "badge warn"
          : "badge";
  return <span className={cls}>{status.replaceAll("_", " ")}</span>;
}

/** Steps that an execute run would touch (planned or failed write/re-export). */
function executableSteps(plan: SyncPlan, onlyDestination: string | null): SyncStep[] {
  return plan.steps.filter(
    (s) =>
      (s.action === "write" || s.action === "reexport") &&
      (s.status === "planned" || s.status === "failed") &&
      (onlyDestination === null || s.destination_id === onlyDestination),
  );
}

export function SyncView() {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [filter, setFilter] = useState("");
  const [note, setNote] = useState("");
  const [plans, setPlans] = useState<SyncPlan[]>([]);
  const [plan, setPlan] = useState<SyncPlan | null>(null);
  const [confirming, setConfirming] = useState<Action | null>(null);
  const [reauthing, setReauthing] = useState<Action | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reloadPlans = useCallback(async (credential: string) => {
    try {
      setPlans(await api.syncPlansList(credential || null, 50));
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    api
      .credentialList()
      .then((c) => setCredentials(c.filter((cr) => !cr.is_reference)))
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
  }, []);

  useEffect(() => {
    void reloadPlans(filter);
  }, [filter, reloadPlans]);

  const run = async (action: () => Promise<void>) => {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await action();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const generate = () =>
    run(async () => {
      if (!filter) {
        setError("Choose a credential to plan for.");
        return;
      }
      const created = await api.syncPlanCreate(filter, note.trim());
      setNote("");
      setPlan(created);
      setNotice(
        "Plan generated (dry run). Nothing has been written — review the steps, then execute.",
      );
      await reloadPlans(filter);
    });

  const openPlan = (id: string) =>
    run(async () => {
      setPlan(await api.syncPlanGet(id));
    });

  const describeSteps = (steps: SyncStep[]) =>
    steps
      .map((s) => `'${s.secret_name}' at ${s.destination_name} (${s.destination_kind})`)
      .join("; ");

  const confirmBody = (a: Action) => {
    if (a.kind === "rollback") {
      const executed = a.plan.steps.filter(
        (s) =>
          s.status === "executed" &&
          (a.onlyDestination === null || s.destination_id === a.onlyDestination),
      );
      return `Roll ${a.plan.project_name}/${a.plan.credential_name} back to retained version v${a.plan.from_version} (${a.plan.from_masked ?? "masked"}) by re-writing: ${describeSteps(executed) || "nothing (no executed steps)"}.`;
    }
    const steps = executableSteps(a.plan, a.onlyDestination);
    return `Write version v${a.plan.to_version} (${a.plan.to_masked}) of ${a.plan.project_name}/${a.plan.credential_name} to: ${describeSteps(steps) || "nothing (no pending steps)"}. Requests go directly from this machine to each destination.`;
  };

  const performAction = async (a: Action, password: string) => {
    const result =
      a.kind === "execute"
        ? await api.syncPlanExecute(a.plan.id, a.onlyDestination, password)
        : await api.syncPlanRollback(a.plan.id, a.onlyDestination, password);
    setPlan(result);
    const failed = result.steps.filter((s) => s.status === "failed").length;
    if (failed > 0) {
      setError(
        `${failed} step(s) failed — the plan is ${result.status.replaceAll("_", " ")}. ` +
          "Fix the cause and retry the failed steps, or roll back executed ones.",
      );
    } else {
      setNotice(a.kind === "execute" ? "Plan executed." : "Rollback complete.");
    }
    await reloadPlans(filter);
  };

  const pendingCount = plan ? executableSteps(plan, null).length : 0;
  const executedCount = plan ? plan.steps.filter((s) => s.status === "executed").length : 0;
  const hasFailed = plan ? plan.steps.some((s) => s.status === "failed") : false;

  return (
    <div>
      <h1>Sync plans</h1>
      <p className="muted">
        A sync plan is a reviewed, per-destination rollout of a credential&apos;s current value.
        Generating a plan writes nothing; execution requires your master password and explicit
        confirmation. Values are shown masked only.
      </p>

      <div className="stack" style={{ maxWidth: "44rem" }}>
        <label className="field">
          Credential (empty shows plans for every credential)
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="">— all credentials —</option>
            {credentials.map((c) => (
              <option key={c.id} value={c.id}>
                {c.project_name}/{c.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Note (why this rollout is happening, optional)
          <input value={note} onChange={(e) => setNote(e.target.value)} />
        </label>
        <div>
          <button onClick={() => void generate()} disabled={busy || !filter}>
            {busy ? "Working…" : "Generate plan (dry run)"}
          </button>
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      <h2>Plans</h2>
      {plans.length === 0 ? (
        <p>No plans yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Created</th>
              <th>Credential</th>
              <th>Change</th>
              <th>Status</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody>
            {plans.map((p) => (
              <tr key={p.id}>
                <td>
                  <button className="link" onClick={() => void openPlan(p.id)}>
                    {formatTimestamp(p.created_at)}
                  </button>
                </td>
                <td>
                  {p.project_name}/{p.credential_name}
                </td>
                <td className="mono">
                  {p.from_version != null ? `v${p.from_version}` : "—"} → v{p.to_version}
                </td>
                <td>{planStatusBadge(p.status)}</td>
                <td>{p.note || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {plan && (
        <div style={{ marginTop: "1rem" }}>
          <h2>
            Plan for {plan.project_name}/{plan.credential_name} {planStatusBadge(plan.status)}
          </h2>
          <dl className="detail-grid">
            <dt>Change</dt>
            <dd className="mono">
              {plan.from_version != null
                ? `v${plan.from_version} (${plan.from_masked ?? "masked"})`
                : "no retained previous version"}{" "}
              → v{plan.to_version} ({plan.to_masked})
            </dd>
            <dt>Created</dt>
            <dd>{formatTimestamp(plan.created_at)}</dd>
            {plan.note && (
              <>
                <dt>Note</dt>
                <dd>{plan.note}</dd>
              </>
            )}
            <dt>Affected projects</dt>
            <dd>{plan.affected_projects.join(", ") || "—"}</dd>
          </dl>

          {plan.status === "stale" && (
            <p className="warnbox">
              The credential&apos;s value changed after this plan was created. It can no longer
              be executed — generate a new plan.
            </p>
          )}
          {plan.status === "partially_failed" && (
            <p className="warnbox">
              Some steps failed while others were executed: destinations are currently
              inconsistent. Retry the failed steps, or roll back the executed ones.
            </p>
          )}
          {plan.manual_steps.length > 0 && (
            <div className="warnbox">
              <strong>Manual steps required</strong> — API Tracker cannot write these for you:
              <ul>
                {plan.manual_steps.map((m, i) => (
                  <li key={i}>{m}</li>
                ))}
              </ul>
            </div>
          )}

          <table>
            <thead>
              <tr>
                <th>Destination</th>
                <th>Kind</th>
                <th>Secret</th>
                <th>Action</th>
                <th>Validation</th>
                <th>Rollback?</th>
                <th>Status</th>
                <th>Detail</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {plan.steps.map((s) => (
                <tr key={`${s.destination_id}:${s.secret_name}`}>
                  <td>{s.destination_name}</td>
                  <td className="mono">{s.destination_kind}</td>
                  <td className="mono">{s.secret_name}</td>
                  <td>{s.action}</td>
                  <td>{s.validation}</td>
                  <td>{s.rollback_available ? "yes" : "no"}</td>
                  <td>
                    {stepStatusBadge(s.status)}
                    <div className="muted">
                      {s.executed_at && <>executed {formatTimestamp(s.executed_at)} </>}
                      {s.verified_at && <>verified {formatTimestamp(s.verified_at)} </>}
                      {s.rolled_back_at && <>rolled back {formatTimestamp(s.rolled_back_at)}</>}
                    </div>
                  </td>
                  <td>
                    {s.status === "failed" ? (
                      <span className="error">{s.detail}</span>
                    ) : (
                      s.detail || "—"
                    )}
                  </td>
                  <td>
                    {(s.action === "write" || s.action === "reexport") &&
                      (s.status === "planned" || s.status === "failed") &&
                      plan.status !== "stale" && (
                        <button
                          className="link"
                          disabled={busy}
                          onClick={() =>
                            setConfirming({
                              kind: "execute",
                              plan,
                              onlyDestination: s.destination_id,
                            })
                          }
                        >
                          {s.status === "failed" ? "retry" : "execute"}
                        </button>
                      )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button
              disabled={busy || pendingCount === 0 || plan.status === "stale"}
              onClick={() => setConfirming({ kind: "execute", plan, onlyDestination: null })}
            >
              {hasFailed ? "Retry failed steps…" : `Execute plan (${pendingCount} step(s))…`}
            </button>
            {plan.from_version != null && (
              <button
                className="danger"
                disabled={busy || executedCount === 0}
                onClick={() => setConfirming({ kind: "rollback", plan, onlyDestination: null })}
              >
                Roll back to v{plan.from_version}…
              </button>
            )}
            <button onClick={() => void openPlan(plan.id)} disabled={busy}>
              Refresh
            </button>
          </div>
        </div>
      )}

      {confirming && (
        <ConfirmDialog
          title={
            confirming.kind === "execute"
              ? "Execute synchronization plan"
              : "Roll back synchronization plan"
          }
          body={confirmBody(confirming)}
          confirmLabel={confirming.kind === "execute" ? "Continue to password" : "Continue"}
          danger={confirming.kind === "rollback"}
          onConfirm={() => {
            setReauthing(confirming);
            setConfirming(null);
          }}
          onCancel={() => setConfirming(null)}
        />
      )}
      {reauthing && (
        <ReauthDialog
          title={
            reauthing.kind === "execute"
              ? "Confirm execution with your master password"
              : "Confirm rollback with your master password"
          }
          actionLabel={reauthing.kind === "execute" ? "Execute" : "Roll back"}
          onConfirm={async (password) => {
            await performAction(reauthing, password);
          }}
          onClose={() => setReauthing(null)}
        />
      )}
    </div>
  );
}
