// Temporary LOCAL access grants for `api-tracker run`. A grant bounds what
// this machine injects (time window, launch count, per-process duration,
// credential subset). These are local controls only: they never constrain
// the provider-side credential, and local expiry is not provider revocation.
// The desktop app never terminates processes — it surfaces recorded PIDs and
// points at the CLI's `access end --kill`.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type { AccessGrant, Credential, GrantEndResult, Project } from "../types";
import { formatMicros, formatTimestamp } from "../utils";
import { ConfirmDialog } from "./ConfirmDialog";

function grantStatusBadge(status: AccessGrant["status"]) {
  const cls =
    status === "active" ? "badge ok" : status === "revoked" ? "badge bad" : "badge warn";
  return <span className={cls}>{status.replaceAll("_", " ")}</span>;
}

export function AccessView() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [grants, setGrants] = useState<AccessGrant[]>([]);
  const [includeInactive, setIncludeInactive] = useState(false);

  // Grant creation form.
  const [project, setProject] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [ttlMinutes, setTtlMinutes] = useState("60");
  const [oneTime, setOneTime] = useState(false);
  const [maxLaunches, setMaxLaunches] = useState("0");
  const [maxDurationSecs, setMaxDurationSecs] = useState("");
  const [budgetWarn, setBudgetWarn] = useState("");
  const [label, setLabel] = useState("");

  const [ending, setEnding] = useState<AccessGrant | null>(null);
  const [endResult, setEndResult] = useState<GrantEndResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reloadGrants = useCallback(async (all: boolean) => {
    setGrants(await api.accessGrants(all));
  }, []);

  useEffect(() => {
    api
      .projectList(false)
      .then(setProjects)
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
  }, []);

  useEffect(() => {
    reloadGrants(includeInactive).catch((e) => setError(isApiError(e) ? e.message : String(e)));
  }, [includeInactive, reloadGrants]);

  // Load the selected project's credentials for the subset picker.
  useEffect(() => {
    setSelected([]);
    if (!project) {
      setCredentials([]);
      return;
    }
    api
      .credentialList(project)
      .then(setCredentials)
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
  }, [project]);

  const projectName = useCallback(
    (id: string) => projects.find((p) => p.id === id)?.name ?? id,
    [projects],
  );

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

  const toggleCredential = (id: string) => {
    setSelected((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]));
  };

  const create = () =>
    run(async () => {
      const ttl = Number(ttlMinutes);
      if (!Number.isFinite(ttl) || ttl <= 0) {
        setError("The grant lifetime must be a positive number of minutes.");
        return;
      }
      const launches = oneTime ? 1 : Number(maxLaunches);
      if (!Number.isFinite(launches) || launches < 0) {
        setError("Max launches must be 0 (unlimited within the window) or positive.");
        return;
      }
      const duration = maxDurationSecs.trim() === "" ? null : Number(maxDurationSecs);
      if (duration !== null && (!Number.isFinite(duration) || duration <= 0)) {
        setError("The per-process duration must be a positive number of seconds.");
        return;
      }
      const grant = await api.accessGrantCreate({
        project,
        label: label.trim(),
        credentials: selected,
        ttlMinutes: ttl,
        maxLaunches: launches,
        maxDurationSecs: duration,
        budgetWarn: budgetWarn.trim() || null,
      });
      setEndResult(null);
      await reloadGrants(includeInactive);
      setLabel("");
      setNotice(
        `Grant ${grant.id} created — expires ${formatTimestamp(grant.expires_at)}, ` +
          (grant.max_launches === 0
            ? "unlimited launches within the window."
            : `${grant.max_launches} launch(es) max.`) +
          ` Run with it: api-tracker run --grant ${grant.id} -- <command>`,
      );
    });

  const endGrant = (grant: AccessGrant) =>
    run(async () => {
      const result = await api.accessGrantEnd(grant.id);
      setEndResult(result);
      await reloadGrants(includeInactive);
      setNotice(`Grant ${result.grant.id} ended. New launches are refused immediately.`);
    });

  return (
    <div>
      <h1>Temporary access</h1>
      <p className="muted">
        A grant bounds what <code>api-tracker run</code> will inject on this machine: which
        credentials, until when, how many launches, and (optionally) how long each launched
        process may live. These are LOCAL controls enforced by API Tracker on this device — they
        never constrain the provider-side credential, and local expiry is not provider
        revocation.
      </p>

      <h2>Create a grant</h2>
      <div className="stack" style={{ maxWidth: "44rem" }}>
        <label className="field">
          Project (whose credentials the grant may inject)
          <select value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="">— choose —</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        {project && (
          <div className="field">
            Limit to specific credentials (none selected = the project&apos;s configured
            mappings)
            {credentials.length === 0 ? (
              <p className="muted">This project has no credentials.</p>
            ) : (
              credentials.map((c) => (
                <label key={c.id}>
                  <input
                    type="checkbox"
                    checked={selected.includes(c.id)}
                    onChange={() => toggleCredential(c.id)}
                  />{" "}
                  {c.name} ({c.provider}, {c.environment})
                </label>
              ))
            )}
          </div>
        )}
        <label className="field">
          Lifetime (minutes)
          <input
            type="number"
            min={1}
            value={ttlMinutes}
            onChange={(e) => setTtlMinutes(e.target.value)}
          />
        </label>
        <label className="field">
          <span>
            <input
              type="checkbox"
              checked={oneTime}
              onChange={(e) => setOneTime(e.target.checked)}
            />{" "}
            One-time grant (exactly one launch)
          </span>
        </label>
        {!oneTime && (
          <label className="field">
            Maximum launches (0 = unlimited within the window)
            <input
              type="number"
              min={0}
              value={maxLaunches}
              onChange={(e) => setMaxLaunches(e.target.value)}
            />
          </label>
        )}
        <label className="field">
          Terminate each launched process after this many seconds (optional)
          <input
            type="number"
            min={1}
            value={maxDurationSecs}
            onChange={(e) => setMaxDurationSecs(e.target.value)}
          />
        </label>
        <label className="field">
          Budget warning threshold in dollars (optional; advisory only — it observes recorded
          usage and cannot cap provider-side spend)
          <input
            value={budgetWarn}
            placeholder="e.g. 5.00"
            onChange={(e) => setBudgetWarn(e.target.value)}
          />
        </label>
        <label className="field">
          Label (optional)
          <input value={label} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <div>
          <button onClick={() => void create()} disabled={busy || !project}>
            {busy ? "Working…" : "Create grant"}
          </button>
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      <h2>Grants</h2>
      <label className="field">
        <span>
          <input
            type="checkbox"
            checked={includeInactive}
            onChange={(e) => setIncludeInactive(e.target.checked)}
          />{" "}
          Include expired, used-up, and revoked grants
        </span>
      </label>
      {grants.length === 0 ? (
        <p>No grants{includeInactive ? "" : " active"}. Create one above.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Grant</th>
              <th>Project</th>
              <th>Label</th>
              <th>Status</th>
              <th>Expires</th>
              <th>Launches</th>
              <th>Proc TTL</th>
              <th>Budget warn</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id}>
                <td className="mono">{g.id.slice(0, 8)}</td>
                <td>{projectName(g.project_id)}</td>
                <td>{g.label || "—"}</td>
                <td>{grantStatusBadge(g.status)}</td>
                <td>{formatTimestamp(g.expires_at)}</td>
                <td>
                  {g.max_launches === 0
                    ? `${g.launches_used}`
                    : `${g.launches_used}/${g.max_launches}`}
                </td>
                <td>{g.max_duration_secs != null ? `${g.max_duration_secs}s` : "—"}</td>
                <td>
                  {g.budget_warn_micros != null ? formatMicros(g.budget_warn_micros) : "—"}
                </td>
                <td>
                  {g.status === "active" && (
                    <button className="link" disabled={busy} onClick={() => setEnding(g)}>
                      end
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {endResult && (
        <div className="warnbox">
          <strong>Grant {endResult.grant.id} ended.</strong>
          {endResult.running.length === 0 ? (
            <p>No recorded running processes.</p>
          ) : (
            <>
              <p>Recorded running processes launched under this grant:</p>
              <ul>
                {endResult.running.map((s) => (
                  <li key={s.session_id} className="mono">
                    session {s.session_id}: pid {s.pid} still running
                  </li>
                ))}
              </ul>
              <p>
                The desktop app does not terminate processes. To send SIGTERM to these, use the
                CLI: <code>api-tracker access end {endResult.grant.id} --kill</code>
              </p>
            </>
          )}
          <p>
            Reminder: values already injected into a process remain in its environment until it
            exits, and the provider credential itself stays valid — ending a grant never revokes
            anything at the provider.
          </p>
        </div>
      )}

      {ending && (
        <ConfirmDialog
          title="End access grant"
          body={
            `End grant ${ending.label ? `"${ending.label}" (${ending.id.slice(0, 8)})` : ending.id}? ` +
            "New launches are refused immediately. Running processes keep running — the " +
            "desktop app does not terminate them (the CLI's `access end --kill` can), and " +
            "values already injected stay in those processes until they exit. Ending a grant " +
            "never revokes the provider credential."
          }
          confirmLabel="End grant"
          danger
          onConfirm={() => {
            const grant = ending;
            setEnding(null);
            void endGrant(grant);
          }}
          onCancel={() => setEnding(null)}
        />
      )}
    </div>
  );
}
