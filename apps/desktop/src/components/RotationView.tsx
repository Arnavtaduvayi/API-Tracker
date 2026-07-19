// Credential rotation: durable, human-approved workflows. Planning is a dry
// run that creates nothing at the provider; approve, advance, rollback,
// complete-manual, and cancel are all reauthentication-gated. Schedules only
// raise "due" alerts — nothing ever runs automatically. Only masked values,
// version numbers, and provider-side key ids are ever shown.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type {
  Credential,
  ProviderKeyListing,
  RotationEvent,
  RotationSchedule,
  RotationView as RotationData,
} from "../types";
import { formatTimestamp } from "../utils";
import { ConfirmDialog } from "./ConfirmDialog";
import { ReauthDialog } from "./ReauthDialog";

type ActionKind = "approve" | "advance" | "rollback" | "complete_manual" | "cancel";

/** States in which Advance can still make progress (mirrors core is_active). */
const ADVANCEABLE = [
  "approved",
  "creating_replacement",
  "creating_in_progress",
  "awaiting_manual_key",
  "replacement_stored",
  "updating_destinations",
  "destinations_verified",
  "grace_period",
  "old_disabled",
];

/** An in-flight rotation idle for over a day needs human attention (the
 * monitor raises a rotation_stuck alert on the same condition). */
function needsAttention(state: string, updatedAt: string): boolean {
  if (!ADVANCEABLE.includes(state) && state !== "planned") return false;
  const idleMs = Date.now() - Date.parse(updatedAt);
  return Number.isFinite(idleMs) && idleMs > 24 * 60 * 60 * 1000;
}

function stateBadge(state: string) {
  const cls =
    state === "completed"
      ? "badge ok"
      : state === "failed"
        ? "badge bad"
        : state === "manual_required" || state === "rolling_back" || state === "rolled_back"
          ? "badge warn"
          : "badge";
  return <span className={cls}>{state.replaceAll("_", " ")}</span>;
}

function modeLabel(mode: string) {
  return mode === "api_create"
    ? "API creation (provider admin connection)"
    : "manual creation (provider dashboard)";
}

export function RotationView() {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [rotations, setRotations] = useState<RotationData[]>([]);
  const [filter, setFilter] = useState("");
  const [rotation, setRotation] = useState<RotationData | null>(null);
  const [events, setEvents] = useState<RotationEvent[]>([]);
  const [schedules, setSchedules] = useState<RotationSchedule[]>([]);

  // Plan form.
  const [planCredential, setPlanCredential] = useState("");
  const [graceMinutes, setGraceMinutes] = useState("60");
  const [providerProject, setProviderProject] = useState("");
  const [oldKeyId, setOldKeyId] = useState("");
  const [planNote, setPlanNote] = useState("");
  const [providerKeys, setProviderKeys] = useState<ProviderKeyListing[] | null>(null);

  // Per-action inputs on the selected rotation.
  const [provideValue, setProvideValue] = useState("");
  const [acknowledge, setAcknowledge] = useState(false);
  const [revokeNew, setRevokeNew] = useState(false);
  const [completeNote, setCompleteNote] = useState("manual provider-side steps done");

  // Schedule form.
  const [scheduleCredential, setScheduleCredential] = useState("");
  const [scheduleDays, setScheduleDays] = useState("90");
  const [removingSchedule, setRemovingSchedule] = useState<string | null>(null);

  const [confirming, setConfirming] = useState<ActionKind | null>(null);
  const [reauthing, setReauthing] = useState<ActionKind | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const credentialLabel = useCallback(
    (id: string) => {
      const c = credentials.find((cr) => cr.id === id);
      return c ? `${c.project_name}/${c.name}` : id;
    },
    [credentials],
  );

  const reloadRotations = useCallback(async (credential: string) => {
    setRotations(await api.rotationsList(credential || null, 50));
  }, []);

  const reloadSchedules = useCallback(async () => {
    setSchedules(await api.rotationSchedules());
  }, []);

  useEffect(() => {
    api
      .credentialList()
      .then((c) => setCredentials(c.filter((cr) => !cr.is_reference)))
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
    reloadSchedules().catch((e) => setError(isApiError(e) ? e.message : String(e)));
  }, [reloadSchedules]);

  useEffect(() => {
    reloadRotations(filter).catch((e) => setError(isApiError(e) ? e.message : String(e)));
  }, [filter, reloadRotations]);

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

  /** Show a rotation in the detail panel and reset per-action inputs. */
  const showRotation = async (view: RotationData) => {
    setRotation(view);
    setEvents(await api.rotationEvents(view.id));
    setProvideValue("");
    setAcknowledge(false);
  };

  const openRotation = (id: string) =>
    run(async () => {
      await showRotation(await api.rotationGet(id));
    });

  const plan = () =>
    run(async () => {
      const grace = Number(graceMinutes);
      if (!Number.isFinite(grace)) {
        setError("The grace period must be a number of minutes.");
        return;
      }
      const view = await api.rotationPlan({
        credential: planCredential,
        graceMinutes: grace,
        providerProject: providerProject.trim() || null,
        oldKeyId: oldKeyId.trim() || null,
        note: planNote.trim(),
      });
      await showRotation(view);
      await reloadRotations(filter);
      setPlanNote("");
      setNotice(
        "Dry run — nothing was created, written, or revoked. Review the plan below, then approve it.",
      );
    });

  const listProviderKeys = () =>
    run(async () => {
      const cred = credentials.find((c) => c.id === planCredential);
      if (!cred) {
        setError("Choose a credential first — its provider determines which keys to list.");
        return;
      }
      setProviderKeys(
        await api.providerListKeys(cred.provider, providerProject.trim() || null),
      );
    });

  /** Refresh everything after a state-changing action. */
  const applyResult = async (view: RotationData) => {
    await showRotation(view);
    await reloadRotations(filter);
    await reloadSchedules();
  };

  const confirmBody = (kind: ActionKind): string => {
    if (!rotation) return "";
    const target = `${rotation.project_name}/${rotation.credential_name}`;
    switch (kind) {
      case "approve":
        return (
          `Approve this rotation of ${target}? Subsequent steps will create a replacement key, ` +
          `update destinations, and eventually disable and revoke the OLD key at ` +
          `${rotation.provider}.`
        );
      case "rollback":
        return (
          `Roll this rotation back? Destinations and the vault value return to ` +
          `v${rotation.old_version ?? 0}` +
          (revokeNew
            ? "; the replacement key will be REVOKED at the provider."
            : ' (the replacement key stays valid — tick "also revoke the new key" to revoke it).')
        );
      case "complete_manual":
        return (
          "Confirm that you performed the manual provider-side steps " +
          "(e.g. revoked the old key in the dashboard)?"
        );
      case "cancel":
        return `Cancel this rotation of ${target}? Only rotations that have not changed anything yet can be cancelled.`;
      default:
        return "";
    }
  };

  const performAction = async (kind: ActionKind, password: string) => {
    if (!rotation) return;
    const id = rotation.id;
    let view: RotationData;
    if (kind === "approve") {
      view = await api.rotationApprove(id, password);
      setNotice("Approved. Use Advance to start executing.");
    } else if (kind === "advance") {
      view = await api.rotationAdvance(
        id,
        password,
        rotation.state === "awaiting_manual_key" && provideValue ? provideValue : null,
        acknowledge,
      );
      if (view.state === "completed") {
        setNotice("Rotation completed.");
      } else if (view.state === "manual_required") {
        setNotice("Manual provider-side action is required (see the manual steps below).");
      } else if (view.waiting_on) {
        setNotice("Advance again when ready.");
      }
    } else if (kind === "rollback") {
      view = await api.rotationRollback(id, password, revokeNew);
      setNotice("Rollback finished — review the state details below.");
    } else if (kind === "complete_manual") {
      view = await api.rotationCompleteManual(id, password, completeNote.trim());
      setNotice("Rotation completed after your confirmed manual provider-side action.");
    } else {
      view = await api.rotationCancel(id, password);
      setNotice(`Cancelled (state: ${view.state}).`);
    }
    await applyResult(view);
  };

  const setSchedule = () =>
    run(async () => {
      const days = Number(scheduleDays);
      if (!Number.isFinite(days) || days <= 0) {
        setError("The interval must be a positive number of days.");
        return;
      }
      await api.rotationScheduleSet(scheduleCredential, days);
      await reloadSchedules();
      setNotice(
        `Scheduled: a rotation of ${credentialLabel(scheduleCredential)} becomes DUE every ` +
          `${days} day(s). Nothing runs automatically — when due, the monitor raises an alert ` +
          `(and a desktop notification), and every destructive step still needs your approval ` +
          `and master password.`,
      );
    });

  const removeSchedule = (credentialId: string) =>
    run(async () => {
      const removed = await api.rotationScheduleRemove(credentialId);
      await reloadSchedules();
      setNotice(removed ? "Schedule removed." : "No schedule existed.");
    });

  const showAcknowledge =
    rotation !== null &&
    rotation.state === "grace_period" &&
    rotation.last_error.toLowerCase().includes("old key");

  return (
    <div>
      <h1>Rotation</h1>
      <p className="muted">
        A rotation replaces a credential end to end: dry-run plan, your approval, a replacement
        key (created via the provider API or by you in the dashboard), destination updates,
        validation of the new value, a grace/overlap period, and only then disabling/revoking
        the old key. Every step needs your master password; nothing runs automatically.
      </p>

      <h2>Plan a rotation (dry run)</h2>
      <div className="stack" style={{ maxWidth: "44rem" }}>
        <label className="field">
          Credential
          <select value={planCredential} onChange={(e) => setPlanCredential(e.target.value)}>
            <option value="">— choose —</option>
            {credentials.map((c) => (
              <option key={c.id} value={c.id}>
                {c.project_name}/{c.name} ({c.provider})
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Grace/overlap minutes (between deploying the new key and disabling the old)
          <input
            type="number"
            min={0}
            value={graceMinutes}
            onChange={(e) => setGraceMinutes(e.target.value)}
          />
        </label>
        <label className="field">
          Provider-side project (OpenAI project id / Supabase project ref — optional, derived
          from the linked key when empty)
          <input value={providerProject} onChange={(e) => setProviderProject(e.target.value)} />
        </label>
        <label className="field">
          Provider-side id of the OLD key (optional, derived from a confirmed link when empty)
          <input value={oldKeyId} onChange={(e) => setOldKeyId(e.target.value)} />
        </label>
        <div>
          <button onClick={() => void listProviderKeys()} disabled={busy || !planCredential}>
            List provider keys
          </button>{" "}
          <span className="muted">
            Uses the provider&apos;s administrative connection to list key ids.
          </span>
        </div>
        {providerKeys !== null &&
          (providerKeys.length === 0 ? (
            <p className="muted">The provider reported no keys.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Key id</th>
                  <th>Name</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Hint</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {providerKeys.map((k) => (
                  <tr key={k.id}>
                    <td className="mono">{k.id}</td>
                    <td>{k.name}</td>
                    <td>{k.status}</td>
                    <td>{formatTimestamp(k.created_at)}</td>
                    <td className="mono">{k.redacted_hint || "—"}</td>
                    <td>
                      <button className="link" onClick={() => setOldKeyId(k.id)}>
                        use as old key
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ))}
        <label className="field">
          Note (optional)
          <input value={planNote} onChange={(e) => setPlanNote(e.target.value)} />
        </label>
        <div>
          <button onClick={() => void plan()} disabled={busy || !planCredential}>
            {busy ? "Working…" : "Plan rotation (dry run)"}
          </button>
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      <h2>Rotations</h2>
      <label className="field" style={{ maxWidth: "24rem" }}>
        Filter by credential
        <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="">— all credentials —</option>
          {credentials.map((c) => (
            <option key={c.id} value={c.id}>
              {c.project_name}/{c.name}
            </option>
          ))}
        </select>
      </label>
      {rotations.length === 0 ? (
        <p>No rotations yet. Plan one above.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Rotation</th>
              <th>Credential</th>
              <th>State</th>
              <th>Mode</th>
              <th>Created</th>
              <th>Waiting on</th>
            </tr>
          </thead>
          <tbody>
            {rotations.map((r) => (
              <tr key={r.id}>
                <td>
                  <button className="link" onClick={() => void openRotation(r.id)}>
                    {r.id.slice(0, 8)}
                  </button>
                </td>
                <td>
                  {r.project_name}/{r.credential_name}
                </td>
                <td>
                  {stateBadge(r.state)}
                  {needsAttention(r.state, r.updated_at) && (
                    <>
                      {" "}
                      <span className="badge warn" title="in flight and idle for over 24h">
                        needs attention
                      </span>
                    </>
                  )}
                </td>
                <td className="mono">{r.mode}</td>
                <td>{formatTimestamp(r.created_at)}</td>
                <td>{r.waiting_on ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {rotation && (
        <div style={{ marginTop: "1rem" }}>
          <h2>
            Rotation of {rotation.project_name}/{rotation.credential_name}{" "}
            {stateBadge(rotation.state)}
          </h2>
          {rotation.state === "planned" && (
            <p className="notice">
              Dry run — nothing was created, written, or revoked. Approving is what allows the
              later steps to create a replacement, update destinations, and eventually
              disable/revoke the OLD key.
            </p>
          )}
          <dl className="detail-grid">
            <dt>Rotation id</dt>
            <dd className="mono">{rotation.id}</dd>
            <dt>Provider</dt>
            <dd>{rotation.provider}</dd>
            <dt>Mode</dt>
            <dd>{modeLabel(rotation.mode)}</dd>
            {rotation.note && (
              <>
                <dt>Note</dt>
                <dd>{rotation.note}</dd>
              </>
            )}
            <dt>Grace</dt>
            <dd>
              {rotation.grace_minutes} minute(s)
              {rotation.grace_ends_at && <> — ends {formatTimestamp(rotation.grace_ends_at)}</>}
            </dd>
            {rotation.old_version != null && rotation.new_version != null && (
              <>
                <dt>Versions</dt>
                <dd className="mono">
                  v{rotation.old_version} → v{rotation.new_version}
                </dd>
              </>
            )}
            {rotation.old_provider_key_id && (
              <>
                <dt>Old key id</dt>
                <dd className="mono">{rotation.old_provider_key_id}</dd>
              </>
            )}
            {rotation.new_provider_key_id && (
              <>
                <dt>New key id</dt>
                <dd className="mono">{rotation.new_provider_key_id}</dd>
              </>
            )}
            <dt>New value validated</dt>
            <dd>{rotation.new_value_validated ? "yes" : "not yet"}</dd>
            {rotation.old_disabled_at && (
              <>
                <dt>Old disabled</dt>
                <dd>{formatTimestamp(rotation.old_disabled_at)}</dd>
              </>
            )}
            {rotation.old_revoked_at && (
              <>
                <dt>Old revoked</dt>
                <dd>{formatTimestamp(rotation.old_revoked_at)}</dd>
              </>
            )}
            <dt>Created</dt>
            <dd>{formatTimestamp(rotation.created_at)}</dd>
          </dl>

          {rotation.last_error && (
            <p className="warnbox">
              Last error (the step stays retryable): {rotation.last_error}
            </p>
          )}
          {rotation.manual_instructions && (
            <div className="warnbox">
              <strong>Manual steps</strong> — API Tracker cannot do these for you:
              <ul>
                {rotation.manual_instructions.split("\n").map((line, i) => (
                  <li key={i}>{line}</li>
                ))}
              </ul>
            </div>
          )}
          {rotation.waiting_on && (
            <p>
              <strong>Waiting on:</strong> {rotation.waiting_on}
            </p>
          )}

          {rotation.state === "awaiting_manual_key" && (
            <label className="field" style={{ maxWidth: "32rem" }}>
              Replacement key value (created by you in the provider dashboard; stored encrypted,
              never displayed)
              <input
                type="password"
                value={provideValue}
                onChange={(e) => setProvideValue(e.target.value)}
                autoComplete="off"
              />
            </label>
          )}
          {showAcknowledge && (
            <label className="field">
              <span>
                <input
                  type="checkbox"
                  checked={acknowledge}
                  onChange={(e) => setAcknowledge(e.target.checked)}
                />{" "}
                Acknowledge continued use — I verified every consumer moved off the OLD key and
                want to proceed anyway.
              </span>
            </label>
          )}
          {rotation.old_version != null && !rotation.old_revoked_at && (
            <label className="field">
              <span>
                <input
                  type="checkbox"
                  checked={revokeNew}
                  onChange={(e) => setRevokeNew(e.target.checked)}
                />{" "}
                On rollback, also revoke the new key this rotation created.
              </span>
            </label>
          )}
          {(rotation.state === "manual_required" || rotation.state === "grace_period") && (
            <label className="field" style={{ maxWidth: "32rem" }}>
              Complete-manual note (what you did; recorded in the audit trail)
              <input value={completeNote} onChange={(e) => setCompleteNote(e.target.value)} />
            </label>
          )}

          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
            {rotation.state === "planned" && (
              <button disabled={busy} onClick={() => setConfirming("approve")}>
                Approve…
              </button>
            )}
            {ADVANCEABLE.includes(rotation.state) && (
              <button disabled={busy} onClick={() => setReauthing("advance")}>
                Advance…
              </button>
            )}
            {(rotation.state === "manual_required" || rotation.state === "grace_period") && (
              <button disabled={busy} onClick={() => setConfirming("complete_manual")}>
                Complete manual…
              </button>
            )}
            {rotation.old_version != null &&
              !rotation.old_revoked_at &&
              rotation.state !== "rolled_back" && (
                <button
                  className="danger"
                  disabled={busy}
                  onClick={() => setConfirming("rollback")}
                >
                  Roll back…
                </button>
              )}
            {["planned", "approved", "awaiting_manual_key"].includes(rotation.state) && (
              <button
                className="danger"
                disabled={busy}
                onClick={() => setConfirming("cancel")}
              >
                Cancel rotation…
              </button>
            )}
            <button disabled={busy} onClick={() => void openRotation(rotation.id)}>
              Refresh
            </button>
          </div>

          <h3>Events</h3>
          {events.length === 0 ? (
            <p className="muted">No events recorded.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>At</th>
                  <th>Transition</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => (
                  <tr key={i}>
                    <td>{formatTimestamp(e.at)}</td>
                    <td className="mono">
                      {e.from_state === ""
                        ? e.to_state
                        : e.from_state === e.to_state
                          ? `(${e.to_state})`
                          : `${e.from_state} → ${e.to_state}`}
                    </td>
                    <td>{e.detail || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      <h2>Schedules</h2>
      <p className="muted">
        A schedule is a reminder, never automation: when a rotation becomes due, the monitor
        raises an alert and a desktop notification — nothing is planned, approved, or executed
        automatically, and every destructive step still needs your approval and master password.
        Scheduling needs one manually approved, successfully completed rotation for the
        credential first.
      </p>
      {schedules.length === 0 ? (
        <p>No rotation schedules.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Credential</th>
              <th>Interval</th>
              <th>Next due</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {schedules.map((s) => (
              <tr key={s.credential_id}>
                <td>{credentialLabel(s.credential_id)}</td>
                <td>every {s.interval_days} day(s)</td>
                <td>{formatTimestamp(s.next_due_at)}</td>
                <td>
                  {s.enabled ? (
                    <span className="badge ok">enabled</span>
                  ) : (
                    <span className="badge warn">PAUSED: {s.paused_reason}</span>
                  )}
                </td>
                <td>
                  <button
                    className="link"
                    disabled={busy}
                    onClick={() => setRemovingSchedule(s.credential_id)}
                  >
                    remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="stack" style={{ maxWidth: "32rem" }}>
        <label className="field">
          Credential
          <select
            value={scheduleCredential}
            onChange={(e) => setScheduleCredential(e.target.value)}
          >
            <option value="">— choose —</option>
            {credentials.map((c) => (
              <option key={c.id} value={c.id}>
                {c.project_name}/{c.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Interval (days)
          <input
            type="number"
            min={1}
            value={scheduleDays}
            onChange={(e) => setScheduleDays(e.target.value)}
          />
        </label>
        <div>
          <button onClick={() => void setSchedule()} disabled={busy || !scheduleCredential}>
            Set schedule (re-enables a paused one)
          </button>
        </div>
      </div>

      {confirming && rotation && (
        <ConfirmDialog
          title={
            confirming === "approve"
              ? "Approve rotation"
              : confirming === "rollback"
                ? "Roll rotation back"
                : confirming === "complete_manual"
                  ? "Complete rotation manually"
                  : "Cancel rotation"
          }
          body={confirmBody(confirming)}
          confirmLabel="Continue to password"
          danger={confirming === "rollback" || confirming === "cancel"}
          onConfirm={() => {
            setReauthing(confirming);
            setConfirming(null);
          }}
          onCancel={() => setConfirming(null)}
        />
      )}
      {reauthing && rotation && (
        <ReauthDialog
          title={
            reauthing === "approve"
              ? "Confirm approval with your master password"
              : reauthing === "advance"
                ? "Advance the rotation (master password required)"
                : reauthing === "rollback"
                  ? "Confirm rollback with your master password"
                  : reauthing === "complete_manual"
                    ? "Confirm manual completion with your master password"
                    : "Confirm cancellation with your master password"
          }
          actionLabel={
            reauthing === "approve"
              ? "Approve"
              : reauthing === "advance"
                ? "Advance"
                : reauthing === "rollback"
                  ? "Roll back"
                  : reauthing === "complete_manual"
                    ? "Complete"
                    : "Cancel rotation"
          }
          onConfirm={async (password) => {
            await performAction(reauthing, password);
          }}
          onClose={() => setReauthing(null)}
        />
      )}
      {removingSchedule && (
        <ConfirmDialog
          title="Remove rotation schedule"
          body={`Remove the rotation schedule for ${credentialLabel(removingSchedule)}? Due reminders stop; the credential itself is not touched.`}
          confirmLabel="Remove"
          onConfirm={() => {
            const id = removingSchedule;
            setRemovingSchedule(null);
            void removeSchedule(id);
          }}
          onCancel={() => setRemovingSchedule(null)}
        />
      )}
    </div>
  );
}
