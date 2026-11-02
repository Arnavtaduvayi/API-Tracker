// Spend caps for one shared project (Tethra Mesh, Increment 10; ADR 0032,
// DESIGN §D15, MESH-SI-9/11). Create, show, raise, lower, reclaim, and the
// reauthenticated "Enforce on this device" switch.
//
// - Every figure, label, flag and note is core's report as is (amounts are
//   formatted for display only; dollar inputs go to core as typed text).
// - A raise on a device that does not own the cap is a labelled local
//   override; the UI explains that and asks first. Lowering asks first.
// - Enforcement is per device and reauthenticated in core
//   (`UnlockedVault::mesh_cap_enforce`); the dialog here is UX only.
// - `reconcile: true` (a write) only on open, Refresh and after an action;
//   this panel never polls. No analytics (MESH-SI-14).

import { useCallback, useEffect, useId, useRef, useState } from "react";
import { api } from "../api";
import type {
  MeshCapMonthRow,
  MeshCapReport,
  MeshCapRow,
  MeshGateStatus,
  MeshProjectRow,
} from "../types";
import { formatMicros } from "../utils";
import { ConfirmDialog } from "./ConfirmDialog";
import { ReauthDialog } from "./ReauthDialog";
import {
  formatSignedMicros,
  meshDeviceLabel,
  meshErrText,
  scrubbed,
  shortId,
  typedUsd,
} from "./MeshCommon";
import { MeshAsOf, MeshDeviceCell, MeshNotes } from "./MeshFigureParts";

/** What switching enforcement on means; shown before the password is asked. */
export const ENFORCE_EXPLANATION =
  "With enforcement on, this device's gateway refuses requests to this project with HTTP 403 " +
  "(not 429, so SDKs do not retry them) once this device's share of the cap for the month is " +
  "used up; a refused request never reaches the provider. A request's cost is known only after " +
  "its response, so near the cap the gateway lets one request through at a time and the " +
  "overshoot is at most one request. Models without a price and responses without usage are " +
  "never blocked (they are counted as unpriced or unmetered). It is a self-limit on traffic " +
  "through Tethra's gateway, not a security boundary: requests that do not go through the " +
  "gateway are not capped. It applies to this device only, and no other device can change it.";

function CapMonth(props: { m: MeshCapMonthRow; label: string }) {
  const { m } = props;
  return (
    <div className="stack">
      <h4 style={{ margin: 0 }}>
        {props.label} ({m.month})
      </h4>
      <dl className="detail-grid">
        <dt>Target</dt>
        <dd>{m.target === null ? "no target for this month" : `${formatMicros(m.target)}`}</dd>
        {m.overrides > 0 && m.effective_target !== null && (
          <>
            <dt>Effective target</dt>
            <dd>
              {formatMicros(m.effective_target)}{" "}
              <span className="muted">
                (the target plus {formatMicros(m.overrides)} of local overrides)
              </span>
            </dd>
          </>
        )}
        <dt>Used across devices</dt>
        <dd>
          {formatMicros(m.total_used)}
          {m.used_pct !== null && ` (${m.used_pct}%)`}{" "}
          <span className="muted">— {m.total_label}</span>
        </dd>
        <dt>This device can still spend</dt>
        <dd>
          {m.local_avail === null ? (
            <span className="muted">nothing bound here</span>
          ) : (
            formatSignedMicros(m.local_avail)
          )}
        </dd>
        {m.pending_decrease > 0 && (
          <>
            <dt>Pending decrease</dt>
            <dd>{formatMicros(m.pending_decrease)} until devices burn rights</dd>
          </>
        )}
        {m.escrow_open > 0 && (
          <>
            <dt>In escrow here</dt>
            <dd>{formatMicros(m.escrow_open)} of rights this device is handing over</dd>
          </>
        )}
      </dl>
      {m.devices.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table aria-label={`Rights per device, ${m.month}`}>
            <thead>
              <tr>
                <th scope="col">Device</th>
                <th scope="col">Minted</th>
                <th scope="col">Received</th>
                <th scope="col">Sent</th>
                <th scope="col">Burned</th>
                <th scope="col">Used</th>
                <th scope="col">Available</th>
                <th scope="col">As of</th>
              </tr>
            </thead>
            <tbody>
              {m.devices.map((d) => (
                <tr key={d.device_id}>
                  <td>
                    <MeshDeviceCell
                      id={d.device_id}
                      name={d.device_name}
                      isSelf={d.is_self}
                      stale={d.stale}
                      removed={d.removed}
                    >
                      {d.is_owner && <span className="badge">owner</span>}
                    </MeshDeviceCell>
                  </td>
                  <td>
                    {formatMicros(d.minted)}{" "}
                    {d.is_override && <span className="badge warn">override</span>}
                  </td>
                  <td>{formatMicros(d.received)}</td>
                  <td>
                    {formatMicros(d.sent)}
                    {d.clamped > 0 && (
                      <span className="muted">
                        {" "}
                        (ignored {formatMicros(d.clamped)} sent beyond what it held)
                      </span>
                    )}
                  </td>
                  <td>{formatMicros(d.burned)}</td>
                  <td>{formatMicros(d.used)}</td>
                  <td>{formatSignedMicros(d.avail)}</td>
                  <td>
                    <MeshAsOf isSelf={d.is_self} asOf={d.as_of} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

type CapDialog =
  | { kind: "raise_override"; usd: string }
  | { kind: "lower"; usd: string }
  | { kind: "reclaim" }
  | { kind: "enforce"; on: boolean };

function CapCard(props: {
  cap: MeshCapRow;
  gate: MeshGateStatus | null;
  gateFresh: boolean;
  onChanged: () => void;
}) {
  const { cap } = props;
  const [raiseText, setRaiseText] = useState("");
  const [lowerText, setLowerText] = useState("");
  const [dialog, setDialog] = useState<CapDialog | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const ids = useId();

  const label = `spend cap ${shortId(cap.cap_id)}`;
  const owner = cap.owned_here
    ? "this device"
    : meshDeviceLabel(cap.owner_name, cap.owner_device);
  // Frozen and superseded caps take no raise, lower or reclaim (core refuses
  // them too); this only hides controls that cannot work.
  const adjustable = !cap.frozen && cap.superseded_by === null;
  const current = cap.months[0];
  const gateCap =
    props.gateFresh && current
      ? props.gate?.caps.find((g) => g.cap_id === cap.cap_id && g.month === current.month)
      : undefined;

  const act = async (fn: () => Promise<string>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await fn());
      props.onChanged();
    } catch (e) {
      setError(meshErrText(e));
    } finally {
      setBusy(false);
    }
  };

  const raise = (usd: string) =>
    act(async () => {
      const r = await api.meshCapRaise(cap.cap_id, usd);
      setRaiseText("");
      return r.is_override
        ? `Added ${formatMicros(r.amount_micros)} to this device only, as a local override for ` +
            `${r.months.join(", ")}.`
        : `Raised the cap by ${formatMicros(r.amount_micros)} for ${r.months.join(", ")}; ` +
            `${formatMicros(r.distributed_micros)} handed out to your other devices.`;
    });

  const lower = (usd: string) =>
    act(async () => {
      const r = await api.meshCapLower(cap.cap_id, usd);
      setLowerText("");
      return (
        `Lowered the cap to ${formatMicros(r.amount_micros)} a month (${r.months.join(", ")}); ` +
        `this device gave up ${formatMicros(r.burned_micros)} of rights. The other devices give ` +
        `up theirs as they hear of it.`
      );
    });

  const reclaim = () =>
    act(async () => {
      const r = await api.meshCapReclaim(cap.cap_id, null);
      return r.devices.length === 0
        ? "No other device holds unspent rights for this cap."
        : `Asked ${r.devices.map((d) => shortId(d)).join(", ")} to hand their unspent rights ` +
            "back at their next exchanges with this device.";
    });

  const enforce = async (password: string, on: boolean) => {
    try {
      await api.meshCapEnforce(password, cap.cap_id, on);
    } catch (e) {
      // The reauth dialog shows this, never the typed password.
      throw scrubbed(e, [password]);
    }
    setError(null);
    setNotice(
      on
        ? "This device's gateway now enforces this cap (it applies within 5 seconds while the gateway runs)."
        : "This device's gateway no longer enforces this cap; the cap still raises alerts.",
    );
    props.onChanged();
  };

  return (
    <section className="stack" aria-label={label} style={{ marginTop: "0.5rem" }}>
      <h3 style={{ margin: 0 }}>
        Spend cap <code>{shortId(cap.cap_id)}</code>{" "}
        {cap.frozen && <span className="badge bad">frozen</span>}{" "}
        {cap.superseded_by !== null && <span className="badge warn">replaced</span>}{" "}
        {cap.enforced_here && <span className="badge ok">enforced on this device</span>}
      </h3>
      <p className="muted" style={{ margin: 0 }}>
        Owner: {owner}
        {cap.project_name && ` · on ${cap.project_name}`}
      </p>
      {cap.frozen && (
        <p className="warnbox" role="status">
          Frozen: the device that owns this cap was removed, so no device adds rights to it any
          more. This month&apos;s rights stay usable; next month has none. Create a new spend
          cap for this project to replace it.
        </p>
      )}
      {cap.superseded_by !== null && (
        <p className="muted">Replaced by spend cap {shortId(cap.superseded_by)}.</p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && <p className="notice">{notice}</p>}

      {cap.months.map((m, i) => (
        <CapMonth
          key={m.month}
          m={m}
          label={i === 0 ? "This month" : "Next month (shares handed out in advance)"}
        />
      ))}

      {gateCap && gateCap.enforced && (
        <p className="muted">
          This device&apos;s gateway still admits {formatSignedMicros(gateCap.avail_micros)}{" "}
          this month
          {gateCap.near_exhaustion &&
            "; it is near the cap, so it lets one request through at a time"}
          . Refused: {gateCap.refused_requests}; unpriced: {gateCap.unpriced_requests}; without
          usage: {gateCap.unmetered_requests}
          {gateCap.accounting_incomplete && " (its accounting is incomplete)"}.
        </p>
      )}

      {(cap.superseded_by === null || cap.enforced_here) && (
        <div className="stack">
          <label>
            <input
              type="checkbox"
              checked={cap.enforced_here}
              disabled={busy}
              onChange={() => setDialog({ kind: "enforce", on: !cap.enforced_here })}
            />{" "}
            Enforce on this device
          </label>
          <p className="muted" style={{ margin: 0 }}>
            {cap.enforced_here
              ? "On: this device's gateway refuses this project's requests (HTTP 403) once this device's share for the month is used up."
              : "Off: on this device the cap raises alerts at 80% and 100% and blocks nothing."}{" "}
            Asks for your master password either way.
          </p>
        </div>
      )}

      {adjustable && (
        <div className="stack">
          <form
            style={{ display: "flex", gap: "0.5rem", alignItems: "flex-end", flexWrap: "wrap" }}
            onSubmit={(e) => {
              e.preventDefault();
              if (raiseText.trim() === "") return;
              if (cap.owned_here) void raise(raiseText);
              else setDialog({ kind: "raise_override", usd: raiseText });
            }}
          >
            <label className="field" htmlFor={`${ids}-raise`}>
              Raise by (USD)
              <input
                id={`${ids}-raise`}
                type="text"
                inputMode="decimal"
                placeholder="e.g. 10"
                value={raiseText}
                onChange={(e) => setRaiseText(e.target.value)}
              />
            </label>
            <button type="submit" disabled={busy || raiseText.trim() === ""}>
              Raise
            </button>
          </form>
          <p className="muted" style={{ margin: 0 }}>
            {cap.owned_here
              ? "This device owns the cap: a raise adds to it for every device, this month."
              : "This device does not own the cap: a raise here is a local override for this device only, this month."}
          </p>
          <form
            style={{ display: "flex", gap: "0.5rem", alignItems: "flex-end", flexWrap: "wrap" }}
            onSubmit={(e) => {
              e.preventDefault();
              if (lowerText.trim() === "") return;
              setDialog({ kind: "lower", usd: lowerText });
            }}
          >
            <label className="field" htmlFor={`${ids}-lower`}>
              Lower to (USD a month)
              <input
                id={`${ids}-lower`}
                type="text"
                inputMode="decimal"
                placeholder="e.g. 30"
                value={lowerText}
                onChange={(e) => setLowerText(e.target.value)}
              />
            </label>
            <button type="submit" disabled={busy || lowerText.trim() === ""}>
              Lower
            </button>
          </form>
          {cap.owned_here && (
            <div>
              <button
                type="button"
                disabled={busy}
                onClick={() => setDialog({ kind: "reclaim" })}
              >
                Reclaim unspent rights
              </button>{" "}
              <span className="muted">
                Asks your other devices to give unspent rights back to this device, for example
                before you remove one.
              </span>
            </div>
          )}
        </div>
      )}

      {dialog?.kind === "raise_override" && (
        <ConfirmDialog
          title="Add a local override?"
          body={
            `This device does not own this spend cap (${owner} does), so raising it here is a ` +
            `local override: it adds ${typedUsd(dialog.usd)} of rights to this device only, ` +
            "until the end of this month. Every device sees it labelled as an override. It does " +
            "not change the cap's target for your other devices."
          }
          confirmLabel="Add local override"
          onConfirm={() => {
            const usd = dialog.usd;
            setDialog(null);
            void raise(usd);
          }}
          onCancel={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "lower" && (
        <ConfirmDialog
          title={`Lower this spend cap to ${typedUsd(dialog.usd)} a month?`}
          body={
            "Every device gives up the rights it holds above its new share as it hears of the " +
            "change, and the owner takes back the rest; until then this panel shows a pending " +
            "decrease. Spend already made stays counted: lowering below what is already spent " +
            "caps every device at once for the rest of the month."
          }
          confirmLabel="Lower the cap"
          danger
          onConfirm={() => {
            const usd = dialog.usd;
            setDialog(null);
            void lower(usd);
          }}
          onCancel={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "reclaim" && (
        <ConfirmDialog
          title="Reclaim unspent rights?"
          body={
            "Every other device holding unspent rights for this cap is asked, at its next " +
            "exchanges with this device over the next 24 hours, to give them back to this " +
            "device. Meanwhile this device hands them no rights, so they may reach their share " +
            "early."
          }
          confirmLabel="Reclaim rights"
          onConfirm={() => {
            setDialog(null);
            void reclaim();
          }}
          onCancel={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "enforce" && (
        <ReauthDialog
          title={
            dialog.on
              ? "Enforce this spend cap on this device"
              : "Stop enforcing this spend cap on this device"
          }
          actionLabel={dialog.on ? "Enforce" : "Stop enforcing"}
          body={
            (dialog.on
              ? ""
              : "This device's gateway stops refusing this project's requests over the cap; " +
                "the cap still raises alerts. ") + ENFORCE_EXPLANATION
          }
          onConfirm={(password) => enforce(password, dialog.on)}
          onClose={() => setDialog(null)}
        />
      )}
    </section>
  );
}

export function CapsPanel(props: {
  meshProjectId: string;
  /** Every mesh project (`mesh_projects_list`), to find a merged project's root. */
  projects: MeshProjectRow[];
  /** An archived shared project takes no new cap. */
  archived?: boolean;
}) {
  const titleId = useId();
  const createId = useId();
  const [report, setReport] = useState<MeshCapReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [createText, setCreateText] = useState("");
  const [busy, setBusy] = useState(false);

  const seq = useRef(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  /** Reconciles first: on open, Refresh and after an action only (never polled). */
  const load = useCallback(async () => {
    const mine = ++seq.current;
    try {
      const r = await api.meshCapsList(true);
      if (!mounted.current || mine !== seq.current) return;
      setReport(r);
      setError(null);
    } catch (e) {
      if (!mounted.current || mine !== seq.current) return;
      setError(meshErrText(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // A cap counts for this project when it is on the same root (a merged
  // project's caps live on the project it folds into). Matching only;
  // `root` is core's.
  const rootOf = (id: string) =>
    props.projects.find((p) => p.mesh_project_id === id)?.root ?? id;
  const root = rootOf(props.meshProjectId);
  const caps = report?.caps.filter((c) => rootOf(c.mesh_project_id) === root) ?? [];
  // Core refuses a new cap while one that is not frozen exists (a new cap
  // replaces a frozen one); the form is offered exactly then.
  const canCreate = !props.archived && !caps.some((c) => !c.frozen && c.superseded_by === null);
  const gate = report?.gate ?? null;
  const gateFresh = report?.gate_fresh ?? false;
  const enforcedHere = caps.some((c) => c.enforced_here);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (createText.trim() === "") return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      // The cap goes on the root: core refuses one on a merged project.
      const r = await api.meshCapCreate(root, createText);
      setCreateText("");
      setNotice(
        `Created a ${formatMicros(r.monthly_micros)} monthly spend cap (from ${r.month}). This ` +
          `device owns it and handed ${formatMicros(r.distributed_micros)} out to your other devices.`,
      );
      await load();
    } catch (err) {
      setError(meshErrText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card stack" aria-labelledby={titleId} data-testid="mesh-caps-panel">
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
        <h2 id={titleId} style={{ margin: 0 }}>
          Spend cap
        </h2>
        <span style={{ flex: 1 }} />
        <button type="button" onClick={() => void load()}>
          Refresh
        </button>
      </div>
      <p className="muted" style={{ margin: 0 }}>
        A monthly ceiling on this project&apos;s gateway-estimated cost across all your devices.
        It raises alerts at 80% and 100% on every device; a device&apos;s gateway refuses
        requests over it only where you switch enforcement on.
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && <p className="notice">{notice}</p>}
      {report?.reconcile_error && (
        <p className="muted">
          The spend caps were not reconciled first ({report.reconcile_error}); the figures are
          from the last reconcile.
        </p>
      )}

      {caps.length > 0 && gateFresh && gate?.inactive_reason && (
        <p className={gate.failing_open ? "error" : "warnbox"} role="alert">
          Enforcement inactive: {gate.inactive_reason}.
          {gate.failing_open &&
            " The gateway is forwarding every request, so the spend caps you switched on here are not holding."}
        </p>
      )}
      {enforcedHere && !gateFresh && (
        <p className="warnbox" role="alert">
          Tethra&apos;s gateway does not seem to be running on this device (it has not reported
          recently), so nothing is being enforced right now.
        </p>
      )}

      {report === null && !error && <p className="muted">Loading…</p>}
      {caps.map((c) => (
        <CapCard
          key={c.cap_id}
          cap={c}
          gate={gate}
          gateFresh={gateFresh}
          onChanged={() => void load()}
        />
      ))}

      {report !== null && canCreate && (
        <form
          className="stack"
          onSubmit={(e) => void create(e)}
          aria-label="Create a spend cap"
        >
          {caps.length === 0 && <p style={{ margin: 0 }}>This project has no spend cap.</p>}
          <label className="field" htmlFor={createId} style={{ maxWidth: "20rem" }}>
            Monthly spend cap (USD)
            <input
              id={createId}
              type="text"
              inputMode="decimal"
              placeholder="e.g. 50"
              value={createText}
              onChange={(e) => setCreateText(e.target.value)}
            />
          </label>
          <p className="muted" style={{ margin: 0 }}>
            This device becomes the cap&apos;s owner: each month it hands every recently active
            device an equal share of rights.
          </p>
          <div>
            <button type="submit" disabled={busy || createText.trim() === ""}>
              Create a spend cap
            </button>
          </div>
        </form>
      )}

      {report !== null && caps.length > 0 && <MeshNotes notes={report.notes} />}
    </section>
  );
}
