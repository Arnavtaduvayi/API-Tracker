// Cross-device usage for shared projects (Tethra Mesh, Increment 10; DESIGN
// §D14, MESH-SI-11, gateway SI-19). One project (`meshProjectId`) on the
// project page, or every shared project on the Usage page.
//
// Honesty rules this card keeps:
// - It is its own card with its own wording. Its figures are each device's
//   gateway-observed estimate and are never shown beside, mixed with or added
//   to provider figures.
// - Every row is one device, with core's freshness: "current" for this
//   device, "as of" the last exchange for the others, stale and removed
//   badges.
// - A device with no figures is listed as "No data from <device>": unknown,
//   never a row of zeros.
// - The total is core's sum, shown only with core's `total_label`, and the
//   report's notes are shown under the figures.
// - Unpriced, not-extracted and split-unknown requests are counted beside the
//   estimate, never folded into it as $0.
//
// It publishes this device's usage first (`publish: true`) on open and on
// Refresh only; it never polls. No analytics (MESH-SI-14).

import { useCallback, useEffect, useId, useRef, useState } from "react";
import { api } from "../api";
import type { MeshProjectUsage, MeshUsageReport } from "../types";
import { formatMicros } from "../utils";
import { meshDeviceLabel, meshErrText, shortId } from "./MeshCommon";
import { MeshAsOf, MeshDeviceCell, MeshNotes } from "./MeshFigureParts";

const n = (v: number) => v.toLocaleString();

function ProjectTable(props: { p: MeshProjectUsage; titled: boolean }) {
  const { p } = props;
  // A column for split-unknown requests only when some device has them.
  const showSplit = p.devices.some((d) => d.split_unknown_requests > 0);
  const cols = showSplit ? 10 : 9;
  const splitNotes = p.devices.filter((d) => d.split_known_since !== null);
  return (
    <div className="stack">
      {props.titled && (
        <h3 style={{ margin: 0 }}>
          {p.name} <code>{shortId(p.mesh_project_id)}</code>{" "}
          {p.archived && <span className="badge">archived</span>}
        </h3>
      )}
      {p.merged.length > 0 && (
        <p className="muted" style={{ margin: 0 }}>
          Includes the usage of {p.merged.length} merged project(s):{" "}
          {p.merged.map((m) => shortId(m)).join(", ")}.
        </p>
      )}
      <div style={{ overflowX: "auto" }}>
        <table>
          <thead>
            <tr>
              <th scope="col">Device</th>
              <th scope="col">Requests</th>
              <th scope="col">Priced</th>
              <th scope="col">Unpriced</th>
              <th scope="col">Not extracted</th>
              {showSplit && <th scope="col">Split unknown</th>}
              <th scope="col">Input tokens</th>
              <th scope="col">Output tokens</th>
              <th scope="col">Estimated cost</th>
              <th scope="col">As of</th>
            </tr>
          </thead>
          <tbody>
            {p.devices.map((d) => (
              <tr key={d.device_id}>
                <td>
                  <MeshDeviceCell
                    id={d.device_id}
                    name={d.device_name}
                    isSelf={d.is_self}
                    stale={d.stale}
                    removed={d.removed}
                  />
                </td>
                <td>{n(d.totals.requests)}</td>
                <td>{n(d.totals.priced_requests)}</td>
                <td>{n(d.totals.unpriced_requests)}</td>
                <td>{n(d.totals.unextracted_requests)}</td>
                {showSplit && <td>{n(d.split_unknown_requests)}</td>}
                <td>{n(d.totals.input_tokens)}</td>
                <td>{n(d.totals.output_tokens)}</td>
                <td>{formatMicros(d.totals.estimated_cost_micros)} est.</td>
                <td>
                  <MeshAsOf isSelf={d.is_self} asOf={d.as_of} />
                </td>
              </tr>
            ))}
            {p.no_data_from.map(([id, name]) => (
              <tr key={`none-${id}`}>
                <td>
                  <MeshDeviceCell
                    id={id}
                    name={name}
                    isSelf={false}
                    stale={false}
                    removed={false}
                  />
                </td>
                <td colSpan={cols - 1}>
                  <span className="muted">
                    No data from {meshDeviceLabel(name, id)}: unknown, not zero. It may not have
                    bound this project, or not exchanged since.
                  </span>
                </td>
              </tr>
            ))}
            {p.devices.length > 0 && (
              <tr>
                <th scope="row">Total — {p.total_label}</th>
                <td>{n(p.total.requests)}</td>
                <td>{n(p.total.priced_requests)}</td>
                <td>{n(p.total.unpriced_requests)}</td>
                <td>{n(p.total.unextracted_requests)}</td>
                {showSplit && <td />}
                <td>{n(p.total.input_tokens)}</td>
                <td>{n(p.total.output_tokens)}</td>
                <td>{formatMicros(p.total.estimated_cost_micros)} est.</td>
                <td />
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {p.devices.length === 0 && (
        <p className="muted" style={{ margin: 0 }}>
          No device has published figures for this project in this period, so there is no total.
        </p>
      )}
      {splitNotes.map((d) => (
        <p key={`split-${d.device_id}`} className="muted" style={{ margin: 0 }}>
          {meshDeviceLabel(d.device_name, d.device_id)}: the priced/unpriced split is known from{" "}
          {d.split_known_since}; earlier requests are counted as split unknown.
        </p>
      ))}
    </div>
  );
}

/**
 * `meshProjectId`: one shared project (the project page). Absent: every
 * shared project, and the card renders nothing outside a mesh (the Usage
 * page, where a mesh is optional).
 */
export function MeshUsageCard(props: { meshProjectId?: string; refreshKey?: number }) {
  const titleId = useId();
  const all = props.meshProjectId === undefined;
  /** All-projects mode only: null until the mesh status is known. */
  const [inMesh, setInMesh] = useState<boolean | null>(all ? null : true);
  const [report, setReport] = useState<MeshUsageReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const seq = useRef(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  /** Publishes this device's usage first: open, Refresh, and after an action only. */
  const load = useCallback(async () => {
    const mine = ++seq.current;
    setLoading(true);
    try {
      if (all) {
        let initialized = false;
        try {
          initialized = (await api.meshStatus()).initialized;
        } catch {
          // The Usage page is not where a broken mesh is diagnosed (the
          // Devices view shows that error); without a readable status this
          // card stays out of the way rather than guessing.
          initialized = false;
        }
        if (!mounted.current || mine !== seq.current) return;
        setInMesh(initialized);
        if (!initialized) return;
      }
      const r = await api.meshUsageReport(
        { project: props.meshProjectId ?? null, month: null, day: null },
        true,
      );
      if (!mounted.current || mine !== seq.current) return;
      setReport(r);
      setError(null);
    } catch (e) {
      if (!mounted.current || mine !== seq.current) return;
      setError(meshErrText(e));
    } finally {
      if (mounted.current && mine === seq.current) setLoading(false);
    }
  }, [all, props.meshProjectId]);

  useEffect(() => {
    void load();
  }, [load, props.refreshKey]);

  if (all && inMesh !== true) return null;

  return (
    <section className="card stack" aria-labelledby={titleId} data-testid="mesh-usage-card">
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
        <h2 id={titleId} style={{ margin: 0 }}>
          Usage across your devices (estimated, gateway-observed)
        </h2>
        <span style={{ flex: 1 }} />
        <button type="button" onClick={() => void load()} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>
      <p className="muted" style={{ margin: 0 }}>
        Tethra Mesh: what each of your devices&apos; gateways observed for{" "}
        {all ? "your shared projects" : "this shared project"}, priced by that device. A
        separate figure from the provider usage elsewhere in Tethra, and never added to it.
        {report && ` Period: ${report.period}.`}
      </p>
      {error && (
        <p className="error" role="alert">
          Could not read the usage across your devices: {error}
        </p>
      )}
      {report?.publish_error && (
        <p className="muted">
          This device&apos;s latest usage could not be published first ({report.publish_error}),
          so its own row may be behind its gateway.
        </p>
      )}
      {report === null && !error && <p className="muted">Loading…</p>}
      {report !== null && report.projects.length === 0 && (
        <p className="muted">
          {all
            ? "No shared projects yet. Share a project from its page, or bind one another device shared (Devices)."
            : "No figures for this shared project yet."}
        </p>
      )}
      {report?.projects.map((p) => (
        <ProjectTable key={p.mesh_project_id} p={p} titled={all} />
      ))}
      {report !== null && <MeshNotes notes={report.notes} />}
    </section>
  );
}
