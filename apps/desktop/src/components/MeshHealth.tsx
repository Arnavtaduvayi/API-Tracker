// Devices view: the `doctor` checks and "Replicate now" (Increment 09).
// Doctor decrypts this device's mesh keys to check them, so it runs when the
// panel opens and on request, never on a timer.

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { MeshDoctorReport, MeshReplicateResult, MeshSeverity } from "../types";
import { meshErrText } from "./MeshCommon";

const SEVERITY_CLASS: Record<MeshSeverity, string> = {
  ok: "finding ok",
  info: "finding",
  warning: "finding warn",
  problem: "finding bad",
};

const BADGE_CLASS: Record<MeshSeverity, string> = {
  ok: "badge ok",
  info: "badge",
  warning: "badge warn",
  problem: "badge bad",
};

const VIA_TEXT: Record<MeshReplicateResult["via"], string> = {
  app_node: "through this app's mesh node",
  external_node: "through the mesh node another process runs",
  one_shot: "directly, one exchange per known address (no node runs)",
};

function ReplicateOutcome({ r }: { r: MeshReplicateResult }) {
  return (
    <div>
      <p className="notice">
        Replicated {VIA_TEXT[r.via] ?? r.via}: {r.exchanges.length} exchange(s).
        {r.repairs_changed > 0 && ` Repair changed stored state ${r.repairs_changed} time(s).`}
      </p>
      {r.exchanges.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th scope="col">Address</th>
                <th scope="col">Device</th>
                <th scope="col">Items in</th>
                <th scope="col">Items out</th>
                <th scope="col">Result</th>
              </tr>
            </thead>
            <tbody>
              {r.exchanges.map((x, i) => (
                <tr key={`${x.addr}-${i}`}>
                  <td>
                    <code>{x.addr}</code>
                  </td>
                  <td>{x.device ?? <span className="muted">—</span>}</td>
                  <td>{x.items_in}</td>
                  <td>{x.items_out}</td>
                  <td>{x.error ? <span className="error">{x.error}</span> : "ok"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {r.notes.length > 0 && (
        <ul>
          {r.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function MeshHealth(props: { onChanged: () => void }) {
  const [report, setReport] = useState<MeshDoctorReport | null>(null);
  const [doctorError, setDoctorError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [replicating, setReplicating] = useState(false);
  const [result, setResult] = useState<MeshReplicateResult | null>(null);
  const [replicateError, setReplicateError] = useState<string | null>(null);

  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const runDoctor = useCallback(async () => {
    setChecking(true);
    try {
      const r = await api.meshDoctor();
      if (!mounted.current) return;
      setReport(r);
      setDoctorError(null);
    } catch (e) {
      if (mounted.current) setDoctorError(meshErrText(e));
    } finally {
      if (mounted.current) setChecking(false);
    }
  }, []);

  useEffect(() => {
    void runDoctor();
  }, [runDoctor]);

  const replicate = async () => {
    setReplicating(true);
    setResult(null);
    setReplicateError(null);
    try {
      const r = await api.meshReplicateNow(null);
      if (!mounted.current) return;
      setResult(r);
      props.onChanged();
      void runDoctor();
    } catch (e) {
      if (mounted.current) setReplicateError(meshErrText(e));
    } finally {
      if (mounted.current) setReplicating(false);
    }
  };

  const notOk = report?.findings.filter((f) => f.severity !== "ok") ?? [];
  const ok = report?.findings.filter((f) => f.severity === "ok") ?? [];

  return (
    <section className="card stack" aria-labelledby="mesh-health-title">
      <h2 id="mesh-health-title">Health</h2>
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button type="button" onClick={() => void replicate()} disabled={replicating}>
          {replicating ? "Replicating…" : "Replicate now"}
        </button>
        <button type="button" onClick={() => void runDoctor()} disabled={checking}>
          {checking ? "Checking…" : "Run checks again"}
        </button>
      </div>
      {replicateError && (
        <p className="error" role="alert">
          {replicateError}
        </p>
      )}
      {result && <ReplicateOutcome r={result} />}

      {doctorError && (
        <p className="error" role="alert">
          Could not run the checks: {doctorError}
        </p>
      )}
      {report === null && !doctorError && <p className="muted">Running the checks…</p>}
      {report && (
        <>
          <p>
            Overall: <span className={BADGE_CLASS[report.worst]}>{report.worst}</span>
          </p>
          {notOk.map((f, i) => (
            <div key={`${f.check}-${i}`} className={SEVERITY_CLASS[f.severity]}>
              <p style={{ margin: 0 }}>
                <span className={BADGE_CLASS[f.severity]}>{f.severity}</span>{" "}
                <code>{f.check}</code> {f.summary}
              </p>
              {f.fix && <p className="muted">Fix: {f.fix}</p>}
            </div>
          ))}
          {ok.length > 0 && (
            <details>
              <summary>{ok.length} check(s) passed</summary>
              <ul>
                {ok.map((f, i) => (
                  <li key={`${f.check}-${i}`}>
                    <code>{f.check}</code> {f.summary}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </section>
  );
}
