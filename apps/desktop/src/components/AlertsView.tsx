// Alerts: run local monitoring, view alerts, acknowledge/resolve. New
// high-severity alerts trigger a native desktop notification where the OS
// permits it.

import { useCallback, useEffect, useState } from "react";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { api, isApiError } from "../api";
import type { Alert, MonitorStatus } from "../types";
import { formatTimestamp } from "../utils";

function severityClass(sev: Alert["severity"]): "ok" | "warn" | "bad" {
  if (sev === "critical" || sev === "high") return "bad";
  if (sev === "medium") return "warn";
  return "ok";
}

async function notify(count: number) {
  if (count <= 0) return;
  try {
    let granted = await isPermissionGranted();
    if (!granted) {
      granted = (await requestPermission()) === "granted";
    }
    if (granted) {
      sendNotification({
        title: "Tethra",
        body: `${count} new high-priority alert(s)`,
      });
    }
  } catch {
    // Notifications are best-effort; never block the UI on them.
  }
}

export function AlertsView() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [includeResolved, setIncludeResolved] = useState(false);
  const [status, setStatus] = useState<MonitorStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setAlerts(await api.alertsList(includeResolved));
      setStatus(await api.monitorStatus());
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  }, [includeResolved]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const runMonitor = async () => {
    setError(null);
    setNotice(null);
    try {
      const report = await api.monitorRunFull();
      const summary = report.summary;
      setNotice(
        `Checked ${summary.checked} credential(s): ${summary.alerts_created} new, ` +
          `${summary.alerts_resolved} resolved, ${summary.open_alerts} open. ` +
          `Documentation checks: ${report.doc_checks} · webhook deliveries: ${report.delivered}.`,
      );
      await reload();
      const highNew = (await api.alertsList(false)).filter(
        (a) => a.severity === "high" || a.severity === "critical",
      ).length;
      if (summary.alerts_created > 0) void notify(highNew);
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  };

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      await reload();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  };

  return (
    <div>
      <h1>Alerts</h1>
      <p style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
        <button onClick={() => void runMonitor()}>Run checks now</button>
        <label>
          <input
            type="checkbox"
            checked={includeResolved}
            onChange={(e) => setIncludeResolved(e.target.checked)}
          />{" "}
          include acknowledged &amp; resolved
        </label>
      </p>
      {status && (status.last_run_at || status.last_failure_at) && (
        <p className="muted">
          Checks last ran {status.last_run_at ? formatTimestamp(status.last_run_at) : "never"}
          {status.last_success_at &&
            ` · last success ${formatTimestamp(status.last_success_at)}`}
          {status.last_failure_at &&
            ` · last failure ${formatTimestamp(status.last_failure_at)}`}
          {status.last_error && ` (${status.last_error})`}
          {status.last_detail && ` — ${status.last_detail}`}
        </p>
      )}
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}
      {alerts.length === 0 ? (
        <p>No alerts. Run the checks to evaluate your credentials.</p>
      ) : (
        alerts.map((a) => (
          <div key={a.id} className={`finding ${severityClass(a.severity)}`}>
            <div>
              <span className={`badge ${severityClass(a.severity)}`}>{a.severity}</span>{" "}
              <strong>{a.title}</strong>{" "}
              {a.resolved_at ? (
                <span className="muted">(resolved)</span>
              ) : a.acknowledged_at ? (
                <span className="muted">(acknowledged)</span>
              ) : null}
            </div>
            <div>{a.detail}</div>
            <div className="muted">Evidence: {a.evidence}</div>
            <div className="muted">Recommended: {a.recommended_action}</div>
            {!a.resolved_at && (
              <div style={{ marginTop: "0.3rem", display: "flex", gap: "0.5rem" }}>
                {!a.acknowledged_at && (
                  <button
                    className="link"
                    onClick={() => void act(() => api.alertAcknowledge(a.id))}
                  >
                    acknowledge
                  </button>
                )}
                <button className="link" onClick={() => void act(() => api.alertResolve(a.id))}>
                  resolve
                </button>
              </div>
            )}
          </div>
        ))
      )}
    </div>
  );
}
