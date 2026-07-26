// API activity — the runtime observability experience. Metadata only: this
// screen never shows request/response bodies, headers, cookies, query strings,
// or secrets, because none are ever stored. Monitored runs are launched from
// the CLI (`api-tracker run --observe -- <command>`); this screen inspects the
// resulting data and manages the local certificate + settings.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type {
  CompatibilityResult,
  CredentialAttribution,
  DiagnosticCheck,
  ObservabilitySettings,
  ObservationSession,
  ObserveCertStatus,
  ObserveMetrics,
  ObservedEndpoint,
  RuntimeEvent,
  ServiceOverview,
} from "../types";
import { ReauthDialog } from "./ReauthDialog";

type Tab = "overview" | "sessions" | "certificate" | "settings" | "privacy" | "diagnostics";

function errMsg(e: unknown): string {
  return isApiError(e) ? e.message : String(e);
}

function Metrics({ m }: { m: ObserveMetrics }) {
  const fmt = (v: number | null) => (v === null ? "—" : `${v}ms`);
  return (
    <dl className="detail-grid">
      <dt>Requests</dt>
      <dd>
        {m.total} ({m.success} success, {m.errors} errors, {(m.error_rate * 100).toFixed(1)}%
        error rate)
      </dd>
      <dt>Status classes</dt>
      <dd>
        2xx {m.c2xx} · 3xx {m.c3xx} · 4xx {m.c4xx} · 5xx {m.c5xx}
      </dd>
      <dt>Failures (separated)</dt>
      <dd>
        auth(401) {m.auth_errors} · forbidden(403) {m.forbidden} · rate-limited(429){" "}
        {m.rate_limited} · transport {m.transport_errors} · TLS {m.tls_errors}
      </dd>
      <dt>Latency</dt>
      <dd>
        p50 {fmt(m.p50_ms)} · p95 {fmt(m.p95_ms)} · p99 {fmt(m.p99_ms)}{" "}
        <span className="muted">(approximate, from a histogram)</span>
      </dd>
      <dt>Bytes</dt>
      <dd>
        req {m.request_bytes} · resp {m.response_bytes}
      </dd>
    </dl>
  );
}

export function ApiActivityView() {
  const [tab, setTab] = useState<Tab>("overview");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  return (
    <div className="stack">
      <h1>API activity</h1>
      <p className="muted">
        Metadata only — endpoint paths are sanitized; request/response bodies, header values,
        cookies, and query strings are never stored, and your traffic never leaves this device.
      </p>
      <nav className="tabs" style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        {(
          ["overview", "sessions", "certificate", "settings", "diagnostics", "privacy"] as Tab[]
        ).map((t) => (
          <button
            key={t}
            className={t === tab ? "" : "link"}
            onClick={() => {
              setTab(t);
              setError(null);
              setNotice(null);
            }}
          >
            {t === "overview"
              ? "Overview"
              : t === "sessions"
                ? "Sessions"
                : t === "certificate"
                  ? "Certificate"
                  : t === "settings"
                    ? "Settings"
                    : t === "diagnostics"
                      ? "Diagnostics"
                      : "Privacy"}
          </button>
        ))}
      </nav>
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      {tab === "overview" && <Overview onError={setError} />}
      {tab === "sessions" && <Sessions onError={setError} />}
      {tab === "certificate" && <Certificate onError={setError} onNotice={setNotice} />}
      {tab === "settings" && <Settings onError={setError} onNotice={setNotice} />}
      {tab === "diagnostics" && <Diagnostics onError={setError} />}
      {tab === "privacy" && <Privacy />}
    </div>
  );
}

function Overview({ onError }: { onError: (s: string) => void }) {
  const [services, setServices] = useState<ServiceOverview[]>([]);
  const [selected, setSelected] = useState<ServiceOverview | null>(null);
  const [endpoints, setEndpoints] = useState<ObservedEndpoint[]>([]);
  const [events, setEvents] = useState<RuntimeEvent[]>([]);

  useEffect(() => {
    api
      .observeOverview()
      .then(setServices)
      .catch((e) => onError(errMsg(e)));
  }, [onError]);

  const open = useCallback(
    (s: ServiceOverview) => {
      setSelected(s);
      api
        .observeServiceEndpoints(s.id)
        .then(setEndpoints)
        .catch((e) => onError(errMsg(e)));
      api
        .observeServiceEvents(s.id, 25)
        .then(setEvents)
        .catch((e) => onError(errMsg(e)));
    },
    [onError],
  );

  if (selected) {
    return (
      <div className="stack">
        <button className="link" onClick={() => setSelected(null)}>
          ← back to all APIs
        </button>
        <h2>
          {selected.host}{" "}
          <span className="muted">
            ({selected.user_provider ?? selected.provider_id ?? "unknown provider"} —{" "}
            {selected.source})
          </span>
        </h2>
        <Metrics m={selected.metrics} />
        <h3>Endpoints (sanitized)</h3>
        <table>
          <thead>
            <tr>
              <th>Method</th>
              <th>Path template</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {endpoints.map((e) => (
              <tr key={e.id}>
                <td className="mono">{e.method}</td>
                <td className="mono">{e.path_template}</td>
                <td>{e.template_confidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <h3>Recent events (sanitized)</h3>
        <table>
          <thead>
            <tr>
              <th>At</th>
              <th>Method</th>
              <th>Path</th>
              <th>Status</th>
              <th>Outcome</th>
              <th>Latency</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={i}>
                <td>{e.at}</td>
                <td className="mono">{e.method}</td>
                <td className="mono">{e.path_template}</td>
                <td>{e.status_code ?? "—"}</td>
                <td>{e.outcome}</td>
                <td>{e.latency_ms === null ? "—" : `${e.latency_ms}ms`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (services.length === 0) {
    return (
      <p className="muted">
        No API traffic observed yet. Launch a monitored run:{" "}
        <span className="mono">api-tracker run --observe -- &lt;command&gt;</span>
      </p>
    );
  }
  return (
    <table>
      <thead>
        <tr>
          <th>API</th>
          <th>Provider</th>
          <th>Requests</th>
          <th>Error rate</th>
          <th>p95</th>
        </tr>
      </thead>
      <tbody>
        {services.map((s) => (
          <tr key={s.id} onClick={() => open(s)} style={{ cursor: "pointer" }}>
            <td className="mono">{s.host}</td>
            <td>{s.user_provider ?? s.provider_id ?? "(unknown)"}</td>
            <td>{s.metrics.total}</td>
            <td>{(s.metrics.error_rate * 100).toFixed(0)}%</td>
            <td>{s.metrics.p95_ms === null ? "—" : `${s.metrics.p95_ms}ms`}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Sessions({ onError }: { onError: (s: string) => void }) {
  const [sessions, setSessions] = useState<ObservationSession[]>([]);
  const [detail, setDetail] = useState<{
    session: ObservationSession;
    metrics: ObserveMetrics;
    attributions: CredentialAttribution[];
    compat: CompatibilityResult[];
  } | null>(null);

  useEffect(() => {
    api
      .observeSessions(null, 50)
      .then(setSessions)
      .catch((e) => onError(errMsg(e)));
  }, [onError]);

  const open = useCallback(
    async (s: ObservationSession) => {
      try {
        const [metrics, attributions, compat] = await Promise.all([
          api.observeSessionMetrics(s.id),
          api.observeSessionAttributions(s.id),
          api.observeSessionCompat(s.id),
        ]);
        setDetail({ session: s, metrics, attributions, compat });
      } catch (e) {
        onError(errMsg(e));
      }
    },
    [onError],
  );

  if (detail) {
    const s = detail.session;
    return (
      <div className="stack">
        <button className="link" onClick={() => setDetail(null)}>
          ← back to sessions
        </button>
        <h2 className="mono">{s.command}</h2>
        <dl className="detail-grid">
          <dt>Mode</dt>
          <dd>
            {s.mode} — {s.status}
            {s.interrupt_reason ? ` (${s.interrupt_reason})` : ""}
          </dd>
          <dt>Runtime</dt>
          <dd>
            {s.runtime_detected ?? "—"} · trust {s.trust_level ?? "—"}
          </dd>
        </dl>
        {s.partial_coverage && (
          <div className="warnbox">
            <span className="badge bad">Partial coverage</span> Some traffic bypassed monitoring
            (see compatibility below). Metrics do not reflect the whole run.
          </div>
        )}
        <Metrics m={detail.metrics} />
        {detail.attributions.length > 0 && (
          <>
            <h3>Credential attribution</h3>
            <table>
              <thead>
                <tr>
                  <th>API</th>
                  <th>Confidence</th>
                  <th>Requests</th>
                  <th>Version</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {detail.attributions.map((a, i) => (
                  <tr key={i}>
                    <td className="mono">{a.host}</td>
                    <td>{a.confidence}</td>
                    <td>{a.request_count}</td>
                    <td>{a.credential_version === null ? "—" : `v${a.credential_version}`}</td>
                    <td className="muted">{a.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
        {detail.compat.length > 0 && (
          <>
            <h3>Compatibility</h3>
            <ul>
              {detail.compat.map((c, i) => (
                <li key={i}>
                  <span className="badge">{c.status}</span> {c.check}: {c.detail}
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    );
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Session</th>
          <th>Mode</th>
          <th>Status</th>
          <th>Runtime</th>
          <th>Req</th>
          <th>Err</th>
          <th>Coverage</th>
          <th>Started</th>
        </tr>
      </thead>
      <tbody>
        {sessions.map((s) => (
          <tr key={s.id} onClick={() => void open(s)} style={{ cursor: "pointer" }}>
            <td className="mono">{s.id.slice(0, 8)}</td>
            <td>{s.mode}</td>
            <td>{s.status}</td>
            <td>{s.runtime_detected ?? "—"}</td>
            <td>{s.request_count}</td>
            <td>{s.error_count}</td>
            <td>{s.partial_coverage ? <span className="badge bad">partial</span> : "full"}</td>
            <td>{s.started_at}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Certificate({
  onError,
  onNotice,
}: {
  onError: (s: string) => void;
  onNotice: (s: string) => void;
}) {
  const [status, setStatus] = useState<ObserveCertStatus | null>(null);
  const [pending, setPending] = useState<null | "rotate" | "remove" | "install">(null);

  const load = useCallback(() => {
    api
      .observeCertStatus()
      .then(setStatus)
      .catch((e) => onError(errMsg(e)));
  }, [onError]);
  useEffect(load, [load]);

  return (
    <div className="stack">
      <h2>Local certificate authority</h2>
      {!status?.present ? (
        <p className="muted">
          No local CA yet — one is generated automatically the first time you run a
          metadata-mode observation. The private key is stored encrypted under your vault and
          never leaves this device.
        </p>
      ) : (
        <dl className="detail-grid">
          <dt>Fingerprint (SHA-256)</dt>
          <dd className="mono">{status.fingerprint_sha256}</dd>
          <dt>Created</dt>
          <dd>{status.created_at}</dd>
          <dt>Expires</dt>
          <dd>{status.not_after}</dd>
          <dt>System trust</dt>
          <dd>{status.system_trust}</dd>
        </dl>
      )}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button onClick={() => setPending("rotate")} disabled={!status?.present}>
          Rotate CA
        </button>
        <button
          className="danger"
          onClick={() => setPending("remove")}
          disabled={!status?.present}
        >
          Remove CA
        </button>
        <button onClick={() => setPending("install")} disabled={!status?.present}>
          Install in system trust (Mode C)
        </button>
        <button
          onClick={() =>
            api
              .observeCertUninstallSystem()
              .then(() => {
                onNotice("Removed from the system trust store (if present).");
                load();
              })
              .catch((e) => onError(errMsg(e)))
          }
        >
          Remove from system trust
        </button>
      </div>
      <div className="warnbox">
        <strong>Mode C</strong> makes <em>every</em> application on this machine trust
        certificates signed by this CA. It is off by default, requires your master password, and
        shows the operating system's own prompt. The certificate can always be removed. Deleting
        the app does NOT remove a system-trust certificate.
      </div>

      {pending === "rotate" && (
        <ReauthDialog
          title="Rotate the local CA"
          actionLabel="Rotate"
          body="A new CA is generated. If you installed the old one in your system trust store, remove and reinstall it."
          onClose={() => setPending(null)}
          onConfirm={async (pw) => {
            await api.observeCertRotate(pw);
            setPending(null);
            onNotice("CA rotated.");
            load();
          }}
        />
      )}
      {pending === "remove" && (
        <ReauthDialog
          title="Remove the local CA"
          actionLabel="Remove"
          onClose={() => setPending(null)}
          onConfirm={async (pw) => {
            await api.observeCertRemove(pw);
            setPending(null);
            onNotice("CA removed.");
            load();
          }}
        />
      )}
      {pending === "install" && (
        <ReauthDialog
          title="Install the CA in your system trust store"
          actionLabel="Install"
          body="Your operating system will show its own authorization prompt. The CA key stays on this device; observation remains metadata-only."
          onClose={() => setPending(null)}
          onConfirm={async (pw) => {
            await api.observeCertInstallSystem(pw);
            setPending(null);
            onNotice("Installed in the system trust store.");
            load();
          }}
        />
      )}
    </div>
  );
}

function Settings({
  onError,
  onNotice,
}: {
  onError: (s: string) => void;
  onNotice: (s: string) => void;
}) {
  const [s, setS] = useState<ObservabilitySettings | null>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    api
      .observeSettingsGet()
      .then(setS)
      .catch((e) => onError(errMsg(e)));
  }, [onError]);

  if (!s) return <p className="muted">Loading…</p>;
  return (
    <div className="stack">
      <h2>Settings</h2>
      <label className="field">
        Default observation mode (stored preference)
        <select
          value={s.default_mode}
          onChange={(e) => setS({ ...s, default_mode: e.target.value })}
        >
          <option value="off">off (recommended — monitoring is opt-in per run)</option>
          <option value="connection">connection (no HTTPS decryption)</option>
          <option value="metadata">metadata (decrypts HTTPS for that process)</option>
        </select>
        <small>
          Note: this preference is stored but not yet consumed automatically. The desktop app
          does not launch monitored runs, and <code>api-tracker run</code> observes only when{" "}
          <code>--observe</code> is passed explicitly. Pass{" "}
          <code>--observe=connection|metadata</code> per run.
        </small>
      </label>
      <label className="field">
        Event retention (days)
        <input
          type="number"
          min={1}
          max={90}
          value={s.event_retention_days}
          onChange={(e) => setS({ ...s, event_retention_days: Number(e.target.value) })}
        />
      </label>
      <label className="field">
        Aggregate retention (days)
        <input
          type="number"
          min={7}
          max={730}
          value={s.aggregate_retention_days}
          onChange={(e) => setS({ ...s, aggregate_retention_days: Number(e.target.value) })}
        />
      </label>
      <button
        onClick={() =>
          api
            .observeSettingsSet({
              defaultMode: s.default_mode,
              eventDays: s.event_retention_days,
              aggregateDays: s.aggregate_retention_days,
            })
            .then(() => onNotice("Settings saved."))
            .catch((e) => onError(errMsg(e)))
        }
      >
        Save settings
      </button>

      <h3>Delete observability data</h3>
      <p className="muted">
        Removes all observed sessions, events, metrics, and inventory. Does not touch
        credentials or the certificate.
      </p>
      <button className="danger" onClick={() => setDeleting(true)}>
        Delete all observability data
      </button>
      {deleting && (
        <ReauthDialog
          title="Delete ALL observability data"
          actionLabel="Delete everything"
          body="This cannot be undone."
          onClose={() => setDeleting(false)}
          onConfirm={async (pw) => {
            await api.observeDeleteAll(pw);
            setDeleting(false);
            onNotice("All observability data deleted.");
          }}
        />
      )}
    </div>
  );
}

function Diagnostics({ onError }: { onError: (s: string) => void }) {
  const [checks, setChecks] = useState<DiagnosticCheck[]>([]);
  useEffect(() => {
    api
      .observeDiagnostics()
      .then(setChecks)
      .catch((e) => onError(errMsg(e)));
  }, [onError]);
  return (
    <div className="stack">
      <h2>Diagnostics</h2>
      {checks.map((c) => (
        <div
          key={c.name}
          className={`finding ${c.status === "fail" ? "bad" : c.status === "warn" ? "warn" : "ok"}`}
        >
          <strong>{c.name}</strong> — {c.detail}
        </div>
      ))}
    </div>
  );
}

function Privacy() {
  return (
    <div className="stack">
      <h2>What runtime observation does — and does not — store</h2>
      <ul>
        <li>Tethra observes only processes you explicitly launch with observation on.</li>
        <li>Monitoring is off by default.</li>
        <li>Metadata mode temporarily decrypts HTTPS for that one process, on this device.</li>
        <li>Request and response bodies are never retained.</li>
        <li>Authorization values, cookies, and secrets are never read into storage.</li>
        <li>
          Query strings are discarded; endpoint paths are sanitized (identifiers → :id/:uuid).
        </li>
        <li>Everything stays on your device — nothing is uploaded to Tethra.</li>
        <li>
          Some programs may bypass monitoring (HTTP/3/QUIC, certificate pinning, or runtimes
          that ignore trust configuration). Detected unsupported runtimes (Go, Java, .NET) are
          flagged with a partial-coverage badge; QUIC and pinning are documented limitations
          that are not yet auto-detected, so an empty result is not proof of no traffic.
        </li>
        <li>The certificate can be removed at any time from the Certificate tab.</li>
      </ul>
    </div>
  );
}
