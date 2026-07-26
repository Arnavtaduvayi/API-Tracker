// Local Gateway panel (ADR 0019, Phase 3).
//
// Security posture: everything rendered here is metadata — never bodies,
// header values, query strings, or credential values. The status/diagnosis
// commands are lock-free on the backend so this panel (and the lock-screen
// strip) keeps working while the vault is locked. The gateway is NEVER
// installed silently: enabling requires the explicit consent action below,
// which names the service files, the Login Items entry, the loopback-port
// exposure, and the standing-egress-relay property before anything happens.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, isApiError } from "../api";
import type {
  GatewayActivitySummary,
  GatewayDoctor,
  GatewayFinding,
  GatewayLinkPlan,
  GatewayRouteList,
  Project,
  ProviderManifest,
} from "../types";
import { ConfirmDialog } from "./ConfirmDialog";
import { ReauthDialog } from "./ReauthDialog";

type Tab = "overview" | "routes" | "projects" | "activity" | "diagnostics" | "privacy";

function errText(e: unknown): string {
  return isApiError(e) ? e.message : String(e);
}

function osWillRunLabel(d: GatewayDoctor): string {
  const w = d.service.os_will_run;
  switch (w.state) {
    case "yes":
      return "starts automatically at login";
    case "only_while_logged_in":
      return "starts at login, stops at logout (systemd linger is off — your call)";
    case "registered_but_never_validated":
      return "registered (Windows support is compile-validated only; never executed on Windows)";
    case "no":
      return "will not start automatically";
    case "unknown":
      return `unknown (${w.why})`;
  }
}

function identityLabel(d: GatewayDoctor): string | null {
  if (!d.listener) return null;
  switch (d.listener.verdict) {
    case "verified":
      return "identity verified (answers this vault's nonce challenge)";
    case "not_ours":
      return "PORT HELD BY SOMETHING ELSE — not this vault's gateway";
    case "no_listener":
      return "nothing listening";
    case "no_nonce":
      return "listener present but unverifiable (no nonce file)";
  }
}

export function GatewayView() {
  const [tab, setTab] = useState<Tab>("overview");
  const [report, setReport] = useState<GatewayDoctor | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setReport(await api.gatewayDoctor());
      setError(null);
    } catch (e) {
      setError(errText(e));
    }
  }, []);

  useEffect(() => {
    void reload();
    // Passive poll: gateway_doctor never touches the vault slot, so this
    // cannot defeat inactivity auto-lock.
    const timer = setInterval(() => void reload(), 10_000);
    return () => clearInterval(timer);
  }, [reload]);

  const live = report?.gateway != null;
  const installed = report?.service.installed ?? false;

  return (
    <div>
      <h1>Local Gateway</h1>
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        {(
          ["overview", "routes", "projects", "activity", "diagnostics", "privacy"] as Tab[]
        ).map((t) => (
          <button key={t} className={tab === t ? undefined : "link"} onClick={() => setTab(t)}>
            {t === "overview"
              ? "Status"
              : t === "routes"
                ? "Routes"
                : t === "projects"
                  ? "Projects"
                  : t === "activity"
                    ? "Activity"
                    : t === "diagnostics"
                      ? "Diagnostics"
                      : "Privacy"}
          </button>
        ))}
      </div>
      {report === null && !error && <p>Loading…</p>}
      {report && tab === "overview" && (
        <Overview
          report={report}
          onChanged={(msg) => {
            setNotice(msg);
            void reload();
          }}
          onError={setError}
          onLinkFirstProject={() => setTab("projects")}
        />
      )}
      {report && tab === "routes" && (
        <RoutesTab gatewayRunning={live} onError={setError} onChanged={() => void reload()} />
      )}
      {report && tab === "projects" && (
        <ProjectsTab
          report={report}
          installed={installed}
          gatewayRunning={live}
          onError={setError}
          onChanged={(msg) => {
            setNotice(msg);
            void reload();
          }}
        />
      )}
      {report && tab === "activity" && <ActivityTab onError={setError} />}
      {report && tab === "diagnostics" && <DiagnosticsTab report={report} />}
      {tab === "privacy" && <PrivacyTab />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Overview: consent onboarding when absent, status + actions when present.
// ---------------------------------------------------------------------------

function Overview(props: {
  report: GatewayDoctor;
  onChanged: (msg: string) => void;
  onError: (msg: string) => void;
  onLinkFirstProject: () => void;
}) {
  const { report } = props;
  const installed = report.service.installed;
  const live = report.gateway != null;

  if (!installed && !live) {
    return <ConsentCard {...props} />;
  }
  return <StatusPanel {...props} />;
}

function ConsentCard(props: {
  report: GatewayDoctor;
  onChanged: (msg: string) => void;
  onError: (msg: string) => void;
  onLinkFirstProject: () => void;
}) {
  const [learnMore, setLearnMore] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [cliMissing, setCliMissing] = useState<string | null>(null);

  if (dismissed) {
    return (
      <p className="muted">The Local Gateway stays off. Enable it any time from this panel.</p>
    );
  }

  const enable = async () => {
    setBusy(true);
    try {
      const cli = await api.gatewayLocateCli();
      if (!cli) {
        setCliMissing(
          "The gateway service runs the Tethra CLI binary, and no runnable " +
            "`tethra` CLI was found on this machine. Install the Tethra CLI " +
            "archive (see the install guide), then enable the gateway again. " +
            "Nothing was installed or changed.",
        );
        setBusy(false);
        return;
      }
      setConfirming(true);
    } catch (e) {
      props.onError(errText(e));
    }
    setBusy(false);
  };

  const reallyInstall = async () => {
    setBusy(true);
    try {
      const reportOut = await api.gatewayInstall(false);
      props.onChanged(
        `Gateway enabled (service at ${reportOut.definition}). ` +
          "Next: add a route and link your first project.",
      );
      props.onLinkFirstProject();
    } catch (e) {
      props.onError(errText(e));
    }
    setBusy(false);
    setConfirming(false);
  };

  return (
    <div className="finding warn" style={{ maxWidth: "44rem" }}>
      <h2>Enable the Local Gateway?</h2>
      <p>
        Tethra can run a local background gateway at 127.0.0.1. Projects you explicitly link can
        send API traffic through it. Tethra records metadata such as status and latency, but
        does not store API keys, authorization headers, query values, prompts, request bodies,
        or response bodies.
      </p>
      {cliMissing && <p className="error">{cliMissing}</p>}
      {learnMore && (
        <div>
          <p>Enabling creates exactly these files and registrations:</p>
          <ul>
            <li className="mono">{report_path(props.report)}</li>
            <li className="mono">
              …/bin/tethra-gateway-&lt;version&gt; (a copy of the CLI binary)
            </li>
            <li className="mono">…/logs/gateway.log</li>
            <li>
              a per-user login service (on macOS it appears under System Settings → General →
              Login Items as a background item)
            </li>
          </ul>
          <p>
            Honest cautions: the gateway listens on a loopback port, and any program on this
            machine can use that port — credentials pass through the gateway&apos;s memory
            (never stored). It is also a standing local egress relay to your registered
            providers, so a process blocked by a per-application firewall could still reach
            those providers through it. Routes can be disabled individually, and one action
            removes everything and restores your .env files.
          </p>
          <p>
            Credential attribution (matching observed traffic to a vault credential) stays OFF
            until you push the matching key, and the keep-matching-while-locked toggle defaults
            OFF.
          </p>
          <p>
            Coverage honesty: the gateway sees only traffic whose base URL points at it. Absence
            of recorded traffic is never evidence of absence of traffic.
          </p>
        </div>
      )}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button onClick={() => void enable()} disabled={busy}>
          Enable Local Gateway
        </button>
        <button className="link" onClick={() => setDismissed(true)}>
          Not now
        </button>
        <button className="link" onClick={() => setLearnMore((v) => !v)}>
          {learnMore ? "Hide details" : "Learn more"}
        </button>
      </div>
      {confirming && (
        <ConfirmDialog
          title="Install and start the gateway service?"
          body={
            "This installs the per-user login service and starts it now. " +
            "It records metadata only (never bodies or credentials), any local " +
            "program can use the loopback port, and it acts as a standing local " +
            "egress relay to your registered providers. One action removes it " +
            "and restores your .env files."
          }
          confirmLabel={busy ? "Installing…" : "Install and start"}
          onConfirm={() => void reallyInstall()}
          onCancel={() => setConfirming(false)}
        />
      )}
    </div>
  );
}

function report_path(report: GatewayDoctor): string {
  return (
    report.service.definition_path || "~/Library/LaunchAgents/dev.api-tracker.gateway.plist"
  );
}

function StatusPanel(props: {
  report: GatewayDoctor;
  onChanged: (msg: string) => void;
  onError: (msg: string) => void;
  onLinkFirstProject: () => void;
}) {
  const { report, onChanged, onError } = props;
  const g = report.gateway;
  const [busy, setBusy] = useState(false);
  const [dialog, setDialog] = useState<
    null | "repair" | "disable" | "uninstall" | "push-key" | "change-port"
  >(null);
  const [keepEnv, setKeepEnv] = useState(false);

  const act = async (label: string, f: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await f();
      onChanged(label);
    } catch (e) {
      onError(errText(e));
    }
    setBusy(false);
    setDialog(null);
  };

  const problems = report.findings.filter(
    (f) => f.severity === "warn" || f.severity === "error",
  );
  const linkedCount = report.links.length;

  return (
    <div>
      {problems.length > 0 && (
        <div>
          {problems.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
      <dl className="detail-grid">
        <dt>Service</dt>
        <dd>
          {report.service.installed
            ? `installed (${report.service.platform})`
            : "not installed"}
          {report.service.installed && ` — ${osWillRunLabel(report)}`}
        </dd>
        <dt>Process</dt>
        <dd>
          {g
            ? `running v${g.version} (pid ${g.pid}), up ${g.uptime_secs}s`
            : report.service.running
              ? "service reports running, but the gateway is not answering"
              : "not running"}
        </dd>
        <dt>Listening</dt>
        <dd>
          {g
            ? `http://127.0.0.1:${g.port}`
            : report.configured_port
              ? `port ${report.configured_port} persisted; nothing listening`
              : "no port chosen yet"}
          {identityLabel(report) && ` — ${identityLabel(report)}`}
        </dd>
        <dt>Forwarding</dt>
        <dd>
          {g
            ? `${g.routes} route(s) forwardable, ${g.routes_unavailable} unavailable, ${g.routes_disabled} disabled`
            : "—"}
        </dd>
        <dt>Recording</dt>
        <dd>
          {g
            ? g.recording_paused
              ? "PAUSED (forwarding continues; this window is a coverage gap)"
              : g.recording_degraded
                ? `DEGRADED (${g.persist_failures} persist failure(s); forwarding unaffected)`
                : "on (metadata and token counts only)"
            : "—"}
        </dd>
        <dt>Attribution</dt>
        <dd>
          {g
            ? g.matching_key_present
              ? "on (matching key resident in the gateway process)"
              : "off — exchanges record `unavailable_vault_locked` until a key is pushed"
            : "—"}
        </dd>
        <dt>Queue</dt>
        <dd>{g ? `${g.queue_depth} queued, ${g.dropped_events} dropped ever` : "—"}</dd>
        <dt>Events</dt>
        <dd>
          {g
            ? `${g.written_events} written${
                g.last_observation_at
                  ? `, last at ${g.last_observation_at}`
                  : " — none yet (absence of recorded traffic is not evidence of absence of traffic)"
              }`
            : "—"}
        </dd>
        <dt>Last error</dt>
        <dd>{g?.last_error ?? "—"}</dd>
        <dt>Linked projects</dt>
        <dd>{linkedCount}</dd>
      </dl>

      <h2>Actions</h2>
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button
          disabled={busy || !report.service.installed}
          onClick={() => void act("start requested", api.gatewayStart)}
        >
          Start
        </button>
        <button
          disabled={busy}
          onClick={() => void act("stop requested (graceful drain)", api.gatewayStop)}
        >
          Stop
        </button>
        <button
          disabled={busy || !report.service.installed}
          onClick={() => void act("restart requested", api.gatewayRestart)}
        >
          Restart
        </button>
        <button disabled={busy} onClick={() => setDialog("repair")}>
          Repair
        </button>
        {g && (
          <button
            disabled={busy}
            onClick={() =>
              void act(g.recording_paused ? "recording resumed" : "recording paused", () =>
                api.gatewayRecording(!g.recording_paused),
              )
            }
          >
            {g.recording_paused ? "Resume recording" : "Pause recording"}
          </button>
        )}
        {g && !g.matching_key_present && (
          <button disabled={busy} onClick={() => setDialog("push-key")}>
            Enable attribution…
          </button>
        )}
        {g && g.matching_key_present && (
          <button
            disabled={busy}
            onClick={() => void act("matching key revoked", api.gatewayRevokeKey)}
          >
            Revoke matching key
          </button>
        )}
        <span className="spacer" />
        <button className="danger" disabled={busy} onClick={() => setDialog("disable")}>
          Disable…
        </button>
        <button className="danger" disabled={busy} onClick={() => setDialog("uninstall")}>
          Uninstall…
        </button>
      </div>

      {dialog === "repair" && (
        <ConfirmDialog
          title="Repair the gateway service?"
          body="Repair re-copies the CLI binary, rewrites the service definition for this data directory, re-registers it, and restarts the service."
          confirmLabel="Repair"
          onConfirm={() => void act("repaired", api.gatewayRepair)}
          onCancel={() => setDialog(null)}
        />
      )}
      {(dialog === "disable" || dialog === "uninstall") && (
        <ConfirmDialog
          title={dialog === "disable" ? "Disable the gateway?" : "Uninstall the gateway?"}
          danger
          body={
            (linkedCount > 0
              ? `${linkedCount} linked project(s) currently point at the gateway. ` +
                (keepEnv
                  ? "You chose to KEEP their .env files, so their SDK calls will get " +
                    "connection-refused until you unlink or re-enable. "
                  : "Their .env files will be restored to their pre-link values first " +
                    "(values you edited after linking are left alone and reported). ")
              : "") +
            (dialog === "disable"
              ? "The service stops and is unregistered; binaries and recorded history stay."
              : "The service, its binaries, logs, and runtime files are removed. Recorded history stays in your vault.")
          }
          confirmLabel={dialog === "disable" ? "Disable" : "Uninstall"}
          onConfirm={() =>
            void act(dialog === "disable" ? "gateway disabled" : "gateway uninstalled", () =>
              dialog === "disable"
                ? api.gatewayDisable(keepEnv)
                : api.gatewayUninstall(keepEnv),
            )
          }
          onCancel={() => setDialog(null)}
        />
      )}
      {(dialog === "disable" || dialog === "uninstall") && linkedCount > 0 && (
        <label className="field" style={{ maxWidth: "28rem" }}>
          <span>
            <input
              type="checkbox"
              checked={keepEnv}
              onChange={(e) => setKeepEnv(e.target.checked)}
            />{" "}
            Keep .env files pointing at the gateway (not recommended)
          </span>
        </label>
      )}
      {dialog === "push-key" && (
        <ReauthDialog
          title="Enable credential attribution"
          actionLabel="Push matching key"
          body={
            "This hands the gateway a derived matching-only key so it can label " +
            "observed traffic with which vault credential was used. The key cannot " +
            "decrypt anything, but while it is resident, a process that can read the " +
            "gateway's memory (or its database) gains an oracle for testing whether a " +
            "value matches one of your credentials. The key is dropped on stop, " +
            "revoke, or lock (keep-while-locked defaults OFF)."
          }
          onConfirm={async (password) => {
            await api.gatewayPushKey(password);
            onChanged("credential attribution enabled");
            setDialog(null);
          }}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}

function FindingCard({ finding }: { finding: GatewayFinding }) {
  const cls =
    finding.severity === "error"
      ? "finding bad"
      : finding.severity === "warn"
        ? "finding warn"
        : "finding ok";
  return (
    <div className={cls}>
      <strong>{finding.title}</strong>
      <p>{finding.detail}</p>
      {finding.repair && (
        <p className="muted">
          Fix: <span className="mono">{finding.repair}</span>
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

function RoutesTab(props: {
  gatewayRunning: boolean;
  onError: (msg: string) => void;
  onChanged: () => void;
}) {
  const [list, setList] = useState<GatewayRouteList | null>(null);
  const [providers, setProviders] = useState<ProviderManifest[]>([]);
  const [provider, setProvider] = useState("");
  const [prefix, setPrefix] = useState("");
  const [origin, setOrigin] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setList(await api.gatewayRouteList());
    } catch (e) {
      props.onError(errText(e));
    }
  }, [props]);

  useEffect(() => {
    void reload();
    api.providersList().then(setProviders, () => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!provider) {
      setFormError("Pick a provider.");
      return;
    }
    setBusy(true);
    try {
      await api.gatewayRouteAdd(provider, prefix.trim() || null, origin.trim() || null);
      setPrefix("");
      setOrigin("");
      await reload();
      props.onChanged();
    } catch (err) {
      // The backend's refusals are the honest explanations (unsupported
      // provider → custom-origin hint; invalid origin → policy detail).
      setFormError(errText(err));
    }
    setBusy(false);
  };

  const setEnabled = async (routePrefix: string, enabled: boolean) => {
    try {
      await api.gatewayRouteSetEnabled(routePrefix, enabled);
      await reload();
      props.onChanged();
    } catch (e) {
      props.onError(errText(e));
    }
  };

  const manifest = providers.find((p) => p.id === provider);
  const needsCustomOrigin =
    manifest != null && (!manifest.gateway || manifest.gateway.origins.length === 0);

  return (
    <div>
      {!props.gatewayRunning && (
        <div className="warnbox">
          The gateway is not running: routes can be edited, but nothing forwards until it
          starts.
        </div>
      )}
      {list && list.routes.length === 0 && (
        <p className="muted">
          No routes yet. A route maps a path prefix (http://127.0.0.1:&lt;port&gt;/openai/…) to
          one provider origin.
        </p>
      )}
      {list && list.routes.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Prefix</th>
              <th>Provider</th>
              <th>Origin</th>
              <th>Source</th>
              <th>State</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.routes.map((r) => (
              <tr key={r.prefix}>
                <td className="mono">{r.prefix}</td>
                <td>{r.provider_id}</td>
                <td className="mono">
                  {r.origin ?? (r.enabled ? (r.unavailable_reason ?? "—") : "—")}
                </td>
                <td>{r.custom ? "custom" : "manifest"}</td>
                <td>
                  {r.enabled ? (
                    r.available ? (
                      <span className="badge ok">enabled</span>
                    ) : (
                      <span className="badge warn">
                        {r.unavailable_reason ?? "unavailable"}
                      </span>
                    )
                  ) : (
                    <span className="badge warn">disabled</span>
                  )}
                </td>
                <td>
                  <div style={{ display: "flex", gap: "0.4rem" }}>
                    <button
                      className="link"
                      onClick={() => void setEnabled(r.prefix, !r.enabled)}
                    >
                      {r.enabled ? "Disable" : "Enable"}
                    </button>
                    <button className="link danger" onClick={() => setRemoving(r.prefix)}>
                      Remove
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {list && list.skipped.length > 0 && (
        <div className="finding bad">
          <strong>Route rows that cannot be loaded</strong>
          {list.skipped.map(([p, why]) => (
            <p key={p} className="mono">
              {p}: {why}
            </p>
          ))}
          <p className="muted">Remove and re-add the affected route.</p>
        </div>
      )}

      <h2>Add a route</h2>
      <form className="stack" style={{ maxWidth: "28rem" }} onSubmit={(e) => void add(e)}>
        <label className="field">
          Provider
          <select value={provider} onChange={(e) => setProvider(e.target.value)}>
            <option value="">Choose…</option>
            {providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Route prefix (optional; defaults to the provider id)
          <input
            value={prefix}
            onChange={(e) => setPrefix(e.target.value)}
            placeholder={provider || "openai"}
            pattern="[a-z][a-z0-9-]*"
            title="lowercase letters, digits, and hyphens; starts with a letter"
          />
        </label>
        <label className="field">
          Custom origin {needsCustomOrigin ? "(required for this provider)" : "(optional)"}
          <input
            value={origin}
            onChange={(e) => setOrigin(e.target.value)}
            placeholder="https://xyzcompany.supabase.co"
          />
        </label>
        {needsCustomOrigin && (
          <p className="muted">
            {manifest?.name} has no fixed API origin — every project gets its own host — so the
            exact origin must be given here and is integrity-protected against database
            tampering.
          </p>
        )}
        {formError && <p className="error">{formError}</p>}
        <button disabled={busy}>Add route</button>
      </form>

      {removing && (
        <ConfirmDialog
          title={`Remove route '${removing}'?`}
          danger
          body="Requests to this prefix will answer 404. Linked projects using it will get errors until re-routed or unlinked."
          confirmLabel="Remove"
          onConfirm={() => {
            void (async () => {
              try {
                await api.gatewayRouteRemove(removing);
                setRemoving(null);
                await reload();
                props.onChanged();
              } catch (e) {
                props.onError(errText(e));
                setRemoving(null);
              }
            })();
          }}
          onCancel={() => setRemoving(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Projects (link / unlink)
// ---------------------------------------------------------------------------

function ProjectsTab(props: {
  report: GatewayDoctor;
  installed: boolean;
  gatewayRunning: boolean;
  onError: (msg: string) => void;
  onChanged: (msg: string) => void;
}) {
  const { report } = props;
  const [projects, setProjects] = useState<Project[]>([]);
  const [routes, setRoutes] = useState<GatewayRouteList | null>(null);
  const [project, setProject] = useState("");
  const [route, setRoute] = useState("");
  const [envFile, setEnvFile] = useState("");
  const [dir, setDir] = useState("");
  const [varName, setVarName] = useState("");
  const [plan, setPlan] = useState<GatewayLinkPlan | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [unlinking, setUnlinking] = useState<{ project: string; route: string } | null>(null);
  const planRequest = useRef<{
    project: string;
    route: string;
    envFiles: string[];
    dir: string | null;
    var: string | null;
  } | null>(null);

  useEffect(() => {
    api.projectList(false).then(setProjects, () => {});
    api.gatewayRouteList().then(setRoutes, () => {});
  }, []);

  const preview = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setPlan(null);
    if (!project || !route) {
      setFormError("Pick a project and a route.");
      return;
    }
    if (!envFile.trim() && !dir.trim()) {
      setFormError(
        "Name the .env file to rewrite (or a project directory whose .env should be used).",
      );
      return;
    }
    setBusy(true);
    const request = {
      project,
      route,
      envFiles: envFile.trim() ? [envFile.trim()] : [],
      dir: dir.trim() ? dir.trim() : null,
      var: varName.trim() ? varName.trim() : null,
    };
    try {
      const p = await api.gatewayLinkPlan(request);
      planRequest.current = request;
      setPlan(p);
    } catch (err) {
      setFormError(errText(err));
    }
    setBusy(false);
  };

  const apply = async () => {
    if (!plan || !planRequest.current) return;
    setBusy(true);
    try {
      await api.gatewayLinkApply({
        ...planRequest.current,
        slug: plan.link_slug,
        digest: plan.digest,
      });
      setPlan(null);
      props.onChanged(
        `Linked ${plan.project_name} → ${plan.route_prefix}. ` +
          (props.gatewayRunning
            ? "Traffic will appear once the project actually sends requests."
            : "The gateway is NOT running — SDK calls will get connection-refused until it starts."),
      );
    } catch (err) {
      setFormError(errText(err));
    }
    setBusy(false);
  };

  return (
    <div>
      {!props.gatewayRunning && (
        <div className="warnbox">
          The gateway is not running. Linking rewrites .env files to point at 127.0.0.1 — until
          the gateway starts, linked SDKs get connection refused.
        </div>
      )}

      <h2>Linked projects</h2>
      {report.links.length === 0 ? (
        <p className="muted">
          No projects are linked. A link rewrites the project&apos;s .env (with a preview) so
          its SDK talks to the gateway; unlinking restores the exact prior state.
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Project</th>
              <th>Route</th>
              <th>.env</th>
              <th>Health</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {report.links.map((l) => (
              <tr key={`${l.project_id}:${l.route_prefix}`}>
                <td>{l.project_id}</td>
                <td className="mono">{l.route_prefix}</td>
                <td className="mono">{l.env_path ?? "—"}</td>
                <td>
                  {l.issues.length === 0 ? (
                    <span className="badge ok">ok</span>
                  ) : (
                    <span className="badge warn">{l.issues.join("; ")}</span>
                  )}
                </td>
                <td>
                  <button
                    className="link danger"
                    onClick={() =>
                      setUnlinking({ project: l.project_id, route: l.route_prefix })
                    }
                  >
                    Unlink
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Link a project</h2>
      <form className="stack" style={{ maxWidth: "34rem" }} onSubmit={(e) => void preview(e)}>
        <label className="field">
          Project
          <select value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="">Choose…</option>
            {projects.map((p) => (
              <option key={p.id} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Route
          <select value={route} onChange={(e) => setRoute(e.target.value)}>
            <option value="">Choose…</option>
            {routes?.routes
              .filter((r) => r.enabled)
              .map((r) => (
                <option key={r.prefix} value={r.prefix}>
                  {r.prefix} ({r.provider_id})
                </option>
              ))}
          </select>
        </label>
        <label className="field">
          Environment file (full path)
          <input
            value={envFile}
            onChange={(e) => setEnvFile(e.target.value)}
            placeholder="/path/to/project/.env"
          />
        </label>
        <label className="field">
          …or project directory (its .env is used / created)
          <input
            value={dir}
            onChange={(e) => setDir(e.target.value)}
            placeholder="/path/to/project"
          />
        </label>
        <label className="field">
          Variable override (only for providers without a declared base-URL variable)
          <input
            value={varName}
            onChange={(e) => setVarName(e.target.value)}
            placeholder="MY_PROVIDER_BASE_URL"
          />
        </label>
        {formError && <p className="error">{formError}</p>}
        <button disabled={busy}>Preview changes</button>
      </form>

      {plan && (
        <div>
          <h2>Preview</h2>
          <p>
            Base URL (written verbatim): <span className="mono">{plan.base_url}</span>
          </p>
          {plan.warnings.length > 0 && (
            <div className="warnbox">
              {plan.warnings.map((w, i) => (
                <p key={i}>
                  {w.kind}
                  {w.path ? `: ${w.path}` : ""}
                  {w.key ? ` (${w.key})` : ""}
                </p>
              ))}
            </div>
          )}
          {plan.files.map((f) => (
            <div key={f.path}>
              <p className="mono">
                {f.path}
                {!f.exists && " (will be created)"}
                {!f.changed && " — no change"}
              </p>
              {f.changed && (
                <pre style={{ overflowX: "auto", background: "#f6f6f6", padding: "0.5rem" }}>
                  {f.diff}
                </pre>
              )}
            </div>
          ))}
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button disabled={busy} onClick={() => void apply()}>
              Apply exactly this
            </button>
            <button className="link" onClick={() => setPlan(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {unlinking && (
        <ConfirmDialog
          title={`Unlink ${unlinking.project} from ${unlinking.route}?`}
          body="The recorded pre-link .env state is restored: prior values come back, lines Tethra created are removed, and anything you edited after linking is left alone and reported."
          confirmLabel="Unlink and restore"
          onConfirm={() => {
            void (async () => {
              try {
                const report = await api.gatewayUnlink(unlinking.project, unlinking.route);
                props.onChanged(
                  report.complete
                    ? `Unlinked ${unlinking.project} (restored).`
                    : `Some files could not be restored; the link was kept for retry.`,
                );
              } catch (e) {
                props.onError(errText(e));
              }
              setUnlinking(null);
            })();
          }}
          onCancel={() => setUnlinking(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Activity: gateway-only metrics, honestly labeled.
// ---------------------------------------------------------------------------

function ActivityTab({ onError }: { onError: (msg: string) => void }) {
  const [summary, setSummary] = useState<GatewayActivitySummary | null>(null);
  const [days, setDays] = useState(7);

  useEffect(() => {
    const since = new Date(Date.now() - days * 86_400_000).toISOString();
    api.gatewayActivity(since).then(setSummary, (e) => onError(errText(e)));
  }, [days, onError]);

  if (!summary) return <p>Loading…</p>;
  const rate = (n: number) =>
    summary.total_requests > 0 ? `${((n / summary.total_requests) * 100).toFixed(1)}%` : "—";
  return (
    <div>
      <p className="muted">
        Locally observed by the gateway only — traffic whose base URL points at it. Never summed
        with provider-reported usage, and an empty view is not evidence of zero provider usage.
        (Proxy double counting is prevented by the NO_PROXY entry every link writes: each
        exchange is recorded under exactly one source.)
      </p>
      <label className="field" style={{ maxWidth: "12rem" }}>
        Window (days)
        <input
          type="number"
          min={1}
          max={90}
          value={days}
          onChange={(e) => setDays(Number(e.target.value) || 7)}
        />
      </label>
      <dl className="detail-grid">
        <dt>Requests</dt>
        <dd>{summary.total_requests}</dd>
        <dt>Success rate</dt>
        <dd>
          {rate(summary.success_count)} ({summary.success_count} of {summary.total_requests})
        </dd>
        <dt>Error rate</dt>
        <dd>
          {rate(summary.error_count)} HTTP errors, {summary.transport_error_count} transport
          failures
        </dd>
        <dt>Latency</dt>
        <dd>
          p50 {summary.p50_latency_ms ?? "—"} ms / p95 {summary.p95_latency_ms ?? "—"} ms / p99{" "}
          {summary.p99_latency_ms ?? "—"} ms (through-gateway, includes provider time)
        </dd>
        <dt>Bytes</dt>
        <dd>
          {summary.request_bytes} sent / {summary.response_bytes} received
        </dd>
        <dt>Tokens</dt>
        <dd>
          {summary.usage_event_count > 0
            ? `${summary.input_tokens} in / ${summary.output_tokens} out (from ${summary.usage_event_count} response(s) that carried usage — absent usage is never counted as zero)`
            : "none extracted (providers report usage only on some responses)"}
        </dd>
        <dt>Estimated cost</dt>
        <dd>
          {summary.usage_event_count > 0
            ? `$${(summary.estimated_cost_micros / 1_000_000).toFixed(4)} (LOWER-bound estimate from local pricing; cache-read tokens excluded; never provider-billed truth)`
            : "—"}
        </dd>
        <dt>Freshness</dt>
        <dd>
          {summary.last_event_at
            ? `last event ${summary.last_event_at}`
            : "no events in this window"}
        </dd>
      </dl>
      {summary.top_endpoints.length > 0 && (
        <div>
          <h2>Top endpoints (sanitized templates)</h2>
          <table>
            <tbody>
              {summary.top_endpoints.map(([path, n]) => (
                <tr key={path}>
                  <td className="mono">{path}</td>
                  <td>{n}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {summary.top_models.length > 0 && (
        <div>
          <h2>Models (as parsed from responses)</h2>
          <table>
            <tbody>
              {summary.top_models.map(([model, n]) => (
                <tr key={model}>
                  <td className="mono">{model}</td>
                  <td>{n}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {summary.attribution.length > 0 && (
        <div>
          <h2>Attribution states</h2>
          <table>
            <tbody>
              {summary.attribution.map(([state, n]) => (
                <tr key={state}>
                  <td className="mono">{state}</td>
                  <td>{n}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Diagnostics / privacy
// ---------------------------------------------------------------------------

function DiagnosticsTab({ report }: { report: GatewayDoctor }) {
  return (
    <div>
      <p>
        Overall:{" "}
        <span
          className={`badge ${report.overall === "error" ? "bad" : report.overall === "warn" ? "warn" : "ok"}`}
        >
          {report.overall}
        </span>
        {"  "}CLI v{report.cli_version}
        {report.gateway && ` / service v${report.gateway.version}`}
      </p>
      {report.findings.map((f) => (
        <FindingCard key={f.id} finding={f} />
      ))}
      <h2>Owned artifacts</h2>
      <p className="muted">Everything uninstall removes (recorded history stays):</p>
      <ul>
        {report.service.owned_artifacts.map((a) => (
          <li key={a} className="mono">
            {a}
          </li>
        ))}
      </ul>
    </div>
  );
}

function PrivacyTab() {
  return (
    <div style={{ maxWidth: "44rem" }}>
      <h2>What the gateway stores</h2>
      <ul>
        <li>request metadata: method class, sanitized path template, status, timing, sizes</li>
        <li>
          bounded usage: model name and token counts, when the provider response carries them
        </li>
        <li>attribution STATE (and a credential id only on a match) — never header values</li>
        <li>operational counters (drops, rejections, queue behavior)</li>
      </ul>
      <h2>What it never stores, by construction</h2>
      <ul>
        <li>API keys, authorization headers, cookies</li>
        <li>query values, request bodies, response bodies, prompts, generated text</li>
        <li>raw URLs or client Host values</li>
      </ul>
      <p>
        The record type has no field capable of holding a body or header value, and privacy
        canary tests drive real traffic through the gateway and scan every artifact on disk for
        planted markers.
      </p>
      <h2>Honest limits</h2>
      <ul>
        <li>
          Local observation only: the gateway sees traffic whose base URL points at it. Absence
          of recorded traffic is never evidence of absence of traffic.
        </li>
        <li>
          Locally observed usage is never summed with provider-reported usage, and it does not
          feed budget alerts.
        </li>
        <li>
          The gateway is a standing local egress relay to your registered providers; any local
          program can use its loopback port.
        </li>
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Lock-screen strip (rendered by App while the vault is locked)
// ---------------------------------------------------------------------------

export function GatewayLockStrip() {
  const [report, setReport] = useState<GatewayDoctor | null>(null);

  useEffect(() => {
    const load = () => api.gatewayDoctor().then(setReport, () => setReport(null));
    load();
    const timer = setInterval(load, 15_000);
    return () => clearInterval(timer);
  }, []);

  if (!report || (!report.service.installed && report.gateway == null)) {
    return null;
  }
  const g = report.gateway;
  return (
    <p className="muted" style={{ marginTop: "1rem" }}>
      Local Gateway:{" "}
      {g
        ? `running on 127.0.0.1:${g.port} — forwarding continues while locked; ` +
          (g.recording_paused
            ? "recording paused"
            : g.recording_degraded
              ? "recording degraded"
              : "recording on") +
          "; attribution " +
          (g.matching_key_present ? "on" : "off (vault locked)")
        : "installed but not running"}
    </p>
  );
}
