// Top-level shell: vault state machine (missing → create, locked → unlock,
// unlocked → main navigation) plus a simple view router. The backend
// enforces auto-lock; this component reacts to `vault_locked` errors and
// polls the status so the UI locks visibly too.
//
// While the app is OPEN and UNLOCKED, a single timer runs the full monitor
// (local checks + due documentation checks + webhook delivery) every
// `monitor_interval_minutes` and raises a native notification for new
// alerts of medium severity or above. This is not an OS background service:
// nothing runs when the app is closed or the vault is locked. The timer is
// disarmed on lock and re-armed when the setting changes.

import { useCallback, useEffect, useState } from "react";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { api, isApiError } from "./api";
import { setVaultLockedHandler } from "./api";
import { severityRank, topSeverity } from "./utils";
import type { VaultStatus } from "./types";
import { VaultSetup } from "./components/VaultSetup";
import { VaultUnlock } from "./components/VaultUnlock";
import { ProjectList } from "./components/ProjectList";
import { ProjectForm } from "./components/ProjectForm";
import { ProjectDetail } from "./components/ProjectDetail";
import { CredentialForm } from "./components/CredentialForm";
import { CredentialDetail } from "./components/CredentialDetail";
import { PricingView } from "./components/PricingView";
import { TemplatesView } from "./components/TemplatesView";
import { SettingsView } from "./components/SettingsView";
import { BackupView } from "./components/BackupView";
import { ProviderCatalog } from "./components/ProviderCatalog";
import { ProviderDetail } from "./components/ProviderDetail";
import { ScanView } from "./components/ScanView";
import { AlertsView } from "./components/AlertsView";
import { UsageView } from "./components/UsageView";
import { EnvView } from "./components/EnvView";
import { DestinationsView } from "./components/DestinationsView";
import { SyncView } from "./components/SyncView";
import { RotationView } from "./components/RotationView";
import { AccessView } from "./components/AccessView";
import { NotifyView } from "./components/NotifyView";
import { ApiActivityView } from "./components/ApiActivityView";
import { GatewayView, GatewayLockStrip } from "./components/GatewayView";
import { DashboardView } from "./components/DashboardView";
import { TrackFlow } from "./components/TrackFlow";
import { AnalyticsConsentBanner } from "./components/AnalyticsConsent";
import { Gate } from "./components/visuals/Gate";
import { BrandLockup } from "./components/visuals/BrandLockup";
import { ParticleField, type ParticleMode } from "./components/visuals/ParticleField";
import { WireGlobe } from "./components/visuals/WireGlobe";
import { NavIcon } from "./components/visuals/NavIcons";
import {
  getAnalyticsConsent,
  initializeAnalytics,
  subscribeToAnalyticsConsent,
  trackAnalytics,
  type AnalyticsConsent,
  type AnalyticsScreen,
} from "./analytics";

export type View =
  | { name: "dashboard" }
  | { name: "track" }
  | { name: "projects" }
  | { name: "project"; ident: string }
  | { name: "project-new" }
  | { name: "project-edit"; ident: string }
  | { name: "credential"; id: string }
  | { name: "credential-new"; project: string }
  | { name: "credential-edit"; id: string }
  | { name: "providers" }
  | { name: "provider"; id: string }
  | { name: "scan" }
  | { name: "env" }
  | { name: "destinations" }
  | { name: "sync" }
  | { name: "rotation" }
  | { name: "access" }
  | { name: "alerts" }
  | { name: "notify" }
  | { name: "usage" }
  | { name: "api-activity" }
  | { name: "gateway" }
  | { name: "pricing" }
  | { name: "templates" }
  | { name: "settings" }
  | { name: "backup" };

type VaultState = "loading" | "missing" | "locked" | "unlocked";

/**
 * Sidebar navigation. These are the same 16 destinations the old top bar had,
 * with identical labels — only grouped for scanability.
 */
const NAV_GROUPS: { label: string; items: [View["name"], string][] }[] = [
  {
    label: "Activity",
    items: [
      ["dashboard", "Activity"],
      ["projects", "Projects"],
    ],
  },
  {
    label: "Vault",
    items: [["providers", "Providers"]],
  },
  {
    label: "Exposure",
    items: [
      ["scan", "Scan"],
      ["env", "Env files"],
    ],
  },
  {
    label: "Delivery",
    items: [
      ["destinations", "Destinations"],
      ["sync", "Sync plans"],
      ["rotation", "Rotation"],
      ["access", "Temporary access"],
    ],
  },
  {
    label: "Monitoring",
    items: [
      ["alerts", "Alerts"],
      ["notify", "Notifications"],
      ["usage", "Usage"],
      ["api-activity", "API activity"],
      ["pricing", "Pricing"],
    ],
  },
  {
    label: "Advanced",
    items: [
      ["track", "Tracking setup"],
      ["gateway", "Gateway internals"],
    ],
  },
  {
    label: "System",
    items: [
      ["templates", "Templates"],
      ["backup", "Backup"],
      ["settings", "Settings"],
    ],
  },
];

/** Nested views highlight (and breadcrumb to) their owning nav destination. */
const SECTION_OF: Record<View["name"], View["name"]> = {
  dashboard: "dashboard",
  track: "track",
  projects: "projects",
  project: "projects",
  "project-new": "projects",
  "project-edit": "projects",
  credential: "projects",
  "credential-new": "projects",
  "credential-edit": "projects",
  providers: "providers",
  provider: "providers",
  scan: "scan",
  env: "env",
  destinations: "destinations",
  sync: "sync",
  rotation: "rotation",
  access: "access",
  alerts: "alerts",
  notify: "notify",
  usage: "usage",
  "api-activity": "api-activity",
  gateway: "gateway",
  pricing: "pricing",
  templates: "templates",
  backup: "backup",
  settings: "settings",
};

/** Ambient topology follows the current workspace without reading its data. */
function particleModeFor(view: View["name"]): ParticleMode {
  if (["dashboard", "usage", "api-activity", "pricing"].includes(view)) return "routes";
  if (
    [
      "projects",
      "project",
      "project-new",
      "project-edit",
      "credential",
      "credential-new",
      "credential-edit",
      "providers",
      "provider",
      "templates",
    ].includes(view)
  ) {
    return "graph";
  }
  if (["scan", "env", "alerts", "notify", "backup", "settings"].includes(view)) {
    return "vault";
  }
  return "flow";
}

/** Finite screen names keep project identifiers and other user data out of Analytics. */
function analyticsScreenFor(view: View["name"]): AnalyticsScreen {
  const screens: Record<View["name"], AnalyticsScreen> = {
    dashboard: "dashboard",
    track: "tracking_setup",
    projects: "projects",
    project: "project_detail",
    "project-new": "project_form",
    "project-edit": "project_form",
    credential: "credential_detail",
    "credential-new": "credential_form",
    "credential-edit": "credential_form",
    providers: "providers",
    provider: "provider_detail",
    scan: "repository_scan",
    env: "env_files",
    destinations: "destinations",
    sync: "sync_plans",
    rotation: "rotation",
    access: "temporary_access",
    alerts: "alerts",
    notify: "notifications",
    usage: "usage",
    "api-activity": "api_activity",
    gateway: "gateway",
    pricing: "pricing",
    templates: "templates",
    settings: "settings",
    backup: "backup",
  };
  return screens[view];
}

/** Native notification for freshly created alerts of medium+ severity. */
async function notifyNewAlerts(severities: string[]) {
  const notable = severities.filter((s) => severityRank(s) >= severityRank("medium"));
  const top = topSeverity(notable);
  if (notable.length === 0 || !top) return;
  try {
    let granted = await isPermissionGranted();
    if (!granted) {
      granted = (await requestPermission()) === "granted";
    }
    if (granted) {
      // Alert counts and severities only — titles could name credentials.
      sendNotification({
        title: "Tethra",
        body: `${notable.length} new alert(s) — top severity: ${top}. Open Alerts for details.`,
      });
    }
  } catch {
    // Notifications are best-effort; never surface an error for them.
  }
}

export default function App() {
  const [vaultState, setVaultState] = useState<VaultState>("loading");
  const [dataDir, setDataDir] = useState("");
  const [view, setView] = useState<View>({ name: "dashboard" });
  const [fatal, setFatal] = useState<string | null>(null);
  const [monitorMinutes, setMonitorMinutes] = useState(0);
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [analyticsConsent, setAnalyticsConsentState] = useState<AnalyticsConsent>(() =>
    getAnalyticsConsent(),
  );

  useEffect(() => {
    initializeAnalytics();
    return subscribeToAnalyticsConsent(setAnalyticsConsentState);
  }, []);

  useEffect(() => {
    if (analyticsConsent !== "granted") return;
    trackAnalytics({ name: "app_session_start" });
    if (vaultState === "missing") {
      trackAnalytics({ name: "screen_view", screen_name: "vault_setup" });
    } else if (vaultState === "locked") {
      trackAnalytics({ name: "screen_view", screen_name: "vault_unlock" });
    } else if (vaultState === "unlocked") {
      trackAnalytics({ name: "screen_view", screen_name: analyticsScreenFor(view.name) });
    }
  }, [analyticsConsent, vaultState, view.name]);

  // The sidebar collapses itself when the window gets narrow and expands again
  // when there is room. Crossing the breakpoint re-syncs, but between
  // crossings the user's manual toggle wins.
  useEffect(() => {
    // Guarded: a webview without matchMedia must not take down the whole app
    // over a piece of navigation chrome. It just stays expanded.
    if (typeof window.matchMedia !== "function") return;
    // The shipped window is 1050px wide; keep the branded navigation visible
    // there and reserve the icon-only rail for genuinely compact windows.
    const mq = window.matchMedia("(max-width: 900px)");
    setNavCollapsed(mq.matches);
    const onChange = (e: MediaQueryListEvent) => setNavCollapsed(e.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const refreshStatus = useCallback(async () => {
    try {
      const status: VaultStatus = await api.vaultStatus();
      setDataDir(status.data_dir);
      setVaultState(!status.exists ? "missing" : status.unlocked ? "unlocked" : "locked");
    } catch (e) {
      setFatal(isApiError(e) ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    setVaultLockedHandler(() => {
      trackAnalytics({ name: "vault_locked" });
      setVaultState("locked");
      setView({ name: "projects" });
    });
    void refreshStatus();
    const timer = setInterval(() => void refreshStatus(), 30_000);
    return () => clearInterval(timer);
  }, [refreshStatus]);

  // --- Background monitoring (one timer, armed only while unlocked) ---

  const reloadMonitorInterval = useCallback(async () => {
    try {
      const settings = await api.settingsGet();
      setMonitorMinutes(settings.monitor_interval_minutes);
    } catch {
      setMonitorMinutes(0); // locked or unreadable: keep the timer disarmed
    }
  }, []);

  useEffect(() => {
    if (vaultState === "unlocked") {
      void reloadMonitorInterval();
    } else {
      setMonitorMinutes(0);
    }
  }, [vaultState, reloadMonitorInterval]);

  const runBackgroundMonitor = useCallback(async () => {
    try {
      // One passive command: the backend diffs open alerts around the run
      // and reports the new severities, so this timer needs no extra
      // calls and never counts as user activity (auto-lock still works).
      const report = await api.monitorRunFull();
      if (report.summary.alerts_created > 0) {
        await notifyNewAlerts(report.new_alert_severities);
      }
    } catch {
      // Locked meanwhile, or a transient failure: the next tick (or a
      // manual "Run checks now") covers it. Never disturb the user.
    }
  }, []);

  useEffect(() => {
    if (vaultState !== "unlocked" || monitorMinutes <= 0) return;
    const timer = setInterval(() => void runBackgroundMonitor(), monitorMinutes * 60_000);
    return () => clearInterval(timer);
  }, [vaultState, monitorMinutes, runBackgroundMonitor]);

  const [lockError, setLockError] = useState<string | null>(null);

  // A failed lock must never look like a successful one. Without the catch,
  // a rejected `vaultLock` left the UI on whatever screen it was on with an
  // unhandled rejection in the console — and the user, having clicked "Lock
  // vault", reasonably believed the vault was locked when it was not
  // (ZFT-031). The view and the state flag move only after the backend
  // confirms.
  const lockNow = async () => {
    setLockError(null);
    try {
      await api.vaultLock();
    } catch (e) {
      setLockError(
        `The vault could NOT be locked: ${isApiError(e) ? e.message : String(e)}. It is still ` +
          `unlocked. Try again, or quit Tethra — quitting ends the session.`,
      );
      return;
    }
    setView({ name: "projects" });
    setVaultState("locked");
    trackAnalytics({ name: "vault_locked" });
  };

  if (fatal) {
    return (
      <div className="center-page">
        <div>
          <BrandLockup className="fatal-brand" />
          <p className="error">Startup error: {fatal}</p>
        </div>
      </div>
    );
  }
  if (vaultState === "loading") {
    return (
      <div className="center-page">
        <p className="muted">Loading…</p>
      </div>
    );
  }
  if (vaultState === "missing") {
    return (
      <>
        <Gate eyebrow="Local-first credential vault">
          <VaultSetup
            dataDir={dataDir}
            onCreated={() => {
              trackAnalytics({ name: "vault_unlocked" });
              void refreshStatus();
            }}
          />
        </Gate>
        <AnalyticsConsentBanner />
      </>
    );
  }
  if (vaultState === "locked") {
    // The gateway keeps forwarding while the vault is locked; the strip
    // keeps that visible (its backend commands are lock-free).
    return (
      <>
        <Gate eyebrow="Vault locked">
          <VaultUnlock
            dataDir={dataDir}
            onUnlocked={() => {
              trackAnalytics({ name: "vault_unlocked" });
              void refreshStatus();
            }}
          />
          <GatewayLockStrip />
        </Gate>
        <AnalyticsConsentBanner />
      </>
    );
  }

  const navItem = (name: View["name"], label: string, active: boolean) => (
    <button
      key={name}
      className={active ? "nav-item active" : "nav-item"}
      aria-current={active ? "page" : undefined}
      // The tooltip is what makes the collapsed rail usable.
      title={navCollapsed ? label : undefined}
      onClick={() => setView({ name } as View)}
    >
      <NavIcon name={name} />
      <span className="nav-text">{label}</span>
    </button>
  );

  const current = SECTION_OF[view.name];
  const activeLabel =
    NAV_GROUPS.flatMap((g) => g.items).find(([n]) => n === current)?.[1] ?? "";

  return (
    <>
      <div className={navCollapsed ? "shell nav-collapsed" : "shell"}>
        <ParticleField mode={particleModeFor(view.name)} />
        <aside className={navCollapsed ? "sidebar collapsed" : "sidebar"}>
          <div className="brand">
            <BrandLockup />
            <span className="spacer" />
            <button
              className="nav-toggle"
              aria-label={navCollapsed ? "Expand navigation" : "Collapse navigation"}
              aria-expanded={!navCollapsed}
              title={navCollapsed ? "Expand navigation" : "Collapse navigation"}
              onClick={() => setNavCollapsed((c) => !c)}
            >
              <svg
                viewBox="0 0 16 16"
                width="15"
                height="15"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.4"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <rect x="2" y="2.6" width="12" height="10.8" rx="1.4" />
                <path d="M6.4 2.6v10.8" />
              </svg>
            </button>
          </div>
          <nav className="nav" aria-label="Main">
            {NAV_GROUPS.map((group) => (
              <div className="nav-group" key={group.label}>
                <div className="nav-label">{group.label}</div>
                {group.items.map(([name, label]) => navItem(name, label, current === name))}
              </div>
            ))}
          </nav>
          <div className="sidebar-foot">
            <WireGlobe className="globe-mini" />
          </div>
        </aside>

        <div className="main">
          <header className="topbar">
            <span className="crumb">{activeLabel}</span>
            <span className="spacer" />
            <span className="local-status">
              <i aria-hidden="true" /> Local vault
            </span>
            <button className="lock-button" onClick={() => void lockNow()}>
              Lock vault
            </button>
          </header>
          <main className="content">
            {lockError && (
              <p className="error" role="alert">
                {lockError}
              </p>
            )}
            {view.name === "dashboard" && (
              <DashboardView
                onTrack={() => {
                  trackAnalytics({ name: "tracking_setup_started" });
                  setView({ name: "track" });
                }}
              />
            )}
            {view.name === "track" && (
              // The manual route form lives in Advanced → Gateway internals. A
              // desktop-only user must be able to REACH it, not be told to run a
              // CLI command they do not have (ZFT-009).
              <TrackFlow
                onDone={() => setView({ name: "dashboard" })}
                onOpenAdvanced={() => setView({ name: "gateway" })}
              />
            )}
            {view.name === "projects" && (
              <ProjectList
                onOpen={(ident) => setView({ name: "project", ident })}
                onNew={() => setView({ name: "project-new" })}
              />
            )}
            {view.name === "project-new" && (
              <ProjectForm
                onDone={(ident) =>
                  setView(ident ? { name: "project", ident } : { name: "projects" })
                }
              />
            )}
            {view.name === "project-edit" && (
              <ProjectForm
                editIdent={view.ident}
                onDone={(ident) =>
                  setView(ident ? { name: "project", ident } : { name: "projects" })
                }
              />
            )}
            {view.name === "project" && (
              <ProjectDetail
                ident={view.ident}
                onBack={() => setView({ name: "projects" })}
                onEdit={() => setView({ name: "project-edit", ident: view.ident })}
                onOpenCredential={(id) => setView({ name: "credential", id })}
                onAddCredential={() => setView({ name: "credential-new", project: view.ident })}
                onOpenAdvanced={() => setView({ name: "track" })}
              />
            )}
            {view.name === "credential-new" && (
              <CredentialForm
                project={view.project}
                onDone={(id) =>
                  setView(
                    id ? { name: "credential", id } : { name: "project", ident: view.project },
                  )
                }
              />
            )}
            {view.name === "credential-edit" && (
              <CredentialForm
                editId={view.id}
                onDone={(id) => setView(id ? { name: "credential", id } : { name: "projects" })}
              />
            )}
            {view.name === "credential" && (
              <CredentialDetail
                id={view.id}
                onBack={(projectIdent) =>
                  setView(
                    projectIdent
                      ? { name: "project", ident: projectIdent }
                      : { name: "projects" },
                  )
                }
                onEdit={() => setView({ name: "credential-edit", id: view.id })}
              />
            )}
            {view.name === "providers" && (
              <ProviderCatalog onOpen={(id) => setView({ name: "provider", id })} />
            )}
            {view.name === "provider" && (
              <ProviderDetail id={view.id} onBack={() => setView({ name: "providers" })} />
            )}
            {view.name === "scan" && <ScanView />}
            {view.name === "env" && <EnvView />}
            {view.name === "destinations" && <DestinationsView />}
            {view.name === "sync" && <SyncView />}
            {view.name === "rotation" && <RotationView />}
            {view.name === "access" && <AccessView />}
            {view.name === "alerts" && <AlertsView />}
            {view.name === "notify" && <NotifyView />}
            {view.name === "usage" && <UsageView />}
            {view.name === "api-activity" && <ApiActivityView />}
            {view.name === "gateway" && <GatewayView />}
            {view.name === "pricing" && <PricingView />}
            {view.name === "templates" && <TemplatesView />}
            {view.name === "settings" && (
              <SettingsView dataDir={dataDir} onSaved={() => void reloadMonitorInterval()} />
            )}
            {view.name === "backup" && <BackupView onRestored={() => void refreshStatus()} />}
          </main>
        </div>
      </div>
      <AnalyticsConsentBanner />
    </>
  );
}
