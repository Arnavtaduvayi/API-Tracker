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
import { Gate } from "./components/visuals/Gate";
import { WireGlobe } from "./components/visuals/WireGlobe";
import { NavIcon } from "./components/visuals/NavIcons";

export type View =
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
  | { name: "pricing" }
  | { name: "templates" }
  | { name: "settings" }
  | { name: "backup" };

type VaultState = "loading" | "missing" | "locked" | "unlocked";

/**
 * Sidebar navigation. These are the same 15 destinations the old top bar had,
 * with identical labels — only grouped for scanability.
 */
const NAV_GROUPS: { label: string; items: [View["name"], string][] }[] = [
  {
    label: "Vault",
    items: [
      ["projects", "Projects"],
      ["providers", "Providers"],
    ],
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
      ["pricing", "Pricing"],
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
  pricing: "pricing",
  templates: "templates",
  backup: "backup",
  settings: "settings",
};

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
  const [view, setView] = useState<View>({ name: "projects" });
  const [fatal, setFatal] = useState<string | null>(null);
  const [monitorMinutes, setMonitorMinutes] = useState(0);
  const [navCollapsed, setNavCollapsed] = useState(false);

  // The sidebar collapses itself when the window gets narrow and expands again
  // when there is room. Crossing the breakpoint re-syncs, but between
  // crossings the user's manual toggle wins.
  useEffect(() => {
    // Guarded: a webview without matchMedia must not take down the whole app
    // over a piece of navigation chrome. It just stays expanded.
    if (typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(max-width: 1080px)");
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

  const lockNow = async () => {
    await api.vaultLock();
    setView({ name: "projects" });
    setVaultState("locked");
  };

  if (fatal) {
    return (
      <div className="center-page">
        <div>
          <h1>Tethra</h1>
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
      <Gate eyebrow="Local-first credential vault">
        <VaultSetup dataDir={dataDir} onCreated={() => void refreshStatus()} />
      </Gate>
    );
  }
  if (vaultState === "locked") {
    return (
      <Gate eyebrow="Vault locked">
        <VaultUnlock dataDir={dataDir} onUnlocked={() => void refreshStatus()} />
      </Gate>
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
    <div className={navCollapsed ? "shell nav-collapsed" : "shell"}>
      <aside className={navCollapsed ? "sidebar collapsed" : "sidebar"}>
        <div className="brand">
          <span className="brand-mark" />
          <span className="brand-name">Tethra</span>
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
          <button onClick={() => void lockNow()}>Lock vault</button>
        </header>
        <main className="content">
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
          {view.name === "pricing" && <PricingView />}
          {view.name === "templates" && <TemplatesView />}
          {view.name === "settings" && (
            <SettingsView dataDir={dataDir} onSaved={() => void reloadMonitorInterval()} />
          )}
          {view.name === "backup" && <BackupView onRestored={() => void refreshStatus()} />}
        </main>
      </div>
    </div>
  );
}
