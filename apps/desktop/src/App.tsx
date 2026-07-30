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
  };

  if (fatal) {
    return (
      <div>
        <h1>Tethra</h1>
        <p className="error">Startup error: {fatal}</p>
      </div>
    );
  }
  if (vaultState === "loading") {
    return <p>Loading…</p>;
  }
  if (vaultState === "missing") {
    return <VaultSetup dataDir={dataDir} onCreated={() => void refreshStatus()} />;
  }
  if (vaultState === "locked") {
    // The gateway keeps forwarding while the vault is locked; the strip
    // keeps that visible (its backend commands are lock-free).
    return (
      <div>
        <VaultUnlock dataDir={dataDir} onUnlocked={() => void refreshStatus()} />
        <GatewayLockStrip />
      </div>
    );
  }

  return (
    <div>
      <nav className="topbar">
        <strong>Tethra</strong>
        <button
          className={view.name === "dashboard" ? undefined : "link"}
          onClick={() => setView({ name: "dashboard" })}
        >
          Activity
        </button>
        {/* Projects is the primary surface: folder selection, detection,
            tracking setup and live activity all live on a project page. The
            standalone "Track API activity" flow is NOT deleted — its
            diagnostics, destination approvals and undo are still the only place
            some of those decisions can be made — but it moves under Advanced so
            the normal path never needs it (ADR 0029). */}
        <button
          className={view.name === "projects" ? undefined : "link"}
          onClick={() => setView({ name: "projects" })}
        >
          Projects
        </button>
        <span className="navgroup">Vault</span>
        <button className="link" onClick={() => setView({ name: "providers" })}>
          Providers
        </button>
        <button className="link" onClick={() => setView({ name: "scan" })}>
          Scan
        </button>
        <button className="link" onClick={() => setView({ name: "env" })}>
          Env files
        </button>
        <button className="link" onClick={() => setView({ name: "destinations" })}>
          Destinations
        </button>
        <button className="link" onClick={() => setView({ name: "sync" })}>
          Sync plans
        </button>
        <button className="link" onClick={() => setView({ name: "rotation" })}>
          Rotation
        </button>
        <button className="link" onClick={() => setView({ name: "access" })}>
          Temporary access
        </button>
        <span className="navgroup">Security</span>
        <button className="link" onClick={() => setView({ name: "alerts" })}>
          Alerts
        </button>
        <button className="link" onClick={() => setView({ name: "notify" })}>
          Notifications
        </button>
        <span className="navgroup">Advanced</span>
        <button className="link" onClick={() => setView({ name: "usage" })}>
          Usage
        </button>
        <button className="link" onClick={() => setView({ name: "track" })}>
          Tracking setup (advanced)
        </button>
        <button className="link" onClick={() => setView({ name: "api-activity" })}>
          Observation runs
        </button>
        <button className="link" onClick={() => setView({ name: "gateway" })}>
          Gateway internals
        </button>
        <button className="link" onClick={() => setView({ name: "pricing" })}>
          Pricing
        </button>
        <button className="link" onClick={() => setView({ name: "templates" })}>
          Templates
        </button>
        <button className="link" onClick={() => setView({ name: "backup" })}>
          Backup
        </button>
        <button className="link" onClick={() => setView({ name: "settings" })}>
          Settings
        </button>
        <span className="spacer" />
        <button onClick={() => void lockNow()}>Lock vault</button>
      </nav>
      {lockError && (
        <p className="error" role="alert">
          {lockError}
        </p>
      )}
      {view.name === "dashboard" && (
        <DashboardView onTrack={() => setView({ name: "track" })} />
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
          onDone={(ident) => setView(ident ? { name: "project", ident } : { name: "projects" })}
        />
      )}
      {view.name === "project-edit" && (
        <ProjectForm
          editIdent={view.ident}
          onDone={(ident) => setView(ident ? { name: "project", ident } : { name: "projects" })}
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
            setView(id ? { name: "credential", id } : { name: "project", ident: view.project })
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
              projectIdent ? { name: "project", ident: projectIdent } : { name: "projects" },
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
    </div>
  );
}
