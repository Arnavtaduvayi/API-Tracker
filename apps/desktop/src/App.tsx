// Top-level shell: vault state machine (missing → create, locked → unlock,
// unlocked → main navigation) plus a simple view router. The backend
// enforces auto-lock; this component reacts to `vault_locked` errors and
// polls the status so the UI locks visibly too.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "./api";
import { setVaultLockedHandler } from "./api";
import type { VaultStatus } from "./types";
import { VaultSetup } from "./components/VaultSetup";
import { VaultUnlock } from "./components/VaultUnlock";
import { ProjectList } from "./components/ProjectList";
import { ProjectForm } from "./components/ProjectForm";
import { ProjectDetail } from "./components/ProjectDetail";
import { CredentialForm } from "./components/CredentialForm";
import { CredentialDetail } from "./components/CredentialDetail";
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
  | { name: "alerts" }
  | { name: "usage" }
  | { name: "settings" }
  | { name: "backup" };

type VaultState = "loading" | "missing" | "locked" | "unlocked";

export default function App() {
  const [vaultState, setVaultState] = useState<VaultState>("loading");
  const [dataDir, setDataDir] = useState("");
  const [view, setView] = useState<View>({ name: "projects" });
  const [fatal, setFatal] = useState<string | null>(null);

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

  const lockNow = async () => {
    await api.vaultLock();
    setView({ name: "projects" });
    setVaultState("locked");
  };

  if (fatal) {
    return (
      <div>
        <h1>API Tracker</h1>
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
    return <VaultUnlock dataDir={dataDir} onUnlocked={() => void refreshStatus()} />;
  }

  return (
    <div>
      <nav className="topbar">
        <strong>API Tracker</strong>
        <button className="link" onClick={() => setView({ name: "projects" })}>
          Projects
        </button>
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
        <button className="link" onClick={() => setView({ name: "alerts" })}>
          Alerts
        </button>
        <button className="link" onClick={() => setView({ name: "usage" })}>
          Usage
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
      {view.name === "alerts" && <AlertsView />}
      {view.name === "usage" && <UsageView />}
      {view.name === "settings" && <SettingsView dataDir={dataDir} />}
      {view.name === "backup" && <BackupView onRestored={() => void refreshStatus()} />}
    </div>
  );
}
