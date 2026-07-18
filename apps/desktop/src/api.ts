// Typed wrappers around the Tauri commands. Every call funnels through
// `call`, which converts backend errors into ApiError objects and notifies
// the app when the vault has auto-locked.

import { invoke } from "@tauri-apps/api/core";
import type {
  ApiError,
  BackupInfo,
  Credential,
  Environment,
  Project,
  ProviderInfo,
  ReuseWarning,
  VaultSettings,
  VaultStatus,
} from "./types";

let onVaultLocked: (() => void) | null = null;

export function setVaultLockedHandler(handler: () => void) {
  onVaultLocked = handler;
}

export function isApiError(e: unknown): e is ApiError {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (raw) {
    const err: ApiError = isApiError(raw) ? raw : { code: "unknown", message: String(raw) };
    if (err.code === "vault_locked" && onVaultLocked) {
      onVaultLocked();
    }
    throw err;
  }
}

export const api = {
  vaultStatus: () => call<VaultStatus>("vault_status"),
  vaultCreate: (password: string) => call<void>("vault_create", { password }),
  vaultUnlock: (password: string) => call<void>("vault_unlock", { password }),
  vaultLock: () => call<void>("vault_lock"),
  reauth: (password: string) => call<void>("reauth", { password }),

  settingsGet: () => call<VaultSettings>("settings_get"),
  settingsSet: (settings: VaultSettings) => call<void>("settings_set", { settings }),
  providersList: () => call<ProviderInfo[]>("providers_list"),

  projectList: (includeArchived: boolean) =>
    call<Project[]>("project_list", { includeArchived }),
  projectGet: (ident: string) => call<Project>("project_get", { ident }),
  projectCreate: (args: {
    name: string;
    description: string;
    notes: string;
    environments: Environment[];
    repoPaths: string[];
  }) => call<Project>("project_create", args),
  projectUpdate: (
    ident: string,
    args: {
      name: string;
      description: string;
      notes: string;
      environments: Environment[];
      repoPaths: string[];
    },
  ) => call<Project>("project_update", { ident, ...args }),
  projectSetArchived: (ident: string, archived: boolean) =>
    call<Project>("project_set_archived", { ident, archived }),
  projectSetPassword: (ident: string, password: string) =>
    call<void>("project_set_password", { ident, password }),
  projectRemovePassword: (ident: string, password: string) =>
    call<void>("project_remove_password", { ident, password }),
  projectUnlock: (ident: string, password: string) =>
    call<Project>("project_unlock", { ident, password }),
  projectLock: (ident: string) => call<Project>("project_lock", { ident }),

  credentialList: (project?: string) =>
    call<Credential[]>("credential_list", { project: project ?? null }),
  credentialGet: (selector: string) => call<Credential>("credential_get", { selector }),
  credentialCheckReuse: (project: string, environment: Environment, value: string) =>
    call<ReuseWarning[]>("credential_check_reuse", { project, environment, value }),
  credentialAdd: (args: {
    project: string;
    provider: string;
    name: string;
    environment: Environment;
    value: string;
    keyCreatedAt: string | null;
    expiresAt: string | null;
    docsUrl: string;
    notes: string;
  }) => call<Credential>("credential_add", args),
  credentialAddReference: (args: {
    project: string;
    source: string;
    name: string;
    environment: Environment;
  }) => call<Credential>("credential_add_reference", args),
  credentialUpdate: (
    selector: string,
    args: {
      name: string;
      provider: string;
      environment: Environment;
      keyCreatedAt: string | null;
      expiresAt: string | null;
      docsUrl: string;
      notes: string;
    },
  ) => call<Credential>("credential_update", { selector, ...args }),
  credentialMark: (
    selector: string,
    args: {
      markUsedNow?: boolean;
      markValidated?: boolean | null;
      disabled?: boolean | null;
      revoked?: boolean | null;
      possiblyExposed?: boolean | null;
      exposureNote?: string | null;
    },
  ) => call<Credential>("credential_mark", { selector, ...args }),
  credentialReplaceValue: (selector: string, password: string, value: string) =>
    call<ReuseWarning[]>("credential_replace_value", { selector, password, value }),
  credentialDelete: (selector: string) => call<void>("credential_delete", { selector }),
  credentialReveal: (selector: string, password: string) =>
    call<string>("credential_reveal", { selector, password }),
  credentialCopy: (selector: string, password: string) =>
    call<number>("credential_copy", { selector, password }),

  backupCreate: (
    path: string,
    masterPassword: string,
    backupPassword: string,
    overwrite: boolean,
  ) => call<BackupInfo>("backup_create", { path, masterPassword, backupPassword, overwrite }),
  backupVerify: (path: string, backupPassword: string) =>
    call<BackupInfo>("backup_verify", { path, backupPassword }),
  backupRestore: (path: string, backupPassword: string, force: boolean) =>
    call<BackupInfo>("backup_restore", { path, backupPassword, force }),
};
