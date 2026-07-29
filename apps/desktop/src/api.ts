// Typed wrappers around the Tauri commands. Every call funnels through
// `call`, which converts backend errors into ApiError objects and notifies
// the app when the vault has auto-locked.

import { invoke } from "@tauri-apps/api/core";
import type {
  AccountInfo,
  AccessGrant,
  ActivityEvent,
  Alert,
  ApiError,
  ObservedService,
  ObservedEndpoint,
  RuntimeEvent,
  ObservationSession,
  CredentialAttribution,
  CompatibilityResult,
  ObserveMetrics,
  ServiceOverview,
  ObserveCertStatus,
  ObservabilitySettings,
  DiagnosticCheck,
  Attachment,
  DriftCheckOutcome,
  BackupInfo,
  BudgetReport,
  CleanupResult,
  Credential,
  CredentialVersionInfo,
  Destination,
  DestinationKindInfo,
  DocHistoryEntry,
  DocWatch,
  EnvExampleProposal,
  EnvExport,
  EnvExportReport,
  EnvFileInfo,
  EnvImportOutcome,
  Environment,
  DriftFinding,
  FetchedMetadata,
  GrantEndResult,
  HookStatus,
  MonitorFullReport,
  MonitorStatus,
  NotificationChannel,
  ProcessSession,
  SessionKillResult,
  Suppression,
  PermissionsPreview,
  DetectionReport,
  PricingImportOutcome,
  PricingRecord,
  StackPreference,
  Template,
  TemplateApplyOutcome,
  Project,
  ProjectActivityFilter,
  ProjectActivitySnapshot,
  ProjectOverview,
  ProjectRestoreEntry,
  DetectedCredential,
  DetectedStatus,
  FolderLinkPreview,
  LinkOutcome,
  ProviderConnection,
  ProviderKeyListing,
  CredentialActivitySources,
  GatewayActivitySummary,
  ProjectActivity,
  TrackingScan,
  TrackingPlan,
  TrackingApplyReport,
  TrackingStatus,
  TrackingDiagnosis,
  TrackingOriginRequest,
  TrackingUndoReport,
  ForegroundStatus,
  GatewayDisableReport,
  GatewayDoctor,
  GatewayInstallReport,
  GatewayLinkPlan,
  GatewayRouteList,
  GatewayUninstallReport,
  GatewayUnlinkReport,
  ProviderKeyOverview,
  ProviderManifest,
  ProviderProjectOverview,
  RepoReverifyReport,
  ScanPathReport,
  ReuseWarning,
  RotationEvent,
  RotationSchedule,
  RotationView,
  StoredPermissions,
  SyncPlan,
  SyncReport,
  TestKeyResult,
  TimelineEvent,
  UsageSnapshot,
  UsageTotals,
  ValidationResult,
  VarPreview,
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
  vaultChangePassword: (current: string, newPassword: string) =>
    call<void>("vault_change_password", { current, new: newPassword }),

  settingsGet: () => call<VaultSettings>("settings_get"),
  settingsSet: (settings: VaultSettings) => call<void>("settings_set", { settings }),
  providersList: () => call<ProviderManifest[]>("providers_list"),
  providerGet: (id: string) => call<ProviderManifest>("provider_get", { id }),

  scanPath: (
    path: string,
    mode: "working" | "staged" | "history",
    markExposed: boolean,
    historyDepth: number | null,
  ) => call<ScanPathReport>("scan_path", { path, mode, markExposed, historyDepth }),
  scanReverify: (path: string) => call<RepoReverifyReport>("scan_reverify", { path }),
  suppressionAdd: (suppressionKey: string, path: string, reason: string) =>
    call<void>("suppression_add", { suppressionKey, path, reason }),
  suppressionList: () => call<Suppression[]>("suppression_list"),
  suppressionRemove: (suppressionKey: string) =>
    call<void>("suppression_remove", { suppressionKey }),
  hookStatus: (path: string) => call<HookStatus>("hook_status", { path }),
  hookInstall: (path: string, force: boolean) =>
    call<HookStatus>("hook_install", { path, force }),
  hookRemove: (path: string) => call<HookStatus>("hook_remove", { path }),

  monitorStatus: () => call<MonitorStatus>("monitor_status"),
  monitorRunFull: () => call<MonitorFullReport>("monitor_run_full"),
  alertsList: (includeResolved: boolean) => call<Alert[]>("alerts_list", { includeResolved }),
  alertAcknowledge: (id: string) => call<Alert>("alert_acknowledge", { id }),
  alertResolve: (id: string) => call<Alert>("alert_resolve", { id }),

  docWatchAdd: (provider: string, url: string) =>
    call<DocWatch>("doc_watch_add", { provider, url }),
  docWatchRemove: (url: string) => call<boolean>("doc_watch_remove", { url }),
  docWatchList: () => call<DocWatch[]>("doc_watch_list"),
  docWatchCheck: (url: string) => call<DocWatch>("doc_watch_check", { url }),
  docWatchHistory: (url: string | null, limit: number) =>
    call<DocHistoryEntry[]>("doc_watch_history", { url, limit }),

  notificationChannelAdd: (name: string, url: string, minSeverity: string) =>
    call<NotificationChannel>("notification_channel_add", { name, url, minSeverity }),
  notificationChannels: () => call<NotificationChannel[]>("notification_channels"),
  notificationChannelRemove: (ident: string) =>
    call<void>("notification_channel_remove", { ident }),
  notificationChannelEnable: (ident: string, enabled: boolean) =>
    call<void>("notification_channel_enable", { ident, enabled }),
  notificationChannelTest: (ident: string) =>
    call<string>("notification_channel_test", { ident }),
  notificationHistory: (limit: number) =>
    call<ActivityEvent[]>("notification_history", { limit }),

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
  projectSetPassword: (ident: string, password: string, master: string) =>
    call<void>("project_set_password", { ident, password, master }),
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
    docsUrl: string;
    notes: string;
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
  credentialDelete: (selector: string, password: string) =>
    call<void>("credential_delete", { selector, password }),
  credentialReveal: (selector: string, password: string) =>
    call<string>("credential_reveal", { selector, password }),
  credentialCopy: (selector: string, password: string) =>
    call<number>("credential_copy", { selector, password }),

  credentialValidate: (selector: string) =>
    call<ValidationResult>("credential_validate", { selector }),
  credentialMetadata: (selector: string) =>
    call<FetchedMetadata>("credential_metadata", { selector }),
  credentialPermissions: (selector: string, sync: boolean) =>
    call<StoredPermissions | null>("credential_permissions", { selector, sync }),
  providerConnect: (provider: string, credential: string) =>
    call<void>("provider_connect", { provider, credential }),
  providerAdminConnect: (
    provider: string,
    adminKey: string,
    org: string | null,
    password: string | null,
  ) => call<string>("provider_admin_connect", { provider, adminKey, org, password }),
  providerAdminDisconnect: (provider: string, password: string) =>
    call<boolean>("provider_admin_disconnect", { provider, password }),
  providerAdminTest: (provider: string, password: string) =>
    call<string>("provider_admin_test", { provider, password }),
  providerSync: (provider: string, days: number | null, from?: string, to?: string) =>
    call<SyncReport>("provider_sync", {
      provider,
      days,
      from: from ?? null,
      to: to ?? null,
    }),
  providerConnectionStatus: (provider: string) =>
    call<ProviderConnection>("provider_connection_status", { provider }),
  providerAccountSync: (provider: string) =>
    call<AccountInfo>("provider_account_sync", { provider }),
  providerKeys: (provider: string) =>
    call<ProviderKeyOverview[]>("provider_keys", { provider }),
  providerProjects: (provider: string) =>
    call<ProviderProjectOverview[]>("provider_projects", { provider }),
  providerLinkKey: (provider: string, apiKeyId: string, credential: string) =>
    call<number>("provider_link_key", { provider, apiKeyId, credential }),
  providerUnlinkKey: (provider: string, apiKeyId: string) =>
    call<number>("provider_unlink_key", { provider, apiKeyId }),
  usageReport: (project?: string, credential?: string) =>
    call<UsageTotals>("usage_report", {
      project: project ?? null,
      credential: credential ?? null,
    }),
  usageRecords: (args: {
    project?: string;
    credential?: string;
    provider?: string;
    source: "all" | "provider" | "manual";
  }) =>
    call<UsageSnapshot[]>("usage_records", {
      project: args.project ?? null,
      credential: args.credential ?? null,
      provider: args.provider ?? null,
      source: args.source,
    }),
  budgetCostSourceGet: () => call<string>("budget_cost_source_get"),
  budgetCostSourceSet: (value: string) => call<void>("budget_cost_source_set", { value }),
  pricingRecords: (all: boolean) => call<PricingRecord[]>("pricing_records", { all }),
  pricingSetOverride: (args: {
    provider: string;
    model: string;
    unit: "tokens" | "requests";
    input: string | null;
    output: string | null;
    cachedInput: string | null;
    perRequest: string | null;
    note: string | null;
  }) =>
    call<void>("pricing_set_override", {
      provider: args.provider,
      model: args.model,
      unit: args.unit,
      input: args.input,
      output: args.output,
      cachedInput: args.cachedInput,
      perRequest: args.perRequest,
      note: args.note,
    }),
  pricingRemoveOverride: (provider: string, model: string) =>
    call<number>("pricing_remove_override", { provider, model }),
  pricingImport: (json: string) => call<PricingImportOutcome>("pricing_import", { json }),
  pricingExport: (provider: string | null) => call<string>("pricing_export", { provider }),
  templateList: () => call<Template[]>("template_list"),
  templateApply: (templateId: string, project: string, writeExampleDir: string | null) =>
    call<TemplateApplyOutcome>("template_apply", { templateId, project, writeExampleDir }),
  stackDetect: (project: string | null, repo: string | null) =>
    call<DetectionReport[]>("stack_detect", { project, repo }),
  stackDecide: (repo: string, templateId: string, decision: "confirmed" | "dismissed") =>
    call<void>("stack_decide", { repo, templateId, decision }),
  stackPrefs: () => call<StackPreference[]>("stack_prefs"),
  stackPrefsReset: (repo: string | null) => call<number>("stack_prefs_reset", { repo }),
  usageRecordManual: (
    credential: string,
    model: string | null,
    inputTokens: number,
    outputTokens: number,
  ) => call<void>("usage_record_manual", { credential, model, inputTokens, outputTokens }),
  budgetSet: (project: string | null, credential: string | null, amount: string | null) =>
    call<void>("budget_set", { project, credential, amount }),
  budgetReport: (project?: string, credential?: string) =>
    call<BudgetReport>("budget_report", {
      project: project ?? null,
      credential: credential ?? null,
    }),
  activityList: (credential: string | null, limit: number) =>
    call<ActivityEvent[]>("activity_list", { credential, limit }),

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

  envDiscover: (project: string | null, path: string | null) =>
    call<EnvFileInfo[]>("env_discover", { project, path }),
  envPreview: (project: string, file: string) =>
    call<VarPreview[]>("env_preview", { project, file }),
  envImport: (project: string, file: string, keys: string[] | null) =>
    call<EnvImportOutcome[]>("env_import", { project, file, keys }),
  envDrift: (project: string) => call<DriftFinding[]>("env_drift", { project }),
  envExamplePreview: (file: string) =>
    call<EnvExampleProposal>("env_example_preview", { file }),
  envExampleWrite: (project: string, examplePath: string, content: string, password: string) =>
    call<string>("env_example_write", { project, examplePath, content, password }),
  envExport: (args: {
    project: string;
    path: string;
    vars: string[] | null;
    password: string;
    overwrite: boolean;
    ttlMinutes: number | null;
  }) => call<EnvExportReport>("env_export", args),
  envCleanup: (all: boolean, force: boolean) =>
    call<CleanupResult[]>("env_cleanup", { all, force }),
  envExportsList: () => call<EnvExport[]>("env_exports_list"),

  credentialVersions: (id: string, password: string) =>
    call<CredentialVersionInfo[]>("credential_versions", { id, password }),

  destinationCatalog: () => call<DestinationKindInfo[]>("destination_catalog"),
  destinationAdd: (
    kind: string,
    name: string,
    config: Record<string, unknown>,
    auth: string | null,
  ) => call<Destination>("destination_add", { kind, name, config, auth }),
  destinationRemove: (ident: string, password: string) =>
    call<Destination>("destination_remove", { ident, password }),
  destinationList: () => call<Destination[]>("destination_list"),
  destinationTest: (ident: string) => call<string>("destination_test", { ident }),
  destinationAttach: (
    credential: string,
    destination: string,
    secretName: string,
    environment: string,
  ) => call<void>("destination_attach", { credential, destination, secretName, environment }),
  destinationDeleteSecret: (ident: string, secretName: string, password: string) =>
    call<string>("destination_delete_secret", { ident, secretName, password }),
  destinationDetach: (credential: string, destination: string, secretName: string | null) =>
    call<number>("destination_detach", { credential, destination, secretName }),
  destinationAttachments: (credential: string | null) =>
    call<Attachment[]>("destination_attachments", { credential }),
  destinationDriftCheck: (credential: string | null) =>
    call<DriftCheckOutcome[]>("destination_drift_check", { credential }),

  syncPlanCreate: (credential: string, note: string) =>
    call<SyncPlan>("sync_plan_create", { credential, note }),
  syncPlanGet: (id: string) => call<SyncPlan>("sync_plan_get", { id }),
  syncPlansList: (credential: string | null, limit: number) =>
    call<SyncPlan[]>("sync_plans_list", { credential, limit }),
  syncPlanExecute: (id: string, onlyDestination: string | null, password: string) =>
    call<SyncPlan>("sync_plan_execute", { id, onlyDestination, password }),
  syncPlanRollback: (id: string, onlyDestination: string | null, password: string) =>
    call<SyncPlan>("sync_plan_rollback", { id, onlyDestination, password }),

  rotationPlan: (args: {
    credential: string;
    graceMinutes: number;
    providerProject: string | null;
    oldKeyId: string | null;
    note: string;
  }) => call<RotationView>("rotation_plan", args),
  rotationApprove: (id: string, password: string) =>
    call<RotationView>("rotation_approve", { id, password }),
  rotationAdvance: (
    id: string,
    password: string,
    provideValue: string | null,
    acknowledgeContinuedUse: boolean,
  ) =>
    call<RotationView>("rotation_advance", {
      id,
      password,
      provideValue,
      acknowledgeContinuedUse,
    }),
  rotationRollback: (id: string, password: string, revokeNew: boolean) =>
    call<RotationView>("rotation_rollback", { id, password, revokeNew }),
  rotationCompleteManual: (id: string, password: string, note: string) =>
    call<RotationView>("rotation_complete_manual", { id, password, note }),
  rotationCancel: (id: string, password: string) =>
    call<RotationView>("rotation_cancel", { id, password }),
  rotationGet: (id: string) => call<RotationView>("rotation_get", { id }),
  rotationsList: (credential: string | null, limit: number) =>
    call<RotationView[]>("rotations_list", { credential, limit }),
  rotationEvents: (id: string) => call<RotationEvent[]>("rotation_events", { id }),
  rotationScheduleSet: (credential: string, everyDays: number) =>
    call<void>("rotation_schedule_set", { credential, everyDays }),
  rotationScheduleRemove: (credential: string) =>
    call<boolean>("rotation_schedule_remove", { credential }),
  rotationSchedules: () => call<RotationSchedule[]>("rotation_schedules"),

  accessGrantCreate: (args: {
    project: string;
    label: string;
    credentials: string[];
    ttlMinutes: number;
    maxLaunches: number;
    maxDurationSecs: number | null;
    budgetWarn: string | null;
  }) => call<AccessGrant>("access_grant_create", args),
  accessGrants: (includeInactive: boolean) =>
    call<AccessGrant[]>("access_grants", { includeInactive }),
  accessGrantEnd: (id: string) => call<GrantEndResult>("access_grant_end", { id }),
  accessSessions: (includeEnded: boolean, limit: number) =>
    call<ProcessSession[]>("access_sessions", { includeEnded, limit }),
  accessSessionKill: (id: string) => call<SessionKillResult>("access_session_kill", { id }),

  credentialTimeline: (id: string) => call<TimelineEvent[]>("credential_timeline", { id }),
  permissionsPreview: (id: string) => call<PermissionsPreview>("permissions_preview", { id }),
  providerListKeys: (provider: string, providerProject: string | null) =>
    call<ProviderKeyListing[]>("provider_list_keys", { provider, providerProject }),
  testKeyCreate: (args: {
    project: string;
    provider: string;
    providerProject: string | null;
    name: string;
    ttlMinutes: number;
    password: string;
  }) => call<TestKeyResult>("test_key_create", args),
  credentialProviderRevoke: (id: string, password: string) =>
    call<string>("credential_provider_revoke", { id, password }),

  // --- Runtime API observability (metadata only) ---
  observeOverview: () => call<ServiceOverview[]>("observe_overview"),
  observeServices: () => call<ObservedService[]>("observe_services"),
  observeService: (id: string) => call<ObservedService>("observe_service", { id }),
  observeServiceMetrics: (id: string) =>
    call<ObserveMetrics>("observe_service_metrics", { id }),
  observeServiceEndpoints: (id: string) =>
    call<ObservedEndpoint[]>("observe_service_endpoints", { id }),
  observeServiceEvents: (id: string, limit: number) =>
    call<RuntimeEvent[]>("observe_service_events", { id, limit }),
  observeSessions: (project: string | null, limit: number) =>
    call<ObservationSession[]>("observe_sessions", { project, limit }),
  observeSession: (id: string) => call<ObservationSession>("observe_session", { id }),
  observeSessionMetrics: (id: string) =>
    call<ObserveMetrics>("observe_session_metrics", { id }),
  observeSessionEvents: (id: string, limit: number) =>
    call<RuntimeEvent[]>("observe_session_events", { id, limit }),
  observeSessionAttributions: (id: string) =>
    call<CredentialAttribution[]>("observe_session_attributions", { id }),
  observeSessionCompat: (id: string) =>
    call<CompatibilityResult[]>("observe_session_compat", { id }),
  observeCredentialActivity: (selector: string, limit: number) =>
    call<CredentialAttribution[]>("observe_credential_activity", { selector, limit }),
  observeCertStatus: () => call<ObserveCertStatus>("observe_cert_status"),
  observeCertRotate: (password: string) =>
    call<ObserveCertStatus>("observe_cert_rotate", { password }),
  observeCertRemove: (password: string) => call<void>("observe_cert_remove", { password }),
  observeCertInstallSystem: (password: string) =>
    call<void>("observe_cert_install_system", { password }),
  observeCertUninstallSystem: () => call<void>("observe_cert_uninstall_system"),
  observeSettingsGet: () => call<ObservabilitySettings>("observe_settings_get"),
  observeSettingsSet: (args: {
    defaultMode?: string | null;
    eventDays?: number | null;
    aggregateDays?: number | null;
  }) => call<void>("observe_settings_set", args),
  observeDiagnostics: () => call<DiagnosticCheck[]>("observe_diagnostics"),
  observeDeleteSession: (id: string) => call<void>("observe_delete_session", { id }),
  observeDeleteAll: (password: string) => call<void>("observe_delete_all", { password }),
  observeAllowlist: (project: string) =>
    call<[string, number, string][]>("observe_allowlist", { project }),
  observeAllowlistAdd: (project: string, host: string, port: number, note: string) =>
    call<void>("observe_allowlist_add", { project, host, port, note }),
  observeAllowlistRemove: (project: string, host: string, port: number) =>
    call<boolean>("observe_allowlist_remove", { project, host, port }),

  // --- Local Gateway (ADR 0019, Phase 3) ---
  // Doctor/status/start/stop/restart are lock-free on the backend so the
  // lock screen's status strip keeps working; route/link mutations and
  // install/disable/uninstall require the unlocked vault.
  gatewayDoctor: () => call<GatewayDoctor>("gateway_doctor"),
  gatewayLocateCli: () => call<string | null>("gateway_locate_cli"),
  gatewayInstall: (force: boolean) => call<GatewayInstallReport>("gateway_install", { force }),
  gatewayDisable: (keepEnv: boolean) =>
    call<GatewayDisableReport>("gateway_disable", { keepEnv }),
  gatewayUninstall: (keepEnv: boolean) =>
    call<GatewayUninstallReport>("gateway_uninstall", { keepEnv }),
  gatewayStart: () => call<void>("gateway_start"),
  gatewayStop: () => call<void>("gateway_stop"),
  gatewayRestart: () => call<void>("gateway_restart"),
  gatewayRepair: () => call<GatewayInstallReport>("gateway_repair"),
  gatewayRouteList: () => call<GatewayRouteList>("gateway_route_list"),
  gatewayRouteAdd: (provider: string, prefix: string | null, origin: string | null) =>
    call<void>("gateway_route_add", { provider, prefix, origin }),
  gatewayRouteRemove: (prefix: string) => call<boolean>("gateway_route_remove", { prefix }),
  gatewayRouteSetEnabled: (prefix: string, enabled: boolean) =>
    call<boolean>("gateway_route_set_enabled", { prefix, enabled }),
  gatewayLinkPlan: (args: {
    project: string;
    route: string;
    envFiles: string[];
    dir: string | null;
    var: string | null;
  }) => call<GatewayLinkPlan>("gateway_link_plan", { ...args }),
  gatewayLinkApply: (args: {
    project: string;
    route: string;
    envFiles: string[];
    dir: string | null;
    var: string | null;
    slug: string;
    digest: string;
  }) => call<void>("gateway_link_apply", { ...args }),
  gatewayUnlink: (project: string, route: string) =>
    call<GatewayUnlinkReport>("gateway_unlink", { project, route }),
  gatewayPushKey: (password: string) => call<void>("gateway_push_key", { password }),
  gatewayRevokeKey: () => call<void>("gateway_revoke_key"),
  gatewayMatchWhileLockedGet: () => call<boolean>("gateway_match_while_locked_get"),
  gatewayMatchWhileLockedSet: (enabled: boolean, password?: string) =>
    call<void>("gateway_match_while_locked_set", { enabled, password: password ?? null }),
  gatewayRecording: (pause: boolean) => call<void>("gateway_recording", { pause }),
  gatewayActivity: (since: string | null) =>
    call<GatewayActivitySummary>("gateway_activity", { since }),
  /** Same rows and window as `gatewayActivity`, split by project. */
  gatewayActivityByProject: (since: string | null) =>
    call<ProjectActivity[]>("gateway_activity_by_project", { since }),
  credentialActivitySources: (selector: string) =>
    call<CredentialActivitySources>("credential_activity_sources", { selector }),

  // --- Track API activity (ADR 0022) ----------------------------------
  trackingScan: (folder: string) => call<TrackingScan>("tracking_scan", { folder }),
  /** Every repository-discovered destination, with its full disclosure. */
  trackingOriginRequests: () => call<TrackingOriginRequest[]>("tracking_origin_requests"),
  /**
   * The ONLY way a repository-discovered destination enters a plan.
   * Deliberately separate from planning and applying: neither of those can
   * approve anything (ADR 0024, ZFT-004).
   */
  trackingOriginApprove: (providerId: string, origin: string) =>
    call<TrackingOriginRequest>("tracking_origin_approve", { providerId, origin }),
  trackingOriginRevoke: (providerId: string) =>
    call<void>("tracking_origin_revoke", { providerId }),
  /** Providers only — destinations come from the approvals above. */
  trackingPlanBuild: (providers: string[]) =>
    call<TrackingPlan>("tracking_plan_build", { providers }),
  trackingApply: (password: string | null) =>
    call<TrackingApplyReport>("tracking_apply", { password }),
  trackingStatus: (setupId: string) => call<TrackingStatus>("tracking_status", { setupId }),
  trackingList: () => call<TrackingStatus[]>("tracking_list"),
  trackingDiagnose: (setupId: string) =>
    call<TrackingDiagnosis[]>("tracking_diagnose", { setupId }),
  trackingUndo: (setupId: string) => call<TrackingUndoReport>("tracking_undo", { setupId }),
  trackingForegroundStart: () => call<void>("tracking_foreground_start"),
  trackingForegroundActive: () => call<ForegroundStatus>("tracking_foreground_active"),
  trackingForegroundStop: () => call<void>("tracking_foreground_stop"),
  trackingResumeAttribution: (password: string) =>
    call<void>("tracking_resume_attribution", { password }),

  // --- Projects-first live activity (ADR 0029) -------------------------

  /** What selecting this folder would do, plus the digest that binds a
   *  confirmation to it. Read-only with respect to the user's files. */
  projectFolderPreview: (project: string, folder: string) =>
    call<FolderLinkPreview>("project_folder_preview", { project, folder }),
  /** Apply the previewed configuration. `digest` must be the one the user was
   *  shown; a mismatch is refused rather than reconciled. */
  projectFolderLink: (
    project: string,
    folder: string,
    digest: string,
    password: string | null,
  ) => call<LinkOutcome>("project_folder_link", { project, folder, digest, password }),
  /** Configuration and health. Resolves present-tense health, so this is for
   *  page open, manual refresh and focus — not for the 5s timer. */
  projectTrackingOverview: (project: string) =>
    call<ProjectOverview>("project_tracking_overview", { project }),
  /** The live snapshot. Lock-free-ish by design: the backend reads it without
   *  touching the inactivity clock, so polling cannot defeat auto-lock. */
  projectActivity: (
    project: string,
    range: string,
    filter: ProjectActivityFilter = {},
    limit?: number,
  ) => call<ProjectActivitySnapshot>("project_activity", { project, range, filter, limit }),
  /** Re-run detection. Writes no project file and creates no route. */
  projectRescan: (project: string) => call<DetectedCredential[]>("project_rescan", { project }),
  projectSetTrackingEnabled: (project: string, enabled: boolean) =>
    call<void>("project_set_tracking_enabled", { project, enabled }),
  /** Forget the folder association. Undoing managed file changes is the
   *  separate `trackingUndo` call. */
  projectUnlinkFolder: (project: string) => call<boolean>("project_unlink_folder", { project }),
  projectResolveDetection: (id: string, status: DetectedStatus, credential: string | null) =>
    call<DetectedCredential>("project_resolve_detection", { id, status, credential }),
  projectUpdateDetection: (
    id: string,
    fields: { name?: string; provider?: string; environment?: string },
  ) =>
    call<DetectedCredential>("project_update_detection", {
      id,
      name: fields.name ?? null,
      provider: fields.provider ?? null,
      environment: fields.environment ?? null,
    }),
  /** Name an observed host the catalog does not know. Creates no route and
   *  approves no destination. */
  projectNameUnknownApi: (host: string, provider: string | null, apiName: string | null) =>
    call<void>("project_name_unknown_api", { host, provider, apiName }),
  projectRestoreTracking: () => call<ProjectRestoreEntry[]>("project_restore_tracking"),
};
