// TypeScript mirrors of the core Rust models (serialized via serde).
// Secret values never appear in these types: credentials carry only a
// masked value. The single exception is the string returned by the
// explicit `credential_reveal` command.

export type Environment = "development" | "test" | "staging" | "production";

export const ENVIRONMENTS: Environment[] = ["development", "test", "staging", "production"];

export type Status =
  | "unknown"
  | "active"
  | "invalid"
  | "expired"
  | "expiring_soon"
  | "unused"
  | "stale"
  | "shared_across_projects"
  | "possibly_exposed"
  | "manually_disabled"
  | "revoked";

export interface Finding {
  status: Status;
  reason: string;
  source: string;
  observed_at: string;
  confidence: "high" | "medium" | "low";
  recommended_action: string;
}

export interface StatusReport {
  primary: Status;
  findings: Finding[];
}

export interface Project {
  id: string;
  name: string;
  description: string;
  notes: string;
  environments: Environment[];
  repo_paths: string[];
  archived: boolean;
  password_locked: boolean;
  unlocked: boolean;
  created_at: string;
  updated_at: string;
  credential_count: number;
}

export interface Credential {
  id: string;
  project_id: string;
  project_name: string;
  provider: string;
  name: string;
  environment: Environment;
  credential_type: string;
  masked_value: string;
  is_reference: boolean;
  linked_credential_id: string | null;
  linked_target: string | null;
  created_at: string;
  updated_at: string;
  key_created_at: string | null;
  expires_at: string | null;
  /** True when expires_at is present but unparseable (shown as invalid). */
  expires_at_invalid: boolean;
  /** Expiration reported by the provider itself (recorded during validation). */
  provider_expires_at: string | null;
  /** True when provider_expires_at is present but unparseable (OBS-004). */
  provider_expires_at_invalid: boolean;
  last_validated_at: string | null;
  last_used_at: string | null;
  docs_url: string;
  notes: string;
  manually_disabled: boolean;
  revoked: boolean;
  marked_invalid: boolean;
  possibly_exposed: boolean;
  exposure_note: string;
  status: StatusReport;
}

export interface ReuseWarning {
  kind:
    | "duplicate_in_project"
    | "across_projects"
    | "production_shared_with_development"
    | "intentional_reference";
  other: {
    credential_id: string;
    credential_name: string;
    project_id: string;
    project_name: string;
    environment: Environment;
    is_reference: boolean;
  };
  message: string;
  recommendation: string;
}

export interface VaultSettings {
  auto_lock_minutes: number;
  expiring_soon_days: number;
  unused_days: number;
  stale_days: number;
  clipboard_clear_seconds: number;
  provider_stale_days: number;
  rollback_window_days: number;
  /** Hours between scheduled documentation checks. 0 = manual only. */
  docwatch_interval_hours: number;
  /** Minutes between background monitor runs in the desktop app. 0 = off. */
  monitor_interval_minutes: number;
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  data_dir: string;
}

export interface ProviderInfo {
  id: string;
  name: string;
  docs_url: string;
  manage_url: string;
  common_env_vars: string[];
}

export type SupportLevel =
  "implemented" | "supported_not_implemented" | "unsupported" | "manual_only";

export type Attribution =
  "not_applicable" | "account_level" | "provider_project_level" | "exact_credential";

export interface CapabilityEntry {
  support: SupportLevel;
  requires_admin_credential: boolean;
  attribution: Attribution;
  note: string;
}

export interface Capabilities {
  validate_credential: CapabilityEntry;
  fetch_metadata: CapabilityEntry;
  fetch_usage: CapabilityEntry;
  read_permissions: CapabilityEntry;
  change_permissions: CapabilityEntry;
  create_credential: CapabilityEntry;
  disable_credential: CapabilityEntry;
  revoke_credential: CapabilityEntry;
  rotate_credential: CapabilityEntry;
  fetch_pricing: CapabilityEntry;
}

export interface DetectionPattern {
  name: string;
  regex: string;
  confidence: "low" | "medium" | "high";
}

export interface ProviderManifest {
  id: string;
  name: string;
  description: string;
  website: string;
  api_docs_url: string;
  auth_docs_url: string;
  manage_url: string;
  env_vars: string[];
  credential_types: string[];
  expiration: string;
  /** Official changelog / release-notes page ("" when none is declared). */
  changelog_url: string;
  /** Official pricing documentation ("" when none is declared). */
  pricing_url: string;
  /** Official permission/scope documentation ("" when none is declared). */
  permissions_docs_url: string;
  /** Official console/login page ("" when none is declared). */
  login_url: string;
  /** Official billing portal page ("" when none is declared). */
  billing_url: string;
  watch_docs: string[];
  detection: DetectionPattern[];
  capabilities: Capabilities;
}

export interface VaultMatch {
  credential_id: string;
  credential_name: string;
  project_id: string;
  project_name: string;
  other_projects: string[];
}

export interface Finding {
  rule: string;
  provider: string | null;
  confidence: "low" | "medium" | "high";
  file: string;
  line: number;
  redacted: string;
  reason: string;
  recommended: string;
  suppression_key: string;
  vault_match: VaultMatch | null;
}

export interface RepoReverifyReport {
  repo_path: string;
  findings: number;
  /** Clean means zero findings AND complete coverage. */
  clean: boolean;
  resolved_alerts: number;
  /** False when the history scan hit a time/size limit; alerts stay open. */
  coverage_complete: boolean;
  coverage_warnings: string[];
}

/** Findings plus an honest statement of scan coverage. */
export interface ScanPathReport {
  findings: Finding[];
  coverage_complete: boolean;
  coverage_warnings: string[];
}

export type HookState =
  "absent" | "installed" | "foreign" | "chained_into_foreign" | "overridden" | "unsupported";

export interface HookStatus {
  repo: string;
  /** The hook file git will actually use (honours core.hooksPath). */
  hook_path: string;
  /** Raw core.hooksPath value when configured. */
  hooks_path_override: string | null;
  state: HookState;
  /** True only when git will genuinely execute the scan on commit. */
  active: boolean;
  /** Honest explanation of the state. */
  detail: string;
}

export type AlertKind =
  | "expiring_soon"
  | "expired"
  | "stale"
  | "unused"
  | "reused_across_projects"
  | "production_in_development"
  | "possible_exposure"
  | "provider_sync_failed"
  | "documentation_changed";

export interface Alert {
  id: string;
  kind: AlertKind;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  detail: string;
  evidence: string;
  confidence: string;
  recommended_action: string;
  project_id: string | null;
  credential_id: string | null;
  created_at: string;
  observed_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
}

export interface MonitorSummary {
  checked: number;
  alerts_created: number;
  alerts_resolved: number;
  open_alerts: number;
}

/** Monitor run including the best-effort network phases (CLI parity). */
export interface MonitorFullReport {
  summary: MonitorSummary;
  /** Documentation watches that were due and got checked. */
  doc_checks: number;
  /** Webhook notifications delivered. */
  delivered: number;
  /** Severities of alerts created by this run (severities only). */
  new_alert_severities: string[];
}

/** When monitoring last ran and how it went (no run performed). */
export interface MonitorStatus {
  last_run_at: string | null;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error: string;
  last_detail: string;
}

/** A stored scan suppression (no secret material). */
export interface Suppression {
  suppression_key: string;
  rule: string;
  path: string;
  reason: string;
  created_at: string;
}

/** A recorded injection session from `run` (names and PIDs only). */
export interface ProcessSession {
  id: string;
  project_id: string;
  started_at: string;
  ended_at: string | null;
  command: string;
  injected_vars: string;
  exit_code: number | null;
  pid: number | null;
  grant_id: string | null;
  /** Launch-time process identity; null means termination will be refused. */
  proc_identity: string | null;
}

/**
 * Truthful result of a termination request. The backend re-verifies the
 * launch identity before signalling and refuses when the PID can no longer
 * be confirmed as the launched process.
 */
export type TerminationOutcome =
  | { kind: "refused"; reason: string }
  | { kind: "already_exited" }
  | { kind: "signalled" }
  | { kind: "signal_failed" };

export interface SessionKillResult {
  session_id: string;
  pid: number;
  /** True only when the identity matched and the signal was accepted. */
  signalled: boolean;
  outcome: TerminationOutcome;
  outcome_text: string;
}

/**
 * A user-configured webhook channel. The URL may embed a token, so only the
 * masked form ever reaches the frontend; delivery payloads carry alert
 * metadata only, never secret values.
 */
export interface NotificationChannel {
  id: string;
  name: string;
  kind: string;
  url_masked: string;
  min_severity: "info" | "low" | "medium" | "high" | "critical";
  enabled: boolean;
  created_at: string;
  last_delivery_at: string | null;
  last_error: string;
}

/** One documentation-check history entry (validators/outcomes only). */
export interface DocHistoryEntry {
  url: string;
  provider: string;
  at: string;
  outcome: string;
  detail: string;
}

export interface DocWatch {
  id: string;
  provider: string;
  url: string;
  etag: string | null;
  last_modified: string | null;
  content_hash: string | null;
  last_checked_at: string | null;
  last_changed_at: string | null;
  last_status: string;
  created_at: string;
}

export interface ValidationResult {
  valid: boolean;
  status: number;
  detail: string;
}

export interface FetchedMetadata {
  fields: [string, string][];
  source: string;
}

export interface NormalizedPermissions {
  read: string[];
  write: string[];
  admin: string[];
  sensitive: string[];
  summary: string;
}

export interface StoredPermissions {
  credential_id: string;
  raw_scopes: string[];
  normalized: NormalizedPermissions;
  source: string;
  precision: string;
  confidence: string;
  synced_at: string;
}

export interface ProviderConnection {
  provider: string;
  connected: boolean;
  admin_key_masked: string | null;
  admin_credential_id: string | null;
  org_label: string | null;
  connected_at: string | null;
  last_synced_at: string | null;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error: string;
  last_status: string;
  detail: string;
  /** Provider-reported account identity (official endpoints only). */
  account_id: string | null;
  account_email: string | null;
  account_name: string | null;
  account_plan: string | null;
  account_source: string | null;
  account_synced_at: string | null;
  stale: boolean;
}

/** Provider-reported account identity (official endpoints only). */
export interface AccountInfo {
  account_id: string | null;
  email: string | null;
  name: string | null;
  plan: string | null;
  source: string;
}

export interface SyncReport {
  provider: string;
  usage_rows: number;
  cost_rows: number;
  window_start: string;
  window_end: string;
  notes: string[];
}

export interface ProviderKeyOverview {
  provider: string;
  api_key_id: string;
  name: string;
  redacted_value: string;
  provider_project_id: string | null;
  provider_project_name: string | null;
  linked_credential_id: string | null;
  linked_credential: string | null;
  link_source: string | null;
  usage_rows: number;
  suggested_credential_id: string | null;
  suggested_credential: string | null;
  note: string;
}

export interface ProviderProjectOverview {
  provider_project_id: string;
  name: string;
  reported_cost_micros_month: number;
  has_linked_usage: boolean;
}

export interface UsageSnapshot {
  id: string;
  credential_id: string | null;
  project_id: string | null;
  provider: string;
  model: string | null;
  window_start: string;
  window_end: string;
  request_count: number | null;
  input_tokens: number | null;
  output_tokens: number | null;
  total_tokens: number | null;
  reported_cost_micros: number | null;
  estimated_cost_micros: number | null;
  currency: string;
  source: string;
  attribution: string;
  collected_at: string;
  provider_account_id: string | null;
  provider_project_id: string | null;
  provider_api_key_id: string | null;
  line_item: string | null;
  /** Non-token quantity, verbatim from the provider (with `unit`). */
  quantity: number | null;
  /** Unit for `quantity` (e.g. "requests", "events") — rendered verbatim. */
  unit: string | null;
}

export interface UsageTotals {
  snapshots: number;
  request_count: number;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  reported_cost_micros: number;
  estimated_cost_micros: number;
  has_inexact_attribution: boolean;
  coarsest_attribution: string | null;
  reported_currencies: string[];
  has_non_usd_reported: boolean;
  last_collected_at: string | null;
}

export interface BudgetReport {
  scope: string;
  budget_micros: number | null;
  period_start: string;
  reported_cost_micros: number;
  estimated_cost_micros: number;
  used_micros: number;
  used_is_estimated: boolean;
  cost_source: string;
  remaining_micros: number | null;
  projected_period_end_micros: number;
  over_budget: boolean;
  attribution_note: string | null;
}

export interface ActivityEvent {
  id: number;
  at: string;
  source: string;
  kind: string;
  credential_id: string | null;
  project_id: string | null;
  detail: string;
  measurements: string;
}

export interface BackupInfo {
  path: string;
  vault_id: string;
  created_at: string;
  schema_version: number;
  project_count: number;
  credential_count: number;
}

// --- .env governance ---

export type EnvFileClass = "values" | "template";

export type GitStatus = "tracked" | "ignored" | "untracked" | "not_in_repo";

export interface EnvProblem {
  line: number;
  kind: "malformed" | "duplicate_key";
  detail: string;
}

export interface EnvFileInfo {
  path: string;
  rel_path: string;
  class: EnvFileClass;
  environment: Environment | null;
  git_status: GitStatus;
  in_git_history: boolean;
  entry_count: number;
  problems: EnvProblem[];
}

export interface VarPreview {
  key: string;
  line: number;
  masked: string;
  provider: string | null;
  looks_secret: boolean;
  is_placeholder: boolean;
  vault_credential: string | null;
  mapped_credential: string | null;
}

export type DriftKind =
  | "value_differs_from_vault"
  | "missing_expected_variable"
  | "unmapped_secret"
  | "mapping_not_in_files"
  | "production_value_in_dev_file"
  | "same_value_in_multiple_files";

export interface DriftFinding {
  kind: DriftKind;
  file: string;
  key: string;
  credential: string | null;
  detail: string;
  recommendation: string;
}

export interface EnvImportOutcome {
  key: string;
  action: string;
  credential: string | null;
  note: string;
}

export interface EnvExampleProposal {
  proposed: string;
  diff: string;
  example_path: string;
  changed: boolean;
}

export interface EnvExportReport {
  export_id: string;
  path: string;
  var_names: string[];
  git_status: GitStatus;
  expires_at: string | null;
  warnings: string[];
}

export interface EnvExport {
  id: string;
  project_id: string;
  path: string;
  var_names: string;
  created_at: string;
  expires_at: string | null;
  cleaned_at: string | null;
}

export type CleanupOutcome =
  "removed" | "already_gone" | "modified_since_export" | "not_yet_expired";

export interface CleanupResult {
  export_id: string;
  path: string;
  outcome: CleanupOutcome;
}

// --- Credential version history (masked values only) ---

export interface CredentialVersionInfo {
  version: number;
  masked_value: string;
  created_at: string;
  reason: string;
  current: boolean;
}

// --- Destinations ---

export type DestSupport =
  "implemented" | "supported_not_implemented" | "unsupported" | "platform_unavailable";

export interface DestCapabilities {
  read: DestSupport;
  write: DestSupport;
  delete: DestSupport;
  versioning: DestSupport;
  rollback: DestSupport;
  validation: DestSupport;
}

export interface DestinationKindInfo {
  kind: string;
  name: string;
  description: string;
  auth: string;
  platforms: string;
  status: string;
  capabilities: DestCapabilities;
  /** How a write is verified: value read-back or existence only. */
  verify_method: string;
  /** Plan/tier the destination requires, if any. */
  required_plan: string;
  /** Possible charges from using this destination. */
  charges: string;
  /** Automated-test coverage status (fixtures vs live). */
  testing: string;
  config_help: string;
}

export interface Destination {
  id: string;
  kind: string;
  name: string;
  config: Record<string, unknown> | null;
  auth_masked: string | null;
  created_at: string;
  updated_at: string;
  last_verified_at: string | null;
  last_error: string;
}

export interface Attachment {
  credential_id: string;
  credential_name: string;
  project_name: string;
  destination_id: string;
  destination_name: string;
  destination_kind: string;
  secret_name: string;
  environment: string;
  last_synced_version: number | null;
  last_synced_at: string | null;
  last_verified_at: string | null;
  drift: string;
}

/**
 * An attachment plus whether THIS drift check actually reached it. When
 * `checked` is false the drift/verified fields are prior state, not a fresh
 * result — the UI must not present them as newly verified (DEST-03).
 * Fields are flattened, so all Attachment fields are present here too.
 */
export interface DriftCheckOutcome extends Attachment {
  checked: boolean;
  check_error: string | null;
}

// --- Synchronization plans (masked versions only, never values) ---

export interface SyncStep {
  destination_id: string;
  destination_name: string;
  destination_kind: string;
  secret_name: string;
  environment: string;
  action: string;
  status: string;
  detail: string;
  validation: string;
  rollback_available: boolean;
  executed_at: string | null;
  verified_at: string | null;
  rolled_back_at: string | null;
}

export interface SyncPlan {
  id: string;
  credential_id: string;
  credential_name: string;
  project_name: string;
  from_version: number | null;
  from_masked: string | null;
  to_version: number;
  to_masked: string;
  created_at: string;
  status: string;
  note: string;
  affected_projects: string[];
  manual_steps: string[];
  steps: SyncStep[];
}

// --- Credential rotation (state, ids, and versions only — never values) ---

export type RotationState =
  | "planned"
  | "approved"
  | "creating_replacement"
  | "awaiting_manual_key"
  | "replacement_stored"
  | "updating_destinations"
  | "destinations_verified"
  | "grace_period"
  | "old_disabled"
  | "completed"
  | "failed"
  | "rolling_back"
  | "rolled_back"
  | "manual_required";

export type RotationMode = "api_create" | "manual_create";

/** A rotation with display context (core's RotationView, serde-flattened). */
export interface RotationView {
  id: string;
  credential_id: string;
  provider: string;
  state: RotationState;
  mode: RotationMode;
  note: string;
  created_at: string;
  updated_at: string;
  approved_at: string | null;
  old_version: number | null;
  new_version: number | null;
  sync_plan_id: string | null;
  grace_minutes: number;
  grace_ends_at: string | null;
  old_provider_key_id: string | null;
  new_provider_key_id: string | null;
  provider_project_id: string | null;
  new_value_validated: boolean;
  old_disabled_at: string | null;
  old_revoked_at: string | null;
  last_error: string;
  manual_instructions: string;
  credential_name: string;
  project_name: string;
  waiting_on: string | null;
}

export interface RotationEvent {
  at: string;
  from_state: string;
  to_state: string;
  detail: string;
}

export interface RotationSchedule {
  credential_id: string;
  interval_days: number;
  next_due_at: string;
  enabled: boolean;
  paused_reason: string;
  created_at: string;
  last_completed_rotation_id: string | null;
}

// --- Temporary LOCAL access grants ---

export type AccessGrantStatus = "active" | "expired" | "used_up" | "revoked";

export interface AccessGrant {
  id: string;
  project_id: string;
  label: string;
  /** Credential ids the grant is limited to; empty = the project's mappings. */
  credential_ids: string[];
  expires_at: string;
  /** 0 = unlimited launches within the window. */
  max_launches: number;
  launches_used: number;
  max_duration_secs: number | null;
  budget_warn_micros: number | null;
  created_at: string;
  revoked_at: string | null;
  status: AccessGrantStatus;
}

export interface RunningSession {
  session_id: string;
  pid: number;
}

export interface GrantEndResult {
  grant: AccessGrant;
  running: RunningSession[];
}

// --- Credential lifecycle timeline (metadata only) ---

export interface TimelineEvent {
  at: string;
  kind: string;
  detail: string;
  source: string;
}

// --- Provider-side keys, permission preview, test keys ---

export interface ProviderKeyListing {
  id: string;
  name: string;
  status: string;
  created_at: string | null;
  redacted_hint: string;
}

export interface FetchedPermissions {
  raw_scopes: string[];
  precision: string;
  confidence: string;
  source: string;
}

export interface PermissionsPreview {
  stored: StoredPermissions | null;
  /** Fresh from the provider — NOT stored until an explicit sync. */
  fetched: FetchedPermissions;
  normalized: NormalizedPermissions;
}

export interface TestKeyResult {
  credential: Credential;
  /** Honest enforcement notes from core, rendered verbatim. */
  notes: string[];
}

export interface PricingRecord {
  provider: string;
  model: string;
  unit: "tokens" | "requests" | "credits";
  input_price_per_m_micros: number | null;
  cached_input_price_per_m_micros: number | null;
  output_price_per_m_micros: number | null;
  batch_input_price_per_m_micros: number | null;
  batch_output_price_per_m_micros: number | null;
  per_request_micros: number | null;
  currency: string;
  source: string;
  effective_from: string;
  last_verified: string;
  origin: "bundled" | "imported" | "override";
  version: number;
  note: string;
  stale: boolean;
}

export interface PricingImportOutcome {
  added: number;
  replaced: number;
}

export interface TemplateEnvVar {
  name: string;
  provider: string | null;
  secret: boolean;
  description: string;
}

export interface Template {
  id: string;
  name: string;
  description: string;
  providers: string[];
  environments: string[];
  docs: string[];
  destinations: string[];
  credential_separation: string;
  permission_guidance: string;
  rotation_guidance: string;
  env: TemplateEnvVar[];
}

export interface TemplateApplyOutcome {
  project: Project;
  template: Template;
  example_path: string | null;
  /** Names only — never values. */
  example_content: string;
  next_steps: string[];
}

export interface StackSignal {
  file: string;
  evidence: string;
  template_id: string | null;
  provider: string | null;
  confidence: "low" | "medium" | "high";
}

export interface StackSuggestion {
  template_id: string;
  confidence: "low" | "medium" | "high";
  evidence: string[];
  prior_decision: "confirmed" | "dismissed" | null;
}

export interface DetectionReport {
  repo_path: string;
  signals: StackSignal[];
  suggestions: StackSuggestion[];
}

export interface StackPreference {
  repo_path: string;
  template_id: string;
  decision: string;
  decided_at: string;
}

export interface ApiError {
  code: string;
  message: string;
}

// --- Runtime API observability (metadata only) ---

export interface ObservedService {
  id: string;
  host: string;
  provider_id: string | null;
  source: string;
  classification: string;
  is_internal: boolean;
  user_provider: string | null;
  user_api_name: string | null;
  user_notes: string | null;
  confirmed: boolean;
  first_seen_at: string;
  last_seen_at: string;
}

export interface ObservedEndpoint {
  id: string;
  service_id: string;
  method: string;
  path_template: string;
  template_confidence: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface RuntimeEvent {
  at: string;
  host: string;
  method: string;
  path_template: string;
  status_code: number | null;
  outcome: string;
  latency_ms: number | null;
  request_bytes: number | null;
  response_bytes: number | null;
  protocol: string;
  observation_source: string;
  attribution_confidence: string | null;
}

export interface ObservationSession {
  id: string;
  project_id: string;
  mode: string;
  source: string;
  status: string;
  interrupt_reason: string | null;
  command: string;
  credential_names: string;
  runtime_detected: string | null;
  trust_level: string | null;
  partial_coverage: boolean;
  proxy_port: number | null;
  pid: number | null;
  started_at: string;
  ended_at: string | null;
  exit_code: number | null;
  request_count: number;
  error_count: number;
}

export interface CredentialAttribution {
  session_id: string;
  credential_id: string;
  service_id: string;
  host: string;
  request_count: number;
  confidence: string;
  evidence: string;
  credential_version: number | null;
  used_current_version: boolean | null;
}

export interface CompatibilityResult {
  session_id: string;
  check: string;
  status: string;
  detail: string;
}

export interface ObserveMetrics {
  total: number;
  success: number;
  c2xx: number;
  c3xx: number;
  c4xx: number;
  c5xx: number;
  auth_errors: number;
  forbidden: number;
  rate_limited: number;
  server_errors: number;
  transport_errors: number;
  tls_errors: number;
  errors: number;
  error_rate: number;
  request_bytes: number;
  response_bytes: number;
  p50_ms: number | null;
  p95_ms: number | null;
  p99_ms: number | null;
  latency_approximate: boolean;
}

export interface ServiceOverview extends ObservedService {
  metrics: ObserveMetrics;
}

export interface ObserveCertStatus {
  present: boolean;
  fingerprint_sha256: string | null;
  serial: string | null;
  created_at: string | null;
  not_after: string | null;
  system_trust: string;
  system_trust_at: string | null;
}

export interface ObservabilitySettings {
  default_mode: string;
  event_retention_days: number;
  aggregate_retention_days: number;
}

export interface DiagnosticCheck {
  name: string;
  status: string;
  detail: string;
}
