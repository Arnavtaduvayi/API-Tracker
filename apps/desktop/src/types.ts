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

export type HookState = "absent" | "installed" | "foreign" | "chained_into_foreign";

export interface HookStatus {
  repo: string;
  hook_path: string;
  state: HookState;
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
  admin_credential_id: string | null;
  last_synced_at: string | null;
  last_status: string;
  detail: string;
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
}

export interface BudgetReport {
  scope: string;
  budget_micros: number | null;
  period_start: string;
  reported_cost_micros: number;
  estimated_cost_micros: number;
  used_micros: number;
  used_is_estimated: boolean;
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

export interface ApiError {
  code: string;
  message: string;
}
