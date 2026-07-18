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
