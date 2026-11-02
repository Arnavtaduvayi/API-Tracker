// Test fixtures for the Tethra Mesh project, usage and spend-cap components
// (Increment 10). Imported by tests only. Every id, name and amount here is
// obviously fake.

import type {
  MeshCapDeviceRow,
  MeshCapMonthRow,
  MeshCapReport,
  MeshCapRow,
  MeshDeviceUsage,
  MeshProjectRow,
  MeshProjectUsage,
  MeshStatus,
  MeshUsageReport,
  MeshUsageTotals,
  Project,
} from "../types";

export const SELF_ID = "11".repeat(16);
export const DESKTOP_ID = "22".repeat(16);
export const SERVER_ID = "33".repeat(16);
export const OLD_ID = "44".repeat(16);
export const MESH_A = "aa".repeat(16);
export const MESH_B = "bb".repeat(16);
export const MESH_C = "cd".repeat(16);
export const CAP_ID = "c0".repeat(16);
export const LOCAL_ID = "local-project-1";

export const NOT_IN_MESH: MeshStatus = {
  initialized: false,
  node: { running: null, stopping: false, last_error: null, last_stop: null, external: null },
};

export function inMesh(): MeshStatus {
  return {
    initialized: true,
    mesh_id: "ab".repeat(16),
    mesh_id_short: "abababab",
    genesis_device: SELF_ID,
    device_id: SELF_ID,
    device_name: "test-laptop",
    state: "active",
    next_seq: 5,
    marker: "ok",
    marker_problem: null,
    self_forked: false,
    roster_size: 3,
    devices: [
      {
        device_id: SELF_ID,
        name: "test-laptop",
        is_self: true,
        member: true,
        active: true,
        removed: false,
        cutoff_seq: null,
        fork_seq: null,
      },
      {
        device_id: DESKTOP_ID,
        name: "test-desktop",
        is_self: false,
        member: true,
        active: true,
        removed: false,
        cutoff_seq: null,
        fork_seq: null,
      },
    ],
    vv: {},
    items_by_kind: {},
    rejected_items: 0,
    clock_skew: {},
    fork_evidence: 0,
    forked_devices: 0,
    regressions: 0,
    repairs_changed: 0,
    rollback_hold: null,
    node: { running: null, stopping: false, last_error: null, last_stop: null, external: null },
  };
}

export function projectRow(over: Partial<MeshProjectRow> = {}): MeshProjectRow {
  return {
    mesh_project_id: MESH_A,
    name: "fake-app",
    archived: false,
    merged_into: null,
    root: over.mesh_project_id ?? MESH_A,
    bound_local_project: null,
    bound_local_project_name: null,
    publishing_devices: [],
    ...over,
  };
}

export function localProject(over: Partial<Project> = {}): Project {
  return {
    id: LOCAL_ID,
    name: "fake-local",
    description: "",
    notes: "",
    environments: [],
    repo_paths: [],
    archived: false,
    password_locked: false,
    unlocked: true,
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
    credential_count: 0,
    ...over,
  };
}

export function totals(over: Partial<MeshUsageTotals> = {}): MeshUsageTotals {
  return {
    requests: 0,
    priced_requests: 0,
    unpriced_requests: 0,
    unextracted_requests: 0,
    input_tokens: 0,
    output_tokens: 0,
    cached_input_tokens: 0,
    estimated_cost_micros: 0,
    ...over,
  };
}

export function deviceUsage(over: Partial<MeshDeviceUsage> = {}): MeshDeviceUsage {
  return {
    device_id: SELF_ID,
    device_name: "test-laptop",
    is_self: true,
    as_of: null,
    stale: false,
    removed: false,
    totals: totals(),
    split_unknown_requests: 0,
    split_known_since: null,
    ...over,
  };
}

export function projectUsage(over: Partial<MeshProjectUsage> = {}): MeshProjectUsage {
  return {
    mesh_project_id: MESH_A,
    name: "fake-app",
    archived: false,
    merged: [],
    devices: [],
    no_data_from: [],
    total: totals(),
    total_label: "estimated, gateway-observed, across 0 device(s); 0 stale; 0 with no data",
    ...over,
  };
}

export const USAGE_NOTES = [
  "Estimated from gateway-observed traffic only; never summed with provider-reported cost.",
  "A device with no data is unknown, not zero.",
];

export function usageReport(over: Partial<MeshUsageReport> = {}): MeshUsageReport {
  return {
    period: "2026-11",
    projects: [],
    horizon_start: "2026-08-04",
    notes: USAGE_NOTES,
    publish_error: null,
    ...over,
  };
}

export function capDevice(over: Partial<MeshCapDeviceRow> = {}): MeshCapDeviceRow {
  return {
    device_id: SELF_ID,
    device_name: "test-laptop",
    is_self: true,
    is_owner: true,
    removed: false,
    as_of: null,
    stale: false,
    minted: 50_000_000,
    is_override: false,
    received: 0,
    sent: 25_000_000,
    burned: 0,
    clamped: 0,
    used: 5_000_000,
    avail: 20_000_000,
    ...over,
  };
}

export function capMonth(over: Partial<MeshCapMonthRow> = {}): MeshCapMonthRow {
  return {
    month: "2026-11",
    target: 50_000_000,
    effective_target: 50_000_000,
    owner_minted: 50_000_000,
    overrides: 0,
    burned: 0,
    total_used: 12_000_000,
    supply: 50_000_000,
    pending_decrease: 0,
    used_pct: 24,
    devices: [capDevice()],
    local_spend: 5_000_000,
    local_avail: 20_000_000,
    escrow_open: 0,
    total_label: "estimated, gateway-observed, across 2 device(s); 1 stale",
    ...over,
  };
}

export function capRow(over: Partial<MeshCapRow> = {}): MeshCapRow {
  return {
    enforced_here: false,
    cap_id: CAP_ID,
    mesh_project_id: MESH_A,
    project_name: "fake-app",
    owner_device: SELF_ID,
    owner_name: "test-laptop",
    owned_here: true,
    bound_here: true,
    frozen: false,
    superseded_by: null,
    months: [capMonth()],
    ...over,
  };
}

export const CAP_NOTES = [
  "A spend cap is a self-limit on traffic through Tethra's gateway, not a security boundary, and never a provider budget.",
];

export function capReport(over: Partial<MeshCapReport> = {}): MeshCapReport {
  return {
    month: "2026-11",
    caps: [],
    gate: null,
    gate_fresh: false,
    notes: CAP_NOTES,
    reconcile_error: null,
    ...over,
  };
}
