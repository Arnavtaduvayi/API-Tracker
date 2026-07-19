// Small pure helpers (unit-tested with vitest).

import type { DriftKind, Status } from "./types";

/** RFC 3339 timestamp -> short local display, or a placeholder. */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

/** RFC 3339 timestamp -> YYYY-MM-DD for date inputs. */
export function toDateInput(iso: string | null | undefined): string {
  if (!iso) return "";
  return iso.slice(0, 10);
}

/** Human label for a status code. */
export function statusLabel(status: Status): string {
  const labels: Record<Status, string> = {
    unknown: "unknown",
    active: "active",
    invalid: "invalid",
    expired: "expired",
    expiring_soon: "expiring soon",
    unused: "unused",
    stale: "stale",
    shared_across_projects: "shared across projects",
    possibly_exposed: "possibly exposed",
    manually_disabled: "manually disabled",
    revoked: "revoked",
  };
  return labels[status] ?? status;
}

/** Statuses that should render as warnings/errors in the UI. */
export function statusSeverity(status: Status): "ok" | "warn" | "bad" {
  switch (status) {
    case "active":
      return "ok";
    case "expired":
    case "invalid":
    case "possibly_exposed":
    case "revoked":
      return "bad";
    case "unknown":
      return "ok";
    default:
      return "warn";
  }
}

/** Alert severity -> ordinal rank (mirrors notify::severity_rank in core). */
export function severityRank(severity: string): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

/** Highest severity among alerts (empty input -> null). */
export function topSeverity(severities: string[]): string | null {
  let top: string | null = null;
  for (const s of severities) {
    if (top === null || severityRank(s) > severityRank(top)) top = s;
  }
  return top;
}

/** Empty string -> null (for optional date fields sent to the backend). */
export function emptyToNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

/** Format integer micro-USD as a dollar string. */
export function formatMicros(micros: number): string {
  return `$${(micros / 1_000_000).toFixed(2)}`;
}

/** Display severity for an .env drift finding (mirrors DriftKind::severity in core). */
export function driftSeverity(kind: DriftKind): "high" | "medium" | "low" | "info" {
  switch (kind) {
    case "production_value_in_dev_file":
    case "unmapped_secret":
      return "high";
    case "value_differs_from_vault":
    case "same_value_in_multiple_files":
      return "medium";
    case "missing_expected_variable":
      return "low";
    case "mapping_not_in_files":
      return "info";
  }
}

/**
 * Whether `url` is safe to place in an anchor `href` that opens externally.
 * Only `http:`, `https:`, and `mailto:` are allowed. A `javascript:`,
 * `data:`, `file:`, `vbscript:`, or otherwise unusual scheme — which a
 * user- or vault-supplied `docs_url` could carry (IPC-05) — is rejected so
 * it can never execute or read local files when clicked. Relative or
 * unparseable values are treated as unsafe (we only render absolute,
 * explicitly-safe external links).
 */
export function safeExternalUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  const trimmed = url.trim();
  if (trimmed === "") return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null; // relative or malformed: not a safe absolute external link
  }
  const scheme = parsed.protocol.toLowerCase();
  if (scheme === "http:" || scheme === "https:" || scheme === "mailto:") {
    return trimmed;
  }
  return null;
}
