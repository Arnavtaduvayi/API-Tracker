// Small pure helpers (unit-tested with vitest).

import type { Status } from "./types";

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

/** Empty string -> null (for optional date fields sent to the backend). */
export function emptyToNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

/** Format integer micro-USD as a dollar string. */
export function formatMicros(micros: number): string {
  return `$${(micros / 1_000_000).toFixed(2)}`;
}
