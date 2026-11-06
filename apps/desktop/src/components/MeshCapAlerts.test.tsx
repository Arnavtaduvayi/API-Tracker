// Spend-cap alerts (Tethra Mesh, Increment 07) in the existing Alerts view
// (Increment 10's check). The view renders core's title, detail, evidence and
// recommended action as is and never branches on the alert kind, so a
// `mesh_spend_cap` alert reads like any other: its severity, title and the
// honesty wording core writes into the detail. The text below mirrors
// crates/core/src/mesh/caps/alerts.rs; values are fake.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { Alert } from "../types";

vi.mock("@tauri-apps/plugin-notification", () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(false),
  requestPermission: vi.fn().mockResolvedValue("denied"),
  sendNotification: vi.fn(),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      alertsList: vi.fn(),
      monitorStatus: vi.fn(),
      monitorRunFull: vi.fn(),
      alertAcknowledge: vi.fn(),
      alertResolve: vi.fn(),
    },
  };
});

import { api } from "../api";
import { AlertsView } from "./AlertsView";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

function capAlert(threshold: 80 | 100): Alert {
  const pct = threshold === 100 ? 104 : 85;
  return {
    id: `mesh-cap-${threshold}`,
    // Not in the TS `AlertKind` union (which predates many core kinds); the
    // view does not read `kind`.
    kind: "mesh_spend_cap",
    severity: threshold === 100 ? "high" : "medium",
    title: `Spend cap for fake-app is at ${pct}% for 2026-11`,
    detail:
      "Estimated gateway-observed spend across your devices is $42.50 of a $50.00 cap this " +
      "month (2 device(s), 1 not heard from in 24 hours). It is this device's view as of the " +
      "last exchange with each device, priced by each device's own pricing table; a device " +
      "not heard from may have spent more. This device's gateway does not enforce it (alerts " +
      "only); switch that on with `tethra mesh cap enforce`.",
    evidence:
      `cap=${"c0".repeat(16)} month=2026-11 used_micros=42500000 cap_micros=50000000 ` +
      `threshold=${threshold}% devices=2 stale=1`,
    confidence: "medium",
    recommended_action:
      "Check the spend with `tethra mesh cap show` and `tethra mesh usage`; raise the cap " +
      "with `tethra mesh cap raise` if the spend is expected.",
    project_id: null,
    credential_id: null,
    created_at: "2026-11-02T00:00:00Z",
    observed_at: "2026-11-02T00:00:00Z",
    acknowledged_at: null,
    resolved_at: null,
  } as unknown as Alert;
}

beforeEach(() => {
  mockApi.monitorStatus.mockResolvedValue({
    last_run_at: null,
    last_success_at: null,
    last_failure_at: null,
    last_error: null,
    last_detail: null,
  });
});

describe("AlertsView with spend-cap alerts", () => {
  it("renders the 80% and 100% alerts readably, with core's honesty wording", async () => {
    mockApi.alertsList.mockResolvedValue([capAlert(100), capAlert(80)]);
    render(<AlertsView />);

    const high = (await screen.findByText("Spend cap for fake-app is at 104% for 2026-11"))
      .parentElement?.parentElement as HTMLElement;
    expect(within(high).getByText("high")).toHaveClass("badge", "bad");
    expect(high).toHaveTextContent(/Estimated gateway-observed spend across your devices/);
    expect(high).toHaveTextContent(/a device not heard from may have spent more/);
    expect(high).toHaveTextContent(/Evidence: cap=c0c0/);
    expect(high).toHaveTextContent(/Recommended: Check the spend/);
    expect(within(high).getByRole("button", { name: "acknowledge" })).toBeInTheDocument();

    const medium = (await screen.findByText("Spend cap for fake-app is at 85% for 2026-11"))
      .parentElement?.parentElement as HTMLElement;
    expect(within(medium).getByText("medium")).toHaveClass("badge", "warn");

    // Never mixed up with a budget or rendered as a raw kind or object.
    expect(document.body.textContent).not.toContain("mesh_spend_cap");
    expect(document.body.textContent).not.toContain("[object Object]");
    expect(document.body.textContent).not.toMatch(/over budget/i);
  });
});
