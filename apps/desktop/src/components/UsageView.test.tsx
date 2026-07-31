// Monthly totals must not present a fold over unknown records as a
// measurement (NEW-37). `UsageTotals` sums every Option with
// `unwrap_or(0)` and keeps no residual count, so a month of records that
// carried no tokens summed to a confident "0" beside a real request count.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { Project, ProviderConnection, UsageSnapshot, UsageTotals } from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      projectList: vi.fn(),
      credentialList: vi.fn(),
      budgetCostSourceGet: vi.fn(),
      providerConnectionStatus: vi.fn(),
      usageReport: vi.fn(),
      budgetReport: vi.fn(),
      usageRecords: vi.fn(),
      activityList: vi.fn(),
    },
  };
});

import { api } from "../api";
import { UsageView } from "./UsageView";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

function project(): Project {
  return {
    id: "p1",
    name: "web",
    description: "",
    notes: "",
    environments: ["production"],
    repo_paths: [],
    archived: false,
    password_locked: false,
    unlocked: true,
    created_at: "2026-07-01T00:00:00Z",
    updated_at: "2026-07-01T00:00:00Z",
    credential_count: 1,
  };
}

function totals(over: Partial<UsageTotals> = {}): UsageTotals {
  return {
    snapshots: 0,
    request_count: 0,
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    reported_cost_micros: 0,
    estimated_cost_micros: 0,
    has_inexact_attribution: false,
    coarsest_attribution: null,
    reported_currencies: ["USD"],
    has_non_usd_reported: false,
    last_collected_at: null,
    ...over,
  };
}

function snapshot(over: Partial<UsageSnapshot> = {}): UsageSnapshot {
  return {
    id: "u1",
    credential_id: null,
    project_id: "p1",
    provider: "openai",
    model: "gpt-4o-mini",
    window_start: "2026-07-01T00:00:00Z",
    window_end: "2026-07-02T00:00:00Z",
    request_count: 1,
    input_tokens: null,
    output_tokens: null,
    total_tokens: null,
    reported_cost_micros: null,
    estimated_cost_micros: null,
    currency: "USD",
    source: "provider",
    attribution: "exact_credential",
    collected_at: "2026-07-02T00:00:00Z",
    provider_account_id: null,
    provider_project_id: null,
    provider_api_key_id: null,
    line_item: null,
    quantity: null,
    unit: null,
    ...over,
  };
}

function connection(over: Partial<ProviderConnection> = {}): ProviderConnection {
  return {
    provider: "openai",
    connected: true,
    admin_key_masked: "sk-…zz",
    admin_credential_id: null,
    org_label: null,
    connected_at: null,
    last_synced_at: null,
    last_success_at: "2026-07-01T00:00:00Z",
    last_failure_at: null,
    last_error: "",
    last_status: "ok",
    detail: "",
    account_id: null,
    account_email: null,
    account_name: null,
    account_plan: null,
    account_source: null,
    account_synced_at: null,
    stale: false,
    ...over,
  };
}

/** Render with one project selected and the given totals + backing records. */
async function renderUsage(t: UsageTotals, rows: UsageSnapshot[], conns: ProviderConnection[]) {
  mockApi.projectList.mockResolvedValue([project()]);
  mockApi.credentialList.mockResolvedValue([]);
  mockApi.budgetCostSourceGet.mockResolvedValue("best_available");
  mockApi.providerConnectionStatus.mockImplementation((p: string) =>
    Promise.resolve(conns.find((c) => c.provider === p) ?? connection({ connected: false })),
  );
  mockApi.usageReport.mockResolvedValue(t);
  mockApi.usageRecords.mockResolvedValue(rows);
  mockApi.activityList.mockResolvedValue([]);
  mockApi.budgetReport.mockResolvedValue({
    scope: "project",
    budget_micros: null,
    period_start: "2026-07-01T00:00:00Z",
    reported_cost_micros: t.reported_cost_micros,
    estimated_cost_micros: t.estimated_cost_micros,
    used_micros: t.estimated_cost_micros,
    used_is_estimated: true,
    cost_source: "best_available",
    remaining_micros: null,
    projected_period_end_micros: t.estimated_cost_micros,
    over_budget: false,
    attribution_note: null,
  });
  render(<UsageView />);
  await screen.findByRole("heading", { name: "This month" });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("UsageView monthly totals (NEW-37)", () => {
  it("does not render 0 tokens for a month whose records carried none", async () => {
    await renderUsage(
      totals({ snapshots: 2, request_count: 30 }),
      [snapshot({ id: "a" }), snapshot({ id: "b" })],
      [],
    );
    expect(screen.getAllByText(/Tokens not reported/).length).toBeGreaterThan(0);
    // The negative controls: the values the audited screen printed.
    const grid = screen.getByRole("heading", { name: "This month" })
      .nextElementSibling as HTMLElement;
    expect(grid.textContent).not.toMatch(/\b0\b/);
    expect(grid.textContent).not.toMatch(/\$0\.00/);
    // Anti-vacuity: the request count it does know still renders.
    expect(screen.getByText("30")).toBeInTheDocument();
  });

  it("renders the figures when every record carried them", async () => {
    await renderUsage(
      totals({
        snapshots: 1,
        request_count: 4,
        input_tokens: 1_000,
        output_tokens: 250,
        reported_cost_micros: 2_000_000,
        estimated_cost_micros: 1_800_000,
      }),
      [
        snapshot({
          id: "a",
          input_tokens: 1_000,
          output_tokens: 250,
          reported_cost_micros: 2_000_000,
          estimated_cost_micros: 1_800_000,
        }),
      ],
      [],
    );
    expect(screen.getByText("1,000")).toBeInTheDocument();
    expect(screen.getByText("250")).toBeInTheDocument();
    expect(screen.getAllByText(/^\$2\.00/).length).toBeGreaterThan(0);
    expect(screen.getByText("(provider-reported)")).toBeInTheDocument();
  });

  it("labels a total folded over a mix of known and unknown records", async () => {
    await renderUsage(
      totals({ snapshots: 2, request_count: 9, input_tokens: 500, output_tokens: 100 }),
      [snapshot({ id: "a", input_tokens: 500, output_tokens: 100 }), snapshot({ id: "b" })],
      [],
    );
    expect(
      screen.getByText(/500 — Partial token data: 1 of 2 usage record\(s\)/),
    ).toBeInTheDocument();
  });

  it("says a provider metered in other units does not report tokens", async () => {
    await renderUsage(
      totals({ snapshots: 2, request_count: 2, reported_cost_micros: 500_000 }),
      [
        snapshot({ id: "a", provider: "stripe", quantity: 10, unit: "events" }),
        snapshot({ id: "b", provider: "stripe", quantity: 4, unit: "events" }),
      ],
      [],
    );
    expect(screen.getAllByText(/Tokens not reported by this provider/).length).toBeGreaterThan(
      0,
    );
    expect(screen.getAllByText(/metered in events, not tokens/).length).toBeGreaterThan(0);
  });

  it("dates the totals when the provider connection behind them is stale", async () => {
    await renderUsage(
      totals({
        snapshots: 1,
        request_count: 2,
        input_tokens: 10,
        output_tokens: 5,
        reported_cost_micros: 1_000_000,
        estimated_cost_micros: 900_000,
      }),
      [
        snapshot({
          id: "a",
          input_tokens: 10,
          output_tokens: 5,
          reported_cost_micros: 1_000_000,
          estimated_cost_micros: 900_000,
        }),
      ],
      [connection({ stale: true, last_success_at: "2026-07-01T00:00:00Z" })],
    );
    expect(
      screen.getByText(/10 — as of 2026-07-01T00:00:00Z; the source has not synced since/),
    ).toBeInTheDocument();
  });

  it("says the budget's used figure is a floor when its records are incomplete", async () => {
    await renderUsage(
      totals({ snapshots: 2, request_count: 9, estimated_cost_micros: 1_000_000 }),
      [snapshot({ id: "a", estimated_cost_micros: 1_000_000 }), snapshot({ id: "b" })],
      [],
    );
    expect(
      screen.getByText(/This is a lower bound, not the month's whole spend/),
    ).toBeInTheDocument();
  });

  it("measures completeness over every source, not the filtered table", async () => {
    // The totals are folded over ALL sources; the table may be filtered. The
    // basis for the availability judgement must be the same set the totals
    // came from, so a second read with source=all is what is measured.
    await renderUsage(
      totals({ snapshots: 2, request_count: 9, input_tokens: 500 }),
      [snapshot({ id: "a", input_tokens: 500 })],
      [],
    );
    expect(mockApi.usageRecords).toHaveBeenCalledWith(
      expect.objectContaining({ source: "all" }),
    );
  });
});
