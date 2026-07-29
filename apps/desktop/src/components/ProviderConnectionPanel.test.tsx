// Two honesty properties of the administrative-connection panel:
//
// * a failed status read is not "no connection" — `return null` erased the
//   whole panel, so an error and a never-connected provider looked the same
//   (NEW-41);
// * the per-provider-project cost rollup sums only rows that carried a cost,
//   so its zero cannot be told from an absence and is not shown as $0.00
//   (NEW-37).

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { ProviderConnection } from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      providerConnectionStatus: vi.fn(),
      providerKeys: vi.fn(),
      providerProjects: vi.fn(),
      credentialList: vi.fn(),
    },
  };
});

import { api } from "../api";
import { ProviderConnectionPanel } from "./ProviderConnectionPanel";

const mockApi = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

function connection(over: Partial<ProviderConnection> = {}): ProviderConnection {
  return {
    provider: "openai",
    connected: true,
    admin_key_masked: "sk-…zz",
    admin_credential_id: null,
    org_label: null,
    connected_at: "2026-07-01T00:00:00Z",
    last_synced_at: "2026-07-20T00:00:00Z",
    last_success_at: "2026-07-20T00:00:00Z",
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

beforeEach(() => {
  vi.clearAllMocks();
  mockApi.providerKeys.mockResolvedValue([]);
  mockApi.providerProjects.mockResolvedValue([]);
  mockApi.credentialList.mockResolvedValue([]);
});

describe("ProviderConnectionPanel load failure (NEW-41)", () => {
  it("says the status could not be read instead of rendering nothing", async () => {
    mockApi.providerConnectionStatus.mockRejectedValue({
      code: "locked",
      message: "the vault is locked",
    });
    render(<ProviderConnectionPanel provider="openai" />);
    expect(
      await screen.findByText(/could not be read: the vault is locked/),
    ).toBeInTheDocument();
    expect(screen.getByText(/This is not evidence that none exists/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});

describe("ProviderConnectionPanel per-project cost (NEW-37)", () => {
  it("does not render an absent month's cost as $0.00", async () => {
    mockApi.providerConnectionStatus.mockResolvedValue(connection());
    mockApi.providerProjects.mockResolvedValue([
      {
        provider_project_id: "proj_a",
        name: "billing",
        reported_cost_micros_month: 0,
        has_linked_usage: false,
      },
      {
        provider_project_id: "proj_b",
        name: "app",
        reported_cost_micros_month: 2_500_000,
        has_linked_usage: true,
      },
    ]);
    render(<ProviderConnectionPanel provider="openai" />);
    expect(await screen.findByText(/Reported cost not reported/)).toBeInTheDocument();
    // The known figure is untouched — the rule suppresses fabrication, not data.
    expect(screen.getByText("$2.50")).toBeInTheDocument();
    // The negative control, scoped to the table: no cell claims $0.00.
    const table = screen.getByRole("table");
    expect(table.textContent).not.toMatch(/\$0\.00/);
  });
});
