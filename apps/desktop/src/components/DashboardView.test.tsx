// Dashboard state rendering: activity and tracked-project loading
// failures must be VISIBLE (never a silently empty panel), empty states
// must be actionable, and the attribution-paused banner must say traffic
// is still recorded.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DashboardView } from "./DashboardView";
import { api } from "../api";
import type { GatewayActivitySummary, TrackingStatus } from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      gatewayActivity: vi.fn(),
      trackingList: vi.fn(),
      trackingForegroundActive: vi.fn(),
      trackingDiagnose: vi.fn(),
      trackingUndo: vi.fn(),
      trackingResumeAttribution: vi.fn(),
    },
  };
});

const mockApi = api as unknown as {
  gatewayActivity: ReturnType<typeof vi.fn>;
  trackingList: ReturnType<typeof vi.fn>;
  trackingForegroundActive: ReturnType<typeof vi.fn>;
  trackingDiagnose: ReturnType<typeof vi.fn>;
  trackingUndo: ReturnType<typeof vi.fn>;
  trackingResumeAttribution: ReturnType<typeof vi.fn>;
};

function emptySummary(over: Partial<GatewayActivitySummary> = {}): GatewayActivitySummary {
  return {
    since: null,
    total_requests: 0,
    success_count: 0,
    error_count: 0,
    transport_error_count: 0,
    p50_latency_ms: null,
    p95_latency_ms: null,
    p99_latency_ms: null,
    request_bytes: 0,
    response_bytes: 0,
    top_endpoints: [],
    attribution: [],
    input_tokens: 0,
    output_tokens: 0,
    usage_event_count: 0,
    top_models: [],
    estimated_cost_micros: 0,
    first_event_at: null,
    last_event_at: null,
    ...over,
  };
}

function setup(over: Partial<TrackingStatus> = {}): TrackingStatus {
  return {
    setup_id: "setup-1",
    state: "traffic_observed",
    project_id: "p1",
    folder: "/Users/dev/my-app",
    watch: "observed",
    observed_provider: "openai",
    observed_latency_ms: 120,
    observed_model: null,
    providers: [{ provider_id: "openai", last_observed_at: "2026-07-27T10:00:00Z" }],
    attribution_paused: false,
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockApi.gatewayActivity.mockResolvedValue(emptySummary());
  mockApi.trackingList.mockResolvedValue([]);
  mockApi.trackingForegroundActive.mockResolvedValue(false);
});

describe("DashboardView", () => {
  it("offers tracking from an empty state instead of a bare zero", async () => {
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText("No activity observed yet.")).toBeInTheDocument();
    expect(
      screen.getByText(/Select a project folder and turn on tracking/),
    ).toBeInTheDocument();
  });

  it("tells a configured-but-silent project to restart and make a request", async () => {
    mockApi.trackingList.mockResolvedValue([
      setup({ state: "awaiting_restart", watch: "waiting" }),
    ]);
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText("Restart the project and make one API request."),
    ).toBeInTheDocument();
    expect(screen.getByText(/Project needs restart/)).toBeInTheDocument();
  });

  it("renders an activity load failure with a retry, not an empty panel", async () => {
    mockApi.gatewayActivity.mockRejectedValue({
      code: "db_error",
      message: "database is locked",
    });
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText(/Activity could not be loaded: database is locked/),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Retry" }).length).toBeGreaterThan(0);
  });

  it("renders a tracked-project load failure without blanking activity", async () => {
    mockApi.gatewayActivity.mockResolvedValue(emptySummary({ total_requests: 5 }));
    mockApi.trackingList.mockRejectedValue({ code: "unknown", message: "boom" });
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText(/Tracked projects could not be loaded: boom/),
    ).toBeInTheDocument();
    // The independent panel still rendered.
    expect(screen.getByText("Requests")).toBeInTheDocument();
  });

  it("shows the attribution-paused banner and keeps the recording promise honest", async () => {
    mockApi.trackingList.mockResolvedValue([setup({ attribution_paused: true })]);
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText("Credential attribution paused — traffic is still recorded."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Resume attribution" })).toBeInTheDocument();
  });

  it("labels the estimated cost as a lower bound", async () => {
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({ total_requests: 3, success_count: 3, estimated_cost_micros: 12_345 }),
    );
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText(/lower bound; cache reads excluded/)).toBeInTheDocument();
    expect(screen.getByText("100%")).toBeInTheDocument();
  });

  it("says provider-reported usage is never added to observed numbers", async () => {
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText(/never added to these numbers/)).toBeInTheDocument();
    expect(screen.getByText(/some traffic may bypass\s+Tethra/)).toBeInTheDocument();
  });

  it("surfaces the foreground-fallback limitation when it is in use", async () => {
    mockApi.trackingForegroundActive.mockResolvedValue(true);
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText(/Tracking pauses when Tethra closes/)).toBeInTheDocument();
  });

  it("runs a tracking check and shows the result", async () => {
    mockApi.trackingList.mockResolvedValue([setup({ state: "awaiting_first_request" })]);
    mockApi.trackingDiagnose.mockResolvedValue([
      { id: "not_restarted", severity: "hint", message: "Restart it, then make one request." },
    ]);
    render(<DashboardView onTrack={() => {}} />);
    await userEvent.click(await screen.findByRole("button", { name: "Run tracking check" }));
    expect(await screen.findByText(/Restart it, then make one request\./)).toBeInTheDocument();
  });

  it("reports an incomplete stop honestly", async () => {
    mockApi.trackingList.mockResolvedValue([setup()]);
    mockApi.trackingUndo.mockResolvedValue({
      complete: false,
      restored: [],
      removed_routes: [],
      kept_routes: [],
    });
    render(<DashboardView onTrack={() => {}} />);
    await userEvent.click(await screen.findByRole("button", { name: "Stop tracking…" }));
    expect(
      await screen.findByText(/Some files could not be restored; the link was kept/),
    ).toBeInTheDocument();
  });
});
