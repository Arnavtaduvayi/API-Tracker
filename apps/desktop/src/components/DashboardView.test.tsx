// Dashboard state rendering: activity and tracked-project loading
// failures must be VISIBLE (never a silently empty panel), empty states
// must be actionable, and the attribution-paused banner must say traffic
// is still recorded.
//
// The regression guards here are:
//
// * present-tense health and historical verification render under separate
//   headings, and "verified previously, gateway down" is never a success
//   (ZFT-005);
// * no internal enum token reaches the screen (ZFT-030);
// * a failed foreground check does not render as "all fine" (ZFT-031);
// * traffic can be attributed to a project (ZFT-029).
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DashboardView } from "./DashboardView";
import { api } from "../api";
import type { GatewayActivitySummary, TrackingHealth, TrackingStatus } from "../types";

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      gatewayActivity: vi.fn(),
      gatewayActivityByProject: vi.fn(),
      trackingList: vi.fn(),
      trackingForegroundActive: vi.fn(),
      trackingForegroundStop: vi.fn(),
      trackingDiagnose: vi.fn(),
      trackingUndo: vi.fn(),
      trackingResumeAttribution: vi.fn(),
    },
  };
});

const mockApi = api as unknown as {
  gatewayActivity: ReturnType<typeof vi.fn>;
  gatewayActivityByProject: ReturnType<typeof vi.fn>;
  trackingList: ReturnType<typeof vi.fn>;
  trackingForegroundActive: ReturnType<typeof vi.fn>;
  trackingForegroundStop: ReturnType<typeof vi.fn>;
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

const activeHealth: TrackingHealth = {
  kind: "verified_and_active",
  sentence: "tracking verified and active",
  currently_working: true,
};

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
    health: activeHealth,
    history: {
      first_verified_at: "2026-07-20T08:00:00Z",
      last_observed_at: "2026-07-27T10:00:00Z",
      verification_session: "sess-1",
      config_generation: 1,
      sentence:
        "First verified 2026-07-20T08:00:00Z. Most recent observation in this configuration: 2026-07-27T10:00:00Z.",
    },
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockApi.gatewayActivity.mockResolvedValue(emptySummary());
  mockApi.gatewayActivityByProject.mockResolvedValue([]);
  mockApi.trackingList.mockResolvedValue([]);
  mockApi.trackingForegroundActive.mockResolvedValue({
    active: false,
    stopped: false,
    detail: null,
  });
});

describe("DashboardView", () => {
  it("offers tracking from an empty state instead of a bare zero", async () => {
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText("No activity observed yet.")).toBeInTheDocument();
    expect(
      screen.getByText(/Select a project folder and turn on tracking/),
    ).toBeInTheDocument();
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

  it("runs a tracking check and shows the result", async () => {
    mockApi.trackingList.mockResolvedValue([
      setup({
        state: "awaiting_first_request",
        health: {
          kind: "waiting_for_first_request",
          sentence: "waiting for the first request",
          currently_working: false,
        },
      }),
    ]);
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

describe("DashboardView current vs historical status (ZFT-005)", () => {
  it("separates what is true now from what was true before", async () => {
    mockApi.trackingList.mockResolvedValue([setup()]);
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByRole("heading", { name: "Right now" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Previously" })).toBeInTheDocument();
    expect(screen.getByText("tracking verified and active")).toBeInTheDocument();
    expect(screen.getByText(/First verified 2026-07-20T08:00:00Z\./)).toBeInTheDocument();
  });

  it("never renders 'verified previously, gateway down' as a success", async () => {
    mockApi.trackingList.mockResolvedValue([
      setup({
        state: "traffic_observed",
        health: {
          kind: "verified_previously_gateway_down",
          sentence:
            "verified previously — the local tracking service is not running, so requests are not reaching your APIs",
          currently_working: false,
        },
      }),
    ]);
    render(<DashboardView onTrack={() => {}} />);
    const now = (await screen.findByRole("heading", { name: "Right now" }))
      .parentElement as HTMLElement;
    const sentence = within(now).getByText(
      /the local tracking service is not running, so requests are not reaching your APIs/,
    );
    // The negative control: this must be flagged, not rendered as normal
    // body text alongside "Tracking verified".
    expect(sentence).toHaveClass("warnbox");
    expect(screen.queryByText("Tracking verified")).not.toBeInTheDocument();
    expect(screen.getByText(/1 project\(s\) are not tracking right now/)).toBeInTheDocument();
    // History survives — it is shown, just not as present-tense success.
    expect(screen.getByText(/First verified 2026-07-20T08:00:00Z\./)).toBeInTheDocument();
  });

  it("says a never-verified setup has never been verified", async () => {
    mockApi.trackingList.mockResolvedValue([
      setup({
        state: "awaiting_restart",
        health: {
          kind: "needs_restart",
          sentence: "restart your project, then make one request",
          currently_working: false,
        },
        history: {
          first_verified_at: null,
          last_observed_at: null,
          verification_session: null,
          config_generation: 1,
          sentence: null,
        },
      }),
    ]);
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText(
        /This setup has never been verified\. Recorded state: Applied; waiting for the project to restart\./,
      ),
    ).toBeInTheDocument();
  });
});

describe("DashboardView renders sentences, not enum tokens (ZFT-030)", () => {
  it("maps every attribution label to a sentence", async () => {
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({
        total_requests: 16,
        success_count: 16,
        attribution: [
          ["matched_fingerprint", 12],
          ["unavailable", 4],
        ],
      }),
    );
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText("Matched a stored credential by its fingerprint — 12 request(s)"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Attribution was not running when these requests were recorded — 4 request(s)",
      ),
    ).toBeInTheDocument();
    // The negative control: the raw tokens must not appear anywhere.
    expect(document.body.textContent).not.toMatch(/matched_fingerprint/);
    expect(document.body.textContent).not.toMatch(/— 12\b(?!.*request)/);
  });

  it("labels a value it does not recognise as unknown rather than showing it bare", async () => {
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({ total_requests: 1, attribution: [["some_future_label", 1]] }),
    );
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText(
        /Recorded with a label this version of Tethra does not know \(“some_future_label”\)/,
      ),
    ).toBeInTheDocument();
  });
});

describe("DashboardView foreground fallback (ZFT-031)", () => {
  it("surfaces the foreground-fallback limitation when it is in use", async () => {
    mockApi.trackingForegroundActive.mockResolvedValue({
      active: true,
      stopped: false,
      detail: null,
    });
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText(/Tracking pauses when Tethra closes/)).toBeInTheDocument();
  });

  it("renders a stopped foreground helper distinctly from a healthy background service", async () => {
    mockApi.trackingForegroundActive.mockResolvedValue({
      active: false,
      stopped: true,
      detail: "The helper that was tracking while Tethra is open exited (exit status: 1).",
    });
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText(
        "The helper that was tracking while Tethra is open exited (exit status: 1).",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/Traffic is not being recorded through it/)).toBeInTheDocument();
  });

  it("does not render a failed foreground check as 'nothing to report'", async () => {
    mockApi.trackingForegroundActive.mockRejectedValue({
      code: "ipc",
      message: "the backend did not answer",
    });
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText(
        /Whether tracking is running in the foreground could not be checked: the backend did not answer/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Treat the tracking state below as unconfirmed/),
    ).toBeInTheDocument();
  });

  it("can stop the foreground helper without quitting the app", async () => {
    mockApi.trackingForegroundActive.mockResolvedValue({
      active: true,
      stopped: false,
      detail: null,
    });
    mockApi.trackingForegroundStop.mockResolvedValue(undefined);
    render(<DashboardView onTrack={() => {}} />);
    await userEvent.click(await screen.findByRole("button", { name: "Stop it now" }));
    expect(mockApi.trackingForegroundStop).toHaveBeenCalled();
    expect(
      await screen.findByText("The foreground tracking helper was stopped."),
    ).toBeInTheDocument();
  });
});

describe("DashboardView per-project attribution (ZFT-029)", () => {
  it("answers which project generated the traffic", async () => {
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({ total_requests: 30, success_count: 28, error_count: 2 }),
    );
    mockApi.gatewayActivityByProject.mockResolvedValue([
      {
        project_id: "p1",
        project_name: "my-app",
        total_requests: 20,
        success_count: 20,
        error_count: 0,
        transport_error_count: 0,
        first_event_at: "2026-07-27T09:00:00Z",
        last_event_at: "2026-07-27T10:00:00Z",
      },
      {
        project_id: "p2",
        project_name: "side-project",
        total_requests: 10,
        success_count: 8,
        error_count: 2,
        transport_error_count: 0,
        first_event_at: "2026-07-27T09:30:00Z",
        last_event_at: "2026-07-27T09:45:00Z",
      },
    ]);
    render(<DashboardView onTrack={() => {}} />);
    const heading = await screen.findByRole("heading", { name: "By project" });
    expect(heading).toBeInTheDocument();
    expect(screen.getByText("my-app")).toBeInTheDocument();
    expect(screen.getByText(/20 request\(s\), 0 error\(s\)/)).toBeInTheDocument();
    expect(screen.getByText("side-project")).toBeInTheDocument();
    expect(screen.getByText(/10 request\(s\), 2 error\(s\)/)).toBeInTheDocument();
    // The totals stay honestly labelled as global.
    expect(
      screen.getByText(
        /These totals cover every tracked project on this machine\. The per-project split is below\./,
      ),
    ).toBeInTheDocument();
  });

  it("says the split failed rather than implying the totals are per project", async () => {
    mockApi.gatewayActivity.mockResolvedValue(emptySummary({ total_requests: 4 }));
    mockApi.gatewayActivityByProject.mockRejectedValue({
      code: "db_error",
      message: "database is locked",
    });
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText(
        /The per-project split could not be loaded: database is locked\. The totals above are across all projects\./,
      ),
    ).toBeInTheDocument();
  });

  it("names an events-without-a-project row instead of rendering a blank", async () => {
    mockApi.gatewayActivity.mockResolvedValue(emptySummary({ total_requests: 3 }));
    mockApi.gatewayActivityByProject.mockResolvedValue([
      {
        project_id: "gone",
        project_name: null,
        total_requests: 3,
        success_count: 3,
        error_count: 0,
        transport_error_count: 0,
        first_event_at: null,
        last_event_at: null,
      },
    ]);
    render(<DashboardView onTrack={() => {}} />);
    expect(
      await screen.findByText("A project that has since been removed"),
    ).toBeInTheDocument();
  });
});
