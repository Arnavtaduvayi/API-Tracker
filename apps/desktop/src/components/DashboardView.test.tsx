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
import { DashboardView, aggregateSeries } from "./DashboardView";
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
      projectActivity: vi.fn(),
      alertsList: vi.fn(),
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
  projectActivity: ReturnType<typeof vi.fn>;
  alertsList: ReturnType<typeof vi.fn>;
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

/**
 * `CurrentHealth::ApplyIncomplete::describe()` verbatim (NEW-35). Copied
 * rather than paraphrased on purpose: the point of the variant is that one
 * sentence serves the desktop and the CLI, so a test that invents its own
 * wording would pass while the two surfaces disagreed.
 */
const APPLY_INCOMPLETE_SENTENCE =
  "setup has not finished applying — nothing is verified yet and no request will be " +
  "observed; if no setup is running right now it was interrupted, so start tracking for " +
  "this folder again to finish it";

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
      session_first_observed_at: "2026-07-27T10:00:00Z",
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
  mockApi.alertsList.mockResolvedValue([]);
  mockApi.projectActivity.mockResolvedValue({ granularity: "hour", series: [] });
});

function seriesPoint(bucket: string, requests: number, errors = 0) {
  return {
    bucket_start: bucket,
    requests,
    errors,
    avg_latency_ms: null,
    input_tokens: null,
    output_tokens: null,
    estimated_micros: null,
    cost_complete: true,
  };
}

describe("DashboardView", () => {
  it("offers tracking from an empty state instead of a bare zero", async () => {
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText("No activity observed yet")).toBeInTheDocument();
    expect(screen.getByText(/Point Tethra at a project folder/)).toBeInTheDocument();
    // The empty state's whole job is to offer the next action.
    expect(screen.getByRole("button", { name: "Choose a project folder" })).toBeInTheDocument();
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
    // usage_event_count matches the request count on purpose: a cost with no
    // usage event behind it is a state the backend cannot produce, and the
    // fixture used to encode exactly that (NEW-37).
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({
        total_requests: 3,
        success_count: 3,
        usage_event_count: 3,
        input_tokens: 90,
        output_tokens: 30,
        estimated_cost_micros: 12_345,
      }),
    );
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText(/lower bound; cache reads excluded/)).toBeInTheDocument();
    expect(screen.getByText("100% succeeded")).toBeInTheDocument();
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

describe("DashboardView never fabricates a zero (NEW-37)", () => {
  it("does not render 0 tokens or $0.0000 when no response carried usage", async () => {
    // The audited state: real traffic through a provider whose manifest has
    // usage_shape = "" (cohere, google-gemini, langsmith, replicate,
    // supabase). Nothing is extractable, so the rollup has no row and every
    // usage field arrives as 0.
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({ total_requests: 42, success_count: 42, usage_event_count: 0 }),
    );
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText(/Tokens not reported/)).toBeInTheDocument();

    // The negative controls: the two strings the audited screen printed.
    expect(screen.queryByText("0 / 0")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/\$0\.0000/);
    // And the disclaimer that only makes sense beside a figure.
    expect(document.body.textContent).not.toMatch(/lower bound; cache reads excluded/);
    // Anti-vacuity: the panel rendered, it was not blanked. The real numbers
    // are still there.
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("100% succeeded")).toBeInTheDocument();
  });

  it("still shows a measured zero, because hiding a measurement is a different lie", async () => {
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({
        total_requests: 5,
        success_count: 5,
        usage_event_count: 5,
        input_tokens: 0,
        output_tokens: 0,
        estimated_cost_micros: 0,
      }),
    );
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText("0 in / 0 out")).toBeInTheDocument();
    expect(document.body.textContent).toMatch(/\$0\.0000/);
    expect(screen.getByText(/lower bound; cache reads excluded/)).toBeInTheDocument();
  });

  it("labels a total folded over some unknown records as partial", async () => {
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({
        total_requests: 500,
        success_count: 500,
        usage_event_count: 3,
        input_tokens: 900,
        output_tokens: 100,
        estimated_cost_micros: 4_000,
      }),
    );
    render(<DashboardView onTrack={() => {}} />);
    const tokens = await screen.findByText(/900 in \/ 100 out/);
    expect(tokens.textContent).toMatch(/Partial token data: 3 of 500 response\(s\)/);
    expect(tokens.textContent).toMatch(/not counted as zero/);
  });

  it("does not invent an estimate for tokens it could not price", async () => {
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({
        total_requests: 3,
        success_count: 3,
        usage_event_count: 3,
        input_tokens: 900,
        output_tokens: 120,
        estimated_cost_micros: 0,
      }),
    );
    render(<DashboardView onTrack={() => {}} />);
    expect(await screen.findByText("900 in / 120 out")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/\$0\.0000/);
    expect(screen.getByText(/no local price covers the model/)).toBeInTheDocument();
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

  it("does not tell a half-applied setup to go and make a request (NEW-35)", async () => {
    // `applying` is not in the backend's watchable set, so it falls through to
    // `health_without_evidence`, where it used to be answered by the catch-all
    // "waiting for the first request" — advice for a setup that finished. This
    // one did not. The backend now answers it with `ApplyIncomplete`, and this
    // screen renders that sentence rather than a paraphrase of its own, so the
    // desktop and the CLI say the same thing about the same row.
    mockApi.trackingList.mockResolvedValue([
      setup({
        state: "applying",
        health: {
          kind: "apply_incomplete",
          sentence: APPLY_INCOMPLETE_SENTENCE,
          currently_working: false,
        },
      }),
    ]);
    render(<DashboardView onTrack={() => {}} />);
    const now = (await screen.findByRole("heading", { name: "Right now" }))
      .parentElement as HTMLElement;
    const sentence = within(now).getByText(APPLY_INCOMPLETE_SENTENCE);
    // Not verified, and flagged as such: `is_currently_working()` is false for
    // this variant, so the row must read as a problem, not as body text.
    expect(sentence).toHaveClass("warnbox");
    expect(screen.getByText(/1 project\(s\) are not tracking right now/)).toBeInTheDocument();
    // The negative control that fails if the catch-all ever answers this row
    // again, in the backend or in a reinstated local special case.
    expect(document.body.textContent).not.toMatch(/waiting for the first request/);
  });

  it("renders the backend's apply-incomplete sentence, not a local paraphrase (NEW-35)", async () => {
    // The audited fix lived HERE, as `presentTenseSentence`'s `state ===
    // "applying"` branch, so the desktop and the CLI stated the same condition
    // in two different sentences and only one of them could be corrected. The
    // rule is now `CurrentHealth::ApplyIncomplete`; this pins that nothing on
    // this screen rewrites it.
    mockApi.trackingList.mockResolvedValue([
      setup({
        state: "applying",
        health: {
          kind: "apply_incomplete",
          sentence: APPLY_INCOMPLETE_SENTENCE,
          currently_working: false,
        },
      }),
    ]);
    render(<DashboardView onTrack={() => {}} />);
    await screen.findByRole("heading", { name: "Right now" });
    // The distinctive clause of the removed local sentence. It shares its
    // opening words with the backend's, so only a phrase unique to the
    // workaround can tell the two apart.
    expect(document.body.textContent).not.toMatch(
      /so nothing here is verified and no request will be observed yet/,
    );
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
          session_first_observed_at: null,
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
    // The sentence and its count are separate cells of the same feed row.
    const matched = await screen.findByText("Matched a stored credential by its fingerprint");
    expect(matched).toBeInTheDocument();
    expect(matched.closest(".feed-row")).toHaveTextContent("12");
    const unavailable = screen.getByText(
      "Attribution was not running when these requests were recorded",
    );
    expect(unavailable).toBeInTheDocument();
    expect(unavailable.closest(".feed-row")).toHaveTextContent("4");
    // The negative control: the raw tokens must not appear anywhere.
    expect(document.body.textContent).not.toMatch(/matched_fingerprint/);
    expect(document.body.textContent).not.toMatch(/unavailable/);
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
    // Each project is its own card carrying its own counts.
    const mine = screen.getByText("my-app").closest(".entity-card");
    expect(mine).toHaveTextContent("20");
    expect(mine).toHaveTextContent("requests");
    expect(mine).toHaveTextContent("0");
    expect(mine).toHaveTextContent("errors");
    const side = screen.getByText("side-project").closest(".entity-card");
    expect(side).toHaveTextContent("10");
    expect(side).toHaveTextContent("2");
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

// --- The card / chart layer (card-based UI overhaul) --------------------

describe("DashboardView headline tiles", () => {
  it("shows the four headline figures without inventing any of them", async () => {
    mockApi.gatewayActivity.mockResolvedValue(
      emptySummary({ total_requests: 18_492, success_count: 18_492, usage_event_count: 0 }),
    );
    mockApi.trackingList.mockResolvedValue([setup()]);
    mockApi.alertsList.mockResolvedValue([]);
    render(<DashboardView onTrack={() => {}} />);

    const tiles = await screen.findByTestId("dashboard-tiles");
    expect(within(tiles).getByText("18,492")).toBeInTheDocument();
    expect(within(tiles).getByText("Tracked projects")).toBeInTheDocument();
    expect(within(tiles).getByText("nothing needs attention")).toBeInTheDocument();
    // No usage was reported, so the cost tile must not print a dollar figure
    // and must not carry the lower-bound caveat that only fits a real one.
    expect(within(tiles).queryByText(/lower bound/)).not.toBeInTheDocument();
    expect(tiles.textContent).not.toMatch(/\$0\.0000/);
  });

  it("says a figure could not be read rather than showing it as zero", async () => {
    mockApi.gatewayActivity.mockResolvedValue(emptySummary({ total_requests: 4 }));
    mockApi.trackingList.mockRejectedValue({ code: "unknown", message: "boom" });
    mockApi.alertsList.mockRejectedValue({ code: "unknown", message: "boom" });
    render(<DashboardView onTrack={() => {}} />);

    const tiles = await screen.findByTestId("dashboard-tiles");
    expect(within(tiles).getAllByText("could not be read")).toHaveLength(2);
    // The negative control: an unreadable count is never rendered as 0.
    expect(within(tiles).queryByText("0")).not.toBeInTheDocument();
  });

  it("reports the top open-alert severity", async () => {
    mockApi.gatewayActivity.mockResolvedValue(emptySummary({ total_requests: 4 }));
    mockApi.alertsList.mockResolvedValue([
      { id: "a1", severity: "high", title: "Rotation due" },
      { id: "a2", severity: "low", title: "Docs changed" },
    ]);
    render(<DashboardView onTrack={() => {}} />);

    const tiles = await screen.findByTestId("dashboard-tiles");
    expect(within(tiles).getByText("2")).toBeInTheDocument();
    expect(within(tiles).getByText("top severity: high")).toBeInTheDocument();
  });
});

describe("DashboardView request-volume chart", () => {
  it("sums per-project request counts into one series", () => {
    const merged = aggregateSeries([
      [seriesPoint("2026-08-01T00:00:00Z", 3), seriesPoint("2026-08-01T01:00:00Z", 5)],
      [seriesPoint("2026-08-01T01:00:00Z", 7, 2)],
    ]);
    expect(merged).toHaveLength(2);
    expect(merged[0]).toMatchObject({ bucket_start: "2026-08-01T00:00:00Z", requests: 3 });
    expect(merged[1]).toMatchObject({
      bucket_start: "2026-08-01T01:00:00Z",
      requests: 12,
      errors: 2,
    });
  });

  it("never sums tokens, latency or cost across projects", () => {
    const merged = aggregateSeries([
      [{ ...seriesPoint("2026-08-01T00:00:00Z", 1), input_tokens: 100, estimated_micros: 50 }],
      [{ ...seriesPoint("2026-08-01T00:00:00Z", 1), input_tokens: null }],
    ]);
    // Coverage differs per project, so a summed figure would present a partial
    // total as a complete one. These stay unknown, and the point is marked
    // incomplete so nothing downstream reads it as a costed series.
    expect(merged[0].input_tokens).toBeNull();
    expect(merged[0].output_tokens).toBeNull();
    expect(merged[0].avg_latency_ms).toBeNull();
    expect(merged[0].estimated_micros).toBeNull();
    expect(merged[0].cost_complete).toBe(false);
  });

  it("draws the chart from the per-project series", async () => {
    mockApi.gatewayActivity.mockResolvedValue(emptySummary({ total_requests: 8 }));
    mockApi.gatewayActivityByProject.mockResolvedValue([
      {
        project_id: "p1",
        project_name: "my-app",
        total_requests: 8,
        success_count: 8,
        error_count: 0,
        transport_error_count: 0,
        first_event_at: "2026-08-01T00:00:00Z",
        last_event_at: "2026-08-01T01:00:00Z",
      },
    ]);
    mockApi.projectActivity.mockResolvedValue({
      granularity: "hour",
      series: [seriesPoint("2026-08-01T00:00:00Z", 3), seriesPoint("2026-08-01T01:00:00Z", 5)],
    });
    render(<DashboardView onTrack={() => {}} />);

    expect(await screen.findByRole("img", { name: /Requests/ })).toBeInTheDocument();
  });

  it("keeps the per-project split when the chart cannot be read", async () => {
    mockApi.gatewayActivity.mockResolvedValue(emptySummary({ total_requests: 8 }));
    mockApi.gatewayActivityByProject.mockResolvedValue([
      {
        project_id: "p1",
        project_name: "my-app",
        total_requests: 8,
        success_count: 8,
        error_count: 0,
        transport_error_count: 0,
        first_event_at: null,
        last_event_at: null,
      },
    ]);
    mockApi.projectActivity.mockRejectedValue({ code: "db_error", message: "locked" });
    render(<DashboardView onTrack={() => {}} />);

    // The chart says it is missing; the split it decorates is untouched.
    expect(
      await screen.findByText(/request-volume chart could not be read/),
    ).toBeInTheDocument();
    expect(screen.getByText("my-app")).toBeInTheDocument();
    expect(screen.queryByText(/per-project split could not be loaded/)).not.toBeInTheDocument();
  });
});
