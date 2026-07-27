// TrackFlow state rendering (TEST_PLAN §7). Load-bearing strings are
// asserted verbatim: the disclosure, the waiting instruction, the
// verified banner, the nothing-detected empty state, and the honest
// partial-apply report. Fetch failures must render an error, never an
// empty screen.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TrackFlow } from "./TrackFlow";
import { api } from "../api";
import type { TrackingApplyReport, TrackingPlan, TrackingScan } from "../types";

const openDialog = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: (...args: unknown[]) => openDialog(...args),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      trackingScan: vi.fn(),
      trackingPlanBuild: vi.fn(),
      trackingApply: vi.fn(),
      trackingStatus: vi.fn(),
      trackingDiagnose: vi.fn(),
      trackingForegroundStart: vi.fn(),
    },
  };
});

const mockApi = api as unknown as {
  trackingScan: ReturnType<typeof vi.fn>;
  trackingPlanBuild: ReturnType<typeof vi.fn>;
  trackingApply: ReturnType<typeof vi.fn>;
  trackingStatus: ReturnType<typeof vi.fn>;
  trackingDiagnose: ReturnType<typeof vi.fn>;
  trackingForegroundStart: ReturnType<typeof vi.fn>;
};

function scanFixture(overrides: Partial<TrackingScan> = {}): TrackingScan {
  return {
    folder: "/Users/dev/my-app",
    project_name: "my-app",
    project_exists: true,
    providers: [
      {
        provider_id: "openai",
        display_name: "OpenAI",
        confidence: "confirmed",
        configurability: "automatic",
        inferred_origin: null,
        evidence: ["Found OPENAI_API_KEY in .env (value not read)"],
        limitations: [],
        credential_candidates: [],
        selected_by_default: true,
      },
      {
        provider_id: "stripe",
        display_name: "Stripe",
        confidence: "confirmed",
        configurability: "unsupported",
        inferred_origin: null,
        evidence: ["Found STRIPE_SECRET_KEY in .env (value not read)"],
        limitations: [
          "The Stripe SDK does not read a base-URL environment variable, so Tethra cannot observe it this way yet. Everything else still works.",
        ],
        credential_candidates: [],
        selected_by_default: false,
      },
    ],
    scanned_files: 3,
    skipped_oversized: 0,
    env_files: [".env"],
    already_tracking: false,
    ...overrides,
  };
}

function planFixture(overrides: Partial<TrackingPlan> = {}): TrackingPlan {
  return {
    project_name: "my-app",
    creates_project: false,
    service_actions: ["Install and start the local tracking service"],
    routes: ["openai"],
    files: [
      {
        path: "/Users/dev/my-app/.env",
        exists: true,
        changed: true,
        diff: "+ OPENAI_BASE_URL=http://127.0.0.1:49152/p/abc/openai/v1",
      },
    ],
    warnings: [],
    restart_expected: true,
    port: 49152,
    providers: ["openai"],
    ...overrides,
  };
}

function applyFixture(overrides: Partial<TrackingApplyReport> = {}): TrackingApplyReport {
  return {
    steps: [
      { title: "Local service installed and running", outcome: "done", detail: "port 49152" },
      { title: "Provider routes created", outcome: "done", detail: "created: openai" },
    ],
    state: "awaiting_restart",
    setup_id: "setup-1",
    install_blocked: false,
    attribution_enabled: true,
    failed: false,
    restart_expected: true,
    ...overrides,
  };
}

async function reachReview() {
  openDialog.mockResolvedValue("/Users/dev/my-app");
  render(<TrackFlow onDone={() => {}} />);
  await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
  await screen.findByText(/Tethra detected 2 APIs/);
}

beforeEach(() => {
  vi.clearAllMocks();
  mockApi.trackingScan.mockResolvedValue(scanFixture());
  mockApi.trackingPlanBuild.mockResolvedValue(planFixture());
  mockApi.trackingApply.mockResolvedValue(applyFixture());
  mockApi.trackingStatus.mockResolvedValue({
    setup_id: "setup-1",
    state: "awaiting_restart",
    project_id: "p1",
    folder: "/Users/dev/my-app",
    watch: "waiting",
    observed_provider: null,
    observed_latency_ms: null,
    observed_model: null,
    providers: [],
    attribution_paused: false,
  });
});

describe("TrackFlow review screen", () => {
  it("summarizes detections and shows the exact diff", async () => {
    await reachReview();
    expect(screen.getByText(/1 can be configured automatically/)).toBeInTheDocument();
    expect(screen.getByText(/1 not currently supported/)).toBeInTheDocument();
    expect(
      await screen.findByText(/OPENAI_BASE_URL=http:\/\/127\.0\.0\.1:49152/),
    ).toBeInTheDocument();
  });

  it("states what is never recorded, in the primary card", async () => {
    await reachReview();
    expect(
      screen.getByText(
        /It will never record API keys, authorization headers, cookies, query values, prompts, request bodies, or response bodies\./,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/local or remote traffic that bypasses Tethra is not observed/i),
    ).toBeInTheDocument();
  });

  it("lists an unsupported provider honestly without blocking the supported one", async () => {
    await reachReview();
    expect(screen.getByText(/detected, not currently supported/)).toBeInTheDocument();
    expect(
      screen.getByText(/does not read a base-URL environment variable/),
    ).toBeInTheDocument();
    const stripeBox = screen.getByRole("checkbox", { name: /Stripe/ });
    expect(stripeBox).toBeDisabled();
    expect(screen.getByRole("button", { name: "Start tracking" })).toBeEnabled();
  });

  it("disables Start tracking when nothing is selected and says why", async () => {
    await reachReview();
    await userEvent.click(screen.getByRole("checkbox", { name: /OpenAI/ }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Start tracking" })).toBeDisabled(),
    );
    expect(
      screen.getByText(/nothing is selected, so there is nothing to configure/),
    ).toBeInTheDocument();
  });

  it("renders a plan-building failure instead of an empty diff", async () => {
    mockApi.trackingPlanBuild.mockRejectedValue({
      code: "invalid_input",
      message: "the gateway has no persisted port yet",
    });
    await reachReview();
    expect(
      await screen.findByText(
        /The changes could not be prepared: the gateway has no persisted port yet/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start tracking" })).toBeDisabled();
  });

  it("renders a scan failure with a retry instead of a blank screen", async () => {
    mockApi.trackingScan.mockRejectedValue({
      code: "invalid_input",
      message: "refusing to scan /: it is the filesystem root",
    });
    openDialog.mockResolvedValue("/");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    expect(
      await screen.findByText(/refusing to scan \/: it is the filesystem root/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("shows the nothing-detected state with what was scanned", async () => {
    mockApi.trackingScan.mockResolvedValue(scanFixture({ providers: [], scanned_files: 7 }));
    openDialog.mockResolvedValue("/Users/dev/empty");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    expect(
      await screen.findByText("No trackable APIs detected in this folder."),
    ).toBeInTheDocument();
    expect(screen.getByText(/7 file\(s\) read, 6 levels deep/)).toBeInTheDocument();
  });
});

describe("TrackFlow apply and verification", () => {
  it("asks for a restart and does not claim verified before traffic", async () => {
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    expect(await screen.findByText("Configuration applied")).toBeInTheDocument();
    expect(
      screen.getByText("Restart your app, then make one API request."),
    ).toBeInTheDocument();
    expect(screen.getByText(/Waiting for traffic…/)).toBeInTheDocument();
    // The negative control: no verified banner while watch === "waiting".
    expect(screen.queryByText("Tracking verified")).not.toBeInTheDocument();
  });

  it("claims verified only once an observation arrives", async () => {
    mockApi.trackingStatus.mockResolvedValue({
      setup_id: "setup-1",
      state: "traffic_observed",
      project_id: "p1",
      folder: "/Users/dev/my-app",
      watch: "observed",
      observed_provider: "anthropic",
      observed_latency_ms: 201,
      observed_model: "claude-fable-5",
      providers: [{ provider_id: "anthropic", last_observed_at: "2026-07-27T00:00:00Z" }],
      attribution_paused: false,
    });
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    expect(await screen.findByText("Tracking verified")).toBeInTheDocument();
    expect(
      screen.getByText(/Observed anthropic from \/Users\/dev\/my-app/),
    ).toBeInTheDocument();
    expect(screen.getByText(/201 ms/)).toBeInTheDocument();
  });

  it("reports a partial apply honestly and never silently rolls back", async () => {
    mockApi.trackingApply.mockResolvedValue(
      applyFixture({
        failed: true,
        state: "needs_attention",
        steps: [
          { title: "Local service installed and running", outcome: "done", detail: "" },
          {
            title: "Environment files updated",
            outcome: "failed",
            detail: "openai: the environment files changed since the preview",
          },
        ],
      }),
    );
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    expect(await screen.findByText("Tracking is partially configured")).toBeInTheDocument();
    expect(screen.getByText(/Completed steps are left in place/)).toBeInTheDocument();
  });

  it("offers the foreground fallback when the OS blocks the service", async () => {
    mockApi.trackingApply.mockResolvedValue(
      applyFixture({
        failed: true,
        install_blocked: true,
        state: "needs_attention",
        steps: [
          {
            title: "Local service installed and running",
            outcome: "failed",
            detail: "macOS blocked the background service",
          },
        ],
      }),
    );
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    const fallback = await screen.findByRole("button", {
      name: "Track while the app is open",
    });
    await userEvent.click(fallback);
    expect(mockApi.trackingForegroundStart).toHaveBeenCalled();
  });

  it("shows a ranked diagnosis on demand rather than a blank screen", async () => {
    mockApi.trackingDiagnose.mockResolvedValue([
      {
        id: "not_restarted",
        severity: "hint",
        message: "The project may not have been restarted — restart it, then make one request.",
      },
      {
        id: "docker_compose",
        severity: "warn",
        message: "This project runs with Docker Compose (compose file found).",
      },
    ]);
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    await screen.findByText("Configuration applied");
    await userEvent.click(screen.getByRole("button", { name: "Run diagnostics" }));
    expect(
      await screen.findByText(/The project may not have been restarted/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Docker Compose/)).toBeInTheDocument();
  });

  it("passes the master password through to apply exactly once", async () => {
    await reachReview();
    await userEvent.type(
      screen.getByLabelText(/Label traffic with which stored credential was used/),
      "correct-horse-battery",
    );
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    await waitFor(() =>
      expect(mockApi.trackingApply).toHaveBeenCalledWith("correct-horse-battery"),
    );
    expect(mockApi.trackingApply).toHaveBeenCalledTimes(1);
  });

  it("sends null instead of an empty password when attribution is skipped", async () => {
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    await waitFor(() => expect(mockApi.trackingApply).toHaveBeenCalledWith(null));
  });
});
