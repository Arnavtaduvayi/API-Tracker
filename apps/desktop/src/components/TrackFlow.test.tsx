// TrackFlow state rendering (TEST_PLAN §7). Load-bearing strings are
// asserted verbatim: the disclosure, the waiting instruction, the
// verified banner, the nothing-detected empty state, and the honest
// partial-apply report. Fetch failures must render an error, never an
// empty screen.
//
// The security-critical assertions here are the negative controls:
//
// * a repository-discovered destination is UNCHECKED, and clicking "Start
//   tracking" approves nothing (ZFT-004);
// * unrecognised credentials are enumerated with an exact count and never
//   a value (ZFT-010);
// * a stopped watch says so and can be re-armed (ZFT-015).
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TrackFlow } from "./TrackFlow";
import { api } from "../api";
import type {
  TrackingApplyReport,
  TrackingOriginRequest,
  TrackingPlan,
  TrackingScan,
} from "../types";

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
      trackingOriginRequests: vi.fn(),
      trackingOriginApprove: vi.fn(),
      trackingOriginRevoke: vi.fn(),
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
  trackingOriginRequests: ReturnType<typeof vi.fn>;
  trackingOriginApprove: ReturnType<typeof vi.fn>;
  trackingOriginRevoke: ReturnType<typeof vi.fn>;
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
        needs_origin_approval: false,
        unsupported_reason: null,
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
        needs_origin_approval: false,
        unsupported_reason:
          "This provider's SDK reads no base-URL setting, so Tethra has no way to route its traffic through the local service. Nothing about your setup is wrong.",
      },
    ],
    scanned_files: 3,
    skipped_oversized: 0,
    env_files: [".env"],
    already_tracking: false,
    coverage_lines: [
      "2 API integrations found",
      "1 can be tracked automatically",
      "1 use an SDK configuration Tethra cannot observe yet",
    ],
    coverage: {
      total: 2,
      tracked_automatically: 1,
      needs_origin_confirmation: 0,
      detected_unsupported: 1,
      unrecognized: 0,
      low_confidence: 0,
    },
    unrecognized: [],
    scan_gaps: null,
    git_warnings: [],
    ...overrides,
  };
}

/** A destination read out of the project's own files (ADR 0024). */
function originRequestFixture(
  over: Partial<TrackingOriginRequest> = {},
): TrackingOriginRequest {
  return {
    provider_id: "supabase",
    provider_display_name: "Supabase",
    origin: "https://attacker.example",
    scheme: "https",
    host: "attacker.example",
    port: 443,
    network_class: "public",
    source_file: ".env",
    source_var: "SUPABASE_URL",
    forwards_credentials: true,
    trust: "repository_discovered",
    question: "Allow this project to send API traffic through https://attacker.example?",
    disclosure: [
      "Destination: https://attacker.example (host attacker.example, port 443)",
      "Provider: Supabase",
      "Why Tethra suggests it: SUPABASE_URL in .env — this value comes from the project, not from Tethra",
      "If you allow it, requests carrying this project's API credential will be forwarded to that host.",
      "The host is a public internet address.",
    ],
    previously_approved_at: null,
    approved_now: false,
    refusal: null,
    ...over,
  };
}

/**
 * A provider Tethra recognises but whose destination is nowhere in the
 * project, so the user has to type it. No fixture anywhere exercised this
 * configurability before RA-012.
 */
function needsInputScan(): TrackingScan {
  return scanFixture({
    providers: [
      {
        provider_id: "self-hosted",
        display_name: "Self-hosted LLM",
        confidence: "likely",
        configurability: "needs_origin_input",
        inferred_origin: null,
        evidence: ["Found LLM_API_KEY in .env (value not read)"],
        limitations: [],
        credential_candidates: [],
        selected_by_default: false,
        needs_origin_approval: true,
        unsupported_reason: null,
      },
    ],
    coverage_lines: ["1 API integration found", "1 needs you to say where its traffic goes"],
    coverage: {
      total: 1,
      tracked_automatically: 0,
      needs_origin_confirmation: 1,
      detected_unsupported: 0,
      unrecognized: 0,
      low_confidence: 0,
    },
  });
}

/**
 * What `tracking_origin_approve` returns for a TYPED destination
 * (main.rs `origin_request_dto`): the same shared disclosure the inferred
 * path gets, with no source file/variable because the user supplied it.
 */
function typedApprovalFixture(
  over: Partial<TrackingOriginRequest> = {},
): TrackingOriginRequest {
  return originRequestFixture({
    provider_id: "self-hosted",
    provider_display_name: "Self-hosted LLM",
    origin: "https://llm.corp.example",
    host: "llm.corp.example",
    source_file: null,
    source_var: null,
    question: "Allow this project to send API traffic through https://llm.corp.example?",
    disclosure: [
      "Destination: https://llm.corp.example (host llm.corp.example, port 443)",
      "Provider: Self-hosted LLM",
      "Why Tethra suggests it: read from this project's configuration, not from Tethra",
      "If you allow it, requests carrying this project's API credential will be forwarded to that host.",
      "The host is a public internet address.",
    ],
    approved_now: true,
    ...over,
  });
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

function waitingStatus() {
  return {
    setup_id: "setup-1",
    state: "awaiting_restart",
    project_id: "p1",
    folder: "/Users/dev/my-app",
    watch: "waiting" as const,
    observed_provider: null,
    observed_latency_ms: null,
    observed_model: null,
    providers: [],
    attribution_paused: false,
    health: {
      kind: "waiting_for_first_request" as const,
      sentence: "waiting for the first request",
      currently_working: false,
    },
    history: {
      first_verified_at: null,
      session_first_observed_at: null,
      verification_session: null,
      config_generation: 1,
      sentence: null,
    },
  };
}

async function reachReview() {
  openDialog.mockResolvedValue("/Users/dev/my-app");
  render(<TrackFlow onDone={() => {}} onOpenAdvanced={() => {}} />);
  await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
  await screen.findByText("2 API integrations found");
}

beforeEach(() => {
  vi.clearAllMocks();
  mockApi.trackingScan.mockResolvedValue(scanFixture());
  mockApi.trackingOriginRequests.mockResolvedValue([]);
  mockApi.trackingPlanBuild.mockResolvedValue(planFixture());
  mockApi.trackingApply.mockResolvedValue(applyFixture());
  mockApi.trackingStatus.mockResolvedValue(waitingStatus());
});

describe("TrackFlow review screen", () => {
  it("leads with the coverage summary and shows the exact diff", async () => {
    await reachReview();
    expect(screen.getByText("1 can be tracked automatically")).toBeInTheDocument();
    expect(
      screen.getByText("1 use an SDK configuration Tethra cannot observe yet"),
    ).toBeInTheDocument();
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
    await userEvent.click(screen.getByRole("button", { name: "Review this API" }));
    expect(
      screen.getByText(/reads no base-URL setting, so Tethra has no way to route/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start tracking" })).toBeEnabled();
  });

  it("offers only in-app actions for an unsupported API, never a CLI command", async () => {
    await reachReview();
    expect(
      screen.getByRole("button", { name: "Copy manual setup instructions" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Add a custom destination" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy a provider-support request" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open advanced settings" })).toBeInTheDocument();
    // The negative control: no shell instruction anywhere on the screen.
    expect(document.body.textContent).not.toMatch(/tethra provider list/);
    expect(document.body.textContent).not.toMatch(/tethra gateway route add/);
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
    mockApi.trackingScan.mockResolvedValue(
      scanFixture({
        providers: [],
        scanned_files: 7,
        coverage_lines: ["0 API integrations found"],
        coverage: {
          total: 0,
          tracked_automatically: 0,
          needs_origin_confirmation: 0,
          detected_unsupported: 0,
          unrecognized: 0,
          low_confidence: 0,
        },
      }),
    );
    openDialog.mockResolvedValue("/Users/dev/empty");
    render(<TrackFlow onDone={() => {}} onOpenAdvanced={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    expect(await screen.findByText("0 API integrations found")).toBeInTheDocument();
    expect(screen.getByText(/7 file\(s\) read, 6 levels deep/)).toBeInTheDocument();
    // The dead end is replaced by an in-app route.
    expect(
      screen.getByRole("button", { name: "Add a destination by hand (Advanced)" }),
    ).toBeInTheDocument();
  });

  it("reports what the scan could not inspect instead of implying full coverage", async () => {
    mockApi.trackingScan.mockResolvedValue(
      scanFixture({
        scan_gaps: "2 too large to read; 1 outside the selected folder (symlink)",
        git_warnings: ["the Git packed-refs file was larger than the read limit"],
      }),
    );
    await reachReview();
    expect(
      screen.getByText(/Not everything could be inspected: 2 too large to read/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/packed-refs file was larger than the read limit/),
    ).toBeInTheDocument();
  });
});

describe("TrackFlow scope statement (ZFT-009)", () => {
  it("states the supported scope BEFORE the user picks a folder", async () => {
    render(<TrackFlow onDone={() => {}} />);
    expect(
      screen.getByRole("heading", { name: "What Tethra can and cannot track" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/pointing its SDK's base-URL setting at a local address/),
    ).toBeInTheDocument();
    // Still on the idle screen: the scope is not a post-hoc excuse.
    expect(screen.getByRole("button", { name: "Select project folder" })).toBeInTheDocument();
  });
});

describe("TrackFlow unrecognised credentials (ZFT-010)", () => {
  const many = Array.from({ length: 15 }, (_, i) => ({
    var: `SERVICE_${i}_API_KEY`,
    file: ".env",
    name_hint: i === 0 ? "groq" : null,
  }));

  it("enumerates unrecognised variables with an exact count and no values", async () => {
    mockApi.trackingScan.mockResolvedValue(
      scanFixture({
        unrecognized: [{ var: "GROQ_API_KEY", file: ".env", name_hint: "groq" }],
        coverage_lines: [
          "3 API integrations found",
          "1 could not be identified — Tethra has no provider definition for them",
        ],
        coverage: {
          total: 3,
          tracked_automatically: 1,
          needs_origin_confirmation: 0,
          detected_unsupported: 1,
          unrecognized: 1,
          low_confidence: 0,
        },
      }),
    );
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    expect(await screen.findByText("Not recognised (1)")).toBeInTheDocument();
    expect(screen.getByText("GROQ_API_KEY")).toBeInTheDocument();
    expect(screen.getByText(/looks like groq/)).toBeInTheDocument();
    expect(screen.getByText("in .env")).toBeInTheDocument();
    expect(screen.getByText(/never a value/)).toBeInTheDocument();
  });

  it("bounds the enumeration but never the count", async () => {
    mockApi.trackingScan.mockResolvedValue(scanFixture({ unrecognized: many }));
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    expect(await screen.findByText("Not recognised (15)")).toBeInTheDocument();
    expect(screen.getByText("SERVICE_0_API_KEY")).toBeInTheDocument();
    expect(screen.queryByText("SERVICE_14_API_KEY")).not.toBeInTheDocument();
    expect(screen.getByText(/… and 3 more, all counted in the 15 above\./)).toBeInTheDocument();
  });
});

describe("TrackFlow destination approval (ZFT-004)", () => {
  beforeEach(() => {
    mockApi.trackingOriginRequests.mockResolvedValue([originRequestFixture()]);
    mockApi.trackingScan.mockResolvedValue(
      scanFixture({
        coverage_lines: [
          "3 API integrations found",
          "1 need you to confirm where their traffic goes",
        ],
      }),
    );
  });

  it("ships every repository-discovered destination UNCHECKED", async () => {
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    const box = await screen.findByRole("checkbox", { name: /attacker\.example/ });
    expect(box).not.toBeChecked();
  });

  it("shows the full disclosure the shared Rust request renders", async () => {
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    expect(
      await screen.findByText(
        "Allow this project to send API traffic through https://attacker.example?",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /Destination: https:\/\/attacker\.example \(host attacker\.example, port 443\)/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/SUPABASE_URL in \.env/)).toBeInTheDocument();
    expect(
      screen.getByText(/requests carrying this project's API credential will be forwarded/),
    ).toBeInTheDocument();
    expect(screen.getByText("The host is a public internet address.")).toBeInTheDocument();
  });

  it("does not approve a destination when Start tracking is clicked", async () => {
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    await screen.findByRole("checkbox", { name: /attacker\.example/ });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Start tracking" })).toBeEnabled(),
    );
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    await waitFor(() => expect(mockApi.trackingApply).toHaveBeenCalled());
    expect(mockApi.trackingOriginApprove).not.toHaveBeenCalled();
    // Only the manifest-origin provider was ever planned.
    expect(mockApi.trackingPlanBuild).toHaveBeenLastCalledWith(["openai"]);
  });

  it("approves exactly one destination, only when its own box is ticked", async () => {
    mockApi.trackingOriginApprove.mockResolvedValue(
      originRequestFixture({ approved_now: true }),
    );
    mockApi.trackingOriginRequests
      .mockResolvedValueOnce([originRequestFixture()])
      .mockResolvedValue([originRequestFixture({ approved_now: true })]);
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    await userEvent.click(await screen.findByRole("checkbox", { name: /attacker\.example/ }));
    await waitFor(() =>
      expect(mockApi.trackingOriginApprove).toHaveBeenCalledWith(
        "supabase",
        "https://attacker.example",
      ),
    );
    await waitFor(() =>
      expect(mockApi.trackingPlanBuild).toHaveBeenLastCalledWith(["openai", "supabase"]),
    );
  });

  it("keeps a previously approved destination unchecked and says so", async () => {
    mockApi.trackingOriginRequests.mockResolvedValue([
      originRequestFixture({ previously_approved_at: "2026-07-01T09:00:00Z" }),
    ]);
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    const box = await screen.findByRole("checkbox", { name: /attacker\.example/ });
    expect(box).not.toBeChecked();
    expect(
      screen.getByText(/approving it again is your decision, not a memory/),
    ).toBeInTheDocument();
  });

  it("explains a refused destination instead of dropping it", async () => {
    mockApi.trackingOriginRequests.mockResolvedValue([
      originRequestFixture({
        refusal: "origin 'http://10.0.0.5' is a private network address",
        question: "Tethra will not send traffic to http://10.0.0.5.",
      }),
    ]);
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    expect(await screen.findByText(/is a private network address/)).toBeInTheDocument();
    expect(
      screen.queryByRole("checkbox", { name: /attacker\.example/ }),
    ).not.toBeInTheDocument();
  });

  it("renders a failed approval read without pretending nothing was found", async () => {
    mockApi.trackingOriginRequests.mockRejectedValue({
      code: "locked",
      message: "the vault is locked",
    });
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    expect(
      await screen.findByText(/The destinations could not be reviewed: the vault is locked/),
    ).toBeInTheDocument();
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
      ...waitingStatus(),
      state: "traffic_observed",
      watch: "observed",
      observed_provider: "anthropic",
      observed_latency_ms: 201,
      observed_model: "claude-fable-5",
      providers: [{ provider_id: "anthropic", last_observed_at: "2026-07-27T00:00:00Z" }],
      health: {
        kind: "verified_and_active",
        sentence: "tracking verified and active",
        currently_working: true,
      },
    });
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    expect(await screen.findByText("Tracking verified")).toBeInTheDocument();
    expect(
      screen.getByText(/Observed anthropic from \/Users\/dev\/my-app/),
    ).toBeInTheDocument();
    expect(screen.getByText(/201 ms/)).toBeInTheDocument();
  });

  it("never claims verified when the gateway is down, even with an observation", async () => {
    // ZFT-005 was closed on the dashboard but left open HERE. `watch` comes
    // from `check_traffic`, which is liveness-blind by construction, so a
    // setup whose gateway had died still reached the terminal phase and
    // rendered the unqualified headline "Tracking verified". Found by an
    // adversarial reviewer, not by the test written for the finding.
    mockApi.trackingStatus.mockResolvedValue({
      ...waitingStatus(),
      state: "traffic_observed",
      watch: "observed",
      observed_provider: "anthropic",
      providers: [{ provider_id: "anthropic", last_observed_at: "2026-07-27T00:00:00Z" }],
      health: {
        kind: "verified_previously_gateway_down",
        sentence:
          "verified previously — the local tracking service is not running, so requests are not reaching your APIs",
        currently_working: false,
      },
    });
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    // Whatever it shows, it must carry the reason...
    expect(await screen.findByText(/not reaching your APIs/)).toBeInTheDocument();
    // ...and it must not be an unqualified success headline.
    expect(screen.queryByText("Tracking verified")).not.toBeInTheDocument();
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
    expect(
      screen.queryByText(/Tethra stops that helper when it quits/),
    ).not.toBeInTheDocument();
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

  it("carries the ADR-0020 oracle disclosure into the primary flow (ZFT-013)", async () => {
    await reachReview();
    const field = screen
      .getByLabelText(/Label traffic with which stored credential was used/)
      .closest(".field") as HTMLElement;
    expect(within(field).getByText(/matching-only key/)).toBeInTheDocument();
    expect(
      within(field).getByText(/gains an oracle for testing whether a value matches/),
    ).toBeInTheDocument();
    expect(
      within(field).getByText(
        /dropped when the service stops, when you revoke it, and when the vault locks/,
      ),
    ).toBeInTheDocument();
    expect(
      within(field).getByText(/only credentials in linked, non-password-locked projects/),
    ).toBeInTheDocument();
  });
});

describe("TrackFlow typed destination approval (RA-012)", () => {
  /** Reach the review screen for a provider whose origin must be typed. */
  async function reachTypedReview() {
    mockApi.trackingScan.mockResolvedValue(needsInputScan());
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    await screen.findByText("1 API integration found");
  }

  const box = () =>
    screen.getByRole("checkbox", {
      name: /Allow this project to send API traffic through this address/,
    });

  it("renders the backend's own disclosure for a destination the user typed", async () => {
    mockApi.trackingOriginApprove.mockResolvedValue(typedApprovalFixture());
    await reachTypedReview();

    // The negative control: before the box is ticked the screen shows the
    // user's own string and nothing else. If these passed before the click
    // the assertions below would prove nothing about the approval call.
    expect(
      screen.queryByText(
        "Allow this project to send API traffic through https://llm.corp.example?",
      ),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/will be forwarded to that host/)).not.toBeInTheDocument();

    await userEvent.type(screen.getByLabelText(/Its project URL/), "https://llm.corp.example");
    await userEvent.click(box());

    await waitFor(() =>
      expect(mockApi.trackingOriginApprove).toHaveBeenCalledWith(
        "self-hosted",
        "https://llm.corp.example",
      ),
    );
    // Every line the shared Rust request renders, not a paraphrase.
    expect(
      await screen.findByText(
        "Allow this project to send API traffic through https://llm.corp.example?",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Destination: https://llm.corp.example (host llm.corp.example, port 443)",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Provider: Self-hosted LLM")).toBeInTheDocument();
    expect(
      screen.getByText(
        /requests carrying this project's API credential will be forwarded to that host/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("The host is a public internet address.")).toBeInTheDocument();
    expect(box()).toBeChecked();
  });

  it("never leaves the tick beside an address other than the approved one", async () => {
    mockApi.trackingOriginApprove.mockResolvedValue(typedApprovalFixture());
    // The withdrawal is still IN FLIGHT while the user keeps typing. The tick
    // must not wait on it to stop claiming an approval for an address that is
    // no longer the one on screen — approval is granted for one exact
    // destination, so it can only ever be shown against that one.
    mockApi.trackingOriginRevoke.mockReturnValue(new Promise<void>(() => {}));
    await reachTypedReview();
    const field = screen.getByLabelText(/Its project URL/);
    await userEvent.type(field, "https://llm.corp.example");
    await userEvent.click(box());
    await waitFor(() => expect(box()).toBeChecked());

    await userEvent.type(field, "x");
    await waitFor(() => expect(box()).not.toBeChecked());
    expect(mockApi.trackingOriginRevoke).toHaveBeenCalledWith("self-hosted");
    expect(
      screen.queryByText(
        "Destination: https://llm.corp.example (host llm.corp.example, port 443)",
      ),
    ).not.toBeInTheDocument();
  });

  it("drops the approval and the selection when the approve call fails", async () => {
    mockApi.trackingOriginApprove.mockRejectedValue({
      code: "invalid_input",
      message: "origin 'https://llm.corp.example' is a private network address",
    });
    await reachTypedReview();
    const requestReadsBefore = mockApi.trackingOriginRequests.mock.calls.length;

    await userEvent.type(screen.getByLabelText(/Its project URL/), "https://llm.corp.example");
    await userEvent.click(box());

    expect(await screen.findByText(/is a private network address/)).toBeInTheDocument();
    // The tick reflects the BACKEND, not the click...
    expect(box()).not.toBeChecked();
    // ...the destination the user never got approved cannot reach a plan...
    expect(mockApi.trackingPlanBuild).not.toHaveBeenCalledWith(["self-hosted"]);
    expect(
      screen.getByText(/nothing is selected, so there is nothing to configure/),
    ).toBeInTheDocument();
    // ...and the backend was re-read, as the inferred path does on failure.
    await waitFor(() =>
      expect(mockApi.trackingOriginRequests.mock.calls.length).toBeGreaterThan(
        requestReadsBefore,
      ),
    );
  });

  it("drops the selection when the WITHDRAWAL fails, not just the approval", async () => {
    mockApi.trackingOriginApprove.mockResolvedValue(typedApprovalFixture());
    mockApi.trackingOriginRevoke.mockRejectedValue({
      code: "no_session",
      message: "no folder has been scanned yet",
    });
    await reachTypedReview();
    await userEvent.type(screen.getByLabelText(/Its project URL/), "https://llm.corp.example");
    await userEvent.click(box());
    await waitFor(() => expect(box()).toBeChecked());
    await waitFor(() =>
      expect(mockApi.trackingPlanBuild).toHaveBeenLastCalledWith(["self-hosted"]),
    );

    // The user unticks and the withdrawal fails. The backend may still hold
    // that approval, and `tracking_plan_build` reads the destination from
    // there — so leaving the provider selected would configure an origin the
    // user has just said they do not want. Fail closed instead.
    await userEvent.click(box());
    expect(await screen.findByText(/no folder has been scanned yet/)).toBeInTheDocument();
    expect(box()).not.toBeChecked();
    await waitFor(() =>
      expect(
        screen.getByText(/nothing is selected, so there is nothing to configure/),
      ).toBeInTheDocument(),
    );
  });
});

describe("TrackFlow recurring poll (ZFT-015)", () => {
  // No other test in this suite uses fake timers, which is why deleting the
  // `setInterval` in the waiting effect kept the whole suite green while
  // reproducing the original ZFT-015 symptom exactly: one poll, then
  // "Waiting for traffic…" forever with nothing watching (RA-014).
  //
  // These tests drive the DOM with `fireEvent` and settle promises with
  // `flushPromises`, deliberately using neither `userEvent` nor `waitFor`:
  // both wait on real wall-clock timers that `vi.useFakeTimers` has frozen,
  // so under a fake clock they hang instead of failing.
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  /** Settle pending promise chains without touching the (frozen) clock. */
  async function flushPromises() {
    for (let i = 0; i < 10; i += 1) {
      await act(async () => {
        await Promise.resolve();
      });
    }
  }

  /** Reach the waiting screen, where the poll lives. */
  async function reachWaiting() {
    openDialog.mockResolvedValue("/Users/dev/my-app");
    render(<TrackFlow onDone={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Select project folder" }));
    await flushPromises();
    expect(screen.getByText("2 API integrations found")).toBeInTheDocument();
    const start = screen.getByRole("button", { name: "Start tracking" });
    expect(start).toBeEnabled();
    fireEvent.click(start);
    await flushPromises();
    expect(screen.getByText("Configuration applied")).toBeInTheDocument();
  }

  /** Let the fake clock run, then settle whatever the ticks started. */
  async function advance(ms: number) {
    await act(async () => {
      vi.advanceTimersByTime(ms);
    });
    await flushPromises();
  }

  it("polls AGAIN on the interval, so traffic that arrives later is still seen", async () => {
    await reachWaiting();
    expect(mockApi.trackingStatus).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/Waiting for traffic…/)).toBeInTheDocument();

    // The request the user makes AFTER the immediate first poll. Only a
    // RECURRING poll can see it — this is the whole point of the interval.
    mockApi.trackingStatus.mockResolvedValue({
      ...waitingStatus(),
      state: "traffic_observed",
      watch: "observed",
      observed_provider: "openai",
      health: {
        kind: "verified_and_active",
        sentence: "tracking verified and active",
        currently_working: true,
      },
    });
    await advance(2000);

    expect(mockApi.trackingStatus).toHaveBeenCalledTimes(2);
    expect(screen.getByText("Tracking verified")).toBeInTheDocument();
  });

  it("stops watching after two minutes and says so instead of claiming to wait", async () => {
    mockApi.trackingDiagnose.mockResolvedValue([
      {
        id: "not_restarted",
        severity: "hint",
        message: "The project may not have been restarted.",
      },
    ]);
    await reachWaiting();
    expect(mockApi.trackingStatus).toHaveBeenCalledTimes(1);

    // Just under the cutoff: still watching, and still saying so.
    await advance(118_000);
    expect(screen.getByText(/Waiting for traffic…/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Check again" })).not.toBeInTheDocument();

    // At the cutoff the watch ENDS, and the screen must stop implying it.
    await advance(2000);
    expect(
      screen.getByText(/Tethra stopped watching after two minutes with no traffic/),
    ).toBeInTheDocument();
    expect(screen.getByText(/It is not watching now/)).toBeInTheDocument();
    expect(screen.queryByText(/Waiting for traffic…/)).not.toBeInTheDocument();
    expect(mockApi.trackingDiagnose).toHaveBeenCalledWith("setup-1");
    expect(screen.getByRole("button", { name: "Check again" })).toBeInTheDocument();

    // And it really did stop: nothing polls on its own after the cutoff.
    const callsAtCutoff = mockApi.trackingStatus.mock.calls.length;
    await advance(10_000);
    expect(mockApi.trackingStatus).toHaveBeenCalledTimes(callsAtCutoff);
  });
});

describe("TrackFlow watch re-arm (ZFT-015)", () => {
  it("says watching has stopped after a poll failure and offers Check again", async () => {
    mockApi.trackingStatus.mockRejectedValue({
      code: "ipc",
      message: "the desktop backend did not answer",
    });
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    expect(
      await screen.findByText(
        /Watching stopped because the tracking state could not be read: the desktop backend did not answer/,
      ),
    ).toBeInTheDocument();
    // The negative control: the screen must NOT still claim it is waiting.
    expect(screen.queryByText(/Waiting for traffic…/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check again" })).toBeInTheDocument();
  });

  it("re-arms the poll when Check again is clicked, so an error is not terminal", async () => {
    mockApi.trackingStatus.mockRejectedValueOnce({
      code: "ipc",
      message: "the desktop backend did not answer",
    });
    await reachReview();
    await userEvent.click(screen.getByRole("button", { name: "Start tracking" }));
    await screen.findByRole("button", { name: "Check again" });
    const callsBefore = mockApi.trackingStatus.mock.calls.length;

    mockApi.trackingStatus.mockResolvedValue({
      ...waitingStatus(),
      state: "traffic_observed",
      watch: "observed",
      observed_provider: "openai",
      health: {
        kind: "verified_and_active",
        sentence: "tracking verified and active",
        currently_working: true,
      },
    });
    await userEvent.click(screen.getByRole("button", { name: "Check again" }));
    await waitFor(() =>
      expect(mockApi.trackingStatus.mock.calls.length).toBeGreaterThan(callsBefore),
    );
    expect(await screen.findByText("Tracking verified")).toBeInTheDocument();
  });
});
