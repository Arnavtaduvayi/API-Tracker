// The project activity panel (ADR 0029).
//
// The point of these tests is cost and token HONESTY on screen: an unpriced
// model must never render as "$0.00", an unknown provider must keep its
// universal metadata, and a partial total must be labelled as a floor.

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  ProjectActivitySnapshot,
  ProjectCostCoverage,
  ProjectSeriesPoint,
} from "../types";
import { ProjectActivity } from "./ProjectActivity";

// The whole api object is replaced, so every method the component might reach
// has to be listed or it is `undefined` at call time.
vi.mock("../api", () => ({
  api: {
    projectActivity: vi.fn(),
    projectNameUnknownApi: vi.fn(),
  },
  isApiError: (e: unknown) => typeof e === "object" && e !== null && "message" in e,
}));

import { api } from "../api";

const mocked = api as unknown as Record<string, ReturnType<typeof vi.fn>>;

function cost(over: Partial<ProjectCostCoverage> = {}): ProjectCostCoverage {
  return {
    estimated_micros: 0,
    currency: "USD",
    priced_requests: 0,
    priced_input_tokens: 0,
    priced_output_tokens: 0,
    known_input_tokens: 0,
    known_output_tokens: 0,
    unpriced_requests: 0,
    unpriced_tokens: 0,
    requests_with_unknown_usage: 0,
    token_coverage: null,
    complete: true,
    any_stale_pricing: false,
    truncated: false,
    priced: [],
    unpriced: [],
    ...over,
  };
}

function series(): ProjectSeriesPoint[] {
  return [
    {
      bucket_start: "2026-07-29T10:00:00Z",
      requests: 5,
      errors: 1,
      avg_latency_ms: 420,
      input_tokens: 1000,
      output_tokens: 500,
      estimated_micros: 2_500_000,
      cost_complete: true,
    },
  ];
}

function snapshot(over: Partial<ProjectActivitySnapshot> = {}): ProjectActivitySnapshot {
  return {
    project_id: "p1",
    since: "2026-07-28T10:00:00Z",
    until: null,
    granularity: "hour",
    metrics: {
      total: 5,
      success: 4,
      c2xx: 4,
      c3xx: 0,
      c4xx: 1,
      c5xx: 0,
      auth_errors: 0,
      forbidden: 0,
      rate_limited: 0,
      server_errors: 0,
      transport_errors: 0,
      tls_errors: 0,
      errors: 1,
      error_rate: 0.2,
      request_bytes: 100,
      response_bytes: 500,
      p50_ms: 420,
      p95_ms: 900,
      p99_ms: 1200,
      latency_approximate: true,
    },
    no_observations: false,
    series: series(),
    integrations: [],
    recent: [],
    cost: cost(),
    facets: {
      hosts: [],
      providers: [],
      models: [],
      status_classes: [],
      endpoints: [],
      observation_sources: [],
    },
    refreshed_at: "2026-07-29T11:00:00Z",
    ...over,
  };
}

describe("ProjectActivity", () => {
  beforeEach(() => {
    mocked.projectActivity.mockReset();
    mocked.projectNameUnknownApi.mockReset();
  });

  it("says it is waiting for the first request rather than showing zeroes", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        no_observations: true,
        series: [],
        metrics: { ...snapshot().metrics, total: 0, errors: 0, error_rate: 0 },
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    expect(await screen.findByTestId("awaiting-first-request")).toBeTruthy();
    expect(screen.queryByTestId("summary-cards")).toBeNull();
  });

  it("shows the summary cards for observed traffic", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        cost: cost({
          priced_requests: 5,
          priced_input_tokens: 1000,
          priced_output_tokens: 500,
          known_input_tokens: 1000,
          known_output_tokens: 500,
          estimated_micros: 2_500_000,
          token_coverage: 1,
          complete: true,
        }),
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    const cards = await screen.findByTestId("summary-cards");
    expect(cards.textContent).toContain("Requests");
    expect(cards.textContent).toContain("1,000");
    expect(cards.textContent).toContain("$2.5000");
    expect(cards.textContent).toContain("20.0%");
    expect(cards.textContent).toContain("420 ms");
  });

  /** The single most important assertion in this file. */
  it("never renders an unpriced cost as a dollar amount", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        cost: cost({
          estimated_micros: 0,
          priced_requests: 0,
          unpriced_requests: 5,
          unpriced_tokens: 12_400,
          token_coverage: 0,
          complete: false,
          unpriced: [
            {
              provider: "openai",
              model: "gpt-unpriced",
              requests: 5,
              input_tokens: 8_000,
              output_tokens: 4_400,
              reason: "no_pricing_record",
            },
          ],
        }),
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    const cards = await screen.findByTestId("summary-cards");
    expect(cards.textContent).not.toContain("$0.00");
    expect(cards.textContent).not.toContain("$0.0000");

    const coverage = screen.getByTestId("cost-coverage");
    expect(coverage.textContent).toContain("Cost is partial");
    expect(coverage.textContent).toContain("12,400 tokens");
    expect(coverage.textContent).toContain("5 request(s)");
  });

  /** Showing only PRICED tokens understates a project whose model has no local
   *  price, and silently drops cache reads. */
  it("reports every known token, not only the priced ones", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        cost: cost({
          priced_requests: 1,
          priced_input_tokens: 600,
          priced_output_tokens: 500,
          known_input_tokens: 1_070,
          known_output_tokens: 530,
          unpriced_requests: 1,
          unpriced_tokens: 100,
          token_coverage: 0.9,
          complete: false,
        }),
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    const cards = await screen.findByTestId("summary-cards");
    expect(cards.textContent).toContain("1,070");
    expect(cards.textContent).toContain("530");
    expect(cards.textContent).not.toContain("600");
  });

  it("states the priced-token coverage percentage", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        cost: cost({
          estimated_micros: 1_420_000,
          priced_requests: 8,
          priced_input_tokens: 60_000,
          priced_output_tokens: 16_000,
          known_input_tokens: 68_000,
          known_output_tokens: 20_400,
          unpriced_requests: 3,
          unpriced_tokens: 12_400,
          token_coverage: 0.86,
          complete: false,
        }),
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    const coverage = await screen.findByTestId("cost-coverage");
    expect(coverage.textContent).toContain("86% of token usage priced");
  });

  it("reports requests with no usage as unknown, not as zero tokens", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        cost: cost({
          requests_with_unknown_usage: 4,
          complete: false,
          unpriced: [
            {
              provider: "openai",
              model: "gpt-4o",
              requests: 4,
              input_tokens: null,
              output_tokens: null,
              reason: "usage_not_extracted",
            },
          ],
        }),
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    const coverage = await screen.findByTestId("cost-coverage");
    expect(coverage.textContent).toContain("reported no token usage");
    expect(coverage.textContent).toContain("unknown — not zero");
  });

  it("lists which models lack a price in an advanced drill-down", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        cost: cost({
          unpriced_requests: 2,
          unpriced_tokens: 100,
          complete: false,
          unpriced: [
            {
              provider: "openai",
              model: "gpt-mystery",
              requests: 2,
              input_tokens: 60,
              output_tokens: 40,
              reason: "no_pricing_record",
            },
          ],
        }),
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    const toggle = await screen.findByText("Review model pricing");
    expect(screen.queryByText("gpt-mystery")).toBeNull();
    fireEvent.click(toggle);
    expect(screen.getByText("gpt-mystery")).toBeTruthy();
    expect(screen.getByText("no local pricing record covers this model")).toBeTruthy();
  });

  it("says pricing was complete when it was", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        cost: cost({
          priced_requests: 5,
          priced_input_tokens: 10,
          priced_output_tokens: 10,
          known_input_tokens: 10,
          known_output_tokens: 10,
          estimated_micros: 500,
          token_coverage: 1,
          complete: true,
        }),
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    expect((await screen.findByTestId("cost-complete")).textContent).toContain(
      "Every request in this period was priced",
    );
  });

  it("keeps an unknown API visible with its universal metadata", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        integrations: [
          {
            host: "api.example.com",
            provider: null,
            user_provider: null,
            user_api_name: null,
            requests: 12,
            errors: 0,
            avg_latency_ms: 420,
            first_at: "2026-07-29T10:00:00Z",
            last_at: "2026-07-29T10:30:00Z",
            internal: false,
          },
        ],
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    const table = await screen.findByTestId("integrations");
    expect(table.textContent).toContain("Unknown API");
    expect(table.textContent).toContain("api.example.com");
    expect(table.textContent).toContain("12");
    expect(table.textContent).toContain("420 ms");
    expect(table.textContent).toContain("Cost estimation unavailable");
    expect(table.textContent).not.toContain("$0.00");
  });

  it("naming an unknown API sends only a display name", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        integrations: [
          {
            host: "api.example.com",
            provider: null,
            user_provider: null,
            user_api_name: null,
            requests: 1,
            errors: 0,
            avg_latency_ms: 100,
            first_at: "2026-07-29T10:00:00Z",
            last_at: "2026-07-29T10:00:00Z",
            internal: false,
          },
        ],
      }),
    );
    mocked.projectNameUnknownApi.mockResolvedValue(undefined);
    render(<ProjectActivity projectIdent="p1" enabled />);
    fireEvent.click(await screen.findByText("Name it"));
    fireEvent.change(screen.getByLabelText(/Name for api.example.com/), {
      target: { value: "Acme" },
    });
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() =>
      expect(mocked.projectNameUnknownApi).toHaveBeenCalledWith(
        "api.example.com",
        null,
        "Acme",
      ),
    );
  });

  it("shows an unavailable estimate in the recent table without a dollar sign", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        recent: [
          {
            id: "e1",
            at: "2026-07-29T10:00:00Z",
            host: "api.example.com",
            provider: null,
            method: "POST",
            endpoint: "/v1/chat",
            status_code: 500,
            status_class: "5xx",
            outcome: "server_error",
            latency_ms: 900,
            ttfb_ms: null,
            request_bytes: 10,
            response_bytes: 20,
            observation_source: "gateway",
            model: null,
            input_tokens: null,
            output_tokens: null,
            credential_id: null,
            attribution_confidence: null,
            estimated_micros: null,
            cost_complete: false,
          },
        ],
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    const table = await screen.findByTestId("recent-activity");
    expect(table.textContent).toContain("Unknown API");
    expect(table.textContent).toContain("/v1/chat");
    expect(table.textContent).toContain("900 ms");
    expect(table.textContent).toContain("not reported");
    expect(table.textContent).toContain("unavailable");
    expect(table.textContent).not.toContain("$0.0000");
  });

  it("labels a per-row partial estimate as a floor", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        recent: [
          {
            id: "e1",
            at: "2026-07-29T10:00:00Z",
            host: "api.openai.com",
            provider: "openai",
            method: "POST",
            endpoint: "/v1/chat",
            status_code: 200,
            status_class: "2xx",
            outcome: "success",
            latency_ms: 100,
            ttfb_ms: null,
            request_bytes: 10,
            response_bytes: 20,
            observation_source: "gateway",
            model: "half-priced",
            input_tokens: 100,
            output_tokens: 100,
            credential_id: null,
            attribution_confidence: null,
            estimated_micros: 1_000_000,
            cost_complete: false,
          },
        ],
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    const table = await screen.findByTestId("recent-activity");
    expect(table.textContent).toContain("$1.0000");
    expect(table.textContent).toContain("(floor)");
  });

  it("changing the time range refetches with the new range", async () => {
    mocked.projectActivity.mockResolvedValue(snapshot());
    render(<ProjectActivity projectIdent="p1" enabled />);
    await screen.findByTestId("summary-cards");
    expect(mocked.projectActivity).toHaveBeenCalledWith("p1", "24h", {}, 50);

    fireEvent.change(screen.getByLabelText("Activity time range"), { target: { value: "7d" } });
    await waitFor(() =>
      expect(mocked.projectActivity).toHaveBeenCalledWith("p1", "7d", {}, 50),
    );
  });

  it("a filter selection refetches with that filter", async () => {
    mocked.projectActivity.mockResolvedValue(
      snapshot({
        facets: {
          hosts: ["api.openai.com"],
          providers: ["openai"],
          models: ["gpt-4o"],
          status_classes: ["2xx"],
          endpoints: ["/v1/chat"],
          observation_sources: ["gateway"],
        },
      }),
    );
    render(<ProjectActivity projectIdent="p1" enabled />);
    await screen.findByTestId("activity-filters");
    fireEvent.change(screen.getByLabelText("Filter by provider"), {
      target: { value: "openai" },
    });
    await waitFor(() =>
      expect(mocked.projectActivity).toHaveBeenCalledWith(
        "p1",
        "24h",
        expect.objectContaining({ provider: "openai" }),
        50,
      ),
    );
  });

  it("a failed refresh reports the error and keeps the last good figures", async () => {
    mocked.projectActivity
      .mockResolvedValueOnce(snapshot())
      .mockRejectedValue({ code: "gw", message: "gateway unavailable" });
    render(<ProjectActivity projectIdent="p1" enabled />);
    await screen.findByTestId("summary-cards");

    fireEvent.click(screen.getByText("Refresh"));
    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toContain("gateway unavailable"),
    );
    // The cards are still there, showing the last successful read.
    expect(screen.getByTestId("summary-cards")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("last successful refresh");
  });

  it("does not fetch at all while disabled", () => {
    mocked.projectActivity.mockResolvedValue(snapshot());
    render(<ProjectActivity projectIdent="p1" enabled={false} />);
    expect(mocked.projectActivity).not.toHaveBeenCalled();
  });

  // AUD-08 — ADR 0029 says Refresh "resolves health"; it only re-read
  // observations, so a gateway that died with the page open went unreported
  // until the user navigated away and back.
  it("manual Refresh re-resolves health as well as re-reading observations", async () => {
    mocked.projectActivity.mockResolvedValue(snapshot());
    const onRefreshHealth = vi.fn();
    render(<ProjectActivity projectIdent="p1" enabled onRefreshHealth={onRefreshHealth} />);
    await screen.findByTestId("summary-cards");
    const readsBefore = mocked.projectActivity.mock.calls.length;
    expect(onRefreshHealth).not.toHaveBeenCalled();

    fireEvent.click(screen.getByText("Refresh"));

    await waitFor(() => expect(onRefreshHealth).toHaveBeenCalledTimes(1));
    expect(mocked.projectActivity.mock.calls.length).toBeGreaterThan(readsBefore);
  });

  it("the five-second timer refreshes observations only, never health", async () => {
    vi.useFakeTimers();
    try {
      mocked.projectActivity.mockResolvedValue(snapshot());
      const onRefreshHealth = vi.fn();
      render(<ProjectActivity projectIdent="p1" enabled onRefreshHealth={onRefreshHealth} />);
      // Several ticks of the shipped cadence.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(30_000);
      });
      expect(mocked.projectActivity.mock.calls.length).toBeGreaterThan(1);
      expect(
        onRefreshHealth,
        "resolving health performs guarded writes and probes the service; it does \
not belong on a timer",
      ).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("works without a health-refresh hook", async () => {
    mocked.projectActivity.mockResolvedValue(snapshot());
    render(<ProjectActivity projectIdent="p1" enabled />);
    await screen.findByTestId("summary-cards");
    fireEvent.click(screen.getByText("Refresh"));
    await waitFor(() => expect(mocked.projectActivity.mock.calls.length).toBeGreaterThan(1));
  });
});
