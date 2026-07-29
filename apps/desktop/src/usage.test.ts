// The one rule that decides whether a token or cost number may be shown
// (NEW-37). Every assertion here is about a number Tethra does NOT know:
// the failure mode is a fabricated 0 or $0.0000 presented next to real
// counts, so the negative controls matter more than the positive ones.

import { describe, expect, it } from "vitest";
import type { GatewayActivitySummary, UsageSnapshot } from "./types";
import {
  GATEWAY_ESTIMATED_COST,
  GATEWAY_TOKENS,
  PROJECT_REPORTED_COST,
  RECORD_ESTIMATED_COST,
  RECORD_REPORTED_COST,
  RECORD_TOKENS,
  type UsageAvailability,
  ambiguousSumAvailability,
  availabilityNote,
  availabilitySentence,
  formatCostMicros,
  formatCount,
  formatTokenPair,
  fromCoverage,
  gatewayCostAvailability,
  gatewayTokenAvailability,
  hasValue,
  markStale,
  snapshotCostAvailability,
  snapshotCoverage,
  snapshotTokenAvailability,
} from "./usage";

function summary(over: Partial<GatewayActivitySummary> = {}): GatewayActivitySummary {
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

function snapshot(over: Partial<UsageSnapshot> = {}): UsageSnapshot {
  return {
    id: "u1",
    credential_id: null,
    project_id: null,
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

describe("the coverage predicate", () => {
  it("calls a number known only when every record in scope carried it", () => {
    expect(fromCoverage(5, 5)).toEqual({ kind: "known", covered: 5, total: 5 });
  });

  it("calls a mixed fold partial, naming how many records contributed", () => {
    expect(fromCoverage(3, 500)).toEqual({ kind: "partial", covered: 3, total: 500 });
  });

  it("calls a fold over records that all carried nothing unknown, never zero", () => {
    expect(fromCoverage(0, 42)).toEqual({ kind: "unknown", total: 42 });
  });

  it("calls an empty scope unknown rather than a measured zero", () => {
    expect(fromCoverage(0, 0)).toEqual({ kind: "unknown", total: 0 });
  });

  it("only lets known, partial and stale carry a value", () => {
    expect(hasValue({ kind: "known", covered: 1, total: 1 })).toBe(true);
    expect(hasValue({ kind: "partial", covered: 1, total: 2 })).toBe(true);
    expect(hasValue({ kind: "stale", asOf: null, covered: 1, total: 1 })).toBe(true);
    expect(hasValue({ kind: "unknown", total: 1 })).toBe(false);
    expect(hasValue({ kind: "unsupported", detail: "x" })).toBe(false);
    expect(hasValue({ kind: "unavailable", reason: "x" })).toBe(false);
  });

  it("does not let staleness promote an unknown into something showable", () => {
    expect(markStale({ kind: "unknown", total: 3 }, "2026-07-01T00:00:00Z")).toEqual({
      kind: "unknown",
      total: 3,
    });
    expect(markStale({ kind: "known", covered: 2, total: 2 }, "2026-07-01T00:00:00Z")).toEqual({
      kind: "stale",
      asOf: "2026-07-01T00:00:00Z",
      covered: 2,
      total: 2,
    });
  });
});

describe("rendering never fabricates a number (NEW-37 regression)", () => {
  // The exact strings the audited dashboard printed for an unknown.
  it("renders no 0 and no $0.0000 for an unknown token or cost figure", () => {
    const unknown: UsageAvailability = { kind: "unknown", total: 42 };
    const tokens = formatTokenPair(0, 0, unknown, GATEWAY_TOKENS);
    const cost = formatCostMicros(0, unknown, GATEWAY_ESTIMATED_COST, 4);
    expect(tokens).not.toMatch(/\b0 in\b/);
    expect(tokens).not.toMatch(/\b0 \/ 0\b/);
    expect(cost).not.toMatch(/\$/);
    expect(cost).not.toMatch(/0\.0000/);
    expect(tokens).toMatch(/Tokens not reported/);
    expect(cost).toMatch(/Estimated cost not reported/);
  });

  it("renders no number when the value itself is null", () => {
    const known: UsageAvailability = { kind: "known", covered: 1, total: 1 };
    expect(formatCount(null, known, RECORD_TOKENS)).toMatch(/not reported|unavailable/);
    expect(formatCostMicros(null, known, RECORD_REPORTED_COST)).not.toMatch(/\$/);
  });

  it("still renders a genuine zero, because hiding a measurement is a different lie", () => {
    const known: UsageAvailability = { kind: "known", covered: 5, total: 5 };
    expect(formatCount(0, known, RECORD_TOKENS)).toBe("0");
    expect(formatCostMicros(0, known, GATEWAY_ESTIMATED_COST, 4)).toBe("$0.0000");
    expect(formatTokenPair(0, 0, known, GATEWAY_TOKENS)).toBe("0 in / 0 out");
  });

  it("labels a partial total with the count that contributed", () => {
    const partial: UsageAvailability = { kind: "partial", covered: 3, total: 500 };
    const rendered = formatTokenPair(900, 100, partial, GATEWAY_TOKENS);
    expect(rendered).toMatch(/^900 in \/ 100 out/);
    expect(rendered).toMatch(/Partial token data: 3 of 500 response\(s\)/);
    expect(rendered).toMatch(/not counted as zero/);
  });

  it("dates a stale figure instead of presenting it as current", () => {
    const stale: UsageAvailability = {
      kind: "stale",
      asOf: "2026-07-01T00:00:00Z",
      covered: 4,
      total: 4,
    };
    const rendered = formatCostMicros(2_500_000, stale, RECORD_REPORTED_COST);
    expect(rendered).toMatch(/^\$2\.50/);
    expect(rendered).toMatch(/as of 2026-07-01T00:00:00Z/);
    expect(rendered).toMatch(/newer usage is missing/);
  });

  it("says a load failure is a load failure, not an absence", () => {
    const unavailable: UsageAvailability = {
      kind: "unavailable",
      reason: "the vault is locked",
    };
    const rendered = formatCount(7, unavailable, RECORD_TOKENS);
    expect(rendered).toBe("Tokens unavailable — the vault is locked");
    expect(rendered).not.toMatch(/\b7\b/);
  });

  it("distinguishes 'this provider never reports it' from 'it was not reported'", () => {
    const unsupported: UsageAvailability = {
      kind: "unsupported",
      detail: "these 2 record(s) are metered in events, not tokens",
    };
    expect(availabilitySentence(unsupported, RECORD_TOKENS)).toBe(
      "Tokens not reported by this provider — these 2 record(s) are metered in events, not tokens",
    );
    expect(availabilitySentence({ kind: "unknown", total: 2 }, RECORD_TOKENS)).toMatch(
      /none of the 2 usage record\(s\) carried a token count/,
    );
  });

  it("renders sentences, never internal enum tokens (ZFT-030)", () => {
    const all: UsageAvailability[] = [
      { kind: "unknown", total: 0 },
      { kind: "unknown", total: 9 },
      { kind: "unsupported", detail: "metered in events" },
      { kind: "unavailable", reason: "the read failed" },
    ];
    for (const a of all) {
      const sentence = availabilitySentence(a, GATEWAY_TOKENS);
      expect(sentence).not.toMatch(/^[a-z_]+$/);
      expect(sentence).not.toMatch(/unsupported_shape|oversized_dropped|usage_event_count/);
      expect(sentence).toMatch(/ /);
    }
    expect(
      availabilityNote({ kind: "known", covered: 1, total: 1 }, GATEWAY_TOKENS),
    ).toBeNull();
  });
});

describe("gateway activity summary", () => {
  it("treats a window where every response carried usage as known", () => {
    const a = gatewayTokenAvailability(
      summary({ total_requests: 4, usage_event_count: 4, input_tokens: 10, output_tokens: 5 }),
    );
    expect(a).toEqual({ kind: "known", covered: 4, total: 4 });
  });

  it("treats real traffic with no extracted usage as unknown (the audited case)", () => {
    const s = summary({ total_requests: 42, success_count: 42, usage_event_count: 0 });
    expect(gatewayTokenAvailability(s).kind).toBe("unknown");
    expect(gatewayCostAvailability(s).kind).toBe("unknown");
    expect(
      formatTokenPair(s.input_tokens, s.output_tokens, gatewayTokenAvailability(s)),
    ).not.toMatch(/0/);
  });

  it("treats a provider that never reports tokens exactly like any other absence", () => {
    // google-gemini, cohere, langsmith, replicate and supabase declare
    // usage_shape = "", so no usage row is ever written for them.
    const s = summary({ total_requests: 120, success_count: 120, usage_event_count: 0 });
    expect(gatewayTokenAvailability(s)).toEqual({ kind: "unknown", total: 120 });
  });

  it("labels a window where only some responses carried usage as partial", () => {
    expect(
      gatewayTokenAvailability(summary({ total_requests: 500, usage_event_count: 3 })),
    ).toEqual({ kind: "partial", covered: 3, total: 500 });
  });

  it("keeps a measured zero measured", () => {
    const s = summary({
      total_requests: 5,
      usage_event_count: 5,
      input_tokens: 0,
      output_tokens: 0,
      estimated_cost_micros: 0,
    });
    expect(gatewayTokenAvailability(s).kind).toBe("known");
    // Zero tokens at any price is zero cost: a DERIVED known zero.
    expect(gatewayCostAvailability(s).kind).toBe("known");
    expect(formatCostMicros(0, gatewayCostAvailability(s), GATEWAY_ESTIMATED_COST, 4)).toBe(
      "$0.0000",
    );
  });

  it("does not price tokens it could not price (cost estimation unsupported)", () => {
    // writer.rs stores cost.unwrap_or(0) when no pricing row covers the
    // model, so tokens are known while the price is not.
    const s = summary({
      total_requests: 3,
      usage_event_count: 3,
      input_tokens: 900,
      output_tokens: 120,
      estimated_cost_micros: 0,
    });
    expect(gatewayTokenAvailability(s).kind).toBe("known");
    const cost = gatewayCostAvailability(s);
    expect(cost.kind).toBe("unknown");
    const rendered = formatCostMicros(s.estimated_cost_micros, cost, GATEWAY_ESTIMATED_COST, 4);
    expect(rendered).not.toMatch(/\$/);
    expect(rendered).toMatch(/no local price covers the model/);
  });

  it("never divides by an empty scope when a rollup outlives its request rows", () => {
    const s = summary({ total_requests: 0, usage_event_count: 2, input_tokens: 30 });
    expect(gatewayTokenAvailability(s)).toEqual({ kind: "known", covered: 2, total: 2 });
  });
});

describe("provider-reported snapshots", () => {
  it("sums only the records that carried the field and counts them", () => {
    const rows = [
      snapshot({ id: "a", total_tokens: 100 }),
      snapshot({ id: "b", total_tokens: null }),
      snapshot({ id: "c", total_tokens: 50 }),
    ];
    expect(snapshotCoverage(rows, "total_tokens")).toEqual({ covered: 2, total: 3, sum: 150 });
  });

  it("is known when every record carried tokens", () => {
    const rows = [
      snapshot({ id: "a", input_tokens: 1 }),
      snapshot({ id: "b", input_tokens: 2 }),
    ];
    expect(snapshotTokenAvailability(rows, "input_tokens").kind).toBe("known");
  });

  it("is partial when only some did, so the sum is a floor", () => {
    const rows = [
      snapshot({ id: "a", input_tokens: 10, output_tokens: 5 }),
      snapshot({ id: "b", input_tokens: 10, output_tokens: null }),
    ];
    // A record can carry an input count and no output count: the two columns
    // are answered independently, never by one guess covering both.
    expect(snapshotTokenAvailability(rows, "input_tokens").kind).toBe("known");
    expect(snapshotTokenAvailability(rows, "output_tokens")).toEqual({
      kind: "partial",
      covered: 1,
      total: 2,
    });
  });

  it("is unknown when no record carried tokens", () => {
    const rows = [snapshot({ id: "a" }), snapshot({ id: "b" })];
    expect(snapshotTokenAvailability(rows, "total_tokens")).toEqual({
      kind: "unknown",
      total: 2,
    });
  });

  it("says 'not metered in tokens' when every record is metered in something else", () => {
    const rows = [
      snapshot({ id: "a", provider: "stripe", quantity: 12, unit: "events" }),
      snapshot({ id: "b", provider: "stripe", quantity: 4, unit: "events" }),
    ];
    const a = snapshotTokenAvailability(rows, "total_tokens");
    expect(a.kind).toBe("unsupported");
    expect(availabilitySentence(a, RECORD_TOKENS)).toMatch(/metered in events, not tokens/);
  });

  it("mixes sources without letting an unpriced row read as a free one", () => {
    const rows = [
      snapshot({ id: "a", source: "provider", reported_cost_micros: 1_000_000 }),
      snapshot({ id: "b", source: "manual", reported_cost_micros: null }),
    ];
    const a = snapshotCostAvailability(rows, "reported_cost_micros");
    expect(a).toEqual({ kind: "partial", covered: 1, total: 2 });
    expect(formatCostMicros(1_000_000, a, RECORD_REPORTED_COST)).toMatch(
      /^\$1\.00 — Partial cost data: 1 of 2 usage record\(s\)/,
    );
  });

  it("keeps an estimate absent when no record carried one", () => {
    const rows = [snapshot({ id: "a", reported_cost_micros: 500 })];
    const a = snapshotCostAvailability(rows, "estimated_cost_micros");
    expect(a.kind).toBe("unknown");
    expect(formatCostMicros(0, a, RECORD_ESTIMATED_COST)).not.toMatch(/\$/);
  });
});

describe("a sum whose zero cannot be told from an absence", () => {
  it("does not present the per-project rollup's zero as a reported cost", () => {
    const a = ambiguousSumAvailability(0, "no USD cost row exists this month");
    expect(a.kind).toBe("unknown");
    expect(formatCostMicros(0, a, PROJECT_REPORTED_COST)).not.toMatch(/\$/);
  });

  it("shows the figure once there is one", () => {
    const a = ambiguousSumAvailability(2_000_000, "irrelevant");
    expect(formatCostMicros(2_000_000, a, PROJECT_REPORTED_COST)).toBe("$2.00");
  });
});
