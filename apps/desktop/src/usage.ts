// The availability of a token or cost number, in one place (NEW-37).
//
// The defect this module exists to prevent: `input_tokens`, `output_tokens`
// and `estimated_cost_micros` cross the IPC boundary as plain integers whose
// SQL origin is `COALESCE(SUM(...), 0)`, so "no response carried usage" and
// "the responses carried usage adding up to zero" arrive as the same value.
// Rendering that value directly turned an unanswerable question into an
// assertion: the Activity dashboard printed "0 / 0" and "$0.0000" next to a
// real request count, for providers (cohere, google-gemini, langsmith,
// replicate, supabase) whose manifests declare `usage_shape = ""` and which
// therefore can never produce a token count at all.
//
// Three shipped invariants say this must not happen — PRODUCT_BEHAVIOR.md
// ("Absent usage data is a state, never a silent zero"),
// COVERAGE_LIMITATIONS.md ("records **absent** — never a fabricated zero"),
// and ADR 0019 ("never a fabricated 0") — and the gateway's own
// `record::UsageState` already models the states honestly on the Rust side.
// Nothing exposed that vocabulary to TypeScript, so each component decided
// for itself; GatewayView guarded on `usage_event_count > 0`, DashboardView
// guarded on nothing, and the two drifted. The rule now lives here and every
// surface calls it, so there is exactly one implementation to audit.
//
// The rule, stated once: a number is only rendered when every record that
// contributed to it carried that number. A sum over a mix of known and
// unknown records is a FLOOR, never a total, and is labelled as partial with
// the count that contributed. A real zero remains expressible — hiding a
// measured zero would be a different lie.

import type {
  GatewayActivitySummary,
  ProjectCostCoverage,
  UnpricedReason,
  UsageSnapshot,
} from "./types";

/**
 * Why a token/cost number is, or is not, showable.
 *
 * Mirrors gateway `record::UsageState` (absent / extracted / unsupported
 * shape) plus the three states only the read side can see: partial coverage,
 * stale source data, and "Tethra could not determine it".
 */
export type UsageAvailability =
  /** Every record in scope carried the number. The value — including 0 — is a measurement. */
  | { kind: "known"; covered: number; total: number }
  /** Some records carried it. The value is a lower bound over `covered` of `total`. */
  | { kind: "partial"; covered: number; total: number }
  /** Known or partial, but the source has not synced since `asOf`, so newer usage is missing. */
  | { kind: "stale"; asOf: string | null; covered: number; total: number }
  /** Nothing in scope carried the number. Absent is not zero. */
  | { kind: "unknown"; total: number; detail?: string }
  /** The provider or response shape never reports this number, by design. */
  | { kind: "unsupported"; detail: string }
  /** Tethra could not determine it: a failed read, extraction off, recording paused. */
  | { kind: "unavailable"; reason: string };

/**
 * The wording for one measured quantity. Only phrasing lives here — the
 * predicate is shared, so a new surface cannot accidentally get a new rule
 * along with its new label.
 */
export interface UsageSubject {
  /** Sentence-leading noun phrase: "Tokens", "Estimated cost". */
  name: string;
  /** Label for a sum that is a floor: "Partial token data". */
  partialLabel: string;
  /** What a record must carry for the number to be known: "a token count". */
  carrier: string;
  /** What is being counted: "response(s)", "usage record(s)". */
  unit: string;
  /** Why absence is normal, so "not reported" does not read as a fault. */
  absentDetail: string | null;
}

export const GATEWAY_TOKENS: UsageSubject = {
  name: "Tokens",
  partialLabel: "Partial token data",
  carrier: "a token count",
  unit: "response(s)",
  absentDetail:
    "providers report usage only on some responses, and absent usage is never counted as zero",
};

export const GATEWAY_ESTIMATED_COST: UsageSubject = {
  name: "Estimated cost",
  partialLabel: "Partial cost data",
  carrier: "a priced token count",
  unit: "response(s)",
  absentDetail: "a cost is derived only from tokens Tethra both extracted and could price",
};

export const RECORD_TOKENS: UsageSubject = {
  name: "Tokens",
  partialLabel: "Partial token data",
  carrier: "a token count",
  unit: "usage record(s)",
  absentDetail: "many providers meter products in units other than tokens",
};

export const RECORD_REPORTED_COST: UsageSubject = {
  name: "Reported cost",
  partialLabel: "Partial cost data",
  carrier: "a provider-reported cost",
  unit: "usage record(s)",
  absentDetail: null,
};

export const RECORD_ESTIMATED_COST: UsageSubject = {
  name: "Estimated cost",
  partialLabel: "Partial cost data",
  carrier: "a local cost estimate",
  unit: "usage record(s)",
  absentDetail: "an estimate exists only where local pricing covers the model",
};

export const PROJECT_REPORTED_COST: UsageSubject = {
  name: "Reported cost",
  partialLabel: "Partial cost data",
  carrier: "a USD provider-reported cost",
  unit: "usage record(s)",
  absentDetail: null,
};

/**
 * The single predicate. `covered` records carried the number; `total` were in
 * scope. Nothing in scope, or nothing carrying it, is unknown — never zero.
 */
export function fromCoverage(covered: number, total: number): UsageAvailability {
  if (total <= 0) return { kind: "unknown", total: 0 };
  if (covered <= 0) return { kind: "unknown", total };
  if (covered < total) return { kind: "partial", covered, total };
  return { kind: "known", covered, total };
}

/** Whether a number may be shown at all. False means the sentence replaces it. */
export function hasValue(a: UsageAvailability): boolean {
  return a.kind === "known" || a.kind === "partial" || a.kind === "stale";
}

/**
 * Age a known or partial value. Staleness qualifies a number that exists; it
 * cannot rescue one that does not, so unknown/unsupported/unavailable pass
 * through unchanged rather than being promoted into something showable.
 */
export function markStale(a: UsageAvailability, asOf: string | null): UsageAvailability {
  if (a.kind === "known" || a.kind === "partial") {
    return { kind: "stale", asOf, covered: a.covered, total: a.total };
  }
  return a;
}

/** The sentence shown INSTEAD of a number. Never contains a fabricated figure. */
export function availabilitySentence(a: UsageAvailability, s: UsageSubject): string {
  switch (a.kind) {
    case "unsupported":
      return `${s.name} not reported by this provider — ${a.detail}`;
    case "unavailable":
      return `${s.name} unavailable — ${a.reason}`;
    case "unknown": {
      const reason =
        a.detail ??
        (a.total > 0
          ? `none of the ${a.total} ${s.unit} carried ${s.carrier}`
          : `no ${s.unit} in this window`);
      const caveat = s.absentDetail ? ` (${s.absentDetail})` : "";
      return `${s.name} not reported — ${reason}${caveat}`;
    }
    default:
      // Reached only when a value-bearing availability arrives with no value
      // — a contradiction between the coverage count and the payload. The
      // number is missing whatever the count claimed, and a missing number is
      // never rendered as a zero.
      return `${s.name} not reported — the value was missing where the source said it was known`;
  }
}

/** The clause that qualifies a number that IS shown, or null when it stands alone. */
export function availabilityNote(a: UsageAvailability, s: UsageSubject): string | null {
  const partial = (covered: number, total: number) =>
    `${s.partialLabel}: ${covered} of ${total} ${s.unit} carried ${s.carrier}, and the rest are not counted as zero`;
  switch (a.kind) {
    case "partial":
      return partial(a.covered, a.total);
    case "stale": {
      const when = a.asOf ?? "an unrecorded time";
      const age = `as of ${when}; the source has not synced since, so newer usage is missing`;
      return a.covered < a.total ? `${age}. ${partial(a.covered, a.total)}` : age;
    }
    default:
      return null;
  }
}

/** Render a formatted value with its qualifier, or the sentence that replaces it. */
function render(text: string | null, a: UsageAvailability, s: UsageSubject): string {
  if (text === null || !hasValue(a)) return availabilitySentence(a, s);
  const note = availabilityNote(a, s);
  return note === null ? text : `${text} — ${note}`;
}

/** A count (tokens, requests). `formatCount(null, …)` can never render "0". */
export function formatCount(
  value: number | null,
  a: UsageAvailability,
  s: UsageSubject,
): string {
  return render(value === null ? null : value.toLocaleString(), a, s);
}

/** The gateway's "N in / M out" pair, which shares one availability. */
export function formatTokenPair(
  input: number | null,
  output: number | null,
  a: UsageAvailability,
  s: UsageSubject = GATEWAY_TOKENS,
): string {
  const text =
    input === null || output === null
      ? null
      : `${input.toLocaleString()} in / ${output.toLocaleString()} out`;
  return render(text, a, s);
}

/**
 * Micro-USD as dollars. Returns "$0.0000" only for a known (measured or
 * derived) zero — an unknown cost never acquires a dollar sign.
 */
export function formatCostMicros(
  micros: number | null,
  a: UsageAvailability,
  s: UsageSubject,
  digits = 2,
): string {
  return render(micros === null ? null : `$${(micros / 1_000_000).toFixed(digits)}`, a, s);
}

// --- gateway activity summary -----------------------------------------

/**
 * Token availability for locally observed gateway traffic.
 *
 * `usage_event_count` is the only disambiguator the rollup keeps: it counts
 * the responses that actually carried usage. Comparing it with the request
 * count is what turns "3 tokens-bearing responses out of 500 requests" into a
 * labelled floor instead of a total that silently omits 497 requests.
 */
export function gatewayTokenAvailability(s: GatewayActivitySummary): UsageAvailability {
  // A rollup row can outlive the request rows it summarises (different
  // retentions), so the denominator is whichever is larger; it must never be
  // smaller than the numerator or coverage would read as "nothing in scope".
  return fromCoverage(s.usage_event_count, Math.max(s.total_requests, s.usage_event_count));
}

/**
 * Cost availability, which is NOT the same question as tokens.
 *
 * `writer.rs` stores `cost.unwrap_or(0)` when `estimate_token_cost_as_of`
 * returns None (no pricing row for the model), so a priced zero and an
 * unpriced request are the same integer in the rollup. Tokens can therefore
 * be known while the price is not, and that case must not print "$0.0000" as
 * a "lower-bound estimate". A zero derived from zero measured tokens is a
 * real zero and is still shown.
 */
export function gatewayCostAvailability(s: GatewayActivitySummary): UsageAvailability {
  const tokens = gatewayTokenAvailability(s);
  if (!hasValue(tokens)) return tokens;
  const measured = s.input_tokens + s.output_tokens;
  if (s.estimated_cost_micros === 0 && measured > 0) {
    return {
      kind: "unknown",
      total: s.usage_event_count,
      detail:
        "tokens were extracted but no local price covers the model(s) in this window, so no estimate can be derived",
    };
  }
  return tokens;
}

// --- provider-reported usage snapshots --------------------------------

/** The nullable fields a snapshot may or may not carry. */
export type SnapshotField =
  | "input_tokens"
  | "output_tokens"
  | "total_tokens"
  | "reported_cost_micros"
  | "estimated_cost_micros";

/** Sum only the records that carried the field, and count how many did. */
export function snapshotCoverage(
  rows: UsageSnapshot[],
  field: SnapshotField,
): { covered: number; total: number; sum: number } {
  let covered = 0;
  let sum = 0;
  for (const r of rows) {
    const v = r[field];
    if (v != null) {
      covered += 1;
      sum += v;
    }
  }
  return { covered, total: rows.length, sum };
}

/**
 * Token availability across provider-reported snapshots.
 *
 * `UsageTotals` folds each `Option<i64>` with `unwrap_or(0)` and keeps no
 * residual count, so the totals alone cannot say how complete they are. The
 * snapshots behind them can, and they are already loaded for the records
 * table. A scope whose records are all metered in some other unit (events,
 * requests — Stripe, Supabase) is reported as unsupported rather than absent:
 * the token count does not exist, it is not merely missing.
 */
export function snapshotTokenAvailability(
  rows: UsageSnapshot[],
  field: SnapshotField = "total_tokens",
): UsageAvailability {
  const { covered, total } = snapshotCoverage(rows, field);
  if (total > 0 && covered === 0 && rows.every((r) => r.unit != null)) {
    const units = [...new Set(rows.map((r) => r.unit).filter((u): u is string => u != null))];
    return {
      kind: "unsupported",
      detail: `these ${total} record(s) are metered in ${units.join(", ")}, not tokens`,
    };
  }
  return fromCoverage(covered, total);
}

/** Cost availability across provider-reported snapshots (reported or estimated). */
export function snapshotCostAvailability(
  rows: UsageSnapshot[],
  field: "reported_cost_micros" | "estimated_cost_micros",
): UsageAvailability {
  const { covered, total } = snapshotCoverage(rows, field);
  return fromCoverage(covered, total);
}

/**
 * A single non-negative sum whose only signal is the value itself, as in the
 * per-provider-project rollup (`COALESCE(SUM(reported_cost_micros), 0)` over
 * rows filtered to non-NULL USD costs). A zero there is genuinely ambiguous —
 * no cost row and a reported $0.00 are the same integer — so it is reported
 * as unknown. Understating certainty is the only safe direction: the opposite
 * asserts spend that may never have been reported.
 */
export function ambiguousSumAvailability(sum: number, detail: string): UsageAvailability {
  if (sum > 0) return { kind: "known", covered: 1, total: 1 };
  return { kind: "unknown", total: 0, detail };
}

// --- projects-first cost coverage (ADR 0029) --------------------------

/** The subject wording for a project's locally estimated cost. */
export const PROJECT_ESTIMATED_COST: UsageSubject = {
  name: "Estimated known cost",
  partialLabel: "Partial cost data",
  carrier: "a priced token count",
  unit: "request(s)",
  absentDetail:
    "an estimate exists only for requests whose model, tokens and local pricing are all known",
};

/** The subject wording for a project's observed token usage. */
export const PROJECT_TOKENS: UsageSubject = {
  name: "Tokens",
  partialLabel: "Partial token data",
  carrier: "a reported token count",
  unit: "request(s)",
  absentDetail:
    "providers report usage only on some responses, and absent usage is never counted as zero",
};

/**
 * Cost availability for one project window.
 *
 * The denominator is every request the window saw, not just the priced ones:
 * a total computed over 4 priced requests while 96 went unpriced is a floor,
 * and comparing against the priced count alone would report it as complete.
 */
export function projectCostAvailability(c: ProjectCostCoverage): UsageAvailability {
  const total = c.priced_requests + c.unpriced_requests + c.requests_with_unknown_usage;
  let base = fromCoverage(c.priced_requests, total);
  // `complete` is the BACKEND's verdict, and it can be false for a reason the
  // request counts cannot express: a record that priced output but not input
  // makes every request "priced" while the amount is only a floor. Ignoring it
  // rendered that floor as an unqualified dollar figure in the headline card.
  if (!c.complete && base.kind === "known") {
    base = { kind: "partial", covered: c.priced_requests, total: Math.max(total, 1) };
  }
  // Deliberately NOT `markStale`. That state means "the SOURCE has not synced,
  // so newer usage is missing", which is a different and wrong thing to tell the
  // user here: the usage is complete and current, and it is the PRICE that is
  // past its verification date. `tokenCoverageSentence`/`CostCoverage` carry the
  // stale-pricing sentence instead, so the number keeps its real availability.
  return base;
}

/** Whether the price behind an estimate is past its verification horizon. */
export function pricingIsStale(c: ProjectCostCoverage): boolean {
  return c.any_stale_pricing;
}

/**
 * Token availability for one project window.
 *
 * Requests whose usage was never reported are the uncovered part. Their tokens
 * are unknown, so they must widen the denominator rather than contribute zero
 * to the numerator.
 */
export function projectTokenAvailability(c: ProjectCostCoverage): UsageAvailability {
  const withTokens = c.priced_requests + c.unpriced_requests;
  return fromCoverage(withTokens, withTokens + c.requests_with_unknown_usage);
}

/**
 * The coverage sentence for a partially priced window, e.g.
 * "76% of token usage priced". Null when there is no ratio to state — which is
 * not the same as 0%.
 */
export function tokenCoverageSentence(c: ProjectCostCoverage): string | null {
  if (c.token_coverage === null) return null;
  const pct = Math.round(c.token_coverage * 100);
  return `${pct}% of token usage priced`;
}

/** Why a slice of usage carries no estimate, as a sentence. */
export function unpricedReasonSentence(reason: UnpricedReason): string {
  switch (reason) {
    case "no_pricing_record":
      return "no local pricing record covers this model";
    case "model_not_detected":
      return "the response did not report a model";
    case "usage_not_extracted":
      return "token usage was not reported for these requests";
    case "non_token_unit":
      return "this model's pricing record is not token-based";
    case "unsupported_currency":
      return "this model's pricing record is in another currency";
    default:
      // An unrecognized reason is reported as unrecognized rather than printed
      // bare, matching how every other enum reaches this UI.
      return "the reason was not recognized";
  }
}
