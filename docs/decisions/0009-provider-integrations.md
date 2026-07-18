# ADR 0009: Provider connectors, usage/cost, permissions, and secure injection

Status: accepted (2026-07-18)

Milestone 3 adds provider network integrations and secure process injection.
New core modules: `http`, `connectors`, `usage`, `pricing`, `budget`,
`permissions`, `activity`, `inject`. Database migration v3 adds the supporting
tables and budget columns.

## Connectors behind a mockable HTTP client

Provider calls go through the `HttpClient` trait (`http.rs`): a real
`UreqClient` (blocking, 20s timeout, 4 MiB body cap) and a `MockHttpClient`
with scripted fixture responses. Connectors (`connectors.rs`) implement a
`Connector` trait; default methods return `CoreError::Unsupported` with the
official management link, and each provider overrides only what it truly
implements. This makes every request builder and response parser testable
offline, so **builds and tests never require live credentials** (a hard
requirement).

### What is implemented, honestly

- **Validation** for all five providers (a lightweight authenticated GET).
- **GitHub metadata + permissions** from `/user` and the `X-OAuth-Scopes`
  header — exact-credential, no admin key.
- **OpenAI/Anthropic usage** from the organization Usage APIs (admin key).
  We do not map provider key ids to vault credentials, so this is recorded at
  **`ProviderAccount`** attribution and never shown as exact per-key. That is
  the honest outcome and satisfies "never display account-level usage as exact
  per-key usage."
- **Stripe/Supabase metadata** (livemode/currencies; project list).

The manifests were reconciled so `support = "implemented"` appears only for
capabilities the connectors actually perform, with accurate `requires_admin`
and `attribution` flags. Nothing is faked (ADR 0007's honesty rule continues).

## Usage, pricing, budgets

Usage snapshots (`usage.rs`) are normalized with an `Attribution` precision
that is always displayed. Money is integer **micro-USD** to avoid float
rounding. Pricing (`pricing.rs`) is a small bundled table of published rates
(each with a source URL and retrieval date) plus DB overrides; estimates are
labeled "estimated", distinguished from provider-reported cost, and flagged
stale after 45 days. Budgets (`budget.rs`) compute current-calendar-month
usage, a linear month-end projection, and over-budget alerts. Only usage that
is *attributable* to a project/credential counts against its budget — provider
account-level usage does not, which is honest about the attribution limit.

## Permissions

`permissions.rs` stores raw scopes verbatim plus a heuristic normalization into
read/write/admin/sensitive with a confidence. Permission **changes** are not
implemented: no initial provider offers a safe documented per-key scope change,
so the product surfaces the official link and marks the action manual. It never
reports a change it did not make.

## Suspicious-activity rules

`activity.rs` records normalized events and implements explainable rules
(over-budget, cost-spike vs the previous month, usage-after-disabled), each
carrying the rule, measurements, comparison period, source, and confidence.
They feed the existing alert lifecycle via `run_monitor`. Nothing is labeled
malicious without evidence, and no credential is auto-revoked.

## Secure process injection

`inject.rs` holds the project credential→env-var mapping config and process-
session records (variable **names** only, never values). The vault's
`build_injection` decrypts strictly within the named project and refuses
credentials from other projects; the CLI `run` command spawns the child with
those variables set on its environment, propagates the exit code, and ends the
session. No `.env` is written and no value is printed. The documented limit:
the value lives in the child's environment while it runs (see THREAT_MODEL).

## Alternatives considered

- **Per-provider HTTP crates / async**: rejected — one small blocking
  `HttpClient` abstraction keeps connectors uniform and fixture-testable.
- **Deriving per-key usage from `group_by=api_key_id`**: rejected for now — we
  don't store provider-side key ids, so mapping would be guesswork; account
  attribution is the honest level.
- **Storing money as floats**: rejected — integer micro-USD avoids rounding
  drift in budgets and cost sums.
- **A background daemon for injection cleanup**: unnecessary — the child's
  environment dies with the process; `SecretString` buffers zeroize on drop.
