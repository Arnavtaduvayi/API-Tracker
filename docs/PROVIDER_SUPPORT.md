# Provider Support Matrix

Tethra never fabricates provider capabilities and never claims more
attribution precision than a provider exposes. This matrix reflects what is
**actually implemented** today; run `tethra provider capabilities <id>`
for the live, per-capability status (with notes) generated from the provider
manifests. The legacy `api-tracker` command remains available as a
compatibility alias for the same program — see
[rebrand/TETHRA_MIGRATION_GUIDE.md](rebrand/TETHRA_MIGRATION_GUIDE.md).

Legend:
- **implemented** — Tethra performs this via the provider's official API.
- **supported (not impl.)** — the provider offers it officially, but Tethra
  does not implement it yet.
- **manual** — only possible through the provider's dashboard; Tethra
  links to it and never pretends the action happened.
- **unsupported** — the provider does not offer it.
- **(admin)** — requires an administrative/organization credential.

| Capability | OpenAI | Anthropic | GitHub | Stripe | Supabase |
| --- | --- | --- | --- | --- | --- |
| Validate | implemented | implemented | implemented | implemented | implemented |
| Metadata | implemented (admin) | implemented (admin) | implemented | implemented | implemented (admin) |
| Usage | implemented (admin) | implemented (admin, per key) | implemented (fine-grained token) | implemented (events) | supported (not impl.) (admin) |
| Provider-reported cost | implemented (admin) | implemented (admin, workspace level) | implemented (billing net amounts) | manual | manual |
| Read permissions | manual | unsupported | implemented | manual | implemented |
| Change permissions | manual | unsupported | manual | manual | unsupported |
| Create | implemented (admin) | manual | manual | manual | implemented (admin) |
| Disable | unsupported | implemented (admin) | unsupported | unsupported | supported (not impl.) (admin) |
| Revoke | implemented (admin) | implemented (admin, soft) | manual | manual | implemented (admin) |
| Rotate | implemented (workflow) | manual create + API disable | manual (guided) | manual (guided) | implemented (workflow) |
| Pricing | manual | manual | unsupported | unsupported | manual |

## Attribution precision (important)

Usage attribution **varies by provider** and is always labeled:

- **OpenAI usage and costs** are synced from the organization Usage and
  Costs APIs (admin key) grouped by provider project × API-key id (× model /
  line item). A row is attributed `exact_credential` **only** when you have
  explicitly linked that provider-side key id to a vault credential
  (`tethra provider link openai <key-id> --credential <c>`); otherwise
  it stays at `provider_key`, `provider_project`, or `provider_account`
  level — never divided among local keys. See
  [OPENAI_SYNC.md](OPENAI_SYNC.md).
- **Anthropic usage and costs** are synced from the organization Usage and
  Cost APIs (admin key). Usage is grouped by provider API-key id ×
  workspace × model (per-key grouping is officially supported); a row is
  `exact_credential` only after you explicitly link the key id. Costs are
  workspace-level at best — the cost API has no per-key grouping, and cost
  is never divided among keys. Amounts arrive as cents-denominated decimal
  strings and are converted with guards.
- **GitHub usage** comes from the Enhanced Billing API at ACCOUNT level
  (quantities + unit types verbatim, e.g. Actions minutes), and needs a
  fine-grained token with "Plan" (read) — classic PATs are not documented
  to work. Never per token.
- **Stripe activity** comes from the official Events API as daily
  event-count aggregates (30-day retention, account-level, unit `events`).
  Per-key request logs are dashboard-only; Stripe offers no API for them.
- **Per-credential / per-project budgets** count usage attributed to that
  credential/project: linked provider-synced rows and manual entries
  (`tethra usage record --credential <c> --model <m> --input-tokens N
  --output-tokens N`).
- **Provider-reported cost vs. estimates:** OpenAI costs are stored exactly
  as reported (amount + currency + line item). Everything else is a local
  estimate from a versioned pricing table (source URL + retrieval date),
  labeled "estimated" and flagged stale after 45 days. Budgets consume one
  configurable source (`tethra budget source`) — never the sum of both.

## Notes per capability

- **Validation** is a lightweight authenticated GET (OpenAI `/v1/models`,
  Anthropic `/v1/models`, GitHub `/user`, Stripe `/v1/balance`, Supabase
  Management `/v1/projects`) and marks the credential valid/invalid.
- **GitHub permissions** come from the `X-OAuth-Scopes` response header
  (classic PATs, exact per credential). Fine-grained token scopes are not
  API-readable — Tethra says so rather than guessing.
- **Permission changes**: no provider offers a safe, documented per-key scope
  change, so Tethra surfaces the official management link and marks the
  action manual — or routes the change through the rotation workflow
  (create a replacement with the desired scope, deploy, verify, revoke the
  old). It never reports a change it did not make.
- **Rotation** (`tethra rotation`): OpenAI and Supabase rotate fully
  via official APIs (create → deploy → verify → grace → delete old);
  Anthropic is guided-manual creation plus API disable/archive (archive is
  a SOFT revoke — no hard delete exists and the output says so); GitHub and
  Stripe are guided-manual with explicit `complete-manual` confirmation.
  Revocation always happens last, only after the new value validated.
- **Provider-reported expiration**: GitHub's token-expiration header is
  recorded during validation and drives expiry status with a
  "provider-reported" source label. No current provider issues short-lived
  credentials via API; Tethra says so rather than simulating it.

## Provider-account identity (official endpoints only)

`tethra provider account <id> [--sync]` (and the desktop connection
panel) stores only what an official endpoint reports, with its source and
sync time — never anything derived from a credential's appearance:

| Provider | Endpoint | Fields stored |
| --- | --- | --- |
| GitHub | `GET /user` | login, numeric id, email (when the token's scope exposes it), plan name |
| Stripe | `GET /v1/account` | account id, email, business/display name |
| Supabase | `GET /v1/organizations` | org id + name when exactly one org is visible; otherwise only the count (never a guess) |
| Anthropic | `GET /v1/organizations/me` | organization id + name (admin key) |
| OpenAI | — | none: the Admin API has no documented account-identity endpoint. The org label you enter at connect time is shown, labeled "user-entered, not provider-verified". |

Provider account **passwords, recovery codes, MFA material, and browser
session data are intentionally excluded** — Tethra is a credential
manager, not a password manager (FEATURE_MATRIX #16). Every manifest also
carries the provider's official console-login and billing-portal URLs
(`provider docs`).

## Optional live verification — what each test needs

Normal development and CI use fixtures only. The opt-in scripts
(`scripts/live_verify_*.sh`) each use a throwaway vault, hidden prompts,
and self-cleaning; none runs in CI. What they require and can cost:

| Script | Credential needed | Plan needed | Billable activity | Max expected cost |
| --- | --- | --- | --- | --- |
| `live_verify_openai.sh` | Admin API key (org settings) | any org | none (admin endpoints are free) | $0 |
| `live_verify_anthropic.sh` | Admin API key | any org | none | $0 |
| `live_verify_github.sh` | fine-grained PAT, Plan: read | any | none | $0 |
| `live_verify_stripe.sh` | secret key (test mode fine) | any | none (reads) | $0 |
| `live_verify_aws.sh` | IAM key scoped to secretsmanager on `api-tracker-live-verify-*` | any AWS account | creates + deletes ONE disposable secret | < $0.05 |
| `live_verify_github_actions.sh` | PAT with secrets access to a THROWAWAY repo | any | none | $0 |
| `live_verify_vercel.sh` | access token; THROWAWAY project | any | none | $0 |

Each script shows the exact provider actions and asks for a typed
confirmation before any write; disposable resources are cleaned up and
cleanup failures are reported loudly with manual instructions.
