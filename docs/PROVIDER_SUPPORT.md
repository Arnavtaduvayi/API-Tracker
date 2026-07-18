# Provider Support Matrix

API Tracker never fabricates provider capabilities and never claims more
attribution precision than a provider exposes. This matrix reflects what is
**actually implemented** today; run `api-tracker provider capabilities <id>`
for the live, per-capability status (with notes) generated from the provider
manifests.

Legend:
- **implemented** — API Tracker performs this via the provider's official API.
- **supported (not impl.)** — the provider offers it officially, but API
  Tracker does not implement it yet.
- **manual** — only possible through the provider's dashboard; API Tracker
  links to it and never pretends the action happened.
- **unsupported** — the provider does not offer it.
- **(admin)** — requires an administrative/organization credential.

| Capability | OpenAI | Anthropic | GitHub | Stripe | Supabase |
| --- | --- | --- | --- | --- | --- |
| Validate | implemented | implemented | implemented | implemented | implemented |
| Metadata | supported (not impl.) (admin) | supported (not impl.) (admin) | implemented | implemented | implemented (admin) |
| Usage | implemented (admin) | implemented (admin) | supported (not impl.) (admin) | manual | supported (not impl.) (admin) |
| Read permissions | manual | unsupported | implemented | manual | supported (not impl.) (admin) |
| Change permissions | manual | unsupported | manual | manual | unsupported |
| Create | supported (not impl.) (admin) | manual | manual | manual | supported (not impl.) (admin) |
| Disable | unsupported | supported (not impl.) (admin) | unsupported | unsupported | supported (not impl.) (admin) |
| Revoke | supported (not impl.) (admin) | supported (not impl.) (admin) | manual | manual | supported (not impl.) (admin) |
| Rotate | manual | manual | manual | manual | supported (not impl.) (admin) |
| Pricing | manual | manual | unsupported | unsupported | manual |

## Attribution precision (important)

Usage attribution **varies by provider** and is always labeled:

- **OpenAI / Anthropic usage** is synced from the organization Usage APIs
  (admin key) and is **account-level** — it is *not* attributed to an
  individual key. API Tracker records it as `provider_account` and never
  presents it as exact per-key usage.
- **Per-credential / per-project budgets** are meaningful for usage you
  attribute yourself (manual usage entries) — record with
  `api-tracker usage record --credential <c> --model <m> --input-tokens N
  --output-tokens N`.
- **Costs are estimates** computed from a local, versioned pricing table (with
  a source URL and retrieval date) unless a provider reports cost directly.
  Estimates are labeled "estimated" and flagged stale after 45 days; override
  with `api-tracker` pricing overrides.

## Notes per capability

- **Validation** is a lightweight authenticated GET (OpenAI `/v1/models`,
  Anthropic `/v1/models`, GitHub `/user`, Stripe `/v1/balance`, Supabase
  Management `/v1/projects`) and marks the credential valid/invalid.
- **GitHub permissions** come from the `X-OAuth-Scopes` response header
  (classic PATs, exact per credential). Fine-grained token scopes are not
  API-readable — API Tracker says so rather than guessing.
- **Permission changes**: no provider offers a safe, documented per-key scope
  change, so API Tracker surfaces the official management link and marks the
  action manual. It never reports a change it did not make.
