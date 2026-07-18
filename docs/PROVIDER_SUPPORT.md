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
| Metadata | implemented (admin) | supported (not impl.) (admin) | implemented | implemented | implemented (admin) |
| Usage | implemented (admin) | implemented (admin) | supported (not impl.) (admin) | manual | supported (not impl.) (admin) |
| Provider-reported cost | implemented (admin) | supported (not impl.) (admin) | supported (not impl.) (admin) | manual | manual |
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
  (`api-tracker provider link openai <key-id> --credential <c>`); otherwise
  it stays at `provider_key`, `provider_project`, or `provider_account`
  level — never divided among local keys. See
  [OPENAI_SYNC.md](OPENAI_SYNC.md).
- **Anthropic usage** is synced from the organization Usage API (admin key)
  and is **account-level** — recorded as `provider_account` and never
  presented as exact per-key usage.
- **Per-credential / per-project budgets** count usage attributed to that
  credential/project: linked provider-synced rows and manual entries
  (`api-tracker usage record --credential <c> --model <m> --input-tokens N
  --output-tokens N`).
- **Provider-reported cost vs. estimates:** OpenAI costs are stored exactly
  as reported (amount + currency + line item). Everything else is a local
  estimate from a versioned pricing table (source URL + retrieval date),
  labeled "estimated" and flagged stale after 45 days. Budgets consume one
  configurable source (`api-tracker budget source`) — never the sum of both.

## Notes per capability

- **Validation** is a lightweight authenticated GET (OpenAI `/v1/models`,
  Anthropic `/v1/models`, GitHub `/user`, Stripe `/v1/balance`, Supabase
  Management `/v1/projects`) and marks the credential valid/invalid.
- **GitHub permissions** come from the `X-OAuth-Scopes` response header
  (classic PATs, exact per credential). Fine-grained token scopes are not
  API-readable — API Tracker says so rather than guessing.
- **Permission changes**: no provider offers a safe, documented per-key scope
  change, so API Tracker surfaces the official management link and marks the
  action manual — or routes the change through the rotation workflow
  (create a replacement with the desired scope, deploy, verify, revoke the
  old). It never reports a change it did not make.
- **Rotation** (`api-tracker rotation`): OpenAI and Supabase rotate fully
  via official APIs (create → deploy → verify → grace → delete old);
  Anthropic is guided-manual creation plus API disable/archive (archive is
  a SOFT revoke — no hard delete exists and the output says so); GitHub and
  Stripe are guided-manual with explicit `complete-manual` confirmation.
  Revocation always happens last, only after the new value validated.
- **Provider-reported expiration**: GitHub's token-expiration header is
  recorded during validation and drives expiry status with a
  "provider-reported" source label. No current provider issues short-lived
  credentials via API; API Tracker says so rather than simulating it.
