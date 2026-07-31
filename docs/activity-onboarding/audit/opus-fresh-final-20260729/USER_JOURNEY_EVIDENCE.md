# User journey and provider honesty — independent evidence

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`.

**Scope limitation, stated up front:** no GUI automation was available on this
machine, and the service-lifecycle scopes could not be run locally because a
live production gateway is present. Desktop UI claims below are therefore
**source-reviewed plus vitest-executed**, and packaged-journey claims are
**read from the exact-head CI artifact**. Where a claim rests on one of those
rather than on something I drove myself, it says so.

## 1. The supported journey

```
Open packaged Tethra → add a credential → Track API activity → select folder
→ review detected APIs → Start tracking → restart the project → one request
→ accurate current activity
```

Evidence that each stage exists and works, on the exact audited head:

| Stage | Evidence | Kind |
| --- | --- | --- |
| Packaged app carries a runnable helper | `service-lifecycle.log:18-22` — Mach-O arm64, measured version 0.1.0 == declared, byte-identical to the sidecar staged from source, exec probe answered | CI-executed |
| App works outside the repository | `:2` `app: /Users/runner/work/_temp/packaged-app/Tethra.app` — copied to `$RUNNER_TEMP`, not the checkout | CI-executed |
| No CLI on PATH required | `tracking_validate_macos.sh:1126` strips PATH to `/usr/bin:/bin:/usr/sbin:/sbin`; `cleanup.log:25` `OK no tethra CLI on PATH` | CI-executed (the strip itself emits no PASS line — `NEW-36`, low) |
| Detection from a selected folder | `DRYRUN` group, 6 checks | CI-executed |
| Review screen, one combined diff | `DRYRUN` — *"the dry run showed the exact env diff"*, *"changed the .env not one byte"* | CI-executed |
| Start tracking applies in bulk | `APPLY` group, 9 checks — route created, exactly one link, one setup recorded | CI-executed |
| Restart + one request → verified | `TRAFFIC` group, 5 checks — *"the provider answered 401 through the gateway (path proven end to end)"*, *"this request added a NEW gateway observation post-dating applied_at"*, *"the setup is marked traffic_observed ONLY after a real request"* | CI-executed |

**Zero-terminal setup holds** for the desktop path. The CLI fallback
`tethra track .` is one command and is covered by `smoke.sh` (below).

## 2. Verification cannot pass without qualifying traffic

The `NEGATIVE` group (8 checks) on the exact head plants a **forged pre-apply
observation** and proves it does not verify:

```
PASS  the setup is NOT marked traffic_observed before any request
PASS  no first-traffic timestamp exists before any request
PASS  track status exits 2 while unverified
PASS  the forged pre-apply gateway observation was really inserted (the control is armed)
PASS  track status STILL exits 2 with a forged pre-apply observation present
PASS  a forged pre-apply observation does not flip the setup to traffic_observed
PASS  a forged pre-apply observation does not set the first-traffic timestamp
PASS  the control removed exactly what it planted
```

Note the fourth line — an explicit **armed-control** check, so the negative
result cannot come from the forgery having silently failed to land. This is
the pattern the rest of the harness should follow.

Crate level: `zft006_regression.rs` (5), `verification_freshness.rs` (16),
`verification_clock.rs` (16), `verification_concurrency.rs` (13) — all
executed here, all passing.

## 3. Idempotence and undo

`IDEMPOTENCE` (4) and `UNDO` (4) on the exact head:

```
PASS  the second run exits 2 — a new verification session, not a crash and not a stale pass
PASS  a second run changed the .env not one byte
PASS  no duplicate link row
PASS  no duplicate tracking setup
PASS  track undo exits 0
PASS  undo restored the .env byte for byte (cmp, not string equality)
PASS  the link row was removed
PASS  recorded history was KEPT (undo never deletes the user's data)
```

The second-run behaviour is important and correct: a rerun opens a **new
verification session** and exits 2 rather than inheriting the previous run's
"verified". That is the ZFT-006 protection visible at the packaged level.

Caveat carried from the deferred set: the last check asserts `COUNT(*) >= 1`
(`VAL-11`), so it would pass if undo deleted almost everything. The product
behaviour is almost certainly right; the *check* does not establish it.

Locally executed: `undo_ground_truth.rs` 7/7,
`plan_apply::apply_twice_converges_with_zero_new_rows` 1/1.

## 4. The ~30-integration fixture — personally verified

`crates/tracking/tests/detect_coverage.rs`. This file exists because a prior
audit found that the "30-provider-scale test" was a four-provider test with a
thirty-variable `.env`, and that 26 of 30 credentials appeared **nowhere** on
the review screen (ZFT-010).

The fixture is genuine: **10 built-in** providers (`OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, `GROQ_API_KEY`, …), **19 unknown** services
(`SENDGRID_API_KEY`, `TWILIO_AUTH_TOKEN`, `PINECONE_API_KEY`, …) and
**custom-origin** entries (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`),
spread across `root`, `local`, `prod` and a **nested** application's env files.

Executed here:

```
running 9 tests
test the_thirty_integration_fixture_really_contains_thirty_integrations ... ok
test built_in_providers_are_still_bulk_configured_at_thirty_api_scale ... ok
test every_env_file_in_the_fixture_is_actually_scanned ... ok
test the_unknown_bucket_carries_a_usable_hint_and_never_a_value ... ok
test a_placeholder_value_is_not_counted_as_a_credential ... ok
test one_unsupported_provider_never_blocks_the_supported_ones ... ok
test no_credential_is_silently_dropped_from_the_review_screen ... ok
test a_hint_never_becomes_a_provider_or_a_route ... ok
test the_counts_add_up_to_the_headline ... ok

test result: ok. 9 passed; 0 failed
```

The first test is an **anti-vacuity control** — it proves the fixture really
presents thirty integrations, so the coverage assertions cannot pass on a
smaller input. `no_credential_is_silently_dropped_from_the_review_screen` and
`the_counts_add_up_to_the_headline` are the direct ZFT-010 regressions.

**Every integration is accounted for in exactly one bucket.** Unknown APIs are
visible with a usable hint and never a value; a hint never becomes a provider
or a route.

## 4b. `NEW-37` (merge blocker) — the default dashboard fabricates a zero

The repository states the invariant three times:

* `docs/activity-onboarding/PRODUCT_BEHAVIOR.md:272` — *"Absent usage data is a
  state, never a silent zero."*
* `docs/gateway/COVERAGE_LIMITATIONS.md:42` — *"records **absent** — never a
  fabricated zero."*
* `docs/decisions/0019-local-gateway.md:61` — *"record `usage_available=false`
  and surface it, never a fabricated 0."*

`GatewayView.tsx:1281-1288` implements it:

```tsx
{summary.usage_event_count > 0
  ? `${summary.input_tokens} in / ${summary.output_tokens} out (… absent usage is never counted as zero)`
  : "none extracted (providers report usage only on some responses)"}
```

`DashboardView.tsx:290-296` — the **default** view, which this PR promoted to
the landing screen — does not:

```tsx
<dt>Tokens in / out</dt>
<dd>{summary.input_tokens} / {summary.output_tokens}</dd>
<dt>Estimated cost</dt>
<dd>${cost} <span className="muted">(lower bound; cache reads excluded)</span></dd>
```

`usage_event_count` is on the DTO (`types.ts:1338`) and appears **nowhere** in
`DashboardView.tsx`. Five of the thirteen routable providers declare
`usage_shape = ""` — `cohere`, `google-gemini`, `langsmith`, `replicate`,
`supabase` — so a user tracking any of them sees requests and latency
populate while tokens read `0 / 0` and cost reads `$0.0000`, after traffic
that succeeded.

`DashboardView.test.tsx:65` even sets `usage_event_count: 0` in its fixture,
so the failing case is already exercised and simply not asserted on.

This is a fabricated zero on the product's primary surface, contradicting the
project's own written rule, with the correct implementation present in the
same codebase. `CLAUDE.md` lists *"Provider capabilities must be represented
honestly"* among the requirements that may not be silently changed. **Merge
blocking.**

## 4c. Related honesty defects (not blocking)

* `NEW-38` (High) — `CredentialDetail.tsx:114` swallows a failed `providerGet`
  into `manifest = null`; `:527`/`:535` then render *"This provider has no API
  key creation"* and *"no API revocation"*. For OpenAI and Supabase both are
  `implemented`, so a **transport error fabricates a provider capability** on
  the surface whose entire purpose is capability honesty.
* `NEW-39` (Med) — `GatewayView.tsx:716-717` tells the eight detect-only
  providers they *"have no fixed API origin — every project gets its own
  host"*. False for all eight (Stripe, GitHub, Mistral, DeepSeek, xAI,
  OpenRouter, HuggingFace, AWS Bedrock); the real reason is that their SDKs
  read no base-URL variable.
* `NEW-41` (Med) — the PR's claim that *"every list distinguishes loading,
  empty, error, unsupported, and not-configured"* generalises two **file-local**
  comments (`TrackFlow.tsx:18-20`, `DashboardView.tsx:5-7`) to the whole app.
  Those two files honour it; `AlertsView.tsx:117-118` and
  `ApiActivityView.tsx:202-207` render their empty message **alongside** the
  error, and `ProviderConnectionPanel.tsx:128` and `CredentialForm.tsx:39`
  swallow the error entirely. No test covers the four swallowing surfaces.
* `NEW-43` (Med) — headline buckets rank confidence first (`detect.rs:1216`)
  while row labels use `configurability` with no confidence guard
  (`track_cmd.rs:317-322`, `TrackFlow.tsx:523`), so the review screen shows six
  "Tethra knows where these go" rows under a headline saying three. Totals
  still sum to 30 — nothing is lost, but the counts do not match the screen.
* `NEW-44` (Med) — the superseded fake scale test still ships:
  `plan_apply.rs:669` `thirty_detected_providers_stay_one_plan_with_no_per_provider_forms`
  plans **three** providers and its own comment concedes the trick, under the
  exact name the prior audit criticised.
* `NEW-42` (Med) — on a machine with **no vault**, `tethra track .` exits 1
  with *"the vault is locked. Set TETHRA_PASSWORD or run this command
  interactively"* — even when `TETHRA_PASSWORD` is already set. The vault is
  not locked, it does not exist, and the message never says `tethra init`
  (`track_cmd.rs:121-136`). `IMPLEMENTATION_STATUS.md:53-54` concedes two
  commands while `README.md:222` says one.

## 4d. `NEW-40` — the status page's evidence claims are stale

`IMPLEMENTATION_STATUS.md:4` — *"Every claim below is executed evidence."*
Measured by this audit:

| Doc claim | line | Measured here |
| --- | --- | --- |
| `packaged run with PATH stripped, 42/42 checks` | `:11` | offline **20**, foreground **57**, service **63** |
| `TrackFlow.tsx, 14 vitest cases` | `:12` | **36** |
| `api-tracker-tracking (new crate) 54` | `:34` | **158** |
| `Frontend vitest 65 passed` | `:35` | **102** |
| `scripts/smoke.sh 138 passed` | `:38` | **140** |
| `tracking_validate_macos.sh 42 passed` | `:39` | the defective pre-`ZFT-VAL-4` number the harness header itself calls out |

`PACKAGED_VALIDATION.md:26-28` carries the **correct** 20/57/63 table. Two
documents in the same branch disagree, and the stale one is the page titled
"status". For a PR whose case rests on measured evidence, this matters more
than its severity suggests.

## 5. Provider coverage honesty

**21 provider manifests** in `provider-manifests/` (`anthropic`, `aws-bedrock`,
`azure-openai`, `cerebras`, `cohere`, `deepseek`, `fireworks`, `github`,
`google-gemini`, `groq`, `huggingface`, `langsmith`, `mistral`, `openai`,
`openrouter`, `perplexity`, `replicate`, `stripe`, `supabase`, `together`,
`xai`), of which 13 carry a `[gateway]` section — matching the documented
claim.

Manifests are `include_str!`-compiled (`crates/core/src/providers.rs:252-304`),
so a scanned repository cannot add or edit one. A provider with no manifest is
`Unsupported` (`detect.rs:1091-1094`) and appears in the unknown bucket rather
than vanishing.

I found no claim presenting account-level usage as per-key usage. The one
honesty gap in this area is carried from the deferred set (`ORG-02`):
`*.localhost` origins are offered for approval and disclosed as *"The host is
a public internet address"* (`origin.rs:165`), contradicting
`KNOWN_LIMITATIONS.md:220-224`. Containment is structural — `upstream.rs:84`
denies the resolved loopback address regardless of approval — so no credential
leaves, but the disclosure text is wrong for that spelling.

## 6. The CLI fallback — executed

`bash scripts/smoke.sh` → **140 passed, 0 failed**, including:

```
-- zero-friction tracking (offline: dry-run, status, undo honesty) --
PASS  track --dry-run succeeds on a detectable project
PASS  the dry run shows the detection and the exact env diff
PASS  the dry run says it changed nothing
PASS  the dry run really changed nothing on disk (cmp, not string equality)
PASS  no key value appears in track output
PASS  track never prints shell-export choreography
PASS  the dry run created no project
PASS  track status exits 2 while tracking is not configured
PASS  track status names the unconfigured state honestly
PASS  track undo is honest when there is nothing to undo
PASS  an empty folder exits 2 (no trackable APIs), not an error
PASS  the empty-folder message names the outcome plainly
PASS  the empty-folder message says what the user can do about it
PASS  the empty-folder message points at no unexecutable CLI command
```

**Zero terminal commands beyond the one, no shell-export choreography, no key
value in output** — all directly asserted.

## 7. Honest states in the UI

Source-reviewed plus vitest (**102 tests across 11 files, all passing**).
`DashboardView.tsx` separates *"Right now"* (`health.sentence`) from
*"Previously"* (`history.sentence`) at `:392-405`, and `stateLabel(s.state)`
— the stale-capable field — can only render under "Previously" (`:403-404`).
`TrackFlow.tsx:1095` gates the headline on `status.health.currently_working`.

Committed regressions for the exact honesty property:
`TrackFlow.test.tsx:650-675` (*"never claims verified when the gateway is
down, even with an observation"*) and `DashboardView.test.tsx:218-242`
(*"never renders 'verified previously, gateway down' as a success"*).

**The desktop is correct on this property. The CLI is not** — see `NEW-01` in
`VERIFICATION_CONCURRENCY_EVIDENCE.md`, which is this audit's single merge
blocker.

`NEW-30` (low): the desktop's partial-apply screen offers no undo button,
contrary to the PR's "offers undo" claim; undo is reachable only from the
dashboard.

## 8. Build prerequisite worth documenting

`NEW-22` (informational): from a clean checkout, `cargo test --workspace
--all-targets`, `cargo clippy --workspace --all-targets` and
`cargo build --workspace --release` all **fail** with
`resource path 'binaries/tethra-aarch64-apple-darwin' doesn't exist` until
`bash scripts/bundle_cli.sh` stages the Tauri sidecar. CI does this correctly
(`ci.yml:117-118`, `packaged-service-macos.yml:106-107`, `release.yml:108-109`)
and the directory is gitignored by design, but `CONTRIBUTING.md` does not
mention it. A first-time contributor running the documented commands hits a
confusing build failure.
