# Findings index — fresh final audit of PR #16

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`
Audit branch: `audit/pr16-fresh-final-20260729`
PR state at audit close: **OPEN, unmerged, MERGEABLE**, all six checks SUCCESS.

## Merge blockers

| ID | Severity | Title |
| --- | --- | --- |
| **`NEW-01`** | **High-Med** | `tethra track` prints "✓ Tracking verified" and exits 0 from a liveness-blind cached state, contradicting the rule the same file states for `track status` |
| **`NEW-37`** | **High** | The default dashboard renders `0 / 0` tokens and `$0.0000` for providers that report no usage — a fabricated zero, contradicting three written invariants, with the correct guard already implemented elsewhere |
| **`NEW-49`** | **High** | `docs/gateway/SECURITY.md:40-47`, `ARCHITECTURE.md:121-123` and a shipped UI string claim database tampering cannot redirect credentials — the exact property SEC-01 does not provide |

**Three blockers.** All three are honesty defects on the product's headline
claims — a false verification claim, a fabricated usage figure, and a false
security guarantee. All three are small, localized fixes, and in each case the
correct statement already exists elsewhere in the same repository. Everything
else below is a real but non-blocking defect, a documentation-accuracy gap, or
an accurately-classified deferral.

## New findings

| ID | Sev | Title | Blocking |
| --- | --- | --- | --- |
| `NEW-01` | High-Med | CLI verify loop gates the success headline on `check_traffic` (liveness-blind), not `CurrentHealth` | **Yes** |
| `NEW-37` | High | `DashboardView.tsx:290-296` prints tokens and cost with no `usage_event_count` guard — a fabricated zero on the default view | **Yes** |
| `NEW-49` | High | Shipping docs and a UI string claim DB tampering cannot redirect credentials; `routes.rs:628-650` resolves manifest routes from an unauthenticated `provider_id` | **Yes** |
| `NEW-48` | Medium | The SEC-02 body deadline is per **request**, not per connection — one connection held a slot **422 s**; three documents state a ~360 s bound that does not hold | No |
| `NEW-38` | High | `CredentialDetail.tsx:114` swallows a failed `providerGet` into `manifest = null`, so a transport error renders as "This provider has no API key creation / no API revocation" | No |
| `NEW-51` | Low | SEC-02 has no integration coverage; deleting the wiring at `forward.rs:854-856` leaves both shipped tests green | No |
| `NEW-52` | Low | A deadline expiry is recorded identically to a client disconnect — no counter, no 408 | No |
| `NEW-50` | Low | `routes.rs:74` `a_direct_update_of_a_manifest_route_row_cannot_redirect_it` tests only an **unknown** provider id (fails closed), never a known one (succeeds) | No |
| `NEW-53` | Low | The Rust privacy canary sweep is non-recursive, so `<data-dir>/logs/gateway.log` is scanned only by the macOS-runner shell harness; CI evidence artifacts are never canary-scanned | No |
| `NEW-54` | Low | Slow request **body** is the one attack class with unit-only coverage; no test drives a slow body at a live gateway | No |
| `NEW-39` | Medium | `GatewayView.tsx:716-717` tells the 8 detect-only providers they "have no fixed API origin", which is false for all of them | No |
| `NEW-40` | Medium | `IMPLEMENTATION_STATUS.md:4` claims "every claim below is executed evidence"; at least five numbers are stale, including the `42` the harness's own header identifies as the defective pre-ZFT-VAL-4 count | No |
| `NEW-41` | Medium | Four UI surfaces swallow load errors into an empty state (`AlertsView`, `ApiActivityView`, `ProviderConnectionPanel`, `CredentialForm`), contradicting the PR's blanket "every list distinguishes … error" claim | No |
| `NEW-42` | Medium | `tethra track .` on a machine with no vault fails with "the vault is locked. Set TETHRA_PASSWORD…" — the vault is not locked, it does not exist, and the message never says `tethra init` | No |
| `NEW-43` | Medium | Headline coverage buckets and row labels use different precedence, so the screen shows 6 "automatic" rows under a headline saying 3 | No |
| `NEW-44` | Medium | The superseded fake scale test `thirty_detected_providers_stay_one_plan_with_no_per_provider_forms` (`plan_apply.rs:669`) still ships, planning 3 providers under the name the prior audit criticised | No |
| `NEW-45` | Low | `RELEASE_NOTES.md:26-27` says "per-key usage/cost sync" for Anthropic; `anthropic.toml:49` says cost has no per-key grouping | No |
| `NEW-46` | Low | `FEATURE_MATRIX.md:243` says 5 embedded manifests; there are 21 | No |
| `NEW-47` | Low | "nothing resolves relative to the repository" is asserted in CI but never tested (I verified the property holds by measurement) | No |
| `NEW-02` | Medium | `tethra gateway install` persists the port *after* starting the service; `doctor`/`status` cannot see the resulting divergence | No |
| `NEW-03` | Medium | Validation cleanup's `bootout` skips its ownership proof when the plist is absent (`$HOME`-keyed guard, non-`$HOME`-keyed operation) | No |
| `NEW-04` | Medium | `TETHRA_VALIDATE_LIB_ONLY=1` exits 0 silently on a real execution; two CI gates would pass vacuously | No |
| `VAL-05-R` | Medium | Manifest binds check *identities* for 9 of 63 service-scope checks; 54 are count-bound, and 0 of 57 in `full:foreground` | No |
| `NEW-05` | Low-Med | `REFRESH_CAS_ATTEMPTS` is unpinned — setting it to 1 leaves 158/158 green | No |
| `NEW-09` | Medium | Origin approval MAC binds vault, not project — a second repo inherits it non-interactively under `--yes` | No |
| `NEW-10` | Medium | `origin::list`/`origin::revoke` have no production callers — approvals are permanent and invisible | No |
| `NEW-06` | Low | `KNOWN_LIMITATIONS.md` carries no ENC-02 entry | No |
| `NEW-07` | Low | `tethra unlock` and `track`'s interactive fallback hold a keyed vault and skip the migration | No |
| `NEW-08` | Low | `checkpoint_truncate` errors swallowed after COMMIT; WAL may retain legacy plaintext, never retried | No |
| `NEW-11` | Low-Med | CLI/desktop drift on `PreviouslyApproved` handling | No |
| `NEW-12` | Low | `--yes --allow-origin` persists an approval; disclosure never says approvals are remembered | No |
| `NEW-13` | Info | No cross-vault MAC replay test (the binding itself is sound) | No |
| `NEW-14` | Low | `BadHostname`/`BadPort` reported as "loopback, private, link-local, cloud-metadata" | No |
| `NEW-15` | Low | `OriginTrust::may_configure_without_asking` is dead code; its doc comment is false | No |
| `NEW-16` | Info | `ExistingOriginKept` suppressed when a manifest route pre-exists — approved redirect silently inert | No |
| `NEW-17` | Low | `validation_ownership_tests.sh:31` claims it never calls launchctl; it does | No |
| `NEW-18` | Low | Ownership-test floor `MIN=29` exactly equals the actual count — zero headroom | No |
| `NEW-19` | Low | Ownership test leaks `/tmp/tethra-track-val-$$`, poisoning a later precondition locally | No |
| `NEW-20` | Low | `ci_service_preconditions.sh` never globs `/private/tmp/tethra-gw-val-*` | No |
| `NEW-21` | Low | Gateway harness teardown emits no positive cleanup evidence | No |
| `NEW-22` | Info | `cargo test --workspace` fails from a clean checkout until `scripts/bundle_cli.sh` stages the sidecar (CI does it; undocumented for contributors) | No |
| `NEW-23` | Info | The handoff lists 14 deferred findings; the matrix defers 15 — ENC-02 is the omitted one | No |
| `NEW-24` | Info | REPO-01 is framed as "blocked on admin access"; the credential in use already has admin | No |
| `NEW-25` | Low | GitHub secret scanning, push protection and Dependabot are all **disabled** on this public credential-manager repository | No |
| `NEW-26` | Low | A counted check inside a nested loop makes the gateway harness's required total data-dependent | No |
| `NEW-27` | Low | A required gateway check sits behind `if command -v python3` with an emitting-nothing else branch | No |

## Prior findings rechecked

| ID | Status at this head | Blocking now |
| --- | --- | --- |
| `VAL-01` | **Fixed and independently proved** — 29/30 forgery vectors refused | No |
| `VAL-02` | Fixed — dead `sed` gone, `product_status_field` fails closed | No |
| `VAL-03` | Fixed — and now **executed** in CI on this head | No |
| `VAL-04` | **Fixed and independently mutation-proved** (4 mutants, all caught) | No |
| `VAL-05` | **Not fixed**, accurately disclosed; `REQUIRED_CHECKS=50` independently confirmed correct | No |
| `VER-01` | Fixed — CAS sound; `transition` callers behave as claimed | No |
| `VER-02` | **Fixed at core and desktop; open at the CLI** → `NEW-01` | **Yes** |
| `ENC-01` | Fixed — desktop call site reachable on every successful unlock | No |
| `ENC-02` | **Unresolved**, independently confirmed; requires a local-write adversary | No |
| `ORG-01` | **Fixed and mutation-proved load-bearing** (6 of 11 tests fail under mutation) | No |
| `SEC-01` | Accepted — threat-model exclusion verified | No |
| `SEC-02` | Fixed — deadline is request-body-only by construction; streaming responses unaffected | No |
| `VER-03` | Accepted | No |
| `REM-001…006` | Fixed; REM-002's subshell defect independently reproduced and shown caught | No |
| `ZFT-006` | Fixed — core mutations M2/M3 killed by named tests | No |
| `ZFT-010` | Fixed — the real 30-integration fixture exists; 9/9 tests pass | No |
| `REPO-01` | Unchanged — governance recommendation, not a product-security block | No |
| 14 deferred | All reproduce; four understated; one genuine compound pair (`VAL-07`+`VAL-08`) | No |
| Intermittent packaged link | **Root-caused** → `NEW-02`; misclassified as harness-only | No |

## Evidence documents

* `VALIDATION_TRUST_EVIDENCE.md` — forgery suite, mutation of the primitives, count derivation
* `VERIFICATION_CONCURRENCY_EVIDENCE.md` — CAS analysis, ZFT-006 mutations, the `NEW-01` trace
* `LEGACY_ENCRYPTION_EVIDENCE.md` — migration properties, ENC-02 mechanism, canaries
* `ORIGIN_APPROVAL_EVIDENCE.md` — every `--yes` branch, canonicalization table, the ORG-01 mutation
* `SERVICE_LIFECYCLE_EVIDENCE.md` — ownership ledger, namespace isolation, CI verb-by-verb evidence
* `PACKAGED_LINK_RELIABILITY.md` — root cause of the nondeterministic failure
* `TRANSACTION_AND_RECOVERY_EVIDENCE.md` — races, crash points, recovery
* `USER_JOURNEY_EVIDENCE.md` — clean packaged journey, provider honesty
* `SECURITY_AND_PRIVACY_EVIDENCE.md` — gateway attack surface, SEC-01/SEC-02, canaries
* `DEFERRED_FINDINGS_REVIEW.md` — all 14 plus REPO-01 and repository controls
* `SOURCE_REVIEW_LEDGER.md` — what was read, executed, mutated, and skipped
* `FINAL_VERDICT.md` — the decision and what would change it
* `findings.json` — machine-readable
* `repro/` — the scripts this audit ran
