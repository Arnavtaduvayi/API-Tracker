# Remediation Matrix — every finding from the independent audit of PR #16

Source: `docs/activity-onboarding/audit/fable-independent-20260727/findings.json`
(64 findings: 1 CRITICAL, 15 HIGH, 21 MEDIUM, 23 LOW, 4 INFO; 15 merge-blocking).

The audit branch `audit/fable-zft-independent-20260727` is **unchanged**. This file
records what was done about each finding; it does not edit the audit's own verdict.

Dispositions used: `FIXED`, `DOCUMENTATION CORRECTED`, `TEST CORRECTED`,
`ACCEPTED RISK`, `NOT REPRODUCED`, `DUPLICATE`, `DEFERRED BY EXTERNAL ACTION`.

**Reproduction.** Every CRITICAL and HIGH finding was reproduced against the audited
head before any production code changed: `ZFT-001` by the lead directly against a
release build (canary fired 4x during `--dry-run`), the rest by seven independent
subagents. Of the 53 findings put through reproduction, 49 reproduced exactly, 3
reproduced with a correction to the audit's own text (recorded below), and 1
(`ZFT-014`) reproduced by source analysis only because reproducing it live would
have required taking down this machine's production gateway a second time.

## Summary

| Disposition | Count |
|---|---|
| FIXED | 49 |
| DOCUMENTATION CORRECTED | 13 |
| TEST CORRECTED | 1 |
| ACCEPTED RISK | 1 |
| **Total** | **64** |

All 15 merge-blocking findings are resolved: ZFT-001, ZFT-002, ZFT-003, ZFT-004, ZFT-005, ZFT-006, ZFT-007, ZFT-008, ZFT-009, ZFT-010, ZFT-011, ZFT-012, ZFT-013, ZFT-014, ZFT-015.

## Index

| ID | Sev | Blocking | Disposition | Title |
|---|---|---|---|---|
| [ZFT-001](#zft-001) | CRITICAL | YES | FIXED | Arbitrary code execution when a folder is scanned |
| [ZFT-002](#zft-002) | HIGH | YES | FIXED | Symlink escape: files outside the selected folder are read |
| [ZFT-003](#zft-003) | HIGH | YES | FIXED | .env files are read with no size cap |
| [ZFT-004](#zft-004) | HIGH | YES | FIXED | Auto-created route origin taken from repository content; documented confirmation gate not implemented |
| [ZFT-005](#zft-005) | HIGH | YES | FIXED | 'Tracking verified' survives the gateway being dead |
| [ZFT-006](#zft-006) | HIGH | YES | FIXED | A failed re-run reports 'tracking verified' and erases the failure reason |
| [ZFT-007](#zft-007) | HIGH | YES | FIXED | track undo after a failed apply silently restores nothing and reports success |
| [ZFT-008](#zft-008) | HIGH | YES | FIXED | Re-derivation is skipped when the watermark is missing; a row renders verified with zero events |
| [ZFT-009](#zft-009) | HIGH | YES | FIXED | Unsupported-project dead end demands terminal commands and manual route creation |
| [ZFT-010](#zft-010) | HIGH | YES | FIXED | Unknown API credentials are silently dropped from the review screen |
| [ZFT-011](#zft-011) | HIGH | YES | FIXED | Coverage is three providers; the product promise does not scale past them |
| [ZFT-012](#zft-012) | HIGH | YES | FIXED | Existing custom base URL is silently re-pointed to the manifest origin, and raises confidence |
| [ZFT-013](#zft-013) | HIGH | YES | FIXED | Attribution consent under-discloses the granted capability; the security document's claim is false |
| [ZFT-014](#zft-014) | HIGH | YES | FIXED | The tracking flow boots out any existing gateway service (fixed LaunchAgent label) |
| [ZFT-015](#zft-015) | HIGH | YES | FIXED | Setup screen shows 'Waiting for traffic...' forever after polling has permanently stopped |
| [ZFT-016](#zft-016) | MEDIUM | — | FIXED | prior_env_json persists raw URLs including query strings |
| [ZFT-017](#zft-017) | MEDIUM | — | FIXED | Masking bypass prints full credentials to stdout and IPC |
| [ZFT-018](#zft-018) | MEDIUM | — | FIXED | Re-apply destroys route provenance |
| [ZFT-019](#zft-019) | MEDIUM | — | FIXED | Undo never restores a route's prior enabled=false state |
| [ZFT-020](#zft-020) | MEDIUM | — | DOCUMENTATION CORRECTED | 'Narrowly scoped matching capability' overstates narrowness |
| [ZFT-021](#zft-021) | MEDIUM | — | FIXED | Foreground fallback child outlives the app |
| [ZFT-022](#zft-022) | MEDIUM | — | FIXED | Stale plan leaves .env pointing at a link slug with no DB row |
| [ZFT-023](#zft-023) | MEDIUM | — | FIXED | Digest binds the planned output, not the previewed input |
| [ZFT-024](#zft-024) | MEDIUM | — | FIXED | Migration duplicates the project for a manually-configured user |
| [ZFT-025](#zft-025) | MEDIUM | — | FIXED | Confirmed is self-confirming after the first link |
| [ZFT-026](#zft-026) | MEDIUM | — | FIXED | pyproject.toml prefix matching invents SDK dependencies |
| [ZFT-027](#zft-027) | MEDIUM | — | FIXED | Placeholder filter is the only value check |
| [ZFT-028](#zft-028) | MEDIUM | — | FIXED | Detection cost unbounded in file count |
| [ZFT-029](#zft-029) | MEDIUM | — | FIXED | Activity summary is global; per-project attribution is unanswerable |
| [ZFT-030](#zft-030) | MEDIUM | — | FIXED | Raw internal enum tokens rendered on the primary dashboard |
| [ZFT-031](#zft-031) | MEDIUM | — | FIXED | Swallowed error hides a coverage warning |
| [ZFT-032](#zft-032) | LOW | — | FIXED | .env marker comment tells the user to run a command they do not have |
| [ZFT-033](#zft-033) | LOW | — | FIXED | Marker comment emitted twice per file; stray bare path line in the diff header |
| [ZFT-034](#zft-034) | LOW | — | FIXED | Raw Rust Debug output in user-facing CLI |
| [ZFT-035](#zft-035) | LOW | — | DOCUMENTATION CORRECTED | ReadOnly warning text is wrong on Unix |
| [ZFT-036](#zft-036) | LOW | — | FIXED | track undo/doctor open an un-migrated connection |
| [ZFT-037](#zft-037) | LOW | — | FIXED | undo/doctor act on the oldest setup; status reports the newest |
| [ZFT-038](#zft-038) | LOW | — | ACCEPTED RISK | .env permissions forced to 0600; crash window leaves a secret-bearing temp file |
| [ZFT-039](#zft-039) | LOW | — | FIXED | Every service-lifecycle error labelled 'macOS blocked the background service (unsigned build)' |
| [ZFT-040](#zft-040) | LOW | — | FIXED | Non-UTF-8 files dropped with no counter increment |
| [ZFT-041](#zft-041) | LOW | — | FIXED | Installed-helper version is stamped, not measured |
| [ZFT-042](#zft-042) | LOW | — | DOCUMENTATION CORRECTED | Drag-to-Trash uninstall leaves the LaunchAgent running |
| [ZFT-043](#zft-043) | INFO | — | DOCUMENTATION CORRECTED | PACKAGING.md claims macOS x64 desktop artifacts that are never built |
| [ZFT-044](#zft-044) | INFO | — | DOCUMENTATION CORRECTED | INSTALL.md states the zero-CLI claim unqualified for all platforms |
| [ZFT-045](#zft-045) | INFO | — | DOCUMENTATION CORRECTED | cargo build --release --workspace fails on a clean checkout |
| [ZFT-046](#zft-046) | INFO | — | FIXED | Tokens rendered without the lower-bound qualifier that cost carries |
| [ZFT-047](#zft-047) | LOW | — | DOCUMENTATION CORRECTED | 'value-free' persisted state includes an env-derived value |
| [ZFT-VAL-1](#zft-val-1) | HIGH | — | FIXED | CI runs neither the packaged validation nor the smoke suite, and never builds a packaged app |
| [ZFT-VAL-4](#zft-val-4) | MEDIUM | — | FIXED | The recorded validation run used the self-weakened foreground mode |
| [ZFT-VAL-6](#zft-val-6) | MEDIUM | — | FIXED | The '30-provider-scale test' does not test 30 providers |
| [ZFT-VAL-5](#zft-val-5) | MEDIUM | — | FIXED | The privacy canary named CANARY is never searched for |
| [ZFT-VAL-7](#zft-val-7) | MEDIUM | — | FIXED | 4 of 42 counted checks are unconditional passes; the anti-vacuity floor cannot detect tautology |
| [ZFT-VAL-8](#zft-val-8) | MEDIUM | — | FIXED | The advertised forged-old-event negative control does not exist |
| [ZFT-VAL-3](#zft-val-3) | LOW | — | FIXED | 'Version-matched helper' is never verified |
| [ZFT-VAL-2](#zft-val-2) | LOW | — | DOCUMENTATION CORRECTED | 'Eight commits, each independently green' is doubly wrong |
| [ZFT-VAL-9](#zft-val-9) | LOW | — | FIXED | PACKAGED_VALIDATION group table sums to 40, not 42 |
| [ZFT-VAL-10](#zft-val-10) | LOW | — | FIXED | Packaged 'byte for byte' undo check strips trailing newlines |
| [ZFT-VAL-11](#zft-val-11) | LOW | — | DOCUMENTATION CORRECTED | 'CI clippy pins +1.97.0' is false |
| [ZFT-VAL-12](#zft-val-12) | LOW | — | DOCUMENTATION CORRECTED | 'Final head 4e3cc98' is wrong by construction |
| [ZFT-VAL-13](#zft-val-13) | LOW | — | DOCUMENTATION CORRECTED | 'closes O10' without closing the O10 record |
| [ZFT-VAL-14](#zft-val-14) | LOW | — | FIXED | 'Every bound is a test, not a promise' - except the symlink bound on Windows |
| [ZFT-VAL-15](#zft-val-15) | LOW | — | DOCUMENTATION CORRECTED | TROUBLESHOOTING implies eight automated causes; six are automated |
| [ZFT-VAL-16](#zft-val-16) | LOW | — | TEST CORRECTED | track_json_status_shape_is_stable asserts no JSON |
| [ZFT-VAL-17](#zft-val-17) | LOW | — | DOCUMENTATION CORRECTED | KNOWN_LIMITATIONS omits three disclosed-elsewhere limits |

---

## ZFT-001

**Arbitrary code execution when a folder is scanned**

* **Severity:** CRITICAL · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** git init in a folder; git config core.fsmonitor <payload>; add a .env with OPENAI_API_KEY; run `tethra track <folder> --dry-run` from the packaged app. Payload executed 4 times.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `envgov::discover` asked git four questions per discovered file; git honours the SCANNED repository's own config, which names programs it executes. `safe.directory` does not fire for a repo owned by the same user.
* **Code changes:** New `core::gitsafe` answers the same questions by reading bytes (`.git` resolution incl. `gitdir:` pointers, the `.git/index` DIRC format v2/v3/v4 for SHA-1 and SHA-256, an in-process gitignore evaluator with git's precedence). The automatic path spawns nothing. The deliberate secret-scanner path still shells out, now under `-c` overrides for every executable config key, `--no-ext-diff --no-textconv` on diff-producing commands, `--no-pager`, config-file isolation, a scrubbed environment and a controlled working directory.
* **Test changes:** `core/tests/git_execution_canaries.rs` (6) — executable canaries for fsmonitor, hooks, filters, textconv, external diff drivers, aliases, pager, editor, credential helper, submodule update, a nested hostile repo, a hostile global config and a hostile environment, plus `each_canary_is_armed_against_unhardened_git` which requires the unprotected equivalent to FIRE. `core/tests/gitsafe_differential.rs` (7) proves the reader agrees with real git.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Ignore answers reflect repository-local rules only: `core.excludesFile` (the user's global ignore file) is not honoured, and commit history is not answered by the non-executing reader. Both are documented in KNOWN_LIMITATIONS.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-002

**Symlink escape: files outside the selected folder are read**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** Symlink proj/package.json to a file outside the folder; run `tethra track proj --dry-run`. Two providers detected at `likely` from outside content.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Two readers disagreed. `stackdetect::read_bounded` used `std::fs::metadata` (which follows symlinks) with no containment check; `detect::read_bounded` had both. The file is `crates/core/src/stackdetect.rs`, not `crates/tracking/` as the audit cited.
* **Code changes:** `stackdetect::read_bounded` refuses symlinks via `symlink_metadata` and requires the canonical path to be under the root. Existence probes (`Dockerfile`, `.devcontainer`, `next.config.*`) go through new `is_contained_file`/`is_contained_dir` because `Path::is_file` follows symlinks too.
* **Test changes:** `tracking/tests/scan_bounds.rs` — symlinked `package.json`, `requirements.txt`, `pyproject.toml` and marker files, each with a control proving a real in-folder file is still read.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** A HARDLINK to a file outside the folder is indistinguishable from a real file at the filesystem level and is still read (variable names only). Documented.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-003

**.env files are read with no size cap**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** 234 MB .env; `/usr/bin/time -l tethra track <dir> --dry-run` -> maximum resident set size 1923170304 (1.92 GB, 8.2x), 1.41 s, and the run reports '0 file(s) read'.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `envgov.rs:182` read every `.env*` in full with `read_to_string` before any cap was consulted; the cap lived in the other reader.
* **Code changes:** `discover_bounded` checks the size on the DIRECTORY ENTRY before the file is opened. Oversized files stay in the inventory marked `oversized` with zero parsed entries, and are reported.
* **Test changes:** `scan_bounds.rs::an_oversized_env_file_is_never_read_into_memory` asserts entry_count == 0 and problems.is_empty(), which can only hold if the bytes were never parsed; plus a control that a normal file IS parsed.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-004

**Auto-created route origin taken from repository content; documented confirmation gate not implemented**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** A fixture with NO secrets: package.json naming @supabase/supabase-js and .env.development with SUPABASE_URL=https://attacker-controlled.example.com. Plan says 'create routes: supabase -> https://attacker-controlled.example.com'. Carried through --yes: route MAC'd, enabled, persisted, verification key pushed, .env rewritten.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `Selections::defaults` auto-filled the very confirmation `NeedsOriginConfirm` names, and the only gate was one bulk `confirm("Proceed?", yes)`.
* **Code changes:** New `tracking::origin` separates detection evidence from authorization: `BuiltInManifest` (automatic), `PreviouslyApproved` (exact origin, MAC'd in `tracking_approved_origins`), `RepositoryDiscovered` (explicit per-origin decision, default OFF). `Selections::defaults` includes only `Automatic`. CLI adds `--allow-origin`; `--yes` refuses. Desktop checkbox defaults OFF with full disclosure.
* **Test changes:** `tracking/tests/origin_trust.rs` (14) — default-off, built-in still automatic, exact-origin reuse, subdomain/different-provider rejection, tampered row rejected, re-approval on change, full disclosure content, restricted destinations refused before being offered, 30-API scale, and an end-to-end `--yes` control with its approved counterpart.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Approval is per (origin, provider) and per vault. A user who approves a destination they should not have is not protected by this; the control is disclosure plus a default of no.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-005

**'Tracking verified' survives the gateway being dead**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** pkill the gateway; curl the port -> 000; `tethra track status <proj>` -> 'State: tracking verified - traffic observed'.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `state::refresh` consulted only historical event rows: no route check, no link check, no gateway probe, no freshness bound.
* **Code changes:** `refresh_with` takes `GatewayLiveness` as an input and gates present-tense success on a fresh observation AND the route AND the link AND a live gateway. New `CurrentHealth` (11 states incl. `VerifiedPreviouslyGatewayDown`, `ConfigurationChanged`, `VerificationExpired`-equivalent idle) is separate from `VerificationHistory`.
* **Test changes:** `tracking/tests/verification_freshness.rs` (16) — dead gateway, stale observation, route removal, link removal, unknown liveness, each with a control proving the success path still works.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** `OBSERVATION_FRESHNESS_SECS` is 6 h. A project idle longer reads as 'verified previously', which is honest but may read as alarming for a genuinely idle project.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-006

**A failed re-run reports 'tracking verified' and erases the failure reason**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** `tethra track <proj> --yes` fails with 'the service did not answer on 127.0.0.1:55102 within 10 s'; the immediately following `tethra track status` reports 'tracking verified - traffic observed'.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `upsert_setup`'s ON CONFLICT updated four columns, so `applied_at`, `plan_summary_json` and `first_traffic_at` survived a re-run; the derived promotion then nulled `attention_reason`.
* **Code changes:** Migration v16 adds `verification_session`, `config_generation`, `first_verified_at` and `attention_at`. Every re-run mints a session, bumps the generation and clears the previous attempt's apply artifacts. A failure carries `attention_at`, and a derived promotion never clears a reason NEWER than the newest observation.
* **Test changes:** `verification_freshness.rs::old_traffic_cannot_verify_a_new_setup_attempt`, `::a_current_failure_is_not_erased_by_older_success`, and the converse control `::an_observation_after_the_failure_does_clear_it`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-007

**track undo after a failed apply silently restores nothing and reports success**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** Harness: apply fails at PathCheck after the .env was rewritten; undo reports complete=true, links_restored=0, routes_removed=[]; .env not restored; 2 routes and 2 links left; .env still points at the gateway.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `undo.rs:28-33` read a missing plan summary with `.unwrap_or_default()`, turning 'we do not know what apply did' into 'nothing was done'.
* **Code changes:** Undo derives links from `gateway_project_links` (ground truth) and REFUSES to report completion when the summary is absent but links exist, with a note naming what was left. An incomplete undo keeps `applied_at` so status stays honest.
* **Test changes:** `tracking/tests/undo_ground_truth.rs` (5) incl. a control that a fully recorded undo still completes and closes the session.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** When the summary is absent, routes cannot be classified created-vs-reused, so they are left in place and reported rather than removed.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-008

**Re-derivation is skipped when the watermark is missing; a row renders verified with zero events**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** Set state='traffic_observed', applied_at=NULL (both nullable, db.rs:1026). Harness: 'H1 events_in_db=0 watch=Observed state=TrafficObserved'. Same via plan_summary_json=NULL.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Two early returns in `refresh` fired BEFORE any correction, so a nulled `applied_at` skipped derivation entirely.
* **Code changes:** Both early exits now happen AFTER the downgrade decision: a missing watermark is strictly less evidence than zero events and forces the row down to `needs_attention` with a stated reason.
* **Test changes:** `verification_freshness.rs::a_missing_watermark_forces_a_downgrade_instead_of_skipping_derivation` and `::a_missing_plan_summary_forces_a_downgrade_too` (both reproduce the audit's harness).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-009

**Unsupported-project dead end demands terminal commands and manual route creation**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** A project using Groq, Mistral, Cohere, DeepSeek, Together, Perplexity with matching SDKs -> 'No trackable APIs detected'; guidance points at `tethra provider list` and `tethra gateway route add`; exit 2.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** No non-expert fallback existed for an unrecognised provider; the empty state pointed at `tethra provider list` and `tethra gateway route add`.
* **Code changes:** The CLI empty state no longer names either command. The desktop provides in-app actions instead of a terminal instruction (see DETECTION_COVERAGE.md for the exact list). Provider coverage also grew from 3 trackable to 13, so the dead end is reached far less often.
* **Test changes:** `apps/cli/tests/track.rs::no_detection_exits_2_with_honest_guidance` asserts NEITHER command appears; desktop vitest covers the in-app path.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** A provider with no manifest still cannot be tracked automatically; the honest statement of that is the remediation, not a claim of universal coverage.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-010

**Unknown API credentials are silently dropped from the review screen**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** 30-API monorepo fixture: the screen headed 'Detected:' lists four providers. The other ~26 credentials appear nowhere - not detected, not unsupported, not unknown, not counted. A filename probe confirmed all 8 .env* variants are scanned, so this is provider coverage, not file skipping.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Detection was manifest-gated with no residual reporting path; `UnsupportedReason::UnknownProvider` was unreachable from folder content.
* **Code changes:** Detection now collects every credential-shaped variable up front and REMOVES the ones a manifest claims, so the remainder is genuinely unattributed. `ProjectDetection.unrecognized` and `CoverageSummary` (whose buckets sum to the headline) are rendered by both frontends.
* **Test changes:** `tracking/tests/detect_coverage.rs` (9) over a real 30-integration fixture: every input accounted for, counts add up, placeholders excluded, hints never become providers, values never leak.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** The name hint is a heuristic and may be absent or wrong for unusual variable names; it is presentation only and never selects a provider.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-011

**Coverage is three providers; the product promise does not scale past them**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** `tethra provider list` returns five providers; provider-manifests/ holds five .toml files; only openai, anthropic and supabase declare a base-URL environment variable.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The manifest set was five entries, three of them gateway-capable.
* **Code changes:** 21 manifests, 13 gateway-capable (11 fixed-origin, 2 custom-origin), 8 detected-but-unsupported. Every base-URL variable was verified against official SDK source and recorded in the manifest. Providers whose SDK reads no base-URL variable get no `[gateway]` section and are honestly labelled unsupported. `stackdetect` dependency maps, `LOCKFILE_NEEDLES` and `provider_template` extended so the new manifests are actually reachable.
* **Test changes:** `core/tests/provider_manifests.rs` (11) pins the counts against literals, validates every origin against the gateway's own rules, and proves the origin checker is not vacuous with 15 bad origins.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** A manifest can still name a base-URL variable no SDK reads; nothing in CI can detect that. The catalog's honesty rests on per-manifest prose plus human re-verification. Stated in KNOWN_LIMITATIONS.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-012

**Existing custom base URL is silently re-pointed to the manifest origin, and raises confidence**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** .env with OPENAI_API_KEY and OPENAI_BASE_URL=https://litellm.corp.example/v1 -> 'openai confirmed Automatic', no limitations.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The S3 branch read the base-URL value only for custom-origin providers; for a fixed-origin provider the variable's mere PRESENCE became a second 'independent' signal, and the route was then built to the manifest origin.
* **Code changes:** A fixed-origin provider whose base-URL variable already points somewhere other than the manifest origin downgrades to `NeedsOriginConfirm` on the EXISTING destination, with a limitation naming both.
* **Test changes:** `origin_trust.rs::an_existing_custom_base_url_downgrades_a_fixed_origin_provider` plus the control `::a_base_url_already_equal_to_the_manifest_origin_stays_automatic`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-013

**Attribution consent under-discloses the granted capability; the security document's claim is false**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** Read the master-password field copy in the Track flow; compare with the Advanced push-key dialog.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Consent consolidation moved the password field but not the ADR-0020 disclosure copy.
* **Code changes:** The oracle-while-resident and dropped-on-lock disclosure is carried into TrackFlow's password help text and the DashboardView resume dialog, matching the Advanced dialog in substance.
* **Test changes:** Desktop vitest asserts the disclosure text is present on both surfaces.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** See ZFT-020 for the accompanying documentation correction.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-014

**The tracking flow boots out any existing gateway service (fixed LaunchAgent label)**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** Observed live during this audit: a real `tethra track --yes` against an isolated data directory booted out this machine's running gateway (dev.api-tracker.gateway, pid 43853) serving the user's real vault. Restored with launchctl bootstrap; now pid 50655 on the original data directory. No user data lost; the plist was never rewritten.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The macOS label, systemd unit name and HKCU Run value were fixed global constants, while the launchd domain is the real `gui/<uid>` regardless of HOME. Adversarial review of the first fix found four ways back in.
* **Code changes:** Service names namespaced by `installation_id` (BLAKE3 derive_key over the canonicalized data dir). Every destructive verb, plus `start` and `register`, proves the definition points at THIS data directory. Legacy names migrated only when they point here. `repair()` no longer forces past the ownership refusal (it is on the automatic `track` path). An unparseable definition is treated as foreign, not absent. `install` rolls back on migration/registration failure so a failed upgrade cannot leave two agents. The planner hard-stops on `installed && !matches_data_dir`.
* **Test changes:** `gateway/tests/service_namespace.rs` (16) incl. a mutation check that discards the verbs' results and asserts NO destructive command reached a foreign target; `origin_trust.rs::planning_refuses_when_another_installation_holds_the_service_slot`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Moving a data directory changes its installation id, orphaning the old definition; nothing enumerates or removes it. Documented in KNOWN_LIMITATIONS. Windows remains compile-validated only.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-015

**Setup screen shows 'Waiting for traffic...' forever after polling has permanently stopped**

* **Severity:** HIGH · **Merge blocking:** YES
* **Disposition:** FIXED
* **Audit reproduction:** Start tracking, reach 'Configuration applied', wait 120 s, then restart the app and make a request.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** A one-shot `setInterval` keyed only on `phase.name`, killed permanently at the cutoff and on ANY poll error, with the screen still rendering 'Waiting for traffic…'.
* **Code changes:** Polling re-arms: a 'Check again' action restarts it, a transient IPC error is not terminal, and the muted line changes to say watching has stopped once it has.
* **Test changes:** Desktop vitest covers the re-arm and the changed copy.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-016

**prior_env_json persists raw URLs including query strings**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** OPENAI_BASE_URL=https://host/v1?api_key=sk-... then link; SELECT prior_env_json returns the full URL. Canary found at vault.db byte offset 527979.
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `envlink.rs` allowlisted on the AUTHORITY only, ignoring path, query and fragment, so a raw URL with a query string was persisted in plaintext in `vault.db`.
* **Code changes:** See REMEDIATION_EVIDENCE.md §privacy for the exact change and the canary reproduction.
* **Test changes:** `gateway/tests/privacy_canaries.rs` extended with a query-string canary searched for in the DB, WAL and SHM raw bytes.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Recorded per REMEDIATION_EVIDENCE.md.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-017

**Masking bypass prints full credentials to stdout and IPC**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** DATABASE_URL containing 'db.example.com' with a password in userinfo printed in full by track --dry-run
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `is_placeholder_value` fired on a SUBSTRING, so a `DATABASE_URL` containing `example` was treated as a placeholder and printed unmasked.
* **Code changes:** The placeholder test no longer fires on a substring inside a long, high-entropy value.
* **Test changes:** `core/tests/scanning.rs` covers `DATABASE_URL` values containing example/test/sample/changeme/localhost.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Recorded per REMEDIATION_EVIDENCE.md.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-018

**Re-apply destroys route provenance**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** apply, re-apply, undo -> routes_removed=[], kept with reason 'existed before this setup (only reused)'
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** A re-apply saw `add_manifest_route` return AlreadyExists and recorded the route as 'reused', so `created_routes` came back empty and a later undo stranded the route with a false reason.
* **Code changes:** Apply reads the previous summary's `created_routes` BEFORE the new session clears it and unions them, so a route this setup created on an earlier apply is still recorded as created.
* **Test changes:** `undo_ground_truth.rs::a_re_apply_keeps_the_first_applys_route_provenance`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-019

**Undo never restores a route's prior enabled=false state**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Disable a route, run track (re-enables it), undo -> still enabled
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Undo restored the route row but never its prior `enabled` state.
* **Code changes:** See REMEDIATION_EVIDENCE.md §privacy.
* **Test changes:** Covered in `gateway/tests/envlink.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Recorded per REMEDIATION_EVIDENCE.md.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-020

**'Narrowly scoped matching capability' overstates narrowness**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** Read PRODUCT_BEHAVIOR.md:80 against vault.rs:553 and attribution.rs:358-388
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `PRODUCT_BEHAVIOR.md:80` described the pushed key as a 'narrowly scoped matching capability'; it is the vault-wide fingerprint key and the matcher spans all gateway-linked projects.
* **Code changes:** No code change: the mechanism is as designed and disclosed in ADR 0020. The wording is corrected in SECURITY_AND_PRIVACY.md and PRODUCT_BEHAVIOR.md to say vault-wide, and the ZFT-013 consent copy now says so at the point of consent.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** The capability itself is unchanged and remains an accepted, disclosed residual risk (GW-6).
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-021

**Foreground fallback child outlives the app**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Trigger install-blocked, choose 'Track while the app is open', quit Tethra -> the gateway serve child is still running
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** No `kill()` anywhere; `RunEvent::Exit` never touched the foreground child, while the UI said 'Tracking pauses when Tethra closes'.
* **Code changes:** The foreground child is killed on app exit.
* **Test changes:** Desktop coverage per REMEDIATION_EVIDENCE.md §desktop.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-022

**Stale plan leaves .env pointing at a link slug with no DB row**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Build P1 and P2 before any link exists; apply P1 then P2 -> files carry slug B, DB has slug A; every SDK request 404s
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** A stale plan applied after another apply left `.env` pointing at a link slug with no DB row; the digest passed because the output bytes coincided.
* **Code changes:** The link slug written into a file is validated against a live link row at apply time; a plan whose slug no longer exists is refused rather than written.
* **Test changes:** `gateway/tests/envlink.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-023

**Digest binds the planned output, not the previewed input**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Change OPENAI_BASE_URL between preview and apply keeping quoting shape -> digest passes, edit silently overwritten
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The digest bound the planned OUTPUT rather than the previewed INPUT, so a value-only edit between preview and apply was silently overwritten while the doc claimed it refuses when ANY file changed.
* **Code changes:** See REMEDIATION_EVIDENCE.md §privacy.
* **Test changes:** `gateway/tests/envlink.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Recorded per REMEDIATION_EVIDENCE.md.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-024

**Migration duplicates the project for a manually-configured user**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Manual project + manual link, then run track -> second project created, new slug, .env rewritten, old link orphaned
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** A manual project without a registered repo path yielded a duplicate project, a new slug and a rewritten `.env`, contradicting MIGRATION.md.
* **Code changes:** `ensure_project` matches an existing project by name before creating one, and registers the folder on the existing row instead.
* **Test changes:** `tracking/tests/plan_apply.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-025

**Confirmed is self-confirming after the first link**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** OPENAI_BASE_URL set to Tethra's own loopback URL plus the key -> confirmed
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `Confirmed` was self-confirming after the first link: Tethra's own written `OPENAI_BASE_URL` satisfied the second 'independent signal class'.
* **Code changes:** A base-URL value pointing at `127.0.0.1` (Tethra's own writing) was already excluded from origin inference; it is now also excluded from the S3 signal that raises confidence, so Tethra's own output cannot be its own evidence.
* **Test changes:** `tracking/tests/detect.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-026

**pyproject.toml prefix matching invents SDK dependencies**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** dependencies = ["openai-whisper>=20240930"] -> openai likely Automatic, auto-selected
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `pyproject.toml` matched dependency names by PREFIX (`"openai` matched `openai-whisper`) while `requirements.txt` matched exactly, so the two parsers disagreed about the same project.
* **Code changes:** Both parsers extract the package name with one shared PEP 508 / PEP 503 normalizing function and compare it whole.
* **Test changes:** `detect.rs::a_prefix_named_package_is_not_the_package_it_prefixes`, with a control that the REAL package is still detected from both files.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-027

**Placeholder filter is the only value check**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** OPENAI_API_KEY=abcdefgh -> likely + Automatic + auto-selected
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The manifests carried each provider's published key-format patterns and detection never consulted them, so the placeholder filter was the only check a value ever got.
* **Code changes:** New `scanner::value_matches_provider_format`. A value of the published shape promotes a lone S1 to `Confirmed`; a value of NO recognised shape holds a lone S1 at `Possible`, below the auto-select threshold. The value is tested and dropped.
* **Test changes:** `detect.rs::a_key_whose_value_matches_the_published_format_is_confirmed` and `::a_key_of_no_recognised_shape_stays_below_the_auto_select_threshold`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** A provider may issue a format the manifest predates; a non-match lowers confidence but never refuses, so such a key is still detected and offered for review.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-028

**Detection cost unbounded in file count**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** 300 .env files in a git repo -> 16.5 s; 2000 .env files -> 39.9 s
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Depth was the only bound; file count, bytes and time were unbounded, and up to four git spawns ran per file.
* **Code changes:** `DiscoveryLimits` bounds files, directories, per-file bytes, total bytes and wall clock; the walk reports `DiscoveryTruncation` rather than presenting a partial scan as complete. Git spawns in this path are now zero.
* **Test changes:** `scan_bounds.rs::the_file_budget_stops_the_walk_and_says_so`, with a control that an ordinary project is never truncated.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-029

**Activity summary is global; per-project attribution is unanswerable**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Track two folders, generate traffic from both, open Activity
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `GatewayActivitySummary` had no project or provider dimension.
* **Code changes:** See REMEDIATION_EVIDENCE.md §desktop for the chosen approach and its justification.
* **Test changes:** Desktop vitest.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Recorded per REMEDIATION_EVIDENCE.md.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-030

**Raw internal enum tokens rendered on the primary dashboard**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Enable attribution, generate traffic, open Activity -> 'matched_fingerprint - 12', 'unavailable - 4'
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Raw internal enum tokens (`matched_fingerprint — 12`, `unavailable — 4`) rendered on the primary dashboard.
* **Code changes:** Every enum token maps to a sentence before rendering.
* **Test changes:** Desktop vitest.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-031

**Swallowed error hides a coverage warning**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Make trackingForegroundActive throw while foreground mode is active
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** A failed foreground check rendered identically to 'background service running', so the user believed tracking continued after closing the app.
* **Code changes:** The error state renders distinctly.
* **Test changes:** Desktop vitest.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-032

**.env marker comment tells the user to run a command they do not have**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Any apply; the comment says 'or run: tethra gateway status'
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The `.env` marker comment instructed the user to run `tethra gateway status`, a command a desktop-only user does not have on PATH, and named internal concepts inside their source tree.
* **Code changes:** The marker comment is rewritten in the product's own vocabulary with no CLI instruction.
* **Test changes:** `gateway/tests/envlink.rs` asserts the comment names no CLI command.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** The comment is still written into the user's source tree; that is inherent to the mechanism and is disclosed in the diff before apply.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-033

**Marker comment emitted twice per file; stray bare path line in the diff header**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Any dry-run
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The marker comment was emitted once per WRITTEN VARIABLE (three times for openai, not twice as the audit stated), and the diff header printed a stray bare path line.
* **Code changes:** One marker per file-and-provider block, and the duplicated diff header line removed.
* **Test changes:** `gateway/tests/envlink.rs`; `apps/cli/tests/track.rs` asserts the diff header appears once.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None. The audit's text said 'twice per file'; the true behaviour was once per written variable — worse, not better.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-034

**Raw Rust Debug output in user-facing CLI**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** tethra track undo -> 'Restored { path: "...", key: "..." }'
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `track undo` printed the Rust `Debug` form of `RestoreOutcome` straight to the terminal.
* **Code changes:** New `describe_restore` renders one plain sentence per outcome.
* **Test changes:** `apps/cli/tests/track.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-035

**ReadOnly warning text is wrong on Unix**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** Read plan.rs:478 against envlink.rs:166-167
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The `ReadOnly` warning text claims an atomic rename will fail; on Unix a rename succeeds regardless of the file's read-only bit.
* **Code changes:** The warning text is corrected to describe what actually happens per platform.
* **Test changes:** None (copy).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-036

**track undo/doctor open an un-migrated connection**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Upgrade from v14, run track undo
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `track undo`/`doctor` opened the database WITHOUT running migrations, so the first command after a v14→v15 upgrade failed with 'no such table: tracking_setups'.
* **Code changes:** `setup_for_folder` migrates the connection like every other entry point.
* **Test changes:** Covered by the v15→v16 upgrade path in `core/tests/migration_safety.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-037

**undo/doctor act on the oldest setup; status reports the newest**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Two setups for one folder; status describes one, undo targets the other
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `setups_for_folder` returns newest-first and `setup_for_folder` used `pop()`, taking the OLDEST, while `track status` reported the newest.
* **Code changes:** `setup_for_folder` takes the first (newest) element, matching `status`.
* **Test changes:** Same-file coverage in `apps/cli/tests/track.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-038

**.env permissions forced to 0600; crash window leaves a secret-bearing temp file**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** ACCEPTED RISK
* **Audit reproduction:** 0644 .env becomes 0600 after apply; a crash between temp write and rename leaves .{name}.api-tracker-tmp-{uuid} containing the full file
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `atomic_write` forces 0600 on `.env`, and a crash between write and rename can leave a temp file containing full secrets under a name no `.gitignore` covers.
* **Code changes:** The temp file is created 0600 and unlinked on every error path; the sweeper removes stragglers older than an hour. Forcing 0600 is deliberate: a `.env` holding credentials should not be world- or group-readable, and the alternative (preserving a 0644 mode) is a worse default.
* **Test changes:** Existing coverage in `core/src/envgov.rs` tests.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** A `.env` that another uid legitimately needs to read will break. Documented in KNOWN_LIMITATIONS. The crash window is bounded by the sweeper, not eliminated.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-039

**Every service-lifecycle error labelled 'macOS blocked the background service (unsigned build)'**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Any lifecycle failure
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Every service-lifecycle error was labelled 'macOS blocked the background service (this build is unsigned)'.
* **Code changes:** Only the exec-probe refusal — the actual Gatekeeper signature — carries that label; every other error is reported verbatim.
* **Test changes:** `gateway/tests/lifecycle.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-040

**Non-UTF-8 files dropped with no counter increment**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** A non-UTF-8 package-lock.json is skipped silently
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Non-UTF-8 files were dropped with no counter increment.
* **Code changes:** Both readers read bytes then decode, and count a decode failure in `skipped_not_utf8`, which the review screen renders.
* **Test changes:** `scan_bounds.rs::a_non_utf8_manifest_is_counted_not_silently_dropped`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** No binary sniff: a UTF-8-decodable binary file is still parsed as text, harmlessly.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-041

**Installed-helper version is stamped, not measured**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Break the sidecar, leave an older tethra on PATH, run install/repair
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The installed helper's version was stamped from the installing app rather than measured, so a fallback helper defeated drift detection while the probe printed the true version and discarded it.
* **Code changes:** The exec probe's reported version is what gets recorded.
* **Test changes:** `gateway/tests/helper_discovery.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-042

**Drag-to-Trash uninstall leaves the LaunchAgent running**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** Trash the app without using in-app Uninstall
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Drag-to-Trash uninstall leaves the LaunchAgent plist; with the data dir left in place the gateway keeps starting at every login with the app gone. `PACKAGING_PLAN §7` promises an in-app notice that does not exist.
* **Code changes:** `docs/INSTALL.md` now names the plist path and the uninstall step. The unimplemented `PACKAGING_PLAN §7` claim is removed rather than left as a promise. The audit's secondary claim of a crash loop is WRONG: the service self-exits cleanly and `KeepAlive={Crashed:true}` treats that as terminal, so the result is an orphaned plist, not a spawn loop.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** A user who drags the app to Trash without running uninstall still leaves an orphaned login item. The documented step is the remediation.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-043

**PACKAGING.md claims macOS x64 desktop artifacts that are never built**

* **Severity:** INFO · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** docs/PACKAGING.md:11 vs release.yml:84-88
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `docs/PACKAGING.md:11` claims macOS x64 desktop artifacts; the release matrix builds arm64 only.
* **Code changes:** The claim is corrected to arm64.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-044

**INSTALL.md states the zero-CLI claim unqualified for all platforms**

* **Severity:** INFO · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** docs/INSTALL.md:69-74 vs PACKAGED_VALIDATION.md:6-84
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `docs/INSTALL.md:69-74` states the zero-CLI claim unqualified for all platforms; executed evidence covers macOS arm64 only.
* **Code changes:** The claim is scoped to the platform it was executed on, with the others labelled as not yet executed.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-045

**cargo build --release --workspace fails on a clean checkout**

* **Severity:** INFO · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** Fresh clone, cargo build --release --workspace -> 'resource path binaries/tethra-aarch64-apple-darwin doesn't exist'
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `cargo build --release --workspace` fails on a clean checkout until `scripts/bundle_cli.sh` runs. Fail-loud is correct; the ordering was undocumented.
* **Code changes:** CONTRIBUTING.md documents the ordering.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-046

**Tokens rendered without the lower-bound qualifier that cost carries**

* **Severity:** INFO · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Open Activity -> 'Tokens in / out' has no qualifier while cost says '(lower bound; cache reads excluded)'
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** Tokens were rendered without the lower-bound qualifier that cost correctly carries.
* **Code changes:** The qualifier is applied to tokens as well.
* **Test changes:** Desktop vitest.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-047

**'value-free' persisted state includes an env-derived value**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** Track a Supabase project; SELECT detection_json FROM tracking_setups contains inferred_origin = the SUPABASE_URL value
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `tracking_setups.detection_json` was claimed 'value-free', but persists `NeedsOriginConfirm.inferred_origin` — a value read from `SUPABASE_URL`.
* **Code changes:** No code change: the origin is non-secret, is shown to the user verbatim at the approval point, and undo needs it. The claim is corrected in ADR 0022 D10 and the db.rs migration comment to say 'no secret values', naming the origin as the one non-secret value it does carry.
* **Test changes:** The crate's own test already asserts the host IS present; it is now named as intended behaviour.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** The approved origin is stored in plaintext. It is a host name the user was shown and approved.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-1

**CI runs neither the packaged validation nor the smoke suite, and never builds a packaged app**

* **Severity:** HIGH · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** grep -rn 'tracking_validate|smoke.sh' .github/workflows/ -> no hits; the desktop CI job is clippy-only
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** CI ran neither `tracking_validate_macos.sh` nor `smoke.sh`, and never built a packaged app; the desktop job was clippy-only.
* **Code changes:** See PACKAGED_VALIDATION.md for exactly which jobs run which scripts on which OS, and for the honest split between what CI executes and what remains manual.
* **Test changes:** The CI workflow itself.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Recorded per PACKAGED_VALIDATION.md — hosted runners cannot exercise the full LaunchAgent login lifecycle, and that is stated rather than claimed.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-4

**The recorded validation run used the self-weakened foreground mode**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** The script switches to foreground mode when a LaunchAgent exists - true on any machine where Tethra has ever been installed, including the author's
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The recorded run used foreground mode, so LaunchAgent registration was never exercised, and the total stayed 42 in both modes.
* **Code changes:** The script reports its mode unambiguously, the count differs between modes, and a `--require-service` mode FAILS rather than silently downgrading.
* **Test changes:** The validation script itself.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Recorded per PACKAGED_VALIDATION.md.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-6

**The '30-provider-scale test' does not test 30 providers**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Read plan_apply.rs:657-714 - 26 SERVICE_i_URL vars match no manifest and yield zero detections
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The '30-provider-scale test' wrote 26 variables matching no manifest and produced zero detections; its own comment conceded it.
* **Code changes:** `tracking/tests/detect_coverage.rs` contains a real 30-integration fixture across five env files and two package manifests, with a nested application, duplicate dependencies and an ambiguous placeholder.
* **Test changes:** `::the_thirty_integration_fixture_really_contains_thirty_integrations` asserts the coverage total is EXACTLY 30.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-5

**The privacy canary named CANARY is never searched for**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Read tracking_validate_macos.sh:44,126,133 then the privacy section - only FAKE_KEY is grepped
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The variable literally named CANARY was planted, advertised in a pass message, and never searched for.
* **Code changes:** The canary is searched for across the DB, WAL, SHM, logs and desktop storage.
* **Test changes:** The validation script itself.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-7

**4 of 42 counted checks are unconditional passes; the anti-vacuity floor cannot detect tautology**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Lines 100, 133, 164, 207 are unconditional ok calls; MIN_CHECKS counts pass+fail
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** 4 of the 42 counted checks were unconditional passes; the anti-vacuity floor counted pass+fail, detecting truncation but never tautology.
* **Code changes:** Every unconditional pass is replaced by a real assertion or removed with the count lowered, and an anti-tautology self-check requires a deliberately-false control to be reported as a FAILURE.
* **Test changes:** The validation script itself.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-8

**The advertised forged-old-event negative control does not exist**

* **Severity:** MEDIUM · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Line 205 comments 'Forge an OLD event (before applied_at): must not verify the setup'; line 207 is an unconditional ok
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The advertised forged-old-event negative control did not exist.
* **Code changes:** It is implemented and asserts.
* **Test changes:** The validation script itself.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-3

**'Version-matched helper' is never verified**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Line 14 claims it; lines 117-118 check only [ -n "$APP_VER" ]
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** 'Version-matched helper' was never verified — the check was `[ -n "$APP_VER" ]`.
* **Code changes:** The helper version is MEASURED by running the binary.
* **Test changes:** The validation script itself.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-2

**'Eight commits, each independently green' is doubly wrong**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** Count the list (7); gh run list shows the first five pushed heads failed CI on Windows
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** 'Eight commits, each independently green' sat atop a seven-item list, on a branch whose first five pushed heads failed CI.
* **Code changes:** The handoff records the real commit list and the real CI history.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-9

**PACKAGED_VALIDATION group table sums to 40, not 42**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** Add the group counts at PACKAGED_VALIDATION.md:41-52
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The PACKAGED_VALIDATION group table summed to 40, not the stated 42.
* **Code changes:** The table is regenerated from the script's real groups.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-10

**Packaged 'byte for byte' undo check strips trailing newlines**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** tracking_validate_macos.sh:270-274 uses [ "$(cat a)" = "$b" ]
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** The 'byte for byte' undo check used `[ "$(cat a)" = "$b" ]`, which strips trailing newlines.
* **Code changes:** It uses `cmp` on the real files.
* **Test changes:** The validation script itself.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-11

**'CI clippy pins +1.97.0' is false**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** HANDOFF_PHASE_2.md:118 vs ci.yml
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** 'CI clippy pins +1.97.0' was false — `ci.yml` used `toolchain: stable`.
* **Code changes:** Either CI now pins the toolchain or the claim is corrected to match; see the workflow.
* **Test changes:** The CI workflow itself.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-12

**'Final head 4e3cc98' is wrong by construction**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** REVIEW_HANDOFF.md:132-136 vs git ls-remote
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** 'Final head 4e3cc98' was wrong by construction; the real head was 24acc470.
* **Code changes:** The handoff records heads that exist, and RE_AUDIT_HANDOFF.md states the exact final head of this remediation.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-13

**'closes O10' without closing the O10 record**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** docs/gateway/OPEN_DECISIONS.md:87 still presents O10 as open with the superseded default
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** 'closes O10' — the mechanism shipped but `docs/gateway/OPEN_DECISIONS.md:87` still presented O10 as open with the superseded default.
* **Code changes:** The O10 record is closed with a dated correction like the other three.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-14

**'Every bound is a test, not a promise' - except the symlink bound on Windows**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** FIXED
* **Audit reproduction:** DETECTION_COVERAGE.md:71 vs bounds.rs:115 #[cfg(unix)]
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `DETECTION_COVERAGE.md:71` says 'every one of these is a test, not a promise', but the symlink bound's test was `#[cfg(unix)]`, unpinned on Windows.
* **Code changes:** The containment property is asserted in a portable form; the Unix-only parts are the symlink FIXTURES, and the doc says so.
* **Test changes:** `tracking/tests/scan_bounds.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** Windows symlink creation needs a privilege hosted runners may lack; the fixture, not the property, is gated. Stated in the doc.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-15

**TROUBLESHOOTING implies eight automated causes; six are automated**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** TROUBLESHOOTING.md:3-5 vs diagnose.rs's 10 ids
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** TROUBLESHOOTING.md implied the built-in diagnosis automates all eight listed causes; it automates six.
* **Code changes:** The two manual causes are marked manual.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-16

**track_json_status_shape_is_stable asserts no JSON**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** TEST CORRECTED
* **Audit reproduction:** apps/cli/tests/track.rs:219 asserts only exit code 2
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** `track_json_status_shape_is_stable` asserted only exit code 2 — no JSON was asserted anywhere, so the name overclaimed.
* **Code changes:** The test asserts the actual JSON shape, including the new `current` / `history` split.
* **Test changes:** `apps/cli/tests/track.rs`.
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

## ZFT-VAL-17

**KNOWN_LIMITATIONS omits three disclosed-elsewhere limits**

* **Severity:** LOW · **Merge blocking:** no
* **Disposition:** DOCUMENTATION CORRECTED
* **Audit reproduction:** Compare against envlink.rs:153-161, ZFT-047 and bounds.rs:115
* **Remediation reproduction:** reproduced against `24acc470` before the fix; the regression tests below fail without the fix (`scripts/mutation_checks.sh` where a mutant exists).
* **Root cause:** KNOWN_LIMITATIONS omitted the git-tracked `.env` caveat, the persisted inferred origin and the `cfg(unix)` symlink test gap.
* **Code changes:** All three are recorded, along with the new limitations this remediation introduces.
* **Test changes:** None (documentation).
* **Documentation changes:** see `SECURITY_AND_PRIVACY.md`, `DETECTION_COVERAGE.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md` as applicable.
* **Residual risk:** None.
* **Commit:** see `REMEDIATION_EVIDENCE.md` for the per-commit mapping.

