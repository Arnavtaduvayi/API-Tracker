# Fresh re-audit handoff

**Do not trust this document.** It is written by the party that did the
remediation. Everything below is a claim to be reproduced, not evidence.

---

## What was audited, and by whom

```text
Original audited head:    24acc470538ca8f198a06456ef84f04c2f891918
Original audit branch:    audit/fable-zft-independent-20260727
Original audit commit:    4edd6a0400398789f0eb79d58045ee40a4abbb3a
Original verdict:         FINAL AUDIT COMPLETE: REMEDIATION REQUIRED
                          64 findings — 1 CRITICAL, 15 HIGH, 21 MEDIUM,
                          23 LOW, 4 INFO; 15 merge-blocking
```

The audit branch has **not** been modified. Its deliverables are copied
byte-identical into this branch at
`docs/activity-onboarding/audit/fable-independent-20260727/` so the PR is
self-contained (`diff -r` against the audit worktree returns nothing).

```text
New implementation head:  see `git rev-parse origin/feat/zero-friction-api-tracking`
PR:                       #16 (OPEN, unmerged, base main)
```

Commits on top of the audited head are listed in `REMEDIATION_EVIDENCE.md`.

---

## Instructions

1. **Use a fresh session and a fresh worktree.** Do not reuse this one.
2. **Audit the exact remote head**, not this description of it.
3. **Reproduce all 15 original merge blockers** (`ZFT-001` … `ZFT-015`)
   against the new head. Each should now fail to reproduce; a re-auditor's
   job is to find the ones that still do, or that reproduce by a route the
   remediation did not consider.
4. **Attempt hostile Git execution.** The canary suite covers eleven
   vectors; try a twelfth. `core.fsmonitor` requires
   `core.fsmonitorHookVersion` on git 2.50, and fires only when git runs
   from a working directory *outside* the repository — a control written
   the wrong way round proves nothing (this cost us an hour; it is recorded
   in `REMEDIATION_EVIDENCE.md` §1 so you do not repeat it).
5. **Attempt repository-controlled route injection.** The audit's fixture
   is in `crates/tracking/tests/origin_trust.rs`; try shapes it does not
   cover — a redirect, an IDN homograph, a very long host, an origin that
   canonicalizes differently on two platforms.
6. **Attempt stale verification reuse.** Try clock skew, a database with a
   future timestamp, and two setups for one folder.
7. **Attempt cross-environment service takeover.** `ensure_ours` and the
   namespaced identity are the controls; look for a verb that reaches
   launchd/systemd/the registry without passing through them.
8. **Distrust the remediation documents until reproduced.** Several claims
   in the ORIGINAL audit needed correcting during remediation (below);
   assume the same of these.

---

## Resolved merge blockers

Each links to its matrix entry, which names the root cause, the code, the
tests, and the residual risk.

| ID | What it was | Where the fix lives |
|---|---|---|
| `ZFT-001` | scanning executed repository-controlled code | `core::gitsafe` (new), `core::gitrepo` hardening, ADR 0023 |
| `ZFT-002` | symlink escape in the manifest reader | `core::stackdetect::read_bounded` |
| `ZFT-003` | `.env` read with no size cap | `envgov::discover_bounded` |
| `ZFT-004` | repository content authorized a route origin | `tracking::origin` (new), ADR 0024 |
| `ZFT-005` | "verified" survived a dead gateway | `state::refresh_with`, ADR 0025 |
| `ZFT-006` | a failed re-run reported verified | migration v16, verification sessions |
| `ZFT-007` | undo reported success having done nothing | `undo::undo` ground-truth derivation |
| `ZFT-008` | re-derivation skipped on a missing watermark | `state::refresh_with` early-exit ordering |
| `ZFT-009` | unsupported dead end demanded CLI commands | CLI empty state, desktop in-app actions |
| `ZFT-010` | unknown credentials silently dropped | `ProjectDetection.unrecognized`, `CoverageSummary` |
| `ZFT-011` | three trackable providers | 21 manifests, 13 trackable |
| `ZFT-012` | custom base URL silently re-pointed | `detect.rs` S3 branch downgrade |
| `ZFT-013` | attribution consent under-disclosed | TrackFlow, resume dialog, CLI step |
| `ZFT-014` | one environment booted out another's service | `installation_id`, `ensure_ours`, ADR 0026 |
| `ZFT-015` | "Waiting for traffic…" after polling stopped | TrackFlow poll re-arm |

---

## Where the remediation corrected the AUDIT

Three of the audit's own statements were wrong, and correcting them made
two findings *worse*, not better. Please re-check these:

* **`ZFT-001` trigger.** The audit attributed execution to `ls-files` and
  `check-ignore`. Confirmed — but it also fires only when git runs from a
  cwd outside the repository, which the audit did not note and which
  determines whether a control test is armed at all.
* **`ZFT-033`.** The audit said the marker comment is emitted "twice per
  file". It is emitted once per **written variable** — three times for
  openai. Worse than reported.
* **`ZFT-042`.** The audit said a stale plist makes launchd "fail-spawn each
  login". It does not: the service self-exits cleanly and
  `KeepAlive={Crashed:true}` treats that as terminal. The real consequence
  is a permanently orphaned Login Item, which is still a defect.
* **`ZFT-014` scope.** The audit's title said the tracking flow boots out
  "any existing gateway service". Reaching that from `track` needs the
  repair branch or a start fallback; a running, non-drifted service is left
  alone. The *surface* is wider than the audit described, though:
  `gateway stop` / `uninstall` / `install --force` gated only on
  `installed`, and `uninstall` DELETED another environment's definition.

---

## Accepted risks

Only one finding is dispositioned `ACCEPTED RISK` (`ZFT-038`, forced 0600
on `.env`). Every other residual is a *consequence* of a fix rather than a
declined fix, and all are enumerated in `KNOWN_LIMITATIONS.md`. The ones
most worth attacking:

1. **The hardened-git key list is an enumeration.** A future git version
   could add an execution surface it does not cover. The automatic path
   spawns nothing, so this only affects `tethra scan`, the pre-commit hook
   and `env discover --check-history`.
2. **A hardlink defeats the folder bound.** Symlinks are refused; hardlinks
   are indistinguishable from ordinary files.
3. **Nothing in CI can verify a manifest's honesty.** A `[gateway]` section
   can name a base-URL variable no SDK reads. All 13 were verified by hand
   against SDK source; a fourteenth added without that would pass.
4. **Moving a data directory orphans its service definition.**
5. **Windows service support is compile-validated only.**
6. **`ZFT-016` trades undo fidelity for privacy.** A prior base URL carrying
   a query string is no longer recorded, so undo cannot restore it
   byte-for-byte; it is warned before apply and reported at undo.

---

## Designs to attack

**Scanning (ADR 0023).** The automatic path spawns no process. Attack the
`.git/index` parser with malformed input, the gitignore evaluator against
real git's semantics (`tests/gitsafe_differential.rs` is the shape to
extend), and the claim that the hardened runner covers every executable
config key.

**Origin approval (ADR 0024).** Attack canonicalization: two spellings that
should be one origin, or one spelling that should be two. Attack the MAC:
can a row be moved between providers, or replayed from another vault?

**Verification state (ADR 0025).** Attack the freshness boundary and the
"newer wins" rule with clock skew. Attack `GatewayLiveness::Unknown` —
prove it can never produce a present-tense success.

**Service namespacing (ADR 0026).** Attack `same_data_dir` (it must fail
closed) and look for any verb reaching the OS without `ensure_ours`.

---

## Files that deserve special attention

| File | Why |
|---|---|
| `crates/core/src/gitsafe.rs` | new, hand-written binary and glob parsing, replaces a security-relevant subprocess |
| `crates/core/src/gitrepo.rs` | the hardening list is an enumeration |
| `crates/tracking/src/origin.rs` | new trust boundary and a new MAC construction |
| `crates/tracking/src/state.rs` | `refresh_with` is the most-changed logic in the branch |
| `crates/gateway/src/lifecycle/*.rs` | rewritten by an agent, then found DEFECTIVE by an adversarial verifier in four ways; re-verify independently |
| `crates/core/src/scanner.rs` | `is_placeholder_value` and `looks_like_key_material` gate whether a value is printed |
| `crates/gateway/src/envlink.rs` | `prior_value_is_recordable` decides what lands in plaintext |
| `provider-manifests/*.toml` | 16 new files whose honesty CI cannot check |

---

## Found by adversarial review of the remediation, and NOT closed

Three independent verifiers were run against this remediation and all three
returned **DEFECTIVE**. Everything they found that is closed is listed in
`REMEDIATION_EVIDENCE.md` §4 and in the matrix. These are the ones that are
**still open**, recorded here rather than left for you to rediscover:

### Validation harness

* **`--scope full` (57 checks) and `--scope full --require-service` (60)
  have NEVER BEEN EXECUTED, on any machine.** The `$LABEL`-unbound crash and
  the legacy-`PLIST` path that would have orphaned a real LaunchAgent are
  fixed, and the resolution now asks the product for its own
  `definition_path` — but the fixes are *reviewed, not run*, because this
  machine has a Tethra gateway and the interlock (correctly) refuses. So the
  remediation code for `ZFT-VAL-5` (the canary sweep), `ZFT-VAL-8` (the
  forged-event control), and the traffic / idempotence / undo / service
  groups is unexecuted source. **A re-auditor with a clean macOS machine
  should run `--scope full --require-service` first.**
* **The mutation suite only exercises `--scope selfcheck`,** so it
  structurally cannot cover `found_in`, the recursive privacy sweep,
  `isolated_files`, `la_digest` or the EXPECTED table. A weakening of the
  privacy sweep — the assertions carrying the `ZFT-VAL-5` remediation — is
  invisible to both the mutation suite and CI.
* **The privacy sweep's falsifiability control tests a different pipeline
  than the sweep itself.** The control calls `found_in` (single file, `-q`);
  the sweep is `grep -rlF … | grep -v "^$PROJECT/"`. Recursion and the
  path-prefix filter are never positively exercised, so a broken `-r`
  traversal would pass silently.
* **Seven checks have labels stronger than their assertions** — e.g. "the
  dry run showed the exact env diff" matches only the variable NAME, and
  `[ -n "$BUNDLE_VER" ]` is the literal `ZFT-VAL-3` shape still counted.
* **`--help` truncates the last five header lines** (a hard-coded `sed -n
  '1,89p'` against a file whose `set -uo pipefail` has moved) — the same
  class of drift as the `LABEL` rename.

### Desktop

* **The typed-destination (`NeedsOriginInput`) consent path has no test
  coverage and no disclosure.** `toggleTypedOrigin` discards the
  `OriginApprovalRequest` that `tracking_origin_approve` returns, so its
  disclosure lines are never shown: the whole consent is one bare label.
  The checkbox-based `NeedsOriginConfirm` path — the one the audit's fixture
  exercises — is covered.
* **The ~770 lines of new Tauri command code have no automated test.**
  `apps/desktop/src-tauri/` has no `#[cfg(test)]` module and no `tests/`
  directory; every vitest case mocks `../api` wholesale. So the structural
  guarantee this remediation headlines — `tracking_plan_build` refusing an
  unapproved `NeedsOriginConfirm` provider — is verified by reading, not by
  running. **This is the single highest-value place to point a re-audit.**
* **The ZFT-015 re-arm test cannot detect loss of the recurring interval.**
  Deleting the `setInterval` and keeping the immediate `tick()` leaves every
  TrackFlow test passing. Only the dependency-array half is pinned.
* **A `Possible`-confidence `NeedsOriginConfirm` provider is counted in the
  headline but rendered as no row anywhere** — the same unnameable-count
  shape `ZFT-010` objected to, at a smaller scale.
* **The "Advanced" escape hatch cannot help an unrecognised credential:**
  the Add-a-route form's provider field is a `<select>` of manifest
  providers, and `add_custom_route` rejects any id outside the catalog. The
  screen does not say so.

### Privacy

* **A secret in a URL PATH SEGMENT shorter than 20 characters, or with no
  digits, is still recorded in plaintext `prior_env_json`.** Verified live:
  `https://llm.corp.example/9f2c8a71e45b30d6/v1` is recoverable from
  `vault.db`. The query-string and userinfo cases are closed; the path case
  rests on a heuristic that raising further would start refusing ordinary
  paths.
* **`scrub_stored_prior_env_once` is called only from the CLI.** A
  GUI-only user — the persona this PR exists for — never runs it, so a leak
  written by an earlier build persists until that link is re-linked.
* **The `NO_PROXY` recordability branch admits secret-shaped values** that
  contain a dot: `sk-proj-AbCdEf123456.xyz789` is recordable.
* **`tethra gateway unlink` still prints raw Rust `Debug`** for restore
  outcomes (the `ZFT-034` shape at a second site), and reports `complete`
  even when a `PriorNotRecorded` left the `.env` pointing at the gateway.
* **`ZFT-023`: the digest binds file CONTENT but not `FilePlan.exists`,**
  so deleting an empty previewed `.env` between preview and apply yields the
  same digest while flipping whether undo deletes the file.

## Known follow-ups the remediation did NOT close

Recorded so they are found by reading rather than by discovery:

* `embedded_catalog_agrees_with_the_manifest_directory` checks embedded →
  disk but **not** disk → embedded. That is exactly the direction that
  would have caught the 16 manifests being inert, which is how they shipped
  inert in the first place.
* `base_url_vars_are_non_secret_and_unique_across_the_catalog` compares a
  base-URL variable against the SAME manifest's secret list, not the
  catalog-wide one. A manifest declaring `[gateway] env_vars =
  ["OPENAI_API_KEY"]` would pass and put another provider's live secret on
  the value-read path.
* `provider-manifests/xai.toml` omits `XAI_MANAGEMENT_KEY`, which the
  official SDK documents — a scanner blind spot on the higher-privilege
  credential.
* ZFT-029's per-**provider** dimension was not implemented (only
  per-project), and the per-project query lives in the desktop crate rather
  than in `gateway::store`, which cuts against the shared-logic rule in
  CLAUDE.md.
* `aws-bedrock.toml` records that the AWS service identifier was not
  verified against AWS's table. Its second reason for having no `[gateway]`
  (SigV4 signs the Host header) is sound and sufficient, but the unverified
  half is shipped.

---

## The decision this handoff does NOT make

Whether PR #16 is ready to merge. It is open and unmerged deliberately.
That decision belongs to a fresh independent audit of the exact remote head.
