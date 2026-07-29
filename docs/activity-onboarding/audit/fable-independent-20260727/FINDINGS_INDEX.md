# Findings Index — Independent Audit of PR #16 (zero-friction API tracking)

Audited commit `24acc470538ca8f198a06456ef84f04c2f891918`, base
`0e6764ba3bcc7a2e3d14afaa91041d4bfcd3b75b`. Fresh session, fresh worktree
(`audit/fable-zft-independent-20260727`), packaged application, clean state.
No implementation claim was accepted without reproduction.

Severity reflects **both security and product usability**. Per the audit brief,
a workflow that technically works but still requires users to understand routes,
matching keys, or separate CLI installation is treated as a serious product
failure.

---

## Summary

| Count | Severity |
|---|---|
| 1 | CRITICAL |
| 15 | HIGH |
| 21 | MEDIUM |
| 23 | LOW |
| 4 | INFO |
| **64** | **total** |

**Merge-blocking: 15** — `ZFT-001` (CRITICAL) plus `ZFT-002` … `ZFT-015` (HIGH).
`ZFT-VAL-1` is also HIGH but concerns the *standing of the evidence* rather than
a product defect, so it is not counted as an independent blocker.

Reproduced first-hand by the lead auditor against the **packaged app**:
`ZFT-001`, `ZFT-002`, `ZFT-003`, `ZFT-004`, `ZFT-005`, `ZFT-006`, `ZFT-009`,
`ZFT-010`, `ZFT-011`, `ZFT-014`. The remainder were produced by independent
subagents with quoted code, empirical harnesses, or mutation testing.

---

# MERGE-BLOCKING FINDINGS

## ZFT-001 — Arbitrary code execution when a folder is scanned
**Severity: CRITICAL · Merge blocking: YES**

**Affected user:** every user. In the desktop app the scan runs the instant a
folder is picked, so merely selecting a cloned repository executes attacker code
— before any confirmation, and with the user's full privileges.

**Reproduction** (executed against the packaged helper, exit 0):
```sh
mkdir hostile && cd hostile
printf '#!/bin/sh\necho PWNED >> ./PWNED.txt\n' > payload.sh && chmod 755 payload.sh
git init -q . && git config core.fsmonitor "$PWD/payload.sh"
printf 'OPENAI_API_KEY=sk-proj-RCEPROBE\n' > .env
Tethra.app/Contents/MacOS/tethra track "$PWD" --dry-run
```
Result:
```
=== AFTER: PWNED.txt ===
!!! ARBITRARY CODE EXECUTION CONFIRMED !!!
PAYLOAD EXECUTED at Mon Jul 27 14:31:09 EDT 2026 argv=2      (×4)
```

**Expected:** `detect.rs:12` — *"Parse-only: nothing is executed."*
`AUTOMATIC_PROVIDER_DETECTION.md:141` — *"Parse only: never execute project
files."* The scan banner printed to the user during this very run says
*"(this folder only; nothing executed or uploaded)"*.

**Actual:** the payload executed four times, during `--dry-run`, the mode that
promises *"Dry run: nothing was changed."*

**Root cause:** `detect.rs:347` → `envgov::discover` → `git_status_of`
(`envgov.rs:118-139`) → `gitrepo::run_git_probe` → `Command::new(git_program())`
(`gitrepo.rs:123`). `git ls-files` and `git check-ignore` honour the *scanned
repository's own* `core.fsmonitor`, which git spawns as a program. Git's
`safe.directory` guard does not fire: it only triggers for repos owned by a
different user, and a cloned or extracted repo is owned by the user.
Trigger isolated to `git ls-files --error-unmatch` and `git check-ignore`.

**Evidence:** reproduction above; `crates/tracking/src/detect.rs:347`;
`crates/core/src/envgov.rs:118-139`; `crates/core/src/gitrepo.rs:123`;
desktop entry point `apps/desktop/src-tauri/src/main.rs:3146` (`tracking_scan`).

**Required remediation:** stop spawning git during detection. Either (a) harden
every spawn with `-c core.fsmonitor=false -c core.hooksPath=/dev/null -c
protocol.ext.allow=never -c alias.*=` and `GIT_CONFIG_GLOBAL=/dev/null`, or
preferably (b) replace the per-file git probes with an in-process `.gitignore`
parser so detection spawns nothing at all. Add a regression fixture with a
hostile `core.fsmonitor`.

**Note on the test suite:** `bounds.rs:238`
`detection_source_makes_no_network_calls` is a textual `include_str!` grep of one
file. `bounds.rs:172` `env_files_are_parsed_never_executed` proves only that the
*env parser* does not shell out. Both pass while this executes.

---

## ZFT-002 — Symlink escape: files outside the selected folder are read
**Severity: HIGH · Merge blocking: YES**

**Affected user:** anyone scanning a folder they did not author (clone, template,
archive, teammate's branch).

**Reproduction** (executed):
```sh
mkdir -p outside proj
echo '{"dependencies":{"openai":"^4","@anthropic-ai/sdk":"^0.30"}}' > outside/secret-package.json
ln -s "$PWD/outside/secret-package.json" proj/package.json
printf '# no keys here\n' > proj/.env
tethra track proj --dry-run
```
Result:
```
Detected:
  anthropic   likely      Found the @anthropic-ai/sdk package in package.json
  openai      likely      Found the openai package in package.json
```
Two providers detected entirely from content outside the folder, at `likely` —
the threshold `plan.rs:43` auto-selects.

**Expected:** `DETECTION_COVERAGE.md:73,80` — *"Reads only under the selected
folder"*, *"Symlinks are never followed out of the folder."*

**Actual:** true for `.env` files only.

**Root cause:** two readers disagree. `detect::read_bounded`
(`detect.rs:253-265`) applies **both** `symlink_metadata` refusal and
`canonicalize().starts_with(root)`. `stackdetect::read_bounded`
(`stackdetect.rs:63-69`) applies **neither** — it uses `std::fs::metadata`,
which follows symlinks, with no containment check — and it is the reader used
for `package.json`, `requirements.txt`, `pyproject.toml`, root `.env*` name
scans, and `.github/workflows`.

Related: a **hardlink** named `.env` targeting a file outside the folder is also
read (variable names only). And `stackdetect` reads are never added to
`scanned_files`, so the run reported `scanned=0` while reading outside content.

**Evidence:** reproduction above; `crates/tracking/src/stackdetect.rs:63-69` vs
`crates/tracking/src/detect.rs:253-265`; test gap at
`crates/tracking/tests/bounds.rs:117` (covers only a symlinked `.env` and a
symlinked directory, then certifies the broader bound).

**Required remediation:** give `stackdetect::read_bounded` the same
`symlink_metadata` + canonicalize-under-root checks, or inject `detect`'s reader.
Add regression tests for a symlinked `package.json`, `requirements.txt`, and
`pyproject.toml`.

---

## ZFT-003 — `.env` files are read with no size cap (1.92 GB RSS from a 234 MB file)
**Severity: HIGH · Merge blocking: YES**

**Affected user:** anyone scanning a folder containing a large file named `.env*`
— log spill, database dump, or a deliberate denial-of-service fixture.

**Reproduction** (executed):
```
$ ls -lh .env                       →  234M
$ /usr/bin/time -l tethra track <dir> --dry-run
Tethra looked at .env files, package manifests, and lockfiles (0 file(s) read, 6 levels deep).
        1.41 real
        1923170304  maximum resident set size          # 1.92 GB, 8.2× the file
```
A 2 GB `.env` requires roughly 16 GB and OOM-kills the process.

**Expected:** `DETECTION_COVERAGE.md:78` — *"256 KiB per file; oversized files
are counted, never silently dropped."*

**Actual:** the file is read in full before any cap is consulted, **and** the run
reports `0 file(s) read` — the honesty counter actively asserts the file was not
read.

**Root cause:** `envgov.rs:182` — `std::fs::read_to_string(&path).unwrap_or_default()`
followed by `EnvDocument::parse`, with no `metadata().len()` check.
`detect::read_bounded` (`detect.rs:266`) does check the cap **before** reading,
but `discover` has already read the whole file at `detect.rs:347`. Amplification
comes from `EnvDocument::parse` allocating a `SecretString` per line plus a
retained `raw` copy (`envfile.rs:278-286`).

**Evidence:** measurement above; `crates/core/src/envgov.rs:182`;
`crates/tracking/src/detect.rs:266,347`. Test `bounds.rs:159` asserts
`skipped_oversized >= 1` with no assertion that the bytes were not read — it
passes in exactly this scenario.

**Required remediation:** enforce the byte cap inside `envgov::discover` before
`read_to_string`; report the file in the inventory as oversized. Add a test that
asserts bounded RSS or, at minimum, that the file's contents never enter memory.

---

## ZFT-004 — Auto-created route origin is taken from repository content; the documented confirmation gate is not implemented
**Severity: HIGH · Merge blocking: YES**

**Affected user:** anyone who runs the tracking flow on a folder they did not
fully author.

**Reproduction** (executed; the fixture contains **no secrets at all**):
```sh
echo '{"dependencies":{"@supabase/supabase-js":"^2.39.0"}}' > package.json
echo 'SUPABASE_URL=https://attacker-controlled.example.com'  > .env.development
tethra track . --dry-run
```
Result:
```
Detected:
  supabase    likely      Found the @supabase/supabase-js package in package.json;
                          Found SUPABASE_URL in .env.development
Will do:
  2. create routes: supabase → https://attacker-controlled.example.com
```
A subagent carried this through a real `--yes` apply: the route was MAC'd,
enabled, persisted in `gateway_routes`, the verification key pushed into the live
service, and `.env.development` rewritten so the app's credential flows through
the local gateway to the attacker's host.

**Expected:** `SECURITY_AND_PRIVACY.md:76-81` — *"it requires an **explicit
checkbox** (never part of Confirmed auto-config)"*.

**Actual:** there is no checkbox in the CLI, and the desktop ships the box
**pre-checked** with the origin **pre-filled**.

**Root cause:** `plan.rs:46-52` auto-fills the confirmation it is named for —
`Configurability::NeedsOriginConfirm { inferred_origin } if p.confidence >=
DetectionConfidence::Likely` inserts into both `sel.include` and
`sel.confirmed_origins`. `track_cmd.rs:239` consumes it verbatim
(`Selections::defaults(&detection)`); the only gate is one bulk
`confirm("Proceed?", yes)` at `track_cmd.rs:375`, satisfied by `--yes`. Desktop:
`main.rs:3179` `selected_by_default`, `TrackFlow.tsx:96` pre-filled origin.
Confidence reaches `Likely` from the SDK dependency alone (`detect.rs:583-589`),
so no secret is needed to arm the path.

**Evidence:** reproduction above; the cited lines; `validate_origin` correctly
refuses loopback and plaintext-http, confirming the transport defenses are
intact — the regression is in *provenance*, not enforcement.

**Required remediation:** (1) drop `NeedsOriginConfirm` from
`Selections::defaults`; (2) make an inferred origin a hard interactive stop in
the CLI and make `--yes` **refuse** it (proceed only when every selected provider
is `Automatic`); (3) ship the desktop checkbox unchecked with the destination
host as the label; (4) add a regression test asserting a non-manifest-shaped
inferred origin is never auto-included.

---

## ZFT-005 — "Tracking verified" survives the gateway being dead
**Severity: HIGH · Merge blocking: YES**

**Affected user:** every tracked user, whenever the service stops (crash, quit,
logout, update, uninstall).

**Reproduction** (executed against the packaged helper):
```
$ pkill -f "gateway serve"
$ curl -o /dev/null -w '%{http_code}' http://127.0.0.1:55102/     → 000
$ tethra track status <proj>
State: tracking verified — traffic observed
  anthropic   last observed 2026-07-27T18:27:58.877919Z
```

**Expected:** a distinct stale/attention state. The user's application is
**broken** at this moment — its `.env` points at a loopback port with nothing
listening, so every API call fails.

**Actual:** the product reports success.

**Root cause:** `state::refresh` consults only historical event rows
(`state.rs:357-361`). It never checks whether the route still exists, the link
still exists, the `.env` still points at the gateway, or the service is running,
and it never bounds the age of the newest observation. `ProviderFreshness.last_observed_at`
is computed and displayed but never compared to now, anywhere in Rust or
TypeScript. `diagnose.rs` *does* check env drift and gateway availability, but is
invoked only on the **no-traffic** branch (`track_cmd.rs:492-501`,
`TrackFlow.tsx:170-175`), which a verified setup never reaches. Event retention
defaults to 7 days and is user-settable to 90 — the false claim persists that
long.

**Evidence:** reproduction above; `crates/tracking/src/state.rs:357-361`;
`crates/tracking/src/diagnose.rs:58-96`; `apps/cli/src/track_cmd.rs:492-501`.
A subagent additionally proved the same state survives
`DELETE FROM gateway_project_links; DELETE FROM gateway_routes;`.

**Required remediation:** gate `Observed`/`PartiallyObserved` on (a) the route
and link for each configured provider still existing, and (b) `last_observed_at`
within a bounded age. Introduce a distinct `stale` / `was_observed_at` state.

---

## ZFT-006 — A failed re-run reports "tracking verified" and erases the failure reason
**Severity: HIGH · Merge blocking: YES**

**Affected user:** every user who re-runs the flow on an already-tracked folder
and hits any failure. No tampering or privilege required.

**Reproduction** (executed, packaged helper, ordinary product use):
```
$ tethra track <proj> --yes
✗ Local service installed and running — the service did not answer on 127.0.0.1:55102 within 10 s
Setup stopped at 'Local service installed and running'.

$ tethra track status <proj>
State: tracking verified — traffic observed
```

**Expected:** `needs_attention`, with the recorded reason.

**Actual:** the failed setup is promoted back to verified by the *previous* run's
traffic, and `attention_reason` is nulled — deleting the record of why setup
failed.

**Root cause:** `upsert_setup`'s conflict clause updates only four columns
(`state.rs:181-185`), so `applied_at`, `plan_summary_json` and `first_traffic_at`
**survive a re-run**. Any apply failure calls `fail!` → `transition(...,
NeedsAttention, ...)` (`apply.rs:262-270`); `NeedsAttention` is watchable
(`state.rs:320-327`); `refresh` therefore runs against the *stale* watermark, old
events satisfy `at >= old applied_at`, and the derived promotion is written by an
UPDATE that deliberately bypasses the legality table and nulls `attention_reason`
(`state.rs:412-421`). `undo.rs:88-95` has the same defect on the incomplete
branch.

**Evidence:** reproduction above; the cited lines; independent harness output
`H3 assertion failed: a FAILED setup was marked verified by the previous run's traffic`.

**Required remediation:** clear `applied_at`, `plan_summary_json` and
`first_traffic_at` in the `ON CONFLICT` branch and on the incomplete-undo branch;
never let a derived promotion clear `attention_reason`; do not promote
`NeedsAttention` without a *post-failure* observation.

---

## ZFT-007 — `track undo` after a failed apply silently restores nothing and reports success
**Severity: HIGH · Merge blocking: YES**

**Affected user:** anyone whose apply fails after step 6 begins, who then runs the
officially recommended recovery.

**Reproduction** (executed harness):
```
A: failed step = PathCheck
A: .env rewritten by failed apply = true
A: undo.complete = true, links_restored = 0, routes_removed = []
A: .env restored to original = false
A: leftover routes = 2, leftover links = 2
A: .env still points at gateway = true
```

**Expected:** the CLI's own failure message promises *"Completed steps are left in
place; `tethra track undo` restores everything"* (`track_cmd.rs:426-429`), as
does `TROUBLESHOOTING.md:69-70`.

**Actual:** undo no-ops, reports `complete: true`, transitions the row to
`not_configured`, prints "Tracking stopped." and exits 0 — leaving the user's
`.env` pointing at the gateway with routes and links intact.

**Root cause:** the plan summary is persisted only at step 10
(`apply.rs:690-696`). Every earlier failure leaves `plan_summary_json` NULL, and
`undo.rs:28-33` defaults it rather than treating it as unknown:
`.map(serde_json::from_str).transpose()?.unwrap_or_default()`. Both loops then
iterate empty collections and `complete` stays `true`.

**Evidence:** harness above; `crates/tracking/src/undo.rs:28-33,35-87`;
`crates/tracking/src/apply.rs:690-696`.

**Required remediation:** persist an incremental summary as steps complete, or
derive undo's work from ground truth (`gateway_project_links` rows carry
`prior_env_json`); and when the summary is absent but link rows exist, **refuse
loudly** instead of reporting completion.

---

## ZFT-008 — Re-derivation is skipped entirely when the watermark is missing; a row then renders verified with zero events
**Severity: HIGH · Merge blocking: YES**

**Affected user:** the exact adversary the shipped invariant names — any process
able to write `vault.db`.

**Reproduction** (executed harness): set `state='traffic_observed',
applied_at=NULL` (both columns nullable, `db.rs:1026`):
```
H1 events_in_db=0 watch=Observed { exchange: None, freshness: [] } state=TrafficObserved
H2 events_in_db=0 watch=Observed ...                     (same via plan_summary_json=NULL)
```

**Expected:** `state.rs:4-6`, `verify.rs:10-12`, `lib.rs:12` and migration
comment `db.rs:1013-1017` all claim *"a stale or hand-edited row can never
overclaim `traffic_observed`."*

**Actual:** one nulled column defeats the entire mechanism.

**Root cause:** two early returns **before** any correction —
`state.rs:329-331` (`if !watchable || providers.is_empty() { return Ok(vec![]) }`)
and `state.rs:332-334` (`let Some(applied_at) = ... else { return Ok(vec![]) }`).
`check_traffic` then reads the uncorrected cached state (`verify.rs:140-145`).

**Evidence:** harness above; cited lines.

**Required remediation:** move both early returns *after* the downgrade decision.
A missing watermark is strictly *less* evidence than zero events and must force
`awaiting_first_request` / `needs_attention`.

---

## ZFT-009 — The unsupported-project dead end demands terminal commands and manual route creation
**Severity: HIGH · Merge blocking: YES**

**Affected user:** every user whose project uses any API outside the three
trackable providers — the majority of real projects.

**Reproduction** (executed): a project using Groq, Mistral, Cohere, DeepSeek,
Together and Perplexity with matching SDK dependencies:
```
No trackable APIs detected in this folder.
• Using a provider Tethra doesn't support yet? See `tethra provider list`.
• Know the provider and its base URL? `tethra gateway route add` is the expert path.
                                                                   exit code 2
```

**Expected / Actual against the acceptance target:**

| Target | Result |
|---|---|
| Terminal commands: 0 | **violated** — `tethra provider list` |
| Manual route creation: 0 | **violated** — `tethra gateway route add` |
| Internal gateway concepts required: 0 | **violated** — "route", "gateway" |

For the desktop-only user both commands are unexecutable: the CLI is inside
`Tethra.app/Contents/MacOS/`, not on PATH. The desktop equivalent
(`TrackFlow.tsx:274-275`, *"Advanced → Gateway internals has the manual route
form"*) is still manual route creation and still internal gateway concepts.

**Root cause:** no non-expert fallback exists for an unrecognised provider.

**Required remediation:** provide an in-app "add this API" path that collects a
name and base URL in the tracking flow's own vocabulary, without exposing routes
or the gateway; or state the supported-provider scope up front so the user is not
led into a dead end.

---

## ZFT-010 — Unknown API credentials are silently dropped from the review screen
**Severity: HIGH · Merge blocking: YES**

**Affected user:** every user with more than the three supported providers.

**Reproduction** (executed): the 30-API monorepo fixture. Output lists four
providers under the heading `Detected:`. The other ~26 credentials — `GROQ_API_KEY`,
`MISTRAL_API_KEY`, `COHERE_API_KEY`, `SENDGRID_API_KEY`, `TWILIO_AUTH_TOKEN`,
`SLACK_BOT_TOKEN`, `DEEPSEEK_API_KEY`, `TOGETHER_API_KEY`, `PERPLEXITY_API_KEY`,
`FIREWORKS_API_KEY`, `HUGGINGFACE_API_KEY`, `AZURE_OPENAI_API_KEY`,
`GOOGLE_API_KEY`, `ELEVENLABS_API_KEY`, `ASSEMBLYAI_API_KEY`, `PINECONE_API_KEY`,
`LANGSMITH_API_KEY`, `REPLICATE_API_TOKEN`, `RESEND_API_KEY`, plus three custom
origins — appear **nowhere**: not detected, not unsupported, not unknown, not
counted.

I confirmed this is provider coverage, not file skipping: a filename probe showed
`.env`, `.env.local`, `.env.production`, `.env.development`, `.env.test`,
`.env.staging`, `.env.qa` and `.env.prod` are all scanned.

**Expected:** the audit brief requires unknown APIs to be surfaced and uncertain
detections reviewed without blocking confirmed ones.
`AUTOMATIC_PROVIDER_DETECTION.md:120-121` promises
`Unsupported { UnknownProvider }` for exactly this case.

**Actual:** `UnsupportedReason::UnknownProvider` (`detect.rs:68`) is unreachable
from folder content — every id entering `signals` already comes from a manifest.
`DETECTION_COVERAGE.md:18` states the truth (*"Anything without a provider
manifest is not detected at all"*), contradicting the other document.

**Root cause:** detection is manifest-gated with no residual reporting path.

**Required remediation:** surface unrecognised secret-shaped variables as an
explicit, non-blocking "not recognised" group with a count, so the screen headed
`Detected:` is not read as complete. Reconcile the two documents.

---

## ZFT-011 — Coverage is three providers; the product promise does not scale past them
**Severity: HIGH · Merge blocking: YES**

**Affected user:** everyone outside OpenAI / Anthropic / Supabase.

**Evidence** (executed):
```
$ tethra provider list
openai · anthropic · github · stripe · supabase          # 5 manifests total
```
`provider-manifests/` contains exactly five `.toml` files. Only `openai`,
`anthropic` and `supabase` declare a base-URL environment variable, so only those
three are trackable. `github` and `stripe` are detected and honestly labelled
unsupported.

**Expected:** a feature titled "zero-friction API activity tracking" implies
coverage of the APIs a developer actually uses.

**Actual:** three. Several unsupported services (Groq, Together, DeepSeek,
Fireworks, Perplexity, Mistral) are OpenAI-compatible and would need little more
than a manifest entry.

**Root cause:** manifest set size.

**Required remediation:** either expand the manifest set to cover the common
OpenAI-compatible providers before shipping this as the primary workflow, or
state the three-provider scope prominently in `KNOWN_LIMITATIONS.md`, the README
and the in-app empty state. It is currently stated in none of them.

---

## ZFT-012 — An existing custom base URL is silently re-pointed to the manifest origin, and raises confidence
**Severity: HIGH · Merge blocking: YES**

**Affected user:** anyone behind a corporate LLM gateway, LiteLLM, Azure OpenAI,
or a self-hosted proxy.

**Reproduction** (executed by subagent):
```
.env: OPENAI_API_KEY=sk-proj-…
      OPENAI_BASE_URL=https://litellm.corp.example/v1
→ openai  conf=confirmed  cfg=Automatic  limitations: []
```

**Expected:** an already-customised base URL should suppress `Automatic` and
surface the existing origin for confirmation — the `NeedsOriginConfirm` shape
already exists.

**Actual:** the user's custom endpoint is what *makes* the detection
"Confirmed"; the route then forwards to the manifest origin
`https://api.openai.com` (`openai.toml:47`). Traffic that was going to
`litellm.corp.example` now goes to OpenAI, carrying the user's key, with no
statement that the destination changed. The only warning names the variable
(*"already had a value; it was recorded and will be restored on undo"*) and never
says the destination changes — and the removed line is **masked** in the diff, so
the user cannot see what is being replaced.

**Root cause:** `detect.rs:402-431` — the S3 branch reads the value only when
`gw.origins.is_empty()` (Supabase); for OpenAI/Anthropic the variable's mere
*presence* becomes evidence. `s1 && s3` then hits the `Confirmed` arm at
`detect.rs:583`.

**Required remediation:** in the S3 branch, when `!gw.origins.is_empty()` and the
value is non-empty, non-loopback and not the manifest origin, emit a limitation
and downgrade `Automatic` → `NeedsOriginConfirm { inferred_origin: <existing> }`.

---

## ZFT-013 — Attribution consent under-discloses the capability being granted; the security document's claim is false
**Severity: HIGH · Merge blocking: YES**

**Affected user:** every user enabling tracking or resuming attribution through
the primary flow.

**Reproduction:** open the Track flow, read the master-password field copy;
compare with Advanced → push-key dialog.

**Expected:** `SECURITY_AND_PRIVACY.md` §2 claims *"Residual risks stated at
consent time, carried over verbatim: … matching-key-resident memory oracle while
attribution is on (GW-6)."* ADR 0020 mandates the disclosure. The Advanced dialog
does it properly (`GatewayView.tsx:584-594`): *"…a process that can read the
gateway's memory (or its database) gains an oracle for testing whether a value
matches one of your credentials. The key is dropped on stop, revoke, or lock…"*

**Actual:** the new primary flow authorizes the same capability with only
*"Label traffic with which stored credential was used (recommended)"* /
*"Master password — leave empty to skip"* (`TrackFlow.tsx:419-431`), the resume
dialog (`DashboardView.tsx:319`), and the CLI step line (`track_cmd.rs:328`).
No oracle, no residency, no drop-on-lock, no scope. The GW-11 standing-relay
disclosure *was* carried over, so the omission is specific to attribution.

**Root cause:** consent consolidation moved the password field but not the
ADR-0020 disclosure copy.

**Required remediation:** add the oracle-while-resident and dropped-on-lock
sentences to the password field help text in `TrackFlow`, the resume dialog, and
the CLI step line. Correct `SECURITY_AND_PRIVACY.md` §2 and ADR 0022 D10.

Related (MEDIUM, `ZFT-020`): *"narrowly scoped matching capability"*
(`PRODUCT_BEHAVIOR.md:80`) overstates — the pushed key is the vault-wide
fingerprint key (`vault.rs:553`) and the matcher covers all gateway-linked
projects (`attribution.rs:358-388`).

---

## ZFT-014 — The tracking flow boots out any existing gateway service (fixed LaunchAgent label)
**Severity: HIGH · Merge blocking: YES**

**Affected user:** anyone with more than one Tethra data directory, and anyone
running the shipped validation script.

**Observed live during this audit.** A subagent ran a real `tethra track --yes`
against an isolated data directory. It **booted out this machine's live gateway
service** (`dev.api-tracker.gateway`, pid 43853) which was serving the user's
real vault at `~/Library/Application Support/api-tracker`. I detected the loss
and restored it (`launchctl bootstrap gui/501
~/Library/LaunchAgents/dev.api-tracker.gateway.plist`; now pid 50655, original
data directory). No user data was lost; the plist was never rewritten; the
service was down until restored.

**Expected:** installing tracking for one data directory must not disable another.

**Actual:** `LABEL` is a fixed global constant —
`crates/gateway/src/lifecycle/macos.rs:26`,
`pub const LABEL: &str = "dev.api-tracker.gateway"`. The plist path derives from
`$HOME`, but the launchd *domain target* is the real `gui/<uid>` regardless. On
"already bootstrapped", install performs **`bootout` then `bootstrap`**
(`macos.rs:204-221`).

**Root cause:** one login slot per user, with no per-data-directory
discrimination and no detection that the existing job belongs to a different
data directory.

**Required remediation:** derive the label from the data directory (hash), or
refuse with a clear error when the loaded job's `--data-dir` differs from the
target. This is also the root cause of the validation script's self-weakening
foreground mode (see `VALIDATION_INTEGRITY.md`).

---

## ZFT-015 — Setup screen shows "Waiting for traffic…" forever after polling has permanently stopped
**Severity: HIGH · Merge blocking: YES**

**Affected user:** anyone who takes longer than two minutes to restart their
project, or who hits one transient IPC error during the wait.

**Reproduction:** Track API activity → folder → Start tracking → reach
"Configuration applied" → wait 120 s → then restart the app and make a request.

**Expected:** the screen flips to "Tracking verified", or says it stopped
watching.

**Actual:** polling is killed permanently and never resumes —
`stopPolling(); void runDiagnosis(setupId);` (`TrackFlow.tsx:173-176`) on the
cutoff, and `stopPolling(); setError(...)` (`TrackFlow.tsx:177-180`) on any poll
error. The phase stays `waiting` and the screen keeps rendering
*"Waiting for traffic…"* unconditionally (`TrackFlow.tsx:495-499`) — a claim that
is now false. "Run diagnostics" does not restart the poll. The setup may have
actually verified; the dashboard shows the truth while this screen does not.

**Root cause:** one-shot `setInterval` lifecycle keyed only on `phase.name`
(`TrackFlow.tsx:161-186`) with no re-arm path.

**Required remediation:** resume polling after diagnosis/error, or add a "Check
again" action, and change the muted line to *"No longer watching — run
diagnostics or open the dashboard"* once polling stops.

---

# NON-BLOCKING FINDINGS

| ID | Sev | Finding | Evidence |
|---|---|---|---|
| ZFT-016 | MEDIUM | `prior_env_json` persists raw URLs **including query strings** in plaintext in `vault.db`. Canary `sk-QUERYCANARY-…` found at byte offset 527979. Violates the forbidden-persistence rule for "query-string values" and "raw URLs containing queries". | `envlink.rs:97-130` — the allowlist inspects only the authority and ignores path/query/fragment |
| ZFT-017 | MEDIUM | Masking bypass prints **full credentials** to stdout and across IPC when the value contains a placeholder needle (e.g. a `DATABASE_URL` containing `example`). Violates "never print full credentials in CLI output". | `envgov.rs:353-370` + substring test `scanner.rs:122-147` |
| ZFT-018 | MEDIUM | Re-apply destroys route provenance: `created_routes` becomes `[]`, so a later undo strands routes with the false reason *"existed before this setup (only reused)"*. | `state.rs:285-291`, `apply.rs:443-448`; harness scenario B |
| ZFT-019 | MEDIUM | Undo never restores a route's prior `enabled=false`; a deliberately disabled route is left permanently re-enabled. | `apply.rs:438-448`, `undo.rs:71-76` |
| ZFT-020 | MEDIUM | "Narrowly scoped matching capability" overstates: vault-wide fingerprint key, matcher spans all linked projects. | `PRODUCT_BEHAVIOR.md:80` vs `vault.rs:553`, `attribution.rs:358-388` |
| ZFT-021 | MEDIUM | Foreground fallback child **outlives the app**; "Tracking pauses when Tethra closes" is false. No `kill()` anywhere; `RunEvent::Exit` never touches it. | `main.rs:3607`, `main.rs:3881-3891`, `TrackFlow.tsx:589-591` |
| ZFT-022 | MEDIUM | Stale plan applied after another apply leaves `.env` pointing at a link slug with no DB row — every SDK request 404s. Digest passes because output bytes coincide. | `envlink.rs:475-513`, `routes.rs:432-444` |
| ZFT-023 | MEDIUM | Digest binds the planned **output**, not the previewed input; a value-only edit between preview and apply is silently overwritten. Doc claims "refuses when **any** file changed". | `envlink.rs:386-391,408-410` |
| ZFT-024 | MEDIUM | Migration: a manual project without a registered repo path yields a **duplicate project**, a new slug, and a rewritten `.env`. Contradicts `MIGRATION.md` ("Nothing is deleted, duplicated, or re-created"). | `track_cmd.rs:136-164`, `apply.rs:772-779` |
| ZFT-025 | MEDIUM | `Confirmed` is self-confirming after the first link — Tethra's own written `OPENAI_BASE_URL` satisfies the second "independent signal class". | `detect.rs:402,417` |
| ZFT-026 | MEDIUM | `pyproject.toml` prefix matching invents dependencies: `openai-whisper` (offline STT) ⇒ `openai likely Automatic`. `requirements.txt` matches exactly; the two parsers disagree. | `stackdetect.rs:191-193` |
| ZFT-027 | MEDIUM | Placeholder filter is the only value check; `OPENAI_API_KEY=abcdefgh` ⇒ `likely` + auto-selected. Manifest key-format regexes exist and are never consulted. | `detect.rs:391`, `scanner.rs:122-158`, `openai.toml:27-40` |
| ZFT-028 | MEDIUM | Detection cost unbounded in file count: 300 `.env` files ⇒ 16.5 s; 2000 ⇒ 39.9 s. Depth is capped, file count/bytes/time are not; up to 4 git spawns per file. | `envgov.rs:144-199`, `gitrepo.rs:73` |
| ZFT-029 | MEDIUM | Activity summary is global — with 2+ projects, "which project generated the traffic?" is unanswerable. `GatewayActivitySummary` has no project or provider dimension. | `types.ts:1323-1343`, `DashboardView.tsx:66` |
| ZFT-030 | MEDIUM | Raw internal enum tokens on the primary dashboard: `matched_fingerprint — 12`, `unavailable — 4`. | `DashboardView.tsx:218-228` |
| ZFT-031 | MEDIUM | Swallowed error hides a coverage warning: a failed foreground check renders identically to "background service running", so the user believes tracking continues after closing the app. | `DashboardView.tsx:82-88` |
| ZFT-032 | LOW | `.env` marker comment instructs the user to run `tethra gateway status` — a command the desktop-only user does not have on PATH — and names internal concepts, written into their source tree. | Journey 1 output |
| ZFT-033 | LOW | The marker comment is emitted **twice** per file; the diff header prints a stray bare path line. | Journey 1 output |
| ZFT-034 | LOW | Raw Rust `Debug` output in user-facing CLI: `Restored { path: "…", key: "…" }`. | `tethra track undo` output |
| ZFT-035 | LOW | `ReadOnly` warning text is wrong on Unix — atomic rename succeeds regardless of the file's read-only bit. | `plan.rs:478` vs `envlink.rs:166-167` |
| ZFT-036 | LOW | `track undo`/`doctor` open an **un-migrated** connection — first command after a v14→v15 upgrade fails with "no such table: tracking_setups". | `track_cmd.rs:546`, `db.rs:1039-1044` |
| ZFT-037 | LOW | `track undo`/`doctor` act on the **oldest** setup for a folder; `track status` reports the **newest**. | `track_cmd.rs:544-560` |
| ZFT-038 | LOW | `.env` permissions forced to 0600 by `atomic_write`; a 0644 `.env` read by another uid breaks. Crash window leaves a temp file containing full secrets under a name no `.gitignore` covers. | `envgov.rs:401-437,413-419` |
| ZFT-039 | LOW | Every service-lifecycle error is labeled "macOS blocked the background service (this build is unsigned)". | `apply.rs:177-181`, `TrackFlow.tsx:585` |
| ZFT-040 | LOW | Non-UTF-8 files dropped with no counter increment; no binary sniff. Contradicts "nothing silently capped". | `detect.rs:270`, `stackdetect.rs:68` |
| ZFT-041 | LOW | Installed-helper version is **stamped from the installing app**, not measured from the binary; a fallback helper defeats drift detection. The probe prints the true version and it is discarded. | `lifecycle/mod.rs:230-232,269` |
| ZFT-042 | LOW | Drag-to-Trash uninstall leaves the LaunchAgent plist; if the data dir remains, the gateway **keeps running at every login with the app gone**. The `PACKAGING_PLAN §7` notice does not exist in the UI. | grep of `apps/desktop/src`; `docs/INSTALL.md:137-145` |
| ZFT-043 | INFO | `docs/PACKAGING.md:11` claims macOS x64 desktop artifacts; the release matrix builds arm64 only. | `release.yml:84-88` |
| ZFT-044 | INFO | `docs/INSTALL.md:69-74` states the zero-CLI claim unqualified for all platforms; executed evidence covers macOS arm64 foreground mode only. | `PACKAGED_VALIDATION.md:6-84` |
| ZFT-045 | INFO | `cargo build --release --workspace` **fails** on a clean checkout (`resource path binaries/tethra-… doesn't exist`) until `scripts/bundle_cli.sh` runs. Fail-loud is correct; the ordering is undocumented in CONTRIBUTING. | reproduced this session |
| ZFT-046 | INFO | Tokens rendered without the "lower bound" qualifier that cost correctly carries. | `DashboardView.tsx:179-182` |
| ZFT-047 | LOW | `tracking_setups.detection_json` is claimed "value-free" / "never env values", but persists `NeedsOriginConfirm.inferred_origin` — the value read from `SUPABASE_URL`. The crate's own test asserts the host **is** present. Non-secret and disclosed elsewhere, so a wording defect. | `db.rs:1016`, ADR 0022 D10 vs `apply.rs:309`, `tests/detect.rs:339` |

### Validation and self-reporting integrity

| ID | Sev | Finding | Evidence |
|---|---|---|---|
| ZFT-VAL-1 | HIGH | **CI runs neither `tracking_validate_macos.sh` nor `smoke.sh`, and never builds a packaged app on any platform.** The headline "42 checks" is one developer-machine run, not repeatable PR evidence. The desktop CI job is clippy-only. | `grep -rn "tracking_validate\|smoke.sh" .github/workflows/` → no hits |
| ZFT-VAL-4 | MEDIUM-HIGH | The one recorded validation run used **foreground mode**, so LaunchAgent registration — the path every real user gets — was never exercised. The total stays 42 in both modes, so the number self-launders the downgrade. | `tracking_validate_macos.sh:96-102,164,179`; `PACKAGED_VALIDATION.md:64-84` |
| ZFT-VAL-6 | MEDIUM | The *"30-provider-scale test"* writes 26 variables that match no manifest and produce **zero** detections. It is a 4-provider test with a 30-variable `.env`. | `plan_apply.rs:657-714` (the test's own comment concedes it) |
| ZFT-VAL-5 | MEDIUM | The variable literally named `CANARY` is planted in the fixture `.env`, advertised in a pass message, and **never searched for**. The "unrelated env value never persists" property is untested. | `tracking_validate_macos.sh:44,126,133` |
| ZFT-VAL-7 | MEDIUM | 4 of the 42 counted checks are **unconditional passes** (lines 100, 133, 164, 207); 7 more are weak. The anti-vacuity floor counts `pass+fail`, so it detects only truncation, never tautology. | classified line by line in `VALIDATION_INTEGRITY.md` §2 |
| ZFT-VAL-8 | MEDIUM | The advertised forged-old-event negative control does not exist — line 205 promises it, line 207 is an unconditional `ok`. (The property is covered by an in-crate test elsewhere.) | `tracking_validate_macos.sh:205-207` |
| ZFT-VAL-3 | LOW | "Version-matched helper" is never verified — the check is `[ -n "$APP_VER" ]`. | `tracking_validate_macos.sh:14,117-118` |
| ZFT-VAL-2 | LOW | *"Eight commits, each independently green"* sits atop a **seven**-item list, and the branch's first five pushed heads all **failed** CI on the Windows job. "Green" means local macOS gates only. | `HANDOFF_PHASE_2.md:71`; `gh run list --branch feat/zero-friction-api-tracking` |
| ZFT-VAL-9 | LOW | `PACKAGED_VALIDATION.md:41-52` group table sums to **40**, not the stated 42. | arithmetic |
| ZFT-VAL-10 | LOW | Packaged "byte for byte" undo check uses `[ "$(cat a)" = "$b" ]`, which strips trailing newlines. (The product property is separately pinned in-crate; the label overstates the script.) | `tracking_validate_macos.sh:270-274` |
| ZFT-VAL-11 | LOW | *"CI clippy pins `+1.97.0`"* — `ci.yml` uses `toolchain: stable`; only the action is SHA-pinned. | `HANDOFF_PHASE_2.md:118` vs `ci.yml` |
| ZFT-VAL-12 | LOW | *"Final head `4e3cc98`"* is wrong by construction — the real head is `24acc470`. CI did pass on the real head, so the substance survives. | `REVIEW_HANDOFF.md:132-136` |
| ZFT-VAL-13 | LOW | *"closes O10"* — the mechanism ships, but `docs/gateway/OPEN_DECISIONS.md:87` still presents O10 as open with the superseded default, while three other gateway docs got dated corrections. | `OPEN_DECISIONS.md:87` |
| ZFT-VAL-14 | LOW | `DETECTION_COVERAGE.md:71` *"every one of these is a test, not a promise"* — the symlink bound's test is `#[cfg(unix)]`, so it is unpinned on Windows: the exact platform where this branch just proved platform-conditional bounds fail silently. | `bounds.rs:115` |
| ZFT-VAL-15 | LOW | `TROUBLESHOOTING.md:3-5` implies the built-in diagnosis automates all eight listed causes; it automates six ("wrong folder" and "proxy bypass" have no check). | `diagnose.rs` (10 ids) |
| ZFT-VAL-16 | LOW | `track.rs:219 track_json_status_shape_is_stable` asserts only exit code 2 — **no JSON is asserted anywhere.** The name overclaims. | `apps/cli/tests/track.rs:219` |
| ZFT-VAL-17 | LOW | `KNOWN_LIMITATIONS.md` omits: the git-tracked `.env` caveat (the loopback URL + link slug can be committed), the persisted inferred origin (`ZFT-047`), and the `cfg(unix)` symlink test gap. | doc review |

---

## What is genuinely good

Recorded so the verdict is not read as uniformly negative. Each was verified, not
assumed:

* **The packaged app really does ship and use its own helper.** Byte-identical
  sidecar inside `Tethra.app/Contents/MacOS/tethra`, correct Tauri v2
  `externalBin` naming, hard build failure when unstaged, sidecar-first discovery
  behind a real exec probe, **zero** `target/release` or repo-relative paths in
  production code, no elevation anywhere, argv-based (shell-free) command
  construction throughout.
* **One screen, N providers.** Bulk review with pre-selected providers, one
  confirmation, an exact file diff. Three-provider and thirty-provider projects
  take the same four clicks. No per-provider forms.
* **Verification is genuine on the happy path.** Unrelated local traffic, a wrong
  slug and a wrong route prefix all correctly fail to verify; one real request
  through the correct route correctly flips it.
* **Undo restores byte-for-byte** on a successfully recorded apply, and keeps
  recorded history.
* **Coverage honesty is excellent.** No claim of remote/Docker coverage; empty
  state says "observed yet", never "no API usage"; cost labelled a lower bound;
  unsupported providers get specific, accurate explanations.
* **Gateway enforcement did not regress.** 269 gateway tests pass, 0 failures;
  all 19 named black-box threats have passing tests; `routes.rs` changed by one
  doc-comment line; auto-created routes reuse the identical `validate_origin` +
  MAC + SSRF machinery (loopback and plaintext-http origins correctly refused).
* **No API keys, headers, cookies, bodies, prompts or key material are
  persisted** — verified statically and by canary across DB, WAL, SHM, logs,
  helper state and desktop storage. The one exception is `ZFT-016`.
