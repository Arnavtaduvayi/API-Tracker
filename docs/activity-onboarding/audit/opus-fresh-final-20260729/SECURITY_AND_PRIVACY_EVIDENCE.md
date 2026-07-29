# Security and privacy — independent evidence

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`.
All test counts below were derived by this audit from its own
`cargo test --workspace --all-targets` run, not copied from any handoff.

## 1. Executed suite inventory

Security- and privacy-relevant suites, from this audit's own run:

| Suite | pass | fail |
| --- | --- | --- |
| `crates/gateway/tests/forwarding.rs` | 44 | 0 |
| `crates/gateway/tests/control.rs` | 24 | 0 |
| `crates/gateway/tests/envlink.rs` | 26 | 0 |
| `crates/gateway/tests/service_namespace.rs` | 21 | 0 |
| `apps/desktop/…/tauri_command_authz.rs` | 18 | 0 |
| `crates/core/tests/gitsafe_differential.rs` | 12 | 0 |
| `crates/core/tests/gitbound_scanning.rs` | 10 | 0 |
| `crates/gateway/tests/privacy_canaries.rs` | 10 | 0 |
| `crates/core/tests/scan_bounds.rs` | 10 | 0 |
| `crates/gateway/tests/bounds.rs` | 10 | 0 |
| `crates/core/tests/git_isolation_canaries.rs` | 9 | 0 |
| `crates/core/tests/gitsafe_bounds.rs` | 7 | 0 |
| `crates/core/tests/git_execution_canaries.rs` | 6 | 0 |
| `crates/observe/tests/proxy_integration.rs` | 6 | 0 |
| `crates/gateway/tests/restore_record_privacy.rs` | 5 | 0 |
| `crates/core/tests/obs004_expiration_isolation.rs` | 5 | 0 |
| `crates/core/tests/monitor_scan_isolation.rs` | 1 | 0 |
| **Total** | **177** | **0** |

Whole workspace: **1254 passed, 0 failed, 9 ignored across 86 binaries.** The
nine ignored are all documented performance benchmarks
(`crates/gateway/tests/perf.rs` ×8 — *"performance measurement; run via
scripts/gateway_perf.sh"*; `crates/observe/tests/proxy_integration.rs:550`),
run separately. No functional test is skipped.

## 2. SEC-02 — the absolute request-body deadline

**The regression risk here is that a request-body deadline also kills a long
streaming response.** It does not, and the scoping is structural rather than
incidental.

`crates/gateway/src/forward.rs:44-49`:

```rust
/// … Applies to the REQUEST body only —
/// a streaming response is a legitimate long-lived read and is not bounded by
/// this.
pub const CLIENT_BODY_DEADLINE: Duration = Duration::from_secs(300);
```

`forward.rs:849-856` — the deadline exists only inside the `if !skip_body`
block, wrapping the **client** stream for the duration of the body relay:

```rust
let body_deadline = Instant::now() + CLIENT_BODY_DEADLINE;
let relayed = {
    let mut client = crate::stream::DeadlineReader::new(client, body_deadline);
    …
};
```

The `DeadlineReader` is dropped when that block ends, so the response path
never sees it. The comment notes the scoping is deliberate — *"Scoped to the
relay itself so the error paths below still see the raw stream."*

Layered bounds, each with a distinct job:

| Constant | Value | Bounds |
| --- | --- | --- |
| `CLIENT_BODY_IDLE_TIMEOUT` (`:38`) | 60 s | per-read stall during upload |
| `CLIENT_BODY_DEADLINE` (`:49`) | 300 s | total upload duration |
| `CLIENT_KEEPALIVE_IDLE` (`:51`) | 120 s | idle between requests |
| `CLIENT_WRITE_TIMEOUT` (`:54`) | 120 s | a client that stops reading mid-response |
| `MAX_CONNECTIONS` (`:57`) | 128 | **503 immediately** rather than unbounded queueing |

| Case | Behaviour |
| --- | --- |
| Slow upload | allowed up to 300 s total |
| Never-ending upload | terminated at 300 s, slot released |
| Idle upload | terminated at 60 s by the idle timeout |
| Long but active upload | allowed, up to the 300 s ceiling |
| Streaming response after a completed body | **unbounded by this deadline** — correct |
| Slot exhaustion | 503 at 128 concurrent; slots return as connections close |

**SEC-02 does not break legitimate streaming — but it is PARTIAL, not fixed.**

### `NEW-48` (Medium) — the deadline is per REQUEST, not per connection

`let body_deadline = Instant::now() + CLIENT_BODY_DEADLINE;` (`forward.rs:853`)
lives inside `handle_request`, which is called once per iteration of the
keep-alive loop at `forward.rs:463`. A client that keeps **completing** slow
bodies therefore gets a fresh 300 s every request and is never idle, so
`CLIENT_BODY_DEADLINE`, `CLIENT_BODY_IDLE_TIMEOUT` and `CLIENT_KEEPALIVE_IDLE`
all fail to fire.

Measured during this audit: **one connection held one of 128 slots for
422.06 s across 20 slow-body requests**, still healthy when the test stopped.
Attacker cost: `Content-Length: 30`, one byte every 700 ms.

This falsifies three documents verbatim:

* `docs/activity-onboarding/KNOWN_LIMITATIONS.md:281-287` — *"the true worst
  case is that deadline plus one 60-second idle timeout … recovers by itself
  once the connections expire."*
* `docs/activity-onboarding/SECURITY_AND_PRIVACY.md:352-357` — *"the true bound
  is the deadline plus one idle timeout (≈360s)."*
* `POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md:194` — the residual-risk row.

The bound is not merely larger than stated; it is **not stateable**. Severity is
unchanged in kind — availability only, loopback-only, 503 rather than queueing,
no credential impact, and an attacker able to open loopback connections is
already running on the machine — so this is **not merge-blocking**. But
**SEC-02 should be re-dispositioned FIXED → PARTIAL**, and the three documents
corrected. Fix: hoist the deadline into `serve_connection` as a per-*connection*
budget, or cap total body-phase seconds per connection.

Two further residues:

* `NEW-51` (low): SEC-02 has **no integration coverage**. Both shipped tests
  exercise `DeadlineReader` against a `&[u8]`. Deleting the wiring at
  `forward.rs:854-856` while keeping the struct leaves both green — the matrix's
  claimed mutation guard covers the primitive, not its use.
* `NEW-52` (low): a deadline expiry is recorded as
  `Completion::ClientDisconnected` + `TransportError::Reset`
  (`forward.rs:902-907`) — byte-identical to a real client drop, with no
  dedicated counter and no 408. A user cannot tell "I hit the upload deadline"
  from "my client died."

## 3. SEC-01 — provider-ID database tampering

The claim is that an attacker who can write `vault.db` can redirect a
credential between *trusted built-in* origins. The exclusion is documented at
`docs/activity-onboarding/SECURITY_AND_PRIVACY.md:308-324`, and the governing
threat-model row is `THREAT_MODEL.md:159`:

> Malware running as the user — **Not defended.** It can keylog the master
> password, read process memory, read the session file plus environment, or
> capture the clipboard. Local encryption cannot beat an attacker inside your
> account.

That exclusion is clear and reasonable, and it is the same adversary. Two
observations that keep it honest:

* The redirection is bounded to origins already in the compiled-in manifest
  set — `add_manifest_route` (`routes.rs:187-211`) re-derives the origin from
  the compiled manifest, so tampering cannot introduce a new destination.
* `THREAT_MODEL.md:157` states in the same table that *"Metadata edits … are
  NOT cryptographically detected"*, which is the honest framing of both SEC-01
  and ENC-02.

### `NEW-49` (merge blocker) — shipping documents claim the protection SEC-01 does not provide

The mechanism first, verified in source. `crates/gateway/src/routes.rs:628-650`
— for a manifest route the row tuple is `(None, None, None, None)` and the
upstream is resolved by `providers::find(&provider_id)`, where `provider_id`
is read **straight from the untrusted row**. `route_mac` is computed and
verified only for custom rows (`:696-716`). So
`UPDATE gateway_routes SET provider_id='anthropic' WHERE route_prefix='openai'`
makes `/openai/*` resolve to `api.anthropic.com:443` — **with the OpenAI
credential still attached**. Thirteen manifests declare a gateway origin, so
any prefix can be pointed at any of thirteen shipped origins.

The exclusion is stated correctly in exactly one place,
`docs/activity-onboarding/SECURITY_AND_PRIVACY.md:306-327`, and that statement
is defensible. But it is contradicted, unqualified, elsewhere:

* **`docs/gateway/SECURITY.md:40-47`** — section heading *"Why database
  tampering cannot redirect your credentials"*, closing with *"A same-user
  process editing SQLite cannot make `/openai/...` (with your key attached) go
  **anywhere else**."* That is the exact inverse of the measured behaviour.
* **`docs/gateway/ARCHITECTURE.md:121-123`** — *"a same-user `UPDATE
  gateway_routes` cannot redirect a live pass-through credential."*
  Unqualified; false.
* **`apps/desktop/src/components/GatewayView.tsx:830-832`** — a **shipped UI
  string** saying the route is *"integrity-protected against database
  tampering."* True for custom origins; it is the only tamper statement in the
  desktop UI, with no counterpart telling the user built-in routes carry no
  such binding.

`docs/gateway/THREAT_MODEL.md:64-79` labels GW-3 **DEFENDED** but qualifies its
sentence to *"an **attacker** origin"* — technically accurate, since SEC-01
reaches only shipped provider origins. I do **not** count that one as false,
though the label oversells it. `README.md:399-404` is about ciphertext binding
and is qualified for metadata at `THREAT_MODEL.md:157`.

**Why this blocks.** SEC-01's disposition is *accepted risk*, and the
acceptance rests on the exclusion being honestly disclosed. It is not: a file
named `SECURITY.md` promises the property in its heading and denies the
limitation in its conclusion, and a shipped UI string reinforces it.
`POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md:182` records as completed work that
*"no user-facing claim implies DB tamper resistance beyond what exists"* — that
is not the case. `SECURITY_AND_PRIVACY.md:337-339` even states the correct
position (*"What is therefore NOT claimed anywhere in this product: that
Tethra detects or resists tampering with its own database…"*), so the
repository contradicts itself. The remediation was applied to one file and
never propagated.

**Correction to this audit's own earlier note.** An earlier draft of this
section recorded that no user-facing claim asserted protection that does not
exist. That was wrong: it searched the root `SECURITY.md` and `THREAT_MODEL.md`
but not `docs/gateway/`. The finding above is the corrected position.

**Test-naming gap** (`NEW-50`, low): `crates/gateway/tests/routes.rs:74`
`a_direct_update_of_a_manifest_route_row_cannot_redirect_it` sets
`provider_id='evil'` — an **unknown** id, which fails closed at `routes.rs:631`.
It never tests a **known** id, which succeeds. The test name is what the other
documents cite.

## 4. Gateway attack surface

Coverage confirmed by suite and by reading the refusal sites. Where a class is
covered by an executed request-and-refusal assertion I mark it **driven**;
where the assertion is a unit check I mark it **unit**.

| Class | Coverage | Anchor |
| --- | --- | --- |
| Open relay / request-selected upstream | **driven** | route resolution rejects anything not in `gateway_routes`; `RouteTarget::Unforwardable` |
| CONNECT | **driven** | method rejected before routing |
| Absolute-form request URI | **driven** | `forwarding.rs` |
| Host confusion | **driven** | upstream host comes from the route, never the request |
| Request smuggling (CL.TE / TE.CL) | **driven** | `Framing` is resolved once; `relay_chunked_strict` **rejects bare-LF chunk bodies** (`forward.rs:858-862`) rather than forwarding them — the comment names this as the difference from `observe::relay` |
| CRLF injection | **driven** | strict CRLF framing toward upstream |
| Redirect escape | **driven** | upstream 3xx is relayed, not followed |
| Traversal / encoding confusion | **driven** | prefix routing on a canonical path |
| Slowloris / slow body | **driven** | `bounds.rs` + the SEC-02 deadline above |
| Connection exhaustion | **driven** | `MAX_CONNECTIONS = 128`, 503 not queue |
| Cross-route credential isolation | **driven** | per-route credential resolution; `forwarding.rs` |
| Route-state tampering | **driven** | `route_mac` BLAKE3-keyed, constant-time verify (`routes.rs:696-714`) → `Unforwardable(MacMismatch)` |
| Approval-state tampering | **driven** | `approval_mac`; a tampered row is treated as **absent**, never trusted (`origin.rs:319-327`) |
| Verification spoofing | **driven** | the packaged `NEGATIVE` group plants a forged pre-apply observation and proves it does **not** flip verification (5 checks), plus `zft006_regression.rs` |
| Diagnostic secret leakage | **driven** | `privacy_canaries.rs`, `restore_record_privacy.rs` |
| Sealed Git execution | **driven** | `git_execution_canaries.rs` (6), `git_isolation_canaries.rs` (9) — fsmonitor, hooks, filters, textconv, diff drivers |
| Signature verifier | **driven** | `gitsafe_differential.rs` (12) |
| Git bounds | **driven** | `gitsafe_bounds.rs` (7), `gitbound_scanning.rs` (10), `scan_bounds.rs` (10) |

**One residue** carried forward from the deferred set: `GIT-01`
(`gitseal.rs:390-392`) truncates the alternates chain silently instead of
refusing, so a chained `clone --shared` deeper than 8 hops yields a silently
short object view. Every other bound in that file refuses loudly. Not
merge-blocking (unusual topology; missed detection rather than a boundary
crossing) but understated — see `DEFERRED_FINDINGS_REVIEW.md`.

## 5. Privacy canaries

**Executed, crate level** — all passing in this audit's run:

* `no_canary_survives_the_real_persistence_path`
* `no_canary_survives_a_live_exchange_into_any_artifact`
* `no_env_value_canary_survives_the_link_writers_restore_record`
* `the_matching_key_never_reaches_disk_argv_or_environ`
* `a_hostile_stream_cannot_grow_the_extractor_without_bound`

**Executed, packaged level** — the `PRIVACY` group on the exact audited head
(from the CI artifact), covering main DB, WAL, SHM, logs, temp files, restore
records and the shared data directory:

```
PASS  the searched inventory is non-empty and includes the vault database
PASS  the API key value appears in no file under the isolated data directory
PASS  the unrelated env value (canary) appears in no file under the isolated data directory
PASS  no authorization header line and no bearer token is stored
PASS  neither needle reached the shared desktop/CLI data directory (it does not exist)
```

The gateway harness adds `no credential or query canary in any on-disk
artifact`, and `smoke.sh` (140/140 here) covers `.env`/vault/backup
git-ignore protection.

**Two qualifications on the packaged privacy claim**, both from the deferred
set and both harness-side:

* `VAL-07` — the header sweep excludes the whole `$DIR/bin/` directory rather
  than the single helper binary (`tracking_validate_macos.sh:1579`). In
  practice `prune_old_binaries` keeps exactly one file there.
* `VAL-08` — helper provenance is an unanchored whole-file `grep -qF`
  (`:1369`) under a label claiming the LaunchAgent *runs* that helper.

Taken together these are the one genuine compound in the deferred set: the
exemption's soundness rests on byte-identity, and nothing binds
`ProgramArguments[0]` to the exempt file. **Harness-only**, and the per-run
needle sweeps still cover `bin/`. Both are one-line fixes.

## 6. Supply chain and repository security

* **All 28 GitHub Action references are pinned to full 40-char commit SHAs**
  with version comments; the policy is documented at `ci.yml:8-11`. Zero
  mutable tags. This is better than most repositories of this size.
* Workflow permissions are `contents: read` at workflow scope, escalated
  per-job only in `release.yml`. Triggers are `pull_request`, **not**
  `pull_request_target` — no fork-PR secret exposure.
* `NEW-25`: GitHub **secret scanning, push protection, validity checks and
  Dependabot security updates are all disabled** on this public repository,
  verified via `gh api … --jq .security_and_analysis`. All are free for public
  repos. On a public credential-manager repository whose tests deliberately
  plant API-key-shaped canaries, push protection being off is a sharper
  omission than the missing branch protection. Not merge-blocking; cheaper and
  higher-value than REPO-01.
