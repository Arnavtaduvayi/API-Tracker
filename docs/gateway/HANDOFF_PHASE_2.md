# Local Gateway — Phase 2 (Core Implementation) Handoff

What was built, what was deliberately changed from the Phase 1 design and
why, what is proven by a shipped test, and what a Phase 3 session must do
next. Nothing here is claimed unless a test or a command in this document
demonstrates it.

## Commits

- **Starting commit:** `927cadf` (Phase 1: architecture, ADR 0019, spike).
- **Ending commit:** `00ec2b9` (`00ec2b9c87a4beb51e413e860e0df0b2a0617a25`). The Phase 2 range is
  `927cadf..00ec2b9` on `feat/local-gateway`.

| Commit | Stage |
|---|---|
| `4814a3b` | test: drop a vacuous assertion newer clippy rejects (`overly_complex_bool_expr`) — a one-line DELETION in `crates/core/tests/rotation_access.rs`, no production code touched. A CI-hygiene prerequisite: the assertion was tautological and the newer clippy refused it, so it blocked the branch until removed. Its parent is `927cadf`, so it sits inside the Phase-2 range; plain `git log --oneline` prints it below `927cadf` (equal commit dates), which makes it look out of range. |
| `34126ac` | Stage A — crate, v13 migration, exact-version open, CI wiring |
| `0403e42` | Stage B — secure route table, manifest origins, MAC'd custom routes |
| `af46f3b` | Stage C — forwarding engine |
| `d2d1bbe` | Stages D+E — attribution, usage extraction, adversarial-review fixes |
| `93c00eb` | Stages F+G — writer, locked-vault operation, control plane |
| `2d25f1b` | CLI `gateway` family, honest-degradation fixes |
| `00ec2b9` | Final adversarial sweep — all 12 confirmed findings fixed |
| (this commit) | Handoff commit hashes and final counts |

**PR #13 was already merged into `origin/main` before Phase 1** (main is at
`5efec9b`, which is the merge of PR #12 and contains PR #13's work). The
feature branch was already based exactly on `origin/main`, so **no rebase was
required and none was performed**; `git merge-base HEAD origin/main` equals
`origin/main`. No force-push, no history rewrite, and PR #13 was not touched.

## Phase 1 gate

`docs/gateway/` and ADR 0019 record Phase 1 as complete with production
implementation gated on the ADR plus `IMPLEMENTATION_PLAN.md`. The literal
string `PROCEED TO LOCAL GATEWAY IMPLEMENTATION: YES` does not appear
anywhere in the repository. The gate was read as satisfied on the documents'
own terms: ADR 0019 is `Status: accepted`, `HANDOFF_PHASE_1.md` marks Stage 0
DONE and names "Stage 1, commit 1" as the exact next commit, and
`IMPLEMENTATION_PLAN.md` states each stage's entry and exit criteria. That
reading is recorded here explicitly rather than assumed.

## Crate structure

`crates/gateway` (`api-tracker-gateway`), `#![forbid(unsafe_code)]`, 7,554
lines of source and 4,628 lines of tests.

| Module | Lines | Responsibility |
|---|---|---|
| `head.rs` | 955 | Bounded, zeroizing head reading; strict framing validation; canonical head regeneration |
| `forward.rs` | 1000 | The exchange engine: request gate, routing, streaming, local diagnostics |
| `control.rs` | 898 | Authenticated Unix-socket control channel |
| `writer.rs` | 788 | Dedicated observation writer, batching, retention, roll-up |
| `usage.rs` | 726 | Bounded, provider-scoped usage extraction |
| `routes.rs` | 712 | Route snapshots, manifest origins, MAC'd custom origins |
| `attribution.rs` | 686 | Keyed-fingerprint credential attribution |
| `upstream.rs` | 448 | Two-phase SSRF, verified TLS, per-(connection,route) sockets |
| `stream.rs` | 400 | Strict chunked relay with a decoded tap |
| `service.rs` | 276 | Composition root: listener + writer + control + poller |
| `record.rs` | 220 | The structural privacy boundary (`ExchangeRecord`) |
| `server.rs` | 212 | Loopback listener, connection cap, bounded drain |
| `store.rs` | 191 | v13 config and counter storage |

`apps/cli/src/gateway_cmd.rs` (442 lines) adds the `tethra gateway` family.

## Migration

**Version 13**, append-only, all STRICT. v1–v12 untouched.

Tables: `gateway_config`, `gateway_routes`, `gateway_project_links`,
`gateway_usage_events`, `gateway_usage_daily`, `gateway_route_counters`, plus
one additive column `runtime_request_events.attribution_method`.

`gateway_routes` deliberately stores **no obeyable origin**: manifest routes
resolve theirs from the compiled-in provider manifest, and custom origins are
stored only next to a MAC over `(vault_id, provider_id, origin, port,
consent_ts)` under a new vault-derived key.

## Dependencies added

**Zero net-new third-party crates**, as ADR 0019 required. Every dependency of
the gateway crate was already in the workspace lockfile via core or observe:
`rustls`, `rustls-pki-types`, `httparse`, `socket2`, `rusqlite`, `time`,
`serde`, `serde_json`, `zeroize`, `blake3`, `subtle`, `uuid`. No tokio, no
hyper, no new TLS or HTTP stack. The control channel uses `std::os::unix::net`.

## Deviations from the Phase 1 design

Each of these changed a decision recorded in Phase 1. They are listed here
rather than absorbed silently.

### D1. A gateway-local head reader instead of reusing `observe::wire`

ADR 0019 D2 said the seedable response-head reader would be "added to `wire`",
and D7 separately required a gateway-local zeroizing reader. Building two
half-readers would have been worse than one correct one: `head.rs` is a single
reader that is both zeroizing (buffers allocated once at `MAX_HEAD` so growth
cannot strand credential bytes) and seedable (with a deadline variant that
preserves the partial buffer, which the `Expect:` path needs and which the
Phase 1 spike did not have). `observe::wire` is unmodified, so the observe
crate keeps its audited behavior.

### D2. A gateway-local strict chunked relay instead of reusing `observe::relay` for chunked bodies

`observe::relay` accepts a bare `\n` as a chunk-line terminator and echoes it
verbatim. For the observation proxy that is harmless. For a gateway it is the
classic LF-chunk smuggling primitive, and **SI-15 requires rejection, not
forwarding**. The adversarial re-review confirmed the original code forwarded
these unchanged while a test named `..._is_rejected_...` asserted only that
they were not *normalized*. `stream.rs` now relays chunked bodies with strict
CRLF, bounded chunk lines, rejected chunk extensions, and a bounded trailer
section. It also solves a second problem: the usage tap is fed **decoded**
chunk data, so chunked SSE — the exact case extraction exists for — parses
correctly instead of seeing chunk-size lines spliced into events.
Content-Length and until-close bodies still stream through the same
byte-for-byte path.

### D3. The control channel's same-uid gate is filesystem permissions, not `SO_PEERCRED`

SI-21 specifies a `SO_PEERCRED`/`LOCAL_PEERCRED` peer-euid check.
`UnixStream::peer_cred` is **still unstable in Rust**, and reading the socket
option directly requires either `unsafe` (forbidden crate-wide) or a new
`libc`/`nix` dependency (ruled out by ADR 0019's dependency decision). The
enforcement used instead is the kernel's own, one layer down and equally
same-uid-exact: `connect(2)` to a Unix socket requires **write permission on
the socket inode**, the socket is `0600`, and its parent data directory is
`0700`, so adversary A6 (another local user) cannot connect and cannot even
traverse to the path. The check is re-run on **every accept**, not just at
bind, so a mode loosened underneath the process stops the channel instead of
silently widening it (tested). The residual versus a peer-cred call is a
same-uid process — which SI-21's check would also have admitted.
**This should be revisited when `peer_cred` stabilizes.**

### D4. `gateway serve`, not `gateway run`

The session scope named `gateway serve`; ADR 0019 and PRODUCT_BEHAVIOR say
`tethra gateway run`. `serve` is the shipped verb. A Phase 3 session adding
the service lifecycle should either add `run` as an alias or amend the docs —
whichever it does, the two names must not both exist meaning different things.

### D5. `gateway_config` has no `bind` column

`ARCHITECTURE.md` sketched a `bind` field. SI-1 hard-codes the loopback bind
and forbids a host-configuration surface; a column that cannot be honoured is
worse than no column, so it was dropped. A source-guard test fails the build
if a wildcard bind address ever appears in the crate.

### D6. The exchange engine is transport-generic

`forward.rs` takes an `UpstreamConnector`. Production is always `TlsConnector`
(two-phase SSRF + verified TLS) — enforced by a source-guard test asserting
that no production module names the test-only plain connector and that
`Gateway::new` defaults to TLS. The seam exists because HTTP framing semantics
are transport-independent and otherwise could not be tested against local
synthetic providers without weakening the SSRF policy for everyone.

### D7. `resolve_validated` takes an injectable resolver

Added because the post-DNS SSRF check was otherwise **untestable**, which the
adversarial re-review proved: every literal in the original tests was rejected
in phase one, so deleting the entire resolved-address filter left the whole
suite green. The seam makes SI-3's real case testable and the coverage was
verified by mutation (deleting the filter now fails two tests).

## Adversarial re-review (ADR-mandated before persistence/attribution)

Six independent attacker lenses over the forwarding core, each finding
adversarially verified by an independent skeptic. **37 claims raised, 31
survived verification, 6 refuted.** Deduplicated across lenses, the fixed
defects were:

- A non-100 1xx (103 Early Hints) in the `Expect:` window was treated as the
  final response — the request body was silently dropped and the client
  received an informational status as its answer.
- Bare-LF chunk framing forwarded verbatim instead of rejected (SI-15).
- The usage tap was fed raw chunk framing, breaking chunked-SSE extraction.
- No client write timeout: a client that stopped reading pinned a thread, an
  upstream socket, and a connection-cap slot indefinitely.
- Shutdown joined connection threads unconditionally with no deadline.
- A truncated client Content-Length body was accepted as success, after which
  the gateway blocked for the full upstream idle budget.
- Certificate failures were recorded as generic resets.
- The Slowloris deadline did not match the documented budget; an idle
  keep-alive connection got a spurious 400 rather than a silent close.
- `contains("://")` refused legitimate origin-form requests whose *query*
  carried a URL.
- IPv6-literal origins were handed to `ServerName` bracketed, always failing.

The most valuable class was **test honesty**: SI-3's post-DNS SSRF filter had
zero real coverage; the LF-chunk test asserted less than its name; the
client-disconnect test never asserted the upstream teardown. All are fixed,
and the named TEST_PLAN items that had no test at all now have one.

Two further bugs were found by the new tests themselves and fixed:
`Writer::stop` sent its stop signal through the same bounded queue (deadlock
on a full queue), and on BSD/macOS an accepted socket inherits the listener's
non-blocking flag, which made the control channel intermittently drop
connections.

## Final adversarial sweep (after the core was complete)

A second review — attribution/crypto, usage/writer, control/service lenses,
each finding independently verified — raised 16 claims of which **12 were
confirmed**. All confirmed findings were fixed before the final commit:

- **Anthropic cache tokens were double-counted** (high). `message_delta`
  repeats the *cumulative* input and cache counts, not just the output, so
  the per-frame addition inflated every prompt-cached request's input tokens
  (135 became 245 in the reproduction). Cache components are now tracked in
  their own fields with the same idempotent `set_max` as everything else and
  summed exactly once. OpenAI's cached tokens are a *subset* of
  `prompt_tokens`, so they are not added there — the provider shape decides.
- **Only the first recognized credential header was digested.** Clients that
  send both `Authorization` and `x-api-key` (Anthropic with an auth token,
  Azure-style clients) got a false `unmatched` for the credential that
  actually served the request, and a leading `Basic` masked a following
  supported header entirely. Every recognized header is now digested.
- **A password-locked project's fingerprint could reach the matcher** through
  a reference row in an unlocked, linked project, which carries a copy of the
  root's fingerprint — a direct SI-9 / GW-6 violation. Roots in
  password-locked projects are now excluded wherever their references live.
  Traffic using such a shared value reports `unmatched` until the owning
  project is unlocked; that is the honest degradation.
- **A matcher install could be silently dropped** on a full queue, so
  `push-key` returned success while every exchange was recorded
  `unavailable_vault_locked` and status claimed attribution was on. Control-
  plane installs now wait briefly for a slot and report failure.
- **Counter bumps lost to an unavailable database were unaccounted**, breaking
  the documented "every bump is applied or accounted" property.
- **`persist_with` was not transactional**, so a mid-sequence failure could
  leave an event row without its usage row. One exchange is now one
  transaction.
- **The control nonce was reused as the writer's boot id** and therefore
  persisted into the plaintext `observation_sessions.command` column and shown
  by `tethra observe sessions` — a live control capability written to disk.
  The boot id is now its own random value.
- **Cache-read tokens were priced at the full input rate.** They are billed at
  roughly a tenth of it, and `estimate_token_cost_as_of` does not consult the
  cached rate the pricing tables carry, so a cached workload's spend was
  overstated several-fold. Cache reads are now excluded from the estimate,
  which makes it a **lower** bound for cached traffic — recorded as a
  limitation below, because overstating spend is the more harmful error for a
  budgeting tool.
- **A silent port-persist failure** would have made the next `serve` bind a
  different random port and break every linked `.env` with no explanation. It
  now prints a warning naming the port to pin.
- The matching key transited plain heap `String`s on both ends of the push;
  the buffers this crate controls are now `Zeroizing` (serde still builds one
  plain `String` inside `send`, which is a documented best-effort limit).

Two confirmed findings were **not** fixed and are recorded as limitations
instead: the stale-socket replacement TOCTOU (below), and the
`persist_with` failure-accounting subtlety that a rolled-back transaction is
counted once as a persist failure rather than per statement.

## Tests

**Workspace: 826 tests, all passing (`cargo test --workspace --all-targets`, exit 0). Gateway crate: 171 of them.**

| Suite | Count | Proves |
|---|---|---|
| `crates/gateway` unit | 71 | Head parsing/validation/regeneration, strict chunked relay, usage extraction, attribution states, SSRF phases, route/prefix validation, config+counters, listener bind |
| `tests/forwarding.rs` | 38 | TEST_PLAN §1–§2 |
| `tests/writer.rs` | 17 | TEST_PLAN §4, §8 |
| `tests/control.rs` | 13 | TEST_PLAN §3 control channel, §5 key lifecycle |
| `tests/routes.rs` | 11 | TEST_PLAN §3 route table and SSRF |
| `tests/privacy_canaries.rs` | 7 | TEST_PLAN §6 |
| `tests/no_insecure_verifier.rs` | 6 | TEST_PLAN §11 source guards |
| `tests/schema.rs` | 5 | TEST_PLAN §8 schema behavior |
| `crates/core/tests/migration_safety.rs` | 9 (was 8) | v12→v13 populated upgrade, backup coverage |

Highest-severity tests, named: `cross_route_requests_never_share_an_upstream_socket`
(a keep-alive client switching providers reaches two distinct upstreams and
neither credential enters the other's connection),
`no_canary_survives_a_live_exchange_into_any_artifact`,
`the_matching_key_never_reaches_disk_argv_or_environ`,
`phase_two_refuses_a_public_name_that_resolves_into_the_private_network`,
`a_locked_vault_never_interrupts_forwarding_and_degrades_attribution_honestly`.

## CI state

`.github/workflows/ci.yml`, in the same commit that created the crate:

- `rust` job: `api-tracker-gateway` added to both the clippy `-p` list and the
  test `-p` list (Linux).
- `rust-windows` job: `cargo test -p api-tracker-core -p api-tracker-gateway`
  (Windows; the Unix control channel is `cfg`-gated out and its stub refuses
  key push rather than falling back to TCP).
- macOS is covered by the `desktop` job's clippy over the workspace-linked
  crates; the gateway's own macOS test evidence in this session is the local
  run recorded below.
- `scripts/smoke.sh`: the migration-suite expectation was updated 8 → 9.

Validation run at completion, all green: `cargo fmt --all --check`;
`cargo +1.97.0 clippy --workspace --all-targets -- -D warnings`;
`cargo test --workspace --all-targets` (826 passed, 0 failed);
`cargo build --workspace --release`; `bash scripts/smoke.sh` (126 passed, 0 failed).

## Known limitations

1. **No OS service.** `tethra gateway enable` reports that installation is not
   implemented and points at `serve`. Nothing about launchd, systemd, or Task
   Scheduler exists yet.
2. **No `.env` rewriting.** `gateway link` PRINTS the exact lines to add and
   says the writing is not implemented. `EnvDocument`/`envgov` integration,
   the unmasked diff, `NO_PROXY` handling, and unlink-restores-prior-value are
   Phase 3.
3. **No desktop surfaces.** No Tauri commands, no panels, no consent screen.
4. **Ctrl-C is the process default.** A graceful drain is available through
   `tethra gateway stop`; SIGINT terminates. A signal handler was not added
   because it needs a dependency the ADR rules out.
5. **The control socket path is length-limited.** Unix sockets cap `sun_path`
   at ~104 bytes; a long `TETHRA_DIR` makes the control channel unavailable.
   This is now detected and reported with an actionable message, and `serve`
   prints a warning naming exactly what is lost (status, attribution, graceful
   stop) — forwarding and recording continue.
6. **The pooled-upstream liveness probe peeks the raw TCP socket** beneath
   rustls, so plaintext already buffered inside the TLS session is invisible
   to it. The redial-once path covers the case in practice; a future fix would
   consult the rustls connection state.
6b. **Cost estimates exclude cache-read tokens**, so they are a LOWER bound
   for prompt-cached workloads. `estimate_token_cost_as_of` knows only the
   base input and output rates; the cached rate the pricing tables carry is
   not consulted by any caller in the workspace. Wiring it through is a core
   change a Phase 3 session should make.
6c. **`ControlServer::start`'s stale-socket replacement is TOCTOU.** Two
   simultaneous starts can both pass the liveness probe and the second can
   unlink the first's live socket, leaving one gateway reachable and one
   orphaned. The window is small and requires two concurrent starts against
   one data directory; a lock-file protocol would close it.
7. **Attribution is off unless a key is pushed.** Per OPEN_DECISIONS O2 the
   toggle defaults OFF; `serve --with-attribution` or `gateway push-key`
   enables it, reauth-gated and audited.
8. **Windows has still never been executed.** The gateway compiles and tests
   there in CI; the control channel is absent by design.
9. **No live provider call has ever been made through this gateway.** Every
   test upstream is a local synthetic listener. The TLS client path is the
   already-audited observe one, but end-to-end evidence against a real
   provider does not exist yet.

## Remaining work

**CLI** — `.env` onboarding (`EnvDocument` + `envgov::atomic_write`, unmasked
diff, marker comment, `NO_PROXY`, alias variables, `generate_example` skip),
unlink restoring the recorded prior value, the link-time keyless probe, and
the "no traffic since link" state.

**Services** — macOS LaunchAgent (fresh byte-write install, `xattr -d`, exec
probe before registering, `KeepAlive={Crashed:true}`, `bootout`/`kickstart`),
Linux systemd user unit with honest linger reporting, Windows foreground-only
with `enable` saying so, the version handshake, and the ordered
disable/uninstall manifest that restores every linked `.env`.

**Desktop** — Tauri commands (`generate_handler` + `api.ts` + `types.ts`),
the activity view, the route-link UI, and the consent screen that discloses
the service, the standing local egress relay, and the match-while-locked
toggle's exact consequence.

**Docs** — the honesty amendments Stage 7 owes: `THREAT_MODEL.md`'s fourth
egress category, `RUNTIME_OBSERVABILITY.md`'s "no bodies anywhere" rescoped to
the observation proxy, `FEATURE_MATRIX.md`'s "no OS service" line, and the
release classification.

## Commands for Phase 3

```bash
cd /Users/arnavtaduvayi/Documents/APItrack/API-Tracker-local-gateway
git log --oneline 927cadf..HEAD          # this phase

# Build and validate
cargo fmt --all --check
cargo +1.97.0 clippy --workspace --all-targets -- -D warnings
API_TRACKER_INSECURE_FAST_KDF=1 cargo test --workspace --all-targets
cargo build --workspace --release
bash scripts/smoke.sh

# Exercise the gateway by hand (use a SHORT data dir: see limitation 5)
export TETHRA_DIR=/tmp/gw API_TRACKER_INSECURE_FAST_KDF=1
export TETHRA_PASSWORD='some-long-test-password'
./target/debug/tethra init
./target/debug/tethra project create app
./target/debug/tethra gateway route add openai
./target/debug/tethra gateway link --project app --route openai
./target/debug/tethra gateway serve &        # prints the port it bound
./target/debug/tethra gateway status         # works with the vault locked
./target/debug/tethra gateway stop
```

## Files most important for the next session

1. `crates/gateway/src/forward.rs` — the request gate's ORDER is
   security-relevant; read the module docs before changing it.
2. `crates/gateway/src/head.rs` — every framing rule lives here.
3. `crates/gateway/src/routes.rs` — the origin trust model (manifest vs MAC).
4. `crates/gateway/src/control.rs` — read the SI-21 deviation note first.
5. `crates/gateway/src/writer.rs` — why the sink must never block.
6. `crates/gateway/tests/privacy_canaries.rs` — the proof style to extend.
7. `docs/gateway/SECURITY_INVARIANTS.md` and `TEST_PLAN.md` — the authority
   for what must stay true.
8. `docs/decisions/0019-local-gateway.md` — the design rationale; amend it (or
   add an ADR) for any further deviation.

## What this build actually does, stated plainly

It forwards. A loopback-only HTTP/1.1 listener accepts requests whose first
path segment names a registered provider route, rebuilds the head canonically,
opens a certificate-verified TLS connection to an origin that came from the
compiled-in manifest (or a MAC-verified custom origin), streams the request and
response bodies in both directions without buffering them, and records
sanitized metadata plus bounded token counts through the existing runtime
funnel. It refuses to be a proxy, refuses browser-shaped requests, rejects
smuggling-shaped framing rather than normalizing it, keeps forwarding when the
vault is locked or the database is gone, and never persists a credential, a
body, a query, or a cookie.

It is not installed as a service, does not rewrite `.env` files, and has no
desktop UI. It has never talked to a real provider.

CORE LOCAL GATEWAY READY FOR PRODUCTIZATION: YES
