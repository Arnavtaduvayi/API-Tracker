# Local Gateway — Known Conflicts With Shipped Code and Documentation

Every place where this feature contradicts, supersedes, or must amend
something the repository already ships. Each entry states the conflict, the
resolution, and where the resolution is recorded. Compiled from a full
repository read (docs, ADRs, crates, CI, packaging) during the architecture
phase; anything discovered later must be added here, not silently absorbed.

## C1. ADR 0014 rejected a local gateway

`docs/decisions/0014-cross-provider-observability.md:42-50` rejected a local
request gateway/SDK shim ("mandatory-feeling moving part... none was built")
and left the door open: "the decision stands until a concrete use case
demands an OPTIONAL gateway." ADR 0017:27-36 reaffirmed the constraints while
superseding 0014 for the observation-proxy mechanism only.

**Resolution:** ADR 0019 formally supersedes ADR 0014's gateway stance for
this mechanism, invoking the same escape clause, and re-binds its
constraints: opt-in, never ambient, never required by any other feature.
`PRODUCT_SPEC.md:116` lists "a mandatory API proxy" as a non-goal — the
gateway remains optional; nothing else in the product depends on it.

## C2. "Functions, not daemons" doctrine vs an OS background service

ADR 0008:66-69 chose monitor-as-function over daemon; ADR 0013:132-134
rejected a background daemon; `docs/FEATURE_MATRIX.md` #17 stresses the
monitor "is NOT an OS background service"; the release-readiness inventory
records "no OS background service (by design, documented)".

**Resolution:** ADR 0019 supersedes this doctrine ONLY for the gateway, with
consent-first installation (nothing installs on app launch), one-action
removal, and a foreground `tethra gateway run` alternative. FEATURE_MATRIX
and the readiness inventory must be amended in the implementation PR.

## C3. Stop-on-lock precedent vs forward-while-locked

PR #13 made vault lock tear down active observation
(`crates/observe/src/session.rs` LockPolicy; RO-13;
`docs/RUNTIME_OBSERVABILITY.md:394-412` "no further HTTPS is decrypted").
The gateway continues forwarding while locked.

**Resolution:** the two behaviors protect different things. Observation
teardown exists because the interception proxy holds the CA signing key and
decrypts TLS — capabilities that must not outlive an unlocked vault. The
gateway holds no vault-derived key material (except the optional matching-only
fingerprint key, separately consented and revocable — see PRIVACY_MODEL §4),
terminates no TLS toward clients, and reads no credentials from the vault, so
a lock removes nothing it depends on. ADR 0019 records the distinction; user
docs must present both behaviors side by side so "lock stops observation" is
not read as covering the gateway.

## C4. "No capability anywhere to record bodies" vs bounded usage extraction

`docs/RUNTIME_OBSERVABILITY.md:9-12` claims no capability anywhere in the
design to record bodies; `RUNTIME_OBSERVABILITY_ARCHITECTURE.md:189` says
bodies are "relayed, never parsed and never accumulated"; the privacy model's
structural enforcement is a type with no body-capable field.

**Resolution:** those claims stay true for `crates/observe`. The gateway
introduces a NEW, narrowly-scoped capability: in-flight, bounded inspection
of response bytes that extracts a fixed numeric/enum allowlist (model string,
token counts) and can never persist body bytes (its record type has no
body-capable field either — same structural pattern). Product-wide phrasing
must be re-scoped from "the design" to "the observation proxy", and the
gateway's own PRIVACY_MODEL.md documents the extraction allowlist and its
property tests. This is the single largest privacy-posture delta in the
feature and is called out in ADR 0019, not buried.

## C5. Attribution "never reads an Authorization value"

`crates/core/src/runtime/attribution.rs:1-8` derives attribution only from
injected credentials; header values are never read (presence flag only,
`wire.rs`).

**Resolution:** the gateway is the terminating server for loopback requests —
it unavoidably holds the presented credential in memory to forward it. The
design adds transient keyed-fingerprint matching (never storage, never
logging) as a new, documented attribution source with its own confidence
labels; the injection-based mechanism is unchanged for `tethra run`. See
PRIVACY_MODEL §4 for the exact lifecycle and the locked-vault fallback.

## C6. THREAT_MODEL.md egress enumeration

`THREAT_MODEL.md:46-56` states outbound network use "is limited to three
things" and the observation proxy "originates no requests of its own".

**Resolution:** the implementation PR must add the gateway as a fourth
enumerated egress category (forwards client-initiated requests to registered
provider origins only) and adjust the "originates no requests" phrasing to
stay accurate per subsystem.

## C7. ADR numbering collision

Three shipped documents (ADR 0017:144,213;
`RUNTIME_OBSERVABILITY_ARCHITECTURE.md:338`; `DEVELOPER_GUIDE.md:237`)
already cite "ADR 0018" as the runtime-observability storage decision, but
the file was never written.

**Resolution:** `0018-runtime-observability-storage.md` is backfilled in this
branch (recorded retroactively, clearly labeled); the gateway ADR takes 0019.

## C8. Usage double-counting

`crates/core/src/usage.rs` `totals()` sums all matching `usage_snapshots`
regardless of source; a user running both gateway routing and provider admin
sync would double-count the same consumption.

**Resolution:** gateway-extracted usage is NEVER written to
`usage_snapshots`. It lands in new v13 gateway tables and is surfaced as its
own labeled series. Budgets/alerts keyed to provider-reported usage are
unaffected; whether gateway-observed spend feeds budget rules is an explicit
OPEN_DECISIONS item, not an accident.

## C9. CI's explicit `-p` lists give new crates zero coverage

`.github/workflows/ci.yml` clippy/test steps enumerate crates explicitly
(the observe crate's own history documents this failure mode), and
`release.yml` builds only `api-tracker-cli`.

**Resolution:** the implementation PR's first commit adds `crates/gateway` to
the clippy and test `-p` lists, the Windows job, and the release build list
for the new binary; the `no_insecure_verifier` source-grep guard is
duplicated scoped to `crates/gateway/src` (the existing guard scans only
`crates/observe/src`).

## C10. `tethra run` env scrubbing vs gateway env vars

`crates/core/src/inject.rs` `scrub_own_env` strips all `TETHRA_*` /
`API_TRACKER_*` variables from monitored children.

**Resolution:** gateway `.env` onboarding writes provider-native variable
names only (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, ...) so redirects
survive `tethra run`; Tethra ownership is marked with a comment line, not a
variable name. Interplay note: monitored children reach the loopback gateway
directly (`trust.rs` NO_PROXY covers loopback), so the two features compose;
the exact composed behavior must be integration-tested, not assumed.

## C11. Supabase-style per-project origins

`provider-manifests/supabase.toml` deliberately has no fixed data-plane
origin (each project is `https://<ref>.supabase.co`).

**Resolution:** route registration supports validated custom origins (https,
port 443, SSRF-policy-checked, explicit user consent) in addition to
manifest-declared fixed origins; the manifest gains an additive `[gateway]`
section only where a fixed origin truly exists.

## C12. Unsigned-alpha macOS reality vs a launchd-run binary

`docs/release/TETHRA_MACOS_PACKAGING_RESULTS.md`: current artifacts are
ad-hoc-signed and Gatekeeper-rejected; users bypass via right-click-Open.
A launchd-spawned background binary gets no interactive bypass, and
quarantine-attribute propagation on the relocated copy must be validated.

**Resolution:** the service-install step must verify the installed copy
actually executes under launchd on a quarantined install (stage-gated in
IMPLEMENTATION_PLAN; if it does not, `tethra gateway run` foreground mode is
the honest fallback until signing lands, and the consent screen must say so).

## C13. Windows has never been executed

`TETHRA_KNOWN_RELEASE_LIMITATIONS.md:54-56`: Windows code paths compile in CI
but have never run on Windows.

**Resolution:** the Windows scheduled-task installer ships labeled
experimental, off the default path, with the foreground mode as primary until
the platform has real execution evidence.

## C14. Terminology drift in the original brief

The proposal referenced `RuntimeObservation` and a `freshness` field; neither
exists (`ObservedRequest` is the DTO; the closest concepts are
`first_seen_at`/`last_seen_at`). Gateway documents use the real names.

## C15. `db::open` performs no schema check

`crates/core/src/db.rs:866` `open()` runs pragmas + permissions only;
`SchemaTooNew` is raised solely inside `migrate_with`. A relocated KeepAlive
service that outlives an app upgrade would `INSERT` into a newer schema with no
error.

**Resolution:** the gateway uses a new `db::open_at_current_version` helper
(open + assert `user_version == current_schema_version`) for every flush and
route load; mismatch in either direction → persistence-degraded, keep
forwarding. Migration v13 is applied only by the enable/unlock flow, never by
the service. (ADR 0019 D3.)

## C16. `retention::sweep` does not cover the new gateway tables

`crates/core/src/runtime/retention.rs:43` sweeps only
`runtime_request_events` and `runtime_metric_buckets`. The new
`gateway_usage_events` / `gateway_usage_daily` / `gateway_route_counters`
tables would grow unbounded, and folding usage into the 7-day event window
would erase the displayed 90-day spend series.

**Resolution:** retention is extended (new function or params) — raw usage on
7 days, `gateway_usage_daily` on ~90 days, counters swept alongside; the
gateway timer drives it; uninstall enumerates and deletes all gateway tables.
PRIVACY_MODEL §6 wording corrected. (ADR 0019 D6/D7.)

## C17. Roll-up watermark vs the async writer

`aggregate::roll_up` (`aggregate.rs:277`) advances a SHARED watermark and never
revisits earlier hours; a desktop `run_monitor` roll-up concurrent with a
late gateway flush could permanently exclude an event from hour/day buckets
once 7-day raw retention expires.

**Resolution:** after each flush the writer compares the batch's `min(at)` hour
to the watermark and calls `aggregate::reroll_hours(min_at, max_at)` when the
batch lands at-or-below it (existing API). (ADR 0019 D7.)

## C18. `migration_safety.rs` does NOT assert a fixed migration count

An earlier draft of these gateway docs claimed v13 migration tests must avoid
`migration_safety.rs` because it "greps a fixed count". A direct read of the
409-line file shows NO fixed-count assertion: it iterates `MIGRATIONS`
dynamically and its `populated_v5_and_v6_tables_survive_the_upgrade` test is
exactly the pattern a v12→v13 populated-upgrade test should follow.

**Resolution:** the v12→v13 test goes IN `migration_safety.rs`; the false claim
is corrected in TEST_PLAN and IMPLEMENTATION_PLAN. (Self-correction from the
adversarial review.)
