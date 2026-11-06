# Tethra Mesh — review handoff

Branch: `feat/device-mesh` · Base: `origin/main` @ `5ec8198` (2026-10-26) ·
PR [#19](https://github.com/Arnavtaduvayi/API-Tracker/pull/19).

Tethra Mesh replicates a fixed set of data — shared projects, gateway-observed
usage counters, spend-cap rights, device roster, and (only when the user shares
one) a sealed credential — peer-to-peer between one developer's own paired
devices, with no Tethra server, relay or cloud
([ADR 0031](../decisions/0031-device-mesh.md),
[ADR 0032](../decisions/0032-spend-caps.md),
[ADR 0033](../decisions/0033-credential-sharing.md)). It was built in twelve
increments (`increments/STATUS.md`), each committed, pushed and CI-checked.

## What changed

| Area | Where |
|---|---|
| Protocol, CRDTs, views, sessions (sans-IO) | `crates/core/src/mesh/` (`codec`, `sign`, `hlc`, `crdt/*`, `views`, `proto`, `chain`) |
| Storage, identity, marker, membership | `crates/core/src/mesh/{sqlite_store,identity,marker,membership}.rs`; migrations v21-v24 in `crates/core/src/db.rs` |
| Shared projects, usage publishing | `crates/core/src/mesh/{projects,publish,usage}.rs` |
| Spend caps | `crates/core/src/mesh/caps/`; gateway gate `crates/gateway/src/capgate.rs` |
| Credential sharing | `crates/core/src/mesh/share.rs`, `crates/core/src/vault/mesh_share.rs` |
| Transport and node | `crates/mesh/` (`wire`, `noise`, `handshake`, `pair`, `session`, `serve`, `runtime`, `discover`, `supervisor`) |
| Simulator and independent oracle | `crates/core/src/mesh/sim/` (feature `mesh-sim`), `crates/core/tests/mesh_sim.rs` |
| CLI | `apps/cli/src/mesh_cmd.rs`, `mesh_cap_cmd.rs`, `mesh_share_cmd.rs` |
| Desktop | `apps/desktop/src-tauri/src/mesh_*cmds.rs`; `DevicesView.tsx`, `Mesh*.tsx`, `CapsPanel.tsx` |
| Docs | `docs/mesh/` (ARCHITECTURE, PROTOCOL, THREAT_MODEL, SECURITY_INVARIANTS, KNOWN_LIMITATIONS, TEST_PLAN, USER_GUIDE, audit/) |

## Independent audit and remediation (Increment 12)

Four auditors (protocol and crypto, persistence and identity, caps and
gateway, claims/UX/leakage) reviewed `5ec8198..fb55b07` read-only:
**48 findings, 41 confirmed, 7 accepted, 0 rejected**
([`audit/2026-11-03/FINDINGS_INDEX.md`](audit/2026-11-03/FINDINGS_INDEX.md),
`findings.json`). Every confirmed finding is fixed with a test that failed
first (`audit/2026-11-03/evidence/<id>_baseline_fail.log.txt`; for
documentation findings, the stale text). The fixes are four commits, one per
track: `bd49ebf` (MP-), `0b569ae` (MI-), `e2999b7` (MC-), `9e1eaf6` (MD-,
MC-12), and a follow-up for what verification reopened. A fresh verification
agent re-checked them
([`audit/2026-11-03/FINAL_VERDICT.md`](audit/2026-11-03/FINAL_VERDICT.md)).

The high-severity ones: a removed device could cancel its own removal (MP-1);
a failed multi-block write locked a device's identity for good, and `leave`
could not recover it (MI-1, MI-2); a cold gateway admitted unbounded
concurrency (MC-1); a burn awaiting the gateway's acknowledgement was burned
again (MC-2).

One decision was narrowed during remediation and is recorded: MP-2's "fork
evidence needs two signed items" was not adopted (it would hide real forks in
superseded history, and any member's `fork.report` already counts); the
residual is in KNOWN_LIMITATIONS.

## Local validation — measured on this branch

Darwin 25.5.0 arm64, 2026-11-05, on the remediated head:

```text
cargo fmt --all -- --check                                          PASS
cargo clippy (core, cli, observe, gateway, tracking, mesh) -D warnings, 1.96   PASS
cargo +1.99.1 clippy (same packages, CI's newer stable) -D warnings PASS
cargo clippy -p api-tracker-desktop -D warnings                     PASS
API_TRACKER_INSECURE_FAST_KDF=1 cargo test --no-fail-fast \
  -p api-tracker-core -p api-tracker-cli -p api-tracker-observe \
  -p api-tracker-gateway -p api-tracker-tracking -p api-tracker-mesh  PASS 1 923 passed / 0 failed / 14 ignored
bash scripts/smoke.sh                                               PASS 186 passed / 0 failed
(apps/desktop) npm ci, format:check, lint, typecheck                PASS
(apps/desktop) npm test                                             PASS 413 passed / 38 files
(apps/desktop) npm run build                                        PASS
API_TRACKER_INSECURE_FAST_KDF=1 bash scripts/mutation_checks.sh <13 mesh mutants>  PASS 13 killed / 0 skipped / 0 survived
bash scripts/mesh_soak.sh --minutes 10 (protocol, release)          PASS 63 000 seeds x 3 000 steps / 0 failing
bash scripts/mesh_soak.sh --scenario caps --minutes 10 (release)    PASS 832 seeds (5000000-5000831) x 240 steps / 0 failing (the range that found seed 5000331 below; final invariant)
```

The first 10-minute caps soak on the remediated head failed one seed of 832,
**5000331**: the reclaim's new respect for a device's overrides (MC-6) left a
lower's remainder under an override, which the "lower settles" invariant did
not allow for. The policy is the documented one (ADR 0032 D4); the invariant
was corrected, the seed is a permanent regression test, and the consequence
is in KNOWN_LIMITATIONS ([`FINAL_VERDICT.md`](audit/2026-11-03/FINAL_VERDICT.md)).

Earlier, Phase A: protocol soak 481 000 seeds × 3 000 steps in 30 min, 0
failing; caps soak 3 136 seeds, 2 failing (a real policy bug, fixed in
`d7accf6`, both seeds now regression tests), then 1 600 seeds, 0 failing.

## Not executed here, and why

- **Service-mode validation** (`scripts/gateway_validate_macos.sh`, the
  packaged LaunchAgent lifecycle). A live production gateway occupies the
  LaunchAgent slot on this machine and `launchctl` is not isolated by `$HOME`;
  CI's `packaged-service-macos` job runs it.
- **LAN binds and real mDNS.** Every test and manual run binds `127.0.0.1:0`;
  discovery is exercised through an in-memory fake (no test constructs the
  real mDNS discovery).
- **Windows end to end.** CI runs core and mesh tests on Windows; the desktop
  app and the gateway's Windows probe are not exercised there.
- **Real providers.** All usage is seeded or produced by a mock upstream.

## CI on the final head

Head `92e5530` (the last commit with code; the record commit after it
changes docs only):

| Workflow | Run | Result |
|---|---|---|
| CI (Rust core+CLI+mesh on Linux, Rust core+mesh on Windows, desktop frontend, desktop backend, packaged app on macOS) | `42154484846` | success |
| Packaged macOS service lifecycle | `42154484849` | success |

Earlier remediation heads: `9e1eaf6` CI `42113513995`, service
`42113514032`; `6a279d4` CI `42113920148`, service `42113919915`;
`24eb4a4` CI `42121555608`, service `42121555601` (all success). The record commit's own runs are listed in `increments/STATUS.md`.

## Please look hardest at

1. **Roster resolution and admission** (`crates/core/src/mesh/crdt/roster.rs`,
   PROTOCOL §6): every removal, fork and cutoff rule (the cutoff is now the
   minimum, MP-1); this is what decides who may write.
2. **The marker floor** (`marker.rs`, `sqlite_store.rs` `MarkerState`,
   `raise_marker_floor`, MI-1): a mistake here either locks honest devices
   out or lets a rolled-back database reuse seqs.
3. **The gate's admission** (`crates/gateway/src/capgate.rs` `admit_with`,
   MC-1/MC-5): concurrency, reservations and the serialized 403.
4. **The pending decrease and burns** (`caps/view.rs` `pending_decrease`,
   `caps/reconcile.rs` `burn_after_lower`, MC-2/MC-3/MC-6).
5. **Sealed-share bindings and revocation** (`mesh/share.rs`,
   `views.rs` `share_at`/`share_revoked_by`, MP-10).
6. **Handshake candidates** (`crates/mesh/src/handshake.rs`, `session.rs`
   `exchange_with`, MP-7): the session's peer is resolved by the Hello among
   the devices sharing a Noise key.

## Residual risks (accepted or by design)

From [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md):

- every paired device reads everything that replicates; a compromised device
  of yours can remove your other devices, report any device forked, pin a
  last-writer-wins value with a far-future timestamp (MP-6), and grind the
  access key's tie-break (MP-8);
- spend-cap overshoot is limited, not zero; caps are a self-limit; the
  gateway probe sits outside the write transaction (MC-9); the 403 drain can
  hold a connection thread up to 5 s (MC-11);
- the shown invite passes through ordinary strings (MD-15); a stale Unix
  socket can race a single-instance claim (MI-6); fork evidence can be
  reported one exchange late (MI-7);
- no NAT traversal or relay; no background service; no forward secrecy for
  shared credentials.

## Recommended next milestone

A background node service consistent with ADR 0020 (so devices converge
without the app or `serve` running), then multi-user meshes or a read-only
mobile client.
