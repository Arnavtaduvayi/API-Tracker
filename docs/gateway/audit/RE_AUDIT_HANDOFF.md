# Fresh independent re-audit — handoff

**The Local Gateway is NOT approved for merge. PR #15 is open and unmerged,
and must stay that way until an independent reviewer who did not perform this
remediation reaches their own verdict.**

Use a **fresh session** and a **fresh worktree**. Do not trust anything in this
document, in `REMEDIATION.md`, or in any commit message without reproducing it.
The previous audit found that the branch's own documents asserted mitigations
that did not exist; the correct posture toward this remediation's documents is
the same one that audit took toward the originals.

## State to audit

| Field | Value |
| --- | --- |
| Base commit previously audited | `ae66ca7` |
| Original audit branch (immutable — do not modify) | `audit/lg-final-independent-20260726` |
| Original remediation proposal commit | `17ef76a` (on the audit branch only) |
| Original verdict | `LOCAL GATEWAY READY TO MERGE: NO` |
| New implementation head | see `git rev-parse origin/feat/local-gateway` |
| Branch | `feat/local-gateway` |
| PR | #15 — **open, unmerged** |
| Remediation commits | `f202193`, `7ec7289`, `b348084`, `45390f0`, `d78f740`, plus the documentation commit |
| CI status | recorded in `HANDOFF_PHASE_5.md`; re-check it yourself against the head you audit |

## Decisions made during remediation that need independent judgement

These are the places where remediation exercised discretion. They are the
highest-value things to disagree with.

### 1. Matching-key lifecycle (ADR 0020)

Policy lives in `service::lock_disposition`, not in the frontends;
`ControlTarget::vault_locked` is a required trait method so a target cannot
silently ignore a lock. Default is drop-on-lock; the consented, default-OFF
`match_while_locked` toggle buys bounded retention.

**The TTL is a product decision, not a derived one.** Retention is the locking
session's `auto_lock_minutes`, hard-capped at 8 hours. The reasoning is in ADR
0020 under "Why 8 hours" and is explicitly not a security proof. If you think
the cap is wrong, that is a legitimate finding — the number is asserted in a
test that says so.

Verify at minimum: manual lock, both desktop auto-lock paths, backup restore,
app exit, CLI lock; unreadable/malformed/missing config; restart with the
toggle ON; whether the frontends can reach a lock path that does not signal.

### 2. Custom-route verification key (ADR 0021)

The key is installed on route add, unlock, route enable, and foreground
`serve`, and is **NOT dropped on vault lock** — deliberately, because dropping
it would stop forwarding for custom routes and break forward-while-locked.
The matching key IS dropped on lock. These two opposite rules for two
vault-derived keys are the thing to scrutinise.

Also judge: the key is symmetric, so anyone who can read gateway memory can
MINT a route MAC, not merely verify one. ADR 0021 states this and argues it is
acceptable because that attacker is same-uid and out of scope. An asymmetric
scheme was rejected on dependency grounds. Disagree if you think the cost is
worth paying.

MAC v2 binds `route_prefix`; v1 MACs fail closed. The claim that no migration
is needed rests on custom routes never having worked in any build — check that.

### 3. Findings dispositioned ACCEPTED RISK

Six, listed together in `REMEDIATION.md` under "What is NOT fixed, and why".
Each should be challenged on whether acceptance is reasonable AND whether the
product claim around it is now honest.

### 4. Findings the original audit never verified

Five low findings hit a per-lens cap and were never adversarially checked.
They were verified during remediation — by the party doing the remediation,
which is not the same thing. They are listed in `REMEDIATION.md` and flagged
there. Treat them as unconfirmed.

## Claims implemented vs. removed

**Implemented** (were false, now true and tested): drop-on-lock for the
matching key; enforcement of `match_while_locked`; a matching-key TTL;
fail-toward-revocation on unreadable config; custom-route usability;
route-prefix binding in the MAC; load-time port re-validation; gateway-table
deletion coverage; trailer sanitization; encoded-traversal rejection.

**Removed or narrowed** (were false, now stated accurately rather than
implemented): SIGTERM key clearing (no signal handler exists); automatic
disabling of unused routes (does not exist, deliberately not added);
`SO_PEERCRED` peer-credential enforcement (filesystem permissions instead);
the per-tool link coverage note (Node-only heuristic ships); "the service only
READS" (it writes counters and usage rows); "uninstall deletes every gateway
table" (uninstall keeps history by design); "observe::wire and observe::relay
reused unchanged" (both forked); GW-4's fixed port and PID+path identity check.

For each removed claim, the question to ask is whether removal was the right
call or whether the mitigation should have been built.

## Platform honesty — check this specifically

| Platform | What has actually been executed |
| --- | --- |
| macOS | Unit/integration tests locally. Packaged lifecycle: the recorded run in `PACKAGED_MACOS_RESULTS.md` PREDATES the validation-script corrections and has NOT been re-executed. That document is marked superseded. |
| Linux | Compiled and tested in CI only. No packaged lifecycle validation ever. |
| Windows | Compiled and tested in CI only. The HKCU `Run` path has never run on a real login session. |

"Compiled and tested in CI" and "packaged lifecycle validated" are different
claims and are kept distinct throughout. Verify no document conflates them.

## Files deserving special attention

| File | Why |
| --- | --- |
| `crates/gateway/src/service.rs` | `lock_disposition`, `KeyRetention` (dual-clock expiry), poller enforcement, the socket claim ordering in `start` |
| `crates/gateway/src/control.rs` | New request variants, the required trait method, manual `Debug`, the claim/serve split |
| `crates/gateway/src/routes.rs` | MAC v2, load-time port re-validation, `route_key_exists` |
| `apps/desktop/src-tauri/src/main.rs` | Five lock paths + unlock; the `RunEvent::Exit` handler; route-key installation |
| `apps/cli/src/gateway_cmd.rs`, `vault_cmd.rs` | `install_route_key` gating, lock/unlock signalling, `--dry-run` ordering |
| `crates/gateway/src/envlink.rs` | Prior-value withholding, `prior_all`, symlink refusal, version check, created-file removal |
| `crates/gateway/src/stream.rs` | Trailer filtering and the terminating-CRLF handling |
| `crates/gateway/src/forward.rs` | Traversal gate, synthesized `100 Continue` |
| `scripts/gateway_validate_macos.sh` | Whether any check can still pass vacuously |
| `crates/gateway/tests/privacy_canaries.rs` | Whether the new canary really exercises the persistence path |
| `crates/gateway/tests/adversarial_blackbox.rs` | Whether the adopted battery was weakened |

## Specific things to try to break

1. Find a lock path that does not signal, or a `ControlTarget` that ignores one.
2. Make the retention window outlive its cap (sleep, clock changes, repeated
   lock signals, a re-push during a window).
3. Make a restart resurrect either key.
4. Make a custom route forward to an origin its MAC does not cover.
5. Make the gateway act as an open relay — the 16-category battery is a
   starting point, not a ceiling.
6. Make a canary reach disk (the mutation that proves the canary works is
   described in `REMEDIATION.md`; find one it misses).
7. Make `gateway_validate_macos.sh` report success while the gateway does
   nothing.
8. Find a claim in any document that the code does not support. That is the
   failure mode this branch has had twice.

## Exact commands run during remediation

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p api-tracker-gateway
cargo build --workspace --release
bash scripts/smoke.sh
cd apps/desktop && npm ci && npx prettier --check "src/**/*.{ts,tsx}" \
  && npx eslint src && npx tsc --noEmit && npx vitest run
```

Results are in `HANDOFF_PHASE_5.md`. Re-run them; do not take the numbers on
trust.

## Not done here, on purpose

The final independent re-audit itself. The party that wrote this remediation
must not also certify it.
