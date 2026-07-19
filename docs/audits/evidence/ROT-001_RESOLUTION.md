# ROT-001 (+ ROT-010) — Resolution (Phase 4)

**Model:** Fable 5 (`claude-fable-5`). **Baseline:** `7d81090`.
**Verdict:** CONFIRMED as a reliability + correctness defect, with a **refined characterization** — the raw title's "no exit path" is imprecise (rollback exits), but there is **no correct/safe exit** and the honest manual-completion path is unreachable. Evidence class: rigorous state-machine proof from source + provider capability matrix (deterministic; not timing-dependent). Executable end-to-end mock reproduction is listed as a recommended regression test (TEST_COVERAGE_GAPS).

## Scenario (Phase 4 spec)
Provider revoke/delete of the old key **succeeds**, but the network response is **lost or returns a transport/5xx error** (no crash). API Tracker records no confirmed revoke. On retry the provider answers **404** (key already gone).

## Mechanism (`crates/core/src/vault.rs`, `rotation.rs` @ 7d81090)

`rotation_revoke_old` (7219-7312) uses a durable marker to recover the crash window:
```
7244  attempted_before = rotation::events(id).last().detail.starts_with("attempting revocation of old key")
7248  record_event_note("attempting revocation of old key {old_key}")   // MARKER
7253  revoke_credential(...) =>
        Ok  => set old_revoked_at; Ok(true)                            // -> rotation_complete -> COMPLETED
        Err(NotFound) if attempted_before => "completed retry"; Ok(true)// crash-window recovery
        Err(NotFound)  => record_error("...wrong key id...nothing revoked"); Ok(false)  // stays OLD_DISABLED
        Err(e) => Err(e)                                                 // -> handler record_error; stays OLD_DISABLED
```

**The marker is fragile.** `attempted_before` is true **only if the last event IS the marker** (comment 7237-7243: "Only an attempt with NO recorded outcome counts — the crash window"). A **graceful** failed/lost response is a *recorded outcome*: the `Err(e)` arm (7279) → handler (7072) `record_error` appends a `"step failed (retryable)"` event; the `Err(NotFound)` arm (7266) itself calls `record_error` (7267). Either way the marker is **buried** — it is no longer `events().last()`.

Consequence on retry (key really gone → 404):
- `attempted_before` = false (last event is "step failed…", not the marker).
- 404 → the `Err(NotFound)` **without** attempted_before arm → `record_error("provider says key … does not exist — a wrong key id … would look exactly like this … nothing was marked revoked")` → `Ok(false)`.
- Handler `Ok(false) => return`: state **stays OLD_DISABLED**. Every subsequent `advance` repeats this. **`advance` can never reach COMPLETED.**

There is no failure counter that promotes OLD_DISABLED → MANUAL_REQUIRED; the only OLD_DISABLED→MANUAL_REQUIRED path is `rotation_revoke_old`'s `_` arm (7299), reached only when the provider has **no** programmatic revoke (GitHub/Stripe) — not for OpenAI/Supabase.

## Exit paths from OLD_DISABLED (all literal state guards — provable by inspection)
- `rotation_complete_manual` (7344-7347): allows only `MANUAL_REQUIRED | GRACE_PERIOD` → **rejects OLD_DISABLED**. The honest "I verified the old key is gone; mark complete" path is unreachable.
- `rotation_cancel` (7386-7396): rejects if `old_disabled_at` OR `old_revoked_at` set; and rejects if `new_version` set. A rotation in OLD_DISABLED always has a stored replacement (`new_version`) → **rejected**.
- `rotation_rollback` (7411-7562): `old_revoked_at` is **not** set (revoke never confirmed) → allowed; it **is** the only exit. But it restores the vault value and destinations to `old_version`. Re-enable of the old key is implemented **only for Anthropic** (7470-7480); for OpenAI/Supabase the old key was **permanently deleted**, so rollback redeploys a **dead** credential everywhere and lands in `ROLLED_BACK`, misrepresenting a clean rollback.

## Per-provider scope (from provider-manifests + connectors)
| Provider | disable | revoke | ROT-001 exposure |
|---|---|---|---|
| **OpenAI** | unsupported | implemented (permanent DELETE) | **Exposed.** `old_disabled_at` unset (no disable step). advance wedges; only exit is rollback → restores a deleted key. |
| **Supabase** | not implemented | implemented (permanent, new-format) | **Exposed.** Same shape as OpenAI. |
| **Anthropic** | implemented (soft) | implemented (soft, status=archived) | Exposed to the wedge, but rollback safely re-enables (status=active); soft-revoke is reversible-ish. |
| GitHub / Stripe | unsupported | manual_only | **Not exposed** — routed honestly to MANUAL_REQUIRED (7299), where complete_manual works. |

## Final finding record
- **ID:** ROT-001 (sibling: **ROT-010**, same root cause, opposite direction — when `attempted_before` IS true, a 404 is accepted as success (7260-7265), which can mark as "revoked" a key this rotation never actually revoked if it was gone for another reason).
- **Title:** A lost/failed revoke response (provider actually revoked) strands the rotation in `OLD_DISABLED`; `advance` cannot complete (buried crash-marker), `complete_manual`/`cancel` refuse the state, and the only exit — `rollback` — restores a permanently-deleted key (OpenAI/Supabase) and reports a clean rollback.
- **Category:** Reliability + correctness (credential-lifecycle workflow); unsafe recovery.
- **Severity:** Medium (original evidence: High). Impact: High for the rotation workflow (stuck state; unsafe rollback redeploys a dead key; no honest completion path). Likelihood: Moderate — a lost response / transport error coinciding with an actual provider-side revoke is a realistic network condition; deterministic once it occurs. No data loss, no secret exposure, no auth bypass → held at Medium; High is defensible.
- **Confidence:** High.
- **Affected symbols:** `rotation_revoke_old` (7219-7312), OLD_DISABLED handler (7057-7079), `rotation_complete_manual` (7336-7358 guard), `rotation_cancel` (7379-7396 guards), `rotation_rollback` (7411-7482 re-enable scope), `rotation::record_error`/`record_event` (rotation.rs 262-336).
- **Expected:** after a lost revoke response, the rotation can be driven to a correct terminal state (complete once revocation is confirmed/verified, or a safe manual path), without redeploying a dead key.
- **Actual:** wedged in OLD_DISABLED; only exit restores a deleted key and misreports success.
- **Existing defenses:** durable pre-call marker (works for hard crash only); conservative 404 handling (avoids false-success at the cost of false-stuck); rollback refuses once `old_revoked_at` set.
- **Recommended remediation (design only — NOT implemented):** (1) allow `rotation_complete_manual` from `OLD_DISABLED` (with an explicit "I verified the old key is gone" confirmation, ideally re-checking via `provider list-keys`); (2) make the OLD_DISABLED `advance` promote to `MANUAL_REQUIRED` after a recorded revoke attempt returns 404 (surface the manual verify+complete path) instead of re-erroring forever; (3) make the marker check "any recorded attempt for THIS revoke round" rather than strictly the last event, gated by a per-round attempt id, so a graceful lost-response is recoverable without converting an unrelated 404 to success; (4) have `rollback` refuse (or loudly warn) for OpenAI/Supabase when the old key is a permanent-delete provider and revoke may have occurred.
- **Regression test (gap):** mock `HttpClient` driving a rotation to OLD_DISABLED, first revoke returns transport error, retry returns 404 → assert the rotation reaches a correct terminal state and never silently redeploys a deleted key.
- **Verification provenance:** Fable 5 primary review — rigorous state-machine proof + provider capability matrix. Deterministic by inspection (state guards are literal allow-lists; marker burial is a deterministic consequence of event recording).
- **Related:** ROT-010, ROT-004 (destructive steps don't re-verify version), ROT-005 (rollback not retryable).
