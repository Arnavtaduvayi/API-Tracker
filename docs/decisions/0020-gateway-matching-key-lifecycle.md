# ADR 0020: Gateway matching-key lifecycle — drop on lock, bounded retention when consented

Status: accepted (2026-07-26). Amends ADR 0019 D5. Supersedes nothing.

ADR 0019 D5 designed the gateway's vault-derived matching key to be "dropped on lock, default OFF while locked, TTL-bounded residency" — and made that the condition on which holding vault-derived material in a long-lived process was acceptable at all. The final independent audit of `feat/local-gateway` (branch `audit/lg-final-independent-20260726`, base `ae66ca7`) found that none of the three was implemented: no lock path revoked the key, `gateway_config.match_while_locked` was a stored column with no consumer anywhere in the tree, and no TTL existed. Meanwhile the push-key consent dialog told the user "The key is dropped on stop, revoke, or lock (keep-while-locked defaults OFF)."

This ADR records the lifecycle that is now implemented, and — the part ADR 0019 deferred and the audit correctly declined to invent — the TTL decision.

## The threat being mitigated

The matching key is the ADR 0005 keyed-fingerprint key. It cannot decrypt anything. What it can do is confirm guesses: given a candidate credential value, it produces the fingerprint that would be stored, so anyone holding both the key and the vault database gains an offline oracle over every in-scope fingerprint (THREAT_MODEL GW-6). Three properties make its residency the sharp edge:

- **Lifetime.** A header carrying a credential is in gateway memory for microseconds. The key, in a `KeepAlive` login service, is resident for as long as the process lives — weeks — and the process deliberately outlives the desktop app and every CLI session.
- **Scope.** The key confirms *any* value against *all* in-scope fingerprints, not merely values the gateway happened to observe.
- **Capability change.** It converts a stolen database from inert ciphertext into a testable oracle.

The vault's own auto-lock exists because a user who walks away should not leave decrypted capability resident. A matching key that ignores the lock silently defeats that decision for the one capability that outlives every other process.

## The user value on the other side

Attribution is why the key is pushed at all: without it every exchange records `unavailable_no_key` and the user sees traffic they cannot attribute to a credential. A user whose vault auto-locks after 15 minutes but whose linked project runs all afternoon has a real reason to want matching to continue. Refusing that outright would push users toward disabling auto-lock entirely — strictly worse for the vault as a whole.

## Selected policy

**Default (`match_while_locked` OFF): every lock event revokes the key immediately.**

**Consented opt-out (`match_while_locked` ON): the key is retained after a lock for the locking session's `auto_lock_minutes`, clamped to a hard cap of 8 hours (`service::MATCH_WHILE_LOCKED_TTL_CAP_MINUTES = 480`), then revoked. Retention is never indefinite.**

### Why a TTL at all (Option B over Option A)

Option A — no TTL, retain indefinitely whenever the user consented — was rejected. The consent it relies on is given once, at a moment when the user is present and thinking about attribution; the exposure it grants is unbounded and accrues precisely when the user is *not* present. A machine left locked over a weekend would hold the oracle for 60+ hours on the strength of a checkbox ticked on Friday morning. ADR 0019 D5 already named TTL-bounding as a condition of accepting the key in a long-lived process, and nothing found during implementation argues against it.

### Why 8 hours

The cap is not the expected retention — it is the ceiling on a value the user already chose. In the common case the retention window is the user's own `auto_lock_minutes` (typically 5–60), which is the duration they have already judged acceptable for decrypted capability to sit idle. The cap binds in exactly two cases: auto-lock disabled (`0`), and a caller that could not read the setting.

8 hours is chosen as slightly longer than one working day at the keyboard and decisively shorter than an overnight or weekend absence. It means:

- A user who locks the vault and keeps working keeps attribution for the rest of the day.
- A user who closes the laptop on Friday does not return on Monday to a still-resident oracle.
- No plausible "I was only away for a moment" case is interrupted, so the setting does not train users to disable auto-lock to escape it.

The number is deliberately not derived from a security proof — there isn't one to be had. It is a product bound on a consented exposure, and it is recorded here so that changing it is a documented decision rather than a constant edit. The regression test `the_retention_request_is_clamped_to_the_documented_cap` asserts the value and says so.

### Rejected alternatives

- **Option A, no TTL.** Rejected above.
- **Retention keyed to a fixed short window (e.g. 15 min) regardless of the user's setting.** Rejected: it ignores the auto-lock duration the user already chose, and a user with a 60-minute auto-lock would find locked-vault matching stop sooner than their own unlocked idle timeout — surprising in the wrong direction.
- **Re-derive the key on demand from a cached password/KEK.** Rejected outright: it would put decryption-capable material in the gateway, which violates the immutable "the gateway holds no vault key material and forwards while locked" property (ADR 0019 D4).
- **Persist the key (wrapped) so a restarted service can resume attribution.** Rejected: it converts a memory-resident capability into an at-rest one and makes restart a silent re-authorization. See "Restart behavior".
- **Ask the user at lock time.** Rejected: the lock paths include two automatic ones and app exit, where no interactive prompt is possible or wanted.

## Lifecycle

The key exists in exactly one place: `Gateway::matching_key`, in the running service's memory. It reaches it only over the authenticated control channel (SI-21).

| Event | Effect |
| --- | --- |
| `PushKey` (reauth-gated, audited) | Key installed, scoped matcher loaded, any pending retention window cancelled, expiry marker cleared |
| Explicit revoke (`gateway revoke-key`, desktop button) | Key dropped, matcher dropped, window cancelled |
| Toggle `match_while_locked` OFF | Key dropped immediately (best-effort control call); does not wait for the next lock |
| Vault lock, toggle OFF (default) | Key dropped, matcher dropped |
| Vault lock, toggle ON | Window armed for `min(auto_lock_minutes, 480)` minutes; key retained until it expires |
| Repeated lock signals | Window may only be *tightened*, never extended — otherwise the desktop's 10-second status poll would refresh it forever |
| Window expiry | Key dropped by the service's own poller; status reports `matching_key_expired` |
| Vault unlock | Pending window cancelled (the key, if still resident, stays; an already-expired key stays gone until re-pushed) |
| Graceful stop (`Service::stop`) | Key dropped |
| SIGTERM / SIGKILL / crash / power loss | **No clearing occurs.** See THREAT_MODEL GW-6; this is a disclosed residual, not a mitigation |

The lock signal is `control::Request::VaultLocked { ttl_minutes }`. Every lock path sends it: the desktop's explicit `vault_lock`, both inactivity auto-lock paths (`with_vault_impl` and the `vault_status` poll), backup restore, app exit, and `tethra vault lock`. The frontends carry no policy — they report the event and the locking session's auto-lock duration, and `service::lock_disposition` decides. That is deliberate: policy in one place cannot drift between frontends, and `ControlTarget::vault_locked` is a required trait method, so a new target that forgets to handle it does not compile.

## Persistence rules

- The key is **never** written to disk in any form by the gateway. It exists in the vault (wrapped, as the fingerprint key) and in the running service's memory. Nothing else.
- The retention *deadline* is process memory only. It is not persisted, and a deadline cannot survive the process that armed it.
- `match_while_locked` is a plaintext row in `gateway_config` — a preference, not a capability. Reading it requires no vault, which is what lets the service apply the policy while locked.
- The deadline is tracked on both the monotonic and the wall clock and expires when **either** passes. A monotonic clock that pauses across system sleep and a wall clock set backwards would each otherwise silently stretch the window; taking the earlier of the two fails toward revocation.

## Restart behavior

**A restarted service never has a resident key**, regardless of the toggle. Nothing persists it, and the service reconstructs nothing at startup. Attribution is off — honestly labelled — until a vault session pushes the key again through the supported reauth-gated flow. This is asserted by `a_restarted_service_never_reconstructs_the_matching_key`, which runs with the toggle **ON** precisely because that is the case where a future implementer would be most tempted to add resumption.

Keep-while-locked bounds residency *within* a process. It is not a persistence feature and must never become one.

## Configuration-failure behavior

`lock_disposition` fails toward revocation. A database that cannot be opened, a schema at a different version, a missing config row, or a malformed one all yield `RevokeNow`. Retention happens only when the toggle is affirmatively readable and ON. Forwarding is unaffected by any of this — a failure to read the policy never stops the gateway serving.

## UI disclosure

- The push-key consent dialog states the drop-on-lock rule and, in the same breath, what enabling keep-while-locked would change.
- Enabling keep-while-locked is its own reauth-gated dialog that states the retained capability and the bound in plain words. Enabling it is not a passive checkbox flip.
- The Status panel shows the live countdown while a window is armed ("key drops in N min unless you unlock"), and distinguishes "expired — push again" from "never pushed".
- `tethra gateway match-while-locked on|off` prints the same facts.

## Tests

`crates/gateway/tests/control.rs`, all `#[cfg(unix)]` except the pure clamp test:

- `locking_the_vault_revokes_the_resident_matching_key_by_default` — the audited blocker. Mutation-checked: deleting the revoke in `ServiceControl::vault_locked` fails it.
- `forwarding_continues_after_the_lock_revokes_the_key` — SI-12's lock twin.
- `an_unreadable_policy_config_fails_toward_revoking_the_key` — missing DB, malformed DB, and default-OFF.
- `keep_while_locked_retains_the_key_within_a_bounded_window` — the opt-out is honored and bounded.
- `the_retention_request_is_clamped_to_the_documented_cap` — the cap, including `None` and `0`.
- `an_expired_keep_while_locked_window_drops_the_key` — the service enforces its own window.
- `unlocking_cancels_the_window_and_a_fresh_push_clears_the_expiry`.
- `a_restarted_service_never_reconstructs_the_matching_key`.
- `disabling_keep_while_locked_drops_the_resident_key_now`.
- `a_lock_with_no_resident_key_arms_nothing`.
- `repeated_lock_signals_never_extend_the_window`.
- `a_vault_lock_signal_reaches_the_target_with_its_ttl`, `a_vault_locked_request_without_a_ttl_field_parses` (wire compatibility), `debug_formatting_a_push_key_request_never_prints_the_key` — in `control.rs`'s unit tests.

## Security implications

The residency of a guess-confirmation oracle is now bounded in every configuration: by the lock event in the default, and by a documented cap under the consented opt-out. The exposure that remains is stated rather than mitigated:

- Abrupt termination (SIGKILL, crash, power loss) leaves whatever was in memory; no handler runs.
- The operating system may have paged the key to swap; the gateway cannot prove otherwise.
- A same-uid attacker who can read the gateway's memory while the key is resident has the oracle for that window. That adversary is out of scope repo-wide, and the window is now bounded rather than unbounded.

## Future limitations

The retention window is per-process and per-boot. A user who genuinely wants attribution across restarts must push the key again; there is no supported way to avoid that, by design. If a future version wants a longer or shorter cap, it changes here, in the consent copy, and in the test that asserts the number — all three, or the change does not ship.
