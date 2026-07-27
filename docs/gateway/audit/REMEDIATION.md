# Local Gateway — final-audit remediation report

Remediation of the final independent audit of `feat/local-gateway`.

| Field | Value |
| --- | --- |
| Audited base commit | `ae66ca7` |
| Audit branch (immutable, not modified) | `audit/lg-final-independent-20260726` |
| Audit's proposed remediation commit | `17ef76a` (reviewed, partially adopted — see below) |
| Audit verdict | `LOCAL GATEWAY READY TO MERGE: NO` |
| Remediation commits | `f202193`, `7ec7289`, `b348084`, `45390f0`, `d78f740`, and the documentation commit carrying this file |
| PR | #15, **open and unmerged** |

**This branch still requires a fresh independent re-audit.** Nothing in this
document is a merge recommendation. See `RE_AUDIT_HANDOFF.md`.

## How the audit's own proposal was treated

Commit `17ef76a` on the audit branch proposed a fix for the blocker. It was
read and reproduced, not applied blind. Its diagnosis was correct and its
three regression tests were the right shape. Two things were done differently:

1. **The policy lives in the service, not in a helper the frontends call.**
   `17ef76a` put `control::revoke_key_on_lock` in the gateway crate and called
   it from three desktop lock paths. That leaves the decision in the caller: a
   fourth lock path (or a second frontend) that forgets to call it silently
   recreates the defect. Here the frontends send a `VaultLocked` signal and the
   SERVICE decides (`service::lock_disposition`), and `ControlTarget::vault_locked`
   is a required trait method — a target that ignores a lock does not compile.
2. **More lock paths.** `17ef76a` covered explicit lock and the two auto-lock
   paths. Backup restore (which drops the session) and app exit (`RunEvent::Exit`)
   also end a vault session and also left the key resident; both now signal.
   The CLI's `vault lock` does too.

The audit's 16-category black-box attack battery was adopted essentially
unchanged as `crates/gateway/tests/adversarial_blackbox.rs`.

## Findings matrix

Severities are the audit's. Dispositions: FIXED, DOCUMENTATION CORRECTED,
TEST CORRECTED, ACCEPTED RISK, NOT REPRODUCED, DUPLICATE.

Every finding below was reproduced against `ae66ca7` before any code changed.
None failed to reproduce. Two carried qualifications, recorded in place.

### Blocker

| ID | Claim | Repro | Root cause | Disposition | Code | Test | Docs | Residual | Commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| matching-key-survives-vault-lock (+ 3 duplicates: `matching-key-lifecycle-claims-false`, `consent-key-drop-on-lock-false`, `match-while-locked-toggle-does-not-exist`) | The vault-derived matching key is never dropped on lock, though SI-9, ADR 0019 D5, THREAT_MODEL GW-6 and the push-key consent dialog all promise it is; `match_while_locked` has no consumer; no TTL | YES — `set_matching_key(None)` had exactly three callers (push, revoke, graceful stop), none reachable from any lock path | The designed lifecycle was never wired up; the toggle was schema-only | FIXED | `control.rs` (`VaultLocked`/`VaultUnlocked`, required trait method), `service.rs` (`lock_disposition`, `KeyRetention`, poller enforcement), desktop (5 lock paths + unlock), CLI (`vault lock`/`unlock`, `gateway match-while-locked`), UI toggle + countdown | 11 in `tests/control.rs`, 1 mutation-checked; 4 frontend | ADR 0020 (new), SI-9, THREAT_MODEL GW-6, TEST_PLAN §5, consent copy | Abrupt termination leaves the key resident (no signal handler); disclosed, not mitigated | `f202193` |

### High

| ID | Claim | Repro | Root cause | Disposition | Code | Test | Docs | Residual | Commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| custom-origin-routes-never-forward | `RouteState::set_mac_key` has no callers, so every custom-origin route is permanently 503 — and the 503 tells the user to do something that cannot help | YES — grep returns only the definition | The verification key had no delivery path | FIXED | `PushRouteKey`/`RevokeRouteKey`; installed on route add, unlock, route enable, `serve`; `route_key_exists` gate so no key is minted as a side effect | 13 in `tests/custom_routes.rs` (end to end through a real listener) | ADR 0021 (new) | A restart still needs a session to reinstall the key (documented outage window) | `7ec7289` |
| var-override-secret-unmasked-and-plaintext | `--var` prints the prior secret unmasked and stores it in plaintext | YES — allowlist applied to both diff sides; `prior_env_json` is a plaintext column | The "base URLs are non-secret" assumption does not survive an arbitrary `--var` | FIXED | Unmask ADDED lines only; withhold non-configuration prior values from the record | 2 envgov, 2 envlink (canary-based) | PRIVACY, link warnings | A withheld prior cannot be auto-restored; reported honestly at link and unlink | `b348084` |
| filemissing-destroys-restore-record | A missing `.env` at unlink deletes the link row and the only copy of the prior values | YES — `Path::exists()` is false for ANY stat error | Conflated "deleted" with "not readable right now" | FIXED | Only `NotFound` is terminal; other errors keep the row; symlink refused | 1 envlink (symlink) | — | A genuinely deleted file still ends the link (correct) | `b348084` |
| macos-upgrade-never-swaps-running-service | Install/repair never restarts a running service; launchd keeps the stale job spec and prune deletes its binary | YES — `bootstrap` swallows already-loaded; `kickstart` without `-k` | Registration assumed a rewritten plist would be re-read | FIXED | `register` boots out then re-bootstraps; install restarts when running; `start` re-bootstraps after a bootout | 3 lifecycle | — | Not executed on real launchd since the fix (see platform honesty) | `b348084` |
| privacy-doc-deletion-claim-false | PRIVACY.md claims delete-all covers gateway records; three gateway tables have no deletion path | YES — only the retention sweep touched them | The tables were added without extending the deletion set | FIXED | All three in `delete_all`; the two project-scoped ones in `delete_project_data` | 2 core (both assert rows existed first) | PRIVACY, PRIVACY_MODEL, KNOWN_CONFLICTS, ADR 0019 | `gateway_route_counters` is route-scoped and clears only with delete-all; stated | `b348084` |

### Medium

| ID | Repro | Disposition | What changed | Commit |
| --- | --- | --- | --- | --- |
| systemd-unit-no-escaping | YES | FIXED | `systemd_escape`/`systemd_unescape`; `%`, `"`, `\`, control chars | `45390f0` |
| self-exit-single-exists-sample | YES | FIXED | 3 consecutive confirmations before the terminal self-unload | `45390f0` |
| macos-start-cannot-bootstrap | YES | FIXED | `start` re-bootstraps after a bootout-based stop | `b348084` |
| sanitize-collapses-preview-diff | YES | FIXED | Per-line sanitization; the consent diff is readable again | `b348084` |
| duplicate-key-restore-not-exact | YES | FIXED | `prior_all` + `set_each_occurrence`; each occurrence restores its own value | `b348084` |
| restore-replaces-symlink | YES | FIXED | Restore refuses a symlink, matching link-time policy | `b348084` |
| writer-stop-unbounded-join | YES | FIXED | `finished` flag + 15 s bounded join; `stop` returns false on timeout | `45390f0` |
| windows-crashed-session-never-closed | YES | FIXED | Shared sweep body + Windows `tasklist` probe (fail-safe) | `45390f0` |
| stale-doctor-report-rendered-as-current | YES | FIXED | Explicit STALE banner with an as-of time | `45390f0` |
| concurrent-first-run-start-clobbers-nonce | YES | FIXED | Socket claim taken before any shared file is written; cleanup gated on ownership | `45390f0` |
| token-count-wrapping-cast | YES | FIXED | `clamp_i64` at all five persistence sites | `45390f0` |
| missing-fk-index-gue-event-id | YES | FIXED | Migration v14 | `b348084` |
| data-dir-not-resolved-absolute | YES | FIXED | `std::path::absolute` at both entry points | `45390f0` |
| canary-db-scan-vacuous | YES | TEST CORRECTED | New real-persistence canary (mutation-checked); the old test now states its scope | `d78f740` |
| per-tool-coverage-note-missing | YES | DOCUMENTATION CORRECTED | PRODUCT_BEHAVIOR narrowed to the Node-only heuristic that ships; COVERAGE_LIMITATIONS lists what is not detected | docs |
| threat-model-sigterm-handler-false | YES | DOCUMENTATION CORRECTED | GW-6 distinguishes graceful stop from SIGTERM/SIGINT/SIGKILL/crash/shutdown | docs |
| threat-model-auto-disable-nonexistent | YES | DOCUMENTATION CORRECTED | GW-7 states no auto-disable exists, why it is not being added, and that an enabled route is a standing exposure | docs |
| si21-peercred-never-corrected | YES | DOCUMENTATION CORRECTED | SI-21 states filesystem permissions re-checked per accept; the non-existent "peer-cred tests" citation removed | docs |
| docs-claim-observe-reuse-but-both-are-forked | YES | DOCUMENTATION CORRECTED | ARCHITECTURE gains a "Forked from observe, with reasons" section | docs |
| route-mac-omits-route-prefix-transplant | YES | FIXED | MAC v2 binds `route_prefix` | `7ec7289` |
| route-list-always-reports-custom-routes-unavailable | YES | FIXED | Both frontends verify with the real key when a session exists, and say "unverifiable from here" otherwise | `7ec7289` |

### Low

| ID | Repro | Disposition | Note | Commit |
| --- | --- | --- | --- | --- |
| pushkey-debug-prints-key-hex | YES | FIXED | Manual `Debug`; key and nonce redacted; asserted | `f202193` |
| nonce-does-not-authenticate-server | YES | DOCUMENTATION CORRECTED | Module doc states what the nonce does and does not do | `f202193` |
| accept-recheck-is-file-mode-not-peer | YES | DOCUMENTATION CORRECTED | Same correction as SI-21 | `f202193` |
| unavailable-vault-locked-label-when-unlocked | YES | FIXED | Renamed to `unavailable_no_key` (enum, label, docs) | `45390f0` |
| queue-depth-omits-counter-messages | YES | FIXED | Counter messages counted and released | `45390f0` |
| disk-full-indistinguishable-from-busy | YES | FIXED | `db_full`/`db_busy`/`db_corrupt`/`db_readonly` | `45390f0` |
| boot-orphan-sweep-one-shot | YES | FIXED | Retried from maintenance until it succeeds once | `45390f0` |
| store-module-doc-false-write-claim | YES | DOCUMENTATION CORRECTED | Module doc + ARCHITECTURE + ADR 0019 amendment | `45390f0` |
| chunk-trailers-bypass-response-head-sanitization | YES | FIXED | Trailers filtered through the head predicate; test added | `45390f0` |
| expect-100-continue-silent-upstream-deadlocks-a-waiting-client | YES | FIXED | Interim synthesized per RFC 9110 §10.1.1; new test withholds the body | `45390f0` |
| partial-body-forwarded-before-chunk-framing-rejection | YES | DOCUMENTATION CORRECTED | Error text no longer claims "was not forwarded" | `45390f0` |
| dry-run-writes-db-when-no-change | YES | FIXED | `--dry-run` returns before any write | `b348084` |
| windows-trailing-backslash-run-value | YES | FIXED | `quote_safe_path` strips trailing separators | `45390f0` |
| custom-origin-port-not-revalidated-at-load | YES | FIXED | The stored port is re-validated; test added | `7ec7289` |
| threat-model-pid-identity-stale | YES | DOCUMENTATION CORRECTED | GW-4 names the random persisted port and the nonce probe | docs |
| gateway-arch-windows-enable-stale | YES | DOCUMENTATION CORRECTED | ARCHITECTURE + TEST_PLAN + ADR 0019 amendment | docs |
| spike-not-deleted-divergent-lockfile | YES | FIXED | `experiments/gateway-spike` deleted | `45390f0` |
| stale-skeptic-repro-test | YES | FIXED | `zz_skeptic_overflow_repro.rs` deleted (asserted nothing; premises gone) | `45390f0` |
| activity-summary-mixed-windows | YES | ACCEPTED RISK | The event window is an instant, the usage window a calendar day, so usage tiles can cover up to 24 h more than the request tiles beside them. Not fixed: changing the daily rollup's granularity would break the 90-day spend series the tiles exist to show. Recorded in COVERAGE_LIMITATIONS as a labelling limitation. | — |
| zeroizing-carryover-voided-by-plain-copies | YES | ACCEPTED RISK | Carryover bytes transit plain `Vec`s between `Zeroizing` wrappers. Threading `Zeroizing` through the relay signatures would touch the smuggling-critical path for a best-effort property SI-7 already labels best-effort. Residual: carryover bytes may persist in freed memory. | — |
| keepalive-head-deadline-is-120s | YES | DOCUMENTATION CORRECTED | The comment claimed the head deadline re-arms once bytes arrive; it does not. Behavior unchanged (a kept-alive connection legitimately idles longer); the comment now matches. | `45390f0` |
| observe-run-breaks-gateway-linked-projects | PARTIAL | ACCEPTED RISK | Verified differently than reported: `NO_PROXY` covers loopback in both directions, so a conforming client does NOT fail — the gateway-routed traffic simply bypasses the observe session (zero observe coverage, no warning). Only a client honoring `HTTP_PROXY` while ignoring `NO_PROXY` hits the 403. Recorded in KNOWN_CONFLICTS C10, which already conceded the composition is untested. | — |
| audit-says-pushed-when-push-may-fail | YES | ACCEPTED RISK | `gateway_matching_key_pushed` is recorded at key-read time, before the push can fail. The audit event is the RELEASE of key material from the vault, which is the security-relevant act and does happen. Renaming it would break existing audit-log consumers for a naming improvement. | — |
| consent-file-list-behind-optional-expander | YES | ACCEPTED RISK | The file list sits behind "Learn more"; the confirmation dialog names the login service and the loopback exposure. Moving the full list into the primary card was judged to bury the decision in detail. Revisit with user feedback. | — |
| confirm-dialog-a11y | YES | ACCEPTED RISK | `<dialog open>` is non-modal: no focus trap, no Esc, no `aria-modal`. A real accessibility defect, but it is repo-wide (every confirmation surface), not gateway-specific, and fixing it here would leave the rest inconsistent. Tracked for a dedicated a11y pass. | — |
| query-borne-credential-mislabeled | YES | DOCUMENTATION CORRECTED | Comments claimed query/cookie credentials yield `unsupported_form`; they yield `no_credential_present` because only the four credential headers are inspected. Comments corrected; behavior unchanged. | `45390f0` |

### The five findings the audit could not verify (verified here)

The audit reported five low findings that hit a per-lens verification cap and
were **not** adversarially checked by any reviewer. They were verified during
remediation. **This is remediation-time verification, not independent audit
verification** — a fresh reviewer should treat them as unconfirmed by the
original audit.

| ID | Verified here? | Disposition | Commit |
| --- | --- | --- | --- |
| created-file-never-deleted-on-restore | YES, reproduces — `PriorFile.existed` was written once and never read | FIXED: a link-created `.env` with nothing else in it is removed on restore; one the user added to is kept. 2 tests | `b348084` |
| prior-env-version-unchecked | YES, reproduces — `prior.v` deserialized, never compared | FIXED: a record from a newer build is refused rather than half-restored. 1 test | `b348084` |
| leftover-temporary-skeptic-test | YES, reproduces — both tests end in a captured `eprintln!` and assert nothing | FIXED: deleted | `45390f0` |
| top-architecture-md-not-updated | YES, reproduces — `crates/observe` and `crates/gateway` absent from the workspace diagram; migration list stops at v10 while the schema is v14; heading said "schema v5" | DOCUMENTATION CORRECTED | docs |
| sse-test-name-claims-a-latency-bound-it-never-asserts | YES, reproduces — the test computes `first_event` and compares it to nothing | TEST CORRECTED: renamed to what it asserts | `45390f0` |

### The refuted finding

`transfer-encoding-regenerated-onto-bodyless-keepalive-responses` was refuted
by the audit itself with RFC citations. Re-checked and agreed: RFC 9112 §6.1
permits `Transfer-Encoding` on a response to HEAD and on a 304, §6.3 rule 1
makes those responses bodyless regardless of headers, the guard at
`head.rs` excludes exactly the 1xx/204 cases the RFC forbids, and the gateway
never injects the header — it re-emits only what a validated upstream head
carried. **No change made.** The auditor's observation that no test covers the
chunked-framed HEAD/304 case remains true and is not a defect.

## What is NOT fixed, and why

Every item above dispositioned ACCEPTED RISK is repeated here so it is visible
in one place:

1. **Activity summary mixes window granularities** — usage tiles cover whole
   calendar days, request tiles cover an exact instant.
2. **Zeroizing carryover passes through plain allocations** — best-effort
   zeroization, as SI-7 already labels it.
3. **`tethra run --observe` over a gateway-linked project** silently produces
   zero observe coverage rather than an error, with no warning at either
   surface.
4. **`gateway_matching_key_pushed`** is recorded when the key is released from
   the vault, not when the push succeeds.
5. **The consent file list is behind "Learn more"**, not in the primary card.
6. **Confirmation dialogs are non-modal** and lack focus management and Esc —
   repo-wide, not gateway-specific.

None of these is a false security claim: each is now described accurately in
the document a reader would consult.

## Validation run for this remediation

```
cargo fmt --all --check                                  clean
cargo clippy --workspace --all-targets -- -D warnings    clean
cargo test --workspace                                   936 passed, 0 failed
  of which crates/gateway                                263 passed, 0 failed
cargo build --workspace --release                        ok
npm ci / prettier --check / eslint / tsc --noEmit         clean
vitest run                                               41 passed (9 files)
```

Not run here, and not claimed: packaged macOS validation (the corrected script
has not been executed on macOS hardware since the corrections), and any
runtime validation on Linux or Windows.
