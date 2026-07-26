# PR #13 — Source Review Ledger (independent verification)

Every audit finding was verified against the actual source before being fixed —
agent output was treated as a lead, not a verdict. This ledger records the
verification method and the cases where inspection changed the disposition.

## Method

For each finding I (a) read the cited code at the cited line, (b) traced the
data/control flow to confirm the failure is reachable, and (c) for the
highest-severity items wrote a failing test first where practical (e.g. the
plain-HTTP relay reversal was proven by a round-trip integration test that
would hang under the old code). SQL findings were confirmed by constructing the
exact NULL/empty-group condition in a unit test.

## Confirmations (representative)

- **H1 relay reversal** — `relay_body(src,dst,…)` signature confirmed in
  relay.rs; `intercept_https` (proxy.rs:600) uses `(upstream,client)` while
  `handle_plain` (proxy.rs:798) used `(client,upstream)` — definitively
  reversed. Fixed + integration test.
- **H3/H5/M13 NULL SUM** — `SUM(status_code=403)` over an all-NULL-status group
  returns NULL in SQLite; reproduced by a transport-error-only seed. The STRICT
  `NOT NULL` bucket columns and the `i64` row read both fail. COALESCE fixes
  every consumer of `EVENT_AGG` at once.
- **H4 day undercount** — DELETE bound `from_day`, INSERT SELECT bound
  `from_hour` (params![from_hour]) — verified the desync; a two-roll_up test
  reproduced total=1 vs expected 3.
- **H8/H9 attribution** — `observe_injected` set launch==current from one
  pre-launch read of the *reference* row; confirmed `value_version` defaults to
  1 on references and only the root increments on rotation. Fixed by resolving
  `COALESCE(linked_credential_id, id)` and re-reading at finalize.
- **M12 CA laundering** — confirmed the AAD bound only `{vault_id}`; the install
  paths call `observe_ca_material` which decrypts. Binding the cert-PEM hash
  makes a swapped cert fail decryption; proven by a DB-tamper test.

## Cases downgraded / reframed on inspection (did NOT take the agent at face value)

- **"No insecure verifier exists today" — TRUE.** Whole-repo grep confirmed no
  `.dangerous()`, no custom `ServerCertVerifier`, no `danger_accept_invalid`.
  The finding was the *missing guard test*, not a live bypass. Created the guard
  (which passes), rather than "fixing" a non-existent verifier.
- **`inject.rs` BusyBox/Windows probes (M25/M26) — pre-existing, not in this
  branch.** `git diff origin/main…HEAD -- crates/core/src/inject.rs` is empty.
  Scoped the fix to the NEW `sweep_orphaned_sessions` (/proc on Linux); left the
  pre-existing termination code untouched and recorded it as a residual rather
  than modifying security-critical code on a suspected, untestable-here finding.
- **AEAD "detects ciphertext swapping" claim (threat model) — was FALSE for the
  CA cert, now TRUE.** The audit flagged it; rather than only deleting the
  claim, I implemented the binding that makes it true.
- **Go "connection-only fallback" and "partial coverage never shows full" —
  were false claims *and* fixable.** Implemented the downgrade + partial flags
  so the docs became true, instead of only softening the docs.
- **rotation_access.rs:563 clippy `logic_bug`** — confirmed pre-existing,
  clean on clippy 1.97 (CI's stable), not in this diff. Left untouched
  (correct: do not modify unrelated pre-existing tests on a local-toolchain
  version artifact).
- **1xx-as-transport-error (I8), first-run CA race (I4)** — traced as
  theoretical/consistency-only, not reproduced; recorded as residual, not
  "fixed" with speculative code.

## Independent cross-checks (re-verified, not assumed)

- Loopback-only bind (`127.0.0.1:0`), no wildcard/`::1` listener.
- Constant-time proxy-token compare via `SecretString::ct_eq` (subtle).
- Connection cap enforced on the single accept thread (no TOCTOU).
- DNS resolved once; connect only to a validated `SocketAddr` (no rebinding
  window) — preserved by the dual-stack `connect_any` change (all addresses are
  from the single resolution).
