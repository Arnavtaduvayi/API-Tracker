# Tethra Mesh audit — final verdict (2026-11-05)

Phase D of Increment 12: a fresh verification agent, which had seen only
`findings.json`, the remediation commits and the docs (not the auditors'
reasoning), re-checked every confirmed finding against the code and its
failing-first test, judged the accepted findings' rationale, ran the full
suite and clippy, and spot-checked five invariants from scratch. It worked
read-only against `6a279d4`.

## First pass (against `6a279d4`): REOPEN

- **39 of 41 confirmed findings: fixed and tested.**
- **MP-2: partially fixed.** The `ChainReply` range check and the
  no-self-report rule for chain claims were in, but a peer-supplied **dot
  hash** for the receiver's own origin, committed beside genuine items with
  `upto` naming the receiver's seq, still produced fork evidence against the
  receiver itself (`store.rs` `validate_commit`), and the node then minted a
  `fork.report` against itself. Reproduced by the agent in a scratch copy.
- **MD-1: partially fixed.** ADR 0032 "Security implications" still said
  `Σ used` may exceed supply by at most one request's cost.
- **Accepted findings (MP-6, MP-8, MI-6, MI-7, MC-9, MC-11, MD-15): sound**
  and documented; MP-2's narrowed decision: justified.
- **Suite:** 1 920 passed, 0 failed, 14 ignored (`API_TRACKER_INSECURE_FAST_KDF=1
  cargo test --no-fail-fast -p api-tracker-core -p api-tracker-cli -p
  api-tracker-observe -p api-tracker-gateway -p api-tracker-tracking -p
  api-tracker-mesh`); clippy `-D warnings` clean.
- **Five invariants from scratch** — authentication before data (MESH-SI-2),
  removal and cutoffs, the restore and clone marker (MESH-SI-5), the gate and
  escrow (MESH-SI-9/10), share revocation and sealing (MESH-SI-6): all hold,
  within documented limits.
- **Low items:** the MP-3 "a cut-short repair continues" wording (it is sent
  again from its start); the cold-gate wording "after a gateway restart or at
  the start of a month" (a restarted gate seeds its cost history, so only a
  cap with no priced history is cold); TEST_PLAN's "epoch bump on deletion"
  for `cap.used`; ADR 0032's benchmark line without its scope; a removed
  device's later `cap.used` dropping out of the total; a downgrade past
  marker version 2; MI-5's legacy partial state; the MD-14
  `mesh_shares_list` nit; CLAUDE.md's "end-to-end encrypted" wording.

## Remediation of the reopened items

- **MP-2:** `proto::Session::on_items` drops `Items.dots` for the receiver's
  own origin at or below its own `vv[self]` (a signed item of its own origin
  with another hash still counts: only its key could sign it). Test
  `proto::tests::a_peers_dot_hash_never_makes_this_device_report_itself_forked`
  (the agent's scenario), failing first with the filter disabled
  (`evidence/MP-2_baseline_fail.log.txt`). PROTOCOL §7.2 and ADR 0031 say so.
- **MD-1:** ADR 0032's overshoot paragraph now states the limited, not zero,
  overshoot with its three causes, like every other doc.
- **Low items, done:** MP-3 wording (code comment, PROTOCOL §8.5,
  KNOWN_LIMITATIONS); the cold-gate wording everywhere (docs, CLI, desktop
  text and its test); TEST_PLAN; ADR 0032's benchmark scope;
  KNOWN_LIMITATIONS entries for the removed device's `cap.used` and the
  marker downgrade. **Not changed:** MI-5's legacy state (the mesh has not
  shipped, so no install holds the old partial state); the MD-14 nit
  (`mesh_shares_list`'s purge deletes only items addressed to removed devices,
  recorded as a structural write); CLAUDE.md (the owner's instruction file;
  reported to the owner instead).

## Found by the Phase C soak, after the verification began

The 10-minute caps soak on `6a279d4` failed one seed of 832: **5000331**,
"lower settles" (a pending decrease of 1 556 micros nobody would burn).
Bisection put it in `e2999b7` (MC-6), and the per-device figures showed why:
the remainder sat with a device holding a 200 000 override that had spent
within its own fair share plus override, while other devices had overspent
during partitions. A holder has always kept its overrides in a lower (ADR
0032 D4); MC-6 made the owner's reclaim respect that too. The invariant's
expectation, not the policy, was wrong: it now settles down to rights held
under a device's own overrides, the seed is a permanent regression
(`mesh_sim::caps_regression_seeds`), and the consequence (the month's total
can end above the effective target by up to what overrides still hold) is in
ADR 0032 and KNOWN_LIMITATIONS.

## Second pass

Against `24eb4a4` (the follow-up `fadb4a0` and the ship docs `24eb4a4`), the
same agent returned **REOPEN** for three narrow items, and **resolved**
everything else: MD-1; the MP-3, cold-gate, TEST_PLAN, benchmark-scope and
limitation wording; the ship docs (README, root SECURITY and THREAT_MODEL,
REVIEW_HANDOFF) apart from the items below; `mesh::proto` 15 passed and
`mesh_sim` 8 passed. It judged the 5000331 policy call (overrides survive a
lower) sound.

- **MP-2, a race:** the session's filter compared a dot with this device's
  log when the dot arrived; this device could mint that seq before the
  peer's Commit landed (the store lock is released in between), and the
  store's own comparison then produced fork evidence against itself.
  **Fixed:** `store::validate_commit` takes the store's own device id and
  ignores own-origin dot hashes at or below its log *inside the commit's
  transaction* (a signed own-origin item with another hash still counts).
  Test `proto::tests::a_peers_dot_above_this_devices_log_never_forks_it_after_it_mints`
  (the agent's race), failing first with the store check disabled
  (`evidence/MP-2_baseline_fail.log.txt`). The session's filter stays as a
  first line.
- **The "lower settles" amendment masked real under-burns:** subtracting
  override-held rights outright excused them twice when nobody had
  overspent (the effective target already counts overrides). **Fixed:** the
  floor is `max(effective target, total used + override-held rights)`
  (`sim::caps::unsettled`, unit test with seed 5000331's figures and the
  agent's masked case, failing first with the first formula,
  `evidence/MC-4_baseline_fail.log.txt`). Seed 5000331, the CI seeds and the
  injection test pass with it.
- **CHANGELOG** "the total holds even while devices cannot reach each
  other" is now qualified (enforcement per device, limited overshoot,
  overrides).

The plan allows one repeat of Phase D; these three items were remediated
exactly as the agent specified, each with the failing test it described,
and the agent stated it would concur once they were done.

## Verdict

**41 of 41 confirmed findings fixed and tested; 7 accepted findings
documented; MP-2's narrowed decision justified.** Residual risks are in
[`KNOWN_LIMITATIONS.md`](../../KNOWN_LIMITATIONS.md) and summarized in
[`REVIEW_HANDOFF.md`](../../REVIEW_HANDOFF.md).
