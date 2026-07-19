# Deep Audit — Continuation Checklist

**Model:** Fable 5 (`claude-fable-5`) — session ran on Fable 5 by the user's deliberate `/model` selection; the "Opus 4.8" text in the launch prompt is superseded and **no conclusion is attributed to Opus**. No model fallback occurred.
**Audited production baseline (immutable):** `7d81090a1068476291546963e68ca8c7de1a7145`
**Audit branch / HEAD at session start:** `audit/deep-pressure-test` @ `be8bfd3`
**Constraint honored:** no production source file modified (audit docs/tests/harnesses only).

## Recovered evidence baseline (validated, Phase 1 partial)
- 96 candidate findings in `evidence/all_findings.tsv` (2 High, 25 Med, 42 Low, 27 Info) — counts reconcile.
- 48 verifier verdicts in `evidence/verdicts.tsv` (46 CONFIRMED, 2 REFUTED: IPC-03, CRYPTO-02); ~48 candidates had no completed verifier verdict.
- `findings_raw.tsv` carries reviewer-category provenance per finding.

## Status by phase
- [x] **Phase 0** — environment/provenance reported; model discrepancy surfaced and resolved (proceed on Fable 5).
- [x] **Phase 1** — evidence validated & internally consistent; **FINDINGS_INDEX.md** written (96 dispositions, 10 dedup consolidations).
- [x] **Phase 3 — CRYPTO-01/CONC-03**: RESOLVED. 25/25 reproduction + proof + 5/5 defense control. `evidence/crypto01/`. Promoted Med→High.
- [x] **Phase 4 — ROT-001 (+ROT-010)**: VERIFIED (state proof + provider matrix). `evidence/ROT-001_RESOLUTION.md`. Refined High→Med.
- [x] **Phase 5 — OBS-001**: VERIFIED (control-flow proof). `evidence/OBS-001_RESOLUTION.md`. Refined High→Med.
- [x] **Phase 2/6 — material leads**: PI-02/04/05/06/07, NET-01/02/03, IPC-01/02, CONC-04 verified by inspection. `evidence/MATERIAL_LEADS_VERIFICATION.md`.
- [x] **Phase 8 — SOURCE_REVIEW_LEDGER.md**: every production file represented once.
- [x] **Phase 9 — reports**: DEEP_TECHNICAL_AUDIT (Session-2 addendum), THREAT_MODEL_DELTA, TEST_COVERAGE_GAPS, REMEDIATION_PLAN, FINDINGS_INDEX written. (MANUAL_SECURITY_TESTS from prior session retained.)

## Residual for a future pass (not blocking completion)
- `Ac`-status Low/Info findings (accepted on reviewer citation, not independently re-read): ROT-002..008/011, OBS-005..012, FS-01..08, CONC-07..10. Highest value: independent re-verification of the ROT-* transition races and adopting the CRYPTO-01 harness as a checked-in regression test.
- Live-provider + destination live testing (real creds, out of scope) and Windows/Linux behavioral tests remain required before GA — see TEST_COVERAGE_GAPS.md.

## Key resolved facts (do not re-derive)
- crypto.rs primitive layer is clean (XChaCha20-Poly1305 + Argon2id + AAD binding + version byte; no custom crypto; debug-gated fast KDF). VERIFIED.
- The project-key freshness check (`project_key_for_row` blake3 wrap-hash) is real and works for the **coarse/sequential** stale-cache case, but does **not** cover the intra-op TOCTOU window in `add_credential`/`replace_credential_value` (both non-transactional). See CRYPTO-01 RESOLUTION.

## Reproduction harness (reusable)
`scratchpad/crypto01_repro/` (copied to `evidence/crypto01/harness_*.{rs,toml}`). Pattern for concurrency repro: two `UnlockedVault` handles on one DB via public API; make the rotation hold the SQLite write lock (pad the project) so the racing writer parks at its INSERT. `cargo run` with `ITERS/PAD/DELAY_MS/TMP_ROOT` env.

## Next-session entry point
Continue at **Phase 4 (ROT-001)** then **Phase 5 (OBS-001)**, updating FINDINGS_INDEX incrementally. Commit after each material group. Keep production source untouched.
