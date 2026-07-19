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
- [~] **Phase 1** — evidence validated & internally consistent; dedup started (CRYPTO-01≡CONC-03). **FINDINGS_INDEX.md still to write.**
- [x] **Phase 3 — CRYPTO-01/CONC-03**: RESOLVED. Deterministic reproduction (25/25 orphan+wedge) + transaction proof + defense control (5/5). See `evidence/crypto01/RESOLUTION.md`, `evidence/crypto01/repro_run.log`, harness files. Consolidated CONC-03 into CRYPTO-01.
- [ ] **Phase 4 — ROT-001** (High, unverified): lost-revoke/crash wedge. Source: `vault.rs:7057-7077,7244-7278,7343-7353,7386-7396,7421-7427`. Cross-check ROT-010 (404-as-success). Per provider (OpenAI, Supabase, others).
- [ ] **Phase 5 — OBS-001** (High, unverified): exposure-alert auto-resolve when evidence disappears. Source: `vault.rs:2044-2082,2102-2112,5121-5153` + `monitor.rs:140-150`.
- [ ] **Phase 2/6 — material leads**: PI-02/CONC-11 (PID reuse term), PI-06 (pid<=0), IPC-01/FS-09 (arbitrary file write), IPC-02 (delete no reauth), PI-05/CONC-02 (clock), NET-01/NET-02 (SSRF), GScan-03/CONC-05 (git-history memory), CONC-04/CRYPTO-03 (backup), DEST-01..03 (destination semantics), M-6 (CI action pinning).
- [ ] **Phase 8 — SOURCE_REVIEW_LEDGER.md**: 62 prod Rust (41 core + 19 CLI + 2 desktop) + 31 FE + 9 scripts + 2 CI + Tauri/pkg config.
- [ ] **Phase 9 — reports**: DEEP_TECHNICAL_AUDIT (update), THREAT_MODEL_DELTA, TEST_COVERAGE_GAPS, REMEDIATION_PLAN, MANUAL_SECURITY_TESTS, FINDINGS_INDEX.

## Key resolved facts (do not re-derive)
- crypto.rs primitive layer is clean (XChaCha20-Poly1305 + Argon2id + AAD binding + version byte; no custom crypto; debug-gated fast KDF). VERIFIED.
- The project-key freshness check (`project_key_for_row` blake3 wrap-hash) is real and works for the **coarse/sequential** stale-cache case, but does **not** cover the intra-op TOCTOU window in `add_credential`/`replace_credential_value` (both non-transactional). See CRYPTO-01 RESOLUTION.

## Reproduction harness (reusable)
`scratchpad/crypto01_repro/` (copied to `evidence/crypto01/harness_*.{rs,toml}`). Pattern for concurrency repro: two `UnlockedVault` handles on one DB via public API; make the rotation hold the SQLite write lock (pad the project) so the racing writer parks at its INSERT. `cargo run` with `ITERS/PAD/DELAY_MS/TMP_ROOT` env.

## Next-session entry point
Continue at **Phase 4 (ROT-001)** then **Phase 5 (OBS-001)**, updating FINDINGS_INDEX incrementally. Commit after each material group. Keep production source untouched.
