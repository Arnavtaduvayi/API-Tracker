# Threat Model Delta (Phase 9)

**Baseline:** `7d81090`. **Model:** Fable 5. Deltas the audit discovered relative to `evidence/ARCH_TRUST.md` and the product's stated guarantees.

## New / revised assets
- **Project-key wrap generation** — the freshness of the on-disk wrap vs an in-memory cached key is a security-relevant asset; a stale-vs-fresh mismatch during a write causes silent data loss (CRYPTO-01).
- **Exposure-alert lifecycle state** — whether a `PossibleExposure` alert is open is itself a security signal; its resolution must be trustworthy (OBS-001).
- **Recorded rotation event log** — the "attempting revocation" marker is load-bearing for crash recovery; its position in the event stream is trusted state (ROT-001/010).

## New / revised trust boundaries
- **Two processes, one vault DB.** The desktop+CLI shared-vault design is a real concurrency boundary. Previously treated as safe via "SQLite serializes writers + wrap-hash freshness". **Revised:** serialization orders physical writes but does not re-validate keys inside a writer; the freshness check only covers the coarse sequential case, not the intra-operation TOCTOU (CRYPTO-01, CONC-04, CONC-12, ROT-002/003).
- **Webview → IPC.** `env_example_write` is an arbitrary-file-write boundary reachable from a compromised/misbehaving webview with no reauth (IPC-01); `credential_delete` is a destructive boundary with UI-only confirmation (IPC-02). **Revised:** frontend confirmation/authorization is not authoritative for these two commands.
- **doc-watch URL → outbound GET.** A previously-underweighted boundary: `validate_url` is scheme-only, making the app an SSRF probe against internal/metadata hosts (NET-01). Body is hashed (no exfiltration), but existence/port/change signals leak.
- **PID → signal.** Recorded PID → `kill`/`taskkill` with no identity check and no `pid>0` guard is a boundary that can target an unrelated process or the app's own process group (PI-02/06).

## New threat actors / scenarios
- **Local concurrent-writer (non-malicious).** Ordinary simultaneous desktop+CLI use during a password change → CRYPTO-01 data loss. No attacker needed; a race condition suffices.
- **Compromised/malicious webview content.** Direct `invoke` of destructive/file-write commands bypassing UI sequencing (IPC-01/02, and any command lacking core-side reauth).
- **In-app SSRF actor.** A user (or content that can drive the app) pointing a doc-watch at internal endpoints (NET-01).
- **Hostile/careless provider responses.** Empty `starting_at` (OBS-003 history wipe), unparseable `expires_at` (OBS-004 listing DoS), huge/negative token counts (NET-03/OBS-002).
- **Network fault at a bad moment.** Lost revoke response → stuck rotation + unsafe rollback (ROT-001).

## New failure modes
- **Silent permanent data loss** of a stored credential value from a concurrency race (CRYPTO-01) — previously believed impossible ("SOLID").
- **Sticky recovery breakage:** an orphaned ciphertext also wedges future project-password changes (CRYPTO-01 secondary).
- **Self-resolving security alerts** (OBS-001) and **history-wipe on malformed sync** (OBS-003).
- **Cross-table-inconsistent backup** that restores to an unusable vault (CONC-04).

## Guarantees that must be weakened / restated honestly
- "Cached project keys … defeat the stale-key-after-concurrent-password-change race" (`MY_FINDINGS.md:15`) — **restate:** defeats the *sequential* case only; a concurrent-write TOCTOU window remains (CRYPTO-01).
- Threat model's ".env export = atomic 0600 write" — **restate:** the default no-overwrite export uses non-atomic `write_new` (FS-02); export is owner-restricted on Unix only (FS-07).
- "we never crawl arbitrary hosts" (docwatch comment) — **false**; restate as scheme-only validation (NET-01).
- Repository scanning is best-effort with **undocumented** evasion gaps (GScan-05) and a **transient** alert lifecycle (OBS-001) — the tool must not imply detection or persistence guarantees.

## Residual risks (accepted, documented)
- Local malware / unlocked device / memory inspection / clipboard monitoring — inherent to a local-first secret manager; documented.
- https-to-internal for webhooks (NET-02) — defense-in-depth only (secret-free payload, no redirects).
- Wall-clock trust for CLI sessions/grants (PI-05, M-3) — bounded, documented; desktop auto-lock uses monotonic time.
- Provider soft-revoke semantics (Anthropic archive, no OpenAI disable) — provider limitations, represented honestly.

## Required mitigations (see REMEDIATION_PLAN.md)
Transactionalize multi-step DB access (R1/R3/R4); decouple exposure-alert resolution from finding re-emission (R2); reauth + path-confine IPC file write (R6); scrub auth env vars from children (R5); PID-safety guards (R9). These restore the previously-assumed guarantees rather than merely documenting their absence.
