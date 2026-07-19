# New Findings — Remediation Phase 2

Discoveries made while implementing Phase 2. IDs are local to this phase
(`RA-P2-n`). None is introduced by the Phase 2 changes; each is a pre-existing
condition surfaced during the work and recorded for a follow-up pass.

---

## RA-P2-1 — Three commands enforce reauthentication only in the wrapper, not in core

- **Severity:** Low. **Class:** authorization defense-in-depth (IPC-01/02 family).
- **Where:** `apps/desktop/src-tauri/src/main.rs` — `backup_create`
  (verifies the master password in the wrapper, then calls
  `backup::create_backup(vault, …)` on the already-unlocked vault),
  `provider_admin_connect` (conditional wrapper reauth when a connection
  already exists), and `provider_admin_test` (wrapper reauth). The underlying
  core functions do not independently require the master password.
- **Why it matters:** these follow the same wrapper-only-enforcement pattern
  that made IPC-01 and IPC-02 vulnerabilities. A new caller of the core
  function (a future CLI command, another IPC command) could forget the reauth,
  and the check is not reachable from a core-level authorization test. This
  phase moved the destructive `provider_admin_disconnect` reauth INTO core;
  these three were left as-is to bound scope.
- **Not higher severity because:** `backup_create` operates on an
  already-unlocked vault, so its reauth is genuine defense-in-depth (an
  attacker with the unlocked vault already has the data); `provider_admin_test`
  is a non-destructive live network check; `provider_admin_connect`'s
  destructive case (replacing an existing connection) DOES verify in the
  wrapper today. All three verify reauth as things stand — the gap is
  structural (enforcement location), not an active bypass.
- **Recommended fix (follow-up):** move the reauth into the core functions
  (`provider_admin_connect`, `provider_admin_test`, and a `create_backup`
  master-password check), matching `credential_delete` /
  `provider_admin_disconnect`, then extend `tauri_command_authz.rs` to cover
  them. The inventory marks them `not_covered_wrapper_reauth`.

---

## RA-P2-2 — 97 low-relevance Tauri commands have no direct authorization test

- **Severity:** Informational (test coverage). **Blocks GA: no.**
- **Where:** `docs/remediation-phase-2/tauri_command_inventory.json` — 97 of
  137 commands are read/metadata commands gated only by the unlocked vault
  (`with_vault`), with no per-call reauth and no direct Rust test
  (`structural_unlock_gate`, `not_covered`).
- **Why it matters:** the Phase 7 harness deliberately covers the
  security-sensitive/destructive set; it does NOT claim the whole surface is
  tested. A read command that inadvertently returned a secret, or a
  metadata-mutation command that should require reauth, would not be caught.
- **Recommended fix (follow-up):** audit the low-relevance set for any that
  return secret material or perform state changes, promote those into the
  harness, and keep the inventory's `test_status` current.

---

## RA-P2-3 — ProviderDetail opens backend-manifest URLs without frontend scheme validation

- **Severity:** Info / Low. **Blocks GA: no.**
- **Where:** `apps/desktop/src/components/ProviderDetail.tsx` — several buttons
  pass manifest URLs (and watch/history URLs) to `openUrl` from
  `@tauri-apps/plugin-opener` with no FE validation. IPC-05's `docs_url` anchor
  was fixed this phase (`safeExternalUrl`), but this adjacent surface relies
  entirely on the backend/opener allowlist as the gate.
- **Why it matters:** provider-manifest URLs are shipped/vault data, lower risk
  than user-entered `docs_url`, but the FE performs no scheme check before
  invoking the OS opener.
- **Recommended fix (follow-up):** validate with `safeExternalUrl` (or an
  http/https allowlist) before calling `openUrl`, and confirm the Tauri opener
  capability config restricts schemes.

---

## Confirmed still-open (correctly out of Phase 2 scope)

Recorded in `CONTINUATION.md`; the re-audit's `RA-1`/`RA-4` were resolved this
phase (Phase 1 / Phase 9). Remaining re-audit follow-ups: `RA-2` (CLI
broken-pipe panic) and `RA-3` (unconfined `env_preview`/`env_import` reads) —
both deferred per the Phase 2 brief.
