# Material-lead verification (Phase 2/6) — Fable 5 primary source review

Baseline `7d81090`. Each item below was personally read at the cited lines this session (V-insp) and its verdict recorded. Deep items have their own resolution docs.

## Process termination (`crates/core/src/inject.rs`)
- **PI-06 (CONFIRMED, Low→Med sub-issue):** `terminate_pid(pid: i64)` (271-300) has **no `pid<=0` guard**. On Unix `kill 0` signals the **caller's whole process group**; a corrupted/edited `pid` of 0 (or a negative value) self-signals API Tracker. Add `if pid <= 0 { return false }`.
- **PI-02 / CONC-11 (CONFIRMED, Med/Low):** the recorded PID is signalled with **no liveness/identity re-check** (271-300). After the injected child exits, OS PID reuse means SIGTERM/taskkill can hit an unrelated same-user process. `sweep_dead_sessions` guards `pid<=0` and only closes on definitive not-found, but `terminate_pid` does neither. Record start-time/cmd at spawn and compare before signalling.
- **PI-04 (CONFIRMED, Low):** Unix path sends only SIGTERM (no SIGKILL escalation) and reports success on `kill` exit status even if the signal is ignored.

## Clock trust (`crates/core/src/access.rs`)
- **PI-05 (CONFIRMED, Low):** `consume_launch` (163-179) authorizes via `expires_at > now` where `now = clock::now_rfc3339()` (wall-clock). A backward wall-clock change re-activates expired grants. The CAS `UPDATE … WHERE` is otherwise correct (no double-consume — refutes any double-launch concern). Desktop auto-lock uses monotonic `Instant` (immune); CLI session + grants use wall-clock (M-3/PI-05). Platform note: applies to all OSes (wall-clock), not macOS-specific.
- **PI-07 (CONFIRMED, Info):** one-time grant is consumed (launch incremented) before the spawn/project-key can fail — a failed launch still burns the single grant.

## SSRF / URL validation
- **NET-01 (CONFIRMED, Low):** `docwatch::validate_url` (docwatch.rs:108-113) checks **only** the `http(s)://` scheme — no host/userinfo/private-IP checks. Reachable with only an unlocked vault (no reauth). An in-app actor can point a watch at `http://169.254.169.254/…`, `http://10.x`, loopback, etc.; the app GETs it and stores a content **hash** (no body stored) — an SSRF existence/port-probe + change-detection primitive, **not** body exfiltration. The doc comment "we never crawl arbitrary hosts" is **false**. Asymmetric with the webhook validator.
- **NET-02 (CONFIRMED, Info / defense-in-depth):** `validate_webhook_url` (notify.rs:50-96) is strong for http (localhost-only, rejects userinfo, bracket-aware IPv6) but allows **https to any host including internal/link-local/metadata**. Payload is secret-free metadata and `max_redirects(0)`, so impact is defense-in-depth only. Not covered by either validator (residual): IPv4-mapped IPv6 (`::ffff:169.254.169.254`), decimal/hex IP forms, and DNS-rebinding (host string validated, DNS resolved later on a separate connection). Redirects are OFF, which closes redirect-based SSRF and cross-host header forwarding.

## Desktop IPC (`apps/desktop/src-tauri/src/main.rs`)
- **IPC-01 / FS-09 (CONFIRMED, Med):** `env_example_write` (1409-1418) forwards a **frontend-controlled `example_path` + `content`** to `envgov::atomic_write` with only `with_vault` gating — no reauth, no repo/path constraint at this entry. An arbitrary-file **overwrite** primitive reachable over IPC (owner-only 0600 via atomic_write, but any writable path). Require reauth and confine the path.
- **IPC-02 (CONFIRMED, Low):** `credential_delete` (742-748) → `delete_credential` with **no reauth/confirm in Rust**; confirmation is UI-only (`ConfirmDialog`). Direct `invoke` deletes the local record (cascading versions). CLI path confirms; desktop does not. (Local record loss, recoverable from backup → Low.)

## Backup integrity (`crates/core/src/backup.rs`)
- **CONC-04 (CONFIRMED, Med):** `collect_payload_v2` (135-168) reads each table with a **separate autocommit `SELECT`** — no enclosing read transaction/snapshot. A concurrent commit between two tables' reads yields a cross-table-inconsistent backup (worst case: credentials whose project-key wrap is not in the same snapshot → unrestorable rows), and per-row AEAD verify cannot detect the inconsistency. Wrap `collect_payload_v2` in one deferred read transaction. Same root class as CRYPTO-01 (non-transactional multi-step DB access).

## Positive confirmations (defenses that hold)
- `access::consume_launch` single-launch CAS is correct (no double-consume).
- `crypto.rs` primitive layer clean (see CRYPTO-01 RESOLUTION §crypto).
- Webhook http path + `max_redirects(0)` block the classic `http://169.254.169.254` IMDS SSRF.
