# Architecture & trust-boundary map (evidence-based)

## Component topology
- **Shared core** `crates/core` (`api-tracker-core`): all security logic — crypto, vault/key hierarchy, DB+migrations, session, providers/connectors, destinations, rotation, scanner, env handling, pricing/usage/budget, alerts/monitor/notify, backup. `#![forbid(unsafe_code)]`.
- **CLI** `apps/cli` (`api-tracker`): clap command surface; owns process spawning for `run` (injection) and interactive password prompts (rpassword, no-echo). Depends on core.
- **Desktop** `apps/desktop/src-tauri` (Tauri 2): 136 `#[tauri::command]`s wrapping core behind a `Mutex<VaultSlot>` with inactivity auto-lock; React/TS frontend (`apps/desktop/src`). Depends on core.
- Desktop + CLI share ONE vault DB (`vault.db`, WAL). CLI session persisted in `session.json` (split-token). Data dir default via `directories`, overridable by `API_TRACKER_DIR`.

## Key hierarchy (crypto.rs, vault.rs)
master password --Argon2id(salt,params)--> KEK --XChaCha20Poly1305 unwrap--> vault_key
vault_key --> fingerprint_key (reuse detection), provider-admin keys, destination-auth keys, notification-channel URLs, project_key (mode 'vault')
project_key (mode 'vault+password') = vault_key-wrap( password-KEK-wrap( project_key ) )  [double wrap]
project_key --> credential values + retained versions (AAD binds vault:project:credential[:version])
session token (32B, user-held) --> encrypts {vault_key, project_keys+wraphash} in session.json

## Trust boundaries (input → validation → sink)
| Boundary | Source | Validation present | Sink | Residual risk |
|---|---|---|---|---|
| Master/project password | user | length>=12; Argon2id; ct_eq | KEK derive | none material |
| CLI session token+file | env var + 0600 file | AEAD + session_id AAD + wall-clock TTL | vault_key | wall-clock TTL (M-3); file+env combined exposure (documented) |
| IPC payloads | frontend/webview | serde typing; with_vault gates unlock; reauth via password in core | core calls | credential_delete no confirm at IPC (M-2) |
| Provider HTTP responses | network | max_redirects(0); 4MiB cap; 20s timeout; bounded pagination (MAX_PAGES); retry-after cap 30s; JSON field-by-field | usage/pricing/keys | provider dishonesty handled honestly (attribution labels) |
| Webhook URL | user | validate_webhook_url: https-any / http-localhost-only / no userinfo / IPv6-aware; redirects off | POST secret-free metadata | https-to-private-IP (Info) |
| Doc-watch URL | user | validate_url: scheme only (WEAK) | GET (hash stored) | SSRF probe primitive (M-4) |
| .env file content | disk (repo) | textual parse, never executes; SecretString | doc model | none (test-proven) |
| .env export target path | user | canonicalize parent; refuse symlink; refuse git-tracked; no-clobber/atomic 0600 | plaintext write | TOCTOU closed by O_EXCL + rename-replaces-node |
| Git repo content/history | disk | 5MiB file cap; 200k-line recon cap; binary skip; SKIP_DIRS | scanner | full-history stdout buffered whole (M-5) |
| Git subprocess args | stored hashes/paths | hex-only range endpoints + --end-of-options; index paths ":"-prefixed; -C repo (no shell) | git binary | none material |
| Child process env (inject) | selected creds | valid_env_name; only mapped vars; parent env inherited | spawned child | parent-env inheritance is by-design; documented |
| Recorded PID (terminate) | DB | none (no pid<=0 guard, no re-validate) | kill/taskkill | PID reuse + kill 0 (M-1) |
| AWS region | destination config | valid_aws_region [a-z0-9-]<=64 | SigV4 authority | none (authority-injection blocked) |
| Backup file | disk | AEAD + format-version AAD (v2); checked_ident allowlist; SchemaTooNew | restore | force-restore overwrites (confirmed destructive, gated) |
| DB from newer build | disk | SchemaTooNew refusal (found>supported) | migrate | none |
| Pricing import JSON | user file | validate_price>=0; NaN/inf/neg/cap in dollars_to_micros; effective-dating | estimation | huge int → i64::MAX via saturating (bounded) |
| Provider scopes | network | preserved raw + labeled normalized (confidence/precision/source) | permissions view | honest (no fake mutation) |

## Reauth-gated operations (verify_master_password in CORE, not UI)
reveal_credential, credential_copy(desktop reveal path), replace_credential_value, set_project_password,
change_master_password, backup_create/restore, rotation_advance/approve? , rotation_complete_manual,
rotation_cancel, rotation_rollback, env_export. (Verified structurally — password is a required arg.)

## Concurrency model
- Single SQLite DB, WAL, busy_timeout 5s, foreign_keys on. One writer at a time (SQLite serializes); read snapshots.
- Desktop: Mutex<VaultSlot>; auto-lock via monotonic Instant; drop-after-mutex-release for WAL checkpoint.
- Cross-process (desktop+CLI): freshness wrap-hash on cached project keys; rotation CAS transitions; version-prune rotation exemption. No shared in-memory state across processes — DB is the sync point.
