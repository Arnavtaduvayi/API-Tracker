# Independent (orchestrator) findings & verified-solid areas

## Files I personally read in full or in security-critical part
crypto.rs (full), secret.rs (full), error.rs (full), clock.rs (full), db.rs (full),
session.rs (full), inject.rs (full), http.rs (full), docwatch.rs (full), rotation.rs (full),
envfile.rs (full), gitrepo.rs (full), pricing.rs (money math + validate + import),
backup.rs (checked_ident + collect_payload_v2), destinations.rs (sigv4 + capability honesty + valid_aws_region),
vault.rs (paths/create/unlock/resume 40-293; UnlockedVault/master-pw/project-keys 458-1097; reveal/update/replace/delete 1471-1755; rotation advance/create/disable/revoke/complete/cancel/rollback 6753-7565),
desktop main.rs (state/with_vault/auto-lock/reveal/copy/delete/reauth 60-810),
key_cmd.rs (reveal/remove 195-252).

## VERIFIED SOLID (positive findings — strong engineering)
- Crypto: Argon2id 64MiB/t3/p1 (debug-only weak via env), XChaCha20-Poly1305, random 24B nonce, per-row AAD binding (vault/project/credential/version). No custom crypto. getrandom. `forbid(unsafe_code)`.
- SecretString/SecretBytes: zeroize on drop, redact Debug/Display/Serialize, constant-time eq, explicit expose(). Leak-hunt found NO unintended secret->output/log/format flow.
- Key hierarchy: master pw -> KEK -> vault_key -> project_key(s) -> credential values. change_master_password re-wraps unchanged vault_key (sessions survive). set/remove_project_password ROTATE the project key and re-encrypt all values+versions (destroys old wrap; WAL/backup remnants worthless). Cached project keys carry BLAKE3 wrap-hash checked before every use -> defeats stale-key-after-concurrent-password-change race.
- Reauth: reveal/replace/set-project-pw/rotation-advance/complete-manual/cancel/rollback all call verify_master_password (full Argon2id + vault-key decrypt) as a STRUCTURAL precondition in core, not a UI gate.
- Auto-lock: desktop uses monotonic Instant (immune to clock changes). Keys zeroized on drop; drop happens after mutex release.
- Rotation state machine: forward-only, CAS set_state (concurrent advance fails loudly), CREATING_IN_PROGRESS claim before non-idempotent provider call + orphan-key guard, value_version==new_version check arms destructive steps only for THIS rotation, validate-new -> grace -> disable-old -> re-check validated -> revoke-old -> complete. 404-on-revoke refuses to mark revoked unless a prior attempt was recorded (no 404-masquerade). rollback refuses once old_revoked_at set; partial rollback -> MANUAL_REQUIRED. Version prune exempts active-rotation old_version.
- DB: 10 append-only migrations, each atomic in a tx with user_version bumped inside; SchemaTooNew refusal (forward-only); WAL + foreign_keys + secure_delete + 5s busy_timeout; 0600 on db/wal/shm (Unix); money as integer micro-USD. Dynamic SQL uses constant column lists or allowlisted field names; backup checked_ident enforces [A-Za-z0-9_].
- Money math: saturating_mul everywhere; dollars_to_micros rejects NaN/inf/negative and caps $1e12; validate_price rejects negative.
- HTTP: ureq max_redirects(0) (no cross-host header forwarding), 20s timeout, 4 MiB body cap, Debug redacts Authorization/api-key/token/x-amz-security-token. docwatch fetcher also max_redirects(0), 8 MiB cap.
- .env parser: purely textual, never executes/interpolates ($()/`` / $VAR kept literal — test-proven), values in SecretString, hostile multiline values can't inject phantom entries, malformed lines preserved+reported.
- Destinations: write-only honesty encoded (GitHub Actions + Vercel verify_method="existence only"); SigV4 matches official IAM vector + secret-key-never-in-headers test; valid_aws_region blocks authority injection.
- Git scan: hex-only range endpoints + --end-of-options (arg-injection defense, test-proven); 5 MiB working-tree/staged cap; 200k-line reconstruction cap with dense-pack fallback (test-proven); -C repo + separate args (no shell); index paths prefixed ":".
- CLI reveal: reauth-gated no-echo prompt + warning; the one deliberate plaintext output. CLI delete requires ctx::confirm.

## MY CANDIDATE FINDINGS (all appear Low/Med/Info — to reconcile with workflow)

### M-1 [Low->Med] terminate_pid: PID-reuse hazard + missing pid<=0 guard
- File: crates/core/src/inject.rs:271-300 (terminate_pid), used by access_session_kill (desktop main.rs), terminate_process_session (vault.rs:4291), access_cmd.rs:259.
- A recorded PID is signalled (`kill <pid>` / `taskkill /PID`) with NO re-validation that it's still the same process. After the injected child exits, the OS may reuse the PID; killing the session then targets an unrelated process. sweep_dead_sessions guards `pid<=0` and only closes on ps definitive not-found, but terminate_pid has NO `pid<=0` guard: a 0/negative PID from a corrupted/edited row would run `kill 0` -> SIGTERM to the caller's whole process group.
- Impact: wrong-process termination (reliability); `kill 0` self-signal (reliability). Local-only, needs PID reuse race or corrupted row. Product already documents this is a LOCAL control that can't claw back values / never touches provider (good honesty).
- Fix: guard `if pid <= 0 { return false }`; where feasible verify the PID's start-time/command before signalling (record start-time at spawn, compare via ps). At minimum the pid<=0 guard.

### M-2 [Low] Desktop credential_delete has no server-side confirmation/reauth
- File: apps/desktop/src-tauri/src/main.rs:743. Core delete_credential guards active-rotation and linked-references but not reauth/confirm; the confirm is UI-only (ConfirmDialog). Direct IPC invocation (compromised webview / crafted invoke) deletes the local encrypted record (+ cascades versions) without confirmation -> data loss if not backed up. CLI path DOES confirm (key_cmd.rs:243). 
- Fix: require an explicit confirm token or reauth in the delete command, matching the CLI.

### M-3 [Low] CLI session expiry uses wall-clock (clock-rollback extends session)
- File: crates/core/src/session.rs:158-175 (load_and_refresh compares clock::now() >= expires). A backward wall-clock change keeps an expired session valid; desktop auto-lock uses monotonic Instant and is immune. Needs local clock control + session file + token. THREAT_MODEL notes session-file+env exposure already.
- Fix: store a monotonic-ish anchor or accept as documented limitation; at least document explicitly in THREAT_MODEL.

### M-4 [Low] doc-watch URL validation is far weaker than webhook validation (SSRF probe primitive)
- CORRECTION after reading notify.rs: the WEBHOOK validator (notify.rs:50 validate_webhook_url) is STRONG — https anywhere but http only to localhost/127.0.0.1/::1, rejects userinfo (user@host), handles bracketed IPv6; combined with max_redirects(0) this blocks the classic http://169.254.169.254 IMDS SSRF. Residual: https to a private IP with a SECRET-FREE payload = Informational.
- The DOC-WATCH validator (docwatch.rs:108 validate_url) only checks the `http(s)://` scheme — NO userinfo/localhost/private-IP checks. Reachable via desktop doc_watch_add / CLI with only vault-unlocked (no reauth). An in-app actor can point a watch at http://169.254.169.254/... or http://10.x/... ; the app GETs it (http to ANY host), stores last_status + a content HASH (body is never stored/displayed). That is an SSRF existence/port-probe + change-detection primitive against internal http endpoints from the user's machine. Body exfiltration is NOT possible (hash only). Local-first single-user lowers impact, but the two validators are inconsistent.
- Fix: make docwatch::validate_url match validate_webhook_url (block http-to-non-localhost + userinfo; optionally block private/link-local/metadata ranges for https too), or document the asymmetry.

### Positive: permissions.rs honesty CONFIRMED — raw scopes preserved verbatim; normalized buckets carry source/precision/confidence; unknown scopes classified cautiously as write; explicitly never performs/【pretends】a per-key scope change (surfaces the official manage link). notify payloads are metadata-only ("secret-free by construction").

### M-5 [Low/Med] Full-history scan buffers entire `git log -p --all` output; no per-file size cap in history path
- File: crates/core/src/gitrepo.rs:163-176 history_added_units. `.output()` reads the whole diff of all history into memory; unlike staged_blob/working-tree there is no MAX_FILE_BYTES skip for large committed TEXT files. A repo with a huge committed text file (or enormous history) causes a large memory spike. User-initiated + local. parse cap bounds reconstruction but not the raw stdout buffer.
- Fix: stream git output (spawn + read line-by-line) or cap total bytes; skip oversized blobs in history like staged path.

### M-6 [Low] CI/release actions pinned to mutable tags, not commit SHAs
- Files: .github/workflows/ci.yml, release.yml. Uses actions/checkout@v4, Swatinem/rust-cache@v2, dtolnay/rust-toolchain@stable (a BRANCH ref), tauri-apps/tauri-action@v0, softprops/action-gh-release@v2, actions/setup-node@v4. The release pipeline holds `contents: write` + GITHUB_TOKEN and publishes artifacts; a retagged/compromised third-party action could inject into it. Positives: no pull_request_target; least-privilege (contents:read default, write only on publish jobs); draft+prerelease (manual publish gate); SHA256SUMS fail-closed; rust-cache used in release (minor cache-poisoning surface). 
- Fix: pin actions to full commit SHAs (esp. in release.yml); avoid @stable branch ref. Standard hardening; appropriately Low for public-alpha.

### I-1 [Info] SigV4 query canonicalization simplified (destinations.rs:1118) — correct for Secrets Manager (POST `/`, no query); not a general signer. No bug in actual usage.
### I-2 [Info] `key reveal` ignores --json and prints raw plaintext (key_cmd.rs:234) — arguably intentional (avoids embedding secrets in JSON logs); documented as the one deliberate output.
