# Manual Security Test Procedures — API Tracker

Baseline audited: commit `7d81090`, branch `audit/deep-pressure-test`.

These are hands-on procedures a reviewer runs to confirm the security properties
the automated suite asserts, plus the edge cases automated tests do not reach.
All procedures use **synthetic** credentials only. Set a scratch data dir and
(for speed on debug builds) the insecure fast KDF:

```bash
export API_TRACKER_DIR="$(mktemp -d)/vault"
export API_TRACKER_INSECURE_FAST_KDF=1   # debug builds only; release ignores it
FAKE='FAKE-TEST-NOT-A-REAL-KEY-000001'
```

> Never run these against your real vault. `API_TRACKER_DIR` isolates state.

---

## 1. Vault crypto & at-rest protection

### 1.1 Ciphertext is never plaintext on disk
1. `api-tracker init` (set a >=12-char master password), create a project, add a credential with value `$FAKE`.
2. `strings "$API_TRACKER_DIR/vault.db" | grep -F "$FAKE"` → **must print nothing**.
3. `strings "$API_TRACKER_DIR"/vault.db-wal 2>/dev/null | grep -F "$FAKE"` → **nothing** (WAL is checkpoint-truncated on lock).
- Expected: the value exists only as an XChaCha20-Poly1305 envelope.

### 1.2 Wrong password fails closed; repeated attempts don't degrade
1. `api-tracker unlock` with a wrong password → `incorrect password`, exit non-zero.
2. Repeat 10×; confirm no lockout bypass and no partial unlock. There is no attempt-count weakening (Argon2id cost is the throttle).

### 1.3 Reauth is cryptographic, not cosmetic
1. Unlock the vault, then `api-tracker key reveal <sel>` and enter a **wrong** master password → refusal, no value printed.
2. Enter the correct password → value prints once with a warning. Confirms `verify_master_password` (full Argon2id) gates reveal in core, not just the UI.

### 1.4 Corruption / swap / truncation are detected
- Using `sqlite3 "$API_TRACKER_DIR/vault.db"`: flip one byte of a `credentials.ciphertext`, or copy one credential's ciphertext over another's (row swap). Reveal → `decryption failed …` (AAD binds vault:project:credential, so swaps fail).

### 1.5 Project-password rotation destroys old wraps
1. Add a project password (`api-tracker project set-password`). 2. Note the value is re-encrypted under a fresh project key. 3. Confirm the pre-password wrap no longer unlocks anything (search WAL/db as in 1.1). See `rotate_project_key` in vault.rs.

---

## 2. Session & auto-lock

### 2.1 Split-token: neither half alone unlocks
1. `api-tracker unlock` prints a token; it is exported as `API_TRACKER_SESSION`.
2. `cat "$API_TRACKER_DIR/session.json"` → only ciphertext; grep for the token → absent.
3. With `session.json` present but `API_TRACKER_SESSION` unset, run any command needing the vault → `no active session`.

### 2.2 Sliding expiry & lock
1. Set a short auto-lock in settings. 2. Idle past it, run a command → `session has expired`. 3. `api-tracker lock` removes `session.json`.

### 2.3 (Finding M-3) Wall-clock rollback extends a CLI session
1. Unlock with a short TTL. 2. Set the system clock **backwards** by more than the TTL. 3. Resume a command → session still valid past its intended wall-clock life. Confirms `session.rs` compares `clock::now()` (wall clock) not a monotonic anchor. Desktop auto-lock (monotonic `Instant`) is immune — verify by contrast.

---

## 3. Process injection & temporary access

### 3.1 Only mapped vars are injected; parent secrets are not leaked to unrelated names
1. Map one credential to `OPENAI_API_KEY` for a project. 2. `api-tracker run <project> -- /usr/bin/env | grep -E 'OPENAI_API_KEY|MASTER|VAULT'` → only `OPENAI_API_KEY` present.

### 3.2 (Finding M-1) PID reuse / kill-0 hazard
1. Start a short-lived injected child, note the recorded PID. 2. After it exits, in a controlled sandbox force PID reuse (spawn many processes) and `api-tracker access session-kill <id>` → observe it can signal whatever now holds the PID. 3. Inspect `terminate_pid` (inject.rs:271): confirm there is **no `pid<=0` guard** — a `0` PID would `kill 0` (whole process group). Do NOT reproduce kill-0 on a real machine; verify by code inspection + a unit test with a stub runner.

### 3.3 Grant expiry is LOCAL, never called provider revocation
- `api-tracker access grant … ` then let it expire; confirm all messaging says the local grant expired and explicitly does **not** claim the provider key was revoked.

---

## 4. Filesystem / `.env`

### 4.1 Parser never executes shell
- Create `.env` with `CMD=$(touch /tmp/pwned)`, `REF=$HOME/x`, `TICK=\`whoami\``. `api-tracker env import/preview` → values stored literally; `/tmp/pwned` is **not** created.

### 4.2 Export refuses symlink & git-tracked targets; writes 0600 plaintext-labeled
1. `ln -s /etc/hosts out.env; api-tracker env export … out.env` → refused (symlink).
2. In a repo where `.env` is tracked, export to it → refused (would commit secrets).
3. Successful export: file is mode `600`, begins with the PLAINTEXT warning header, and `env exports` records only var names + a hash (no value).

### 4.3 TOCTOU
- Race a symlink swap between the export check and write; with `atomic_write` the rename replaces the link node (never writes through it), and no-clobber `write_new` (`O_EXCL`) fails if a file appears. Confirm no plaintext lands on the link target.

---

## 5. Git scanner & hooks

### 5.1 Detection + redaction
- Stage a file containing `$FAKE`-style provider keys; `api-tracker scan --staged` reports the file/line with a **masked** preview; `--json` output contains only the masked value (raw `secret` serializes as `[REDACTED]`).

### 5.2 (Finding M-5) Full-history memory bound
- Build a repo whose history contains a large (e.g. 400 MB) committed **text** file; run `api-tracker scan --history` (no depth). Watch RSS — the entire `git log -p --all` output is buffered. Confirm the memory spike; the working-tree/staged paths cap at 5 MiB but the history path does not skip oversized blobs.

### 5.3 Hook safety
1. Put a foreign `pre-commit` hook in a repo; `api-tracker hooks install` → refused unless `--force`; with `--force` the existing hook is **preserved** and our sentinel block appended. 2. `hooks remove` strips only our block. 3. In a git worktree (`.git` is a file) → install refused (won't write to the wrong place).

---

## 6. Providers, destinations, network

### 6.1 No redirect-based header leakage
- Point a provider/base at a local mock returning `301` to another host; confirm the client (max_redirects(0)) does **not** follow it and never re-sends `Authorization`/`x-api-key` to the redirect target.

### 6.2 (Finding M-4) Doc-watch SSRF asymmetry
- `api-tracker doc-watch add <provider> http://127.0.0.1:<port>/` succeeds (only scheme is checked), and `http://169.254.169.254/…` is accepted, whereas the **webhook** validator rejects `http://` to non-localhost and `user@host`. Confirm the doc-watch fetch probes the internal endpoint (status recorded) though only a hash — not the body — is stored.

### 6.3 Write-only destinations report existence, not value verification
- Configure a GitHub Actions / Vercel destination (mock). Confirm the UI/CLI verify step is labeled **existence only** and never claims the deployed value was read back and matched. AWS Secrets Manager (SigV4) may verify by value.

### 6.4 SigV4 correctness
- `cargo test -p api-tracker-core sigv4` → the official IAM example vector passes and the secret key never appears in any header.

---

## 7. Rotation lifecycle (mock provider + runner)

Run `cargo test -p api-tracker-core rotation` and the CLI rotation tests, then manually:
1. Plan → approve (reauth) → advance through each state; kill the process between states and re-advance → confirm no duplicate provider key is created (orphan guard) and no step double-executes (CAS).
2. Force the new-value validation to fail → confirm the old key is **never** disabled/revoked.
3. Simulate a provider `404` on revoke with no prior recorded attempt → confirm the rotation refuses to mark revoked ("a wrong key id would look identical").
4. After `old_revoked_at` is set, attempt `rotation rollback` → refused (irreversible).

---

## 8. Backup / restore

1. `backup create` (separate backup password) → file never overwrites without the flag; AEAD-encrypted.
2. Tamper one byte of the backup payload or the format-version header → `restore`/`verify` fails (format version is bound into AEAD AAD).
3. `restore --force` over an existing vault → the current DB is renamed aside first (collision-safe unique name); run twice in the same second → neither aside is clobbered.
4. Restore a backup taken **before** a master-password change → it opens with the **old** backup password (documented); confirm the message says so.

---

## 9. Secret-leakage sweep (run after any change)

```bash
cargo test -p api-tracker-core --test security_residuals   # asserts no secrets in logs/errors
# Manual: exercise reveal/copy/export/scan/sync in --json mode and grep outputs for $FAKE
```
Expected: `$FAKE` appears only in the deliberate `key reveal` stdout and (masked) in scan previews — nowhere in errors, `--json`, Debug output, audit rows, or the DB in plaintext.
