# CRYPTO-01 / CONC-03 — Resolution (Phase 3)

**Model:** Fable 5 (`claude-fable-5`). **Audited production commit:** `7d81090a1068476291546963e68ca8c7de1a7145`.
**Verdict:** CONFIRMED — reproducible concurrent data-loss (silent, permanent) plus a sticky rotation wedge.
**Evidence class:** deterministic reproduction (25/25) **and** rigorous transaction/state proof **and** deterministic control proving the defense works on the coarse case (5/5).

---

## 1. The contradiction being resolved

- Initial (orchestrator) review — `evidence/MY_FINDINGS.md:15` — asserted the cached project key's BLAKE3 wrap-hash "defeats stale-key-after-concurrent-password-change race" and listed the key hierarchy as **SOLID**.
- Later reviewers filed **CRYPTO-01** (`all_findings.tsv:78`, Medium/CONFIRMED) and **CONC-03** (`all_findings.tsv:74`, Medium/CONFIRMED): a concurrent project-key rotation during `add`/`replace` writes ciphertext under a key whose wrap has been destroyed → permanently undecryptable, and later rotations of that project fail.

These are **the same root cause** (dedup: CRYPTO-01 ≡ CONC-03; canonical id **CRYPTO-01**). Both prior conclusions are *partially* correct. The resolution is a precise statement of *which case each covers*.

## 2. Mechanism (source, `crates/core/src/vault.rs` @ 7d81090)

Project-key cache and freshness check:

```
468:  project_keys: HashMap<String, (SecretBytes, [u8; 32])>   // project_id -> (key, blake3(wrap))
846:  fn project_key_for_row(&self, row: &ProjectRow) -> Result<SecretBytes>
863:      if blake3::hash(&row.wrapped_project_key).as_bytes() != wrap_hash { return ProjectLocked }
```

The freshness check compares the cached wrap-hash against **`row.wrapped_project_key` — the row the caller passed in**, not a guaranteed-fresh read taken under the write lock.

Rotation (`set_project_password` / `remove_project_password`) is atomic and destructive:

```
945:  let tx = self.conn.unchecked_transaction()?;                 // BEGIN
946:  rotate_project_key(&tx, ...)   // generate K_new; re-encrypt EVERY value+version under K_new (884-920)
957:  UPDATE projects SET wrapped_project_key = W_new, key_wrap_mode='vault+password', ...
968:  tx.commit()                                                  // COMMIT  (old wrap W_old / K_old now gone)
981:  db::checkpoint_truncate(...)                                 // WAL remnants of W_old removed
```

The writers are **NOT** transactional and do **NOT** re-validate freshness at the write:

```
add_credential (1204-1275):
  1208:  project = project_row_by_ident(...)          // READ project row  -> snapshot W_old  [T1]
  1228:  project_key = project_key_for_row(&project)  // freshness vs the T1 snapshot -> K_old
  1236:  ciphertext = encrypt(K_old, value)           // encrypt under K_old
  1244:  conn.execute("INSERT INTO credentials ...")  // WRITE (autocommit)                    [T3]
         (no BEGIN/COMMIT around 1208..1244; no re-read of the project row)

replace_credential_value (1652-1714):  identical shape
  1671:  project = project_row_by_ident(&row.project_id)
  1672:  project_key = project_key_for_row(&project)  // -> K_old (snapshot)
  1689:  retain_credential_version(...)               // retains OLD value under K_old too
  1693:  UPDATE credentials SET ciphertext=... value_version=...  // WRITE under K_old
```

### The window
Between T1 (1208 read) and T3 (1244 write) there is no lock held and no re-check. A concurrent rotation that **commits** in that window:
1. re-encrypts all *existing* rows to `K_new`, sets `projects.wrapped_project_key = W_new`, destroys `W_old`, checkpoints the WAL;
2. leaves the racing writer still holding `K_old` in a local and about to `INSERT` under it.

SQLite serializes the physical writes (single writer), so T3 lands *after* the rotation commit — but the INSERT is a bare row write; nothing re-derives or re-checks the key. Result: the new row is ciphertext under `K_old`, and `K_old` has no wrap anywhere.

### Consequences (both proven, §4)
- **Permanent unrecoverability.** `reveal_credential` (1487-1494) reads a fresh project row (`W_new` → `K_new`) and `decrypt(K_new, ct_under_K_old)` → `CoreError::Crypto`. No path reconstructs `K_old`.
- **Sticky wedge.** `rotate_project_key` (885-900) decrypts *every* credential under the current key; the orphan fails at 894, so the whole transaction aborts — **all future `set_project_password` / `remove_project_password` on that project fail**. The recovery mechanism is itself broken by the loss.
- **Silent.** `add_credential` returns `Ok`; the user believes the credential was saved.

## 3. Why the freshness check does NOT close it (and what it DOES close)

The BLAKE3 wrap-hash catches the **coarse / sequential** case: if the write's *row read* happens **after** the rotation commit, the caller reads `W_new`, `blake3(W_new) != cached hash(W_old)` → `ProjectLocked`, and **no bad data is written**. That is the case the first reviewer verified as SOLID — and it is genuinely solid (control run, §4, 5/5 refused).

It does **not** cover the **intra-operation TOCTOU** case: the row read at T1 legitimately matches the cache (both `W_old`), so the check passes; the rotation then commits before T3. The check is evaluated against a pre-rotation snapshot and never re-run inside the write, so it has no bearing on a write that straddles the commit.

## 4. Evidence

Standalone harness (audit-only, **no repository file modified**): `harness_main.rs`, `harness_Cargo.toml` (a scratchpad crate path-depending on `crates/core`, exercising the real production key-management code via public API; a raw/held write lock is not needed — B's rotation itself holds the single SQLite write lock while re-encrypting a padded credential set, deterministically parking A's INSERT behind it). Full output: `repro_run.log`; environment: `harness_context.txt`.

- **RACE mode** (rotation commits inside the add window): **25/25 ORPHANED**, each with `add=Ok`, `reveal(cnew)=Crypto`, `c0_ok=true` (loss scoped to the raced write), `rotate_wedge=true` (subsequent rotation fails). Deterministic across the batch.
- **CONTROL / DEFENSE mode** (rotation commits before the add reads the row): **5/5 refused via freshness check** — no data written. Confirms the defense works on the coarse case.

Reproduction is deterministic (controlled interleave via the rotation's own lock hold), not a probabilistic timing race. The `replace_credential_value` path is covered by the identical transaction proof (§2); the harness exercises `add_credential`.

## 5. Final finding record

- **Finding ID:** CRYPTO-01 (consolidates CONC-03).
- **Title:** Concurrent project-key rotation during `add_credential` / `replace_credential_value` persists ciphertext under an orphaned key — silent permanent data loss that also wedges future project-key rotation.
- **Category:** Concurrency / data-loss (integrity).
- **Severity:** Medium. **Impact: High** (silent, permanent loss of a stored secret **and** breakage of the recovery/rotation path). **Likelihood: Low–Moderate** — requires two processes writing the same vault (the desktop+CLI shared-vault configuration the product supports) with a project password set/change/remove committing inside the ~sub-second add/replace window on the same project. Per the audit rule, **not** downgraded merely because timing is required; the timing is deterministically winnable and the trigger is a supported configuration.
- **Confidence:** High.
- **Affected commit:** 7d81090. **Platforms:** all.
- **Affected symbols:** `add_credential` (1204-1275), `replace_credential_value` (1652-1714), `project_key_for_row` (846-870), `rotate_project_key`/`set_project_password`/`remove_project_password` (878-1010, 1049-1110).
- **Expected:** a write and a concurrent key rotation on the same project either serialize safely or the losing operation fails loudly; no committed ciphertext should be unrecoverable.
- **Actual:** the write commits ciphertext under the destroyed old key; reveal fails permanently; rotation wedges.
- **Existing defenses:** BLAKE3 wrap-hash freshness (closes the coarse case only); SQLite single-writer serialization (orders the physical writes but does not re-validate the key).
- **Recommended remediation (design only; NOT implemented this session):** perform read-of-wrap → encrypt → write **inside one `IMMEDIATE` transaction** for `add_credential` / `replace_credential_value`, re-reading `projects.wrapped_project_key` inside that transaction and re-checking the wrap-hash immediately before the INSERT/UPDATE (so a rotation that committed earlier is detected → clean `ProjectLocked`, and a rotation cannot commit between the check and the write because the writer already holds the write lock). Alternatively, make rotation and value-writes take a shared advisory row/version guard (compare-and-swap on a `projects.key_generation` counter carried in the write's WHERE clause). Add a regression test mirroring this harness.
- **Regression test:** deterministic concurrency test (this harness) asserting: raced write is refused OR remains recoverable; never orphaned; rotation never wedged.
- **Verification provenance:** Fable 5 primary review — source proof + deterministic reproduction (25/25) + deterministic defense control (5/5).
- **Related:** CONC-04 (backup snapshot non-transactional, same class), CONC-01/02 (mutex/auto-lock), ROT-004 (rotation destructive steps don't re-verify version).
