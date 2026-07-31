# Legacy rollback encryption (ENC-01) and ENC-02 — independent evidence

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`.

## 1. The migration itself — `upgrade_restore_records`

`crates/gateway/src/envlink.rs:1231`, wrapping `scrub_stored_prior_env_once`
(`:1108`) and `scrub_stored_prior_env` (`:1273`).

| Required property | Verdict | Evidence |
| --- | --- | --- |
| Transactional | **PASS** | `envlink.rs:1148` `BEGIN IMMEDIATE`; rewrites + all three `vault_meta` writes inside; `COMMIT :1170`; `ROLLBACK :1183`. `IMMEDIATE` (not `DEFERRED`) takes the write lock up front, so a racing writer gets `Busy`, not a lost update. |
| Idempotent | **PASS** | Marker `envlink_prior_scrub_v1` in `vault_meta` (`:1192`), checked at `:1232-1245` and `:1112-1121`. Pinned by `the_migration_is_idempotent_and_does_not_rescan_once_complete`. |
| Plaintext removed only AFTER the encrypted replacement commits | **PASS** | No delete-then-write. `:1311-1314` is a single in-place `UPDATE … SET prior_env_json = ?2` with the already-sealed document, inside the outer transaction. Old bytes are released at `COMMIT`. |
| Interrupted migration resumes safely | **PASS** | Single transaction ⇒ no marker without the rewrites. The no-key path returns early at `:1127-1129` **without** setting the marker, so a locked start cannot claim completion. |
| Corrupt rows fail safely | **PASS** | `:1290-1295` — unparseable JSON and future-version records `continue`; the row is left byte-identical, never destroyed. |
| Completion recorded | **PASS** | `:1192-1194` records marker, version and row count. |
| Does not rerun unnecessarily | **PASS** | One `vault_meta` SELECT per unlock after completion. |
| Undo still restores correctly | **PASS** | Round-trip covered; `UNDO` group in the packaged run restores the `.env` byte-for-byte (`cmp`, not string equality). |

### Real production call sites (ENC-01)

| Call site | Runs the migration? |
| --- | --- |
| `apps/cli/src/ctx.rs:71` (session-token unlock) | **Yes** |
| `apps/cli/src/ctx.rs:80` (`TETHRA_PASSWORD` unlock) | **Yes** |
| `apps/desktop/src-tauri/src/main.rs:273` (`vault_unlock`) | **Yes** |
| `apps/cli/src/vault_cmd.rs:54` (`tethra unlock`) | No |
| `apps/cli/src/track_cmd.rs:133` (`track`'s interactive password fallback) | No |
| `main.rs:235` (`vault_create`) | No — new vault, correct |

**The ENC-01 fix is real**: the desktop call site exists and is on the main
`vault_unlock` path, which is the GUI-only persona's only way in. The two
misses are CLI paths that are covered incidentally (the next command goes
through `Ctx::unlocked`). Recorded as `NEW-07`, low.

### Regression coverage is a source-text grep

`crates/gateway/tests/legacy_rollback_migration.rs:432-466` —
`both_front_ends_call_the_shared_migration` reads
`apps/desktop/src-tauri/src/main.rs` as a **string** and asserts
`.contains("envlink::upgrade_restore_records")` inside the `vault_unlock`
body. The test's own comment concedes this.

It is a real guard against the exact defect ENC-01 was (a *missing* call
site — something no unit test can observe). But it pins the **token**, not the
**behaviour**: the call could be moved behind an always-false condition and
the test would still pass. **No test anywhere drives the Tauri command at
runtime.** There is no `apps/desktop/src-tauri/tests/` and no WebDriver
harness. Stated plainly, as required.

## 2. ENC-02 — independently confirmed, mechanism traced end to end

The remediation reports ENC-02 as **unresolved**. I verified every link of
the claim in source.

**Step 1** — `PriorVar.prior_withheld` is `#[serde(default)]`
(`envlink.rs:94-95`), so an absent field deserialises to `false`.

**Step 2** — `open_prior_file` (`envlink.rs:172-174`):

```rust
if var.sealed.is_none() && var.sealed_all.is_empty() {
    continue; // v1 record: `prior` / `prior_all` already hold it
}
```

Strip `sealed` from the plaintext envelope and the record falls through as a
legacy v1 record with `prior: None` — the keyless branch that *would* set
`prior_withheld = true` (`:176-179`) is never reached.

**Step 3** — `restore_file` (`envlink.rs:1553-1580`):

* the honest `PriorNotRecorded` arm requires `var.prior_withheld` ⇒ **not taken**
* `(Some(cur), prior) if *cur == var.written` ⇒ **taken**, `prior` is `None`
  ⇒ `doc.remove_with_comment(&var.key)` — **the line is deleted** — and pushed
  as `RestoreOutcome::Restored`

So `undo` **deletes the user's configuration line and reports it as
restored**, with `complete: true`, and then removes the link row — the only
surviving structural record.

The author documented this exact hazard and defended only the *keyless* case
(`envlink.rs:161-164`): *"deleting a line whose value we merely could not read
would destroy the user's configuration."* The tampered-field case reaches the
same destructive branch by a different route.

### The asymmetry that makes this notable

| Table | MAC'd? | Failure mode |
| --- | --- | --- |
| `gateway_routes` | **Yes** — `custom_origin_mac`, keyed BLAKE3, `tethra:gateway-route-mac:v2` (`routes.rs:128-148`), constant-time verify (`:696-712`) | `Unforwardable(MacMismatch)` — fail closed |
| `tracking_approved_origins` | **Yes** — `origin::approval_mac`, `tethra:origin-approval-mac:v1` (`origin.rs:241-258`) | Row treated as **absent** — ask again |
| `gateway_project_links.prior_env_json` | **No** — schema `crates/core/src/db.rs:920-928` has no MAC column | Silently obeyed |

The gateway compartment opens `vault.db` **read-write** (`writer.rs:519` →
`db.rs:1172` `Connection::open`, default `READ_WRITE|CREATE`) with the
env-restore key **withheld by design** (ADR 0019 D4; `vault.rs:605-607`).
SQLite has no per-table permissions, so the handle that writes usage rows can
write `gateway_project_links`.

That adversary — Tethra's own loopback HTTP listener, deliberately
least-privileged — is exactly who the *other two* tables are MAC'd against.
`prior_env_json` is the one left unprotected, and it is the one whose
tampering causes **filesystem destruction**.

Blast radius: `unlink` is driven in a loop over all links by `gateway disable`
/ `uninstall` (`lifecycle/mod.rs:722-741`).

### Does documentation contradict it?

I checked the three passages flagged during this audit and **disagree with two
of them**:

* `THREAT_MODEL.md:157` — *"AEAD + per-record associated data detect value
  tampering, truncation, and ciphertext swapping between records."* The **same
  row** continues: *"Metadata edits … are NOT cryptographically detected."*
  Removing an unauthenticated JSON field from a plaintext envelope is a
  metadata edit, and the row discloses that. **Not a false claim**, though it
  does not call out that this particular metadata governs a destructive write.
* `KNOWN_LIMITATIONS.md:250-253` — describes the **lost-password / keyless**
  case, where `prior_withheld` *is* set and `unlink` *is* honest. **Accurate
  for its stated scenario.**
* `crates/core/src/envrestore.rs:25-29` — *"What stays in the clear is
  deliberately only the structure: … whether a value was recorded at all."*
  This is a statement about **confidentiality**, not integrity, and it is
  true: the fact is in the clear. Mildly imprecise (there is no `had_prior`
  field; the fact is inferred from `sealed`'s presence) but not a false
  security claim.

**Conclusion: no shipping document makes a protection claim that ENC-02
disproves.** What is missing is a `KNOWN_LIMITATIONS.md` entry for ENC-02
itself. Recorded as `NEW-06`, low, documentation-only.

### Merge-blocking assessment for ENC-02

**Not merge-blocking.** It requires a prior local-write compromise, and
`THREAT_MODEL.md:159` declines to defend against malware running as the user.
It is destructive, not exfiltrating; the AEAD still fails closed against
ciphertext modification (only the *absence* of the field is unprotected).

**But the deferral's reasoning understates it.** The matrix calls the attacker
"the same local-write attacker as SEC-01". The gateway compartment is not an
external attacker — it is a component the design deliberately distrusts, and
two neighbouring tables are hardened against precisely it. The fix is small
(`had_prior: bool` + a keyed MAC mirroring `route_mac`) and should land next.

## 3. Plaintext canaries

The packaged run's `PRIVACY` group (5 checks, all passing on the exact head)
searches the whole isolated data directory:

```
PASS  the searched inventory is non-empty and includes the vault database
PASS  the API key value appears in no file under the isolated data directory
PASS  the unrelated env value (canary) appears in no file under the isolated data directory
PASS  no authorization header line and no bearer token is stored
PASS  neither needle reached the shared desktop/CLI data directory (it does not exist)
```

Crate-level canaries also pass locally (from `cargo test --workspace`):
`no_canary_survives_the_real_persistence_path`,
`no_canary_survives_a_live_exchange_into_any_artifact`,
`no_env_value_canary_survives_the_link_writers_restore_record`,
`the_matching_key_never_reaches_disk_argv_or_environ`.

**One caveat on the "no bytes left behind" claim.** `checkpoint_truncate`
(`crates/core/src/db.rs:1206-1208`) is `let _ = …` — errors swallowed — and
runs *after* `COMMIT` (`envlink.rs:1179`). If the checkpoint fails (a
concurrent reader pinning the WAL is the realistic case), the completion
marker says done, the migration never re-runs, and legacy plaintext can remain
in `vault.db-wal`. The documentation states the guarantee unconditionally.
Recorded as `NEW-08`, low.
