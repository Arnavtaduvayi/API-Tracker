# Increment 03: Persistence and identity

**Mode:** S · **Size:** L · **Prerequisites:** 02 done

## Goal

Make the mesh durable and give each device a real, non-clonable identity:
- migration v21;
- a SQLite `MeshStore` that passes the full simulator suite;
- device keys encrypted under the vault key;
- crash-safe sequence allocation;
- the clone/rollback marker;
- the restore wipe.

It ships the first user-visible commands, `tethra mesh init` and `tethra mesh status`, so
a single device becomes a working one-device mesh.

## Read first

- DESIGN §D5, §D9 (commit semantics), §D12 (durability), §D17 and §D19 (MESH-SI-4/5/7).
- `crates/core/src/db.rs`: `MIGRATIONS`, `configure` (1347-1355), `migrate_with` (1365-1385), `open_at_current_version` (1401-1418), and the existing STRICT table style.
- `crates/core/src/backup.rs` (150-153, 508-645) and `crates/core/tests/migration_safety.rs`, the whole file. Then `scripts/smoke.sh:388`, which pins that file at exactly 9 tests.
- `crates/core/src/vault.rs`: `create_vault`, `UnlockedVault`, `verify_master_password`, and how `wrapped_gateway_mac_key` is created lazily (around 568-593). That is the closest pattern for "a lazily created key wrapped under the vault key". Read `crypto::aad` too.
- `apps/cli/src/lib.rs` (83-177, 204-239), `apps/cli/src/ctx.rs` (68-92), `apps/cli/src/backup_cmd.rs` and `apps/cli/tests/common/mod.rs`.
- The STATUS.md handoff notes for 02, which describe the `MeshStore` surface.

## Scope (build all of this)

### 1. Migration v21

Append it to `MIGRATIONS` in `crates/core/src/db.rs`. It creates **every** table in
DESIGN §D17 except the v22 columns, which come in 06:
- the local-only tables;
- `mesh_items` and `mesh_vv`;
- the materialized view tables;
- `ALTER TABLE gateway_config ADD COLUMN cap_enforcement INTEGER NOT NULL DEFAULT 0`.

Requirements:
- Every table is STRICT, with `CHECK` constraints for the enums.
- `mesh_project_bindings.local_project_id` references `projects(id) ON DELETE CASCADE`.
- Indexes: `mesh_items(kind, item_key)`, `mesh_items(origin, seq)` (the primary key), and
  `UNIQUE(kind, item_key, origin)`.
- Tables that a later increment will populate get a SQL comment naming that increment.

**Watch the background gateway.** It opens the database with `open_at_current_version`,
so once v21 lands, an *installed* older gateway refuses the newer schema. That is the
existing, documented upgrade behaviour. Confirm `CONTRIBUTING.md` covers it, and don't
change it.

### 2. `core::mesh::sqlite_store::SqliteStore`

It implements `MeshStore` on a `rusqlite::Connection` the node owns.

- **`commit`** runs in **one** `BEGIN IMMEDIATE` transaction: insert items
  (`INSERT OR IGNORE` plus a hash comparison for fork evidence), garbage-collect
  superseded rows, update the views, advance `mesh_vv`. Chunk large commits so each
  transaction stays under ~250 ms (D12). Each chunk advances the VV only for origins
  whose items it fully contains.
  - Design and document the chunking rule. The simplest correct one: split by origin,
    and advance an origin's VV only in the chunk that contains its last item.
- **`mint`** allocates seqs from `mesh_self.next_seq` with `PRAGMA synchronous=FULL` on
  this connection. It writes `mesh_meta.hlc_high_water` in the same transaction, and
  enforces the **marker file block allocation** (below) before using a seq past the mark.
- **Views** are maintained incrementally in SQL or Rust. `rebuild_views()` recomputes
  them from `mesh_items` (used by `doctor --rebuild` in 05 and by the conformance test).
- **Opaque storage** for unknown kinds (D6), plus `rematerialize(kinds)`.

### 3. Store conformance

`crates/core/tests/mesh_store_conformance.rs` (feature `mesh-sim`) runs the Increment 02
simulator with every node backed by a `SqliteStore` on its own temp file. Use fewer
seeds, about 30, so it finishes in under 90 s.

Add SQLite-specific faults:
- crash **between commit chunks**, by dropping the connection;
- reopen from disk;
- a `busy` contention test: a second connection holds a write lock for 1 s, and commits
  retry within `busy_timeout` without corrupting anything.

Make the simulator generic over a store factory. That way the same invariants and the
same oracle run against SQLite.

### 4. Identity (`core::mesh::identity`)

- **`init_mesh(vault, device_name)`**:
  - generates `mesh_id`, the access key (epoch 1), `device_id`, and the Ed25519, Noise
    and sealing keys;
  - encrypts the private keys and the access key under the vault key, with new
    `crypto::aad` constructors `mesh_sign_key`, `mesh_noise_key`, `mesh_seal_key` and
    `mesh_access_key(epoch)`, each bound to `vault_id` (D5);
  - mints the genesis `roster.add` (self, seq 1) and `device.info`;
  - writes the marker file.

  Use the X25519 key generation `snow` will accept in 04: 32 random bytes, clamped by
  x25519. Store the Noise public key *derived* from the private key, so 04 needs no
  conversion.
- **`load_keys(vault) -> MeshKeys`** returns `Zeroizing` buffers for the signing key,
  Noise key and access key. **It does not load the sealing key**: D5/MESH-SI-7 reserve
  that for the 11 import path.
- **The marker** lives at `<data-dir>/mesh/identity.marker` (D5): JSON
  `{device_id, marker_nonce, seq_high_water}`.
  - The directory is 0700 and the file 0600 (copy the permission helpers the vault
    already uses).
  - Writes are atomic: temp file, then fsync, then rename, then fsync the directory.
  - Seqs are allocated in blocks of 64.
  - `check_marker()` returns `Ok`, `Missing`, `Mismatch` or `RolledBack`, and the node
    (05) and `status` use it.
  - **Windows:** the permissions calls are cfg-gated the same way the vault does it.
    Document anything that differs.
- **`on_restore(conn)`** deletes all rows from every `mesh_*` table and resets
  `gateway_config.cap_enforcement` to 0.
  - Call it from `backup::restore_backup` right after `restore_v2` succeeds, before
    `session::destroy` and the audit record (`backup.rs:583-584`).
  - It also deletes the marker file, but only when the marker's `device_id` matches the
    wiped identity. Otherwise leave the file alone and report it.
  - Restore also works on v1 backups, which have no mesh tables; make that a no-op.
- **`leave_local_wipe(conn, data_dir)`** is the same wipe. 04 uses it for `mesh leave`.

### 5. Core API on `UnlockedVault`

`mesh_init(device_name) -> MeshSelfInfo` and `mesh_status() -> MeshStatus`. The status
covers:
- initialized or not;
- mesh id (short form);
- device id and name;
- `next_seq`;
- roster size and the device list;
- marker check result;
- VV, and items stored per kind;
- rejected-item, skew and fork counts.

Add audit event `mesh_initialized`.

### 6. CLI

Add `apps/cli/src/mesh_cmd.rs` with `MeshCmd::{Init { name }, Status}`, register it in
`lib.rs`, and support `--json` on both.

- `tethra mesh status` on an uninitialized vault prints a clear "not part of a mesh — run
  `tethra mesh init`" message, and exits 0.
- **No secrets** in output: no key bytes, and no access key.

### 7. `migration_safety`

It asserts that every table's row count survives a restore, and restore now wipes the
`mesh_*` tables. Add the documented `mesh_` exemption by **adjusting the existing
assertions**, keeping it at exactly 9 tests so `smoke.sh:388` still holds. Put the new
mesh restore tests in `mesh_schema.rs`.

### 8. Smoke

Add checks to `scripts/smoke.sh` in a new `-- mesh --` block:
- `mesh status` before init;
- `mesh init --name smoke-a`;
- `mesh status --json` shows initialized with a roster of 1;
- a backup, then a restore into a fresh dir, then `mesh status` shows not initialized.

## Out of scope

Networking and pairing (04), the node (05), publisher and caps (06/07).

## Tests to write

- **`crates/core/tests/mesh_schema.rs`:**
  - v21 applies on a v20 database;
  - every table is STRICT;
  - the enum CHECKs reject bad values;
  - deleting a local project cascades its binding;
  - the background `open_at_current_version` accepts v21;
  - **backup → restore wipes mesh state and mints nothing**;
  - a v1-backup restore is a no-op for mesh;
  - restore removes the marker only when it matches.
- **Identity:**
  - keys round-trip through the vault;
  - a different vault (a different `vault_id`) can't open the key blobs (AAD binding);
  - a corrupted blob gives a typed error;
  - `load_keys` never returns the sealing key;
  - `Debug` of every key type is redacted.
- **Marker:**
  - missing, mismatch (copy the database into another data dir), and rolled back
    (restore an older `next_seq`) are each detected;
  - block allocation fsyncs the marker before handing out seq mark+1. Use a test hook
    that counts marker writes.
- **SQLite store:**
  - `commit` atomicity: inject a failure after the item insert and before the VV update,
    and nothing is visible;
  - the fork-evidence path;
  - superseded rows are garbage-collected but `roster.*`/`cap.def` are kept;
  - `rebuild_views()` equals the incremental views after random workloads;
  - opaque unknown kinds are stored, then rematerialized.
- **Conformance**, as described in scope item 3.
- **CLI** (`apps/cli/tests/mesh_cli.rs`, hermetic env per `apps/cli/tests/common/mod.rs:50-69`):
  - init/status in human and `--json` form;
  - double init is refused with `AlreadyInMesh`;
  - the output contains none of the fake key patterns. Use a test-only env hook to
    inject a known key, *or* assert that no 64-hex run appears.

## Acceptance criteria

- [ ] The full simulator invariant suite passes against `SqliteStore` (conformance test green).
- [ ] MESH-SI-4 (Commit-only VV), MESH-SI-5 (no identity reuse) and MESH-SI-7 (the sealing key is never loaded) each have named tests, listed in SECURITY_INVARIANTS.md.
- [ ] `tethra mesh init` and `tethra mesh status` work end to end in a temp `TETHRA_DIR`, and smoke passes with the new mesh block.
- [ ] `migration_safety` still has exactly 9 tests and passes. `smoke.sh:388` is unchanged and passes.
- [ ] The check suite is green.

## Verification commands

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --test mesh_schema --test migration_safety
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --features mesh-sim --test mesh_store_conformance
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-cli --test mesh_cli
# manual, isolated:
export TETHRA_DIR="$(mktemp -d)/tethra" TETHRA_INSECURE_FAST_KDF=1 TETHRA_PASSWORD='fake-pass-for-mesh-dev-1'
cargo run -p api-tracker-cli -- init         # creates the vault (min password length 12; see smoke.sh:50-56)
cargo run -p api-tracker-cli -- mesh init --name dev-a && cargo run -p api-tracker-cli -- mesh status --json
bash scripts/smoke.sh
```

## Docs to update

- `docs/mesh/ARCHITECTURE.md` (storage section).
- `docs/mesh/PROTOCOL.md` (persistence and durability notes).
- `docs/mesh/SECURITY_INVARIANTS.md`.
- `docs/mesh/TEST_PLAN.md`.
- `docs/mesh/KNOWN_LIMITATIONS.md` (Windows marker permissions, if they differ).
- ADR 0006 / 0015 cross-reference: restore wipes mesh state. Add a short "Amended by
  ADR 0031" note at the end of ADR 0015.
- `CHANGELOG.md`.

## Handoff checklist

- [ ] STATUS.md row 03 `done`. Record the exact v21 table list and any column decisions
      that differ from D17.
- [ ] Handoff notes: how 04 obtains `MeshKeys` from an unlocked vault and where the
      roster's Noise public keys live.
