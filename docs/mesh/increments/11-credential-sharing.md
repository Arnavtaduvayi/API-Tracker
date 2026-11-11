# Increment 11: Opt-in encrypted credential sharing

**Mode:** S+R, single session plus a security-review subagent before the final commit · **Size:** L · **Prerequisites:** 10 done

## Goal

The user can explicitly share **one specific credential** with specific paired devices.
Each share is sealed to each recipient's sealing key and signed by the sharer. A
recipient imports it, after reauthentication, into a local project, where it is
re-encrypted under that project's key.

Nothing is automatic. The credential value never appears in plaintext on the wire, in
logs, in errors or in storage outside the vault's existing encrypted column. This is the
only increment where credential values cross devices, and it is held to the strictest
bar.

## Read first

- DESIGN §D5 (the sealing key is only unwrapped inside import), §D16, §D18 and §D19 (MESH-SI-6/7).
- `CLAUDE.md` "Security requirements" (the whole section), plus `SECURITY.md` and `THREAT_MODEL.md`.
- `crates/core/src/vault.rs`:
  - `add_credential` (around 1426) and the update/version path (`credential_versions`);
  - `set_project_password` and the `vault+password` mode (around 1094-1155): how a
    password-locked project is unlocked;
  - `verify_master_password`.
- `crates/core/src/secret.rs` (`SecretString`/`SecretBytes`), and `crates/core/src/destinations.rs:1546-1557` (the existing `crypto_box` sealing usage).
- `crates/core/tests/security_residuals.rs` and the existing leakage tests (grep for `FAKE_KEY` and "never appears").
- The STATUS.md handoff notes for 10.

## Scope (build all of this)

### 1. Core (`core::mesh::share` plus `UnlockedVault` methods)

**`mesh_credential_share(master_password, credential_id, recipients: Recipients) -> ShareReceipt`**

- `Recipients` is `AllCurrent` or `Devices(Vec<DeviceId>)`.
- Requires reauth.
- The credential's project must be bound to a mesh project, otherwise
  `MeshError::Bound(NotBound)`.
- Password-locked projects also need that project unlocked in the current
  `UnlockedVault`.
- Recipients are non-removed roster members other than self.
- For each recipient it builds the plaintext JSON
  `{mesh_id, share_id, credential_name, provider, value_version, recipient, sharer, value}`
  in a `Zeroizing` buffer, seals it with `crypto_box` to `recipient.seal_pub`, and mints
  `share.sealed` (D16). The value is exposed only inside this function.
- Records the "all current devices" intent for reseal.
- Audit event: `mesh_credential_shared` with the credential id, never its value.

**`mesh_shares_list()`**

- Incoming: available to import here. Outgoing: what I shared, and with whom.
- Each entry shows credential name, provider, sharer device, version, imported (yes or
  no) and revoked.
- **No values.**

**`mesh_credential_import(master_password, share_id, local_project_id) -> CredentialId`**

1. Requires reauth.
2. Unwraps the **sealing private key** for the duration of the call only (MESH-SI-7),
   then opens the box.
3. **Verifies every bound field** against the signed outer item and the signer:
   `mesh_id`, `share_id`, `recipient == self`, `sharer == item origin`,
   `credential_name`, `provider` and `value_version`. Any mismatch is
   `ShareBindingMismatch`, and nothing is imported.
4. Stores the value through the **existing** add-credential path. If a same-named
   credential exists in the target project, use the existing update or version path,
   with an explicit `--replace` flag or confirmation.
5. Records a row in the local-only `mesh_share_imports` table (created by v21 in
   Increment 03; DESIGN §D17). If 03 didn't create it, add a migration v23 and keep
   `migration_safety` at 9.
6. Audit event: `mesh_credential_imported`.

**`mesh_credential_revoke(share_id | credential_id)`**

- Mints `share.revoke` tombstones.
- The UI/CLI states plainly that revoking a share does **not** revoke the credential at
  the provider, and links to the rotation flow.

**Reseal** (in the node round hook, only while unlocked)

- For shares made with `AllCurrent`, when a new roster member appears, queue a reseal
  **offer**: shown in `mesh status` and the desktop, and requiring reauth to perform.
- It never reseals automatically, because that would need the value in memory unattended.

**Purge**

- Shares addressed to removed devices are dropped from views and garbage-collected from
  `mesh_items` once the removal is known.
- LWW per `(credential_ref, recipient)` keeps only the latest share.

### 2. CLI

- `tethra mesh credential share <credential> [--to <device>…]`: reauth, plus a
  confirmation that names the recipients.
- `tethra mesh credential list`.
- `tethra mesh credential import <share> --project <local> [--replace]`: reauth.
- `tethra mesh credential revoke <share|--credential <id>>`: confirmation.

Output **never** prints a value. Import prints the masked value only, using the existing
masking helper.

### 3. Desktop

- `mesh_cmds.rs` gains the share, list, import and revoke commands, with authz tests.
- **The credential detail** (`CredentialDetail.tsx`) gets "Share with my devices…":
  ReauthDialog → recipient checklist → confirm.
- **The Devices page or project page** gets an "Incoming shared credentials" list with
  Import (ReauthDialog → choose the local project → confirm).
- Revoke.
- The "Revoking doesn't rotate" notice links to the existing Rotation view.

Do this in the same session; it's small. If context runs short, the desktop part may
move to 12 with a STATUS note. The CLI and core parts may not move.

### 4. ADR 0033: credential sharing

Covers:
- the construction (signed outer item plus an anonymous sealed box with bound fields)
  and why the bindings are needed;
- the reauth points;
- no auto-import or auto-reseal;
- no forward secrecy;
- recipients keep what they imported;
- revocation semantics;
- the alternatives:
  - a shared mesh symmetric key, rejected: revocation and blast radius;
  - per-share ephemeral ECDH with a double ratchet, rejected: complexity, and the
    recipients are the user's own devices;
  - replicating vault ciphertext with shared project keys, rejected: couples the key
    hierarchies.

## Execution workflow (S+R)

Implement and test everything. **Before the final commit**, run the README §4 review
with a security focus:
- the binding verification is complete;
- the sealing key's lifetime;
- `Zeroizing` on every plaintext buffer;
- error paths that might include values (serde errors echo input!);
- logs, JSON and audit;
- a password-locked project bypass;
- a removed device can't receive new shares;
- a member can't plant a credential into another device's vault;
- replaying an old share after revoke.

Fix confirmed findings test-first.

## Tests to write

- **`crates/core/tests/mesh_share.rs`:**
  - share then import round trip on two in-process vaults, via the simulator store or a
    real two-node setup;
  - wrong password on share or import → `WrongPassword` with nothing changed;
  - not bound → error;
  - password-locked project, locked → refused; unlocked → OK;
  - recipient restriction (C didn't receive anything);
  - **planting attack**: device B crafts a `share.sealed` addressed to C but signed by B
    while claiming sharer A → rejected;
  - **binding mismatch** for each field → `ShareBindingMismatch`;
  - a revoked share can't be imported, and a replayed old share after revoke is ignored
    (LWW);
  - shares to removed devices are purged;
  - the reseal offer appears for a new member and performs nothing without reauth;
  - `--replace` / versioning behaviour.
- **Leakage canaries** (MESH-SI-6), using a unique fake value such as
  `sk-test-FAKE-mesh-canary-…`:
  1. **Wire capture.** In `crates/mesh/tests/share_wire.rs`, a TCP shim between two
     nodes records every byte. The canary never appears in those bytes, nor in base64,
     hex or JSON-escaped forms of it.
  2. **Storage.** It never appears in `mesh_items.bytes` in plaintext, nor in any
     plaintext column of any table (scan every table and column after import). The only
     place it exists is the vault's encrypted credential column, which you verify by
     decrypting through the normal API.
  3. **Logs, errors, output.** It never appears in any `MeshError`/`CoreError` Display or
     Debug output produced in the tests, in CLI stdout/stderr (`--json` and human), in
     audit rows, or in `doctor` output.
- **Desktop:** vitest for the share and import dialogs (reauth required, no value
  rendered), plus authz tests.

## Acceptance criteria

- [ ] Share and import work end to end via the CLI between two real nodes, and via the desktop (or STATUS records the desktop part as moved to 12).
- [ ] Every canary test passes. MESH-SI-6/7 are marked implemented with test names.
- [ ] Planting and binding-mismatch attacks are rejected.
- [ ] ADR 0033 is written, and the review was run with findings resolved.
- [ ] The full suite and smoke are green (add a smoke check: share, then import across the two temp nodes, then the masked value is shown).

## Verification commands

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --test mesh_share --test tauri_command_authz
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-mesh --test share_wire
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-cli --test mesh_cli
bash scripts/smoke.sh
# plus the full README §3 suite and the desktop checks
```

## Docs to update

- ADR 0033.
- `docs/mesh/PROTOCOL.md` (the share section), `SECURITY_INVARIANTS.md`,
  `THREAT_MODEL.md` and `KNOWN_LIMITATIONS.md`.
- `docs/mesh/USER_GUIDE.md`: when to share, how to import, what revoke does and doesn't
  do.
- `SECURITY.md` and `THREAT_MODEL.md` (root): the credential-sharing paragraph.
- `CHANGELOG.md`, under the `### Security` heading where appropriate.

## Handoff checklist

- [ ] STATUS.md row 11 `done`, with the review summary.
- [ ] Handoff notes: anything moved to 12, and the list of every reauth-gated mesh
      method, which 12's auditors need.
