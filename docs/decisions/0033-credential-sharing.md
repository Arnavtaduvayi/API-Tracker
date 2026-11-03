# ADR 0033 — Credential sharing: one credential, sealed to chosen devices, imported on request

Status: accepted (Increment 11 on `feat/device-mesh`)
Date: 2026-11-03
Builds on: ADR 0031 (Tethra Mesh), PROTOCOL.md §2.4 and §5.7 (the share kinds)
Preserves: CLAUDE.md "Security requirements" (reauthentication before a secret
is revealed, copied, exported or changed; no plaintext at rest; no values in
logs or errors), ADR 0020 (keys only while unlocked), MESH-SI-6, MESH-SI-7,
MESH-SI-13

## Context

A developer with a laptop and a desktop wants the same OpenAI key on both
without pasting it through a chat app or a cloud note. Tethra Mesh already
replicates signed items between the user's own paired devices, end to end
encrypted, with no server. Until this increment no item carried a credential
value, on purpose: the owner chose "usage, metadata and caps first; credentials
last and opt-in" (DESIGN §D1). This ADR is the one place credential values
cross devices, so it is held to the strictest bar: nothing automatic, a
reauthentication at every point a value or a key is touched, and an honest
account of what revocation cannot do.

## Decision

1. **Opt-in, one credential at a time.** `UnlockedVault::mesh_credential_share`
   (CLI `tethra mesh credential share`, desktop "Share with my devices…")
   shares exactly one credential with either *all my current devices* or an
   explicit list. It requires the master password. The credential's project
   must be bound to a mesh project (`MeshError::ProjectNotBound` otherwise),
   and a password-locked project must be unlocked in this session (the vault's
   ordinary `ProjectLocked`). A reference record is refused (share the
   credential it points to). Recipients must be active members other than this
   device.

2. **Construction: a signed outer item around an anonymous sealed box with
   bound fields.** For each recipient the sharer mints one `share.sealed` item
   (key `<credential_ref>/<recipient>`), signed by the sharer like every item,
   whose payload carries the share id, mesh project, credential name,
   provider, value version, recipient and `sealed`:
   `crypto_box` sealed box (X25519 + XSalsa20-Poly1305, the crate already used
   for GitHub secrets) to the recipient's **sealing** public key, a key pair
   separate from the Noise and signing keys (DESIGN §D5). The plaintext is JSON
   `{mesh_id, share_id, credential_name, provider, value_version, recipient,
   sharer, value}`, written into a zeroizing buffer reserved large enough
   never to reallocate.

   **Why the bindings.** A sealed box is anonymous: anyone holding the
   recipient's public key can make one, and the box says nothing about who did.
   The signature on the outer item says who minted the *item*, not who made
   the *box*. So after opening, the recipient checks every field the plaintext
   repeats against the signed envelope and its signer
   (`share::verify_bindings`): the mesh, the share id, the recipient (this
   device), the sharer (the item's origin), the credential name, the provider
   and the value version. Any mismatch is `ShareBindingMismatch(<field>)` and
   nothing is imported. Without the check, member B could (a) seal a value of
   its own to C claiming A shared it, or (b) copy A's genuine box for C into an
   item of its own under another name, and plant a credential in C's vault
   attributed to someone else. Both are tested
   (`mesh_share::a_member_cannot_plant_a_credential_in_the_name_of_another_device`).

3. **Reauthentication points.** Share, reseal and import each call
   `verify_master_password` inside the core method before any value or key is
   read. The CLI, the Tauri wrapper and React never repeat or replace the
   check (`tauri_command_authz::mesh::mesh_credential_share_import_and_reseal_require_correct_reauth`).
   Listing and revoking need an unlocked vault only: they touch no value.

4. **The sealing private key lives only inside an import** (MESH-SI-7).
   `identity::load_seal_key` unwraps it (checked against its public key),
   `share::open_incoming` opens the box with it through `crypto_box::SecretKey`
   (zeroized on drop), and both are dropped before the value is stored. A
   running node never holds it, so it can never open a share unattended.

5. **Import stores through the existing credential paths.**
   `mesh_credential_import(master_password, share, local_project, {replace,
   environment})` opens and verifies the share, then calls the vault's own add
   path (a new credential, encrypted under the target project's key, its
   fingerprint and reuse warnings as usual) or, with `replace`, the existing
   replace-and-version path (the old value kept as a version, `value_version`
   bumped). The local `mesh_share_imports` row and the
   `mesh_credential_imported` audit event commit in the same transaction as
   the credential. Without `replace`, a same-named credential in the target
   project is a refusal that says how to replace it; with it, a same-named
   credential of another provider is still refused (the name comes from
   another device and must never pick what to overwrite). A share already
   imported here is refused. Likewise the share's and the revoke's audit rows
   commit in the transaction that mints the items.

6. **Nothing automatic: no auto-import, no auto-reseal** (MESH-SI-13).
   Shares wait until the user imports one. A share to *all my current devices*
   records that intent locally (`mesh_share_outgoing`, migration v24). When a
   device is paired later, or when the credential's value changes (a rotation
   or a replace), the sharer shows a **reseal offer**
   (`share::reseal_offers`, in `mesh credential list`, `mesh status` and on
   the credential page). Performing it (`mesh_credential_reseal`) needs the
   master password, because it needs the value in memory. The node never
   reseals: it would have to hold the value unattended.

7. **Lifecycle.**
   - Last-writer-wins per `(credential_ref, recipient)` among shares: the
     winning share is the admitted `share.sealed` with the greatest
     `(hlc, origin)`, and it is revoked exactly when an admitted
     `share.revoke` names its share id, whatever their HLCs (PROTOCOL.md §5.6,
     amended in this increment by the review: under "greatest `(hlc, origin,
     rank)` over both kinds", a revoke of an older share, written by a device
     that had not seen a newer one, hid the newer share).
   - `share.revoke` is a tombstone naming the share id. Replaying an old
     `share.sealed` changes nothing: the store already holds that entry or a
     later one of its origin. A device revokes only shares **it** made (never
     a share between two other devices that it relays); `revoke --credential`
     covers every live share of it. Revoking one share of an *all current
     devices* credential turns the intent into an explicit list, so no reseal
     offer brings that device back.
   - A share from a device that is no longer active (removed or forked) is
     listed but not imported, even when it is within the removal cutoff: the
     device may have been removed because it was lost or stolen.
   - The sharer lists its shares from its own entries, so another member's
     item at the same key never hides them; it sees the share replaced at the
     recipient and gets a reseal offer.
   - Shares addressed to a removed device are hidden by the views and
     collected from storage (PROTOCOL.md §8.4 (b)): a production store drops an
     arriving one at ingest, and `share::purge` (every node round, and before
     `mesh credential list`) deletes held ones. Removal is forever, so this
     exclusion does not depend on seq.

8. **Bounds.** A shared value is at most 15 KiB, and the sealed box must fit
   the 16 KiB a `share.sealed` may carry; a value that escapes past it is
   refused, never truncated.

## Review (Increment 11, S+R)

An independent review of the increment's diff (`code-review`, high effort)
reported ten findings. Nine were confirmed and fixed, each with a test that
failed first: the revoke rule above; revoking only one's own shares; refusing
imports from removed sharers; another member's item hiding a sharer's row;
`--replace` across providers; the audit rows inside the minting transaction;
moving an unescaped value into the zeroizing wrapper instead of copying it;
sanitizing the masked value the CLI prints (it is a few characters another
device chose); and the desktop collecting old shares when its lists open.
One was rejected with the PROTOCOL.md §8.4 clarification: purging shares
addressed to a removed device deletes items of removed or forked origins
too, which is correct because that exclusion covers every item at the key,
from every origin, independently of seq. Details: `docs/mesh/increments/STATUS.md`,
Increment 11.

## Alternatives considered

- **A shared mesh-wide symmetric key for credentials.** Simple: encrypt once,
  every member decrypts. Rejected: revocation is impossible without rotating
  the key and re-encrypting everything, a removed device keeps the key to every
  share it ever saw, and one leaked key exposes every shared credential (blast
  radius). Per-recipient sealing confines each share to one device's key.
- **Per-share ephemeral ECDH with a double ratchet (Signal-style).** Gives
  forward secrecy and post-compromise security. Rejected: it needs per-pair
  session state kept in sync across offline devices, multiplies the protocol
  surface, and buys little here: the recipients are the user's own devices,
  which keep the imported value anyway, so a later compromise of a recipient
  exposes the value regardless of the transport's secrecy.
- **Replicating vault ciphertext with shared project keys.** Make the same
  project key available on every device and replicate the encrypted
  credential rows. Rejected: it couples the key hierarchies of independent
  vaults (master passwords, project passwords, ADR 0020's lock semantics),
  makes "share one credential" into "share a whole project's key", and turns
  every future vault-format change into a replication change.
- **Automatic import, or automatic reseal by the node.** Rejected outright:
  it would put a value into a vault or into memory without the user present,
  contradicting the reauthentication rule and MESH-SI-13.

## Security implications

- The value appears in plaintext only inside `share::share` (sealing, in a
  zeroizing buffer) and inside the import (the opened buffer is zeroizing; the
  value moves into a `SecretString` until the vault re-encrypts it). It is
  never in a frame, a log, an error, JSON output, an audit row or a plaintext
  column: tested by canaries on the encrypted wire
  (`share_wire::a_shared_credential_never_crosses_the_wire_in_plaintext`), in
  every session frame and every table and column of every device, the item
  store's sealed bytes included (`mesh_share::*`), in errors, doctor, status
  and list output, and in CLI stdout and stderr (`mesh_cli::share_a_credential_…`,
  smoke).
- Every error on these paths has static text: a JSON parse error, which could
  quote its input, is replaced by `ShareBindingMismatch("contents")`; a box
  that does not open is `ShareUnreadable`.
- A malicious member (the user's own device, compromised) cannot plant a value
  under another device's name or re-wrap another device's box (the bindings).
  It can share a value of its own under its own name; the list and the import
  dialog always name the sharer. It can mint items with another share's id to
  make an import by that id ambiguous, or mint its own item at another
  sharer's key so the recipient sees that one until the sharer reseals
  (denials of service within the rate limits, like the others ADR 0031
  documents; it can never deliver a value under another device's name).
- A recipient's sealing key is static: there is **no forward secrecy**. Anyone
  who later obtains a recipient's vault and master password can open every
  share ever sealed to it that its store still holds.

## Future limitations

- **A recipient keeps whatever it imported.** Revoking a share stops a device
  that has not imported it yet; it never removes a value from a vault, and it
  **does not revoke the credential at its provider**. To cut a device off,
  rotate the credential (`tethra rotation`, the Rotation view); the UI and CLI
  say so wherever a share can be revoked.
- A removed or stolen device keeps every credential it imported. Removal stops
  new shares reaching it; rotation is the remedy (THREAT_MODEL.md, Device
  mesh).
- serde's internal scratch buffer for a JSON string that needs unescaping, and
  the vault's own copies while encrypting, are not zeroized; ADR 0020's
  memory-inspection limitation applies.
- Teams (sharing with another person's devices) would need identities beyond
  "my devices"; nothing here blocks adding them, and nothing here provides
  them.
