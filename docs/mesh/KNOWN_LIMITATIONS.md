# Tethra Mesh — Known Limitations

What the mesh does not do, stated plainly
([ADR 0031](../decisions/0031-device-mesh.md)). Each entry says whether it is a
permanent design choice or something a later increment changes.

> **Status.** The mesh is in development on `feat/device-mesh`. As of Increment
> 04, devices pair (`mesh invite`/`join`), serve (`mesh serve --listen`),
> replicate on demand (`mesh replicate --peer`), and remove or leave; the
> automatic node loop arrives in 05. These limitations describe the design the increments build.

## Reachability

- **No NAT traversal, relay or rendezvous.** Devices must reach each other
  directly: the same LAN, or a VPN you run (Tailscale, WireGuard). There is no
  Tethra server to fall back on, by design.
- **Nothing listens unless you ask.** `tethra mesh serve` requires `--listen`;
  all-interfaces binding requires `--all-interfaces`; LAN discovery requires
  `--discover`.

## Membership

- **Removal is eventually consistent.** A removed device keeps exchanging with
  devices that have not yet heard of its removal. Each device refuses it at its
  next handshake after hearing.
- **Leaving without a reachable peer.** `mesh leave` wipes this device either
  way. If no peer was reachable to receive the departure, the other devices
  keep listing it until one of them removes it.
- **The invite is a bearer secret.** Anyone who has it during its lifetime can
  add a device. On the command line it ends up in shell history; pass `-` to
  read it from standard input instead.
- **Pairing reveals the inviter's static key to a client that knows a live
  invite's hint** (message 2 of `XXpsk3` comes before the psk is mixed in). The
  hint is derived from the token, so in practice that means someone who saw
  the invite.
- **Access-key rotation is eventually consistent.** Every session carries the
  current access key, so a rotation spreads as devices talk. A device keeps
  being accepted with the previous key for 30 days after the rotation; after
  that it must pair again. If two devices remove different devices while apart,
  a removed device can briefly get a current key from a member that has not
  yet heard of its removal. Members that have heard still refuse it, because
  the roster check, not the key, decides who gets in.
- **A compromised member is powerful.** It is your own device: it can remove all
  your other devices (recovery is re-pairing), publish false usage about itself,
  and raise its own spend cap with a labelled override. Item signatures stop it
  impersonating another device, key-derived device ids stop it taking
  over another device's identity, and the spend-cap clamp stops it creating
  rights in other devices' views beyond what it held.
- **Mutual removal removes both.** If two devices remove each other at the same
  time, both are removed.
- **Only a device's latest value per key is kept.** When a removed device's
  latest write to a value came after its removal cutoff, that value stops
  counting, and its *earlier* value is not restored: the value falls back to the
  next device's.

## Transport

- **Key copies inside `snow`.** Tethra's own copies of private keys and psks are
  zeroized when dropped, but the Noise library (`snow` 0.10) keeps its own
  copies in its handshake and cipher states and does not zeroize them.
- **Handshake budget.** A client may hold one of a listener's 8 connection
  slots for up to the 5-second handshake timeout, and may make 10 attempts a
  minute from one address. Many addresses can deny service for as long as they
  keep it up.

## Identity and storage

- **A restored backup leaves the mesh.** Restore deletes every mesh row
  (identity, keys, items, peers) because a restored vault is a copy: if it kept
  minting as the original device, the two would reuse item numbers. Pair the
  restored device again.
- **The identity marker sees large rollbacks, not small ones.** The marker
  reserves item numbers in blocks of 64, so a database rolled back by less than
  one block, or a copy of the whole data directory (database and marker
  together), is not caught locally. It is caught as a fork when the diverging
  histories meet another device, and the copy's later items stop counting.
- **A power loss can look like a rollback.** Every write is synced
  (`synchronous=FULL`, and F_FULLFSYNC on macOS). But if a disk still loses more
  than 64 of this device's most recent writes while the marker survives, the
  device refuses to mint until it leaves and pairs again. That is the safe side
  of the error.
- **One device's batch is one transaction.** A large exchange is written in
  several short transactions, but everything received from one origin in one
  exchange is a single transaction (at most the 50 000-row session limit), so
  the gateway's writer may wait for it. Measured on a Mac: 10 000 items in about
  60 ms, so the 50 000-row maximum takes roughly 0.3 s.
- **Windows: marker permissions and directory sync.** On Unix the marker is
  0600 in a 0700 `mesh/` directory, and its directory is fsynced after every
  rename. On Windows the file inherits the data directory's per-user ACLs (as
  the vault's files do), and the directory is not fsynced (the standard library
  cannot open a directory there; NTFS journals the rename).
- **Opened views cost memory and start-up time.** The views are rebuilt in
  memory from the stored items whenever the store opens (`mesh status`, and the
  node from 05). This is linear in the number of held items: one per device, key
  and day for usage, so it grows with history.

## Running the node

- **No LaunchAgent for the mesh in v1.** The node runs only while the desktop
  app is open and unlocked, or while `tethra mesh serve` runs from an unlocked
  CLI session. A LaunchAgent would have to hold keys while locked, which ADR 0020
  forbids.
- **Windows runtime is untested.** It compiles and its unit tests run in Windows
  CI, but behaviour on Windows has not been validated, as for the gateway
  (ADR 0019 D8).

## Usage and cost

- **Cost is computed where the usage happened.** Each device prices its own
  traffic with its own pricing table at ingest time; figures from different
  devices may use different price versions.
- **Cached-read tokens are excluded from cost estimates**, so spend caps
  undercount cached-heavy traffic.
- **Figures are per device, with freshness.** A device not heard from in over
  24 hours is shown as stale, never as zero; mesh figures are never summed with
  provider-reported cost.

## Spend caps

- **Caps are a self-limit, not a security boundary.** Anything that bypasses
  the gateway bypasses the cap.
- **Overshoot is bounded, not zero.** Cost is known only after a response, so a
  device may exceed its rights by at most one in-flight request's cost per cap.
- **A cap whose owner device is removed is frozen**: no new minting; create a new
  cap.

## Credential sharing (Increment 11)

- **No forward secrecy.** Shares are sealed to static per-device keys.
- **A recipient keeps what it imported.** Revoking a share does not revoke the
  credential at the provider; rotate it there.
- **Nothing is imported automatically.** Every import needs reauthentication.
