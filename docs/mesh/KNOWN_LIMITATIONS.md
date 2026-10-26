# Tethra Mesh — Known Limitations

What the mesh does not do, stated plainly
([ADR 0031](../decisions/0031-device-mesh.md)). Each entry says whether it is a
permanent design choice or something a later increment changes.

> **Status.** The mesh is in development on `feat/device-mesh`; as of Increment
> 01 it has no user-visible commands. These limitations describe the design the
> increments build.

## Reachability

- **No NAT traversal, relay or rendezvous.** Devices must reach each other
  directly: the same LAN, or a VPN you run (Tailscale, WireGuard). There is no
  Tethra server to fall back on, by design.
- **Nothing listens unless you ask.** `tethra mesh serve` requires `--listen`;
  all-interfaces binding requires `--all-interfaces`; LAN discovery requires
  `--discover`.

## Membership

- **Removal is eventually consistent.** A removed device keeps exchanging with
  devices that have not yet heard of its removal.
- **Access-key rotation is eventually consistent.** A device that misses a
  rotation for 30 days must re-pair.
- **A compromised member is powerful.** It is your own device: it can remove all
  your other devices (recovery is re-pairing), publish false usage about itself,
  and raise its own spend cap with a labelled override. Item signatures stop it
  impersonating another device, the roster's key-conflict rule stops it taking
  over another device's identity, and the spend-cap clamp stops it creating
  rights in other devices' views beyond what it held.
- **Mutual removal removes both.** If two devices remove each other at the same
  time, both are removed.
- **Only a device's latest value per key is kept.** When a removed device's
  latest write to a value came after its removal cutoff, that value stops
  counting, and its *earlier* value is not restored: the value falls back to the
  next device's.

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
