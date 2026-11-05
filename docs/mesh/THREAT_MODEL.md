# Tethra Mesh — Threat Model

This extends the root [`THREAT_MODEL.md`](../../THREAT_MODEL.md) for Tethra Mesh
([ADR 0031](../decisions/0031-device-mesh.md)). Everything the root model says
still holds; this document adds one trust boundary and the adversaries that
come with it.

> **Status.** Increments 01-11 are built and tested:
> - item signing and verification, and the canonical codec (01);
> - roster admission: removal cutoffs, fork reports, key-derived device ids
>   (01-02);
> - the spend-cap view clamp (01);
> - fork detection on the wire (02);
> - encrypted key storage, the clone/rollback marker and the restore wipe
>   (03);
> - the Noise transport, pairing, removal at the transport and access-key
>   rotation (04);
> - the node loop and opt-in mDNS discovery (05);
> - shared projects and cross-device usage (06);
> - the spend-cap policy, decided inside the publishing transaction, and the
>   node's half of the escrow fence (07), and gateway enforcement (08);
> - the desktop app's in-process node and its Devices, project, usage and cap
>   panels (09-10);
> - opt-in credential sharing, sealed per recipient device (11).
>
> Increment 12 (hardening and the audit of 2026-11-03) is in progress. See
> `SECURITY_INVARIANTS.md` for per-invariant status and `KNOWN_LIMITATIONS.md`
> for the residual risks the audit accepted.

## Assets

- The data that replicates (`ARCHITECTURE.md` "What replicates"): device roster,
  shared project names, per-device usage counters, spend caps and rights, mesh
  settings and — opt-in, one credential at a time (Increment 11, ADR 0033) —
  credential shares, each sealed to one recipient device's sealing key. Only
  a share's value is sealed: its credential name, provider, mesh project,
  value version and recipient are readable by every member device, which
  relays them.
- Each device's mesh private keys: Ed25519 signing key, X25519 Noise static key,
  X25519 sealing key, and the shared mesh access key. Encrypted at rest under
  the vault key (Increment 03); in memory only while unlocked. The sealing key
  is unwrapped only inside a reauthenticated import (Increment 11).
- Invite tokens (bearer secrets for at most 60 minutes, default 10).
- The integrity of spend-cap enforcement on each device's own gateway.

## Trust boundary: the LAN or VPN between paired devices

Paired devices talk directly over the user's LAN or a user-run VPN (Tailscale,
WireGuard). No Tethra server, relay, rendezvous or third-party NAT service is
ever involved (MESH-SI-12). Everything that crosses this boundary is either a
Noise handshake message or Noise ciphertext; only the handshake is parsed before
authentication.

## Adversaries and responses

| Adversary | Response | Residual risk |
|---|---|---|
| Passive LAN observer | Noise encryption of every frame. mDNS (opt-in) publishes only a random per-boot instance name and a daily-rotating HMAC of the access key. | Traffic timing and volume between devices are visible. |
| Active LAN prober | `XXpsk0`: without the access key the handshake fails at message 1, and the responder sends nothing, so the prober never learns a device's static key and cannot track it (04, tested). Only a 16-byte preamble and ≤ 1 KiB handshake messages are parsed before authentication. ≤ 8 connections at once, ≤ 10 new ones per source IP per minute. A pairing listener answers only the hint of a live invite. | Can use up the handshake budget (≤ 10/min per IP) and the 8 connection slots for up to 5 s each. A prober who has a live invite's hint (it is derived from the token) learns the inviter's static key from pairing message 2. |
| Stolen invite token | Single use (claimed in one transaction before the reply, so two concurrent joiners cannot both win), 10-minute default lifetime (at most 60), 5 wrong attempts kill it, and a checksum catches typos before any connection. The inviter stores only the token's hash and the pairing psk encrypted under the vault key, so a copy of its database cannot pair (04, tested). `mesh join -` reads the invite from standard input, out of shell history. | A token stolen and used within its lifetime admits the attacker's device. The user sees an unexpected device in `mesh devices` and removes it, which rotates the access key. Move invites only over channels you trust. |
| Removed or stolen device | Removal mints a cutoff (its later items stop counting) and rotates the access key; sessions with its key are refused. New shares cannot be sealed to it, a reseal never offers it a rotated value, and shares addressed to it are hidden and collected everywhere (11). Removing it (CLI and desktop) says so and says to rotate. | Removal is eventually consistent: devices that have not heard yet may still exchange with it. Credentials it already imported (11) stay compromised, and so do shares sealed to it that it already holds and can open with its vault's password: rotate them at the provider. To cut off a device that stays a member, revoke its share before rotating, or the reseal offer includes it. |
| Malicious member (one of your own devices, compromised) | It reads everything that replicates, share details included (only share values are sealed, each to its recipients). Signatures stop it impersonating other origins. Key-derived device ids stop it hijacking another device's identity (a re-add with other keys is invalid). The bounded-counter clamp stops it creating spend-cap rights in other devices' views beyond what it held. Sealed-field bindings stop it planting a credential in another device's vault under another device's name, or re-wrapping another device's sealed box (11, tested). Since the audit (12): its own remove cannot cancel its removal, it cannot revoke shares between other devices, a copied Noise key cannot shadow another device, small-order keys are refused, and a rollback notice beyond its own Hello is ignored. | It can remove every other device (recovery: re-pair), report any device forked (fork reports rest on the reporter's word), publish false usage about itself, raise its own cap with a labelled override, share a value of its own under its own name, make an import by a share id ambiguous, pin a last-writer-wins value (a cap target, a project's name, the retention setting) with a far-future timestamp (recovery: replace the object; KNOWN_LIMITATIONS), and consume rate-limited resources. It is your device, so this is documented rather than prevented. |
| Someone with this device's unlocked session (a CLI session or the open app) | Every share, import and reseal, creating an invite, removing a device, leaving, switching cap enforcement on or off, and opening the node to the network (all interfaces, mDNS, a non-loopback address) asks for the master password again, in core; nothing imports by itself. | Without the password the session can list shares (names, devices, share ids; never values) and revoke this device's shares; change the mesh-wide retention, which deletes counters on every device (the CLI asks to confirm a lower, but needs no password); create, lower or reclaim a cap, and raise one (a labelled local override on a device that does not own it); add or remove peer addresses; rename this device; and share, bind, unbind, rename, archive or merge projects. Most of these replicate to every device. |
| Cloned or rolled-back installation (Migration Assistant, Time Machine, a copied data dir) | Restoring a backup wipes mesh identity; a marker file with a seq high-water mark catches a copied or rolled-back data dir, which then refuses to mint (03); two items at one dot are fork evidence that cuts the origin off at the fork point. | A clone copied *together with* its marker, or a rollback of fewer than 64 seqs, is caught only on the wire, by fork evidence or a rollback notice. |
| Clock-skewed device | Accept-and-flag: its items are accepted and its skew recorded and shown; it never drags another device's clock more than 60 s ahead. A user's edit is lifted above a skewed value they were looking at. | A device with a far-future clock wins LWW ties against devices that are not editing that value. |
| Forged or tampered item | Strict Ed25519 verification over a domain-separated, canonical body; the hash covers the signature; stored bytes are the received bytes. | — |

## Unchanged

Malware running as the user, memory inspection, a compromised OS and debuggers
remain out of scope (root `THREAT_MODEL.md`). Mesh metadata at rest is plaintext
like other usage data (ADR 0018); private keys are encrypted. Spend caps are a
self-limit, not a security boundary: anything that bypasses the gateway bypasses
the cap.
