# Tethra Mesh — Threat Model

This extends the root [`THREAT_MODEL.md`](../../THREAT_MODEL.md) for Tethra Mesh
([ADR 0031](../decisions/0031-device-mesh.md)). Everything the root model says
still holds; this document adds one trust boundary and the adversaries that
come with it.

> **Status.** The mechanisms named below are built across Increments 01-12.
> Built and tested so far:
> - item signing and verification, and the canonical codec (01);
> - roster admission: removal cutoffs, fork reports, key-derived device ids
>   (01-02);
> - the spend-cap view clamp (01);
> - fork detection on the wire (02);
> - encrypted key storage, the clone/rollback marker and the restore wipe
>   (03).
>
> - the Noise transport, pairing, removal at the transport and access-key
>   rotation (04).
>
> mDNS discovery and the node loop are specified (05). See
> `SECURITY_INVARIANTS.md` for per-invariant status.

## Assets

- The data that replicates (`ARCHITECTURE.md` "What replicates"): device roster,
  shared project names, per-device usage counters, spend caps and rights, mesh
  settings and — from Increment 11, opt-in — sealed credential shares.
- Each device's mesh private keys: Ed25519 signing key, X25519 Noise static key,
  X25519 sealing key, and the shared mesh access key. Encrypted at rest under
  the vault key (Increment 03); in memory only while unlocked.
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
| Removed or stolen device | Removal mints a cutoff (its later items stop counting) and rotates the access key; sessions with its key are refused. | Removal is eventually consistent: devices that have not heard yet may still exchange with it. Credentials it already imported (Increment 11) stay compromised: rotate them at the provider. |
| Malicious member (one of your own devices, compromised) | Signatures stop it impersonating other origins. Key-derived device ids stop it hijacking another device's identity (a re-add with other keys is invalid). The bounded-counter clamp stops it creating spend-cap rights in other devices' views beyond what it held. Payload bindings stop it planting a credential in another device's vault (Increment 11). | It can remove every other device (recovery: re-pair), publish false usage about itself, raise its own cap with a labelled override, and consume rate-limited resources. It is your device, so this is documented rather than prevented. |
| Cloned or rolled-back installation (Migration Assistant, Time Machine, a copied data dir) | Restoring a backup wipes mesh identity; a marker file with a seq high-water mark catches a copied or rolled-back data dir, which then refuses to mint (03); two items at one dot are fork evidence that cuts the origin off at the fork point. | A clone copied *together with* its marker, or a rollback of fewer than 64 seqs, is caught only on the wire, by fork evidence or a rollback notice. |
| Clock-skewed device | Accept-and-flag: its items are accepted and its skew recorded and shown; it never drags another device's clock more than 60 s ahead. A user's edit is lifted above a skewed value they were looking at. | A device with a far-future clock wins LWW ties against devices that are not editing that value. |
| Forged or tampered item | Strict Ed25519 verification over a domain-separated, canonical body; the hash covers the signature; stored bytes are the received bytes. | — |

## Unchanged

Malware running as the user, memory inspection, a compromised OS and debuggers
remain out of scope (root `THREAT_MODEL.md`). Mesh metadata at rest is plaintext
like other usage data (ADR 0018); private keys are encrypted. Spend caps are a
self-limit, not a security boundary: anything that bypasses the gateway bypasses
the cap.
