# Tethra Mesh — User Guide

Tethra Mesh keeps your own devices (a laptop, a desktop, a home server) in step
with each other, peer to peer. There is no Tethra server, relay or cloud: your
devices talk to each other directly, on your LAN or over a VPN you run, such as
Tailscale or WireGuard. Everything they exchange is signed and travels inside an
encrypted Noise channel that only your paired devices can open
([ADR 0031](../decisions/0031-device-mesh.md)).

This guide covers what exists today: pairing, the node that keeps devices
converged, and the `status` and `doctor` views. Shared projects, cross-device
usage and spend caps are later increments.

## What replicates

Only what [ARCHITECTURE.md "What replicates"](ARCHITECTURE.md#what-replicates)
lists: today, the device roster (ids, names, public keys, removals) and each
device's published listen addresses. Credential values never replicate.

## 1. Pair your devices

On the first device:

```bash
tethra mesh init --name laptop
tethra mesh serve --listen 192.168.1.20:7420      # this device's LAN address
```

On the first device, in another terminal, create a one-time invite. It is a
password for 10 minutes; move it over a channel you trust (type it, or use your
password manager), never a public one:

```bash
tethra mesh invite --addr 192.168.1.20:7420
```

On the second device:

```bash
tethra mesh join -          # paste the invite; reading it from stdin keeps it out of shell history
tethra mesh peer add 192.168.1.20:7420
tethra mesh serve --listen 192.168.1.30:7420
```

From here on, each running node exchanges with every peer it knows about every
30 seconds, and learns the addresses your other devices publish. Adding one
address by hand is usually enough to get a mesh going.

### On Tailscale (or another VPN)

Listen on the VPN address, or publish the VPN name:

```bash
tethra mesh serve --listen 100.101.102.103:7420
# or: listen on the LAN address but tell your devices to dial the VPN name
tethra mesh serve --listen 192.168.1.30:7420 --advertise desktop.tail1234.ts.net:7420
```

`peer add` accepts an IP address or a host name (`desktop.tail1234.ts.net:7420`).
mDNS discovery does not cross a VPN; use `peer add` there.

### Discovery on a LAN (optional)

`tethra mesh serve --listen … --discover` announces this node with mDNS and
looks for the others. The announcement carries no name: a random instance name
per start, the port, and a tag that changes every day and that only your mesh's
devices can recognise. Discovery only suggests addresses; every connection still
has to pass the authenticated handshake. It is off unless you pass `--discover`.

## 2. Run the node

```bash
tethra mesh serve --listen ADDR:PORT [--listen …] [--all-interfaces] [--discover]
                  [--advertise HOST:PORT …] [--interval SECONDS] [--max-runtime MINUTES]
```

- **Nothing listens unless you pass `--listen`.** `0.0.0.0` or `[::]` (every
  interface) is refused unless you also pass `--all-interfaces`; the node then
  publishes this machine's concrete interface addresses instead.
- **One node per data directory.** A second `serve` on the same data directory
  fails with "another Tethra Mesh node is already running".
- **Rounds.** Every `--interval` seconds (default 30, at least 5; each round is
  spread by ±20% so devices do not dial in lockstep) the node exchanges with
  every peer that is not backing off. A peer that fails is retried after 5 s,
  then 10 s, 20 s and so on, up to every 15 minutes, until it answers again.
- **Repair.** Every exchange compares a digest of what each side holds and
  repairs any difference. Once a day the node records a round as a *repair
  round*; `doctor --repair` runs one on demand.
- **When it stops.** The node holds this device's mesh keys only while it runs
  and drops them when it stops:
  - with a vault session (`eval "$(tethra unlock --print-export)"`), it stops
    when that session locks or expires. The session's auto-lock timer counts
    time without `tethra` commands, and the node does not reset it, so a node
    started from a session runs for at most the auto-lock period after your
    last command;
  - with `TETHRA_PASSWORD` (scripts), it runs until stopped, or for
    `--max-runtime` minutes;
  - `tethra mesh stop` stops it from another terminal: it finishes the
    exchanges it is in, then exits. Ctrl-C ends the process at once; stored
    state is safe either way, because every write is one transaction and an
    interrupted exchange commits nothing.
- **No background service.** There is no LaunchAgent or system service for the
  mesh: it would have to hold keys while the vault is locked.

Other commands that talk to a running node: `tethra mesh replicate` (exchange
now, through the node; without a node it dials each known peer itself), `tethra
mesh stop`, `tethra mesh status`, `tethra mesh doctor`.

## 3. Peers

```bash
tethra mesh peer add HOST:PORT      # an address to dial
tethra mesh peer list               # every address, where it came from, how dialling went
tethra mesh peer remove HOST:PORT   # forget one
```

`peer list` columns:

| Column | Meaning |
|---|---|
| ADDRESS | What the node dials. |
| DEVICE | The device that answered there last (name and id), once a handshake succeeded. |
| SOURCE | `manual` (you added it), `gossip` (another device publishes it as its listen address), or `mdns` (found by discovery). A manual address stays manual. |
| LAST SUCCESS | The last time a handshake there succeeded. |
| FAILURES | Failed attempts since the last success; drives the backoff. |
| UNREACHABLE SINCE | When the current run of failures began. |

Removing a `gossip` or `mdns` address only lasts until a device publishes it
again. If a different device starts answering at a known address (expected after
that device paired again), `status` notes it.

## 4. `tethra mesh status`

Everything `status` shows is local; nothing in it is secret. `--json` gives the
same fields.

| Field (JSON) | Meaning |
|---|---|
| `mesh_id`, `device_id`, `device_name`, `genesis_device` | This mesh and this device. |
| `marker` / `marker_problem` | Whether the identity marker vouches for this database. Anything but `ok` means the database is a copy or was rolled back; the node will not run. Fix: `tethra mesh leave`, then pair again. |
| `self_forked` | Another installation used this device's identity. Same fix. |
| `devices` | The roster: `active`, `removed` (with its `cutoff_seq`), `forked` (with its `fork_seq`). |
| `vv`, `next_seq`, `items_by_kind` | What this device holds, per origin and per kind. |
| `rejected_items` | Items refused at ingest (bad signature, malformed, over the rate). |
| `clock_skew` | Devices whose clocks ran more than 60 s ahead, with the largest skew seen (ms). Fix their clocks. |
| `fork_evidence`, `forked_devices` | Forks seen. |
| `repairs_changed` | Times repair changed stored state: a bug signal (see `doctor`). |
| `rollback_hold` | A peer holds this device's own items up to this seq, past what its database has (it was restored from an older copy). Nothing is created here until they come back, which the node's next exchange with that peer normally does. |
| `node.running`, `node.pid`, `node.listen`, `node.advertised` | Whether a node runs for this data directory, where it listens, and what addresses it publishes. |
| `node.interval_ms`, `node.rounds`, `node.last_round_at` | The round interval, rounds so far and the last one. |
| `node.discovery`, `node.hooks`, `node.last_hook_error`, `node.last_publish_error` | Discovery on or off; the work it runs before each round (later increments add some); the last failures of either. |
| `peers` | The rows of `peer list`, with each device's name. |
| `lag` | Per device, from the last exchange with it: `at`, `completed`, `at_hello` (per origin, the peer's seq minus this device's at the start of that exchange), `peer_behind` (items it lacked then), `peer_ahead` (items this device lacked then), `peer_behind_now` (items this device holds now that, as far as it knows, the peer still lacks) and `digest_mismatches` (origins repaired in that exchange). A converged pair shows zeros. |
| `address_changes` | Addresses at which a different device answered than before. |

## 5. `tethra mesh doctor`

`doctor` runs every check below and prints each finding with a plain-language
fix. `--json` gives `findings: [{check, severity, summary, fix}]` and `worst`.

| Check | What it verifies | Typical fix |
|---|---|---|
| `schema` | The database is at this Tethra version's schema. | Run the newer Tethra that upgraded it, or any command to migrate. |
| `keys` | The signing, Noise and access keys decrypt and match their public keys. | Leave the mesh and pair again. |
| `sealing_key` | The sealing key (for credential shares) is present. It is never decrypted by `doctor`. | Leave and pair again. |
| `items` | Every stored item's bytes parse, its index columns match its bytes, and its signature verifies. | `doctor --rebuild`. |
| `store` | The mesh store loads (only reported when it does not). | `doctor --rebuild`. |
| `marker` | The identity marker vouches for this database. | Leave and pair again. |
| `fork` | No device, this one included, has forked. | The forked device leaves and pairs again; remove its old identity. |
| `dot_log` | The version vector, dot log and chains are consistent. | Report it; leave and pair again. |
| `views` | The views match a rebuild from the stored items. | `doctor --rebuild`. |
| `clock_skew` | No device's clock is flagged. | Fix that device's clock. |
| `rejected` | No item has been rejected. | A growing count means a peer runs a buggy or incompatible build. |
| `rollback` | No rollback hold. | Keep the node running; remove a peer that keeps claiming items it never sends. |
| `repair` | Repair has never changed stored state, and when the last repair round ran. | Expected right after `--rebuild`; otherwise report it. |
| `digests` | At the last exchange with each peer, equal version vectors meant equal contents. | Repair fixes it; recurring means run `doctor` on that peer. |
| `node` | Whether a node runs here. | `tethra mesh serve --listen …`. |
| `listener` | Every listener accepts connections from this device. | Restart the node; check what holds the port. |
| `advertise`, `hooks` | Shown when the node could not publish its addresses or a round hook failed. | See the message. |
| `peers` | At least one peer address, and which are failing. | `peer add`; check the device is on and reachable. |
| `repair_round` | With `--repair`: the exchanges of a repair round and whether repair changed anything. | As for `repair`. |

`--rebuild` rewrites the item store's index columns from the item bytes and
removes rows whose bytes are unreadable or no longer carry a valid signature.
The version vector is left alone, so the next exchange with a peer that holds a
removed item fetches it again (`repair` then reports a change, which is expected
after a rebuild). `--repair` runs a repair round now: through the running node,
or directly from `doctor` when no node runs.

## Troubleshooting

- **"another Tethra Mesh node is already running for this data directory".**
  Stop it with `tethra mesh stop`, or use it: `replicate` and `status` talk to it.
- **"the data directory path is too long for the node's control socket".**
  Unix sockets are limited to about 100 bytes of path. Use a shorter `TETHRA_DIR`.
- **A peer stays unreachable.** Check that its node is running (`mesh status`
  on that device), that the address is reachable from here (same LAN, or both on
  the VPN), and that no firewall blocks the port. `peer list` shows the last
  error.
- **"refusing to listen on every interface".** Pass a concrete address, or add
  `--all-interfaces` if you mean every interface.
- **The node stopped by itself.** It prints why: the session locked or expired,
  `--max-runtime` elapsed, or this device left the mesh, was removed, or forked.
- **`rollback_hold` stays set.** Keep the node running so it can fetch this
  device's items back. If the device that reported the hold never sends them,
  remove it (`tethra mesh remove`), which also lifts its report.
