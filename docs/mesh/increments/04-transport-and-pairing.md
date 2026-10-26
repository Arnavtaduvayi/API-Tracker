# Increment 04: Transport and pairing

**Mode:** S+R, single session plus a security-review subagent before the final commit · **Size:** L · **Prerequisites:** 03 done

## Goal

Two or more real Tethra installations pair with a one-time invite, authenticate each
other with Noise, and replicate over TCP: relaying through each other, removing devices,
and rotating the access key. The work happens in a new `crates/mesh` crate with strict
bind discipline and bounds.

At the end of this increment, `tethra mesh invite` / `join` / `serve --listen` /
`replicate --peer` work end to end between temp data dirs on 127.0.0.1.

## Read first

- DESIGN §D4 (crate layout), §D10, §D12, §D13 (bind discipline), §D19 (MESH-SI-1/2/8) and §D20.
- `crates/gateway/Cargo.toml` (the dependency philosophy) and `crates/gateway/src/server.rs` (std-thread accept loop and connection caps).
- `crates/gateway/src/forward.rs:146-228` (`ConnBudget`/`ConnLimits` time bounds) and `crates/gateway/tests/no_insecure_verifier.rs:86-104` (the grep-guard pattern).
- `.github/workflows/ci.yml` lines 44, 54 and 71.
- `snow` 0.10 docs (`docs.rs/snow`). Confirm support for the `XXpsk0` and `XXpsk3` pattern strings before writing anything else (D10).
- The STATUS.md handoff notes for 03.

## Scope (build all of this)

### 1. Crate `crates/mesh` (`api-tracker-mesh`)

- Add it to the workspace members in `Cargo.toml` with `#![forbid(unsafe_code)]`.
- Dependencies: `api-tracker-core`, `snow` 0.10.x, `serde`/`serde_json`, `zeroize`,
  `blake3`, `socket2` if needed. Use no async runtime.
- **In the same commit**, add `-p api-tracker-mesh` to `ci.yml` clippy (44), tests (54)
  and Windows tests (71). The commit message cites that rule (`ci.yml:51-53`).
- **Spike first.** A tiny test proves `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s` and
  `Noise_XXpsk3_…` handshakes complete with `snow`.
  - If psk0 is unsupported, fall back as D10 says and record the deviation in ADR 0031
    and STATUS.md.
  - Record the `snow` version and the `cargo tree -d` impact in ADR 0031.

### 2. Modules

- **`bind.rs`** is the only socket-binding function. It refuses unspecified addresses
  unless `allow_all_interfaces` is set, and logs the bound address (MESH-SI-1).
- **`noise.rs`** holds the builders for the pairing and session patterns and the
  prologues (D10), and zeroizes key material.
- **`frame.rs`** handles length-prefixed application frames (u32 big-endian, ≤ 1 MiB),
  fragmented across Noise transport messages (≤ 65 535 bytes each) and reassembled with
  a hard cap. A malformed or oversize frame closes the session.
  - **Before the handshake completes**, only handshake messages are parsed, with a
    ≤ 1 KiB cap per message (MESH-SI-2).
- **`session.rs`** drives `core::mesh::proto::Session` over a framed Noise stream, applies
  `Commit` actions through `SqliteStore`, and surfaces `Direct` messages to a handler.
  - The handshake timeout is 5 s, the idle timeout 30 s and the maximum wall time 10 min,
    all through socket timeouts.
  - After the handshake it checks the remote static key against the roster's non-removed
    `noise_pub` set (MESH-SI-2). It tries the current access-key epoch first, then the
    previous one if it is less than 30 days old.
- **`pair.rs`** handles the invite string (`tethra-mesh-invite:v1:<base32>@<addr>[,<addr>]`,
  parse and format, with a checksum character so typos fail fast) plus the inviter and
  joiner flows (D10).
- **`serve.rs`** is the accept loop: one thread per session, ≤ 8 sessions, a per-source-IP
  handshake token bucket (10/min) and a graceful shutdown flag.
- **`replicate.rs`** provides `replicate_once(store, keys, addr) -> ExchangeReport`
  (items in and out, duration, result) and writes `mesh_exchange_log`.
- **`directs.rs`** handles `AccessKeyUpdate`: the receiver re-wraps the new key under its
  vault key. This needs an unlocked vault, which is available because the node runs only
  while unlocked (D5). It also forwards the update to its other peers on their next
  sessions.

### 3. Core (`UnlockedVault` methods; reauth inside core per D4)

| Method | Behaviour |
|---|---|
| `mesh_invite_create(master_password, ttl_minutes) -> Invite` | Reauth. Stores a token hash. Clamps the TTL to ≤ 60 minutes (default 10). Returns the token **once**. |
| `mesh_pair_accept(...)` | Inviter side, called by `pair.rs`. Checks the token (hash, unexpired, unused, attempts < 5; marks it used before replying), then mints `roster.add`. |
| `mesh_join(invite) -> MeshSelfInfo` | Creates the identity inside the received `mesh_id`. Refuses with `AlreadyInMesh` if one exists. |
| `mesh_devices()` | The roster view: name, short id, added-by, removed flag and cutoff, last exchange. |
| `mesh_device_rename(device, name)` | Self only, through `device.info`. Renaming another device isn't possible by design; say so in the error. |
| `mesh_device_remove(master_password, device)` | Reauth. Mints `roster.remove` with the cutoff (D10). Rotates the access key to epoch+1, stored wrapped, and queues `AccessKeyUpdate` for delivery. |
| `mesh_leave(master_password)` | Reauth. Mints a self-remove when it can, best effort over one exchange, then `leave_local_wipe`. |

Audit events: `mesh_invite_created`, `mesh_device_joined`, `mesh_device_removed` and
`mesh_left`.

### 4. CLI (`mesh_cmd.rs`)

| Command | Behaviour |
|---|---|
| `invite [--ttl] [--wait]` | Reauth prompt via the `ctx` helpers. Prints the invite string once, with a "treat this like a password for 10 minutes" warning. `--wait` runs `serve` on the configured listen address until the invite is used or expires. |
| `join <invite> [--name]` | |
| `devices` | |
| `rename <name>` | |
| `remove <device>` | `confirm_default_no` first, then the reauth prompt. |
| `leave` | Confirm, then reauth. |
| `serve --listen <addr:port> [--listen …] [--all-interfaces]` | Minimal: accepts sessions only. 05 adds the outbound loop. Requires an unlocked vault or session (`ctx.unlocked()`). |
| `replicate --peer <addr:port>` | One-shot outbound exchange. |

### 5. Guards

- `crates/mesh/tests/bind_guard.rs`: a grep test, like the gateway's. No file in
  `crates/mesh/src` other than `bind.rs` contains `TcpListener::bind`, `UdpSocket::bind`,
  `0.0.0.0`, `INADDR_ANY`, `"::"` or `[::]:`.
- `crates/gateway/tests/no_mesh_dependency.rs`: `cargo metadata` (or a parse of the
  gateway's `Cargo.toml` plus the lockfile graph) shows that `api-tracker-gateway` does
  not depend on `api-tracker-mesh`.

### 6. Smoke

Add a two-node block on `127.0.0.1` with two temp `TETHRA_DIR`s:
1. A runs `init`, then `serve --listen 127.0.0.1:<free port>` in the background.
2. A creates an invite.
3. B runs `join`.
4. `devices` on both shows 2.
5. Kill A's server cleanly.

Find a free port by binding `127.0.0.1:0` in a helper, or let `serve` print its bound
port when given `:0`; that's preferred.

## Execution workflow (S+R)

Implement and test everything yourself. Then, **before the final commit**, run the
review described in README §4 (S+R): the `code-review` skill at `high`, or a fresh
`general-purpose` subagent that must not edit anything. The review focus:

- pre-authentication parsing;
- PSK derivation and prologues;
- the roster check timing (is any data accepted before it?);
- invite token lifecycle races (two joiners presenting the same token at once);
- access-key rotation and the epoch window;
- removal enforcement at the transport;
- zeroization of keys and tokens;
- bind guard completeness;
- bounds;
- error messages leaking tokens or keys.

Fix every confirmed finding test-first, and record rejected findings in STATUS.md.

## Tests to write (`crates/mesh/tests/`)

All of these use temp data dirs and `127.0.0.1:0`, with no LAN and no mDNS.

- **`pairing.rs`:**
  - the happy path;
  - a token is single use, including two concurrent joiners where exactly one succeeds;
  - expired;
  - 5 wrong attempts lock the token out;
  - the wrong mesh;
  - a joiner that is already in a mesh is refused;
  - the invite string checksum catches a typo;
  - the token never appears in logs, errors or `--json` output after first display.
- **`replication.rs`:**
  - A↔B replicate;
  - A–B–C where A's items reach C **through B**, and signatures are verified at C;
  - removal: after B removes C, C's handshake is refused by A and B, and C's
    post-cutoff LWW writes are excluded on A;
  - access-key rotation reaches A through B;
  - a device that misses rotation for over 30 days (use the injected clock) is refused;
  - a mid-session kill of the sender advances no VV (MESH-SI-4 over a real socket).
- **`bounds.rs`:**
  - an oversize frame;
  - a malformed handshake;
  - garbage before the handshake;
  - a slowloris handshake, closed at 5 s;
  - an idle session closed;
  - more than 8 concurrent sessions refused;
  - a per-IP handshake flood is rate-limited;
  - the wrong psk fails at message 1 **and the responder never sends its static key**.
    Assert the responder's bytes contain no `noise_pub`.
- **`bind_guard.rs`**, and the gateway's `no_mesh_dependency.rs`.
- **`apps/cli/tests/mesh_cli.rs`:** invite, join, devices, remove and leave across 2-3
  temp dirs, with `serve` started as a child process on port 0.

## Acceptance criteria

- [ ] `crates/mesh` exists, is in CI on all three lists, and is green on Linux, macOS and Windows CI.
- [ ] MESH-SI-1, 2 and 8 have named tests over real sockets.
- [ ] A three-device relay, a removal and a key rotation work end to end through the CLI.
- [ ] The review was run, with findings fixed or explicitly rejected in STATUS.md.
- [ ] Smoke passes with the two-node block.
- [ ] The check suite, now including `-p api-tracker-mesh`, is green.

## Verification commands

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-mesh
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-gateway --test no_mesh_dependency
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-cli --test mesh_cli
cargo clippy -p api-tracker-mesh --all-targets -- -D warnings
bash scripts/smoke.sh
```

## Docs to update

- `docs/mesh/PROTOCOL.md`: the transport section, invite format and handshake transcript.
- `docs/mesh/SECURITY_INVARIANTS.md` and `docs/mesh/THREAT_MODEL.md`: the active prober
  and stolen-token rows.
- `docs/mesh/KNOWN_LIMITATIONS.md`: eventual revocation, the 30-day rotation window,
  and the psk0 fallback if used.
- ADR 0031: the dependency versions.
- `CHANGELOG.md`.

## Handoff checklist

- [ ] STATUS.md row 04 `done`, with the review summary and the CI run ids for all three OSes.
- [ ] Handoff notes:
  - the `serve` internals that 05 will extend (where the outbound loop plugs in);
  - the `Direct` message dispatch points 07 will use for `RightsRequest`.
