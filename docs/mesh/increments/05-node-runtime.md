# Increment 05: Node runtime

**Mode:** S · **Size:** M · **Prerequisites:** 04 done

## Goal

Turn one-shot exchanges into a long-running, self-healing **node**. The node:
- keeps every reachable peer converged on its own;
- learns peer addresses by gossip, and optionally by privacy-preserving mDNS;
- backs off from unreachable peers;
- holds keys only while the vault or session is unlocked;
- runs as a single instance per data dir;
- answers `status`, `replicate-now` and `stop` over a local control socket.

`tethra mesh status` and `tethra mesh doctor` become the operator's view of the
distributed system.

## Read first

- DESIGN §D5 (key lifetime), §D9 (repair), §D13 and §D19 (MESH-SI-7).
- `crates/gateway/src/control.rs` (42-48 and 661-727 for the socket/lock pattern; 943-1004 and 1023-1033 for Windows) and `crates/gateway/src/service.rs` (the poller thread pattern at 374-401, the shutdown flags).
- `crates/core/src/session.rs` (`session.json` and its expiry: how a CLI session ends).
- `docs/decisions/0020-gateway-matching-key-lifecycle.md`.
- `mdns-sd` 0.21 docs.
- The STATUS.md handoff notes for 04.

## Scope (build all of this)

### 1. `crates/mesh::node`

- **Loop:**
  - Every `interval` (default 30 s, ±20% jitter from an injected RNG), and immediately
    on `replicate-now`, the node runs one exchange per eligible peer, with at most 4
    concurrent outbound exchanges.
  - Before each round it calls the **round hooks**. In this increment that list is
    empty; 06 adds the publisher, 07 the cap reconciler.
  - Every 24 h, plus on `doctor --repair`, it runs repair (D9).
- **Peers (`peers.rs`):**
  - Sources are manual (`mesh_peers.source='manual'`), gossip (other devices'
    `device.info.listen_addrs`) and mDNS.
  - Exponential backoff runs from 5 s to 15 min, with jitter.
  - The node records `last_attempt_at`, `last_success_at`, `failures` and
    `unreachable_since`.
  - One address maps to one device once the handshake reveals who it is. A changed key
    at the same address is logged and surfaced; that's the expected situation after a
    device re-pairs.
- **Publishing listen addresses:** the node publishes its configured `--listen`
  addresses in `device.info` (LWW, D6) when they change. Unspecified-address binds
  (only with `--all-interfaces`) publish the concrete interface addresses instead,
  enumerated without new dependencies if possible; otherwise require explicit
  `--advertise <addr>`.
- **Key lifetime (MESH-SI-7):**
  - The node is constructed from `MeshKeys` (03), which live in `Zeroizing`.
  - It takes a `StopCondition` trait object:
    - for the CLI, `SessionAlive(session path, id)`, which stops when `session.json`
      disappears or expires, or when `TETHRA_PASSWORD` mode reaches a maximum runtime
      the user opts into (default: none, so it runs until Ctrl-C);
    - for the desktop (09), a lock signal.
  - On stop, the node drops its keys and closes its listener.
- **Clock-skew and fork reporting:** these feed status through `mesh_meta`.

### 2. `crates/mesh::instance`, single instance plus control

- **Unix:** `<data-dir>/mesh/node.sock`, a 0600 socket in a 0700 directory with
  same-owner checks, and a per-boot nonce file `node.nonce` (0600). Mirror the gateway's
  `control.rs`.
  - Binding is the single-instance lock. A stale socket with no listener is replaced
    safely, the way the gateway does it.
  - The protocol is one JSON line per request (≤ 8 KiB): `{op: Health|Status|ReplicateNow{peer?}|Stop, nonce}`.
- **Windows:** an exclusive `127.0.0.1:0` listener with the port written to a nonce file
  alongside the nonce. Compile it and unit-test it in Windows CI, and mark it "runtime
  untested on Windows" in KNOWN_LIMITATIONS.

### 3. `crates/mesh::discover`

- `trait Discovery { fn announce(&self, port, txt); fn browse(&self) -> Vec<SocketAddr>; }`.
- `MdnsDiscovery` uses `mdns-sd` 0.21. Add the dependency and record it in ADR 0031.
- `FakeDiscovery` is in-memory and shared between test nodes.
- TXT content follows D13 exactly: `v=1` and `m=<16 hex of HMAC-BLAKE3(access_key, "mdns"||utc_day)>`.
  The instance name is random per boot. No hostname, device name or user name.
- Discovery is off unless `mesh serve --discover`.
- **Tests never construct `MdnsDiscovery`.** Guard this with a test that greps the test
  sources for `MdnsDiscovery::new`.

### 4. CLI

| Command | Behaviour |
|---|---|
| `serve --listen … [--all-interfaces] [--discover] [--advertise <addr>]…` | Becomes the full node, in the foreground. Ctrl-C stops it gracefully. |
| `replicate [--peer]` | Goes through the running node's control socket if one exists, otherwise does a one-shot exchange (04). |
| `peer add <addr:port>`, `peer list`, `peer remove <addr:port>` | |
| `status` | Adds the node state (running or not, pid, listen addresses), and per peer: device name, last success, failures, unreachable since, and **lag**. Lag is the number of items the peer is behind or ahead per origin, from the last Hello. Also clock-skew flags, rejected-item counts, fork evidence, repair stats. |
| `doctor [--rebuild] [--repair]` | Checks the marker, the schema version, whether the listener is bound and reachable from itself, whether the views match a rebuild (`--rebuild` rewrites them), digest roots versus peers, the last repair and whether it changed anything (a bug signal), and any keys missing or corrupt. Each check prints a finding with a plain-language fix. |

### 5. Smoke

Extend the two-node block: B runs `peer add` for A and `serve` in the background. Then:
1. A mints an item, for example `rename`.
2. Within about 2 intervals (configure a 1 s interval via a hidden test flag or env
   `TETHRA_MESH_INTERVAL_MS`, **debug builds only**), B's `devices` shows the new name.
3. Stop both nodes through the control `Stop` op.

## Out of scope

The publisher and usage (06), caps (07), a desktop-hosted node (09), and a LaunchAgent
or systemd node (not in v1, D13).

## Tests to write

- **`crates/mesh/tests/node.rs`**: three nodes with short intervals and `FakeDiscovery`.
  - They converge with no manual exchanges.
  - Gossip alone (no manual peer on C) lets C find A through B's view of A's
    `device.info`.
  - Backoff: an unreachable peer's attempts space out as specified (use the injected
    clock/RNG).
  - Partition: block the links with a test shim, then heal. The nodes converge after
    heal.
  - Stop on session expiry: delete or expire the session file and the node stops within
    one interval and zeroizes its keys (assert through a test hook that the `Zeroizing`
    drop ran).
  - Single instance: a second `serve` on the same data dir fails with a clear error.
  - Control: Status, ReplicateNow and Stop, plus a wrong nonce is refused.
- **`discover.rs`:**
  - the TXT contains only `v` and `m`;
  - `m` rotates by UTC day and is computable only with the access key;
  - the instance name is random per boot;
  - the guard that no test constructs `MdnsDiscovery`.
- **`doctor.rs`:** each check's failure is detectable. Simulate a corrupt view row, a
  marker mismatch and a repair that changes state.
- **CLI** (`apps/cli/tests/mesh_cli.rs` additions): `peer add/list/remove`, `status
  --json` field coverage, and `doctor --json`.

## Acceptance criteria

- [ ] Nodes converge on their own across partitions and heals, in real-socket tests.
- [ ] MESH-SI-7 has a test: keys drop on stop and on session expiry.
- [ ] Single-instance and control socket work (Unix). Windows compiles and its unit tests pass in CI.
- [ ] mDNS is opt-in and privacy-preserving, and CI never multicasts.
- [ ] `status` and `doctor` show lag, skew, forks and repair. Each field is documented in `docs/mesh/USER_GUIDE.md`, which you create now.
- [ ] Smoke passes with the autonomous-convergence check.
- [ ] The check suite is green.

## Verification commands

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-mesh --test node --test discover --test doctor
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-cli --test mesh_cli
bash scripts/smoke.sh
```

## Docs to update

- `docs/mesh/USER_GUIDE.md` (new): setup on a LAN and on Tailscale, `serve`, `peer add`,
  `status` and `doctor` field meanings, and troubleshooting.
- `docs/mesh/ARCHITECTURE.md`: the runtime section.
- `docs/mesh/KNOWN_LIMITATIONS.md`: no background service, Windows runtime untested,
  mDNS LAN-only.
- `docs/mesh/SECURITY_INVARIANTS.md`.
- ADR 0031: the `mdns-sd` version.
- `CHANGELOG.md`.

## Handoff checklist

- [ ] STATUS.md row 05 `done`.
- [ ] Handoff notes: the round-hook API that 06 and 07 plug into, and how to run the node
      with short intervals in tests.
