# Local Gateway — measured performance (Phase 3)

Measured, not asserted. Every number below was produced by
`bash scripts/gateway_perf.sh` (the `#[ignore]` suite in
`crates/gateway/tests/perf.rs`, release mode, `--test-threads=1`) against
LOCAL synthetic upstreams on this machine:

- **Machine:** Darwin 25.5.0 arm64 (Apple Silicon laptop), 2026-07-26
- **Suite result:** 8 passed, 0 failed

## How these numbers were produced, honestly

- Synthetic upstreams ride the transport-generic **test seam**
  (`InsecurePlainConnectorForTests` + `RouteTable::insert_for_test`): the
  production SSRF policy refuses loopback origins BY DESIGN (SI-3), so a
  packaged gateway **cannot** forward to a local fake. These numbers come
  from the same forwarding engine compiled in release mode, minus the
  production TLS handshake toward the upstream (a real exchange adds the
  provider's TLS + network time to BOTH the direct and gateway paths).
- "Added" compares client→upstream directly against client→gateway→upstream
  with the same handler on the same machine. Numbers vary run to run by
  tens of microseconds; treat them as magnitudes, not truths.
- Memory/CPU/thread samples are `ps` self-observations of the TEST process
  (they include the harness's own allocations — e.g. the 8 MiB canned
  response body — so they are upper bounds on the gateway's own footprint).

## Added latency (small JSON, keep-alive, n=400)

| path | p50 | p95 | p99 |
|---|---|---|---|
| direct | 29 µs | 51 µs | 70 µs |
| through gateway | 98 µs | 177 µs | 208 µs |
| **added** | **69 µs** | **126 µs** | ~138 µs |

The gateway adds well under a millisecond per request on pooled
connections. Against a real provider round trip (tens to hundreds of ms),
this is not perceptible — a claim made here only because it is measured.

## Streaming (SSE, 200 events at 2 ms cadence, chunked)

| path | first event | full stream |
|---|---|---|
| direct | 6.2 ms | 503.3 ms |
| through gateway | 11.8 ms | 510.6 ms |
| **added** | **5.6 ms first-byte** | **7.3 ms total** |

All 200 events relayed intact through the strict chunked relay (asserted
by the test — streaming correctness, not just speed). First-token latency
includes the gateway's fresh upstream dial for the first request on a
connection.

## Throughput and large bodies

| scenario | direct | gateway |
|---|---|---|
| 8 MiB JSON download (median of 3) | 14 ms | 11–19 ms |
| 4 MiB request upload (median of 3) | 7 ms | 11 ms |
| 300 fresh connections, one request each | 6.18 ms/conn | 7.83 ms/conn (**+1.7 ms**) |
| 12 concurrent clients × 25 requests | — | 22 ms wall, **13,489 req/s**, p50 359 µs, p95 494 µs, p99 12.6 ms |

Large-body relaying is effectively line-speed (the 16 KiB relay buffer
streams; nothing is buffered whole). The p99 tail under concurrency is
connection-setup, not steady-state.

## A measured design fix: accept-poll latency

The first measurement round showed **+47 ms per fresh connection**
(53.6 ms/conn vs 6.1 direct) and a 55 ms concurrent p99. Root cause: the
non-blocking accept loop woke every 50 ms (`ACCEPT_POLL`) to observe the
shutdown flag, so every new connection waited up to 50 ms to be accepted.
Keep-alive SDK traffic never saw this, but one-shot clients (curl,
scripts) always did. `ACCEPT_POLL` is now 5 ms: churn overhead fell from
47 ms to **1.7 ms per connection** and concurrent throughput tripled
(4.3k → 13.5k req/s) with no measurable idle-CPU cost. Recorded here as
the implementation evidence behind the change.

## Slow peers

- **Slow upstream** (300 ms think time): 312 ms end to end — the gateway
  adds ~12 ms around the upstream's own delay, first-byte included.
- **Slow client** (2 MiB response read at 4 KiB/2 ms): completes intact in
  ~1.28 s, paced by the client. The gateway relays with backpressure; the
  bounded client-write timeout (120 s) caps how long a stalled reader can
  pin a thread and an upstream socket.

## Observation queue and database pressure

- **Queue pressure:** 2,000 keep-alive requests forwarded in **165 ms**
  (~12k req/s) while a REAL writer persisted behind them: 1,700 written,
  **300 dropped and counted**, 0 persist failures. Forwarding never waits
  on the writer (SI-12); the drop counter is the honest cost, surfaced in
  status/doctor as `buffer_overflow` + `coverage_gap`.
- **Database pressure:** 200 requests forwarded in **13 ms** while the
  vault database was held under `BEGIN EXCLUSIVE` — forwarding provably
  unaffected by a locked/contended database; unpersistable events are
  dropped-and-counted, never blocking.

## Process footprint (test-process upper bounds)

RSS 4–96 MiB across scenarios (the high readings include the harness's
own 8 MiB response bodies and buffers), CPU 0–15% during active transfer,
4–10 threads (listener + per-connection + writer + control + poller).

## What is NOT claimed

- No "imperceptible overhead" claim beyond what the table shows.
- No real-provider numbers: no live-provider latency was measured in this
  suite (packaged validation exercises real origins with fake keys, where
  provider network time dominates).
- No Windows or Linux numbers: this table is one macOS arm64 machine.
