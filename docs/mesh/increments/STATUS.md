# Tethra Mesh: increment ledger

Every session reads this file first and updates it at the end (README §1).

**States:** `pending`, `in-progress`, `done`, `blocked` (give the reason).

| Branch | Base | Draft PR |
|---|---|---|
| `feat/device-mesh` | `origin/main` @ `5ec8198` (2026-10-26) | _(opened by Increment 01; put the number here)_ |

| # | Increment | Mode | Size | State | Started | Finished | Commits | CI run (result) |
|---|---|---|---|---|---|---|---|---|
| 01 | [Foundations & decision](01-foundations-and-decision.md) | S | L | pending | | | | |
| 02 | [Sans-IO protocol & simulator](02-protocol-and-simulator.md) | O | L | pending | | | | |
| 03 | [Persistence & identity](03-persistence-and-identity.md) | S | L | pending | | | | |
| 04 | [Transport & pairing](04-transport-and-pairing.md) | S+R | L | pending | | | | |
| 05 | [Node runtime](05-node-runtime.md) | S | M | pending | | | | |
| 06 | [Shared projects & cross-device usage](06-shared-projects-and-usage.md) | S | M | pending | | | | |
| 07 | [Spend caps (alerts only)](07-spend-caps.md) | S | L | pending | | | | |
| 08 | [Gateway cap enforcement](08-gateway-cap-enforcement.md) | S+R | M | pending | | | | |
| 09 | [Desktop: devices & node](09-desktop-devices-and-node.md) | O | M | pending | | | | |
| 10 | [Desktop: projects, usage & caps](10-desktop-projects-usage-caps.md) | O | M | pending | | | | |
| 11 | [Opt-in credential sharing](11-credential-sharing.md) | S+R | L | pending | | | | |
| 12 | [Hardening, audit & ship](12-hardening-audit-ship.md) | O | L | pending | | | | |

Sizes are rough context cost for a 1M-token session:
- **M** is about 15-25% of the session.
- **L** is about 25-45%.

A session that finishes an M with plenty left should usually continue; check the 40%
rule (README §1 step 12).

## Test counts (update every increment; always print the command next to the number)

| After | Rust tests (command) | Frontend tests | Smoke |
|---|---|---|---|
| base 5ec8198 | ~1,486 (projects-first handoff) | ~261 | 140 |

## Deviations from DESIGN.md

_(Increment, what changed, why, where it's recorded: ADR or doc. Material deviations
also update DESIGN.md and the affected increment files; README §7.)_

## Handoff notes (newest first)

_(Per increment: surprises, load-bearing facts, environment gotchas, anything not done,
pending CI runs to check first.)_

## Planning record

- **2026-10-26.** Plan created in a planning session.
  - The owner chose a P2P CRDT mesh; usage, metadata and caps first and credentials
    last (opt-in); own devices only; 12 increments maximum.
  - The design was reviewed by an independent planning agent before this was written.
    Its P0 fixes are already folded into DESIGN.md: signed items, accept-and-flag HLC,
    Commit-only VV, per-origin LWW maps, removal cutoffs, fork detection, the
    bounded-counter month rules, the escrow fence, 403 instead of 429, and delta/epoch
    publishing.
