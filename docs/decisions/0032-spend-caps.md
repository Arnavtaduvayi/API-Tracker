# ADR 0032 — Spend caps: a replicated monthly ceiling kept without coordination

Status: accepted (Increment 07 on `feat/device-mesh`: alerts only; gateway
enforcement is Increment 08)
Date: 2026-10-28
Builds on: ADR 0031 (Tethra Mesh), PROTOCOL.md §5.5 (the bounded counter)
Preserves: gateway SI-19 (caps and budgets never share figures), ADR 0020 (the
node holds keys only while unlocked)

## Context

A developer with several devices wants "project X may spend at most $50 a
month across all my machines". Each device's gateway sees only its own
traffic, the devices are often apart (a laptop on a plane), and there is no
server to ask. A global invariant — total gateway-estimated spend across every
device ≤ the cap — has to hold while devices cannot reach each other, and the
cap has to keep working for a device that is offline across the 1st of the
month.

Consensus (a majority must agree before any spend) fails the offline case
outright. Counting spend and comparing it with the cap after the fact
(eventual consistency) gives honest alerts but no bound: two partitioned
devices can each spend the whole cap.

## Decision

**A bounded counter (escrow of rights).** We use the construction of Balegas
et al., "Extending eventually consistent cloud databases for enforcing numeric
invariants" (SRDS 2015): the invariant `Σ used ≤ cap` is split into local
*rights*. Each device may spend only rights it holds; rights move between
devices by single-writer transfers; a device's available amount is what it was
minted or sent, minus what it sent, burned or spent. As long as every device
spends only within its own rights, the invariant holds under any partition and
any merge order, with no coordination on the spend path (the gateway enforces
that from Increment 08, up to the bounded overshoot below). The paper's insight is
that a numeric invariant over replicated state can be kept by pre-dividing the
slack rather than by agreeing on each operation; its cost is that a device
with no rights cannot spend even when the global total has room (the rights
sit elsewhere). Tethra's view, item kinds and the one-hop clamp are specified
in PROTOCOL.md §5.5 (Increment 01, ADR 0031 R3/R4); this ADR is the policy on
top.

**D1 — Ownership and the month.** `tethra mesh cap create <project>
--monthly <usd>` makes this device the cap's immutable owner (`cap.def`, owner
= origin). The period is the UTC calendar month, with the same boundaries as
`budget::period_start` (a test checks they agree; caps have their own helper
and never call into budgets). Each `(cap, month)` is its own bounded counter:
**unused rights expire with the month.** One cap is in force per mesh project
(after merges, per root project). If two devices that cannot see each other
both create one, the one created first (by `created_hlc`, then id) is the cap
and the other is labelled *superseded*: it is not minted, distributed,
changed or alerted on again.

**D2 — Minting and advance minting.** Only the owner mints. It mints the
current month's target when the cap is created (and for a month it has not
minted, the first time it runs in it), and **from day 20 of month m it mints
month m+1 in advance** at the scheduled target (m+1's own target if one was
written, else the latest earlier one). A device that is offline on the 1st
therefore already holds next month's share — provided the owner was online
between the 20th and the end of the month and the share reached it.

**D3 — Distribution and rebalancing.** When the owner holds a minted month it
makes sure every *active* device (this device exchanged with it, or saw it
publish usage or cap figures, in the last 30 days) has received at least
`target / active` from it; the owner keeps the remainder of the division. The
rule is cumulative ("received at least"), so it is idempotent and a device
that becomes active later in the month gets its share then. Rebalancing runs
during exchanges: a device holding less than **20%** of its fair share sends
`Direct RightsRequest { cap, month, want, reclaim: false }`, asking for enough
to get back to its share; the peer answers after the exchange commits, on its
own freshest view, granting `min(want, avail − 50% of its share − its own
overrides)`. The 20%/50% gap is the hysteresis that stops rights moving back
and forth. At most one request per peer per cap per 5 minutes, and at most one
grant per requester per cap per 5 minutes (both recorded atomically in
`mesh_meta`, so two exchanges with one peer at once cannot both act). A grant
reaches the requester in a later exchange.

**D4 — Raise adds; lower sets.** "Set the cap to X" is never offered: two
partitioned devices both setting it would mint twice.
- **Raise** on the owner mints `+x` (this month, and next month once minted)
  and raises the LWW target by `x`; distribution hands out the larger shares.
- **Raise elsewhere is a local override**: a self-mint `R[i][i]` with the
  display flag `override = true`, for this device only, until the end of the
  month, after a confirmation that says so. Views label it; it counts as a
  mint, so the effective cap is `target + overrides`, and an override is never
  burned by a lower or given away by rebalancing. (PROTOCOL.md §5.5 already
  counted a non-owner self-mint; ADR 0031 R4.)
- **Lower** sets the LWW `cap.target` for this month (and next month if a
  target is already scheduled), after confirmation, on any device. The
  *pending decrease* is `supply − max(target + overrides, total used)`: rights
  in existence beyond what the cap now allows, never counting rights already
  spent. Every holder that learns of it burns what it holds above `max(0, its
  share − its own spend) + its own overrides`, never more than the pending
  decrease. The owner then reclaims any remainder: once its own burn is done
  it sends `RightsRequest { reclaim: true }` to holders, who transfer the
  amount back, and the owner burns it. A lower below what has already been
  spent caps every device for the rest of the month. While a month has a
  pending decrease, no device asks for or grants ordinary rights.

**D5 — Reclaim.** `tethra mesh cap reclaim <cap> [--from <device>]` (owner
only) asks devices to hand their unspent rights back, for a device about to be
removed. The requests travel in the owner's next exchanges with them for 24
hours, during which the owner grants them nothing.

**D6 — Freeze.** If the owner device is removed (or forks), the cap is
**frozen**: nobody mints for it again, not even an override (`MeshError::
CapFrozen`). The rights already handed out for the month stay usable; the next
month has none. A frozen cap does not count as the project's cap, so the user
creates a new one, which the CLI suggests.

**D7 — `used` is the gateway's own figure.** Each device publishes `cap.used`
for the current and previous month as its gateway's month spend for the cap's
bound projects — `usage::local_month_spend_micros`, Increment 06's single
function (the estimate from `gateway_usage_daily`, priced requests only). A
decrease (local data deleted) bumps the epoch, as usage counters do (DESIGN
§D8). An unbound device publishes nothing new: what it published stays. A
device's own spendable figure counts its gateway's spend before it is
published, and its open escrow.

**D8 — Decide inside the transaction.** Every decision — what to mint,
distribute, burn, grant, publish — is computed inside the write transaction
that publishes it, from the state and the local gateway figures as they are
there (`SqliteStore::mint_with`). A running node and a CLI command on the same
database can therefore never both act on one snapshot. A decision that mints
and writes nothing rolls back, so an idle round costs no fsync and no
generation bump for other processes.

**D9 — The escrow fence (MESH-SI-10).** Every transfer, burn and reclaim
grant is first a row of the local `mesh_cap_escrow` table. With cap
enforcement off on this device (always, in this increment) or no gateway
running (the gateway's control socket answers no connection), the item is
minted and the row written `published` in one transaction. With enforcement
on and the gateway running, the row is written `pending`, the amount is
reserved (this device's own available figure leaves it out), and nothing is
published; the gateway deducts every open row from its snapshot and marks the
rows it counted `acked` with its snapshot generation (`caps::escrow::ack`,
the contract Increment 08 implements); the node publishes acked rows at its
next round, in the same transaction that marks them `published`. A row not
acknowledged within 15 s is reported as waiting and carried to later rounds;
a row whose month ended or that no longer fits is `cancelled`. Without the
fence, the node could give away rights the running gateway's snapshot (up to
5 s old) still counts as available, and both would spend them.

**D10 — Alerts, not budgets.** In this increment caps raise local alerts
only, through the existing alert system: kind `mesh_spend_cap`, dedup keys
`mesh_cap:<cap>:<YYYY-MM>:80` and `:100`, raised by the monitor while the
vault is unlocked when this device's view of the month's total (its own
unpublished spend included) crosses 80% and 100% of the effective target. The
text says the figure is cross-device, estimated and only as fresh as the last
exchange with each device. Caps never read or write `budget.rs`, and budgets
never see cap figures (SI-19).

## Alternatives considered

- **Consensus (Raft) on each spend or each cap change.** Rejected for the
  same reason as for the mesh (ADR 0031): a lone offline laptop could not
  spend, or the cap would not hold for it.
- **Count spend, alert after.** Honest but unbounded: partitioned devices can
  each spend the whole cap. It is what Increment 07 shows; the rights make the
  bound possible when the gateway enforces (Increment 08).
- **Per-device static quotas (cap / n, no transfers).** Simple and safe, but a
  busy device would be capped while idle ones hold unused rights. Rebalancing
  with hysteresis keeps the safety and recovers most of the liveness.
- **"Set to X" for raise.** Double-mints under partition. Rejected (D4).
- **Proportional or water-filling burns after a lower.** A device-local burn
  above its own share, plus an owner reclaim of the remainder, needs no global
  view and never burns rights below what the cap allows on views that agree;
  with stale views it can over-burn, which is safe (the cap is then tighter
  than the target until the owner raises it).
- **Locking the store across a whole reconcile.** Two processes would still
  decide from their own snapshots; deciding inside each write transaction is
  what makes the decisions idempotent.
- **Using the gateway's control socket for the ack.** Windows has no control
  channel; a table both processes already open works everywhere (DESIGN §D15).

## Security implications

- **A self-limit, not a security boundary.** Caps count only traffic through
  Tethra's gateway; anything that bypasses it is not capped. The docs and every
  report say so.
- **Safety under partition.** For honest devices `Σ used ≤ minted − burned`
  (overrides are mints) in every view, and no device's own available amount
  is below zero. The caps simulator checks both at every step on real SQLite
  stores, and checks the converged state against the independent oracle.
- **A malicious member** can mint itself an override (labelled), lower the
  target (labelled LWW, audited locally), hoard the rights it was given, or
  refuse to answer requests. It cannot create rights in other devices' views:
  the one-hop clamp honours its transfers only up to what it was minted or
  sent. A device that holds rights and never cooperates (malicious, broken or
  gone) keeps a lower from fully settling: its rights are counted as pending
  until it burns them or is removed.
- **Bounded overshoot (Increment 08).** Cost is known only after a response,
  so the gateway will admit at most one in-flight request per cap when rights
  are nearly exhausted; `Σ used` may exceed supply by at most one request's
  cost per cap per device (MESH-SI-9). In Increment 07 nothing blocks: spend
  beyond a device's rights shows as a negative available amount and an alert.
- **Removal.** A removed device's rights entries count up to its cutoff
  (ADR 0031 R2). A removal whose cutoff is below items the removed device
  already handed out drops those transfers from views; recipients that spent
  them then show a negative available amount. Removing a device after a final
  exchange avoids this; `cap reclaim` first returns its rights.
- **Escrow rows** are local, never replicated, wiped with the rest of the mesh
  state on `mesh leave` and backup restore.

## Future limitations

- Rights reach a device only through exchanges: a device that cannot reach
  any holder with surplus stays capped at what it holds (safety over
  liveness). A device offline across the boundary is covered only if the owner
  was online between the 20th and the month end and its share reached it.
- The fair share is equal; it does not follow each device's usage pattern.
- An owner that is removed freezes its cap for good; ownership does not move.
- Stale views after a lower can over-burn (safe, tighter than the target);
  the owner raises the cap to recover.
- Rebalancing is per peer per 5 minutes; a burst on a device with few rights
  waits for its next exchanges.
- On Windows the node cannot yet probe whether the gateway runs (no control
  channel): with enforcement on, every transfer waits for the gateway's ack.
