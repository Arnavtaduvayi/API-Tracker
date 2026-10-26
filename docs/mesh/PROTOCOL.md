# Tethra Mesh protocol, version 1

This is the normative specification of Tethra Mesh: what an item is, how
devices verify and combine items, and how two devices exchange them. Code
lives in `crates/core/src/mesh/` (pure, sans-IO) and, from Increment 04,
`crates/mesh/` (network). The decision record is
[ADR 0031](../decisions/0031-device-mesh.md).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

Every section carries a status line:

- **Status: implemented (NN)** — built and tested in increment NN.
- **Status: specified, lands in NN** — normative now; the code arrives in NN.
  Increment NN MAY refine wording but MUST record any change in ADR 0031 and
  `docs/mesh/increments/STATUS.md`.

Where this document and `docs/mesh/increments/DESIGN.md` differ, this document
wins: it records what was decided while building. Section 13 lists every place
this document deliberately departs from the original design brief.

---

## 1. Vocabulary

**Status: implemented (01)**

| Term | Meaning |
|---|---|
| mesh | The set of devices paired with each other. Identified by a random 16-byte `mesh_id`. |
| device | One Tethra installation (one data directory) holding a mesh identity. Not a machine. Identified by a random 16-byte `device_id`. |
| genesis | The device that ran `mesh init`. Every member learns its `device_id` when it pairs (§9). |
| origin | The device that created and signed an item. |
| item | A signed, immutable record. The only thing that replicates. |
| dot | `(origin, seq)`: an item's position in its origin's log. |
| VV | Version vector: `origin -> highest seq held`. |
| exchange | One anti-entropy session between two devices. Never "sync". |
| bind | A local-only mapping from a local project to a mesh project. Never "link". |
| spend cap | A replicated monthly ceiling on gateway-estimated cost. Never "budget". |
| rights | Bounded-counter allowance, in micro-USD, one device may spend against a cap in one month. |
| admitted | Whether an origin's item at a given seq counts in views (§6.4). |

Identifiers (`mesh_id`, `device_id`, mesh project ids, cap ids, share ids,
credential refs) are 16 bytes from the operating system RNG, written as
**exactly 32 lowercase hexadecimal characters**. That textual form is the only
valid encoding. Identifiers order by their bytes, which is the same as ordering
their hex strings.

## 2. Item body and the canonical codec

**Status: implemented (01)** — `mesh::codec`

### 2.1 Envelope

An item body is a JSON object with exactly these eight members, in exactly this
order:

| # | Member | Type | Rule |
|---|---|---|---|
| 1 | `v` | integer | Format version. MUST be `1`. |
| 2 | `mesh` | string | `mesh_id`, 32 lowercase hex. |
| 3 | `origin` | string | Origin `device_id`, 32 lowercase hex. |
| 4 | `seq` | integer | 1 to 2^64−1. Dense per origin: the origin's n-th item has `seq = n`. |
| 5 | `hlc` | integer | 0 to 2^64−1 (§4). |
| 6 | `kind` | string | 1-64 bytes of `[a-z0-9._-]`. |
| 7 | `key` | string | 1-1024 bytes, no control characters (U+0000-U+001F, U+007F-U+009F). |
| 8 | `payload` | object | Kind-specific (§2.4). |

### 2.2 Canonical form (byte level)

A body has exactly one valid byte encoding:

1. No whitespace anywhere outside strings.
2. The envelope members appear in the order of §2.1.
3. Inside `payload`, at every depth, object members are **sorted by the UTF-8
   bytes of their names**, ascending. Duplicate names are invalid.
4. Numbers are integers in decimal with no sign for non-negative values, a
   single `-` for negative ones, no leading zeros, no fraction, no exponent, and
   never `-0`. Payload integers MUST fit in `i64` or `u64`.
5. Strings are `"`-delimited. Inside them, `"` is written `\"`, `\` is written
   `\\`, U+0008 `\b`, U+000C `\f`, U+000A `\n`, U+000D `\r`, U+0009 `\t`, any other
   code point below U+0020 as `\u00XX` with **lowercase** hex digits, and every
   other code point (including `/`, U+007F and all non-ASCII) as its literal
   UTF-8 bytes.
6. `true`, `false`, `null` as literals.
7. Arrays and objects inside `payload` nest at most 16 deep (the payload object
   itself is depth 1).
8. The body is at most 65 472 bytes (64 KiB minus the 64-byte signature).

A decoder MUST parse the bytes, then re-encode the result by these rules, and
MUST reject the item unless the re-encoding is byte-identical to the input
(`NonCanonical`). This rejects whitespace, reordered members, alternative
escapes (`A`, `\/`), duplicate members, floats and `-0` without listing
them individually. An unknown envelope member is rejected as malformed. A body
whose `v` is not 1 is rejected as `UnsupportedFormat(v)`, so a newer format
reports itself instead of looking like garbage.

**Example.** `mesh = 11…11`, `origin = 22…22` (32 hex digits each), `seq = 7`,
`hlc = Hlc(1700000000000, 3)`, `kind = project.meta`,
`key = 0123456789abcdef0123456789abcdef`, payload
`{name: "Billing API", archived: false, merged_into: null}` encodes as the
single line (shown wrapped):

```text
{"v":1,"mesh":"11111111111111111111111111111111","origin":"22222222222222222222222222222222",
"seq":7,"hlc":111411200000000003,"kind":"project.meta","key":"0123456789abcdef0123456789abcdef",
"payload":{"archived":false,"merged_into":null,"name":"Billing API"}}
```

(`111411200000000003 = 1700000000000 · 2^16 + 3`.) This exact string is pinned
by the unit test `codec::tests::exact_bytes_of_a_sample_body`.

### 2.3 Unknown kinds

A body whose `kind` is not in §2.4 is valid if it satisfies §2.1-2.2. It MUST be
stored and relayed exactly like any other item, and MUST NOT be materialized.
After an upgrade that understands the kind, views are rebuilt from stored items
(`views::rematerialize`, Increment 03). This keeps a newer Tethra's data intact
while it passes through an older one.

### 2.4 Kinds in v1

Payload decoders MUST ignore payload members they do not know (forward
compatibility); the envelope stays strict. A known kind whose key or payload
fails the rules below is **rejected at ingest** like a bad signature (§3.3).
Honest devices never mint one (minting parses first), and rejecting it — rather
than storing it and leaving it out of views — keeps every device's stored
"latest item per key" identical: an invalid item can never silently supersede a
valid one on some devices and not others. (Amended in 02.)

Common value rules: a *name* is 1-128 bytes, not only whitespace, with no
control characters. A *slug* is 1-64 bytes of `[a-z0-9._-]`. A *public key* is
32 bytes as 64 lowercase hex characters. A *day* is `YYYY-MM-DD` (4-digit year,
zero-padded, a real calendar date, UTC). A *month* is `YYYY-MM` (UTC calendar
month).

| Kind | Key | Payload members | Extra rules |
|---|---|---|---|
| `roster.add` | added `device_id` | `added_by`, `name`, `noise_pub`, `seal_pub`, `sign_pub` | `added_by` MUST equal `origin`. `sign_pub` MUST be a valid, non-small-order Ed25519 point. The key MUST equal `derive_device_id(sign_pub, noise_pub, seal_pub)` (§6.1). |
| `roster.remove` | removed `device_id` | `cutoff_seq` (u64) | |
| `device.info` | `device_id` | `listen_addrs` (≤ 16 strings of 1-255 bytes, no whitespace or controls), `name` | key MUST equal `origin`. |
| `mesh.setting` | setting name (slug) | `value` (any canonical JSON) | |
| `project.meta` | `mesh_project_id` | `archived` (bool), `merged_into` (id or null; absent = null), `name` | `merged_into` MUST NOT equal the key. |
| `usage.counter` | `<mesh_project_id>/<day>/<provider>/<model>` | `epoch` (u32), `totals` (object of the eight u64 fields below) | provider is a slug; model is 1-256 bytes without controls and MAY contain `/` (the key splits on the first three `/`). |
| `cap.def` | `cap_id` | `created_hlc` (u64), `mesh_project_id`, `owner_device` | `owner_device` MUST equal `origin`. |
| `cap.target` | `<cap_id>/<month>` | `target_micros` (u64) | |
| `cap.rights` | `<cap_id>/<month>/<to>` | `amount_micros` (u64, cumulative), `override` (bool, absent = false) | `to` is a `device_id` or the literal `burn`. `override = true` requires `to == origin`. |
| `cap.used` | `<cap_id>/<month>` | `epoch` (u32), `used_micros` (u64, cumulative) | |
| `share.sealed` | `<credential_ref>/<recipient>` | `credential_name`, `mesh_project_id`, `provider` (slug), `recipient`, `sealed` (standard base64 with padding, 1-16384 bytes decoded), `share_id`, `value_version` (u64) | payload `recipient` MUST equal the key's. Used from Increment 11. |
| `share.revoke` | `<credential_ref>/<recipient>` | `share_id` | Used from Increment 11. |
| `fork.report` | forked `device_id` | `hash_a`, `hash_b` (item hashes, 64 lowercase hex), `seq` (u64 ≥ 1) | `hash_a ≠ hash_b`. Minted by a device that detected the fork (§7). Added in 02. |

`usage.counter` totals: `requests`, `priced_requests`, `unpriced_requests`,
`unextracted_requests`, `input_tokens`, `output_tokens`, `cached_input_tokens`,
`estimated_cost_micros`. Cost covers priced requests only and is computed on the
device the usage came from, with that device's pricing table.

## 3. Signatures, hashes and ingest

**Status: implemented (01)** — `mesh::sign`, `mesh::item`

### 3.1 Signature

```text
sig = Ed25519-Sign(sign_key, "tethra-mesh/v1/item" || 0x00 || body_bytes)
```

Pure Ed25519 (RFC 8032), 64-byte signature. The 20-byte domain prefix
(`74 65 74 68 72 61 2d 6d 65 73 68 2f 76 31 2f 69 74 65 6d 00`) means an item
signature is never a valid signature over any other message this key signs.
Verifiers MUST use strict verification (`verify_strict`: canonical `S`, and
small-order `A` and `R` rejected). The item hash covers the signature, so a
malleable signature would let a relay create a second valid encoding of one
item and fake a fork.

### 3.2 Wire form and hash

An item on the wire and at rest is `body_bytes || sig` (signature last), at
most 65 536 bytes. Its hash is:

```text
hash = BLAKE3(body_bytes || sig)
```

that is, the BLAKE3 of exactly the wire bytes. Devices MUST store and relay the
exact bytes they received and MUST NOT re-serialize a received body;
verification always runs over stored bytes. Because the codec is canonical and
Ed25519 is deterministic, one body signed by one key always yields one item.

### 3.3 Ingest checks

A receiver MUST apply these checks in order. Any failure rejects the item: it
is not stored, it is counted in `mesh_meta.rejected_items`, and the receiver's
VV MUST NOT advance past it.

1. **Size**: at most 65 536 bytes, and longer than the 64-byte signature.
2. **Parse**: §2 (canonical, v = 1, envelope rules).
3. **Mesh**: `mesh` equals the receiver's `mesh_id`.
4. **Origin known**: the origin is *known* in the receiver's roster (§6.3,
   step 1), evaluated over its stored items **plus every roster item staged
   earlier in the same session**. The one exception is the **genesis
   self-add**: a `roster.add` whose `origin` and `key` both equal the genesis
   `device_id`; it is verified with the `sign_pub` it carries. An item whose
   origin is not yet known is held *pending* and re-checked after every
   `Items` frame and at `Commit`; it is rejected only if its origin is still
   unknown at `Commit`.
5. **Signature**: §3.1 with the origin's `sign_pub` from the roster.
6. **Rate**: the origin has not exceeded 10 000 items per hour as seen by this
   receiver's clock (§11). An item over the rate is deferred to a later session
   like a rejected one.
7. **Gap**: on the main path (§8), `seq ≤ vv[origin] + 50 000`. (A validly
   signed item far beyond the receiver's VV can never be committed anyway —
   commits need every dot in between — so it is refused early.)
8. **Kind**: a known kind MUST parse (§2.4); an unknown kind is kept opaque
   (§2.3).

**Rejection is per origin, per session, and keeps the valid prefix.** When one
of an origin's main-path items is rejected at seq `s`, the receiver commits
that origin's staged items and dots **below `s` only**, advances `vv[origin]`
to at most `s − 1`, and drops the rest of that origin's batch. A later session
retries from there. Consequently an origin that signs an invalid item at seq
`s` (only a misbehaving origin can) never has anything at `s` or above
committed anywhere; a forged item (bad signature) blocks nothing, because the
origin's genuine item at that seq arrives from honest peers.

Items from a removed or forked origin still pass check 4 (such devices stay
*known*), so they keep replicating; whether they count is decided by admission
(§6.4).

## 4. Hybrid logical clock

**Status: implemented (01)** — `mesh::hlc`

An HLC timestamp is one u64: the high 48 bits are physical milliseconds since
the Unix epoch (clamped to 2^48−1), the low 16 bits a logical counter.
Timestamps compare as integers; every tie-break additionally compares the
origin `device_id`. `MAX_DRIFT_MS = 60 000`.

A device keeps `last`, the highest timestamp it has issued or observed.

- **now()**: `last := max(Hlc(physical_now, 0), last + 1)`; return `last`.
  (`last + 1` increments the logical counter and carries into the physical part
  on overflow, so overflow bumps the physical time by 1 ms.) Strictly
  increasing even when the physical clock stalls or steps back.
- **observe(remote)**: `bound := Hlc(physical_now + MAX_DRIFT_MS, 0)`;
  `last := max(last, min(remote, bound))`. The remote **item is accepted
  whatever its timestamp**; a remote above `bound` is *flagged*: the origin and
  its skew (`remote.physical − physical_now`) are recorded in
  `mesh_meta.clock_skew/<origin>` and shown by `status` and `doctor`. An
  observation never moves `last` past `max(last, bound)`.
- **local_write_ts(winner)**: for a local last-writer-wins write, with `winner`
  the HLC of the value the user is looking at: `ts := now()`; if
  `winner ≥ ts` then `ts := winner + 1`. This does **not** move `last`: one
  write is lifted above a skewed device's value, the clock itself stays honest.
- **Persistence**: `mesh_meta.hlc_high_water` is written in the same
  transaction as every minted item; on start, `last := max(last, high_water)`
  (`restore`), so `now()` never returns below it after a restart.
- The HLC orders LWW registers only. Counters, rights and used totals never
  consult it; their day or month comes from the item key.

**Worked example.** Physical clock at 1 000 ms, `last = 0`: `now()` → `1000.0`,
`now()` → `1000.1`. The clock steps back to 500: `now()` → `1000.2`. A remote
`900000.9` arrives at physical 1 000: bound = `61000.0`, so `last := 61000.0`,
flagged with skew 899 000 ms; the next `now()` is `61000.1`. A local LWW write
looking at that remote value gets `local_write_ts(900000.9)` = `900000.10`
while `last` stays `61000.1`.

## 5. Shared CRDT rules

**Status: implemented (01)** — `mesh::crdt`

### 5.1 Single-writer entries

Every item contributes one **entry** to the state of its `(kind, key)`, owned by
its origin. For each `(kind, key, origin)` a device keeps exactly one entry:
the one with the **highest `seq`** — the origin's own order. (Two different
items with the same dot can only come from a fork, §7; between them the higher
hash wins, so the join is total.) This is the same rule the store uses
(`UNIQUE(kind, item_key, origin)`), and it is what makes relaying only the
latest item per key safe (§8.4).

Joining two states is entry-wise: for each `(kind, key, origin)`, keep the
entry with the greater `(seq, hash)`. This is commutative, associative and
idempotent, and the result dominates both inputs.

The HLC plays **no** part in choosing between two entries of the same origin.
For an honest origin, a higher seq also has a higher HLC (and, for counters,
greater-or-equal totals), so nothing changes for honest devices; the rule only
fixes what happens when an origin misbehaves, and it keeps every device's
stored state, incremental views and rebuilt views identical.

The four CRDTs below differ only in how they combine the per-origin entries of
one key across origins.

### 5.2 `lww_map` — last-writer-wins registers

Used by `device.info`, `mesh.setting`, `project.meta`, `cap.target` and (from
Increment 11) `share.*`.

- **State per key**: `origin -> (seq, hash, hlc, value)`, one entry per origin.
- **Value**: among the entries whose origin is **admitted at that entry's seq**
  (§6.4), the one with the greatest `(hlc, origin)`. If none is admitted, the
  key has no value.
- Removing a device needs no history: its entry stops being admitted (if the
  entry's seq is above its cutoff) and the next-greatest admitted entry wins.
  The removed device's *earlier* value for that key is not resurrected — it was
  superseded by its own later entry.

**Worked example.** Device ids order `A < B < C`. Key `k` holds
`A:(seq 3, hlc 100, "x")`, `B:(seq 7, hlc 150, "y")`, `C:(seq 2, hlc 150, "z")`.

1. Value: B and C tie at hlc 150; `C > B`, so the value is `"z"`.
2. Join with a state holding `A:(seq 5, hlc 90, "w")`: A's seq 5 supersedes its
   seq 3 (seq decides within an origin, even though 90 < 100). The register is
   now `A:(5, 90, "w")`, `B:(7, 150, "y")`, `C:(2, 150, "z")`; the value is still
   `"z"`.
3. C is removed with `cutoff_seq = 1`: C's entry (seq 2) is not admitted. The
   value becomes `"y"`.
4. B is also removed with `cutoff_seq = 7`: B's entry (seq 7) is still admitted,
   so the value stays `"y"`.

### 5.3 `owner_counter` — owner-written counters

Used by `usage.counter` (totals) and `cap.used`.

- **State**: `(key, origin) -> (seq, hash, epoch, totals)`, written only by
  `origin`.
- **Value**: one `(epoch, totals)` per admitted origin. Views report every
  origin's figure **labelled by device**; a device with no entry is *unknown*,
  never zero.
- **Honest-writer lattice.** `(e1, t1) ≤ (e2, t2)` iff `e1 < e2`, or `e1 = e2` and
  every field of `t1` ≤ the same field of `t2`. Its join: a higher epoch wins
  outright; equal epochs take the field-wise maximum. An honest origin MUST mint
  each new entry ≥ its previous one in this order: totals only grow within an
  epoch, and when they legitimately fall (the user deleted local data) the
  origin bumps the epoch. For an honest origin, its latest entry therefore
  equals the lattice join of all its entries, so a deletion propagates instead
  of being resurrected by a max.
- A receiver that replaces an origin's entry with a successor that is **not** ≥
  it in the lattice order keeps the successor (seq decides) and SHOULD count a
  regression against that origin (`InsertOutcome::regression`).

**Worked example.** Origin A, key `k`:

1. `seq 4: (epoch 0, {requests 10, cost 500})`, then
   `seq 9: (epoch 1, {requests 2, cost 100})` — A deleted local data and bumped
   the epoch. The value is the seq-9 entry; the lattice agrees:
   `(0,…) ≤ (1,…)`. The deletion propagates.
2. Lattice join of `(2, {requests 5, input 900})` and
   `(2, {requests 7, input 100, cost 3})` is `(2, {requests 7, input 900, cost 3})`.
3. If instead A's seq 9 were `(epoch 0, {requests 8, …})` (smaller, same epoch),
   the value is still the seq-9 entry, and receivers count a regression for A.

### 5.4 `roster` — devices

See §6.

### 5.5 `bounded` — spend-cap rights

One instance per `(cap_id, month)` (UTC calendar month). Amounts are micro-USD.

- **State.** `R[from][to]` for `to` ∈ devices ∪ {`burn`}: `from`'s cumulative
  `cap.rights` amount, written only by `from`. `R[i][i]` is a **mint**. `U[i]`:
  `i`'s cumulative `cap.used`, written only by `i`. All are single-writer
  entries (§5.1).
- **Minting.** `R[owner][owner]` is the cap owner's mint. `R[i][i]` for
  `i ≠ owner` is a **local override** (Increment 07): it counts exactly like a
  mint, and views label it "override" by comparing the origin with the cap's
  owner. The payload's `override` flag is a display hint only.
- **View** (a pure function of the admitted entries; entries whose origin is not
  admitted at their seq are ignored):
  1. `minted(i) = R[i][i]`; `raw_in(i) = Σ_{j≠i} R[j][i]`.
  2. For each device `i`, walk its outgoing entries `R[i][to]`, `to ≠ i`, in
     the order **`burn` first, then recipient devices by ascending
     `device_id`**, honouring each up to what is left of the budget
     `minted(i) + raw_in(i)`. The honoured part counts; the rest is **clamped**
     (ignored).
  3. `received(i)` = honoured amounts into `i`; `sent(i)` = honoured amounts
     from `i` to devices; `burned(i)` = honoured burn of `i`.
  4. `avail(i) = minted(i) + received(i) − sent(i) − burned(i) − U[i]` (may be
     negative after an overshoot).
- **Why this clamp.** No single device's rows can make rights appear in other
  devices' views beyond what that device minted or was sent. It is one hop,
  deliberately: a transitive clamp is a fixpoint whose iteration count hostile
  values control. `U` is not part of the budget: a device that overshoots goes
  negative itself instead of retroactively taking rights back from devices it
  already paid. An honest device never sends more than its own view's `avail`,
  and that view only grows, so for honest devices nothing is ever clamped.
- **Local operations** (each produces one new cumulative entry for the
  operating device): `spend(i, x)` requires `x ≤ avail(i)` and writes
  `U[i] + x`; `transfer(i, j, x)`, `i ≠ j`, requires `x ≤ avail(i)` and writes
  `R[i][j] + x`; `burn(i, x)` requires `x ≤ avail(i)` and writes
  `R[i][burn] + x`; `mint(i, x)` writes `R[i][i] + x`. Who may mint is policy
  (Increment 07). The gateway's bounded overshoot (MESH-SI-9) is a separate,
  explicit path (Increment 08).
- **Invariant** (honest operation, any partitions, any merge order):
  `Σ_i U[i] ≤ Σ minted − Σ burned`, and `avail(i) ≥ 0` for every device; with
  gateway overshoot, `Σ U` may exceed that by at most one request's cost per cap
  per device.

**Worked example.** Ids order `A < B < O`; O is the owner.
`R[O][O] = 100`, `R[O][burn] = 10`, `R[O][A] = 30`, `R[O][B] = 20`,
`R[A][B] = 10`, `U[A] = 5`, `U[B] = 25`.

| | minted | raw_in | budget | honoured out | avail |
|---|---|---|---|---|---|
| O | 100 | 0 | 100 | burn 10, A 30, B 20 | 100 − 50 − 10 = **40** |
| A | 0 | 30 | 30 | B 10 | 30 − 10 − 5 = **15** |
| B | 0 | 30 | 30 | — | 30 − 25 = **5** |

Supply `= 100 − 10 = 90`, `Σ U = 30`, `Σ avail = 60 = 90 − 30`.

Now a device M with no rights writes `R[M][A] = 1 000 000`: M's budget is 0, so
the whole amount is clamped and A's `avail` is unchanged. If instead M had been
sent 10 by O (`R[O][M] = 10`, budget 10), A receives 10 and 999 990 is clamped.
And if M wrote `R[M][burn] = 40`, `R[M][Z] = 50`, `R[M][A] = 50` with a budget of
100: burn 40, A 50 (A < Z), Z 10, clamped 40.

### 5.6 Views: the comparable state

**Status: specified, lands in 02** — `mesh::views`, `mesh::sim::oracle_api::ExpectedState`

What a device shows — and what every device converges to — is a pure function
of the **valid items** it holds. Start from all valid items; for every
`(kind, key, origin)` keep the one with the greatest `(seq, hash)`: its
*entry*. Resolve the roster over the roster entries (§6.3) and decide admission
per §6.4. Then:

| Field | Definition |
|---|---|
| `devices` | Every **known** device: its three public keys, whether it is a `member`, whether it is `active`, its `cutoff` (if removed) and its `fork_seq` (if forked). |
| `device_info` | For each `device.info` key with an admitted entry (only the device itself writes its key): the LWW value's `name` and `listen_addrs`. |
| `settings` | For each `mesh.setting` name with an admitted entry: the LWW value (§5.2). |
| `projects` | For each `project.meta` key with an admitted entry: the LWW value. |
| `usage` | For each `usage.counter` key with at least one admitted entry: each admitted origin's `(epoch, totals)`. |
| `caps` | For each `cap.def` key with at least one admitted entry: `Conflicted` if admitted entries come from more than one origin; otherwise `Defined` with that entry's `mesh_project_id`, `owner_device`, `created_hlc`, and `frozen` = the owner device is removed. |
| `cap_months` | For each `(cap_id, month)` that has an admitted `cap.rights` or `cap.used` entry, or an admitted `cap.target` entry: `target` = the LWW `target_micros` of `<cap_id>/<month>` (or none); `devices` and totals = the bounded-counter view (§5.5) over the admitted `cap.rights` entries (`from` = origin, `to` = the key's recipient, amount = `amount_micros`) and admitted `cap.used` entries (`U[origin] = used_micros`). `devices` lists every device that is the origin or device-recipient of an admitted rights entry or the origin of an admitted used entry. |
| `shares` | For each `<credential_ref>/<recipient>` whose recipient is **not removed**: among the admitted `share.sealed` and `share.revoke` entries for that key, the one with the greatest `(hlc, origin, rank)` with rank 0 for sealed and 1 for revoke; `Sealed` (with the sharer = its origin and its payload fields) or `Revoked` (revoker = its origin, `share_id`). Keys with no admitted entry are absent. |

**Valid items**, as a model with every item ever minted (the simulator's
oracle) must judge them:

1. The item decodes (§2) and its `mesh` is the mesh's id.
2. Its origin is known in the roster resolved over all valid roster items, and
   its signature verifies with that origin's `sign_pub` (the genesis self-add
   with its own). Items that fail are ignored entirely: they occupy no entry
   and block nothing.
3. Its kind is unknown (opaque: valid, never materialized), or it parses
   (§2.4).
4. If an origin ever signed an item that passes 1-2 but fails 3, at seq `s`,
   then none of that origin's items at seq `s` or above are valid (§3.3: no
   honest device can commit past it).

**Forks** in the converged state: an origin's fork seq is the minimum over
(a) admitted-by-known `fork.report` entries about it (§6.3) and (b) the lowest
seq at which two different valid items of that origin exist. The detection
guarantee of §7 makes (a) reach (b) at quiescence; a model that sees every mint
uses both.

## 6. Roster and admission

**Status: implemented (01; forks from reports and key-derived ids in 02)** — `mesh::crdt::roster`

### 6.1 Genesis and device ids

Every mesh has exactly one genesis device: the one that ran `mesh init`. Its
`device_id` is a parameter every member holds (it travels in `PairAccept`, §9)
and is the root of trust. Its keys are those in its **self-add**: the
`roster.add` with `origin = key = genesis`. Any other device's self-add is not
a genesis and admits nothing, and adds of the genesis by other origins are
ignored.

**Device ids are derived from keys** (added in 02):

```text
device_id = BLAKE3-derive_key("tethra-mesh v1 device id",
                              sign_pub || noise_pub || seal_pub)[0..16]
```

A `roster.add` whose key is not derived from its own keys is invalid (§2.4).
So every valid add of one device carries the same keys: a member that re-adds
an existing device id with other keys produces an invalid item, not a conflict
to resolve, and cannot take over that identity. The keys are random, so the id
is too; nothing identifying goes into it.

### 6.2 State

- `adds[(target, origin)]`: `origin`'s latest `roster.add` of `target`, with the
  target's three public keys and name.
- `removes[(target, origin)]`: `origin`'s latest `roster.remove` of `target`,
  with its `cutoff_seq`.
- `forks[(target, origin)]`: `origin`'s latest `fork.report` about `target`,
  with its `seq`.

All three join entry-wise (§5.1).

### 6.3 Resolution

A pure function of the state, in this fixed order (so nothing is circular):

1. **Known**: start with `{genesis}` (only if its self-add is present;
   otherwise the roster is empty). Repeatedly add `target` for every add of
   `target` (≠ genesis) whose `origin` is already in the set, until nothing
   changes. A known device's keys come from its adds (all equal, §6.1); the
   genesis's from its self-add. *Known* is ingest check 4: known devices' items
   verify and are stored and relayed, **including removed and forked
   devices'**. Known only ever grows as items arrive.
2. **Forks**: a `fork.report` counts when its origin is known. A device's fork
   seq is the **minimum** `seq` over the reports about it that count.
3. **Cutoffs**: a `roster.remove` counts when its origin is known. A device's
   cutoff is the **maximum** `cutoff_seq` over the removes that count. A device
   with a cutoff is **removed**. Removers are judged against *known*, so two
   devices that remove each other concurrently are both removed, a removed or
   forked device's removes still count (a compromised member can remove others;
   recovery is re-pairing), and removal is forever.
4. **Members**: step 1 again, but an add counts only if it is admitted at its
   own seq: below its origin's fork seq and at or below its origin's cutoff. A
   removed or forked device's later adds bring no one in.

### 6.4 Admission

An origin's item at `seq` is **admitted** (counts in views) iff the origin is a
**member**, and `seq ≤ cutoff` if it is removed, and `seq < fork seq` if it is
forked.

A device is **active** — the only kind a session may authenticate as
(MESH-SI-2) — iff it is a member, not removed and not forked.

**Removed is forever.** A cutoff, once present, never disappears: removes only
accumulate, their origins only stay known, and re-adding a removed id changes
nothing. Re-pairing mints a new `device_id`.

### 6.5 Worked examples

Genesis G. Each line is an item `origin seq: content`.

1. `G 1: add G` (self-add) · `G 2: add A` · `A 1: add B` · `B 1: add C` →
   members `{G, A, B, C}`, all active.
2. Then `G 3: remove B, cutoff 0` → B removed; B's add of C (seq 1 > 0) no
   longer counts, so C is known (its items verify) but **not a member**; B's
   items are not admitted at any seq ≥ 1.
3. Instead `G 3: remove B, cutoff 1` and later `B 2: add D` → C stays a member
   (B 1 ≤ 1); D is known but not a member; B's seq 1 is admitted, seq 2 is not.
4. `A 2: remove B, cutoff 4` and `G 3: remove B, cutoff 7` concurrently → B's
   cutoff is 7.
5. `A 2: remove B, cutoff 0` and `B 2: remove A, cutoff 0` concurrently → both
   removed (each remove's origin is known).
6. `A 2: fork.report B, seq 2` and then `B 2: add D` → B is forked at 2: not
   active; its seq 1 is admitted (C stays a member), its seq 2 is not (D is
   known but not a member).

## 7. Forks and rollback

**Status: specified, lands in 02 (detection) and 03 (marker)**

### 7.1 Dot logs and chains

Every device keeps, for every origin `o` and every seq `s ≤ vv[o]`, the hash
of the item it accepted at that dot — its **dot log**. Commits require every
dot in the committed range (§8.2), so the dot log has no gaps even though only
the latest item per key is stored. From it, each device derives the origin's
**chain**:

```text
chain(o, 0) = 32 zero bytes
chain(o, s) = BLAKE3-derive_key("tethra-mesh v1 dot chain", chain(o, s−1) || hash(o, s))
```

Two devices agree on `chain(o, s)` iff they accepted exactly the same items at
every dot `1..=s` of `o`. Once two chains differ at some seq they differ at
every later one, so the first difference can be found by bisection.

### 7.2 Detection

- `Hello` carries `chain(o, vv[o])` for every origin in the sender's VV.
- On a peer's `Hello`, for every origin `o` with `0 < peer.vv[o] ≤ own.vv[o]`,
  a device compares `own chain(o, peer.vv[o])` with the peer's chain. If they
  differ, `o` has forked at some seq `≤ peer.vv[o]`.
- The device then bisects with `ChainQuery { origin, seqs }` (at most 64 seqs)
  and `ChainReply { origin, entries: [[seq, chain, hash]] }`, narrowing
  `(lo, hi]` — chains equal at `lo`, different at `hi` — until `hi = lo + 1`.
  The fork seq is `hi`; the two hashes at `hi` are its own and the peer's.
- A direct collision also proves a fork: an item arriving with the same dot as
  an entry in the dot log but a different hash.
- On detection a device mints `fork.report { key: o, seq, hash_a, hash_b }`
  unless its roster already records a fork of `o` at that seq or lower. The
  report replicates like any item; every device applies it (§6.3).

**Guarantee.** Before any device accepts items from a branch that differs from
its own log, the exchange that would deliver them starts with a `Hello`
comparison between two logs that are each still a single branch; the side with
the longer log finds the first differing seq, which is exactly where the
branches diverged. So whenever the two branches of a fork meet — and at
quiescence every pair of devices has exchanged — the fork is reported at its
true divergence point.

### 7.3 After detection

- Items of a forked origin keep being stored and relayed (as for removal,
  §8.3); admission excludes those at or above the fork seq.
- Different devices may hold different branches' items for the same key. So
  that every device ends with the same entry per `(kind, key, origin)` — the
  greatest `(seq, hash)` anywhere — a forked origin is **repaired** in full on
  every exchange where its digests differ (§8.5).
- The forked device itself must `mesh leave` and re-pair under a new id
  (Increment 03 makes the node refuse to run when it is the forked one).

### 7.4 Rollback

`Hello` carries the sender's own `next_seq` (`own_next_seq = vv[self] + 1`). A
peer whose dot log for that origin reaches `own_next_seq` or beyond — it holds
the sender's history past what the sender remembers — MUST send
`Direct RollbackNotice { held_seq }` (its `vv` for the sender). The sender MUST
NOT mint again until its own `vv[self] ≥ held_seq`; it recovers its own items
through ordinary exchanges (a device accepts its own origin's items like any
other), and its next seq then follows them.

### 7.5 Clone marker

Increment 03: `<data-dir>/mesh/identity.marker` holds `device_id`,
`marker_nonce` and a seq high-water mark, rewritten atomically in blocks of 64
before any seq above the mark is used. A missing or mismatched marker, or
`next_seq` below the mark, stops the node.

## 8. Replication sessions

**Status: specified, lands in 02 (state machine) and 04 (transport)** — `mesh::proto`

### 8.1 Frames

Each frame is a JSON object `{"n": <u64>, "t": "<Tag>", ...}` inside a Noise
transport message, at most 1 MiB. `n` counts the frames one side sends in a
session, from 0; a receiver MUST close the session on any frame whose `n` is
not the next expected one (a reliable ordered transport never reorders,
duplicates or drops; anything else means the connection is broken). Item bytes
inside frames are standard base64; hashes and chains are 64 lowercase hex.

| Tag | Members |
|---|---|
| `Hello` | `proto_min`, `proto_max`, `mesh_id`, `device_id`, `kinds` (the kinds the sender materializes), `vv`, `own_next_seq`, `chains` (origin → `chain(o, vv[o])`), `digests` (origin → digest of held items, §8.5) |
| `Items` | `batch` (≤ 512 items and ≤ 1 MiB of item bytes), `dots` (`[origin, seq, hash]` for dots in the served ranges not carried by an item in any batch), `repair` (bool: these items are repair items, §8.5) |
| `Commit` | `upto` (the sender's VV for exactly the origins it served on the main path), `count` (items sent in all `Items` frames), `batch_hash` (BLAKE3 of the concatenated hashes of those items, in send order) |
| `ChainQuery` | `origin`, `seqs` (≤ 64) |
| `ChainReply` | `origin`, `entries` (`[seq, chain, hash]` for each queried seq the sender's dot log covers) |
| `Direct` | `kind` ∈ {`AccessKeyUpdate`, `RightsRequest`, `RollbackNotice`}, `payload` — point to point, never stored or relayed as items |
| `Bye` | `reason` |

Protocol version 1. Peers negotiate the highest version in both
`[proto_min, proto_max]`; no overlap, a different `mesh_id`, or a `device_id`
that is not the authenticated peer ends the session with `Bye`.

DESIGN §D9 also listed `Want`, `RepairDigest` and `RepairWant`. v1 does not use
them: the `Hello` VV says what to stream, and per-origin digests in `Hello`
replace bucket digests (§8.5).

### 8.2 Session (push-pull, symmetric)

1. Both sides send `Hello`.
2. On the peer's `Hello`, each side:
   - checks rollback (§7.4) and forks (§7.2), sending `ChainQuery` as needed;
   - streams, for every origin `o` with `own.vv[o] > peer.vv[o]`, every held
     item of `o` with seq in `(peer.vv[o], own.vv[o]]`, in seq order, plus
     **the hash of every other dot in that range** (items it no longer holds
     because a later item superseded them) in `dots` — at most 50 000 items and
     dots per session, cutting the last origin's range short (and its `upto`
     with it) when the limit is reached;
   - streams repair items (§8.5);
   - sends `Commit`.
3. The receiver checks each item as it arrives (§3.3) and **stages** it,
   together with the dots, bounded by §11.
4. On `Commit` the receiver checks `count` and `batch_hash` against what it
   received (a mismatch closes the session; nothing is applied), re-checks
   pending items, and then, per origin `o` in `upto`, requires a hash for every
   seq in `(own.vv[o], upto[o]]` — from an item or a dot. It commits **in one
   transaction**:
   - the items: an item becomes the stored entry for its
     `(kind, key, origin)` iff its `(seq, hash)` is greater than the stored
     one's;
   - the dot log for the committed range, and the chain;
   - `vv[o] := upto[o]` for each complete origin (reduced to `s − 1` for an
     origin with a rejected item at `s`, §3.3);
   - the materialized views.
5. **The VV never advances without that transaction** (MESH-SI-4). A sender
   that dies mid-stream leaves nothing half-applied; the next session resends.
6. A side is done when it has sent its `Commit`, received the peer's, and has
   no `ChainQuery` outstanding. It then closes.

### 8.3 Removal and relaying

Items from a removed origin — including those **above** its cutoff — MUST still
be stored and relayed like any other item; they are excluded from views by
admission (§6.4), not by withholding them. Withholding them would break
convergence: a device that kept a removed origin's admitted (≤ cutoff) entry
for a key would never learn that the origin's later, non-admitted entry
superseded it, while a device that held the later entry would show nothing for
that origin, and the two views would differ forever. The same holds for a
forked origin's items (§7.3).

### 8.4 Why relaying only the latest item per key is safe

An item is superseded only by a later item of the same origin and key (§5.1).
So when a sender's `vv[o] = n`, it holds, for every key, either `o`'s item or a
later `o` item with seq ≤ n that supersedes it. Sending all held `o` items with
seq in `(peer.vv[o], n]` — and the hashes of the superseded dots, so the
receiver's dot log stays complete — transfers everything the peer needs to
reach the same per-origin state.

**Garbage collection.** A stored item MAY be deleted only when (a) a held item
of the same `(kind, key, origin)` with a higher seq supersedes it, or (b) every
item of its `(kind, key, origin)` is permanently excluded from views on every
device for a reason that does not depend on seq (a share addressed to a removed
recipient; a usage day beyond the retention horizon). An item of a removed or
forked origin above its cutoff or fork seq MUST NOT be deleted under (b): its
exclusion depends on its seq, and it is what supersedes the origin's older entry
for the same key. `roster.*`, `cap.def` and `fork.report` items are never
deleted. The dot log is never pruned below the VV (Increment 03 may bound its
age; a fork older than that bound is then detected only by direct collision).

### 8.5 Repair

`Hello.digests` maps every origin in the sender's VV to
`BLAKE3-derive_key("tethra-mesh v1 origin digest", concatenation of the hashes
of the sender's held items of that origin, sorted ascending)`. After the
`Hello` exchange, a side streams **all** its held items of origin `o` as repair
items (`Items.repair = true`) when its digest for `o` differs from the peer's
and either

- `own.vv[o] == peer.vv[o]` — the main path has nothing to send, yet the two
  devices hold different items, which honest operation never produces; or
- `o` is forked in its own roster (§7.3).

A receiver checks repair items like any other (§3.3, without the gap check)
and commits them with the main path, as entries only: repair never changes the
VV, the dot log or the chain, and an item whose dot is in the dot log with a
different hash is fork evidence (§7.2). A repair that changes the stored state
of an origin that is not forked is a bug signal: count it
(`mesh_meta.repairs_changed`) and show it in `doctor`.

## 9. Pairing, sessions, rotation, removal

**Status: specified, lands in 04**

- **Invite** (reauth-gated): a 20-byte random token; `blake3(token)` stored with
  an expiry (default 10 minutes, maximum 60), `attempts = 0`, `used_at = NULL`.
  Printed once as `tethra-mesh-invite:v1:<base32 token>@<host:port>[,…]`. The
  token is a bearer secret for its lifetime; move it over a channel you trust.
- **Join**: `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`, psk
  `blake3::derive_key("tethra-mesh v1 pairing psk", token)`, prologue
  `"tethra-mesh/v1-pair" || 0x00`. The inviter checks the token hash is unused,
  unexpired and `attempts < 5` (each failure increments), and marks it used
  **before** replying. Inside the channel the joiner sends `PairRequest` (its
  three public keys and name); the inviter mints the joiner's `roster.add` and
  replies `PairAccept` with `mesh_id`, **`genesis` device id**, the access key
  and its epoch, and its own `device_id`. A normal exchange then runs on the same
  connection.
- **Normal sessions**: `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s`, psk = access key
  (current epoch), prologue `"tethra-mesh/v1" || 0x00 || mesh_id`. After the
  handshake the remote static key MUST equal the `noise_pub` of an **active**
  roster device (§6.4), or the session closes (MESH-SI-2). The responder tries
  the current access-key epoch, then the previous one if it is younger than
  30 days. If `snow` lacks `XXpsk0`, Increment 04 falls back to `Noise_XX` and
  records the static-key exposure in ADR 0031.
- **Rotation**: a removal generates access-key epoch + 1, delivered by
  `Direct AccessKeyUpdate` inside authenticated sessions and forwarded by every
  member. A device that misses it for 30 days must re-pair.
- **Removal** (confirm + reauth): mints `roster.remove { cutoff_seq = local
  vv[target] }`. Effects follow from §6.4 and §8.3. **Self-removal**
  (`mesh leave`) mints a self-remove if a peer is reachable, then wipes local
  mesh state. Removal is eventually consistent.

## 10. Data that never replicates

**Status: implemented (01) as a rule; enforced by construction from 03**

Local project ids and bindings, peers and addresses typed by the user, invites,
private keys, cursors, escrow rows, the cap-enforcement switch, gateway request
events, routes, paths, endpoints, scan findings, alerts, audit rows, provider
admin keys and destinations never appear in any item. Only the kinds of §2.4
replicate.

## 11. Bounds

**Status: specified, lands in 02-05 (MESH-SI-8)**; the per-item bounds are
implemented (01).

| Bound | Value |
|---|---|
| Item (wire) | ≤ 65 536 bytes (implemented) |
| Body | ≤ 65 472 bytes (implemented) |
| Payload nesting | ≤ 16 (implemented) |
| `kind` / `key` | ≤ 64 / ≤ 1024 bytes (implemented) |
| Frame | ≤ 1 MiB |
| Batch | ≤ 512 items |
| Staged items per session | ≤ 50 000, else `Bye(too_large)`; resume next session |
| Concurrent sessions | ≤ 8 |
| Handshake / idle / session wall time | 5 s / 30 s / 10 min |
| Handshakes per source IP | ≤ 10 per minute |
| Pairing attempts per token | ≤ 5 |
| Items per origin | ≤ 10 000 per hour, enforced at ingest |
| Write transactions | one `Commit` per transaction, chunked to stay under ~250 ms |

## 12. Versioning

Protocol version and item format version evolve independently. Unknown kinds
are stored opaquely (§2.3). A device whose database schema is newer than its
binary refuses to run the node.

## 13. Departures from the design brief

Recorded here and in ADR 0031 "Decisions resolved while specifying".

1. **Per-origin order is `seq`, for every kind** (§5.1). DESIGN §D8 described
   the LWW per-origin join by HLC and the counter join as epoch-lexicographic.
   Both are kept as honest-writer properties, but the replicated state keeps an
   origin's highest-seq entry: that is what the store holds and what relaying
   latest-only requires, so it is the only rule under which every device, the
   incremental views and a rebuild agree when an origin misbehaves.
2. **Removed origins' items keep relaying** (§8.3). DESIGN §D10 said items above
   the cutoff are never relayed again; that loses convergence.
3. **Bounded-counter clamp** (§5.5): one hop, outgoing amounts honoured from
   `minted + raw_in` (not minus used), burn first then ascending device id.
   DESIGN §D8 said "minted plus received minus used" without fixing the
   recursion or the order.
4. **Non-owner self-mints count as labelled overrides** in the bounded counter
   (§5.5), reconciling DESIGN §D8 ("only the owner may mint") with §D15 (local
   override).
5. **Roster resolution** (§6.3; key conflicts superseded by item 8): the genesis is a parameter, key conflicts lock a
   device out, removers are judged against the cutoff-free known set. DESIGN
   §D8/§D10 left the recursion between adds, removes and cutoffs open.
6. **`PairAccept` carries the genesis device id** (§9).
7. **`local_write_ts` does not move the clock** (§4), so the simulator's clock
   invariant is "no observation moves the HLC past `now + MAX_DRIFT`".

Increment 02 (ADR 0031 R8-R12):

8. **Device ids are derived from the device's keys** (§6.1). DESIGN §D5 had
   random ids; key-derived ids remove key conflicts — and with them a
   membership rule that could not converge under adversarial re-adds.
9. **Fork detection by per-origin dot logs and chains, and `fork.report`
   items** (§7). With latest-only storage, a version-vector comparison or a
   dot collision cannot guarantee detection; chains can, at the true
   divergence point. Reports make forks replicated state (roster §6.3 step 2).
10. **Invalid payloads of known kinds are rejected at ingest** (§2.4, §3.3),
    with the valid prefix kept.
11. **Repair compares per-origin digests carried in `Hello`** (§8.5) instead
    of `(kind, scope)` buckets exchanged in `RepairDigest`/`RepairWant`;
    `Want` is not used.
12. **Frames carry a per-direction sequence number `n`** (§8.1).
