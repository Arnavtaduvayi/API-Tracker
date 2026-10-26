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
fails the rules below is still a validly signed item: it is stored and relayed,
and every device leaves it out of its views (deterministically, so views still
converge).

Common value rules: a *name* is 1-128 bytes, not only whitespace, with no
control characters. A *slug* is 1-64 bytes of `[a-z0-9._-]`. A *public key* is
32 bytes as 64 lowercase hex characters. A *day* is `YYYY-MM-DD` (4-digit year,
zero-padded, a real calendar date, UTC). A *month* is `YYYY-MM` (UTC calendar
month).

| Kind | Key | Payload members | Extra rules |
|---|---|---|---|
| `roster.add` | added `device_id` | `added_by`, `name`, `noise_pub`, `seal_pub`, `sign_pub` | `added_by` MUST equal `origin`. `sign_pub` MUST be a valid, non-small-order Ed25519 point. |
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
4. **Origin known**: the origin is *known* in the receiver's roster (§6.4,
   step 3), evaluated over its stored items **plus every item staged earlier in
   the same session**. The one exception is the **genesis self-add**: a
   `roster.add` whose `origin` and `key` both equal the genesis `device_id`; it
   is verified with the `sign_pub` it carries.
   A receiver MUST NOT finally reject an item only because its origin's
   `roster.add` arrives later in the same session; it re-checks such pending
   items after each batch and at `Commit` (Increment 02).
5. **Signature**: §3.1 with the origin's `sign_pub` from the roster.
6. **Rate**: the origin has not exceeded 10 000 items per hour as seen by this
   receiver (§11).
7. **Kind**: known kinds are parsed (§2.4); unknown kinds are kept opaque (§2.3).

Items from a removed origin still pass check 4 (removed devices stay *known*),
so they keep replicating; whether they count is decided by admission (§6.4).

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

## 6. Roster and admission

**Status: implemented (01)** — `mesh::crdt::roster`

### 6.1 Genesis

Every mesh has exactly one genesis device: the one that ran `mesh init`. Its
`device_id` is a parameter every member holds (it travels in `PairAccept`, §9)
and is the root of trust. Its keys are those in its **self-add**: the
`roster.add` with `origin = key = genesis`. Any other device's self-add is not
a genesis and admits nothing, and adds of the genesis by other origins are
ignored.

### 6.2 State

- `adds[(target, origin)]`: `origin`'s latest `roster.add` of `target`, with the
  target's three public keys and name.
- `removes[(target, origin)]`: `origin`'s latest `roster.remove` of `target`,
  with its `cutoff_seq`.
- `forks[origin]`: the lowest seq at which `origin` is known to have signed two
  different items (§7). Joined by minimum.

The first two join entry-wise (§5.1).

### 6.3 Resolution

A pure function of the state, in this fixed order (so nothing is circular). Let
`fork_ok(o, s)` mean "`o` has no recorded fork, or `s` < its fork seq".

1. **Reachable**: start with `{genesis}` (only if its self-add is present;
   otherwise the roster is empty). Repeatedly add `target` for every add of
   `target` (≠ genesis) whose `origin` is already in the set and
   `fork_ok(origin, add.seq)`, until nothing changes.
2. **Conflicts**: a target (≠ genesis) for which two adds — each from an origin
   reachable in step 1 and each `fork_ok` — carry different keys is
   **conflicted** and excluded from everything below. (A member that re-adds an
   existing device id with other keys locks that device out; it cannot take
   over its identity.)
3. **Known**: step 1 again, skipping conflicted targets. A known device's keys
   are the genesis self-add's keys (genesis) or the keys its adds agree on.
   *Known* is ingest check 4: known devices' items verify and are stored and
   relayed, **including removed devices'**.
4. **Cutoffs**: a `roster.remove` counts when its origin is known and
   `fork_ok(origin, remove.seq)`. A device's cutoff is the **maximum**
   `cutoff_seq` over the removes that count for it. A device with a cutoff is
   **removed**. Removers are judged against the cutoff-free *known* set, so two
   devices that remove each other concurrently are both removed, and a removed
   device's removes still count (a compromised member can remove others;
   recovery is re-pairing).
5. **Members**: step 1 again, skipping conflicted targets, and additionally
   requiring each add's `seq ≤ cutoff(origin)` when its origin is removed. A
   removed device's later adds bring no one in.

### 6.4 Admission

An origin's item at `seq` is **admitted** (counts in views) iff the origin is a
**member**, and `seq ≤ cutoff` if it is removed, and `fork_ok(origin, seq)`.

A device is **active** — the only kind a session may authenticate as
(MESH-SI-2) — iff it is a member, not removed and not forked.

**Removed is forever.** A cutoff, once present, never disappears: removes only
accumulate, and re-adding a removed id changes nothing. Re-pairing mints a new
`device_id`.

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
6. `B 2: add A` with keys different from G's add of A → A is conflicted: not
   known, not a member, its items are rejected at ingest.
7. A fork recorded for B at seq 2 → B's items with seq ≥ 2 are not admitted and
   B is not active; an add B made at seq 2 or later brings no one in.

## 7. Forks and rollback

**Status: specified, lands in 02 (detection) and 03 (marker)**

- **Fork.** Two validly signed items with the same `(origin, seq)` and different
  hashes prove the origin forked (for example a cloned data directory). A device
  that sees this MUST store a `ForkEvidence` record (both items' bytes), MUST
  record the fork in its roster (§6.2) with that seq, and MUST stop accepting new
  items from that origin. The forked origin's items at or above the **lowest
  known fork seq** are not admitted anywhere (§6.4).
- Fork evidence is self-certifying (two signed items), so a device MAY forward
  it to peers. Increment 02 MUST specify how evidence reaches every device:
  because each device keeps only the latest item per `(kind, key, origin)`, two
  devices can hold different branches of a fork with no single dot in common,
  and a VV comparison alone cannot see the conflict. The repair path (§8.5) and
  explicit evidence forwarding are the candidate mechanisms; 02 picks one and
  proves invariant 5 of its simulator ("every device holds the evidence at
  quiescence").
- **Rollback.** Hello carries the sender's own `next_seq` (`own_next_seq`). A
  peer that holds an item from that origin with `seq ≥ own_next_seq` MUST send
  `Direct RollbackNotice`; the sender then enters `rollback_recovery`, fetches
  its own items first, and sets `next_seq` above them before minting again.
- **Clone marker** (Increment 03): `<data-dir>/mesh/identity.marker` holds
  `device_id`, `marker_nonce` and a seq high-water mark, rewritten atomically in
  blocks of 64 before any seq above the mark is used. A missing or mismatched
  marker, or `next_seq` below the mark, stops the node.

## 8. Replication sessions

**Status: specified, lands in 02 (state machine) and 04 (transport)**

### 8.1 Frames

JSON objects inside Noise transport messages, each frame at most 1 MiB, tagged
by member `t`. Item bytes inside frames are standard base64.

| Frame | Members |
|---|---|
| `Hello` | `proto_min`, `proto_max`, `mesh_id`, `device_id`, `kinds` (known kinds), `vv`, `own_next_seq`, `digest_root` |
| `Want` | `since` (a VV) |
| `Items` | `batch` (≤ 512 items and ≤ 1 MiB), `more` (bool) |
| `Commit` | `upto` (the sender's VV for exactly the origins it served), `count`, `batch_hash` |
| `RepairDigest` | `scope`, `buckets` (`[bucket_id, hash]` pairs) |
| `RepairWant` | `buckets` |
| `Direct` | `kind` ∈ {`AccessKeyUpdate`, `RightsRequest`, `RollbackNotice`}, `payload` — point to point, never stored or relayed as items |
| `Bye` | `reason` |

Protocol version 1. Peers negotiate the highest version in both
`[proto_min, proto_max]` ranges; no overlap, or a different `mesh_id`, ends the
session with `Bye`.

### 8.2 Session (push-pull, symmetric)

1. Both sides send `Hello`.
2. Each side computes, for every origin `o` with `own.vv[o] > peer.vv[o]`, the
   items it holds from `o` with `seq` in `(peer.vv[o], own.vv[o]]`, in seq
   order (`VersionVector::missing_from`), streams them in `Items` batches, then
   sends `Commit`.
3. The receiver **stages** each batch in memory (bounded, §11), applying the
   ingest checks of §3.3 to each item as it arrives (re-checking items whose
   origin was unknown once more of the session's roster items have arrived).
4. On `Commit` the receiver applies everything in **one transaction**: insert the
   items (idempotent on `(origin, seq)`; the same dot with a different hash is
   fork evidence), apply entries per §5.1, update the materialized views, and
   set `vv[o] := max(vv[o], upto[o])`.
5. **The VV never advances without that Commit** (MESH-SI-4). A sender that dies
   mid-stream leaves nothing half-applied; the next session resends.
6. Rollback check per §7.

### 8.3 Removal and relaying

Items from a removed origin — including those **above** its cutoff — MUST still
be stored and relayed like any other item; they are excluded from views by
admission (§6.4), not by withholding them. Withholding them would break
convergence: a device that kept a removed origin's admitted (≤ cutoff) entry
for a key would never learn that the origin's later, non-admitted entry
superseded it, while a device that held the later entry would show nothing for
that origin, and the two views would differ forever.

### 8.4 Why relaying only the latest item per key is safe

An item is superseded only by a later item of the same origin and key (§5.1).
So when a sender's `vv[o] = n`, it holds, for every key, either `o`'s item or a
later `o` item with seq ≤ n that supersedes it. Sending all held `o` items with
seq in `(peer.vv[o], n]` transfers everything the peer needs to reach the same
per-origin state.

**Garbage collection.** A stored item MAY be deleted only when (a) a held item
of the same `(kind, key, origin)` with a higher seq supersedes it, or (b) every
item of its `(kind, key, origin)` is permanently excluded from views on every
device for a reason that does not depend on seq (a share addressed to a removed
recipient; a usage day beyond the retention horizon). An item of a removed
origin above that origin's cutoff MUST NOT be deleted under (b): its exclusion
depends on its seq, and it is what supersedes the origin's older entry for the
same key. `roster.*` and `cap.def` items are never deleted.

### 8.5 Repair

A safety net, not the main path. Each side keeps a BLAKE3 digest per bucket —
bucket `(kind, scope)`, scope `<mesh_project_id>/<month>` for usage and caps and
`-` otherwise — over the sorted item hashes in it; `digest_root` is the hash of
all bucket hashes. When the VVs match but the roots differ (and at least every
24 h), the sides exchange `RepairDigest`, request differing buckets with
`RepairWant`, send every item in those buckets and commit as in §8.2 without
changing the VV. A repair that changes state is a bug signal: count it and show
it in `doctor`.

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
5. **Roster resolution** (§6.3): the genesis is a parameter, key conflicts lock a
   device out, removers are judged against the cutoff-free known set. DESIGN
   §D8/§D10 left the recursion between adds, removes and cutoffs open.
6. **`PairAccept` carries the genesis device id** (§9).
7. **`local_write_ts` does not move the clock** (§4), so the simulator's clock
   invariant is "no observation moves the HLC past `now + MAX_DRIFT`".
