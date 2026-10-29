//! The independent oracle (Increment 02).
//!
//! A deliberately naive model of the replicated state, written from
//! `docs/mesh/PROTOCOL.md` alone by an isolated author who did not read the
//! implementation (`crdt`, `views`, `proto`, `memstore`, `sim::world`). It
//! implements [`super::oracle_api::OracleModel`].
//!
//! [`Oracle::expected`] recomputes everything from the set of minted items on
//! every call, in the order PROTOCOL.md §5.6 gives:
//!
//! 1. **Valid items** (§5.6 "Valid items", with rule 4 as amended to the
//!    *dense prefix*): an item is valid when it decodes and names this mesh
//!    (rule 1), its origin is known and its signature verifies with that
//!    origin's `sign_pub` (rule 2; the genesis self-add with the key it
//!    carries), its kind is unknown or parses (rule 3), and its seq is below
//!    the origin's first seq at which no item passes rules 1-3 (rule 4).
//! 2. **Known** (§6.3 step 1) and validity depend on each other. Given an
//!    origin's keys, which of its items pass rules 1-4 depends only on its own
//!    items, so *known* is the least fixpoint of: start from the genesis (if
//!    it has a valid self-add), then repeatedly add the target of every valid
//!    `roster.add` (target ≠ genesis) whose origin is known.
//! 3. **Entries** (§5.1): per `(kind, key, origin)`, the valid item with the
//!    greatest `(seq, hash)`. Unknown kinds occupy entries and are never
//!    materialized.
//! 4. **Roster** (§6.3): forks (minimum of `fork.report` entries and of the
//!    lowest seq holding two different valid items, §5.6 "Forks"), cutoffs
//!    (maximum), members (step 1 again, counting only adds admitted at their
//!    own seq); **admission** and **active** (§6.4).
//! 5. **Views** (§5.6 table) over the admitted entries.
//!
//! Only per-item work that depends on no other item survives between calls:
//! the decoded body, the typed parse, and signature checks keyed by
//! `(item hash, verifying key)`. Every rule above is re-derived on each call.

use super::oracle_api::{
    ExpectedCapDef, ExpectedCapMonth, ExpectedDevice, ExpectedDeviceInfo, ExpectedProject,
    ExpectedRights, ExpectedShare, ExpectedState, GenesisInfo, OracleModel,
};
use crate::mesh::codec::ItemBody;
use crate::mesh::dot::{CapId, CredentialRef, DeviceId, MeshProjectId};
use crate::mesh::hlc::Hlc;
use crate::mesh::item::{ItemHash, SignedItem};
use crate::mesh::kinds::{CapDef, Month, Recipient, RosterAdd, TypedItem, UsageKey, UsageTotals};
use crate::mesh::sign::PublicKeyBytes;
use serde_json::Value;
use std::collections::{hash_map, BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::{Mutex, PoisonError};

/// One minted item and the work on it that depends on no other item.
struct Observed {
    item: SignedItem,
    /// The body, when it decodes and names this mesh (§5.6 rule 1).
    body: Option<ItemBody>,
    /// `Some` when the body passes rule 3: its kind is unknown
    /// ([`TypedItem::Unknown`]) or it parses (§2.4).
    typed: Option<TypedItem>,
}

/// An item that passes rule 1, with what the later rules need.
#[derive(Clone, Copy)]
struct Candidate<'a> {
    item: &'a SignedItem,
    body: &'a ItemBody,
    typed: Option<&'a TypedItem>,
}

/// An item that passes rules 1-4.
#[derive(Clone, Copy)]
struct Valid<'a> {
    hash: ItemHash,
    body: &'a ItemBody,
    typed: &'a TypedItem,
}

/// One `(kind, key, origin)` entry (§5.1).
struct Entry<'a> {
    origin: DeviceId,
    seq: u64,
    hlc: Hlc,
    item: &'a TypedItem,
}

/// Every known origin's valid items.
type ValidByOrigin<'a> = BTreeMap<DeviceId, Vec<Valid<'a>>>;

/// A known device's three public keys (§6.3 step 1).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Keys {
    sign_pub: PublicKeyBytes,
    noise_pub: PublicKeyBytes,
    seal_pub: PublicKeyBytes,
}

impl Keys {
    fn of(add: &RosterAdd) -> Self {
        Self {
            sign_pub: add.sign_pub,
            noise_pub: add.noise_pub,
            seal_pub: add.seal_pub,
        }
    }
}

/// The resolved roster (§6.3, §6.4).
struct Roster {
    known: BTreeMap<DeviceId, Keys>,
    forks: BTreeMap<DeviceId, u64>,
    cutoffs: BTreeMap<DeviceId, u64>,
    members: BTreeSet<DeviceId>,
}

impl Roster {
    /// Below the origin's fork seq and at or below its cutoff (the part of
    /// §6.4 that §6.3 step 4 applies to adds).
    fn within(&self, origin: DeviceId, seq: u64) -> bool {
        self.cutoffs
            .get(&origin)
            .is_none_or(|&cutoff| seq <= cutoff)
            && self.forks.get(&origin).is_none_or(|&fork| seq < fork)
    }

    /// §6.4: the origin's item at `seq` counts in views.
    fn admitted(&self, origin: DeviceId, seq: u64) -> bool {
        self.members.contains(&origin) && self.within(origin, seq)
    }

    fn removed(&self, device: DeviceId) -> bool {
        self.cutoffs.contains_key(&device)
    }
}

/// The naive model. See the module documentation.
pub struct Oracle {
    info: GenesisInfo,
    items: Vec<Observed>,
    seen: HashSet<ItemHash>,
    /// Items that never reached a device in contact (`observe_unreached`):
    /// they fill their dot for rule 4 and count for nothing else.
    unreached: HashSet<ItemHash>,
    /// Memoised signature checks: `(item hash, sign_pub) -> verifies`.
    signature_checks: Mutex<HashMap<(ItemHash, PublicKeyBytes), bool>>,
    /// Cache warming only: a `sign_pub` per device id, from any `roster.add`
    /// that parses (the id is derived from the keys, §6.1, so it is the only
    /// key the roster can ever give that id). Never consulted by `expected`.
    warm_keys: HashMap<DeviceId, PublicKeyBytes>,
    /// Cache warming only: items whose origin has no key in `warm_keys` yet.
    warm_pending: HashMap<DeviceId, Vec<usize>>,
}

impl fmt::Debug for Oracle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Oracle")
            .field("mesh_id", &self.info.mesh_id)
            .field("genesis", &self.info.genesis)
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

impl OracleModel for Oracle {
    fn new(genesis: &GenesisInfo) -> Self {
        Self {
            info: *genesis,
            items: Vec::new(),
            seen: HashSet::new(),
            unreached: HashSet::new(),
            signature_checks: Mutex::new(HashMap::new()),
            warm_keys: HashMap::new(),
            warm_pending: HashMap::new(),
        }
    }

    fn observe_unreached(&mut self, item: &SignedItem) {
        // Added by the orchestrator in 02 with the contract change (STATUS.md).
        self.unreached.insert(item.hash());
        self.observe_minted(item);
    }

    fn observe_minted(&mut self, item: &SignedItem) {
        // The same bytes minted twice (a clone repeating an item) are one item.
        if !self.seen.insert(item.hash()) {
            return;
        }
        let body = item
            .decode_unverified()
            .ok()
            .filter(|body| body.mesh == self.info.mesh_id);
        let typed = body.as_ref().and_then(|body| TypedItem::parse(body).ok());
        let origin = body.as_ref().map(|body| body.origin);
        let added = match &typed {
            Some(TypedItem::RosterAdd(add)) => Some((add.device, add.sign_pub)),
            _ => None,
        };
        let warm = typed.is_some();
        let idx = self.items.len();
        self.items.push(Observed {
            item: item.clone(),
            body,
            typed,
        });

        // Warm the signature cache so that `expected` rarely verifies. This is
        // memoisation only: a key guessed wrong here is simply never looked up.
        if let Some((device, sign_pub)) = added {
            if let hash_map::Entry::Vacant(slot) = self.warm_keys.entry(device) {
                slot.insert(sign_pub);
                for pending in self.warm_pending.remove(&device).unwrap_or_default() {
                    self.check_signature(&self.items[pending].item, &sign_pub);
                }
            }
        }
        if let (true, Some(origin)) = (warm, origin) {
            match self.warm_keys.get(&origin).copied() {
                Some(sign_pub) => {
                    self.check_signature(&self.items[idx].item, &sign_pub);
                }
                None => self.warm_pending.entry(origin).or_default().push(idx),
            }
        }
    }

    fn expected(&self) -> ExpectedState {
        // §5.6 rule 1: decodes and names this mesh. Grouped by origin.
        let mut by_origin: BTreeMap<DeviceId, Vec<Candidate<'_>>> = BTreeMap::new();
        for observed in &self.items {
            if let Some(body) = &observed.body {
                by_origin.entry(body.origin).or_default().push(Candidate {
                    item: &observed.item,
                    body,
                    typed: observed.typed.as_ref(),
                });
            }
        }

        // Rules 2-4 and §6.3 step 1, together.
        let (known, valid) = self.known_and_valid(&by_origin);
        if known.is_empty() {
            // No valid genesis self-add: the roster is empty, so no origin is
            // known and no item is valid.
            return ExpectedState::default();
        }

        // §5.1: one entry per (kind, key, origin), the greatest (seq, hash).
        let mut latest: BTreeMap<(&str, &str, DeviceId), Valid<'_>> = BTreeMap::new();
        for v in valid.values().flatten() {
            let slot = (v.body.kind.as_str(), v.body.key.as_str(), v.body.origin);
            let greater = latest
                .get(&slot)
                .is_none_or(|cur| (v.body.seq, v.hash) > (cur.body.seq, cur.hash));
            if greater {
                latest.insert(slot, *v);
            }
        }
        let entries: Vec<Entry<'_>> = latest
            .values()
            .map(|v| Entry {
                origin: v.body.origin,
                seq: v.body.seq,
                hlc: v.body.hlc,
                item: v.typed,
            })
            .collect();

        let roster = self.resolve_roster(known, &valid, &entries);
        let admitted: Vec<&Entry<'_>> = entries
            .iter()
            .filter(|e| roster.admitted(e.origin, e.seq))
            .collect();

        let mut state = ExpectedState::default();
        for (&id, keys) in &roster.known {
            let member = roster.members.contains(&id);
            let cutoff = roster.cutoffs.get(&id).copied();
            let fork_seq = roster.forks.get(&id).copied();
            state.devices.insert(
                id,
                ExpectedDevice {
                    sign_pub: keys.sign_pub,
                    noise_pub: keys.noise_pub,
                    seal_pub: keys.seal_pub,
                    member,
                    active: member && cutoff.is_none() && fork_seq.is_none(),
                    cutoff,
                    fork_seq,
                },
            );
        }
        state.device_info = view_device_info(&admitted);
        state.settings = view_settings(&admitted);
        state.projects = view_projects(&admitted);
        state.usage = view_usage(&admitted);
        state.caps = view_caps(&admitted, &roster);
        state.cap_months = view_cap_months(&admitted);
        state.shares = view_shares(&admitted, &roster);
        state
    }
}

impl Oracle {
    /// Whether `item` carries a valid signature by `sign_pub` (and decodes
    /// and names this mesh, which `verify_with` re-checks). Memoised.
    fn check_signature(&self, item: &SignedItem, sign_pub: &PublicKeyBytes) -> bool {
        let slot = (item.hash(), *sign_pub);
        let mut cache = self
            .signature_checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(&ok) = cache.get(&slot) {
            return ok;
        }
        let ok = sign_pub
            .to_verifying_key()
            .is_ok_and(|key| item.verify_with(&key, &self.info.mesh_id).is_ok());
        cache.insert(slot, ok);
        ok
    }

    /// One origin's valid items, given that the origin is known with
    /// `sign_pub` (§5.6 rules 2-4; `candidates` already pass rule 1).
    fn valid_items_of<'a>(
        &self,
        candidates: &[Candidate<'a>],
        sign_pub: &PublicKeyBytes,
    ) -> Vec<Valid<'a>> {
        // Rules 2 and 3.
        let passing: Vec<Valid<'a>> = candidates
            .iter()
            .filter_map(|c| {
                let typed = c.typed?;
                self.check_signature(c.item, sign_pub).then_some(Valid {
                    hash: c.item.hash(),
                    body: c.body,
                    typed,
                })
            })
            .collect();
        // Rule 4 (dense prefix), below the origin's ground-truth fork point g
        // (the lowest seq with two different passing items): s* is the
        // smallest seq >= 1 with no passing item; if s* < g, nothing at s* or
        // above is valid. At or above g items travel by repair and need no
        // dense prefix (amended in 02 after an oracle/implementation
        // disagreement, STATUS.md).
        let mut at: BTreeMap<u64, BTreeSet<ItemHash>> = BTreeMap::new();
        for v in &passing {
            at.entry(v.body.seq).or_default().insert(v.hash);
        }
        let g = at
            .iter()
            .find(|(_, hs)| hs.len() > 1)
            .map_or(u64::MAX, |(s, _)| *s);
        let mut gap = 1u64;
        while gap < g && at.contains_key(&gap) {
            gap += 1;
        }
        // Unreached items filled their dots above; they are never valid.
        let reached = |v: &Valid<'a>| !self.unreached.contains(&v.hash);
        if gap < g {
            passing
                .into_iter()
                .filter(|v| v.body.seq < gap && reached(v))
                .collect()
        } else {
            passing.into_iter().filter(reached).collect()
        }
    }

    /// The known devices with their keys (§6.3 step 1) and every known
    /// origin's valid items, as a least fixpoint.
    fn known_and_valid<'a>(
        &self,
        by_origin: &BTreeMap<DeviceId, Vec<Candidate<'a>>>,
    ) -> (BTreeMap<DeviceId, Keys>, ValidByOrigin<'a>) {
        let genesis = self.info.genesis;
        let candidates_of = |device: DeviceId| -> &[Candidate<'a>] {
            by_origin.get(&device).map(Vec::as_slice).unwrap_or(&[])
        };
        let mut known: BTreeMap<DeviceId, Keys> = BTreeMap::new();
        let mut valid: ValidByOrigin<'a> = BTreeMap::new();

        // The seed: the genesis, if its self-add is present. The self-add is
        // verified with the sign_pub it carries. Every self-add that parses
        // carries the same keys (the id is derived from them, §6.1), so the
        // first one found gives them; whether any self-add is valid is then
        // decided by rules 2-4 like any other item.
        let self_add_keys = candidates_of(genesis).iter().find_map(|c| match c.typed {
            Some(TypedItem::RosterAdd(add)) if add.device == genesis => Some(Keys::of(add)),
            _ => None,
        });
        if let Some(keys) = self_add_keys {
            let items = self.valid_items_of(candidates_of(genesis), &keys.sign_pub);
            let self_add_valid = items
                .iter()
                .any(|v| matches!(v.typed, TypedItem::RosterAdd(add) if add.device == genesis));
            if self_add_valid {
                known.insert(genesis, keys);
                valid.insert(genesis, items);
            }
        }

        // Repeatedly add the target of every valid add (target ≠ genesis)
        // whose origin is known, until nothing changes.
        loop {
            let mut found: Vec<(DeviceId, Keys)> = Vec::new();
            for v in valid.values().flatten() {
                if let TypedItem::RosterAdd(add) = v.typed {
                    if add.device != genesis && !known.contains_key(&add.device) {
                        found.push((add.device, Keys::of(add)));
                    }
                }
            }
            if found.is_empty() {
                break;
            }
            for (device, keys) in found {
                if known.contains_key(&device) {
                    continue;
                }
                known.insert(device, keys);
                valid.insert(
                    device,
                    self.valid_items_of(candidates_of(device), &keys.sign_pub),
                );
            }
        }
        (known, valid)
    }

    /// §6.3 steps 2-4 over the entries (§5.6 "Forks" adds the collisions).
    fn resolve_roster(
        &self,
        known: BTreeMap<DeviceId, Keys>,
        valid: &ValidByOrigin<'_>,
        entries: &[Entry<'_>],
    ) -> Roster {
        let genesis = self.info.genesis;

        // Step 2 and §5.6 "Forks": the minimum over (a) fork.report entries
        // (every valid item's origin is known, so every entry counts) and
        // (b) the lowest seq holding two different valid items of the origin.
        let mut forks: BTreeMap<DeviceId, u64> = BTreeMap::new();
        let mut lower = |device: DeviceId, seq: u64| {
            let slot = forks.entry(device).or_insert(seq);
            *slot = (*slot).min(seq);
        };
        for e in entries {
            if let TypedItem::ForkReport(report) = e.item {
                lower(report.device, report.seq);
            }
        }
        for (&origin, items) in valid {
            let mut hashes_at: BTreeMap<u64, BTreeSet<ItemHash>> = BTreeMap::new();
            for v in items {
                hashes_at.entry(v.body.seq).or_default().insert(v.hash);
            }
            if let Some((&seq, _)) = hashes_at.iter().find(|(_, hashes)| hashes.len() > 1) {
                lower(origin, seq);
            }
        }

        // Step 3: the maximum cutoff over remove entries (origins all known).
        let mut cutoffs: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for e in entries {
            if let TypedItem::RosterRemove(remove) = e.item {
                let slot = cutoffs.entry(remove.device).or_insert(remove.cutoff_seq);
                *slot = (*slot).max(remove.cutoff_seq);
            }
        }

        let mut roster = Roster {
            known,
            forks,
            cutoffs,
            members: BTreeSet::new(),
        };

        // Step 4: step 1 again — seeded with the genesis whenever its
        // self-add is present, as in step 1 (PROTOCOL.md §6.3, clarified in
        // 02 after this oracle's ambiguity report; originally this required
        // the self-add itself to be admitted) — but an add of any other
        // device counts only if it is admitted at its own seq.
        let self_add_counts = entries.iter().any(|e| {
            e.origin == genesis
                && matches!(e.item, TypedItem::RosterAdd(add) if add.device == genesis)
        });
        if self_add_counts {
            roster.members.insert(genesis);
            loop {
                let mut changed = false;
                for e in entries {
                    if let TypedItem::RosterAdd(add) = e.item {
                        if add.device != genesis
                            && roster.members.contains(&e.origin)
                            && roster.within(e.origin, e.seq)
                            && roster.members.insert(add.device)
                        {
                            changed = true;
                        }
                    }
                }
                if !changed {
                    break;
                }
            }
        }
        roster
    }
}

/// Per key, the candidate with the greatest rank (§5.2 uses `(hlc, origin)`;
/// shares add a kind rank). Ranks within one key are distinct because each
/// origin has one entry per `(kind, key)`.
fn winners<K: Ord, R: Ord, T>(candidates: impl IntoIterator<Item = (K, R, T)>) -> BTreeMap<K, T> {
    let mut best: BTreeMap<K, (R, T)> = BTreeMap::new();
    for (key, rank, value) in candidates {
        let greater = best.get(&key).is_none_or(|(cur, _)| rank > *cur);
        if greater {
            best.insert(key, (rank, value));
        }
    }
    best.into_iter()
        .map(|(key, (_, value))| (key, value))
        .collect()
}

fn view_device_info(admitted: &[&Entry<'_>]) -> BTreeMap<DeviceId, ExpectedDeviceInfo> {
    winners(admitted.iter().filter_map(|e| match e.item {
        TypedItem::DeviceInfo(info) => Some((
            info.device,
            (e.hlc, e.origin),
            ExpectedDeviceInfo {
                name: info.name.clone(),
                listen_addrs: info.listen_addrs.clone(),
            },
        )),
        _ => None,
    }))
}

fn view_settings(admitted: &[&Entry<'_>]) -> BTreeMap<String, Value> {
    winners(admitted.iter().filter_map(|e| match e.item {
        TypedItem::MeshSetting(setting) => Some((
            setting.name.clone(),
            (e.hlc, e.origin),
            setting.value.clone(),
        )),
        _ => None,
    }))
}

fn view_projects(admitted: &[&Entry<'_>]) -> BTreeMap<MeshProjectId, ExpectedProject> {
    winners(admitted.iter().filter_map(|e| match e.item {
        TypedItem::ProjectMeta(meta) => Some((
            meta.project,
            (e.hlc, e.origin),
            ExpectedProject {
                name: meta.name.clone(),
                archived: meta.archived,
                merged_into: meta.merged_into,
            },
        )),
        _ => None,
    }))
}

fn view_usage(
    admitted: &[&Entry<'_>],
) -> BTreeMap<UsageKey, BTreeMap<DeviceId, (u32, UsageTotals)>> {
    let mut usage: BTreeMap<UsageKey, BTreeMap<DeviceId, (u32, UsageTotals)>> = BTreeMap::new();
    for e in admitted {
        if let TypedItem::UsageCounter(counter) = e.item {
            usage
                .entry(counter.key.clone())
                .or_default()
                .insert(e.origin, (counter.epoch, counter.totals));
        }
    }
    usage
}

fn view_caps(admitted: &[&Entry<'_>], roster: &Roster) -> BTreeMap<CapId, ExpectedCapDef> {
    // Each origin has at most one entry per cap id, so one entry per origin.
    let mut defs: BTreeMap<CapId, BTreeMap<DeviceId, &CapDef>> = BTreeMap::new();
    for e in admitted {
        if let TypedItem::CapDef(def) = e.item {
            defs.entry(def.cap).or_default().insert(e.origin, def);
        }
    }
    defs.into_iter()
        .map(|(cap, by_origin)| {
            let mut defs = by_origin.into_values();
            let view = match (defs.next(), defs.next()) {
                (Some(def), None) => ExpectedCapDef::Defined {
                    mesh_project_id: def.mesh_project_id,
                    owner_device: def.owner_device,
                    created_hlc: def.created_hlc,
                    frozen: roster.removed(def.owner_device),
                },
                // More than one origin (none is impossible: the key exists).
                _ => ExpectedCapDef::Conflicted,
            };
            (cap, view)
        })
        .collect()
}

/// The admitted inputs of one `(cap_id, month)`.
#[derive(Default)]
struct MonthInputs {
    /// `((hlc, origin), target_micros)` per admitted `cap.target` entry.
    targets: Vec<((Hlc, DeviceId), u64)>,
    /// `R[from][to]`.
    rights: BTreeMap<(DeviceId, Recipient), u64>,
    /// `U[i]`.
    used: BTreeMap<DeviceId, u64>,
}

fn view_cap_months(admitted: &[&Entry<'_>]) -> BTreeMap<(CapId, Month), ExpectedCapMonth> {
    let mut months: BTreeMap<(CapId, Month), MonthInputs> = BTreeMap::new();
    for e in admitted {
        match e.item {
            TypedItem::CapTarget(t) => months
                .entry((t.cap, t.month))
                .or_default()
                .targets
                .push(((e.hlc, e.origin), t.target_micros)),
            TypedItem::CapRights(r) => {
                months
                    .entry((r.cap, r.month))
                    .or_default()
                    .rights
                    .insert((e.origin, r.to), r.amount_micros);
            }
            TypedItem::CapUsed(u) => {
                months
                    .entry((u.cap, u.month))
                    .or_default()
                    .used
                    .insert(e.origin, u.used_micros);
            }
            _ => {}
        }
    }
    months
        .into_iter()
        .map(|(slot, inputs)| {
            let mut view = bounded_view(&inputs.rights, &inputs.used);
            view.target = inputs
                .targets
                .iter()
                .max_by_key(|(rank, _)| *rank)
                .map(|(_, target)| *target);
            (slot, view)
        })
        .collect()
}

fn signed(x: u128) -> i128 {
    i128::try_from(x).unwrap_or(i128::MAX)
}

/// The bounded-counter view of §5.5, literally.
fn bounded_view(
    rights: &BTreeMap<(DeviceId, Recipient), u64>,
    used: &BTreeMap<DeviceId, u64>,
) -> ExpectedCapMonth {
    let amount = |from: DeviceId, to: Recipient| -> u128 {
        rights.get(&(from, to)).map_or(0, |&a| u128::from(a))
    };

    // Every origin or device-recipient of a rights entry, and every origin of
    // a used entry.
    let mut devices: BTreeSet<DeviceId> = used.keys().copied().collect();
    for &(from, to) in rights.keys() {
        devices.insert(from);
        if let Recipient::Device(d) = to {
            devices.insert(d);
        }
    }

    // Step 1.
    let minted = |i: DeviceId| amount(i, Recipient::Device(i));
    let raw_in = |i: DeviceId| -> u128 {
        devices
            .iter()
            .filter(|&&j| j != i)
            .map(|&j| amount(j, Recipient::Device(i)))
            .sum()
    };

    // Step 2: burn first, then recipient devices by ascending id, each
    // honoured up to what is left of minted(i) + raw_in(i).
    let mut honoured: BTreeMap<(DeviceId, Recipient), u128> = BTreeMap::new();
    let mut clamped: BTreeMap<DeviceId, u128> = BTreeMap::new();
    for &i in &devices {
        let mut left = minted(i) + raw_in(i);
        let mut recipients: Vec<DeviceId> = rights
            .keys()
            .filter_map(|&(from, to)| match to {
                Recipient::Device(d) if from == i && d != i => Some(d),
                _ => None,
            })
            .collect();
        recipients.sort();
        let mut order = vec![Recipient::Burn];
        order.extend(recipients.into_iter().map(Recipient::Device));
        let mut clamped_here = 0u128;
        for to in order {
            let want = amount(i, to);
            let take = want.min(left);
            left -= take;
            clamped_here += want - take;
            honoured.insert((i, to), take);
        }
        clamped.insert(i, clamped_here);
    }
    let honoured_of =
        |from: DeviceId, to: Recipient| honoured.get(&(from, to)).copied().unwrap_or(0);

    // Steps 3 and 4.
    let mut view = ExpectedCapMonth::default();
    for &i in &devices {
        let minted_i = minted(i);
        let received: u128 = devices
            .iter()
            .filter(|&&j| j != i)
            .map(|&j| honoured_of(j, Recipient::Device(i)))
            .sum();
        let sent: u128 = devices
            .iter()
            .filter(|&&j| j != i)
            .map(|&j| honoured_of(i, Recipient::Device(j)))
            .sum();
        let burned = honoured_of(i, Recipient::Burn);
        let used_i = used.get(&i).map_or(0, |&u| u128::from(u));
        let avail =
            signed(minted_i) + signed(received) - signed(sent) - signed(burned) - signed(used_i);
        view.total_minted += minted_i;
        view.total_burned += burned;
        view.total_used += used_i;
        view.devices.insert(
            i,
            ExpectedRights {
                minted: minted_i,
                received,
                sent,
                burned,
                clamped: clamped.get(&i).copied().unwrap_or(0),
                used: used_i,
                avail,
            },
        );
    }
    view
}

fn view_shares(
    admitted: &[&Entry<'_>],
    roster: &Roster,
) -> BTreeMap<(CredentialRef, DeviceId), ExpectedShare> {
    winners(admitted.iter().filter_map(|e| {
        let (slot, rank, share) = match e.item {
            TypedItem::ShareSealed(s) => (
                (s.credential, s.recipient),
                0u8,
                ExpectedShare::Sealed {
                    sharer: e.origin,
                    share_id: s.share_id,
                    mesh_project_id: s.mesh_project_id,
                    credential_name: s.credential_name.clone(),
                    provider: s.provider.clone(),
                    value_version: s.value_version,
                    sealed: s.sealed.clone(),
                },
            ),
            TypedItem::ShareRevoke(r) => (
                (r.credential, r.recipient),
                1u8,
                ExpectedShare::Revoked {
                    revoker: e.origin,
                    share_id: r.share_id,
                },
            ),
            _ => return None,
        };
        (!roster.removed(slot.1)).then_some((slot, (e.hlc, e.origin, rank), share))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::dot::{MeshId, ShareId};
    use crate::mesh::kinds::{
        CapRights, CapTarget, CapUsed, Day, DeviceInfo, ForkReport, ItemKind, MeshSetting,
        ProjectMeta, RosterRemove, ShareRevoke, ShareSealed, UsageCounter,
    };
    use crate::mesh::sign::{derive_device_id, SigningKeyPair};
    use crate::mesh::sim::rng::SplitMix64;
    use serde_json::json;

    /// A kind v1 does not know: valid, opaque, never materialized. Used to
    /// fill an origin's seqs so that the worked examples' seqs are dense.
    const FILLER: &str = "test.filler";

    fn mesh() -> MeshId {
        MeshId::from_bytes([0x11; 16])
    }

    fn project(byte: u8) -> MeshProjectId {
        MeshProjectId::from_bytes([byte; 16])
    }

    /// A test device: a real signing key, unmistakably fake Noise and sealing
    /// keys, and the key-derived id (§6.1).
    struct Dev {
        kp: SigningKeyPair,
        noise: PublicKeyBytes,
        seal: PublicKeyBytes,
        id: DeviceId,
        next: u64,
    }

    impl Dev {
        fn new() -> Self {
            let kp = SigningKeyPair::generate();
            let noise = PublicKeyBytes([0xAA; 32]);
            let seal = PublicKeyBytes([0xBB; 32]);
            let id = derive_device_id(&kp.public_key(), &noise, &seal);
            Self {
                kp,
                noise,
                seal,
                id,
                next: 1,
            }
        }

        /// Sign a raw body at an explicit seq; does not move `next`.
        fn sign_at(&self, seq: u64, hlc: u64, kind: &str, key: &str, payload: Value) -> SignedItem {
            let body = ItemBody::new(mesh(), self.id, seq, Hlc::from_raw(hlc), kind, key, payload);
            SignedItem::sign(&body, &self.kp).expect("test bodies encode")
        }

        /// Mint a raw body at the next seq.
        fn mint_raw(&mut self, hlc: u64, kind: &str, key: &str, payload: Value) -> SignedItem {
            let item = self.sign_at(self.next, hlc, kind, key, payload);
            self.next += 1;
            item
        }

        /// Mint a typed value at the next seq.
        fn mint<K: ItemKind>(&mut self, hlc: u64, value: &K) -> SignedItem {
            let body = value.to_body(mesh(), self.id, self.next, Hlc::from_raw(hlc));
            self.next += 1;
            SignedItem::sign(&body, &self.kp).expect("test bodies encode")
        }

        /// Opaque filler items until the next seq is `seq`.
        fn fill_to(&mut self, o: &mut Oracle, seq: u64) {
            while self.next < seq {
                let key = format!("filler-{}", self.next);
                let item = self.mint_raw(0, FILLER, &key, json!({}));
                o.observe_minted(&item);
            }
        }

        fn add_of(&self, target: &Dev) -> RosterAdd {
            RosterAdd {
                device: target.id,
                name: "fake test device".into(),
                sign_pub: target.kp.public_key(),
                noise_pub: target.noise,
                seal_pub: target.seal,
                added_by: self.id,
            }
        }
    }

    /// Three fresh devices in ascending id order (the examples name devices
    /// in id order; ids are key-derived, so they are sorted, not chosen).
    fn sorted3() -> (Dev, Dev, Dev) {
        let mut v: Vec<Dev> = (0..3).map(|_| Dev::new()).collect();
        v.sort_by_key(|d| d.id);
        let c = v.pop().expect("three devices");
        let b = v.pop().expect("three devices");
        let a = v.pop().expect("three devices");
        (a, b, c)
    }

    /// An oracle whose genesis is `g`, with `g`'s self-add at seq 1.
    fn oracle_for(g: &mut Dev) -> Oracle {
        let mut o = Oracle::new(&GenesisInfo {
            mesh_id: mesh(),
            genesis: g.id,
        });
        let add = g.add_of(g);
        let item = g.mint(1, &add);
        o.observe_minted(&item);
        o
    }

    fn put<K: ItemKind>(o: &mut Oracle, by: &mut Dev, hlc: u64, value: &K) -> SignedItem {
        let item = by.mint(hlc, value);
        o.observe_minted(&item);
        item
    }

    fn add(o: &mut Oracle, by: &mut Dev, target: &Dev) {
        let value = by.add_of(target);
        put(o, by, 1, &value);
    }

    fn remove(o: &mut Oracle, by: &mut Dev, target: &Dev, cutoff_seq: u64) {
        let value = RosterRemove {
            device: target.id,
            cutoff_seq,
        };
        put(o, by, 1, &value);
    }

    fn set(o: &mut Oracle, by: &mut Dev, hlc: u64, name: &str, value: Value) -> SignedItem {
        let value = MeshSetting {
            name: name.into(),
            value,
        };
        put(o, by, hlc, &value)
    }

    fn fork_report(target: &Dev, seq: u64) -> ForkReport {
        ForkReport {
            device: target.id,
            seq,
            hash_a: ItemHash([0xF1; 32]),
            hash_b: ItemHash([0xF2; 32]),
        }
    }

    fn value_of(o: &Oracle, name: &str) -> Option<Value> {
        o.expected().settings.get(name).cloned()
    }

    fn device(s: &ExpectedState, d: &Dev) -> ExpectedDevice {
        s.devices
            .get(&d.id)
            .cloned()
            .unwrap_or_else(|| panic!("{:?} is not known", d.id))
    }

    // ------------------------------------------------------------ §5.2 LWW

    #[test]
    fn lww_worked_example() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, mut b, mut c) = sorted3();
        for d in [&a, &b, &c] {
            add(&mut o, &mut g, d);
        }
        a.fill_to(&mut o, 3);
        set(&mut o, &mut a, 100, "k", json!("x"));
        b.fill_to(&mut o, 7);
        set(&mut o, &mut b, 150, "k", json!("y"));
        c.fill_to(&mut o, 2);
        set(&mut o, &mut c, 150, "k", json!("z"));
        // 1. B and C tie at hlc 150; C > B.
        assert_eq!(value_of(&o, "k"), Some(json!("z")));

        // 2. A's seq 5 supersedes its seq 3 even though 90 < 100.
        a.fill_to(&mut o, 5);
        set(&mut o, &mut a, 90, "k", json!("w"));
        assert_eq!(value_of(&o, "k"), Some(json!("z")));

        // 3. C removed with cutoff 1: C's seq-2 entry is not admitted.
        remove(&mut o, &mut g, &c, 1);
        assert_eq!(value_of(&o, "k"), Some(json!("y")));
        let s = o.expected();
        assert_eq!(device(&s, &c).cutoff, Some(1));
        assert!(device(&s, &c).member && !device(&s, &c).active);

        // 4. B removed with cutoff 7: B's seq-7 entry is still admitted.
        remove(&mut o, &mut g, &b, 7);
        assert_eq!(value_of(&o, "k"), Some(json!("y")));
    }

    #[test]
    fn removal_cutoff_excludes_later_entries_and_the_value_falls_back() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, mut b) = (Dev::new(), Dev::new());
        add(&mut o, &mut g, &a);
        add(&mut o, &mut g, &b);
        set(&mut o, &mut a, 10, "k", json!("a"));
        b.fill_to(&mut o, 2);
        set(&mut o, &mut b, 20, "k", json!("b"));
        set(&mut o, &mut b, 30, "k", json!("b2"));
        assert_eq!(value_of(&o, "k"), Some(json!("b2")));

        // B's latest entry (seq 3) is above the cutoff, and its seq-2 value was
        // superseded by its own seq 3: the value falls back to A's.
        remove(&mut o, &mut g, &b, 2);
        assert_eq!(value_of(&o, "k"), Some(json!("a")));
    }

    #[test]
    fn device_info_and_projects_are_lww_views() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, mut b) = (Dev::new(), Dev::new());
        add(&mut o, &mut g, &a);
        add(&mut o, &mut g, &b);
        let info = DeviceInfo {
            device: a.id,
            name: "fake laptop".into(),
            listen_addrs: vec!["127.0.0.1:7000".into()],
        };
        put(&mut o, &mut a, 5, &info);
        let meta = |name: &str, merged_into| ProjectMeta {
            project: project(0x31),
            name: name.into(),
            archived: false,
            merged_into,
        };
        put(&mut o, &mut a, 50, &meta("Fake API", None));
        put(
            &mut o,
            &mut b,
            60,
            &meta("Fake API renamed", Some(project(0x32))),
        );
        let s = o.expected();
        assert_eq!(
            s.device_info.get(&a.id),
            Some(&ExpectedDeviceInfo {
                name: "fake laptop".into(),
                listen_addrs: vec!["127.0.0.1:7000".into()],
            })
        );
        assert!(!s.device_info.contains_key(&b.id));
        assert_eq!(
            s.projects.get(&project(0x31)),
            Some(&ExpectedProject {
                name: "Fake API renamed".into(),
                archived: false,
                merged_into: Some(project(0x32)),
            })
        );
    }

    // -------------------------------------------------- §5.3 owner counter

    fn usage_key() -> UsageKey {
        UsageKey {
            project: project(0x33),
            day: Day::parse("2026-10-01").expect("valid day"),
            provider: "fake-provider".into(),
            model: "fake/model-1".into(),
        }
    }

    fn counter(epoch: u32, requests: u64, cost: u64) -> UsageCounter {
        UsageCounter {
            key: usage_key(),
            epoch,
            totals: UsageTotals {
                requests,
                estimated_cost_micros: cost,
                ..UsageTotals::default()
            },
        }
    }

    #[test]
    fn owner_counter_worked_example() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, b) = (Dev::new(), Dev::new());
        add(&mut o, &mut g, &a);
        add(&mut o, &mut g, &b);

        // 1. seq 4 (epoch 0) then seq 9 (epoch 1, smaller totals): seq 9 wins.
        a.fill_to(&mut o, 4);
        put(&mut o, &mut a, 1, &counter(0, 10, 500));
        let s = o.expected();
        assert_eq!(
            s.usage[&usage_key()][&a.id],
            (0, counter(0, 10, 500).totals)
        );
        a.fill_to(&mut o, 9);
        put(&mut o, &mut a, 2, &counter(1, 2, 100));
        let s = o.expected();
        let per_device = &s.usage[&usage_key()];
        assert_eq!(per_device[&a.id], (1, counter(1, 2, 100).totals));
        // A device with no entry is unknown, never zero.
        assert_eq!(per_device.len(), 1);
        assert!(!per_device.contains_key(&b.id));
    }

    #[test]
    fn owner_counter_regression_still_takes_the_higher_seq() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let mut a = Dev::new();
        add(&mut o, &mut g, &a);
        a.fill_to(&mut o, 4);
        put(&mut o, &mut a, 1, &counter(0, 10, 500));
        a.fill_to(&mut o, 9);
        // 3. Same epoch, smaller totals: still the seq-9 entry.
        put(&mut o, &mut a, 2, &counter(0, 8, 400));
        assert_eq!(
            o.expected().usage[&usage_key()][&a.id],
            (0, counter(0, 8, 400).totals)
        );
    }

    // ------------------------------------------------- §5.5 bounded counter

    fn cap() -> CapId {
        CapId::from_bytes([0xC1; 16])
    }

    fn month() -> Month {
        Month::new(2026, 10).expect("valid month")
    }

    fn rights(to: Recipient, amount_micros: u64) -> CapRights {
        CapRights {
            cap: cap(),
            month: month(),
            to,
            amount_micros,
            is_override: false,
        }
    }

    fn used(used_micros: u64) -> CapUsed {
        CapUsed {
            cap: cap(),
            month: month(),
            epoch: 0,
            used_micros,
        }
    }

    /// `[minted, received, sent, burned, clamped, used]` and `avail`.
    fn row(amounts: [u128; 6], avail: i128) -> ExpectedRights {
        let [minted, received, sent, burned, clamped, used] = amounts;
        ExpectedRights {
            minted,
            received,
            sent,
            burned,
            clamped,
            used,
            avail,
        }
    }

    fn cap_def(cap: CapId, owner: &Dev, project_byte: u8) -> CapDef {
        CapDef {
            cap,
            mesh_project_id: project(project_byte),
            owner_device: owner.id,
            created_hlc: Hlc::from_raw(7),
        }
    }

    /// The §5.5 worked example: ids `A < B < O`, O the owner (and genesis).
    struct CapExample {
        o: Oracle,
        a: Dev,
        b: Dev,
        owner: Dev,
    }

    fn cap_example() -> CapExample {
        let (mut a, mut b, mut owner) = sorted3();
        let mut o = oracle_for(&mut owner);
        add(&mut o, &mut owner, &a);
        add(&mut o, &mut owner, &b);
        let def = cap_def(cap(), &owner, 0x34);
        put(&mut o, &mut owner, 1, &def);
        let (owner_id, a_id, b_id) = (owner.id, a.id, b.id);
        put(
            &mut o,
            &mut owner,
            1,
            &rights(Recipient::Device(owner_id), 100),
        );
        put(&mut o, &mut owner, 1, &rights(Recipient::Burn, 10));
        put(&mut o, &mut owner, 1, &rights(Recipient::Device(a_id), 30));
        put(&mut o, &mut owner, 1, &rights(Recipient::Device(b_id), 20));
        put(&mut o, &mut a, 1, &rights(Recipient::Device(b_id), 10));
        put(&mut o, &mut a, 1, &used(5));
        put(&mut o, &mut b, 1, &used(25));
        CapExample { o, a, b, owner }
    }

    #[test]
    fn bounded_counter_worked_example() {
        let ex = cap_example();
        let s = ex.o.expected();
        let m = &s.cap_months[&(cap(), month())];
        assert_eq!(m.devices.len(), 3);
        assert_eq!(m.devices[&ex.owner.id], row([100, 0, 50, 10, 0, 0], 40));
        assert_eq!(m.devices[&ex.a.id], row([0, 30, 10, 0, 0, 5], 15));
        assert_eq!(m.devices[&ex.b.id], row([0, 30, 0, 0, 0, 25], 5));
        assert_eq!(
            (m.total_minted, m.total_burned, m.total_used),
            (100, 10, 30)
        );
        let avail: i128 = m.devices.values().map(|r| r.avail).sum();
        assert_eq!(avail, 60, "Σ avail = supply − Σ U");
        assert_eq!(m.target, None);
        assert_eq!(
            s.caps[&cap()],
            ExpectedCapDef::Defined {
                mesh_project_id: project(0x34),
                owner_device: ex.owner.id,
                created_hlc: Hlc::from_raw(7),
                frozen: false,
            }
        );
    }

    #[test]
    fn clamp_an_unfunded_sender_creates_nothing() {
        let mut ex = cap_example();
        let mut m = Dev::new();
        add(&mut ex.o, &mut ex.owner, &m);
        let a_id = ex.a.id;
        put(
            &mut ex.o,
            &mut m,
            1,
            &rights(Recipient::Device(a_id), 1_000_000),
        );
        let s = ex.o.expected();
        let v = &s.cap_months[&(cap(), month())];
        assert_eq!(v.devices[&m.id], row([0, 0, 0, 0, 1_000_000, 0], 0));
        assert_eq!(v.devices[&ex.a.id], row([0, 30, 10, 0, 0, 5], 15));
    }

    #[test]
    fn clamp_a_partly_funded_sender_passes_on_what_it_was_sent() {
        let mut ex = cap_example();
        let mut m = Dev::new();
        add(&mut ex.o, &mut ex.owner, &m);
        let (a_id, m_id) = (ex.a.id, m.id);
        put(
            &mut ex.o,
            &mut m,
            1,
            &rights(Recipient::Device(a_id), 1_000_000),
        );
        put(
            &mut ex.o,
            &mut ex.owner,
            1,
            &rights(Recipient::Device(m_id), 10),
        );
        let s = ex.o.expected();
        let v = &s.cap_months[&(cap(), month())];
        assert_eq!(v.devices[&m.id], row([0, 10, 10, 0, 999_990, 0], 0));
        assert_eq!(v.devices[&ex.a.id], row([0, 40, 10, 0, 0, 5], 25));
        assert_eq!(v.devices[&ex.owner.id], row([100, 0, 60, 10, 0, 0], 30));
    }

    #[test]
    fn clamp_honours_burn_first_then_ascending_device_ids() {
        // A < M < Z; M has a budget of 100 (a non-owner self-mint counts
        // exactly like a mint) and writes burn 40, Z 50, A 50.
        let (a, mut m, z) = sorted3();
        let mut o = oracle_for(&mut m);
        add(&mut o, &mut m, &a);
        add(&mut o, &mut m, &z);
        let mut self_mint = rights(Recipient::Device(m.id), 100);
        self_mint.is_override = true;
        put(&mut o, &mut m, 1, &self_mint);
        put(&mut o, &mut m, 1, &rights(Recipient::Burn, 40));
        put(&mut o, &mut m, 1, &rights(Recipient::Device(z.id), 50));
        put(&mut o, &mut m, 1, &rights(Recipient::Device(a.id), 50));
        let s = o.expected();
        let v = &s.cap_months[&(cap(), month())];
        assert_eq!(v.devices[&m.id], row([100, 0, 60, 40, 40, 0], 0));
        assert_eq!(v.devices[&a.id], row([0, 50, 0, 0, 0, 0], 50));
        assert_eq!(v.devices[&z.id], row([0, 10, 0, 0, 0, 0], 10));
        assert_eq!((v.total_minted, v.total_burned, v.total_used), (100, 40, 0));
        assert!(s.caps.is_empty(), "no cap.def was minted");
    }

    #[test]
    fn cap_target_is_lww_and_alone_creates_the_month() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let mut a = Dev::new();
        add(&mut o, &mut g, &a);
        let target = |target_micros| CapTarget {
            cap: cap(),
            month: month(),
            target_micros,
        };
        put(&mut o, &mut g, 200, &target(5_000));
        put(&mut o, &mut a, 100, &target(9_000));
        let s = o.expected();
        let v = &s.cap_months[&(cap(), month())];
        assert_eq!(v.target, Some(5_000));
        assert!(v.devices.is_empty());
    }

    #[test]
    fn cap_def_from_two_origins_is_conflicted_and_a_removed_owner_freezes() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, mut b) = (Dev::new(), Dev::new());
        add(&mut o, &mut g, &a);
        add(&mut o, &mut g, &b);
        let shared = CapId::from_bytes([0xD1; 16]);
        let solo = CapId::from_bytes([0xD2; 16]);
        let (da, db, ds) = (
            cap_def(shared, &a, 0x35),
            cap_def(shared, &b, 0x35),
            cap_def(solo, &a, 0x35),
        );
        put(&mut o, &mut a, 1, &da);
        put(&mut o, &mut b, 1, &db);
        put(&mut o, &mut a, 1, &ds);
        let s = o.expected();
        assert_eq!(s.caps[&shared], ExpectedCapDef::Conflicted);
        assert!(matches!(
            s.caps[&solo],
            ExpectedCapDef::Defined { frozen: false, .. }
        ));
        remove(&mut o, &mut g, &a, 10);
        assert!(matches!(
            o.expected().caps[&solo],
            ExpectedCapDef::Defined { frozen: true, .. }
        ));
    }

    // ------------------------------------------------------ §6.5 roster

    /// Example 1: `G 1: add G` · `G 2: add A` · `A 1: add B` · `B 1: add C`.
    struct RosterExample {
        o: Oracle,
        g: Dev,
        a: Dev,
        b: Dev,
        c: Dev,
    }

    fn roster_example() -> RosterExample {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, mut b, c) = (Dev::new(), Dev::new(), Dev::new());
        add(&mut o, &mut g, &a);
        add(&mut o, &mut a, &b);
        add(&mut o, &mut b, &c);
        RosterExample { o, g, a, b, c }
    }

    #[test]
    fn roster_example_1_chain_of_adds() {
        let ex = roster_example();
        let s = ex.o.expected();
        assert_eq!(s.devices.len(), 4);
        for d in [&ex.g, &ex.a, &ex.b, &ex.c] {
            let dev = device(&s, d);
            assert!(dev.member && dev.active, "{:?}", d.id);
            assert_eq!((dev.cutoff, dev.fork_seq), (None, None));
            assert_eq!(
                (dev.sign_pub, dev.noise_pub, dev.seal_pub),
                (d.kp.public_key(), d.noise, d.seal)
            );
        }
    }

    #[test]
    fn roster_example_2_cutoff_zero() {
        let mut ex = roster_example();
        set(&mut ex.o, &mut ex.b, 1, "b-later", json!(true));
        remove(&mut ex.o, &mut ex.g, &ex.b, 0);
        let s = ex.o.expected();
        let b = device(&s, &ex.b);
        assert_eq!(b.cutoff, Some(0));
        assert!(b.member && !b.active);
        let c = device(&s, &ex.c);
        assert!(!c.member && !c.active, "C is known but not a member");
        assert!(
            s.settings.is_empty(),
            "B's items are not admitted at any seq"
        );
    }

    #[test]
    fn roster_example_3_cutoff_one_then_a_late_add() {
        let mut ex = roster_example();
        remove(&mut ex.o, &mut ex.g, &ex.b, 1);
        let d = Dev::new();
        add(&mut ex.o, &mut ex.b, &d);
        let s = ex.o.expected();
        assert!(device(&s, &ex.c).member, "B 1 ≤ 1 still counts");
        let dd = device(&s, &d);
        assert!(!dd.member && !dd.active, "D is known but not a member");
        assert_eq!(device(&s, &ex.b).cutoff, Some(1));
    }

    #[test]
    fn roster_example_4_concurrent_removes_take_the_max_cutoff() {
        let mut ex = roster_example();
        remove(&mut ex.o, &mut ex.a, &ex.b, 4);
        remove(&mut ex.o, &mut ex.g, &ex.b, 7);
        assert_eq!(device(&ex.o.expected(), &ex.b).cutoff, Some(7));
    }

    #[test]
    fn roster_example_5_mutual_removal_removes_both() {
        let mut ex = roster_example();
        remove(&mut ex.o, &mut ex.a, &ex.b, 0);
        remove(&mut ex.o, &mut ex.b, &ex.a, 0);
        let s = ex.o.expected();
        let (a, b) = (device(&s, &ex.a), device(&s, &ex.b));
        assert_eq!((a.cutoff, b.cutoff), (Some(0), Some(0)));
        assert!(!a.active && !b.active);
        // Step 4: A's add of B (A 1 > cutoff 0) no longer counts.
        assert!(a.member && !b.member && !device(&s, &ex.c).member);
    }

    #[test]
    fn roster_example_6_fork_report() {
        let mut ex = roster_example();
        let report = fork_report(&ex.b, 2);
        put(&mut ex.o, &mut ex.a, 1, &report);
        let d = Dev::new();
        add(&mut ex.o, &mut ex.b, &d);
        let s = ex.o.expected();
        let b = device(&s, &ex.b);
        assert_eq!(b.fork_seq, Some(2));
        assert!(b.member && !b.active);
        assert!(device(&s, &ex.c).member, "B's seq 1 is admitted");
        assert!(!device(&s, &d).member, "B's seq 2 is not");
    }

    // ----------------------------------------------- validity and forks

    #[test]
    fn forged_item_is_ignored_and_blocks_nothing() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, b) = (Dev::new(), Dev::new());
        add(&mut o, &mut g, &a);
        add(&mut o, &mut g, &b);
        set(&mut o, &mut a, 10, "k", json!("a"));
        // Origin A at A's next seq, signed by B.
        let mut forged = ItemBody::new(
            mesh(),
            a.id,
            a.next,
            Hlc::from_raw(999),
            "mesh.setting",
            "k",
            json!({"value": "forged"}),
        );
        o.observe_minted(&SignedItem::sign(&forged, &b.kp).expect("encodes"));
        // A forged add of a new device is ignored too.
        let x = Dev::new();
        forged.kind = "roster.add".into();
        forged.key = x.id.to_hex();
        forged.payload = a.add_of(&x).payload();
        o.observe_minted(&SignedItem::sign(&forged, &b.kp).expect("encodes"));
        // A's genuine item at that seq exists, so there is no gap.
        set(&mut o, &mut a, 11, "k2", json!("a2"));
        set(&mut o, &mut a, 12, "k3", json!("a3"));
        let s = o.expected();
        assert_eq!(s.settings.get("k"), Some(&json!("a")));
        assert_eq!(s.settings.get("k2"), Some(&json!("a2")));
        assert_eq!(s.settings.get("k3"), Some(&json!("a3")));
        assert!(!s.devices.contains_key(&x.id));
        assert!(device(&s, &a).active, "a forgery is not a fork");
    }

    #[test]
    fn item_from_a_never_added_origin_is_ignored() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let mut x = Dev::new();
        let y = Dev::new();
        // X's own self-add is not a genesis and admits nothing.
        let self_add = x.add_of(&x);
        put(&mut o, &mut x, 1, &self_add);
        set(&mut o, &mut x, 5, "k", json!("x"));
        add(&mut o, &mut x, &y);
        // An item for another mesh, even from a member, is ignored.
        let other_mesh = ItemBody::new(
            MeshId::from_bytes([0x99; 16]),
            g.id,
            g.next,
            Hlc::from_raw(1),
            "mesh.setting",
            "k",
            json!({"value": "other mesh"}),
        );
        o.observe_minted(&SignedItem::sign(&other_mesh, &g.kp).expect("encodes"));
        let s = o.expected();
        assert_eq!(s.devices.keys().copied().collect::<Vec<_>>(), vec![g.id]);
        assert!(s.settings.is_empty());
    }

    #[test]
    fn unknown_kind_is_ignored_but_holds_its_seq() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let mut a = Dev::new();
        add(&mut o, &mut g, &a);
        let item = a.mint_raw(1, "future.kind", "some/key", json!({"x": [1, 2]}));
        o.observe_minted(&item);
        set(&mut o, &mut a, 2, "k", json!("after"));
        let s = o.expected();
        assert_eq!(s.settings.len(), 1);
        assert_eq!(s.settings.get("k"), Some(&json!("after")));
        assert!(s.device_info.is_empty() && s.projects.is_empty() && s.usage.is_empty());
        assert!(s.caps.is_empty() && s.cap_months.is_empty() && s.shares.is_empty());
        assert!(device(&s, &a).active);
    }

    #[test]
    fn two_items_at_one_dot_fork_the_origin_there() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let mut b = Dev::new();
        add(&mut o, &mut g, &b);
        set(&mut o, &mut b, 1, "k1", json!("b1"));
        // Branch X goes on; branch Y (a clone) signs a different seq 2.
        let x2 = set(&mut o, &mut b, 2, "k2", json!("x"));
        set(&mut o, &mut b, 3, "k3", json!("z"));
        let y2 = b.sign_at(2, 2, "mesh.setting", "k2", json!({"value": "y"}));
        o.observe_minted(&y2);
        // Re-observing an identical item (a clone repeating it) is no fork.
        o.observe_minted(&x2);
        let s = o.expected();
        let dev = device(&s, &b);
        assert_eq!(dev.fork_seq, Some(2));
        assert!(dev.member && !dev.active);
        assert_eq!(s.settings.get("k1"), Some(&json!("b1")));
        assert!(!s.settings.contains_key("k2") && !s.settings.contains_key("k3"));
    }

    #[test]
    fn above_its_fork_point_a_forked_origin_needs_no_dense_prefix() {
        // Added by the orchestrator in 02 with the §5.6 rule 4 amendment: a
        // forked device's own report, reached by repair, counts although a
        // seq between its fork point and the report never travelled.
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let mut b = Dev::new();
        add(&mut o, &mut g, &b);
        set(&mut o, &mut b, 1, "k1", json!("b1"));
        set(&mut o, &mut b, 2, "k2", json!("x"));
        let y2 = b.sign_at(2, 2, "mesh.setting", "k2", json!({"value": "y"}));
        o.observe_minted(&y2);
        // b's seq 3 never travelled; its seq 4 reports g forked at 7.
        let report = b.sign_at(
            4,
            4,
            "fork.report",
            &g.id.to_hex(),
            fork_report(&g, 7).payload(),
        );
        o.observe_minted(&report);
        let s = o.expected();
        assert_eq!(device(&s, &b).fork_seq, Some(2));
        assert_eq!(device(&s, &g).fork_seq, Some(7));
        // Below the fork point the dense prefix still applies: a gap at seq 2
        // of an unforked origin hides seq 3.
        let mut c = Dev::new();
        add(&mut o, &mut g, &c);
        set(&mut o, &mut c, 1, "c1", json!(1));
        let c3 = c.sign_at(3, 3, "mesh.setting", "c3", json!({"value": 3}));
        o.observe_minted(&c3);
        assert!(!o.expected().settings.contains_key("c3"));
    }

    #[test]
    fn identical_items_at_one_dot_are_not_a_fork() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let a = Dev::new();
        add(&mut o, &mut g, &a);
        let first = a.sign_at(1, 3, "mesh.setting", "k", json!({"value": "same"}));
        let again = a.sign_at(1, 3, "mesh.setting", "k", json!({"value": "same"}));
        assert_eq!(first.hash(), again.hash());
        o.observe_minted(&first);
        o.observe_minted(&again);
        let s = o.expected();
        assert!(device(&s, &a).active);
        assert_eq!(s.settings.get("k"), Some(&json!("same")));
    }

    #[test]
    fn fork_report_by_a_known_device_forks_the_target() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, mut b) = (Dev::new(), Dev::new());
        add(&mut o, &mut g, &a);
        add(&mut o, &mut g, &b);
        set(&mut o, &mut b, 1, "k1", json!(1));
        set(&mut o, &mut b, 1, "k2", json!(2));
        set(&mut o, &mut b, 1, "k3", json!(3));
        // A report by a device that is never known counts for nothing.
        let mut stranger = Dev::new();
        let report = fork_report(&b, 1);
        let item = stranger.mint(1, &report);
        o.observe_minted(&item);
        assert!(device(&o.expected(), &b).active);

        let report = fork_report(&b, 3);
        put(&mut o, &mut a, 1, &report);
        let s = o.expected();
        assert_eq!(device(&s, &b).fork_seq, Some(3));
        assert!(s.settings.contains_key("k1") && s.settings.contains_key("k2"));
        assert!(!s.settings.contains_key("k3"));

        // A direct collision lower than the report wins (the minimum).
        let other = b.sign_at(2, 9, "mesh.setting", "k2", json!({"value": "fork"}));
        o.observe_minted(&other);
        let s = o.expected();
        assert_eq!(device(&s, &b).fork_seq, Some(2));
        assert!(!s.settings.contains_key("k2"));
    }

    #[test]
    fn invalid_payload_item_hides_the_origin_from_that_seq() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, b) = (Dev::new(), Dev::new());
        add(&mut o, &mut g, &a);
        add(&mut o, &mut g, &b);
        set(&mut o, &mut a, 1, "early", json!("kept"));
        // Validly signed by A, but a device may only describe itself.
        let bad = a.mint_raw(
            2,
            "device.info",
            &b.id.to_hex(),
            json!({"name": "not me", "listen_addrs": []}),
        );
        o.observe_minted(&bad);
        set(&mut o, &mut a, 3, "late", json!("hidden"));
        let added_late = Dev::new();
        add(&mut o, &mut a, &added_late);
        let s = o.expected();
        assert_eq!(s.settings.get("early"), Some(&json!("kept")));
        assert!(!s.settings.contains_key("late"));
        assert!(s.device_info.is_empty());
        assert!(
            !s.devices.contains_key(&added_late.id),
            "A's later add is not valid"
        );
        assert!(device(&s, &a).active, "an invalid payload is not a fork");
    }

    #[test]
    fn invalid_payload_beside_a_valid_item_at_the_same_seq_is_not_a_gap() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, b) = (Dev::new(), Dev::new());
        add(&mut o, &mut g, &a);
        add(&mut o, &mut g, &b);
        let bad = a.sign_at(
            1,
            1,
            "device.info",
            &b.id.to_hex(),
            json!({"name": "not me", "listen_addrs": []}),
        );
        o.observe_minted(&bad);
        set(&mut o, &mut a, 1, "k1", json!(1));
        set(&mut o, &mut a, 2, "k2", json!(2));
        let s = o.expected();
        assert_eq!(s.settings.get("k2"), Some(&json!(2)));
        assert!(device(&s, &a).active, "only one valid item at seq 1");
    }

    #[test]
    fn dense_prefix_ignores_an_item_far_above_the_last_seq() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let mut a = Dev::new();
        add(&mut o, &mut g, &a);
        set(&mut o, &mut a, 1, "k", json!("dense"));
        let far = a.sign_at(
            1_000_000_000,
            99,
            "mesh.setting",
            "k",
            json!({"value": "far"}),
        );
        o.observe_minted(&far);
        let stranger = Dev::new();
        let far_add = a
            .add_of(&stranger)
            .to_body(mesh(), a.id, 1_000_000_001, Hlc::from_raw(99));
        o.observe_minted(&SignedItem::sign(&far_add, &a.kp).expect("encodes"));
        let s = o.expected();
        assert_eq!(s.settings.get("k"), Some(&json!("dense")));
        assert!(!s.devices.contains_key(&stranger.id));
        assert!(device(&s, &a).active);
    }

    #[test]
    fn a_gap_hides_everything_above_it_until_filled() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let mut a = Dev::new();
        add(&mut o, &mut g, &a);
        set(&mut o, &mut a, 1, "k1", json!(1));
        // Seq 2 is not (yet) observed; seqs 3 and 4 are.
        let s3 = a.sign_at(3, 3, "mesh.setting", "k3", json!({"value": 3}));
        let s4 = a.sign_at(4, 4, "mesh.setting", "k1", json!({"value": 4}));
        o.observe_minted(&s3);
        o.observe_minted(&s4);
        let s = o.expected();
        assert_eq!(s.settings.get("k1"), Some(&json!(1)));
        assert!(!s.settings.contains_key("k3"));
        // Filling the gap makes the rest valid.
        let s2 = a.sign_at(2, 2, "mesh.setting", "k2", json!({"value": 2}));
        o.observe_minted(&s2);
        let s = o.expected();
        assert_eq!(s.settings.get("k1"), Some(&json!(4)));
        assert_eq!(s.settings.get("k3"), Some(&json!(3)));
    }

    #[test]
    fn genesis_without_a_valid_self_add_means_an_empty_roster() {
        let mut g = Dev::new();
        let mut o = Oracle::new(&GenesisInfo {
            mesh_id: mesh(),
            genesis: g.id,
        });
        let a = Dev::new();
        // A self-add of G signed by A, then a genuine add of A by G at seq 2.
        let self_add = g.add_of(&g).to_body(mesh(), g.id, 1, Hlc::from_raw(1));
        o.observe_minted(&SignedItem::sign(&self_add, &a.kp).expect("encodes"));
        g.next = 2;
        add(&mut o, &mut g, &a);
        assert_eq!(o.expected(), ExpectedState::default());

        // The genuine self-add at seq 1 fixes it.
        o.observe_minted(&SignedItem::sign(&self_add, &g.kp).expect("encodes"));
        let s = o.expected();
        assert!(device(&s, &g).active && device(&s, &a).active);
    }

    // ------------------------------------------------------------ shares

    fn share_id() -> ShareId {
        ShareId::from_bytes([0x5E; 16])
    }

    fn sealed(recipient: &Dev, credential: u8) -> ShareSealed {
        ShareSealed {
            credential: CredentialRef::from_bytes([credential; 16]),
            recipient: recipient.id,
            share_id: share_id(),
            mesh_project_id: project(0x36),
            credential_name: "Fake credential".into(),
            provider: "fake-provider".into(),
            value_version: 1,
            sealed: b"FAKE-SEALED-BOX-NOT-A-SECRET".to_vec(),
        }
    }

    fn revoke(recipient: &Dev, credential: u8) -> ShareRevoke {
        ShareRevoke {
            credential: CredentialRef::from_bytes([credential; 16]),
            recipient: recipient.id,
            share_id: share_id(),
        }
    }

    #[test]
    fn removed_recipients_shares_disappear() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut a, r, keep) = (Dev::new(), Dev::new(), Dev::new());
        for d in [&a, &r, &keep] {
            add(&mut o, &mut g, d);
        }
        let (to_r, to_keep) = (sealed(&r, 0xE1), sealed(&keep, 0xE1));
        put(&mut o, &mut a, 5, &to_r);
        put(&mut o, &mut a, 6, &to_keep);
        assert_eq!(o.expected().shares.len(), 2);
        remove(&mut o, &mut g, &r, 100);
        let s = o.expected();
        let key = (CredentialRef::from_bytes([0xE1; 16]), keep.id);
        assert_eq!(s.shares.keys().copied().collect::<Vec<_>>(), vec![key]);
        assert_eq!(
            s.shares[&key],
            ExpectedShare::Sealed {
                sharer: a.id,
                share_id: share_id(),
                mesh_project_id: project(0x36),
                credential_name: "Fake credential".into(),
                provider: "fake-provider".into(),
                value_version: 1,
                sealed: b"FAKE-SEALED-BOX-NOT-A-SECRET".to_vec(),
            }
        );
    }

    #[test]
    fn share_winner_is_greatest_hlc_then_origin_then_rank() {
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let (mut lo, mut hi, r) = sorted3();
        for d in [&lo, &hi, &r] {
            add(&mut o, &mut g, d);
        }
        // Same origin, same hlc: revoke (rank 1) beats sealed (rank 0).
        let (s1, r1) = (sealed(&r, 0xE2), revoke(&r, 0xE2));
        put(&mut o, &mut lo, 50, &s1);
        put(&mut o, &mut lo, 50, &r1);
        // Same hlc, different origins: the greater origin wins before rank.
        let (s2, r2) = (sealed(&r, 0xE3), revoke(&r, 0xE3));
        put(&mut o, &mut hi, 50, &s2);
        put(&mut o, &mut lo, 50, &r2);
        // A greater hlc wins outright.
        let (s3, r3) = (sealed(&r, 0xE4), revoke(&r, 0xE4));
        put(&mut o, &mut lo, 60, &s3);
        put(&mut o, &mut hi, 59, &r3);
        let s = o.expected();
        let at = |c: u8| &s.shares[&(CredentialRef::from_bytes([c; 16]), r.id)];
        assert_eq!(
            at(0xE2),
            &ExpectedShare::Revoked {
                revoker: lo.id,
                share_id: share_id(),
            }
        );
        assert!(matches!(at(0xE3), ExpectedShare::Sealed { sharer, .. } if *sharer == hi.id));
        assert!(matches!(at(0xE4), ExpectedShare::Sealed { sharer, .. } if *sharer == lo.id));
    }

    // ------------------------------------------------------------- scale

    /// About 2 000 random items over eight devices: `expected` is
    /// deterministic, and honoured transfers conserve rights. It prints its
    /// running time (run with `--nocapture` to see it).
    #[test]
    fn expected_is_stable_over_two_thousand_items() {
        let seed = 0x7AC1E;
        let mut rng = SplitMix64::new(seed);
        let mut g = Dev::new();
        let mut o = oracle_for(&mut g);
        let mut devs: Vec<Dev> = (0..7).map(|_| Dev::new()).collect();
        for d in &devs {
            add(&mut o, &mut g, d);
        }
        devs.push(g);
        let ids: Vec<DeviceId> = devs.iter().map(|d| d.id).collect();
        for n in 0..2_000u64 {
            let i = rng.below(devs.len() as u64) as usize;
            let hlc = n + 10;
            let d = &mut devs[i];
            match rng.below(4) {
                0 => {
                    let name = format!("setting-{}", rng.below(20));
                    set(&mut o, d, hlc, &name, json!(n));
                }
                1 => {
                    let mut c = counter(0, n, n * 3);
                    c.key.model = format!("fake/model-{}", rng.below(5));
                    put(&mut o, d, hlc, &c);
                }
                2 => {
                    let to = match rng.below(3) {
                        0 => Recipient::Burn,
                        _ => Recipient::Device(ids[rng.below(ids.len() as u64) as usize]),
                    };
                    put(&mut o, d, hlc, &rights(to, n));
                }
                _ => {
                    put(&mut o, d, hlc, &used(n));
                }
            }
        }
        let started = std::time::Instant::now();
        let first = o.expected();
        let elapsed = started.elapsed();
        eprintln!("MESH_SIM_SEED={seed}: expected() over ~2 000 items took {elapsed:?}");
        assert_eq!(first, o.expected(), "MESH_SIM_SEED={seed}");
        assert_eq!(first.devices.len(), 8);
        assert!(first.devices.values().all(|d| d.active));
        assert!(!first.settings.is_empty() && !first.usage.is_empty());
        let v = &first.cap_months[&(cap(), month())];
        let avail: i128 = v.devices.values().map(|r| r.avail).sum();
        let minted: i128 = signed(v.total_minted);
        assert_eq!(
            avail,
            minted - signed(v.total_burned) - signed(v.total_used),
            "MESH_SIM_SEED={seed}: honoured transfers conserve rights"
        );
    }
}
