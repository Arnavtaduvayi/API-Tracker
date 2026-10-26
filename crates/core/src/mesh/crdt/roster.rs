//! The device roster (PROTOCOL.md §5.4): a two-phase set with removal
//! cutoffs, fork cutoffs and a single genesis.
//!
//! **State** (joined entry-wise, like every replicated value):
//! * `adds[(target, origin)]` — `origin`'s latest `roster.add` of `target`;
//! * `removes[(target, origin)]` — `origin`'s latest `roster.remove` of
//!   `target`, carrying a `cutoff_seq`;
//! * `forks[origin]` — the lowest seq at which `origin` is known to have
//!   signed two different items (joined by minimum).
//!
//! **Resolution**, a pure function of that state, evaluated in a fixed order
//! so it has no circular dependencies:
//! 1. *Reachable:* starting from the genesis device, a `roster.add` brings
//!    its target in when its origin is already in and the add is below the
//!    origin's fork point. The genesis device's keys come only from its own
//!    self-add; adds of the genesis by anyone else are ignored.
//! 2. *Conflicts:* a target that reachable origins added with different keys
//!    is excluded entirely — a member re-adding an existing device id with
//!    other keys cannot take over that identity, only lock it out.
//! 3. *Known* (ingest's "origin is in the roster"): step 1 again without the
//!    conflicted targets. A known device's keys verify its items.
//! 4. *Cutoffs:* a `roster.remove` counts when its origin is known and the
//!    remove is below the origin's fork point; a device's cutoff is the
//!    **maximum** over the removes that count. Removers are checked against
//!    the cutoff-free known set, so two devices that remove each other
//!    concurrently are both removed.
//! 5. *Members:* step 1 again, now also requiring each add to be at or below
//!    its origin's cutoff — a removed device's later adds bring no one in.
//!
//! An origin's item at `seq` is **admitted** when the origin is a member,
//! `seq` ≤ its cutoff (if removed) and `seq` < its fork point (if forked).
//! Removal is forever: cutoffs never disappear, and a removed id stays
//! removed whatever is added later.

use super::{join_map, map_dominates, Admit, SwEntry};
use crate::mesh::dot::DeviceId;
use crate::mesh::error::MeshError;
use crate::mesh::kinds::RosterAdd;
use crate::mesh::sign::PublicKeyBytes;
use std::collections::{BTreeMap, BTreeSet};

/// A device's three public keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceKeys {
    pub sign_pub: PublicKeyBytes,
    pub noise_pub: PublicKeyBytes,
    pub seal_pub: PublicKeyBytes,
}

/// What a `roster.add` contributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddRecord {
    pub keys: DeviceKeys,
    pub name: String,
}

impl From<&RosterAdd> for AddRecord {
    fn from(a: &RosterAdd) -> Self {
        Self {
            keys: DeviceKeys {
                sign_pub: a.sign_pub,
                noise_pub: a.noise_pub,
                seal_pub: a.seal_pub,
            },
            name: a.name.clone(),
        }
    }
}

/// The derived view of a roster state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Resolved {
    known: BTreeMap<DeviceId, DeviceKeys>,
    members: BTreeSet<DeviceId>,
    cutoffs: BTreeMap<DeviceId, u64>,
    conflicted: BTreeSet<DeviceId>,
}

#[derive(Clone, Debug)]
pub struct Roster {
    genesis: DeviceId,
    adds: BTreeMap<(DeviceId, DeviceId), SwEntry<AddRecord>>,
    removes: BTreeMap<(DeviceId, DeviceId), SwEntry<u64>>,
    forks: BTreeMap<DeviceId, u64>,
    resolved: Resolved,
}

impl PartialEq for Roster {
    /// Equality of the replicated state; the resolution is derived from it.
    fn eq(&self, other: &Self) -> bool {
        self.genesis == other.genesis
            && self.adds == other.adds
            && self.removes == other.removes
            && self.forks == other.forks
    }
}

impl Eq for Roster {}

impl Roster {
    pub fn new(genesis: DeviceId) -> Self {
        Self {
            genesis,
            adds: BTreeMap::new(),
            removes: BTreeMap::new(),
            forks: BTreeMap::new(),
            resolved: Resolved::default(),
        }
    }

    pub fn genesis(&self) -> DeviceId {
        self.genesis
    }

    /// Record `origin`'s `roster.add` of `target`. Returns whether the state
    /// changed.
    pub fn apply_add(
        &mut self,
        origin: DeviceId,
        target: DeviceId,
        entry: SwEntry<AddRecord>,
    ) -> bool {
        let changed = super::join_entry(&mut self.adds, (target, origin), entry);
        if changed {
            self.resolve();
        }
        changed
    }

    /// Record `origin`'s `roster.remove` of `target` (`entry.value` is the
    /// cutoff seq).
    pub fn apply_remove(
        &mut self,
        origin: DeviceId,
        target: DeviceId,
        entry: SwEntry<u64>,
    ) -> bool {
        let changed = super::join_entry(&mut self.removes, (target, origin), entry);
        if changed {
            self.resolve();
        }
        changed
    }

    /// Record proof that `origin` signed two different items at `seq`.
    pub fn record_fork(&mut self, origin: DeviceId, seq: u64) -> bool {
        let changed = match self.forks.get(&origin) {
            Some(&s) if s <= seq => false,
            _ => {
                self.forks.insert(origin, seq);
                true
            }
        };
        if changed {
            self.resolve();
        }
        changed
    }

    pub fn join(&mut self, other: &Roster) -> Result<bool, MeshError> {
        if self.genesis != other.genesis {
            return Err(MeshError::GenesisMismatch);
        }
        let mut changed = join_map(&mut self.adds, &other.adds);
        changed |= join_map(&mut self.removes, &other.removes);
        for (o, s) in &other.forks {
            match self.forks.get_mut(o) {
                Some(mine) if *mine <= *s => {}
                Some(mine) => {
                    *mine = *s;
                    changed = true;
                }
                None => {
                    self.forks.insert(*o, *s);
                    changed = true;
                }
            }
        }
        if changed {
            self.resolve();
        }
        Ok(changed)
    }

    /// `self ≥ other` in the join order.
    pub fn dominates(&self, other: &Roster) -> bool {
        self.genesis == other.genesis
            && map_dominates(&self.adds, &other.adds)
            && map_dominates(&self.removes, &other.removes)
            && other
                .forks
                .iter()
                .all(|(o, s)| self.forks.get(o).is_some_and(|mine| mine <= s))
    }

    // ------------------------------------------------------------ queries

    /// Ingest check 4: the origin was brought in by a chain of adds from the
    /// genesis (whatever has been removed since). Its items are stored and
    /// relayed; whether they *count* is [`Roster::is_admitted`].
    pub fn is_known(&self, device: &DeviceId) -> bool {
        self.resolved.known.contains_key(device)
    }

    /// The keys that verify a known device's items.
    pub fn keys(&self, device: &DeviceId) -> Option<&DeviceKeys> {
        self.resolved.known.get(device)
    }

    pub fn is_member(&self, device: &DeviceId) -> bool {
        self.resolved.members.contains(device)
    }

    pub fn cutoff(&self, device: &DeviceId) -> Option<u64> {
        self.resolved.cutoffs.get(device).copied()
    }

    pub fn is_removed(&self, device: &DeviceId) -> bool {
        self.resolved.cutoffs.contains_key(device)
    }

    pub fn fork_seq(&self, device: &DeviceId) -> Option<u64> {
        self.forks.get(device).copied()
    }

    pub fn is_conflicted(&self, device: &DeviceId) -> bool {
        self.resolved.conflicted.contains(device)
    }

    /// A member that has been neither removed nor caught forking: the only
    /// devices a session may authenticate as (MESH-SI-2).
    pub fn is_active(&self, device: &DeviceId) -> bool {
        self.is_member(device) && !self.is_removed(device) && !self.forks.contains_key(device)
    }

    pub fn is_admitted(&self, origin: &DeviceId, seq: u64) -> bool {
        self.is_member(origin)
            && self.cutoff(origin).is_none_or(|c| seq <= c)
            && self.fork_seq(origin).is_none_or(|f| seq < f)
    }

    pub fn members(&self) -> impl Iterator<Item = &DeviceId> {
        self.resolved.members.iter()
    }

    pub fn known(&self) -> impl Iterator<Item = (&DeviceId, &DeviceKeys)> {
        self.resolved.known.iter()
    }

    /// The display name from the device's admitting add (the add from the
    /// smallest origin id when several agree). `device.info` carries renames.
    pub fn added_name(&self, device: &DeviceId) -> Option<&str> {
        self.known_adds_of(*device)
            .next()
            .map(|(_, e)| e.value.name.as_str())
    }

    // --------------------------------------------------------- resolution

    fn fork_ok(&self, origin: &DeviceId, seq: u64) -> bool {
        self.fork_seq(origin).is_none_or(|f| seq < f)
    }

    fn genesis_add(&self) -> Option<&SwEntry<AddRecord>> {
        self.adds.get(&(self.genesis, self.genesis))
    }

    /// Adds of `target` whose origin is known and below its fork point.
    fn known_adds_of(
        &self,
        target: DeviceId,
    ) -> impl Iterator<Item = (&DeviceId, &SwEntry<AddRecord>)> + '_ {
        self.adds
            .range((target, DeviceId::MIN)..=(target, DeviceId::MAX))
            .filter(move |((_, o), e)| {
                self.resolved.known.contains_key(o) && self.fork_ok(o, e.seq)
            })
            .map(|((_, o), e)| (o, e))
    }

    /// Closure from the genesis over adds that pass `ok`, skipping `banned`.
    fn reach(
        &self,
        ok: impl Fn(&DeviceId, u64) -> bool,
        banned: &BTreeSet<DeviceId>,
    ) -> BTreeSet<DeviceId> {
        let mut set = BTreeSet::new();
        if self.genesis_add().is_none() {
            return set;
        }
        set.insert(self.genesis);
        loop {
            let mut grew = false;
            for ((target, origin), e) in &self.adds {
                if *target == self.genesis
                    || banned.contains(target)
                    || set.contains(target)
                    || !set.contains(origin)
                    || !ok(origin, e.seq)
                {
                    continue;
                }
                set.insert(*target);
                grew = true;
            }
            if !grew {
                return set;
            }
        }
    }

    fn resolve(&mut self) {
        let mut r = Resolved::default();
        let Some(genesis_add) = self.genesis_add() else {
            self.resolved = r;
            return;
        };
        let genesis_keys = genesis_add.value.keys;
        let fork_ok = |o: &DeviceId, s: u64| self.fork_ok(o, s);

        // 1-2. Reachability ignoring cutoffs, then key conflicts.
        let reach0 = self.reach(fork_ok, &BTreeSet::new());
        let mut keys_seen: BTreeMap<DeviceId, DeviceKeys> = BTreeMap::new();
        for ((target, origin), e) in &self.adds {
            if *target == self.genesis || !reach0.contains(origin) || !fork_ok(origin, e.seq) {
                continue;
            }
            match keys_seen.get(target) {
                Some(k) if *k != e.value.keys => {
                    r.conflicted.insert(*target);
                }
                Some(_) => {}
                None => {
                    keys_seen.insert(*target, e.value.keys);
                }
            }
        }

        // 3. Known devices and their keys.
        for d in self.reach(fork_ok, &r.conflicted) {
            let keys = if d == self.genesis {
                genesis_keys
            } else {
                keys_seen[&d]
            };
            r.known.insert(d, keys);
        }

        // 4. Cutoffs from removes whose origin is known.
        for ((target, origin), e) in &self.removes {
            if r.known.contains_key(origin) && fork_ok(origin, e.seq) {
                let c = r.cutoffs.entry(*target).or_insert(e.value);
                *c = (*c).max(e.value);
            }
        }

        // 5. Members: reachability that also honours cutoffs.
        let cutoffs = r.cutoffs.clone();
        r.members = self.reach(
            |o, s| fork_ok(o, s) && cutoffs.get(o).is_none_or(|c| s <= *c),
            &r.conflicted,
        );
        self.resolved = r;
    }
}

impl Admit for Roster {
    fn admits(&self, origin: &DeviceId, seq: u64) -> bool {
        self.is_admitted(origin, seq)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::*;
    use crate::mesh::sim::rng::SplitMix64;

    fn keys(n: u8) -> DeviceKeys {
        DeviceKeys {
            sign_pub: PublicKeyBytes([n; 32]),
            noise_pub: PublicKeyBytes([n.wrapping_add(100); 32]),
            seal_pub: PublicKeyBytes([n.wrapping_add(200); 32]),
        }
    }

    fn rec(n: u8) -> AddRecord {
        AddRecord {
            keys: keys(n),
            name: format!("device {n}"),
        }
    }

    /// A tiny harness that mints adds/removes with per-origin seqs.
    struct Mesh {
        roster: Roster,
        next: BTreeMap<DeviceId, u64>,
    }

    impl Mesh {
        fn genesis(g: u64) -> Self {
            let mut m = Self {
                roster: Roster::new(dev(g)),
                next: BTreeMap::new(),
            };
            m.add(g, g);
            m
        }

        fn seq(&mut self, origin: u64) -> u64 {
            let s = self.next.entry(dev(origin)).or_insert(0);
            *s += 1;
            *s
        }

        /// Burn `n` seqs on `origin` (items of other kinds).
        fn mint_other(&mut self, origin: u64, n: u64) -> u64 {
            for _ in 0..n {
                self.seq(origin);
            }
            self.next[&dev(origin)]
        }

        fn add(&mut self, origin: u64, target: u64) -> u64 {
            let seq = self.seq(origin);
            self.roster.apply_add(
                dev(origin),
                dev(target),
                SwEntry::new(seq, hash_of(origin, target, seq, 0), rec(target as u8)),
            );
            seq
        }

        fn add_with_keys(&mut self, origin: u64, target: u64, k: u8) -> u64 {
            let seq = self.seq(origin);
            self.roster.apply_add(
                dev(origin),
                dev(target),
                SwEntry::new(seq, hash_of(origin, target, seq, k as u64), rec(k)),
            );
            seq
        }

        fn remove(&mut self, origin: u64, target: u64, cutoff: u64) -> u64 {
            let seq = self.seq(origin);
            self.roster.apply_remove(
                dev(origin),
                dev(target),
                SwEntry::new(seq, hash_of(origin, 1000 + target, seq, 0), cutoff),
            );
            seq
        }
    }

    #[test]
    fn genesis_rule() {
        let m = Mesh::genesis(1);
        assert!(m.roster.is_member(&dev(1)));
        assert!(m.roster.is_known(&dev(1)));
        assert_eq!(m.roster.keys(&dev(1)), Some(&keys(1)));
        assert!(m.roster.is_admitted(&dev(1), 99));
        // A self-add by any other device is not a genesis.
        let mut r = Roster::new(dev(1));
        r.apply_add(dev(2), dev(2), SwEntry::new(1, hash_of(2, 2, 1, 0), rec(2)));
        assert!(!r.is_known(&dev(2)) && !r.is_member(&dev(2)));
        assert!(
            !r.is_known(&dev(1)),
            "no genesis self-add yet: nothing is known"
        );
        // An empty roster admits nobody.
        assert!(!Roster::new(dev(1)).is_admitted(&dev(1), 1));
    }

    #[test]
    fn an_add_signed_by_a_non_member_is_not_admitted() {
        let mut m = Mesh::genesis(1);
        m.add(5, 6); // dev(5) is nobody
        assert!(!m.roster.is_known(&dev(6)));
        assert!(!m.roster.is_admitted(&dev(6), 1));
        // Once dev(5) is added by a member, its earlier add of dev(6) counts.
        m.add(1, 5);
        assert!(m.roster.is_member(&dev(5)) && m.roster.is_member(&dev(6)));
    }

    #[test]
    fn chains_of_adds_bring_devices_in() {
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.add(2, 3);
        m.add(3, 4);
        for d in 1..=4 {
            assert!(m.roster.is_active(&dev(d)), "dev {d}");
        }
        assert_eq!(m.roster.added_name(&dev(3)), Some("device 3"));
        assert_eq!(m.roster.added_name(&dev(9)), None);
        assert_eq!(m.roster.members().count(), 4);
        assert_eq!(m.roster.known().count(), 4);
    }

    #[test]
    fn removal_cuts_off_later_items_but_keeps_earlier_ones() {
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.mint_other(2, 4); // dev(2) seqs 1..=4
        m.remove(1, 2, 3);
        assert!(m.roster.is_removed(&dev(2)));
        assert!(!m.roster.is_active(&dev(2)));
        assert!(
            m.roster.is_known(&dev(2)),
            "a removed device's items still verify and relay"
        );
        assert!(m.roster.is_admitted(&dev(2), 3));
        assert!(!m.roster.is_admitted(&dev(2), 4));
    }

    #[test]
    fn removed_is_forever() {
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.remove(1, 2, 0);
        // Re-adding the same id by any member changes nothing.
        m.add(1, 2);
        assert!(m.roster.is_removed(&dev(2)));
        assert!(!m.roster.is_admitted(&dev(2), 1));
        // A later, smaller remove cannot un-remove either.
        m.remove(1, 2, 0);
        assert!(m.roster.is_removed(&dev(2)));
    }

    #[test]
    fn concurrent_removals_take_the_max_cutoff() {
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.add(1, 3);
        m.mint_other(3, 10);
        m.remove(1, 3, 4);
        m.remove(2, 3, 7);
        assert_eq!(m.roster.cutoff(&dev(3)), Some(7));
        assert!(m.roster.is_admitted(&dev(3), 7));
        assert!(!m.roster.is_admitted(&dev(3), 8));
    }

    #[test]
    fn two_devices_removing_each_other_are_both_removed() {
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.add(1, 3);
        // Concurrent: each removes the other with a cutoff below the other's
        // remove item.
        m.remove(2, 3, 0);
        m.remove(3, 2, 0);
        assert!(m.roster.is_removed(&dev(2)) && m.roster.is_removed(&dev(3)));
        assert!(m.roster.is_active(&dev(1)));
    }

    #[test]
    fn a_removed_devices_later_adds_bring_no_one_in() {
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.mint_other(2, 2); // seqs 1-2
        m.remove(1, 2, 2);
        m.add(2, 9); // seq 3 > cutoff
        assert!(m.roster.is_known(&dev(9)), "its items verify...");
        assert!(!m.roster.is_member(&dev(9)), "...but it is not a member");
        assert!(!m.roster.is_admitted(&dev(9), 1));
        // An add the removed device made before its cutoff still counts.
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.add(2, 8); // dev(2) seq 1
        m.remove(1, 2, 1);
        assert!(m.roster.is_member(&dev(8)));
    }

    #[test]
    fn removing_the_genesis_keeps_the_devices_it_added() {
        let mut m = Mesh::genesis(1);
        let add2 = m.add(1, 2);
        m.remove(2, 1, add2);
        assert!(m.roster.is_removed(&dev(1)));
        assert!(m.roster.is_active(&dev(2)));
        assert!(!m.roster.is_admitted(&dev(1), add2 + 1));
    }

    #[test]
    fn conflicting_keys_lock_the_device_out_instead_of_hijacking_it() {
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.add(1, 3);
        m.add_with_keys(3, 2, 77); // dev(3) re-adds dev(2) with its own keys
        assert!(m.roster.is_conflicted(&dev(2)));
        assert!(!m.roster.is_known(&dev(2)) && !m.roster.is_member(&dev(2)));
        // Re-adding the genesis with other keys is ignored entirely.
        m.add_with_keys(3, 1, 66);
        assert_eq!(m.roster.keys(&dev(1)), Some(&keys(1)));
        assert!(m.roster.is_active(&dev(1)));
        // Two adds that agree on keys are no conflict.
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.add(1, 3);
        m.add(3, 2);
        assert!(m.roster.is_active(&dev(2)));
    }

    #[test]
    fn a_fork_cuts_the_forked_origin_off_at_the_fork_point() {
        let mut m = Mesh::genesis(1);
        m.add(1, 2);
        m.mint_other(2, 3);
        let add_late = m.add(2, 5); // dev(2) seq 4
        m.roster.record_fork(dev(2), 4);
        assert!(!m.roster.is_active(&dev(2)));
        assert!(m.roster.is_admitted(&dev(2), 3));
        assert!(!m.roster.is_admitted(&dev(2), add_late));
        assert!(
            !m.roster.is_known(&dev(5)),
            "an add at the fork point does not count"
        );
        // A lower fork point wins; a higher one changes nothing.
        assert!(m.roster.record_fork(dev(2), 2));
        assert!(!m.roster.record_fork(dev(2), 3));
        assert_eq!(m.roster.fork_seq(&dev(2)), Some(2));
    }

    #[test]
    fn protocol_md_worked_examples() {
        // PROTOCOL.md §6.5, with G = 1, A = 2, B = 3, C = 4, D = 5.
        let chain = || {
            let mut m = Mesh::genesis(1);
            m.add(1, 2); // G 2: add A
            m.add(2, 3); // A 1: add B
            m.add(3, 4); // B 1: add C
            m
        };
        // 1.
        let m = chain();
        assert!((1..=4).all(|d| m.roster.is_active(&dev(d))));
        // 2.
        let mut m = chain();
        m.remove(1, 3, 0);
        assert!(m.roster.is_removed(&dev(3)));
        assert!(m.roster.is_known(&dev(4)) && !m.roster.is_member(&dev(4)));
        assert!(!m.roster.is_admitted(&dev(3), 1));
        // 3.
        let mut m = chain();
        m.remove(1, 3, 1);
        m.add(3, 5); // B 2: add D
        assert!(m.roster.is_member(&dev(4)));
        assert!(m.roster.is_known(&dev(5)) && !m.roster.is_member(&dev(5)));
        assert!(m.roster.is_admitted(&dev(3), 1) && !m.roster.is_admitted(&dev(3), 2));
        // 4.
        let mut m = chain();
        m.remove(2, 3, 4);
        m.remove(1, 3, 7);
        assert_eq!(m.roster.cutoff(&dev(3)), Some(7));
        // 5.
        let mut m = chain();
        m.remove(2, 3, 0);
        m.remove(3, 2, 0);
        assert!(m.roster.is_removed(&dev(2)) && m.roster.is_removed(&dev(3)));
        // 6.
        let mut m = chain();
        m.add_with_keys(3, 2, 99);
        assert!(m.roster.is_conflicted(&dev(2)) && !m.roster.is_known(&dev(2)));
        // 7.
        let mut m = chain();
        m.roster.record_fork(dev(3), 2);
        m.add(3, 5); // B 2: add D, at the fork point
        assert!(!m.roster.is_active(&dev(3)));
        assert!(!m.roster.is_admitted(&dev(3), 2));
        assert!(!m.roster.is_known(&dev(5)));
    }

    #[test]
    fn join_refuses_a_different_genesis() {
        let mut a = Roster::new(dev(1));
        let b = Roster::new(dev(2));
        assert_eq!(a.join(&b), Err(MeshError::GenesisMismatch));
    }

    fn random_roster(rng: &mut SplitMix64) -> Roster {
        let mut r = Roster::new(dev(0));
        r.apply_add(dev(0), dev(0), SwEntry::new(1, hash_of(0, 0, 1, 0), rec(0)));
        for _ in 0..rng.below(10) {
            let origin = rng.below(5);
            let target = rng.below(5);
            let seq = 1 + rng.below(8);
            let c = content(rng);
            match rng.below(5) {
                0..=2 => {
                    // Mostly each device's own keys; content 1/2 forges others.
                    let k = if c == 0 { target as u8 } else { 50 + c as u8 };
                    r.apply_add(
                        dev(origin),
                        dev(target),
                        SwEntry::new(seq, hash_of(origin, target, seq, c), rec(k)),
                    );
                }
                3 => {
                    r.apply_remove(
                        dev(origin),
                        dev(target),
                        SwEntry::new(
                            seq,
                            hash_of(origin, 100 + target, seq, c),
                            seq.saturating_sub(1 + c),
                        ),
                    );
                }
                _ => {
                    r.record_fork(dev(origin), seq);
                }
            }
        }
        r
    }

    #[test]
    fn join_laws_10k() {
        check_laws(
            "roster",
            0x0505,
            random_roster,
            |a, b| {
                let mut r = a.clone();
                r.join(b).unwrap();
                r
            },
            |a, b| a.dominates(b),
        );
    }

    #[test]
    fn resolution_is_order_independent_10k() {
        // Equal states resolve identically whatever order built them.
        let mut rng = SplitMix64::new(0x0506);
        for case in 0..LAW_CASES {
            let (a, b) = (random_roster(&mut rng), random_roster(&mut rng));
            let mut ab = a.clone();
            ab.join(&b).unwrap();
            let mut ba = b.clone();
            ba.join(&a).unwrap();
            assert_eq!(ab.resolved, ba.resolved, "MESH_SIM_SEED=0x0506 case {case}");
        }
    }
}
