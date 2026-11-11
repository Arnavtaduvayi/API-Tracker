//! Owner-written counters (PROTOCOL.md §5.3): usage counters and cap `used`.
//!
//! One entry per `(key, origin)`, written only by that origin, holding its
//! cumulative totals and an `epoch`. Like every replicated value, the
//! origin's highest-seq entry is its current one.
//!
//! The `(epoch, totals)` **lattice** — a higher epoch wins outright, equal
//! epochs take the field-wise maximum — is the rule an honest writer
//! follows: each new entry is ≥ its predecessor in that order, and when its
//! totals legitimately fall (local data deleted) it bumps the epoch. For an
//! honest writer the latest entry therefore *equals* the lattice join of
//! every entry it ever wrote, so a deletion propagates instead of being
//! "resurrected" by a max. [`OwnerCounterMap::insert`] reports a successor
//! that breaks the rule, so higher layers can flag the origin.

use super::{join_map, map_dominates, Admit, SwEntry};
use crate::mesh::dot::DeviceId;
use crate::mesh::kinds::UsageTotals;
use std::collections::BTreeMap;
use std::fmt::Debug;

/// A struct of `u64` fields with a field-wise maximum.
pub trait Totals: Clone + PartialEq + Eq + Default + Debug {
    fn field_max(&self, other: &Self) -> Self;
    /// Every field of `self` is ≤ the same field of `other`.
    fn fields_le(&self, other: &Self) -> bool;
}

impl Totals for u64 {
    fn field_max(&self, other: &Self) -> Self {
        (*self).max(*other)
    }
    fn fields_le(&self, other: &Self) -> bool {
        self <= other
    }
}

impl Totals for UsageTotals {
    fn field_max(&self, o: &Self) -> Self {
        Self {
            requests: self.requests.max(o.requests),
            priced_requests: self.priced_requests.max(o.priced_requests),
            unpriced_requests: self.unpriced_requests.max(o.unpriced_requests),
            unextracted_requests: self.unextracted_requests.max(o.unextracted_requests),
            input_tokens: self.input_tokens.max(o.input_tokens),
            output_tokens: self.output_tokens.max(o.output_tokens),
            cached_input_tokens: self.cached_input_tokens.max(o.cached_input_tokens),
            estimated_cost_micros: self.estimated_cost_micros.max(o.estimated_cost_micros),
        }
    }

    fn fields_le(&self, o: &Self) -> bool {
        self.requests <= o.requests
            && self.priced_requests <= o.priced_requests
            && self.unpriced_requests <= o.unpriced_requests
            && self.unextracted_requests <= o.unextracted_requests
            && self.input_tokens <= o.input_tokens
            && self.output_tokens <= o.output_tokens
            && self.cached_input_tokens <= o.cached_input_tokens
            && self.estimated_cost_micros <= o.estimated_cost_micros
    }
}

/// `(epoch, totals)`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CounterValue<T> {
    pub epoch: u32,
    pub totals: T,
}

impl<T: Totals> CounterValue<T> {
    pub fn new(epoch: u32, totals: T) -> Self {
        Self { epoch, totals }
    }

    /// The lattice join: a higher epoch wins outright; equal epochs take the
    /// field-wise maximum.
    pub fn lattice_join(&self, other: &Self) -> Self {
        use std::cmp::Ordering::*;
        match self.epoch.cmp(&other.epoch) {
            Greater => self.clone(),
            Less => other.clone(),
            Equal => Self::new(self.epoch, self.totals.field_max(&other.totals)),
        }
    }

    /// `self ≤ other` in the lattice order.
    pub fn lattice_le(&self, other: &Self) -> bool {
        self.epoch < other.epoch
            || (self.epoch == other.epoch && self.totals.fields_le(&other.totals))
    }
}

pub type CounterEntry<T> = SwEntry<CounterValue<T>>;

/// What [`OwnerCounterMap::insert`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct InsertOutcome {
    pub changed: bool,
    /// The new entry replaced an older one from the same origin but is not
    /// ≥ it in the lattice order: the origin broke the honest-writer rule.
    pub regression: bool,
}

/// `(key, origin) -> latest entry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerCounterMap<K: Ord, T> {
    entries: BTreeMap<(K, DeviceId), CounterEntry<T>>,
}

impl<K: Ord, T> Default for OwnerCounterMap<K, T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<K: Ord + Clone, T: Totals> OwnerCounterMap<K, T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: K, origin: DeviceId, entry: CounterEntry<T>) -> InsertOutcome {
        match self.entries.get_mut(&(key.clone(), origin)) {
            Some(existing) if !entry.supersedes(existing) => InsertOutcome::default(),
            Some(existing) => {
                let regression = !existing.value.lattice_le(&entry.value);
                *existing = entry;
                InsertOutcome {
                    changed: true,
                    regression,
                }
            }
            None => {
                self.entries.insert((key, origin), entry);
                InsertOutcome {
                    changed: true,
                    regression: false,
                }
            }
        }
    }

    pub fn join(&mut self, other: &Self) -> bool {
        join_map(&mut self.entries, &other.entries)
    }

    pub fn dominates(&self, other: &Self) -> bool {
        map_dominates(&self.entries, &other.entries)
    }

    pub fn get(&self, key: &K, origin: &DeviceId) -> Option<&CounterEntry<T>> {
        self.entries.get(&(key.clone(), *origin))
    }

    /// The admitted origins' values for `key`, by origin. Views label every
    /// figure by device; they never collapse a missing device into zero.
    pub fn admitted<'a>(
        &'a self,
        key: &'a K,
        admit: &'a impl Admit,
    ) -> impl Iterator<Item = (&'a DeviceId, &'a CounterValue<T>)> {
        self.entries
            .range((key.clone(), DeviceId::MIN)..=(key.clone(), DeviceId::MAX))
            .filter(move |((_, o), e)| admit.admits(o, e.seq))
            .map(|((_, o), e)| (o, &e.value))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &DeviceId, &CounterEntry<T>)> {
        self.entries.iter().map(|((k, o), e)| (k, o, e))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::AdmitAll;
    use super::*;
    use crate::mesh::sim::rng::SplitMix64;

    fn totals(rng: &mut SplitMix64) -> UsageTotals {
        UsageTotals {
            requests: rng.below(50),
            priced_requests: rng.below(50),
            unpriced_requests: rng.below(5),
            unextracted_requests: rng.below(5),
            input_tokens: rng.below(10_000),
            output_tokens: rng.below(10_000),
            cached_input_tokens: rng.below(100),
            estimated_cost_micros: rng.below(1_000_000),
        }
    }

    fn random_value(rng: &mut SplitMix64) -> CounterValue<UsageTotals> {
        CounterValue::new(rng.below(3) as u32, totals(rng))
    }

    fn random_map(rng: &mut SplitMix64) -> OwnerCounterMap<u64, u64> {
        let mut m = OwnerCounterMap::new();
        for _ in 0..rng.below(8) {
            let (origin, key, seq) = (rng.below(4), rng.below(3), 1 + rng.below(6));
            let c = content(rng);
            // The value is a function of the item (origin, key, seq, content).
            let value = CounterValue::new((seq / 3) as u32, seq * 7 + c);
            m.insert(
                key,
                dev(origin),
                SwEntry::new(seq, hash_of(origin, key, seq, c), value),
            );
        }
        m
    }

    #[test]
    fn map_join_laws_10k() {
        check_laws(
            "owner_counter map",
            0xC0_17,
            random_map,
            |a, b| {
                let mut r = a.clone();
                r.join(b);
                r
            },
            |a, b| a.dominates(b),
        );
    }

    #[test]
    fn lattice_join_laws_10k() {
        check_laws(
            "owner_counter lattice",
            0xC0_18,
            random_value,
            |a, b| a.lattice_join(b),
            |a, b| b.lattice_le(a),
        );
    }

    #[test]
    fn epoch_bump_overrides_a_higher_valued_old_epoch() {
        let old = CounterValue::new(0, 1_000_u64);
        let bumped = CounterValue::new(1, 10_u64);
        assert_eq!(old.lattice_join(&bumped), bumped);
        assert_eq!(bumped.lattice_join(&old), bumped);
        assert!(old.lattice_le(&bumped));
        // In the replicated map the bump is simply the origin's later entry.
        let mut m = OwnerCounterMap::new();
        let o = dev(1);
        m.insert("k", o, SwEntry::new(1, hash_of(1, 0, 1, 0), old));
        let out = m.insert("k", o, SwEntry::new(2, hash_of(1, 0, 2, 0), bumped.clone()));
        assert!(out.changed && !out.regression);
        assert_eq!(m.get(&"k", &o).unwrap().value, bumped);
    }

    #[test]
    fn equal_epochs_take_the_field_wise_max() {
        let a = CounterValue::new(
            2,
            UsageTotals {
                requests: 5,
                input_tokens: 900,
                ..Default::default()
            },
        );
        let b = CounterValue::new(
            2,
            UsageTotals {
                requests: 7,
                input_tokens: 100,
                estimated_cost_micros: 3,
                ..Default::default()
            },
        );
        let j = a.lattice_join(&b);
        assert_eq!(j.epoch, 2);
        assert_eq!(j.totals.requests, 7);
        assert_eq!(j.totals.input_tokens, 900);
        assert_eq!(j.totals.estimated_cost_micros, 3);
    }

    #[test]
    fn honest_sequences_latest_equals_the_lattice_join_10k() {
        let seed = 0xC0_19;
        let mut rng = SplitMix64::new(seed);
        for case in 0..LAW_CASES {
            // An honest writer: totals only grow within an epoch; a decrease
            // bumps the epoch.
            let mut cur = CounterValue::new(0, totals(&mut rng));
            let mut lattice = cur.clone();
            let mut m = OwnerCounterMap::new();
            let o = dev(1);
            for seq in 1..=1 + rng.below(10) {
                if seq > 1 {
                    let next = if rng.chance(1, 5) {
                        CounterValue::new(cur.epoch + 1, totals(&mut rng))
                    } else {
                        let add = totals(&mut rng);
                        CounterValue::new(
                            cur.epoch,
                            UsageTotals {
                                requests: cur.totals.requests + add.requests,
                                priced_requests: cur.totals.priced_requests,
                                unpriced_requests: cur.totals.unpriced_requests + 1,
                                unextracted_requests: cur.totals.unextracted_requests,
                                input_tokens: cur.totals.input_tokens + add.input_tokens,
                                output_tokens: cur.totals.output_tokens,
                                cached_input_tokens: cur.totals.cached_input_tokens,
                                estimated_cost_micros: cur.totals.estimated_cost_micros
                                    + add.estimated_cost_micros,
                            },
                        )
                    };
                    assert!(cur.lattice_le(&next));
                    cur = next;
                    lattice = lattice.lattice_join(&cur);
                }
                let out = m.insert(
                    0u8,
                    o,
                    SwEntry::new(seq, hash_of(1, 0, seq, 0), cur.clone()),
                );
                assert!(!out.regression, "MESH_SIM_SEED={seed} case {case}");
            }
            assert_eq!(
                m.get(&0, &o).unwrap().value,
                lattice,
                "MESH_SIM_SEED={seed} case {case}"
            );
        }
    }

    #[test]
    fn a_dishonest_decrease_without_an_epoch_bump_is_reported() {
        let mut m = OwnerCounterMap::new();
        let o = dev(1);
        m.insert(
            0u8,
            o,
            SwEntry::new(1, hash_of(1, 0, 1, 0), CounterValue::new(0, 50_u64)),
        );
        let out = m.insert(
            0u8,
            o,
            SwEntry::new(2, hash_of(1, 0, 2, 0), CounterValue::new(0, 10_u64)),
        );
        assert!(out.changed && out.regression);
        assert_eq!(
            m.get(&0, &o).unwrap().value.totals,
            10,
            "seq order still decides"
        );
    }

    #[test]
    fn admitted_values_are_per_origin() {
        let mut m = OwnerCounterMap::new();
        m.insert(
            "k",
            dev(1),
            SwEntry::new(3, hash_of(1, 0, 3, 0), CounterValue::new(0, 5_u64)),
        );
        m.insert(
            "k",
            dev(2),
            SwEntry::new(9, hash_of(2, 0, 9, 0), CounterValue::new(0, 8_u64)),
        );
        m.insert(
            "j",
            dev(2),
            SwEntry::new(4, hash_of(2, 1, 4, 0), CounterValue::new(0, 1_u64)),
        );
        let all: Vec<_> = m
            .admitted(&"k", &AdmitAll)
            .map(|(o, v)| (*o, v.totals))
            .collect();
        assert_eq!(all, vec![(dev(1), 5), (dev(2), 8)]);
        let cut = |o: &DeviceId, seq: u64| *o != dev(2) || seq <= 5;
        let some: Vec<_> = m.admitted(&"k", &cut).map(|(o, _)| *o).collect();
        assert_eq!(some, vec![dev(1)]);
    }
}
