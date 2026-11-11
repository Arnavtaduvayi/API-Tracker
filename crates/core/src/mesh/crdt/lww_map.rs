//! Last-writer-wins registers and maps (PROTOCOL.md §5.2).
//!
//! A register keeps one entry per origin — that origin's latest write — and
//! its value is the **admitted** entry with the greatest `(hlc, origin)`.
//! Keeping one entry per origin is what lets a device removal take effect
//! without history: the removed origin's entry simply stops counting, and
//! the next-greatest admitted entry becomes the value.

use super::{join_entry, join_map, map_dominates, Admit, SwEntry};
use crate::mesh::dot::DeviceId;
use crate::mesh::hlc::Hlc;
use std::collections::BTreeMap;

/// A written value and the HLC it was written at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LwwValue<V> {
    pub hlc: Hlc,
    pub value: V,
}

pub type LwwEntry<V> = SwEntry<LwwValue<V>>;

/// One key's register: `origin -> latest entry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LwwRegister<V> {
    entries: BTreeMap<DeviceId, LwwEntry<V>>,
}

impl<V> Default for LwwRegister<V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<V: Clone> LwwRegister<V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Join one origin's entry. Returns whether the register changed.
    pub fn insert(&mut self, origin: DeviceId, entry: LwwEntry<V>) -> bool {
        join_entry(&mut self.entries, origin, entry)
    }

    pub fn join(&mut self, other: &Self) -> bool {
        join_map(&mut self.entries, &other.entries)
    }

    pub fn dominates(&self, other: &Self) -> bool {
        map_dominates(&self.entries, &other.entries)
    }

    /// The winning entry: greatest `(hlc, origin)` among admitted entries.
    pub fn winner(&self, admit: &impl Admit) -> Option<(&DeviceId, &LwwEntry<V>)> {
        self.entries
            .iter()
            .filter(|(o, e)| admit.admits(o, e.seq))
            .max_by_key(|(o, e)| (e.value.hlc, **o))
    }

    pub fn value(&self, admit: &impl Admit) -> Option<&V> {
        self.winner(admit).map(|(_, e)| &e.value.value)
    }

    /// The winning timestamp, for [`crate::mesh::hlc::HlcClock::local_write_ts`].
    pub fn winning_hlc(&self, admit: &impl Admit) -> Option<Hlc> {
        self.winner(admit).map(|(_, e)| e.value.hlc)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&DeviceId, &LwwEntry<V>)> {
        self.entries.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A map of registers, one per key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LwwMap<K: Ord, V> {
    regs: BTreeMap<K, LwwRegister<V>>,
}

impl<K: Ord, V> Default for LwwMap<K, V> {
    fn default() -> Self {
        Self {
            regs: BTreeMap::new(),
        }
    }
}

impl<K: Ord + Clone, V: Clone> LwwMap<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: K, origin: DeviceId, entry: LwwEntry<V>) -> bool {
        self.regs.entry(key).or_default().insert(origin, entry)
    }

    pub fn join(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (k, reg) in &other.regs {
            changed |= self.regs.entry(k.clone()).or_default().join(reg);
        }
        changed
    }

    pub fn dominates(&self, other: &Self) -> bool {
        other
            .regs
            .iter()
            .all(|(k, r)| self.regs.get(k).is_some_and(|mine| mine.dominates(r)))
    }

    pub fn register(&self, key: &K) -> Option<&LwwRegister<V>> {
        self.regs.get(key)
    }

    pub fn value(&self, key: &K, admit: &impl Admit) -> Option<&V> {
        self.regs.get(key).and_then(|r| r.value(admit))
    }

    /// Every key with an admitted value, and that value.
    pub fn values<'a>(&'a self, admit: &'a impl Admit) -> impl Iterator<Item = (&'a K, &'a V)> {
        self.regs
            .iter()
            .filter_map(move |(k, r)| r.value(admit).map(|v| (k, v)))
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.regs.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::AdmitAll;
    use super::*;
    use crate::mesh::sim::rng::SplitMix64;

    fn entry(origin: u64, key: u64, seq: u64, hlc: u64, content: u64) -> LwwEntry<u64> {
        SwEntry::new(
            seq,
            hash_of(origin, key, seq, content),
            LwwValue {
                hlc: Hlc::from_raw(hlc ^ content),
                value: seq * 100 + content,
            },
        )
    }

    fn random_map(rng: &mut SplitMix64) -> LwwMap<u64, u64> {
        let mut m = LwwMap::new();
        for _ in 0..rng.below(8) {
            let origin = rng.below(4);
            let key = rng.below(3);
            let seq = 1 + rng.below(6);
            // HLC grows with seq for one origin, like an honest writer, and
            // collides across origins to exercise the origin tie-break. It is
            // a function of the item, like everything an item carries.
            let hlc = seq * 10 + (origin + key) % 3;
            m.insert(key, dev(origin), entry(origin, key, seq, hlc, content(rng)));
        }
        m
    }

    #[test]
    fn join_laws_10k() {
        check_laws(
            "lww_map",
            0x1A11,
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
    fn values_commute_under_admission_too() {
        // Views read values through an admission rule; equal states must give
        // equal values whatever the join order.
        let mut rng = SplitMix64::new(0x1A12);
        let admit = |o: &DeviceId, seq: u64| *o != dev(2) || seq <= 3;
        for case in 0..LAW_CASES {
            let (a, b) = (random_map(&mut rng), random_map(&mut rng));
            let mut ab = a.clone();
            ab.join(&b);
            let mut ba = b.clone();
            ba.join(&a);
            for k in 0..3 {
                assert_eq!(ab.value(&k, &admit), ba.value(&k, &admit), "case {case}");
            }
        }
    }

    #[test]
    fn value_is_the_max_over_admitted_origins() {
        let mut r = LwwRegister::new();
        r.insert(dev(1), entry(1, 0, 1, 100, 0));
        r.insert(dev(2), entry(2, 0, 1, 300, 0));
        r.insert(dev(3), entry(3, 0, 1, 200, 0));
        assert_eq!(r.winner(&AdmitAll).unwrap().0, &dev(2));
        assert_eq!(r.winning_hlc(&AdmitAll), Some(Hlc::from_raw(300)));
    }

    #[test]
    fn excluding_a_removed_origin_above_its_cutoff_falls_back_to_the_next_winner() {
        let mut r = LwwRegister::new();
        r.insert(dev(1), entry(1, 0, 4, 100, 0));
        r.insert(dev(2), entry(2, 0, 9, 300, 0));
        assert_eq!(r.winner(&AdmitAll).unwrap().0, &dev(2));
        // dev(2) removed with cutoff 5: its seq-9 entry no longer counts.
        let cutoff = |o: &DeviceId, seq: u64| *o != dev(2) || seq <= 5;
        assert_eq!(r.winner(&cutoff).unwrap().0, &dev(1));
        // ...but an entry at or below the cutoff still does.
        let generous = |o: &DeviceId, seq: u64| *o != dev(2) || seq <= 9;
        assert_eq!(r.winner(&generous).unwrap().0, &dev(2));
        // Nobody admitted: no value.
        assert!(r.value(&|_: &DeviceId, _| false).is_none());
    }

    #[test]
    fn protocol_md_worked_example() {
        // PROTOCOL.md §5.2: A < B < C.
        let (a, b, c) = (dev(1), dev(2), dev(3));
        let e = |o: u64, seq: u64, hlc: u64, v: &'static str| {
            SwEntry::new(
                seq,
                hash_of(o, 0, seq, 0),
                LwwValue {
                    hlc: Hlc::from_raw(hlc),
                    value: v,
                },
            )
        };
        let mut r = LwwRegister::new();
        r.insert(a, e(1, 3, 100, "x"));
        r.insert(b, e(2, 7, 150, "y"));
        r.insert(c, e(3, 2, 150, "z"));
        assert_eq!(r.value(&AdmitAll), Some(&"z"));
        let mut other = LwwRegister::new();
        other.insert(a, e(1, 5, 90, "w"));
        r.join(&other);
        assert_eq!(
            r.entries().find(|(o, _)| **o == a).unwrap().1.value.value,
            "w"
        );
        assert_eq!(r.value(&AdmitAll), Some(&"z"));
        let c_removed = |o: &DeviceId, seq: u64| *o != c || seq <= 1;
        assert_eq!(r.value(&c_removed), Some(&"y"));
        let both = |o: &DeviceId, seq: u64| (*o != c || seq <= 1) && (*o != b || seq <= 7);
        assert_eq!(r.value(&both), Some(&"y"));
    }

    #[test]
    fn equal_hlc_ties_break_by_origin() {
        let mut r = LwwRegister::new();
        r.insert(dev(7), entry(7, 0, 1, 500, 0));
        r.insert(dev(3), entry(3, 0, 1, 500, 0));
        assert_eq!(
            r.winner(&AdmitAll).unwrap().0,
            &dev(7),
            "greater device id wins a tie"
        );
    }

    #[test]
    fn an_origins_later_write_replaces_its_earlier_one() {
        let mut r = LwwRegister::new();
        r.insert(dev(1), entry(1, 0, 1, 900, 0));
        // A later seq from the same origin with a *smaller* HLC still replaces
        // the earlier entry: within an origin, seq is the order.
        r.insert(dev(1), entry(1, 0, 2, 100, 0));
        assert_eq!(r.entries().count(), 1);
        assert_eq!(r.value(&AdmitAll), Some(&200));
    }
}
