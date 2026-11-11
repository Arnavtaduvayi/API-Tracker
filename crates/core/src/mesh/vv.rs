//! Version vectors: `origin -> highest seq known`.
//!
//! An entry of 0 means "nothing from that origin" and is never stored, so two
//! vectors that cover the same items are always `==`.

use super::dot::{DeviceId, Dot};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize)]
#[serde(transparent)]
pub struct VersionVector(BTreeMap<DeviceId, u64>);

impl VersionVector {
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest seq known from `origin` (0 when none).
    pub fn get(&self, origin: &DeviceId) -> u64 {
        self.0.get(origin).copied().unwrap_or(0)
    }

    /// True when the vector covers `dot`.
    pub fn contains(&self, dot: &Dot) -> bool {
        dot.seq != 0 && dot.seq <= self.get(&dot.origin)
    }

    /// Raise `origin`'s entry to at least `seq`. Never lowers it.
    pub fn advance_to(&mut self, origin: DeviceId, seq: u64) {
        if seq == 0 {
            return;
        }
        let e = self.0.entry(origin).or_insert(0);
        *e = (*e).max(seq);
    }

    /// Pointwise maximum.
    pub fn join(&mut self, other: &VersionVector) {
        for (o, s) in &other.0 {
            self.advance_to(*o, *s);
        }
    }

    /// True when `self` covers everything `other` covers.
    pub fn dominates(&self, other: &VersionVector) -> bool {
        other.0.iter().all(|(o, s)| self.get(o) >= *s)
    }

    /// The ranges `self` holds that `other` lacks, as
    /// `(origin, from_exclusive, to_inclusive)`, ordered by origin. A sender
    /// computes `own.missing_from(&peer)` to decide what to stream.
    pub fn missing_from(&self, other: &VersionVector) -> Vec<(DeviceId, u64, u64)> {
        self.0
            .iter()
            .filter_map(|(o, s)| {
                let theirs = other.get(o);
                (*s > theirs).then_some((*o, theirs, *s))
            })
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, &u64)> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for VersionVector {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut m = BTreeMap::<DeviceId, u64>::deserialize(d)?;
        m.retain(|_, s| *s != 0);
        Ok(Self(m))
    }
}

impl FromIterator<(DeviceId, u64)> for VersionVector {
    fn from_iter<I: IntoIterator<Item = (DeviceId, u64)>>(iter: I) -> Self {
        let mut vv = Self::new();
        for (o, s) in iter {
            vv.advance_to(o, s);
        }
        vv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::sim::rng::SplitMix64;

    fn dev(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    fn random_vv(rng: &mut SplitMix64) -> VersionVector {
        (0..rng.below(5))
            .map(|_| (dev(rng.below(4) as u8), rng.below(6)))
            .collect()
    }

    #[test]
    fn get_advance_and_zero_normalisation() {
        let mut v = VersionVector::new();
        assert_eq!(v.get(&dev(1)), 0);
        v.advance_to(dev(1), 0);
        assert!(v.is_empty(), "a zero entry is never stored");
        v.advance_to(dev(1), 5);
        v.advance_to(dev(1), 3);
        assert_eq!(v.get(&dev(1)), 5, "advance never lowers");
        assert!(v.contains(&Dot::new(dev(1), 5)));
        assert!(!v.contains(&Dot::new(dev(1), 6)));
        assert!(!v.contains(&Dot::new(dev(1), 0)));
    }

    #[test]
    fn missing_from_lists_exactly_what_the_peer_lacks() {
        let a: VersionVector = [(dev(1), 5), (dev(2), 3), (dev(3), 1)]
            .into_iter()
            .collect();
        let b: VersionVector = [(dev(1), 2), (dev(2), 7)].into_iter().collect();
        assert_eq!(a.missing_from(&b), vec![(dev(1), 2, 5), (dev(3), 0, 1)]);
        assert_eq!(b.missing_from(&a), vec![(dev(2), 3, 7)]);
        assert!(a.missing_from(&a).is_empty());
    }

    #[test]
    fn dominance_and_join() {
        let a: VersionVector = [(dev(1), 5), (dev(2), 3)].into_iter().collect();
        let b: VersionVector = [(dev(1), 2), (dev(2), 7)].into_iter().collect();
        assert!(!a.dominates(&b) && !b.dominates(&a));
        let mut j = a.clone();
        j.join(&b);
        assert!(j.dominates(&a) && j.dominates(&b));
        assert_eq!(j.get(&dev(1)), 5);
        assert_eq!(j.get(&dev(2)), 7);
        assert!(VersionVector::new().missing_from(&a).is_empty());
        assert!(a.dominates(&VersionVector::new()));
    }

    #[test]
    fn serde_round_trip_drops_zero_entries() {
        let a: VersionVector = [(dev(1), 5)].into_iter().collect();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<VersionVector>(&json).unwrap(), a);
        let with_zero = format!("{{\"{}\":5,\"{}\":0}}", dev(1), dev(2));
        assert_eq!(
            serde_json::from_str::<VersionVector>(&with_zero).unwrap(),
            a
        );
    }

    #[test]
    fn join_laws_hold_over_10k_random_cases() {
        let seed = 0x5656;
        let mut rng = SplitMix64::new(seed);
        for case in 0..10_000 {
            let (a, b, c) = (
                random_vv(&mut rng),
                random_vv(&mut rng),
                random_vv(&mut rng),
            );
            let j = |x: &VersionVector, y: &VersionVector| {
                let mut r = x.clone();
                r.join(y);
                r
            };
            assert_eq!(j(&a, &b), j(&b, &a), "MESH_SIM_SEED={seed} case {case}");
            assert_eq!(
                j(&j(&a, &b), &c),
                j(&a, &j(&b, &c)),
                "seed {seed} case {case}"
            );
            assert_eq!(j(&a, &a), a, "seed {seed} case {case}");
            assert!(j(&a, &b).dominates(&a), "seed {seed} case {case}");
            // missing_from is exactly the difference the join closes.
            let mut patched = b.clone();
            for (o, _, to) in a.missing_from(&b) {
                patched.advance_to(o, to);
            }
            assert_eq!(patched, j(&a, &b), "seed {seed} case {case}");
        }
    }
}
