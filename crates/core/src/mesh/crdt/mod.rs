//! The mesh's conflict-free replicated data types (PROTOCOL.md §5).
//!
//! Every replicated value is built from one primitive: a **single-writer
//! entry** ([`SwEntry`]) — one origin's latest item for one `(kind, key)`.
//! Only the origin writes it, and a higher `seq` from the same origin
//! supersedes a lower one. That is exactly what the store keeps
//! (`UNIQUE(kind, item_key, origin)`) and what makes relaying only the latest
//! item per key safe. The four CRDTs differ only in how they combine the
//! per-origin entries:
//!
//! | CRDT | Combination across origins |
//! |---|---|
//! | [`lww_map`] | the admitted entry with the greatest `(hlc, origin)` |
//! | [`owner_counter`] | one value per admitted origin, labelled by device |
//! | [`roster`] | a two-phase set of devices with removal cutoffs and a genesis |
//! | [`bounded`] | Balegas-style rights arithmetic with clamped transfers |
//!
//! Every `join` here is commutative, associative and idempotent; the law
//! tests in each module check that over at least 10 000 seeded cases.

pub mod bounded;
pub mod lww_map;
pub mod owner_counter;
pub mod roster;

use super::dot::DeviceId;
use super::item::ItemHash;
use std::collections::BTreeMap;

/// One origin's latest item for one key.
///
/// `(seq, hash)` totally orders the entries of one origin: `seq` is the
/// origin's own order, and `hash` only breaks the tie two different items at
/// one dot would create — which is fork evidence, never honest behaviour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwEntry<T> {
    pub seq: u64,
    pub hash: ItemHash,
    pub value: T,
}

impl<T> SwEntry<T> {
    pub fn new(seq: u64, hash: ItemHash, value: T) -> Self {
        Self { seq, hash, value }
    }

    /// True when `self` replaces `other` in a join.
    pub fn supersedes(&self, other: &Self) -> bool {
        (self.seq, self.hash) > (other.seq, other.hash)
    }

    /// True when `self` is `other` or replaces it (the join order).
    pub fn at_least(&self, other: &Self) -> bool {
        (self.seq, self.hash) >= (other.seq, other.hash)
    }
}

/// Decides whether an origin's entry at `seq` counts in views. The roster is
/// the real implementation ([`roster::Roster`]); tests use closures.
pub trait Admit {
    fn admits(&self, origin: &DeviceId, seq: u64) -> bool;
}

impl<F: Fn(&DeviceId, u64) -> bool> Admit for F {
    fn admits(&self, origin: &DeviceId, seq: u64) -> bool {
        self(origin, seq)
    }
}

/// Admits everything (for tests and for "raw" reads).
#[derive(Debug, Clone, Copy, Default)]
pub struct AdmitAll;

impl Admit for AdmitAll {
    fn admits(&self, _origin: &DeviceId, _seq: u64) -> bool {
        true
    }
}

/// Join one entry into a map of single-writer entries. Returns whether the
/// map changed.
pub(crate) fn join_entry<K: Ord, T: Clone>(
    map: &mut BTreeMap<K, SwEntry<T>>,
    key: K,
    entry: SwEntry<T>,
) -> bool {
    match map.get_mut(&key) {
        Some(existing) if !entry.supersedes(existing) => false,
        Some(existing) => {
            *existing = entry;
            true
        }
        None => {
            map.insert(key, entry);
            true
        }
    }
}

/// Join every entry of `other` into `map`.
pub(crate) fn join_map<K: Ord + Clone, T: Clone>(
    map: &mut BTreeMap<K, SwEntry<T>>,
    other: &BTreeMap<K, SwEntry<T>>,
) -> bool {
    let mut changed = false;
    for (k, e) in other {
        changed |= join_entry(map, k.clone(), e.clone());
    }
    changed
}

/// `a ≥ b` in the join order: every entry of `b` is in `a` or superseded there.
pub(crate) fn map_dominates<K: Ord, T>(
    a: &BTreeMap<K, SwEntry<T>>,
    b: &BTreeMap<K, SwEntry<T>>,
) -> bool {
    b.iter()
        .all(|(k, e)| a.get(k).is_some_and(|mine| mine.at_least(e)))
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Random-state generation shared by the law tests.
    use super::*;
    use crate::mesh::sim::rng::SplitMix64;

    pub const LAW_CASES: u64 = 10_000;

    pub fn dev(n: u64) -> DeviceId {
        DeviceId::from_bytes([n as u8; 16])
    }

    /// A hash that is a function of `(origin, key, seq, content)`, so two
    /// entries with the same dot and the same content are identical items,
    /// and different content at one dot looks like a fork.
    pub fn hash_of(origin: u64, key: u64, seq: u64, content: u64) -> ItemHash {
        let mut h = blake3::Hasher::new();
        for n in [origin, key, seq, content] {
            h.update(&n.to_le_bytes());
        }
        ItemHash(*h.finalize().as_bytes())
    }

    /// Mostly honest content (one per dot) with an occasional fork.
    pub fn content(rng: &mut SplitMix64) -> u64 {
        if rng.chance(1, 20) {
            1 + rng.below(2)
        } else {
            0
        }
    }

    /// Run the three semilattice laws and monotonicity over `cases` random
    /// triples, printing the seed on failure.
    pub fn check_laws<S: Clone + PartialEq + std::fmt::Debug>(
        name: &str,
        seed: u64,
        mut gen: impl FnMut(&mut SplitMix64) -> S,
        join: impl Fn(&S, &S) -> S,
        dominates: impl Fn(&S, &S) -> bool,
    ) {
        let mut rng = SplitMix64::new(seed);
        for case in 0..LAW_CASES {
            let (a, b, c) = (gen(&mut rng), gen(&mut rng), gen(&mut rng));
            let ab = join(&a, &b);
            assert_eq!(
                ab,
                join(&b, &a),
                "{name}: commutativity, MESH_SIM_SEED={seed} case {case}"
            );
            assert_eq!(
                join(&ab, &c),
                join(&a, &join(&b, &c)),
                "{name}: associativity, MESH_SIM_SEED={seed} case {case}"
            );
            assert_eq!(
                join(&a, &a),
                a,
                "{name}: idempotence, MESH_SIM_SEED={seed} case {case}"
            );
            assert!(
                dominates(&ab, &a) && dominates(&ab, &b),
                "{name}: monotonicity, MESH_SIM_SEED={seed} case {case}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    #[test]
    fn higher_seq_supersedes_and_hash_breaks_a_dot_tie() {
        let low = SwEntry::new(1, hash_of(1, 1, 1, 0), "a");
        let high = SwEntry::new(2, hash_of(1, 1, 2, 0), "b");
        assert!(high.supersedes(&low));
        assert!(!low.supersedes(&high));
        assert!(!high.supersedes(&high) && high.at_least(&high));
        let fork_a = SwEntry::new(3, hash_of(1, 1, 3, 1), "x");
        let fork_b = SwEntry::new(3, hash_of(1, 1, 3, 2), "y");
        assert!(fork_a.supersedes(&fork_b) != fork_b.supersedes(&fork_a));
    }

    #[test]
    fn join_entry_reports_change() {
        let mut m = BTreeMap::new();
        assert!(join_entry(
            &mut m,
            1,
            SwEntry::new(1, hash_of(1, 1, 1, 0), 10)
        ));
        assert!(!join_entry(
            &mut m,
            1,
            SwEntry::new(1, hash_of(1, 1, 1, 0), 10)
        ));
        assert!(join_entry(
            &mut m,
            1,
            SwEntry::new(2, hash_of(1, 1, 2, 0), 5)
        ));
        assert_eq!(
            m[&1].value, 5,
            "the later seq wins even with a smaller value"
        );
        assert!(!join_entry(
            &mut m,
            1,
            SwEntry::new(1, hash_of(1, 1, 1, 0), 10)
        ));
    }
}
