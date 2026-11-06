//! SplitMix64: a tiny, dependency-free, seedable PRNG.
//!
//! Used only by tests and the simulator, where determinism matters more than
//! statistical quality: the same seed must replay the same run on every
//! platform. It is never used for anything security-relevant — keys, ids and
//! tokens come from the operating system RNG.

/// Steele, Lea and Flood's SplitMix64 (the JDK `SplittableRandom` mixer).
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (0 when `n == 0`). Lemire's multiply-shift; the tiny
    /// bias is irrelevant for test generation.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        ((u128::from(self.next_u64()) * u128::from(n)) >> 64) as u64
    }

    /// A value in `lo..=hi`.
    pub fn range_inclusive(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(lo <= hi);
        lo + self.below(hi - lo + 1)
    }

    /// True with probability `num / den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// A uniformly chosen element (None for an empty slice).
    pub fn choose<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            items.get(self.below(items.len() as u64) as usize)
        }
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let b = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }

    /// Fisher-Yates shuffle.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }

    /// An independent generator derived from this one (for per-node streams).
    pub fn fork(&mut self) -> Self {
        Self::new(self.next_u64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_reference_sequence() {
        // Reference values for seed 1234567 from the published SplitMix64
        // algorithm (Vigna's splitmix64.c).
        let mut r = SplitMix64::new(1_234_567);
        assert_eq!(r.next_u64(), 6_457_827_717_110_365_317);
        assert_eq!(r.next_u64(), 3_203_168_211_198_807_973);
        assert_eq!(r.next_u64(), 9_817_491_932_198_370_423);
    }

    #[test]
    fn same_seed_same_stream() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..1_000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn helpers_stay_in_range() {
        let mut r = SplitMix64::new(7);
        for _ in 0..10_000 {
            assert!(r.below(10) < 10);
            let v = r.range_inclusive(5, 8);
            assert!((5..=8).contains(&v));
        }
        assert_eq!(r.below(0), 0);
        assert!(r.choose::<u8>(&[]).is_none());
        let mut buf = [0u8; 13];
        r.fill_bytes(&mut buf);
        let mut v: Vec<u32> = (0..50).collect();
        r.shuffle(&mut v);
        v.sort_unstable();
        assert_eq!(v, (0..50).collect::<Vec<_>>());
    }
}
