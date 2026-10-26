//! Hybrid logical clock (PROTOCOL.md §4, DESIGN §D7).
//!
//! An [`Hlc`] is one `u64`: the high 48 bits are physical milliseconds since
//! the Unix epoch and the low 16 bits a logical counter. Timestamps compare
//! as plain integers; every tie-break additionally uses the origin device id.
//!
//! The HLC orders last-writer-wins registers only. Counters, rights and used
//! totals never consult it.

use super::clock::Clock;
use serde::{Deserialize, Serialize};
use std::fmt;

/// How far ahead of the local physical clock an observed timestamp may pull
/// the local HLC. A remote timestamp beyond this is still accepted (its item
/// is stored and counted) but flagged, and it never drags the local clock
/// further than the bound.
pub const MAX_DRIFT_MS: u64 = 60_000;

/// Number of bits of the logical counter.
pub const LOGICAL_BITS: u32 = 16;
/// Largest logical counter value.
pub const MAX_LOGICAL: u16 = u16::MAX;
/// Largest representable physical time (2^48 - 1 ms, about the year 10889).
pub const MAX_PHYSICAL: u64 = (1 << 48) - 1;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hlc(u64);

impl Hlc {
    pub const ZERO: Hlc = Hlc(0);
    pub const MAX: Hlc = Hlc(u64::MAX);

    /// Build from parts. A physical time beyond 48 bits is clamped to
    /// [`MAX_PHYSICAL`].
    pub fn new(physical_ms: u64, logical: u16) -> Self {
        Hlc((physical_ms.min(MAX_PHYSICAL) << LOGICAL_BITS) | u64::from(logical))
    }

    pub const fn from_raw(raw: u64) -> Self {
        Hlc(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn physical(self) -> u64 {
        self.0 >> LOGICAL_BITS
    }

    pub const fn logical(self) -> u16 {
        // Truncation keeps exactly the low 16 bits.
        (self.0 & 0xFFFF) as u16
    }

    /// The next timestamp: logical + 1, carrying into the physical part when
    /// the logical counter overflows. Saturates at [`Hlc::MAX`].
    pub const fn successor(self) -> Self {
        Hlc(self.0.saturating_add(1))
    }
}

impl fmt::Debug for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hlc({}.{})", self.physical(), self.logical())
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.physical(), self.logical())
    }
}

/// What [`HlcClock::observe`] learned about a remote timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// The remote timestamp was beyond `now + max_drift` and was clamped.
    /// Higher layers record this per origin (`mesh_meta.clock_skew/<origin>`).
    pub clamped: bool,
    /// How far the remote physical time is ahead of the local physical time,
    /// in milliseconds (0 when it is not ahead).
    pub skew_ms: u64,
}

/// One device's hybrid logical clock.
#[derive(Debug)]
pub struct HlcClock<C: Clock> {
    clock: C,
    last: Hlc,
    max_drift_ms: u64,
}

impl<C: Clock> HlcClock<C> {
    pub fn new(clock: C) -> Self {
        Self::with_max_drift(clock, MAX_DRIFT_MS)
    }

    pub fn with_max_drift(clock: C, max_drift_ms: u64) -> Self {
        Self {
            clock,
            last: Hlc::ZERO,
            max_drift_ms,
        }
    }

    pub fn clock(&self) -> &C {
        &self.clock
    }

    pub fn max_drift_ms(&self) -> u64 {
        self.max_drift_ms
    }

    /// The highest timestamp this clock has issued or observed. The store
    /// persists it as `mesh_meta.hlc_high_water`.
    pub fn last(&self) -> Hlc {
        self.last
    }

    /// Restore the persisted high-water mark after a restart. Never moves the
    /// clock backwards.
    pub fn restore(&mut self, high_water: Hlc) {
        self.last = self.last.max(high_water);
    }

    fn physical_now(&self) -> u64 {
        self.clock.now_ms().min(MAX_PHYSICAL)
    }

    /// `Hlc(now + max_drift, 0)`: the largest timestamp an observation may
    /// move this clock to.
    pub fn drift_bound(&self) -> Hlc {
        Hlc::new(self.physical_now().saturating_add(self.max_drift_ms), 0)
    }

    /// A fresh timestamp, strictly greater than every timestamp this clock
    /// returned or observed before, even when the physical clock stalls or
    /// steps backwards.
    pub fn now(&mut self) -> Hlc {
        let next = Hlc::new(self.physical_now(), 0).max(self.last.successor());
        self.last = next;
        next
    }

    /// Fold a remote timestamp into the clock:
    /// `last = max(last, min(remote, drift_bound))`.
    ///
    /// The remote item is accepted whatever its timestamp; this only decides
    /// how far it may move the local clock, and reports skew.
    pub fn observe(&mut self, remote: Hlc) -> Observation {
        let now = self.physical_now();
        let bound = Hlc::new(now.saturating_add(self.max_drift_ms), 0);
        self.last = self.last.max(remote.min(bound));
        Observation {
            clamped: remote > bound,
            skew_ms: remote.physical().saturating_sub(now),
        }
    }

    /// The timestamp for a local last-writer-wins write:
    /// `max(now(), current_winner + 1)`.
    ///
    /// A user's edit therefore always beats the value they were looking at,
    /// even when a clock-skewed device wrote that value far in the future.
    /// Deliberately does not move `last` past the drift bound: only this one
    /// write is lifted, the clock itself stays honest.
    pub fn local_write_ts(&mut self, current_winner: Option<Hlc>) -> Hlc {
        let ts = self.now();
        match current_winner {
            Some(w) if w >= ts => w.successor(),
            _ => ts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::clock::ManualClock;
    use std::sync::Arc;

    fn clock_at(ms: u64) -> (Arc<ManualClock>, HlcClock<Arc<ManualClock>>) {
        let c = Arc::new(ManualClock::new(ms));
        (c.clone(), HlcClock::new(c))
    }

    #[test]
    fn encoding_splits_48_16_and_orders_as_integers() {
        let h = Hlc::new(1_700_000_000_000, 7);
        assert_eq!(h.physical(), 1_700_000_000_000);
        assert_eq!(h.logical(), 7);
        assert!(Hlc::new(5, MAX_LOGICAL) < Hlc::new(6, 0));
        assert_eq!(Hlc::new(5, MAX_LOGICAL).successor(), Hlc::new(6, 0));
        assert_eq!(Hlc::new(u64::MAX, 0).physical(), MAX_PHYSICAL);
        assert_eq!(Hlc::MAX.successor(), Hlc::MAX, "successor saturates");
    }

    #[test]
    fn now_is_monotonic_when_the_physical_clock_stalls() {
        let (_c, mut hlc) = clock_at(1_000);
        let a = hlc.now();
        let b = hlc.now();
        let d = hlc.now();
        assert_eq!(a, Hlc::new(1_000, 0));
        assert_eq!(b, Hlc::new(1_000, 1));
        assert_eq!(d, Hlc::new(1_000, 2));
    }

    #[test]
    fn now_is_monotonic_when_the_physical_clock_steps_backwards() {
        let (c, mut hlc) = clock_at(10_000);
        let a = hlc.now();
        c.set(2_000);
        let b = hlc.now();
        assert!(b > a);
        assert_eq!(b, Hlc::new(10_000, 1));
        c.set(20_000);
        assert_eq!(hlc.now(), Hlc::new(20_000, 0));
    }

    #[test]
    fn logical_overflow_bumps_physical_by_one_ms() {
        let (_c, mut hlc) = clock_at(500);
        hlc.restore(Hlc::new(500, MAX_LOGICAL - 1));
        assert_eq!(hlc.now(), Hlc::new(500, MAX_LOGICAL));
        assert_eq!(hlc.now(), Hlc::new(501, 0));
        assert_eq!(hlc.now(), Hlc::new(501, 1));
    }

    #[test]
    fn observe_within_drift_moves_the_clock_without_a_flag() {
        let (_c, mut hlc) = clock_at(100_000);
        let remote = Hlc::new(100_000 + 30_000, 4);
        let obs = hlc.observe(remote);
        assert!(!obs.clamped);
        assert_eq!(obs.skew_ms, 30_000);
        assert_eq!(hlc.last(), remote);
        assert!(hlc.now() > remote);
    }

    #[test]
    fn observe_clamps_at_now_plus_max_drift_and_reports_skew() {
        let (_c, mut hlc) = clock_at(100_000);
        let far = Hlc::new(100_000 + 10 * 60_000, 9);
        let obs = hlc.observe(far);
        assert!(obs.clamped);
        assert_eq!(obs.skew_ms, 10 * 60_000);
        assert_eq!(hlc.last(), Hlc::new(100_000 + MAX_DRIFT_MS, 0));
        // The clock never exceeds its own now + drift because of an observation.
        assert!(hlc.now().physical() <= 100_000 + MAX_DRIFT_MS);
    }

    #[test]
    fn observe_never_moves_the_clock_backwards() {
        let (_c, mut hlc) = clock_at(100_000);
        let before = hlc.now();
        let obs = hlc.observe(Hlc::new(1, 0));
        assert!(!obs.clamped);
        assert_eq!(obs.skew_ms, 0);
        assert_eq!(hlc.last(), before);
    }

    #[test]
    fn local_write_ts_beats_a_far_future_winner_without_dragging_the_clock() {
        let (_c, mut hlc) = clock_at(100_000);
        let winner = Hlc::new(100_000 + 3_600_000, 2);
        let ts = hlc.local_write_ts(Some(winner));
        assert!(ts > winner);
        assert_eq!(ts, winner.successor());
        assert!(
            hlc.last().physical() <= 100_000 + MAX_DRIFT_MS,
            "the write is lifted, the clock is not"
        );
        // A second edit while looking at our own lifted write beats it too.
        let ts2 = hlc.local_write_ts(Some(ts));
        assert!(ts2 > ts);
    }

    #[test]
    fn local_write_ts_with_a_past_winner_is_just_now() {
        let (_c, mut hlc) = clock_at(100_000);
        let ts = hlc.local_write_ts(Some(Hlc::new(50, 0)));
        assert_eq!(ts, Hlc::new(100_000, 0));
        let ts2 = hlc.local_write_ts(None);
        assert_eq!(ts2, Hlc::new(100_000, 1));
    }

    #[test]
    fn restore_never_goes_backwards() {
        let (_c, mut hlc) = clock_at(1_000);
        hlc.restore(Hlc::new(9_000, 3));
        assert_eq!(hlc.last(), Hlc::new(9_000, 3));
        hlc.restore(Hlc::new(2_000, 0));
        assert_eq!(hlc.last(), Hlc::new(9_000, 3));
        assert_eq!(hlc.now(), Hlc::new(9_000, 4));
    }

    #[test]
    fn restart_from_high_water_continues_above_it() {
        let (c, mut hlc) = clock_at(50_000);
        for _ in 0..10 {
            hlc.now();
        }
        let high_water = hlc.last();
        // A "restart": a fresh clock whose physical time went backwards.
        c.set(1_000);
        let mut restarted = HlcClock::new(c.clone());
        restarted.restore(high_water);
        assert!(restarted.now() > high_water);
    }

    #[test]
    fn randomized_monotonicity_under_a_wandering_clock() {
        use crate::mesh::sim::rng::SplitMix64;
        let seed = 0x48_4C_43;
        let mut rng = SplitMix64::new(seed);
        let (c, mut hlc) = clock_at(1_000_000);
        let mut prev = Hlc::ZERO;
        for step in 0..20_000 {
            match rng.below(4) {
                0 => c.advance(rng.below(1_000)),
                1 => c.set(c.now_ms().saturating_sub(rng.below(5_000))),
                2 => {
                    // An observation never moves the clock past the drift
                    // bound. (After the physical clock steps back, `last` may
                    // already sit above it; it must not climb further.)
                    let before = hlc.last();
                    let remote = Hlc::new(c.now_ms() + rng.below(200_000), 0);
                    hlc.observe(remote);
                    assert!(
                        hlc.last() <= before.max(hlc.drift_bound()),
                        "seed {seed} step {step}"
                    );
                }
                _ => {}
            }
            let t = hlc.now();
            assert!(t > prev, "seed {seed} step {step}: {t:?} <= {prev:?}");
            prev = t;
        }
    }
}
