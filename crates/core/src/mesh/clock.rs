//! The mesh's injectable wall clock.
//!
//! Core's [`crate::clock`] is a set of free functions over the system time.
//! The mesh needs time as a *dependency* instead, so the replication state
//! machine stays pure and the simulator can give every node its own skewed,
//! manually advanced clock. Only [`SystemClock`] reads the real time.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of physical time in milliseconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// The operating system's wall clock. A time before 1970 reads as 0.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to. Tests and the simulator share one
/// through an `Arc` and set or advance it explicitly; it may also be moved
/// backwards, which is how a stepped-back system clock is modelled.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(now_ms: u64) -> Self {
        Self(AtomicU64::new(now_ms))
    }

    pub fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }

    pub fn advance(&self, ms: u64) {
        let _ = self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |t| {
                Some(t.saturating_add(ms))
            });
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_sets_advances_and_saturates() {
        let c = ManualClock::new(1_000);
        assert_eq!(c.now_ms(), 1_000);
        c.advance(500);
        assert_eq!(c.now_ms(), 1_500);
        c.set(10);
        assert_eq!(c.now_ms(), 10, "a manual clock may step backwards");
        c.set(u64::MAX - 1);
        c.advance(10);
        assert_eq!(c.now_ms(), u64::MAX);
    }

    #[test]
    fn shared_manual_clock_is_seen_through_arc_and_ref() {
        let c = Arc::new(ManualClock::new(5));
        let by_arc: &dyn Clock = &c;
        c.advance(5);
        assert_eq!(by_arc.now_ms(), 10);
        assert_eq!(Clock::now_ms(&&*c), 10, "a plain reference is a clock too");
    }

    #[test]
    fn system_clock_is_after_2020() {
        assert!(SystemClock.now_ms() > 1_577_836_800_000);
    }
}
