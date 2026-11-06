//! Which addresses a node dials in a round, and when (DESIGN §D13).
//!
//! The rows live in `mesh_peers` (`core::mesh::peers`); this module decides
//! eligibility. After `n` consecutive failures an address waits
//! `backoff_ms(n)` (5 s doubling to 15 min) spread by ±20% jitter from an
//! injected seed, so tests are deterministic and devices that failed
//! together do not retry together. A success makes it eligible every round.
//! After a restart, the wait is recomputed from the stored failure count and
//! `last_attempt_at` (without jitter).
//!
//! Addresses come from three sources: manual, gossip (the listen addresses
//! other **active** devices publish in `device.info`) and mDNS. One device
//! can be reached at several addresses; a round exchanges with it once,
//! trying its addresses (last success first) until one answers.

use api_tracker_core::mesh::peers::{backoff_ms, rfc3339_to_ms, PeerRow};
use api_tracker_core::mesh::sqlite_store::SqliteStore;
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::DeviceId;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A small deterministic generator for jitter (SplitMix64). Not for
/// anything secret.
#[derive(Clone, Debug)]
pub struct Jitter(u64);

impl Jitter {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// A seed from the operating system's generator.
    pub fn from_os() -> Self {
        let b = api_tracker_core::crypto::random_bytes(8);
        let mut s = [0u8; 8];
        s.copy_from_slice(&b[..8]);
        Self(u64::from_le_bytes(s))
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `base` spread uniformly over ±20%.
    pub fn spread(&mut self, base: u64) -> u64 {
        let permille = 800 + self.next_u64() % 401;
        u64::try_from(u128::from(base) * u128::from(permille) / 1000).unwrap_or(u64::MAX)
    }
}

/// Per-address retry times, in the node's clock (ms).
#[derive(Debug)]
pub struct Scheduler {
    next: HashMap<String, u64>,
    jitter: Jitter,
}

impl Scheduler {
    pub fn new(jitter: Jitter) -> Self {
        Self {
            next: HashMap::new(),
            jitter,
        }
    }

    /// Whether `row` may be dialled at `now` (scheduled rounds; a forced
    /// round ignores backoff).
    pub fn due(&mut self, row: &PeerRow, now: u64) -> bool {
        if row.failures == 0 {
            return true;
        }
        let next = *self.next.entry(row.addr.clone()).or_insert_with(|| {
            row.last_attempt_at
                .as_deref()
                .map_or(0, rfc3339_to_ms)
                .saturating_add(backoff_ms(row.failures))
        });
        now >= next
    }

    /// The time `addr` is next due, if it is backing off.
    pub fn next_due(&self, addr: &str) -> Option<u64> {
        self.next.get(addr).copied()
    }

    /// Record the outcome of one dial: `failures` is the row's count after it.
    pub fn record(&mut self, addr: &str, failures: u32, now: u64) {
        if failures == 0 {
            self.next.remove(addr);
        } else {
            let wait = self.jitter.spread(backoff_ms(failures));
            self.next.insert(addr.to_owned(), now.saturating_add(wait));
        }
    }

    /// Forget addresses no longer in the table.
    pub fn retain(&mut self, rows: &[PeerRow]) {
        let keep: BTreeSet<&str> = rows.iter().map(|r| r.addr.as_str()).collect();
        self.next.retain(|a, _| keep.contains(a.as_str()));
    }
}

/// The listen addresses other active devices publish, minus this device's
/// own (`exclude`).
pub fn gossip_addrs(store: &SqliteStore, exclude: &[String]) -> BTreeSet<String> {
    let state = store.state();
    let me = store.self_id();
    let mut out = BTreeSet::new();
    for (d, _) in state.roster.known() {
        if *d == me || !state.roster.is_active(d) {
            continue;
        }
        if let Some(info) = state.device_info.value(d, &state.roster) {
            out.extend(
                info.listen_addrs
                    .iter()
                    .filter(|a| !exclude.contains(a))
                    .cloned(),
            );
        }
    }
    out
}

/// One device to exchange with in a round, and the addresses to try.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub device: Option<DeviceId>,
    pub addrs: Vec<String>,
}

/// Group dialable rows into targets: one per known device (its addresses,
/// most recently successful first), one per address of a device not yet
/// seen. Rows of devices that are not active (removed, forked) or of this
/// device are skipped: a handshake with them would be refused.
pub fn targets(rows: &[PeerRow], store: &SqliteStore) -> Vec<Target> {
    let roster = &store.state().roster;
    let me = store.self_id();
    let mut by_device: BTreeMap<DeviceId, Vec<&PeerRow>> = BTreeMap::new();
    let mut out = Vec::new();
    for r in rows {
        match r.device_id {
            Some(d) if d == me || !roster.is_active(&d) => {}
            Some(d) => by_device.entry(d).or_default().push(r),
            None => out.push(Target {
                device: None,
                addrs: vec![r.addr.clone()],
            }),
        }
    }
    for (d, mut rs) in by_device {
        rs.sort_by(|a, b| b.last_success_at.cmp(&a.last_success_at));
        out.insert(
            0,
            Target {
                device: Some(d),
                addrs: rs.into_iter().map(|r| r.addr.clone()).collect(),
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_tracker_core::mesh::peers::PeerSource;

    fn row(addr: &str, failures: u32, last: Option<&str>) -> PeerRow {
        PeerRow {
            addr: addr.into(),
            device_id: None,
            source: PeerSource::Manual,
            last_attempt_at: last.map(str::to_owned),
            last_success_at: None,
            failures,
            unreachable_since: None,
            last_error: None,
        }
    }

    #[test]
    fn jitter_stays_within_twenty_percent_and_is_reproducible() {
        let mut a = Jitter::new(42);
        let mut b = Jitter::new(42);
        for _ in 0..10_000 {
            let x = a.spread(10_000);
            assert!((8_000..=12_000).contains(&x), "{x}");
            assert_eq!(x, b.spread(10_000));
        }
        let mut c = Jitter::new(43);
        assert!((0..100).any(|_| Jitter::new(42).spread(10_000) != c.spread(10_000)));
    }

    #[test]
    fn a_failing_address_waits_longer_after_each_failure_and_a_success_clears_it() {
        let mut s = Scheduler::new(Jitter::new(7));
        let r = row("10.0.0.1:1", 0, None);
        assert!(s.due(&r, 0));
        let mut now = 1_000_000;
        let mut last_wait = 0;
        for failures in 1..=10u32 {
            s.record(&r.addr, failures, now);
            let next = s.next_due(&r.addr).unwrap();
            let wait = next - now;
            let base = backoff_ms(failures);
            assert!(
                wait >= base * 8 / 10 && wait <= base * 12 / 10,
                "{failures}: {wait}"
            );
            if failures <= 8 {
                assert!(wait > last_wait * 8 / 10 * 10 / 12, "{failures}");
            }
            let failing = row(&r.addr, failures, None);
            assert!(!s.due(&failing, next - 1));
            assert!(s.due(&failing, next));
            last_wait = wait;
            now = next;
        }
        assert!(last_wait <= 15 * 60 * 1000 * 12 / 10);
        s.record(&r.addr, 0, now);
        assert!(s.next_due(&r.addr).is_none());
    }

    #[test]
    fn after_a_restart_the_wait_is_rebuilt_from_the_stored_attempt() {
        let mut s = Scheduler::new(Jitter::new(1));
        let at = api_tracker_core::mesh::peers::ms_rfc3339(5_000_000);
        let r = row("10.0.0.2:1", 3, Some(&at));
        assert!(!s.due(&r, 5_000_000 + 19_999));
        assert!(s.due(&r, 5_000_000 + 20_000));
    }
}
