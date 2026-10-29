//! The bounded counter behind spend caps (PROTOCOL.md §5.5).
//!
//! After Balegas et al., "Extending eventually consistent cloud databases
//! for enforcing numeric invariants" (SRDS 2015). One instance per
//! `(cap_id, month)`.
//!
//! **State.** `R[from][to]` — `from`'s cumulative rights to `to` (a device or
//! the [`Recipient::Burn`] sink), written only by `from`; `R[i][i]` is a mint.
//! `U[i]` — `i`'s cumulative spend, written only by `i`. Both are
//! single-writer entries joined like every other replicated value.
//!
//! **View.** For each device `i`, over admitted entries:
//! * `minted(i) = R[i][i]`, `raw_in(i) = Σ_{j≠i} R[j][i]`;
//! * `i`'s outgoing amounts are honoured from a budget of
//!   `minted(i) + raw_in(i)`, **burn first, then recipients in ascending
//!   device-id order**, each up to what is left — anything beyond is
//!   *clamped* (ignored);
//! * `avail(i) = minted(i) + received(i) − sent(i) − burned(i) − U[i]`,
//!   where received/sent/burned are the honoured amounts.
//!
//! The clamp means no single device's rows can make rights appear in another
//! device's view beyond what that device itself minted or was sent. It is
//! one hop, deliberately: a transitive clamp is a fixpoint whose iteration
//! count hostile values control. An honest device never over-sends (it
//! checks `avail` in its own view, which only grows), so for honest devices
//! nothing is ever clamped and the clamp is invisible. `U` is not part of
//! the budget: a device that overshoots its spend goes negative itself
//! instead of retroactively taking rights back from devices it already paid.
//!
//! **Invariant** (honest operation, any partitions and merge order):
//! `Σ U ≤ Σ minted − Σ burned`, and every `avail ≥ 0`.

use super::{join_map, map_dominates, Admit, SwEntry};
use crate::mesh::dot::DeviceId;
use crate::mesh::error::MeshError;
pub use crate::mesh::kinds::Recipient;
use std::collections::BTreeMap;

/// One device's position in the view. Amounts are micro-USD.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceRights {
    pub minted: u128,
    pub received: u128,
    pub sent: u128,
    pub burned: u128,
    /// Outgoing amounts the view ignored because they exceeded the budget.
    pub clamped: u128,
    pub used: u128,
    pub avail: i128,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoundedView {
    pub devices: BTreeMap<DeviceId, DeviceRights>,
    pub total_minted: u128,
    pub total_burned: u128,
    pub total_used: u128,
}

impl BoundedView {
    pub fn avail(&self, device: &DeviceId) -> i128 {
        self.devices.get(device).map_or(0, |d| d.avail)
    }

    /// `Σ minted − Σ burned`: the rights in existence.
    pub fn supply(&self) -> i128 {
        to_i128(self.total_minted) - to_i128(self.total_burned)
    }
}

fn to_i128(x: u128) -> i128 {
    i128::try_from(x).unwrap_or(i128::MAX)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoundedCounter {
    rights: BTreeMap<(DeviceId, Recipient), SwEntry<u64>>,
    used: BTreeMap<DeviceId, SwEntry<u64>>,
}

impl BoundedCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply `from`'s cumulative amount to `to` (a `cap.rights` item).
    pub fn apply_rights(&mut self, from: DeviceId, to: Recipient, entry: SwEntry<u64>) -> bool {
        super::join_entry(&mut self.rights, (from, to), entry)
    }

    /// Apply `device`'s cumulative spend (a `cap.used` item).
    pub fn apply_used(&mut self, device: DeviceId, entry: SwEntry<u64>) -> bool {
        super::join_entry(&mut self.used, device, entry)
    }

    pub fn join(&mut self, other: &Self) -> bool {
        let a = join_map(&mut self.rights, &other.rights);
        let b = join_map(&mut self.used, &other.used);
        a || b
    }

    pub fn dominates(&self, other: &Self) -> bool {
        map_dominates(&self.rights, &other.rights) && map_dominates(&self.used, &other.used)
    }

    /// `from`'s own latest cumulative amount to `to` (unfiltered: it is the
    /// writer's own counter).
    pub fn own_rights(&self, from: &DeviceId, to: &Recipient) -> u64 {
        self.rights.get(&(*from, *to)).map_or(0, |e| e.value)
    }

    pub fn own_used(&self, device: &DeviceId) -> u64 {
        self.used.get(device).map_or(0, |e| e.value)
    }

    /// Every device that wrote an entry (admitted or not).
    pub fn writers(&self) -> std::collections::BTreeSet<DeviceId> {
        self.rights
            .keys()
            .map(|(from, _)| *from)
            .chain(self.used.keys().copied())
            .collect()
    }

    /// The clamped view over admitted entries.
    pub fn view(&self, admit: &impl Admit) -> BoundedView {
        let mut devs: BTreeMap<DeviceId, DeviceRights> = BTreeMap::new();
        let mut raw_in: BTreeMap<DeviceId, u128> = BTreeMap::new();
        let admitted = || {
            self.rights
                .iter()
                .filter(|((from, _), e)| admit.admits(from, e.seq))
        };

        for ((from, to), e) in admitted() {
            devs.entry(*from).or_default();
            match to {
                Recipient::Device(d) if d == from => {
                    devs.get_mut(from).expect("inserted above").minted += u128::from(e.value);
                }
                Recipient::Device(d) => {
                    devs.entry(*d).or_default();
                    *raw_in.entry(*d).or_default() += u128::from(e.value);
                }
                Recipient::Burn => {}
            }
        }

        // Honour each device's outgoing amounts from its budget, in key order
        // (burn first, then recipients ascending).
        let mut budget: Option<(DeviceId, u128)> = None;
        let mut moves: Vec<(DeviceId, Recipient, u128, u128)> = Vec::new();
        for ((from, to), e) in admitted() {
            if *to == Recipient::Device(*from) {
                continue;
            }
            if budget.is_none_or(|(d, _)| d != *from) {
                let start = devs[from].minted + raw_in.get(from).copied().unwrap_or(0);
                budget = Some((*from, start));
            }
            let (_, remaining) = budget.as_mut().expect("set above");
            let amount = u128::from(e.value);
            let honoured = amount.min(*remaining);
            *remaining -= honoured;
            moves.push((*from, *to, honoured, amount - honoured));
        }
        for (from, to, honoured, clamped) in moves {
            let f = devs.get_mut(&from).expect("every origin has a row");
            f.clamped += clamped;
            match to {
                Recipient::Burn => f.burned += honoured,
                Recipient::Device(d) => {
                    f.sent += honoured;
                    devs.get_mut(&d)
                        .expect("every recipient has a row")
                        .received += honoured;
                }
            }
        }

        for (d, e) in &self.used {
            if admit.admits(d, e.seq) {
                devs.entry(*d).or_default().used = u128::from(e.value);
            }
        }

        let mut view = BoundedView::default();
        for r in devs.values_mut() {
            r.avail = to_i128(r.minted) + to_i128(r.received)
                - to_i128(r.sent)
                - to_i128(r.burned)
                - to_i128(r.used);
            view.total_minted += r.minted;
            view.total_burned += r.burned;
            view.total_used += r.used;
        }
        view.devices = devs;
        view
    }

    pub fn avail(&self, device: &DeviceId, admit: &impl Admit) -> i128 {
        self.view(admit).avail(device)
    }

    pub fn can_spend(&self, device: &DeviceId, amount: u64, admit: &impl Admit) -> bool {
        i128::from(amount) <= self.avail(device, admit)
    }

    fn require(&self, device: &DeviceId, amount: u64, admit: &impl Admit) -> Result<(), MeshError> {
        let available = self.avail(device, admit);
        if i128::from(amount) <= available {
            Ok(())
        } else {
            Err(MeshError::InsufficientRights {
                available,
                requested: amount,
            })
        }
    }

    fn bump(current: u64, amount: u64) -> Result<u64, MeshError> {
        current
            .checked_add(amount)
            .ok_or(MeshError::InvalidOperation("cumulative amount overflows"))
    }

    /// The new cumulative `U[device]` after spending `amount`, if `amount`
    /// fits in `avail(device)`. The gateway's overshoot rule (MESH-SI-9) is a
    /// separate, explicit path; this is the strict check.
    pub fn prepare_spend(
        &self,
        device: &DeviceId,
        amount: u64,
        admit: &impl Admit,
    ) -> Result<u64, MeshError> {
        self.require(device, amount, admit)?;
        Self::bump(self.own_used(device), amount)
    }

    /// The new cumulative `R[from][to]` after giving `to` `amount`.
    pub fn prepare_transfer(
        &self,
        from: &DeviceId,
        to: &DeviceId,
        amount: u64,
        admit: &impl Admit,
    ) -> Result<u64, MeshError> {
        if from == to {
            return Err(MeshError::InvalidOperation(
                "a transfer to yourself is a mint, not a transfer",
            ));
        }
        self.require(from, amount, admit)?;
        Self::bump(self.own_rights(from, &Recipient::Device(*to)), amount)
    }

    /// The new cumulative `R[from][burn]` after burning `amount`.
    pub fn prepare_burn(
        &self,
        from: &DeviceId,
        amount: u64,
        admit: &impl Admit,
    ) -> Result<u64, MeshError> {
        self.require(from, amount, admit)?;
        Self::bump(self.own_rights(from, &Recipient::Burn), amount)
    }

    /// The new cumulative `R[device][device]` after minting `amount`. Who may
    /// mint (the cap owner, or a labelled local override) is policy above
    /// this layer.
    pub fn prepare_mint(&self, device: &DeviceId, amount: u64) -> Result<u64, MeshError> {
        Self::bump(self.own_rights(device, &Recipient::Device(*device)), amount)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::AdmitAll;
    use super::*;
    use crate::mesh::sim::rng::SplitMix64;

    /// One device writing its own entries with its own seqs.
    struct Writer {
        idx: u64,
        id: DeviceId,
        next_seq: u64,
    }

    impl Writer {
        fn new(idx: u64) -> Self {
            Self {
                idx,
                id: dev(idx),
                next_seq: 0,
            }
        }

        fn entry(&mut self, key: u64, value: u64) -> SwEntry<u64> {
            self.next_seq += 1;
            SwEntry::new(
                self.next_seq,
                hash_of(self.idx, key, self.next_seq, value),
                value,
            )
        }

        fn key_of(to: &Recipient) -> u64 {
            match to {
                Recipient::Burn => 999,
                Recipient::Device(d) => u64::from(d.as_bytes()[0]),
            }
        }

        fn rights(&mut self, c: &mut BoundedCounter, to: Recipient, cumulative: u64) {
            let e = self.entry(Self::key_of(&to), cumulative);
            c.apply_rights(self.id, to, e);
        }

        fn used(&mut self, c: &mut BoundedCounter, cumulative: u64) {
            let e = self.entry(1000, cumulative);
            c.apply_used(self.id, e);
        }

        fn mint(&mut self, c: &mut BoundedCounter, x: u64) {
            let v = c.prepare_mint(&self.id, x).unwrap();
            self.rights(c, Recipient::Device(self.id), v);
        }

        fn transfer(
            &mut self,
            c: &mut BoundedCounter,
            to: DeviceId,
            x: u64,
        ) -> Result<(), MeshError> {
            let v = c.prepare_transfer(&self.id, &to, x, &AdmitAll)?;
            self.rights(c, Recipient::Device(to), v);
            Ok(())
        }

        fn burn(&mut self, c: &mut BoundedCounter, x: u64) -> Result<(), MeshError> {
            let v = c.prepare_burn(&self.id, x, &AdmitAll)?;
            self.rights(c, Recipient::Burn, v);
            Ok(())
        }

        fn spend(&mut self, c: &mut BoundedCounter, x: u64) -> Result<(), MeshError> {
            let v = c.prepare_spend(&self.id, x, &AdmitAll)?;
            self.used(c, v);
            Ok(())
        }
    }

    #[test]
    fn avail_arithmetic() {
        let mut c = BoundedCounter::new();
        let (mut o, mut a, b) = (Writer::new(1), Writer::new(2), Writer::new(3));
        o.mint(&mut c, 1_000);
        o.transfer(&mut c, a.id, 300).unwrap();
        o.transfer(&mut c, b.id, 200).unwrap();
        a.transfer(&mut c, b.id, 50).unwrap();
        a.spend(&mut c, 100).unwrap();
        o.burn(&mut c, 100).unwrap();
        let v = c.view(&AdmitAll);
        assert_eq!(v.avail(&o.id), 1_000 - 300 - 200 - 100);
        assert_eq!(v.avail(&a.id), 300 - 50 - 100);
        assert_eq!(v.avail(&b.id), 200 + 50);
        assert_eq!(v.total_minted, 1_000);
        assert_eq!(v.total_burned, 100);
        assert_eq!(v.total_used, 100);
        let sum: i128 = v.devices.values().map(|d| d.avail).sum();
        assert_eq!(
            sum,
            v.supply() - 100,
            "rights are conserved: Σ avail = supply − used"
        );
    }

    #[test]
    fn spend_beyond_avail_is_refused() {
        let mut c = BoundedCounter::new();
        let mut o = Writer::new(1);
        o.mint(&mut c, 100);
        o.spend(&mut c, 60).unwrap();
        assert_eq!(
            o.spend(&mut c, 41),
            Err(MeshError::InsufficientRights {
                available: 40,
                requested: 41
            })
        );
        assert!(c.can_spend(&o.id, 40, &AdmitAll));
        o.spend(&mut c, 40).unwrap();
        assert!(!c.can_spend(&o.id, 1, &AdmitAll));
        assert!(o.transfer(&mut c, dev(5), 1).is_err());
        assert!(o.burn(&mut c, 1).is_err());
    }

    #[test]
    fn a_transfer_conserves_the_total_and_a_burn_reduces_it() {
        let mut c = BoundedCounter::new();
        let (mut o, a) = (Writer::new(1), Writer::new(2));
        o.mint(&mut c, 500);
        let before: i128 = c.view(&AdmitAll).devices.values().map(|d| d.avail).sum();
        o.transfer(&mut c, a.id, 123).unwrap();
        let v = c.view(&AdmitAll);
        let after: i128 = v.devices.values().map(|d| d.avail).sum();
        assert_eq!(before, after);
        assert_eq!(v.avail(&a.id), 123);
        o.burn(&mut c, 77).unwrap();
        let v = c.view(&AdmitAll);
        let burned: i128 = v.devices.values().map(|d| d.avail).sum();
        assert_eq!(burned, after - 77);
        assert_eq!(v.supply(), 500 - 77);
    }

    #[test]
    fn transfers_to_yourself_are_refused() {
        let mut c = BoundedCounter::new();
        let mut o = Writer::new(1);
        o.mint(&mut c, 10);
        assert!(matches!(
            o.transfer(&mut c, o.id, 1),
            Err(MeshError::InvalidOperation(_))
        ));
    }

    #[test]
    fn the_clamped_view_ignores_a_forged_over_transfer() {
        let mut c = BoundedCounter::new();
        let (mut o, mut m, victim) = (Writer::new(1), Writer::new(2), Writer::new(3));
        o.mint(&mut c, 100);
        o.transfer(&mut c, m.id, 10).unwrap();
        // m writes a row claiming it gave the victim far more than it has.
        m.rights(&mut c, Recipient::Device(victim.id), 1_000_000);
        let v = c.view(&AdmitAll);
        assert_eq!(
            v.avail(&victim.id),
            10,
            "only what m actually held reaches the victim"
        );
        assert_eq!(v.devices[&m.id].clamped, 1_000_000 - 10);
        assert_eq!(v.avail(&m.id), 0);
        let sum: i128 = v.devices.values().map(|d| d.avail).sum();
        assert_eq!(sum, v.supply(), "nothing was created");
    }

    #[test]
    fn a_device_with_nothing_creates_nothing() {
        let mut c = BoundedCounter::new();
        let (mut m, victim) = (Writer::new(2), Writer::new(3));
        m.rights(&mut c, Recipient::Device(victim.id), 5_000);
        m.rights(&mut c, Recipient::Burn, 7);
        let v = c.view(&AdmitAll);
        assert_eq!(v.avail(&victim.id), 0);
        assert_eq!(v.total_burned, 0);
        assert_eq!(v.supply(), 0);
    }

    #[test]
    fn clamping_honours_burn_first_then_ascending_recipients() {
        let mut c = BoundedCounter::new();
        let mut m = Writer::new(5);
        m.mint(&mut c, 100);
        // Over-send 3 ways: burn 40, to dev(9) 50, to dev(2) 50. Budget 100.
        m.rights(&mut c, Recipient::Device(dev(9)), 50);
        m.rights(&mut c, Recipient::Burn, 40);
        m.rights(&mut c, Recipient::Device(dev(2)), 50);
        let v = c.view(&AdmitAll);
        assert_eq!(v.devices[&m.id].burned, 40);
        assert_eq!(v.avail(&dev(2)), 50);
        assert_eq!(v.avail(&dev(9)), 10);
        assert_eq!(v.devices[&m.id].clamped, 40);
    }

    #[test]
    fn an_overshoot_stays_with_the_overspender() {
        // i paid j, then its gateway's last in-flight request overshot. The
        // debt is i's; j's rights are not clawed back.
        let mut c = BoundedCounter::new();
        let (mut i, j) = (Writer::new(1), Writer::new(2));
        i.mint(&mut c, 100);
        i.transfer(&mut c, j.id, 100).unwrap();
        i.used(&mut c, 5); // overshoot by one request
        let v = c.view(&AdmitAll);
        assert_eq!(v.avail(&j.id), 100);
        assert_eq!(v.avail(&i.id), -5);
        assert_eq!(v.devices[&i.id].clamped, 0);
    }

    #[test]
    fn cycles_create_nothing() {
        let mut c = BoundedCounter::new();
        let (mut a, mut b) = (Writer::new(1), Writer::new(2));
        a.mint(&mut c, 1);
        // Forged huge cycle between two devices.
        a.rights(&mut c, Recipient::Device(b.id), 1 << 60);
        b.rights(&mut c, Recipient::Device(a.id), 1 << 60);
        let v = c.view(&AdmitAll);
        let sum: i128 = v.devices.values().map(|d| d.avail).sum();
        assert_eq!(sum, 1, "the only right in existence is the one minted");
    }

    #[test]
    fn a_non_admitted_writers_rows_do_not_count() {
        let mut c = BoundedCounter::new();
        let (mut o, mut r) = (Writer::new(1), Writer::new(2));
        o.mint(&mut c, 100);
        o.transfer(&mut c, r.id, 40).unwrap(); // o seq 2
        r.mint(&mut c, 1_000); // r seq 1: an override mint
        let cut = |d: &DeviceId, seq: u64| *d != r.id || seq == 0;
        let v = c.view(&cut);
        assert_eq!(
            v.avail(&r.id),
            40,
            "r's own rows are excluded, rows to it are not"
        );
        assert_eq!(v.total_minted, 100);
    }

    #[test]
    fn protocol_md_worked_example() {
        // PROTOCOL.md §5.5: ids order A < B < O; O is the owner.
        let (mut a, b, mut o) = (Writer::new(1), Writer::new(2), Writer::new(3));
        let mut c = BoundedCounter::new();
        o.rights(&mut c, Recipient::Device(o.id), 100);
        o.rights(&mut c, Recipient::Burn, 10);
        o.rights(&mut c, Recipient::Device(a.id), 30);
        o.rights(&mut c, Recipient::Device(b.id), 20);
        a.rights(&mut c, Recipient::Device(b.id), 10);
        a.used(&mut c, 5);
        let mut b = b;
        b.used(&mut c, 25);
        let v = c.view(&AdmitAll);
        assert_eq!(
            (v.avail(&o.id), v.avail(&a.id), v.avail(&b.id)),
            (40, 15, 5)
        );
        assert_eq!(v.supply(), 90);
        assert_eq!(v.total_used, 30);

        // A device M with no rights: everything clamped.
        let mut m = Writer::new(4);
        let mut forged = c.clone();
        m.rights(&mut forged, Recipient::Device(a.id), 1_000_000);
        assert_eq!(forged.view(&AdmitAll).avail(&a.id), 15);
        // M sent 10 by O: A receives 10, 999 990 clamped.
        let mut m = Writer::new(4);
        let mut funded = c.clone();
        o.rights(&mut funded, Recipient::Device(m.id), 10);
        m.rights(&mut funded, Recipient::Device(a.id), 1_000_000);
        let fv = funded.view(&AdmitAll);
        assert_eq!(fv.avail(&a.id), 25);
        assert_eq!(fv.devices[&m.id].clamped, 999_990);
        // Budget 100: burn 40, A 50 (A < Z), Z 10, clamped 40.
        let mut m = Writer::new(4);
        let z = dev(9);
        let mut order = BoundedCounter::new();
        m.rights(&mut order, Recipient::Device(m.id), 100);
        m.rights(&mut order, Recipient::Burn, 40);
        m.rights(&mut order, Recipient::Device(z), 50);
        m.rights(&mut order, Recipient::Device(a.id), 50);
        let ov = order.view(&AdmitAll);
        assert_eq!(ov.devices[&m.id].burned, 40);
        assert_eq!(ov.avail(&a.id), 50);
        assert_eq!(ov.avail(&z), 10);
        assert_eq!(ov.devices[&m.id].clamped, 40);
    }

    fn random_counter(rng: &mut SplitMix64) -> BoundedCounter {
        let mut c = BoundedCounter::new();
        for _ in 0..rng.below(10) {
            let (from, seq, cn) = (rng.below(4), 1 + rng.below(6), content(rng));
            let value = seq * 13 + cn;
            if rng.chance(1, 3) {
                c.apply_used(
                    dev(from),
                    SwEntry::new(seq, hash_of(from, 1000, seq, cn), value),
                );
            } else {
                let to = match rng.below(5) {
                    4 => Recipient::Burn,
                    n => Recipient::Device(dev(n)),
                };
                c.apply_rights(
                    dev(from),
                    to,
                    SwEntry::new(seq, hash_of(from, Writer::key_of(&to), seq, cn), value),
                );
            }
        }
        c
    }

    #[test]
    fn join_laws_10k() {
        check_laws(
            "bounded",
            0xB0_0D,
            random_counter,
            |a, b| {
                let mut r = a.clone();
                r.join(b);
                r
            },
            |a, b| a.dominates(b),
        );
    }

    /// Honest devices each with their own replica, acting on their own view
    /// and merging in random order (partitions and stale views included).
    #[test]
    fn cap_safety_holds_for_10k_honest_operation_sequences() {
        let seed = 0xCA_FE;
        let mut rng = SplitMix64::new(seed);
        for case in 0..10_000 {
            let n = 2 + rng.below(4) as usize;
            let mut writers: Vec<Writer> = (0..n as u64).map(|i| Writer::new(i + 1)).collect();
            let mut replicas: Vec<BoundedCounter> = vec![BoundedCounter::new(); n];
            for _ in 0..rng.range_inclusive(5, 40) {
                let d = rng.below(n as u64) as usize;
                let x = 1 + rng.below(500);
                match rng.below(10) {
                    0 if d == 0 => writers[d].mint(&mut replicas[d], x),
                    0 if rng.chance(1, 4) => writers[d].mint(&mut replicas[d], x), // override
                    1 | 2 => {
                        let to = writers[rng.below(n as u64) as usize].id;
                        if to != writers[d].id {
                            let _ = writers[d].transfer(&mut replicas[d], to, x);
                        }
                    }
                    3 => {
                        let _ = writers[d].burn(&mut replicas[d], x);
                    }
                    4..=6 => {
                        let _ = writers[d].spend(&mut replicas[d], x);
                    }
                    _ => {
                        let e = rng.below(n as u64) as usize;
                        let other = replicas[e].clone();
                        replicas[d].join(&other);
                    }
                }
            }
            let mut all = BoundedCounter::new();
            for r in &replicas {
                all.join(r);
            }
            for (who, state) in replicas.iter().chain(std::iter::once(&all)).enumerate() {
                let v = state.view(&AdmitAll);
                assert!(
                    to_i128(v.total_used) <= v.supply(),
                    "MESH_SIM_SEED={seed} case {case} replica {who}: Σ U > Σ minted − Σ burned"
                );
                for (d, r) in &v.devices {
                    assert!(
                        r.avail >= 0,
                        "MESH_SIM_SEED={seed} case {case}: {d} negative"
                    );
                    assert_eq!(
                        r.clamped, 0,
                        "MESH_SIM_SEED={seed} case {case}: honest rows clamped"
                    );
                }
            }
        }
    }
}
