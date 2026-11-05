//! Materialized views (PROTOCOL.md §5.6): the CRDT containers every stored
//! item feeds, maintained incrementally on commit.
//!
//! A [`State`] holds one container per kind. The store calls
//! [`State::apply`] for each item that becomes the latest for its
//! `(kind, key, origin)`; [`rebuild`] recomputes the same state from scratch
//! from the stored items, and the two must always be equal (simulator
//! invariant 3). Derived values — LWW winners, bounded-counter views,
//! admission — are computed when read, through the roster.
//!
//! Pure: no I/O, no clock.

use super::codec::ItemBody;
use super::crdt::bounded::BoundedCounter;
use super::crdt::lww_map::{LwwMap, LwwValue};
use super::crdt::owner_counter::{CounterValue, OwnerCounterMap};
use super::crdt::roster::{AddRecord, Roster};
use super::crdt::{Admit, SwEntry};
use super::dot::{CapId, CredentialRef, DeviceId, MeshProjectId, ShareId};
use super::error::MeshError;
use super::hlc::Hlc;
use super::item::{ItemHash, SignedItem};
use super::kinds::{Month, TypedItem, UsageKey, UsageTotals};
use super::store::GenesisInfo;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfoValue {
    pub name: String,
    pub listen_addrs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectValue {
    pub name: String,
    pub archived: bool,
    pub merged_into: Option<MeshProjectId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapDefValue {
    pub mesh_project_id: MeshProjectId,
    pub owner_device: DeviceId,
    pub created_hlc: Hlc,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SealedValue {
    pub share_id: ShareId,
    pub mesh_project_id: MeshProjectId,
    pub credential_name: String,
    pub provider: String,
    pub value_version: u64,
    pub sealed: Vec<u8>,
}

impl std::fmt::Debug for SealedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedValue")
            .field("share_id", &self.share_id)
            .field("sealed_len", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

/// What applying one item did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// An owner counter's successor was not ≥ its predecessor (PROTOCOL §5.3).
    pub regression: bool,
}

/// The replicated state, as CRDT containers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub genesis: GenesisInfo,
    pub roster: Roster,
    pub device_info: LwwMap<DeviceId, DeviceInfoValue>,
    pub settings: LwwMap<String, Value>,
    pub projects: LwwMap<MeshProjectId, ProjectValue>,
    pub usage: OwnerCounterMap<UsageKey, UsageTotals>,
    pub cap_defs: LwwMap<CapId, CapDefValue>,
    pub cap_targets: LwwMap<(CapId, Month), u64>,
    pub cap_counters: BTreeMap<(CapId, Month), BoundedCounter>,
    pub shares_sealed: LwwMap<(CredentialRef, DeviceId), SealedValue>,
    pub shares_revoked: LwwMap<(CredentialRef, DeviceId), ShareId>,
}

impl State {
    pub fn new(genesis: GenesisInfo) -> Self {
        Self {
            genesis,
            roster: Roster::new(genesis.genesis),
            device_info: LwwMap::new(),
            settings: LwwMap::new(),
            projects: LwwMap::new(),
            usage: OwnerCounterMap::new(),
            cap_defs: LwwMap::new(),
            cap_targets: LwwMap::new(),
            cap_counters: BTreeMap::new(),
            shares_sealed: LwwMap::new(),
            shares_revoked: LwwMap::new(),
        }
    }

    /// Fold one item into the containers. The store calls this for every
    /// item that becomes the latest for its `(kind, key, origin)`; folding an
    /// older item is harmless (the containers keep the greater `(seq, hash)`).
    pub fn apply(&mut self, body: &ItemBody, hash: ItemHash, typed: &TypedItem) -> ApplyOutcome {
        let (o, seq, hlc) = (body.origin, body.seq, body.hlc);
        fn entry<V>(seq: u64, hash: ItemHash, hlc: Hlc, value: V) -> SwEntry<LwwValue<V>> {
            SwEntry::new(seq, hash, LwwValue { hlc, value })
        }
        let mut out = ApplyOutcome::default();
        match typed {
            TypedItem::RosterAdd(a) => {
                self.roster
                    .apply_add(o, a.device, SwEntry::new(seq, hash, AddRecord::from(a)));
            }
            TypedItem::RosterRemove(r) => {
                self.roster
                    .apply_remove(o, r.device, SwEntry::new(seq, hash, r.cutoff_seq));
            }
            TypedItem::ForkReport(f) => {
                self.roster
                    .apply_fork_report(o, f.device, SwEntry::new(seq, hash, f.seq));
            }
            TypedItem::DeviceInfo(d) => {
                self.device_info.insert(
                    d.device,
                    o,
                    entry(
                        seq,
                        hash,
                        hlc,
                        DeviceInfoValue {
                            name: d.name.clone(),
                            listen_addrs: d.listen_addrs.clone(),
                        },
                    ),
                );
            }
            TypedItem::MeshSetting(m) => {
                self.settings
                    .insert(m.name.clone(), o, entry(seq, hash, hlc, m.value.clone()));
            }
            TypedItem::ProjectMeta(p) => {
                self.projects.insert(
                    p.project,
                    o,
                    entry(
                        seq,
                        hash,
                        hlc,
                        ProjectValue {
                            name: p.name.clone(),
                            archived: p.archived,
                            merged_into: p.merged_into,
                        },
                    ),
                );
            }
            TypedItem::UsageCounter(u) => {
                let r = self.usage.insert(
                    u.key.clone(),
                    o,
                    SwEntry::new(seq, hash, CounterValue::new(u.epoch, u.totals)),
                );
                out.regression = r.regression;
            }
            TypedItem::CapDef(c) => {
                self.cap_defs.insert(
                    c.cap,
                    o,
                    entry(
                        seq,
                        hash,
                        hlc,
                        CapDefValue {
                            mesh_project_id: c.mesh_project_id,
                            owner_device: c.owner_device,
                            created_hlc: c.created_hlc,
                        },
                    ),
                );
            }
            TypedItem::CapTarget(t) => {
                self.cap_targets.insert(
                    (t.cap, t.month),
                    o,
                    entry(seq, hash, hlc, t.target_micros),
                );
            }
            TypedItem::CapRights(r) => {
                self.cap_counters
                    .entry((r.cap, r.month))
                    .or_default()
                    .apply_rights(o, r.to, SwEntry::new(seq, hash, r.amount_micros));
            }
            TypedItem::CapUsed(u) => {
                self.cap_counters
                    .entry((u.cap, u.month))
                    .or_default()
                    .apply_used(o, SwEntry::new(seq, hash, u.used_micros));
            }
            TypedItem::ShareSealed(sh) => {
                self.shares_sealed.insert(
                    (sh.credential, sh.recipient),
                    o,
                    entry(
                        seq,
                        hash,
                        hlc,
                        SealedValue {
                            share_id: sh.share_id,
                            mesh_project_id: sh.mesh_project_id,
                            credential_name: sh.credential_name.clone(),
                            provider: sh.provider.clone(),
                            value_version: sh.value_version,
                            sealed: sh.sealed.clone(),
                        },
                    ),
                );
            }
            TypedItem::ShareRevoke(r) => {
                self.shares_revoked.insert(
                    (r.credential, r.recipient),
                    o,
                    entry(seq, hash, hlc, r.share_id),
                );
            }
            TypedItem::Unknown => {}
        }
        out
    }
}

/// The current value of one `(credential_ref, recipient)` share key
/// (PROTOCOL.md §5.6 `shares`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareWinner<'a> {
    /// The winning `share.sealed`, which no admitted revoke names; `sharer`
    /// is its origin (the signer).
    Sealed {
        sharer: DeviceId,
        hlc: Hlc,
        value: &'a SealedValue,
    },
    /// An admitted `share.revoke` names the winning share (`sealed` is that
    /// share and its sharer), or there is no admitted share at the key and
    /// this is its greatest revoke (`sealed` is `None`).
    Revoked {
        revoker: DeviceId,
        hlc: Hlc,
        share_id: ShareId,
        sealed: Option<(DeviceId, &'a SealedValue)>,
    },
}

impl State {
    /// Every share key with an entry of either kind.
    pub fn share_keys(&self) -> BTreeSet<(CredentialRef, DeviceId)> {
        self.shares_sealed
            .keys()
            .chain(self.shares_revoked.keys())
            .copied()
            .collect()
    }

    /// The share at `key`, as every device converges to: `None` when the
    /// recipient is removed (such shares are purged, §8.4) or no entry is
    /// admitted. Otherwise the winning share is the admitted `share.sealed`
    /// with the greatest `(hlc, origin)`; it is revoked when an admitted
    /// `share.revoke` **by its sharer or by the key's recipient** names its
    /// share id (the greatest such revoke is the revoker), whatever their
    /// HLCs. A revoke of another share id, or by any other device, ends
    /// nothing (audit MP-10: any member could end another device's share).
    /// With no admitted share, the recipient's greatest admitted revoke is
    /// the value.
    pub fn share_at(&self, key: &(CredentialRef, DeviceId)) -> Option<ShareWinner<'_>> {
        let roster = &self.roster;
        if roster.is_removed(&key.1) {
            return None;
        }
        let revokes: Vec<(DeviceId, Hlc, ShareId)> = self
            .shares_revoked
            .register(key)
            .map(|r| {
                r.entries()
                    .filter(|(o, e)| roster.admits(o, e.seq))
                    .map(|(o, e)| (*o, e.value.hlc, e.value.value))
                    .collect()
            })
            .unwrap_or_default();
        let greatest = |it: &mut dyn Iterator<Item = &(DeviceId, Hlc, ShareId)>| {
            it.max_by_key(|(o, h, _)| (*h, *o)).copied()
        };
        let recipient = key.1;
        match self
            .shares_sealed
            .register(key)
            .and_then(|r| r.winner(roster))
        {
            Some((sharer, e)) => {
                let value = &e.value.value;
                let naming = greatest(&mut revokes.iter().filter(|(o, _, id)| {
                    *id == value.share_id && (*o == *sharer || *o == recipient)
                }));
                Some(match naming {
                    Some((revoker, hlc, share_id)) => ShareWinner::Revoked {
                        revoker,
                        hlc,
                        share_id,
                        sealed: Some((*sharer, value)),
                    },
                    None => ShareWinner::Sealed {
                        sharer: *sharer,
                        hlc: e.value.hlc,
                        value,
                    },
                })
            }
            // No admitted share: no device can be its sharer, so only the
            // recipient's revokes count.
            None => greatest(&mut revokes.iter().filter(|(o, _, _)| *o == recipient)).map(
                |(revoker, hlc, share_id)| ShareWinner::Revoked {
                    revoker,
                    hlc,
                    share_id,
                    sealed: None,
                },
            ),
        }
    }

    /// Whether an admitted `share.revoke` at `key` names `share_id` of a share
    /// written by `sharer`, and the greatest such revoke's origin. As in
    /// [`Self::share_at`], only a revoke by that sharer or by the key's
    /// recipient counts (audit MP-10). The caller names the sharer: share
    /// ids are readable metadata, so another member could copy one into its
    /// own `share.sealed` and must not become a sharer of it.
    pub fn share_revoked_by(
        &self,
        key: &(CredentialRef, DeviceId),
        sharer: &DeviceId,
        share_id: &ShareId,
    ) -> Option<DeviceId> {
        let roster = &self.roster;
        self.shares_revoked.register(key).and_then(|r| {
            r.entries()
                .filter(|(o, e)| {
                    roster.admits(o, e.seq)
                        && e.value.value == *share_id
                        && (**o == key.1 || *o == sharer)
                })
                .max_by_key(|(o, e)| (e.value.hlc, **o))
                .map(|(o, _)| *o)
        })
    }

    /// The timestamp a new write at `key` must exceed to win, whatever its
    /// kind: the greatest admitted HLC of either register.
    pub fn share_winning_hlc(&self, key: &(CredentialRef, DeviceId)) -> Option<Hlc> {
        let roster = &self.roster;
        let a = self
            .shares_sealed
            .register(key)
            .and_then(|r| r.winning_hlc(roster));
        let b = self
            .shares_revoked
            .register(key)
            .and_then(|r| r.winning_hlc(roster));
        a.max(b)
    }
}

/// Fold one stored item (verified when it was accepted) into `state`.
pub fn apply_stored(state: &mut State, item: &SignedItem) -> Result<ApplyOutcome, MeshError> {
    let body = item.decode_unverified()?;
    let typed = TypedItem::parse(&body)?;
    Ok(state.apply(&body, item.hash(), &typed))
}

/// Recompute the state from scratch from stored items. Pure.
pub fn rebuild<'a>(
    genesis: GenesisInfo,
    items: impl IntoIterator<Item = &'a SignedItem>,
) -> Result<State, MeshError> {
    let mut state = State::new(genesis);
    for item in items {
        apply_stored(&mut state, item)?;
    }
    Ok(state)
}

#[cfg(any(test, feature = "mesh-sim"))]
mod expected {
    //! Conversion to the oracle's comparable form (PROTOCOL.md §5.6).

    use super::*;
    use crate::mesh::crdt::Admit;
    use crate::mesh::sim::oracle_api::{
        ExpectedCapDef, ExpectedCapMonth, ExpectedDevice, ExpectedDeviceInfo, ExpectedProject,
        ExpectedRights, ExpectedShare, ExpectedState,
    };

    impl State {
        /// The comparable state, exactly as PROTOCOL.md §5.6 defines it.
        pub fn expected(&self) -> ExpectedState {
            let roster = &self.roster;
            let mut out = ExpectedState::default();

            for (d, keys) in roster.known() {
                out.devices.insert(
                    *d,
                    ExpectedDevice {
                        sign_pub: keys.sign_pub,
                        noise_pub: keys.noise_pub,
                        seal_pub: keys.seal_pub,
                        member: roster.is_member(d),
                        active: roster.is_active(d),
                        cutoff: roster.cutoff(d),
                        fork_seq: roster.fork_seq(d),
                    },
                );
            }
            for (d, v) in self.device_info.values(roster) {
                out.device_info.insert(
                    *d,
                    ExpectedDeviceInfo {
                        name: v.name.clone(),
                        listen_addrs: v.listen_addrs.clone(),
                    },
                );
            }
            for (k, v) in self.settings.values(roster) {
                out.settings.insert(k.clone(), v.clone());
            }
            for (k, v) in self.projects.values(roster) {
                out.projects.insert(
                    *k,
                    ExpectedProject {
                        name: v.name.clone(),
                        archived: v.archived,
                        merged_into: v.merged_into,
                    },
                );
            }
            let usage_keys: BTreeSet<&UsageKey> = self.usage.iter().map(|(k, _, _)| k).collect();
            for key in usage_keys {
                let per: BTreeMap<DeviceId, (u32, UsageTotals)> = self
                    .usage
                    .admitted(key, roster)
                    .map(|(o, v)| (*o, (v.epoch, v.totals)))
                    .collect();
                if !per.is_empty() {
                    out.usage.insert(key.clone(), per);
                }
            }
            for cap in self.cap_defs.keys() {
                let reg = self.cap_defs.register(cap).expect("key from keys()");
                let admitted: Vec<_> = reg
                    .entries()
                    .filter(|(o, e)| roster.admits(o, e.seq))
                    .collect();
                let def = match admitted.as_slice() {
                    [] => continue,
                    [(_, e)] => {
                        let v = &e.value.value;
                        ExpectedCapDef::Defined {
                            mesh_project_id: v.mesh_project_id,
                            owner_device: v.owner_device,
                            created_hlc: v.created_hlc,
                            frozen: roster.is_removed(&v.owner_device),
                        }
                    }
                    _ => ExpectedCapDef::Conflicted,
                };
                out.caps.insert(*cap, def);
            }
            let mut months: BTreeSet<(CapId, Month)> = BTreeSet::new();
            for (k, c) in &self.cap_counters {
                if !c.view(roster).devices.is_empty() {
                    months.insert(*k);
                }
            }
            for (k, _) in self.cap_targets.values(roster) {
                months.insert(*k);
            }
            for k in months {
                let mut m = ExpectedCapMonth {
                    target: self.cap_targets.value(&k, roster).copied(),
                    ..Default::default()
                };
                if let Some(c) = self.cap_counters.get(&k) {
                    let v = c.view(roster);
                    for (d, r) in v.devices {
                        m.devices.insert(
                            d,
                            ExpectedRights {
                                minted: r.minted,
                                received: r.received,
                                sent: r.sent,
                                burned: r.burned,
                                clamped: r.clamped,
                                used: r.used,
                                avail: r.avail,
                            },
                        );
                    }
                    m.total_minted = v.total_minted;
                    m.total_burned = v.total_burned;
                    m.total_used = v.total_used;
                }
                out.cap_months.insert(k, m);
            }
            for k in self.share_keys() {
                let share = match self.share_at(&k) {
                    Some(ShareWinner::Sealed { sharer, value, .. }) => ExpectedShare::Sealed {
                        sharer,
                        share_id: value.share_id,
                        mesh_project_id: value.mesh_project_id,
                        credential_name: value.credential_name.clone(),
                        provider: value.provider.clone(),
                        value_version: value.value_version,
                        sealed: value.sealed.clone(),
                    },
                    Some(ShareWinner::Revoked {
                        revoker, share_id, ..
                    }) => ExpectedShare::Revoked { revoker, share_id },
                    None => continue,
                };
                out.shares.insert(k, share);
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::dot::MeshId;
    use crate::mesh::kinds::{ItemKind, RosterAdd, ShareRevoke, ShareSealed};
    use crate::mesh::sign::PublicKeyBytes;

    fn dev(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    /// A state with the genesis `dev(1)` and members `dev(2..=4)`, and a
    /// per-origin seq counter.
    struct Harness {
        state: State,
        next: BTreeMap<DeviceId, u64>,
    }

    impl Harness {
        fn new() -> Self {
            let genesis = GenesisInfo {
                mesh_id: MeshId::from_bytes([9; 16]),
                genesis: dev(1),
            };
            let mut h = Self {
                state: State::new(genesis),
                next: BTreeMap::new(),
            };
            for d in 1..=4 {
                let add = RosterAdd {
                    device: dev(d),
                    name: format!("fake device {d}"),
                    sign_pub: PublicKeyBytes([d; 32]),
                    noise_pub: PublicKeyBytes([d + 10; 32]),
                    seal_pub: PublicKeyBytes([d + 20; 32]),
                    added_by: dev(1),
                };
                h.put(dev(1), 1, &add, TypedItem::RosterAdd(add.clone()));
            }
            h
        }

        fn put<K: ItemKind>(&mut self, origin: DeviceId, hlc: u64, v: &K, typed: TypedItem) {
            let seq = self.next.entry(origin).or_insert(0);
            *seq += 1;
            let body = v.to_body(self.state.genesis.mesh_id, origin, *seq, Hlc::from_raw(hlc));
            let hash = ItemHash::of(&crate::mesh::codec::encode_body(&body).unwrap());
            self.state.apply(&body, hash, &typed);
        }

        fn share(&mut self, by: DeviceId, hlc: u64, key: (CredentialRef, DeviceId), id: ShareId) {
            let s = ShareSealed {
                credential: key.0,
                recipient: key.1,
                share_id: id,
                mesh_project_id: MeshProjectId::from_bytes([3; 16]),
                credential_name: "Fake credential".into(),
                provider: "fake-provider".into(),
                value_version: 1,
                sealed: b"FAKE-SEALED-BOX-NOT-A-SECRET".to_vec(),
            };
            self.put(by, hlc, &s, TypedItem::ShareSealed(s.clone()));
        }

        fn revoke(&mut self, by: DeviceId, hlc: u64, key: (CredentialRef, DeviceId), id: ShareId) {
            let r = ShareRevoke {
                credential: key.0,
                recipient: key.1,
                share_id: id,
            };
            self.put(by, hlc, &r, TypedItem::ShareRevoke(r.clone()));
        }
    }

    #[test]
    fn a_revoke_by_neither_sharer_nor_recipient_ends_nothing() {
        // Audit MP-10: dev(2) shares to dev(3); dev(4), a third member,
        // revokes that share id with a greater HLC. Only the share's sharer
        // or its recipient may end it.
        let mut h = Harness::new();
        let (sharer, recipient, other) = (dev(2), dev(3), dev(4));
        let key = (CredentialRef::from_bytes([7; 16]), recipient);
        let id = ShareId::from_bytes([5; 16]);
        h.share(sharer, 10, key, id);
        h.revoke(other, 20, key, id);
        assert!(
            matches!(h.state.share_at(&key), Some(ShareWinner::Sealed { sharer: s, .. }) if s == sharer),
            "{:?}",
            h.state.share_at(&key)
        );
        assert_eq!(h.state.share_revoked_by(&key, &sharer, &id), None);
        // A third member's revoke at a key with no share is not a value
        // either.
        let lone = (CredentialRef::from_bytes([8; 16]), recipient);
        h.revoke(other, 20, lone, id);
        assert_eq!(h.state.share_at(&lone), None);
        // The recipient may decline, and the sharer may revoke, whatever the
        // HLCs.
        let declined = (CredentialRef::from_bytes([9; 16]), recipient);
        h.share(sharer, 30, declined, id);
        h.revoke(recipient, 5, declined, id);
        assert!(matches!(
            h.state.share_at(&declined),
            Some(ShareWinner::Revoked { revoker, .. }) if revoker == recipient
        ));
        h.revoke(sharer, 6, key, id);
        assert!(matches!(
            h.state.share_at(&key),
            Some(ShareWinner::Revoked { revoker, sealed: Some((s, _)), .. })
                if revoker == sharer && s == sharer
        ));
        assert_eq!(h.state.share_revoked_by(&key, &sharer, &id), Some(sharer));
    }

    #[test]
    fn copying_a_share_id_does_not_make_a_member_its_sharer() {
        // Share ids are readable metadata. dev(4) copies dev(2)'s share id
        // into its own older share at the same key, then revokes it: that
        // must not end dev(2)'s share, in either view.
        let mut h = Harness::new();
        let (sharer, recipient, other) = (dev(2), dev(3), dev(4));
        let key = (CredentialRef::from_bytes([7; 16]), recipient);
        let id = ShareId::from_bytes([5; 16]);
        h.share(sharer, 10, key, id);
        h.share(other, 5, key, id);
        h.revoke(other, 20, key, id);
        assert_eq!(h.state.share_revoked_by(&key, &sharer, &id), None);
        assert!(matches!(
            h.state.share_at(&key),
            Some(ShareWinner::Sealed { sharer: s, .. }) if s == sharer
        ));
        // The copier's own (losing) share is the one its revoke ends.
        assert_eq!(h.state.share_revoked_by(&key, &other, &id), Some(other));
    }
}
