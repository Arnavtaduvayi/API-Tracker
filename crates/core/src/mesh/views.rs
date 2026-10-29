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
use super::crdt::SwEntry;
use super::dot::{CapId, CredentialRef, DeviceId, MeshProjectId, ShareId};
use super::error::MeshError;
use super::hlc::Hlc;
use super::item::{ItemHash, SignedItem};
use super::kinds::{Month, TypedItem, UsageKey, UsageTotals};
use super::store::GenesisInfo;
use serde_json::Value;
use std::collections::BTreeMap;

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
    use std::collections::BTreeSet;

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
            let share_keys: BTreeSet<(CredentialRef, DeviceId)> = self
                .shares_sealed
                .keys()
                .chain(self.shares_revoked.keys())
                .copied()
                .collect();
            for k in share_keys {
                if roster.is_removed(&k.1) {
                    continue;
                }
                let sealed = self
                    .shares_sealed
                    .register(&k)
                    .and_then(|r| r.winner(roster))
                    .map(|(o, e)| ((e.value.hlc, *o, 0u8), Some(e), None));
                let revoked = self
                    .shares_revoked
                    .register(&k)
                    .and_then(|r| r.winner(roster))
                    .map(|(o, e)| ((e.value.hlc, *o, 1u8), None, Some(e)));
                let winner = [sealed, revoked].into_iter().flatten().max_by_key(|w| w.0);
                let Some(((_, origin, _), s, r)) = winner else {
                    continue;
                };
                let share = match (s, r) {
                    (Some(e), _) => {
                        let v = &e.value.value;
                        ExpectedShare::Sealed {
                            sharer: origin,
                            share_id: v.share_id,
                            mesh_project_id: v.mesh_project_id,
                            credential_name: v.credential_name.clone(),
                            provider: v.provider.clone(),
                            value_version: v.value_version,
                            sealed: v.sealed.clone(),
                        }
                    }
                    (None, Some(e)) => ExpectedShare::Revoked {
                        revoker: origin,
                        share_id: e.value.value,
                    },
                    (None, None) => continue,
                };
                out.shares.insert(k, share);
            }
            out
        }
    }
}
