//! The user's spend-cap operations (`tethra mesh cap …`, DESIGN §D15).
//!
//! - **create**: this device becomes the cap's immutable owner. One live cap
//!   per mesh project (after merges, per root project).
//! - **raise** adds. On the owner it mints more and raises the target; on
//!   any other device it is a labelled **local override**: a self-mint that
//!   raises the cap for that device only, for the rest of the month. "Set
//!   to X" is never offered, because two devices that cannot see each other
//!   both setting it would mint twice.
//! - **lower** sets the last-writer-wins target (this month, and next month
//!   if it is already scheduled). Holders burn what they hold above their
//!   new share, and the owner reclaims the remainder.
//! - **reclaim** (owner only): pull a device's unspent rights back to the
//!   owner, for a device about to be removed.

use super::escrow::GatewayProbe;
use super::period;
use super::reconcile::{self, Plan, ReconcileReport};
use super::view::{self, CapInfo, Ledger};
use crate::error::{CoreError, Result};
use crate::mesh::dot::{CapId, DeviceId, MeshProjectId};
use crate::mesh::error::MeshError;
use crate::mesh::kinds::{CapDef, CapTarget, Month, Recipient};
use crate::mesh::projects;
use crate::mesh::sign::SigningKeyPair;
use crate::mesh::sqlite_store::SqliteStore;
use crate::mesh::store::{Draft, HlcPolicy, MeshStore};
use crate::mesh::views::State;
use serde::Serialize;

fn not_found(ident: &str) -> CoreError {
    CoreError::NotFound {
        kind: "spend cap",
        ident: ident.to_owned(),
    }
}

/// Resolve a cap by its id, a unique prefix of at least 8 hex characters,
/// or a mesh project (id, prefix or name): that project's cap in force.
pub fn resolve(store: &SqliteStore, ident: &str) -> Result<CapId> {
    let caps = view::caps_in(store.state());
    let lower = ident.trim().to_ascii_lowercase();
    if lower.len() >= 8 && lower.bytes().all(|c| c.is_ascii_hexdigit()) {
        let hits: Vec<_> = caps
            .iter()
            .filter(|c| c.cap_id.to_hex().starts_with(&lower))
            .collect();
        if hits.len() == 1 {
            return Ok(hits[0].cap_id);
        }
    }
    if let Ok(p) = projects::resolve(store, ident) {
        let root = projects::root_of(store, &p);
        let mut on: Vec<&CapInfo> = caps.iter().filter(|c| c.root == root).collect();
        // The live cap, else the newest frozen one; superseded ones last.
        on.sort_by_key(|c| {
            (
                c.superseded_by.is_some(),
                !c.is_live(),
                std::cmp::Reverse(c.created_hlc),
            )
        });
        if let Some(c) = on.first() {
            return Ok(c.cap_id);
        }
    }
    Err(not_found(ident.trim()))
}

fn known(state: &State, cap: &CapId) -> std::result::Result<CapInfo, MeshError> {
    view::cap_in(state, cap).ok_or(MeshError::InvalidOperation(
        "that spend cap is not known on this device",
    ))
}

fn not_superseded(c: &CapInfo) -> std::result::Result<(), MeshError> {
    match c.superseded_by {
        Some(_) => Err(MeshError::InvalidOperation(
            "another cap on the same project was created first; change that one instead",
        )),
        None => Ok(()),
    }
}

fn target_winner(state: &State, key: &(CapId, Month)) -> Option<crate::mesh::hlc::Hlc> {
    state
        .cap_targets
        .register(key)
        .and_then(|r| r.winning_hlc(&state.roster))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapCreated {
    pub cap_id: CapId,
    pub mesh_project_id: MeshProjectId,
    pub month: Month,
    pub monthly_micros: u64,
    /// Rights handed to the other active devices right away.
    pub distributed_micros: u64,
}

/// Create a monthly cap of `monthly_micros` on `project`, owned by this
/// device: the definition, this month's target and this month's rights in
/// one transaction, then equal shares to the active devices.
pub fn create(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    probe: &dyn GatewayProbe,
    project: &MeshProjectId,
    monthly_micros: u64,
) -> Result<CapCreated> {
    if monthly_micros == 0 {
        return Err(CoreError::InvalidInput(
            "a spend cap must be more than $0".into(),
        ));
    }
    let p = projects::get(store, project).ok_or_else(|| CoreError::NotFound {
        kind: "mesh project",
        ident: project.to_hex(),
    })?;
    if p.archived {
        return Err(CoreError::InvalidInput(
            "that mesh project is archived".into(),
        ));
    }
    if let Some(root) = p.merged_into {
        return Err(CoreError::InvalidInput(format!(
            "that mesh project was merged into {}; put the cap on that one",
            &root.to_hex()[..8]
        )));
    }
    let cap = CapId::random();
    let (me, now) = (store.self_id(), store.now_ms());
    let month = period::month_of(now);
    // When it was created: "created first" (between two caps made on
    // devices that could not see each other) is decided by this.
    let created_hlc = store
        .hlc_last()
        .successor()
        .max(crate::mesh::hlc::Hlc::new(now, 0));
    let project = *project;
    store.mint_with(signing, |_, state| {
        let root = projects::root_in(state, &project);
        if view::caps_in(state)
            .iter()
            .any(|c| c.root == root && !c.frozen)
        {
            return Err(MeshError::CapExists);
        }
        Ok(vec![
            Draft::of(
                &CapDef {
                    cap,
                    mesh_project_id: project,
                    owner_device: me,
                    created_hlc,
                },
                HlcPolicy::Now,
            ),
            Draft::of(
                &CapTarget {
                    cap,
                    month,
                    target_micros: monthly_micros,
                },
                HlcPolicy::Now,
            ),
            Draft::of(
                &crate::mesh::kinds::CapRights {
                    cap,
                    month,
                    to: Recipient::Device(me),
                    amount_micros: monthly_micros,
                    is_override: false,
                },
                HlcPolicy::Now,
            ),
        ])
    })?;
    let mut rep = ReconcileReport::default();
    reconcile::distribute(store, signing, probe, &mut rep)?;
    Ok(CapCreated {
        cap_id: cap,
        mesh_project_id: project,
        month,
        monthly_micros,
        distributed_micros: rep.distributed_micros,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapChanged {
    pub cap_id: CapId,
    /// Raised on the owner (minted), or a local override elsewhere.
    pub owner: bool,
    pub is_override: bool,
    pub months: Vec<Month>,
    pub amount_micros: u64,
    pub burned_micros: u64,
    pub distributed_micros: u64,
}

/// Raise `cap` by `amount_micros`: on the owner, this month (and next month
/// once minted); elsewhere, a local override for this month.
pub fn raise(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    probe: &dyn GatewayProbe,
    cap: &CapId,
    amount_micros: u64,
) -> Result<CapChanged> {
    if amount_micros == 0 {
        return Err(CoreError::InvalidInput("raise by more than $0".into()));
    }
    let cap = *cap;
    let mut owner = false;
    let mut months = Vec::new();
    reconcile::decide(store, signing, |l| {
        let c = known(l.state, &cap)?;
        if c.frozen {
            return Err(MeshError::CapFrozen.into());
        }
        not_superseded(&c)?;
        let month = l.month();
        let mut plan = Plan::new(l);
        owner = c.owner_device == l.me;
        if owner {
            months.push(month);
            if let Some(next) = month.next() {
                if own_rights_to(l, &c, next, &Recipient::Device(l.me)) {
                    months.push(next);
                }
            }
            for m in &months {
                let key = (cap, *m);
                let target = view::scheduled_target(l.state, &cap, *m).unwrap_or(0);
                plan.push(Draft::of(
                    &CapTarget {
                        cap,
                        month: *m,
                        target_micros: target.saturating_add(amount_micros),
                    },
                    HlcPolicy::After(target_winner(l.state, &key)),
                ));
                plan.mint_self(&cap, *m, amount_micros);
            }
        } else {
            months.push(month);
            plan.mint_self(&cap, month, amount_micros);
        }
        plan.drafts()
    })?;
    let mut rep = ReconcileReport::default();
    if owner {
        reconcile::distribute(store, signing, probe, &mut rep)?;
    }
    Ok(CapChanged {
        cap_id: cap,
        owner,
        is_override: !owner,
        months,
        amount_micros,
        burned_micros: 0,
        distributed_micros: rep.distributed_micros,
    })
}

fn own_rights_to(l: &Ledger<'_>, c: &CapInfo, m: Month, to: &Recipient) -> bool {
    l.state
        .cap_counters
        .get(&(c.cap_id, m))
        .is_some_and(|k| k.own_rights(&l.me, to) > 0)
}

/// Lower `cap` to `target_micros` for this month (and next month, if a
/// target is already scheduled for it), then burn what this device holds
/// above its new share. Refused when it is not lower.
pub fn lower(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    probe: &dyn GatewayProbe,
    cap: &CapId,
    target_micros: u64,
) -> Result<CapChanged> {
    let cap = *cap;
    let mut months = Vec::new();
    reconcile::decide(store, signing, |l| {
        let c = known(l.state, &cap)?;
        not_superseded(&c)?;
        let month = l.month();
        let current = view::scheduled_target(l.state, &cap, month).unwrap_or(0);
        if target_micros >= current {
            return Err(MeshError::InvalidOperation(
                "that is not lower than the cap now; use `tethra mesh cap raise` to raise it",
            )
            .into());
        }
        let mut drafts = vec![Draft::of(
            &CapTarget {
                cap,
                month,
                target_micros,
            },
            HlcPolicy::After(target_winner(l.state, &(cap, month))),
        )];
        months.push(month);
        if let Some(next) = month.next() {
            let key = (cap, next);
            let scheduled = l.state.cap_targets.value(&key, &l.state.roster).copied();
            if scheduled.is_some_and(|t| t > target_micros) {
                drafts.push(Draft::of(
                    &CapTarget {
                        cap,
                        month: next,
                        target_micros,
                    },
                    HlcPolicy::After(target_winner(l.state, &key)),
                ));
                months.push(next);
            }
        }
        Ok(drafts)
    })?;
    let mut rep = ReconcileReport::default();
    reconcile::burn_after_lower(store, signing, probe, &mut rep)?;
    Ok(CapChanged {
        cap_id: cap,
        owner: view::cap_in(store.state(), &cap).is_some_and(|c| c.owner_device == store.self_id()),
        is_override: false,
        months,
        amount_micros: target_micros,
        burned_micros: rep.burned_micros,
        distributed_micros: 0,
    })
}

/// Reclaim `cap`'s unspent rights from `from` (default: every other device
/// holding some this month or next) back to this device, the owner. The
/// requests travel in the node's next exchanges with those devices, for
/// the next 24 hours; meanwhile the owner grants them no rights. Returns
/// the devices asked.
pub fn reclaim(store: &SqliteStore, cap: &CapId, from: Option<DeviceId>) -> Result<Vec<DeviceId>> {
    let l = Ledger::of(store);
    let c = known(l.state, cap)?;
    if c.owner_device != l.me {
        return Err(CoreError::InvalidInput(
            "only the cap's owner device can reclaim its rights; run this on that device".into(),
        ));
    }
    let month = l.month();
    let devices: Vec<DeviceId> = match from {
        Some(d) if d == l.me => {
            return Err(CoreError::InvalidInput(
                "this device is the owner; reclaim from another device".into(),
            ))
        }
        Some(d) => vec![d],
        None => {
            let mut out = std::collections::BTreeSet::new();
            for m in [Some(month), month.next()].into_iter().flatten() {
                for (d, r) in l.figures(&c, m).view.devices {
                    if d != l.me && r.avail > 0 {
                        out.insert(d);
                    }
                }
            }
            out.into_iter().collect()
        }
    };
    let now = i64::try_from(l.now_ms).unwrap_or(i64::MAX);
    for d in &devices {
        store.connection().execute(
            "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![reconcile::reclaim_key(cap, d), now],
        )?;
    }
    Ok(devices)
}

/// The strict local check (Increment 08's gate makes the same one in
/// memory): may this device spend `amount_micros` against `cap` in `month`
/// now? It counts the spend this device's gateway recorded but has not
/// published yet, and its open escrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum SpendDecision {
    Allowed { avail: i128 },
    Refused { avail: i128 },
}

pub fn try_spend(
    store: &SqliteStore,
    cap: &CapId,
    month: Month,
    amount_micros: u64,
) -> Result<SpendDecision> {
    let l = Ledger::of(store);
    let c = known(l.state, cap)?;
    let f = l.figures(&c, month);
    let avail = l.local_avail(&c, month, &f)?;
    Ok(if i128::from(amount_micros) <= avail {
        SpendDecision::Allowed { avail }
    } else {
        SpendDecision::Refused { avail }
    })
}
