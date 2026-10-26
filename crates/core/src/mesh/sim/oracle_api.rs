//! The contract between the simulator and the independent oracle
//! (Increment 02).
//!
//! The oracle is a deliberately naive model written from
//! `docs/mesh/PROTOCOL.md` alone. The simulator tells it about **every** item
//! any device mints (honest, forged, forked or otherwise), and at quiescence
//! asks it for the state every device must have converged to. The simulator
//! converts each device's real views into the same [`ExpectedState`] and
//! compares.
//!
//! Everything here is plain data: comparable values, no CRDT machinery.
//! PROTOCOL.md §5.6 ("Views") defines each field.

use crate::mesh::dot::{CapId, CredentialRef, DeviceId, MeshId, MeshProjectId, ShareId};
use crate::mesh::hlc::Hlc;
use crate::mesh::item::SignedItem;
use crate::mesh::kinds::{Month, UsageKey, UsageTotals};
use crate::mesh::sign::PublicKeyBytes;
use serde_json::Value;
use std::collections::BTreeMap;

/// What every member of one mesh knows from pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisInfo {
    pub mesh_id: MeshId,
    /// The device that ran `mesh init`; its self-add is the root of trust.
    pub genesis: DeviceId,
}

/// A naive, independent model of the replicated state.
pub trait OracleModel {
    fn new(genesis: &GenesisInfo) -> Self
    where
        Self: Sized;

    /// Called once for every item any device mints, in mint order. Includes
    /// items that no honest device will accept (bad signatures, unknown
    /// origins); the oracle applies the protocol's validity rules itself.
    fn observe_minted(&mut self, item: &SignedItem);

    /// The state every device must converge to, recomputed from scratch.
    fn expected(&self) -> ExpectedState;
}

/// One known device (PROTOCOL.md §6.3 step 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedDevice {
    pub sign_pub: PublicKeyBytes,
    pub noise_pub: PublicKeyBytes,
    pub seal_pub: PublicKeyBytes,
    pub member: bool,
    pub active: bool,
    /// Present when removed.
    pub cutoff: Option<u64>,
    /// Present when forked.
    pub fork_seq: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedDeviceInfo {
    pub name: String,
    pub listen_addrs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedProject {
    pub name: String,
    pub archived: bool,
    pub merged_into: Option<MeshProjectId>,
}

/// A cap's definition (PROTOCOL.md §5.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedCapDef {
    Defined {
        mesh_project_id: MeshProjectId,
        owner_device: DeviceId,
        created_hlc: Hlc,
        /// The owner device is removed: no new minting.
        frozen: bool,
    },
    /// More than one origin published a definition for this cap id.
    Conflicted,
}

/// One device's position in a cap month (PROTOCOL.md §5.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectedRights {
    pub minted: u128,
    pub received: u128,
    pub sent: u128,
    pub burned: u128,
    pub clamped: u128,
    pub used: u128,
    pub avail: i128,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectedCapMonth {
    /// The LWW `cap.target`, if any admitted one exists.
    pub target: Option<u64>,
    pub devices: BTreeMap<DeviceId, ExpectedRights>,
    pub total_minted: u128,
    pub total_burned: u128,
    pub total_used: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedShare {
    Sealed {
        sharer: DeviceId,
        share_id: ShareId,
        mesh_project_id: MeshProjectId,
        credential_name: String,
        provider: String,
        value_version: u64,
        sealed: Vec<u8>,
    },
    Revoked {
        revoker: DeviceId,
        share_id: ShareId,
    },
}

/// The comparable replicated state (PROTOCOL.md §5.6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectedState {
    /// Every known device.
    pub devices: BTreeMap<DeviceId, ExpectedDevice>,
    /// `device.info` winners, by device.
    pub device_info: BTreeMap<DeviceId, ExpectedDeviceInfo>,
    /// `mesh.setting` winners, by name.
    pub settings: BTreeMap<String, Value>,
    /// `project.meta` winners, by mesh project.
    pub projects: BTreeMap<MeshProjectId, ExpectedProject>,
    /// `usage.counter`: per key, each admitted origin's `(epoch, totals)`.
    pub usage: BTreeMap<UsageKey, BTreeMap<DeviceId, (u32, UsageTotals)>>,
    /// `cap.def`, by cap.
    pub caps: BTreeMap<CapId, ExpectedCapDef>,
    /// Bounded-counter views and targets, by `(cap, month)`.
    pub cap_months: BTreeMap<(CapId, Month), ExpectedCapMonth>,
    /// `share.sealed` / `share.revoke` winners, by `(credential_ref, recipient)`.
    pub shares: BTreeMap<(CredentialRef, DeviceId), ExpectedShare>,
}
