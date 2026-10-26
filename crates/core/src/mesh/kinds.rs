//! Typed payloads for every v1 item kind (PROTOCOL.md §2.4).
//!
//! An item's `kind` selects one of these types; its `key` and `payload` are
//! parsed and validated here. Unknown kinds stay opaque ([`TypedItem::Unknown`]):
//! they are stored and relayed but never materialized, so a newer Tethra's
//! data passes intact through an older one. Payload parsing ignores fields
//! it does not know for the same reason; the envelope itself is strict.
//!
//! A known kind whose key or payload fails validation is still a validly
//! signed item. It is stored and relayed like any other, and every device
//! deterministically leaves it out of its views.

use super::codec::ItemBody;
use super::dot::{CapId, CredentialRef, DeviceId, MeshId, MeshProjectId, ShareId};
use super::error::MeshError;
use super::hlc::Hlc;
use super::item::ItemHash;
use super::sign::{derive_device_id, PublicKeyBytes};
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// The v1 kind names.
pub mod names {
    pub const ROSTER_ADD: &str = "roster.add";
    pub const ROSTER_REMOVE: &str = "roster.remove";
    pub const DEVICE_INFO: &str = "device.info";
    pub const MESH_SETTING: &str = "mesh.setting";
    pub const PROJECT_META: &str = "project.meta";
    pub const USAGE_COUNTER: &str = "usage.counter";
    pub const CAP_DEF: &str = "cap.def";
    pub const CAP_TARGET: &str = "cap.target";
    pub const CAP_RIGHTS: &str = "cap.rights";
    pub const CAP_USED: &str = "cap.used";
    pub const SHARE_SEALED: &str = "share.sealed";
    pub const SHARE_REVOKE: &str = "share.revoke";
    pub const FORK_REPORT: &str = "fork.report";
}

/// Every kind this version materializes.
pub const KNOWN_KINDS: [&str; 13] = [
    names::ROSTER_ADD,
    names::ROSTER_REMOVE,
    names::DEVICE_INFO,
    names::MESH_SETTING,
    names::PROJECT_META,
    names::USAGE_COUNTER,
    names::CAP_DEF,
    names::CAP_TARGET,
    names::CAP_RIGHTS,
    names::CAP_USED,
    names::SHARE_SEALED,
    names::SHARE_REVOKE,
    names::FORK_REPORT,
];

pub fn is_known_kind(kind: &str) -> bool {
    KNOWN_KINDS.contains(&kind)
}

/// Longest device or project display name, in bytes.
pub const MAX_NAME_BYTES: usize = 128;
/// Most listen addresses one device may publish.
pub const MAX_LISTEN_ADDRS: usize = 16;
/// Longest listen address (`host:port`), in bytes.
pub const MAX_ADDR_BYTES: usize = 255;
/// Longest model name, in bytes.
pub const MAX_MODEL_BYTES: usize = 256;
/// Largest sealed credential box, in bytes (before base64).
pub const MAX_SEALED_BYTES: usize = 16 * 1024;

/// A kind's typed form.
pub trait ItemKind: Sized {
    const KIND: &'static str;

    /// The item `key` this value is written under.
    fn item_key(&self) -> String;

    /// The `payload` object.
    fn payload(&self) -> Value;

    /// Parse and validate from an item's origin, key and payload.
    fn parse(origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError>;

    /// A v1 body carrying this value.
    fn to_body(&self, mesh: MeshId, origin: DeviceId, seq: u64, hlc: Hlc) -> ItemBody {
        ItemBody::new(
            mesh,
            origin,
            seq,
            hlc,
            Self::KIND,
            self.item_key(),
            self.payload(),
        )
    }
}

macro_rules! item_kind_try_from {
    ($($ty:ty),* $(,)?) => {$(
        impl TryFrom<&ItemBody> for $ty {
            type Error = MeshError;
            fn try_from(body: &ItemBody) -> Result<Self, MeshError> {
                if body.kind != <$ty as ItemKind>::KIND {
                    return Err(MeshError::KindMismatch {
                        expected: <$ty as ItemKind>::KIND,
                        found: body.kind.clone(),
                    });
                }
                <$ty as ItemKind>::parse(&body.origin, &body.key, &body.payload)
            }
        }
    )*};
}

fn invalid(kind: &'static str, reason: &'static str) -> MeshError {
    MeshError::InvalidPayload { kind, reason }
}

fn from_payload<T: DeserializeOwned>(kind: &'static str, payload: &Value) -> Result<T, MeshError> {
    T::deserialize(payload).map_err(|_| invalid(kind, "payload fields are missing or mistyped"))
}

fn to_value<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("payload structs always serialize")
}

fn valid_name(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= MAX_NAME_BYTES && !s.chars().any(char::is_control)
}

/// `[a-z0-9._-]{1,64}` — provider ids and setting names.
fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn valid_addr(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ADDR_BYTES
        && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn valid_model(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_MODEL_BYTES && !s.chars().any(char::is_control)
}

/// Split `key` into exactly `N` `/`-separated parts; the last part keeps any
/// further slashes (model names contain them).
fn split_key<'k, const N: usize>(
    kind: &'static str,
    key: &'k str,
) -> Result<[&'k str; N], MeshError> {
    let parts: Vec<&str> = key.splitn(N, '/').collect();
    parts
        .try_into()
        .map_err(|_| invalid(kind, "key does not have the expected parts"))
}

/// A UTC calendar day, `YYYY-MM-DD`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Day(time::Date);

impl Day {
    pub fn new(date: time::Date) -> Self {
        Self(date)
    }

    pub fn date(&self) -> time::Date {
        self.0
    }

    pub fn month(&self) -> Month {
        Month {
            year: self.0.year(),
            month: u8::from(self.0.month()),
        }
    }

    /// Parse the canonical form only (four-digit year, zero-padded fields).
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        let shaped = b.len() == 10
            && b[4] == b'-'
            && b[7] == b'-'
            && b.iter()
                .enumerate()
                .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
        if !shaped {
            return None;
        }
        let year: i32 = s[0..4].parse().ok()?;
        let month: u8 = s[5..7].parse().ok()?;
        let day: u8 = s[8..10].parse().ok()?;
        let month = time::Month::try_from(month).ok()?;
        time::Date::from_calendar_date(year, month, day)
            .ok()
            .map(Self)
    }
}

impl fmt::Display for Day {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}",
            self.0.year(),
            u8::from(self.0.month()),
            self.0.day()
        )
    }
}

/// A UTC calendar month, `YYYY-MM` — the spend-cap period, with the same
/// semantics as [`crate::budget::period_start`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Month {
    year: i32,
    month: u8,
}

impl Month {
    pub fn new(year: i32, month: u8) -> Option<Self> {
        ((1000..=9999).contains(&year) && (1..=12).contains(&month)).then_some(Self { year, month })
    }

    pub fn year(&self) -> i32 {
        self.year
    }

    pub fn month(&self) -> u8 {
        self.month
    }

    pub fn next(&self) -> Option<Self> {
        if self.month == 12 {
            Self::new(self.year + 1, 1)
        } else {
            Self::new(self.year, self.month + 1)
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        let shaped = b.len() == 7
            && b[4] == b'-'
            && b.iter()
                .enumerate()
                .all(|(i, c)| i == 4 || c.is_ascii_digit());
        if !shaped {
            return None;
        }
        Self::new(s[0..4].parse().ok()?, s[5..7].parse().ok()?)
    }
}

impl fmt::Display for Month {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}", self.year, self.month)
    }
}

/// Where a `cap.rights` amount goes. `Burn` sorts first, which is the order
/// the view honours outgoing amounts in.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Recipient {
    Burn,
    Device(DeviceId),
}

impl Recipient {
    /// The reserved key segment for the burn sink.
    pub const BURN: &'static str = "burn";

    pub fn parse(s: &str) -> Option<Self> {
        if s == Self::BURN {
            Some(Self::Burn)
        } else {
            DeviceId::parse(s).ok().map(Self::Device)
        }
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Burn => f.write_str(Self::BURN),
            Self::Device(d) => write!(f, "{d}"),
        }
    }
}

// ---------------------------------------------------------------- roster.add

/// `roster.add`, key = the added device's id. Minted by an existing member
/// for a joining device, or by the genesis device for itself at `mesh init`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterAdd {
    pub device: DeviceId,
    pub name: String,
    pub sign_pub: PublicKeyBytes,
    pub noise_pub: PublicKeyBytes,
    pub seal_pub: PublicKeyBytes,
    /// Must equal the item's origin.
    pub added_by: DeviceId,
}

#[derive(Serialize, Deserialize)]
struct RosterAddPayload {
    added_by: DeviceId,
    name: String,
    noise_pub: PublicKeyBytes,
    seal_pub: PublicKeyBytes,
    sign_pub: PublicKeyBytes,
}

impl ItemKind for RosterAdd {
    const KIND: &'static str = names::ROSTER_ADD;

    fn item_key(&self) -> String {
        self.device.to_hex()
    }

    fn payload(&self) -> Value {
        to_value(&RosterAddPayload {
            added_by: self.added_by,
            name: self.name.clone(),
            noise_pub: self.noise_pub,
            seal_pub: self.seal_pub,
            sign_pub: self.sign_pub,
        })
    }

    fn parse(origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let k = Self::KIND;
        let device = DeviceId::parse(key).map_err(|_| invalid(k, "key is not a device id"))?;
        let p: RosterAddPayload = from_payload(k, payload)?;
        if p.added_by != *origin {
            return Err(invalid(k, "added_by does not match the signing origin"));
        }
        if !valid_name(&p.name) {
            return Err(invalid(
                k,
                "device name is empty, too long or has control characters",
            ));
        }
        p.sign_pub
            .to_verifying_key()
            .map_err(|_| invalid(k, "sign_pub is not a usable Ed25519 key"))?;
        if derive_device_id(&p.sign_pub, &p.noise_pub, &p.seal_pub) != device {
            return Err(invalid(k, "device id is not derived from these keys"));
        }
        Ok(Self {
            device,
            name: p.name,
            sign_pub: p.sign_pub,
            noise_pub: p.noise_pub,
            seal_pub: p.seal_pub,
            added_by: p.added_by,
        })
    }
}

// ------------------------------------------------------------- roster.remove

/// `roster.remove`, key = the removed device's id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterRemove {
    pub device: DeviceId,
    /// The removed device's items with seq above this stop counting.
    pub cutoff_seq: u64,
}

#[derive(Serialize, Deserialize)]
struct RosterRemovePayload {
    cutoff_seq: u64,
}

impl ItemKind for RosterRemove {
    const KIND: &'static str = names::ROSTER_REMOVE;

    fn item_key(&self) -> String {
        self.device.to_hex()
    }

    fn payload(&self) -> Value {
        to_value(&RosterRemovePayload {
            cutoff_seq: self.cutoff_seq,
        })
    }

    fn parse(_origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let k = Self::KIND;
        let device = DeviceId::parse(key).map_err(|_| invalid(k, "key is not a device id"))?;
        let p: RosterRemovePayload = from_payload(k, payload)?;
        Ok(Self {
            device,
            cutoff_seq: p.cutoff_seq,
        })
    }
}

// --------------------------------------------------------------- device.info

/// `device.info`, key = the device's own id (origin == key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub device: DeviceId,
    pub name: String,
    pub listen_addrs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct DeviceInfoPayload {
    listen_addrs: Vec<String>,
    name: String,
}

impl ItemKind for DeviceInfo {
    const KIND: &'static str = names::DEVICE_INFO;

    fn item_key(&self) -> String {
        self.device.to_hex()
    }

    fn payload(&self) -> Value {
        to_value(&DeviceInfoPayload {
            listen_addrs: self.listen_addrs.clone(),
            name: self.name.clone(),
        })
    }

    fn parse(origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let k = Self::KIND;
        let device = DeviceId::parse(key).map_err(|_| invalid(k, "key is not a device id"))?;
        if device != *origin {
            return Err(invalid(k, "a device may only describe itself"));
        }
        let p: DeviceInfoPayload = from_payload(k, payload)?;
        if !valid_name(&p.name) {
            return Err(invalid(
                k,
                "device name is empty, too long or has control characters",
            ));
        }
        if p.listen_addrs.len() > MAX_LISTEN_ADDRS || !p.listen_addrs.iter().all(|a| valid_addr(a))
        {
            return Err(invalid(k, "listen_addrs has too many or malformed entries"));
        }
        Ok(Self {
            device,
            name: p.name,
            listen_addrs: p.listen_addrs,
        })
    }
}

// -------------------------------------------------------------- mesh.setting

/// `mesh.setting`, key = setting name (`[a-z0-9._-]{1,64}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshSetting {
    pub name: String,
    pub value: Value,
}

#[derive(Serialize, Deserialize)]
struct MeshSettingPayload {
    value: Value,
}

impl ItemKind for MeshSetting {
    const KIND: &'static str = names::MESH_SETTING;

    fn item_key(&self) -> String {
        self.name.clone()
    }

    fn payload(&self) -> Value {
        to_value(&MeshSettingPayload {
            value: self.value.clone(),
        })
    }

    fn parse(_origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let k = Self::KIND;
        if !valid_slug(key) {
            return Err(invalid(k, "setting name must be 1-64 of [a-z0-9._-]"));
        }
        let p: MeshSettingPayload = from_payload(k, payload)?;
        Ok(Self {
            name: key.to_owned(),
            value: p.value,
        })
    }
}

// -------------------------------------------------------------- project.meta

/// `project.meta`, key = mesh project id. Mesh projects are never deleted;
/// they are archived or merged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectMeta {
    pub project: MeshProjectId,
    pub name: String,
    pub archived: bool,
    pub merged_into: Option<MeshProjectId>,
}

#[derive(Serialize, Deserialize)]
struct ProjectMetaPayload {
    archived: bool,
    #[serde(default)]
    merged_into: Option<MeshProjectId>,
    name: String,
}

impl ItemKind for ProjectMeta {
    const KIND: &'static str = names::PROJECT_META;

    fn item_key(&self) -> String {
        self.project.to_hex()
    }

    fn payload(&self) -> Value {
        to_value(&ProjectMetaPayload {
            archived: self.archived,
            merged_into: self.merged_into,
            name: self.name.clone(),
        })
    }

    fn parse(_origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let k = Self::KIND;
        let project =
            MeshProjectId::parse(key).map_err(|_| invalid(k, "key is not a mesh project id"))?;
        let p: ProjectMetaPayload = from_payload(k, payload)?;
        if !valid_name(&p.name) {
            return Err(invalid(
                k,
                "project name is empty, too long or has control characters",
            ));
        }
        if p.merged_into == Some(project) {
            return Err(invalid(k, "a project cannot be merged into itself"));
        }
        Ok(Self {
            project,
            name: p.name,
            archived: p.archived,
            merged_into: p.merged_into,
        })
    }
}

// ------------------------------------------------------------- usage.counter

/// Gateway usage totals for one counter. `estimated_cost_micros` covers
/// priced requests only, computed on the device the usage came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageTotals {
    pub requests: u64,
    pub priced_requests: u64,
    pub unpriced_requests: u64,
    pub unextracted_requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub estimated_cost_micros: u64,
}

/// The key of a usage counter: `<mesh_project_id>/<YYYY-MM-DD>/<provider>/<model>`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UsageKey {
    pub project: MeshProjectId,
    pub day: Day,
    pub provider: String,
    pub model: String,
}

impl fmt::Display for UsageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}",
            self.project, self.day, self.provider, self.model
        )
    }
}

impl UsageKey {
    pub fn parse(key: &str) -> Result<Self, MeshError> {
        let k = names::USAGE_COUNTER;
        let [project, day, provider, model] = split_key::<4>(k, key)?;
        let project =
            MeshProjectId::parse(project).map_err(|_| invalid(k, "key has no mesh project id"))?;
        let day = Day::parse(day).ok_or(invalid(k, "key day is not YYYY-MM-DD"))?;
        if !valid_slug(provider) {
            return Err(invalid(k, "key provider must be 1-64 of [a-z0-9._-]"));
        }
        if !valid_model(model) {
            return Err(invalid(
                k,
                "key model is empty, too long or has control characters",
            ));
        }
        Ok(Self {
            project,
            day,
            provider: provider.to_owned(),
            model: model.to_owned(),
        })
    }
}

/// `usage.counter`: one origin's cumulative usage for one key. The origin
/// bumps `epoch` when its totals legitimately decrease (local data deleted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageCounter {
    pub key: UsageKey,
    pub epoch: u32,
    pub totals: UsageTotals,
}

#[derive(Serialize, Deserialize)]
struct UsageCounterPayload {
    epoch: u32,
    totals: UsageTotals,
}

impl ItemKind for UsageCounter {
    const KIND: &'static str = names::USAGE_COUNTER;

    fn item_key(&self) -> String {
        self.key.to_string()
    }

    fn payload(&self) -> Value {
        to_value(&UsageCounterPayload {
            epoch: self.epoch,
            totals: self.totals,
        })
    }

    fn parse(_origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let key = UsageKey::parse(key)?;
        let p: UsageCounterPayload = from_payload(Self::KIND, payload)?;
        Ok(Self {
            key,
            epoch: p.epoch,
            totals: p.totals,
        })
    }
}

// ------------------------------------------------------------------ cap.def

/// `cap.def`, key = cap id. Immutable; written once by its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapDef {
    pub cap: CapId,
    pub mesh_project_id: MeshProjectId,
    /// Must equal the item's origin.
    pub owner_device: DeviceId,
    pub created_hlc: Hlc,
}

#[derive(Serialize, Deserialize)]
struct CapDefPayload {
    created_hlc: u64,
    mesh_project_id: MeshProjectId,
    owner_device: DeviceId,
}

impl ItemKind for CapDef {
    const KIND: &'static str = names::CAP_DEF;

    fn item_key(&self) -> String {
        self.cap.to_hex()
    }

    fn payload(&self) -> Value {
        to_value(&CapDefPayload {
            created_hlc: self.created_hlc.raw(),
            mesh_project_id: self.mesh_project_id,
            owner_device: self.owner_device,
        })
    }

    fn parse(origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let k = Self::KIND;
        let cap = CapId::parse(key).map_err(|_| invalid(k, "key is not a cap id"))?;
        let p: CapDefPayload = from_payload(k, payload)?;
        if p.owner_device != *origin {
            return Err(invalid(k, "owner_device does not match the signing origin"));
        }
        Ok(Self {
            cap,
            mesh_project_id: p.mesh_project_id,
            owner_device: p.owner_device,
            created_hlc: Hlc::from_raw(p.created_hlc),
        })
    }
}

fn parse_cap_month(
    kind: &'static str,
    cap: &str,
    month: &str,
) -> Result<(CapId, Month), MeshError> {
    let cap = CapId::parse(cap).map_err(|_| invalid(kind, "key has no cap id"))?;
    let month = Month::parse(month).ok_or(invalid(kind, "key month is not YYYY-MM"))?;
    Ok((cap, month))
}

// --------------------------------------------------------------- cap.target

/// `cap.target`, key = `<cap_id>/<YYYY-MM>`. The (last-writer-wins) target a
/// device lowered the cap to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapTarget {
    pub cap: CapId,
    pub month: Month,
    pub target_micros: u64,
}

#[derive(Serialize, Deserialize)]
struct CapTargetPayload {
    target_micros: u64,
}

impl ItemKind for CapTarget {
    const KIND: &'static str = names::CAP_TARGET;

    fn item_key(&self) -> String {
        format!("{}/{}", self.cap, self.month)
    }

    fn payload(&self) -> Value {
        to_value(&CapTargetPayload {
            target_micros: self.target_micros,
        })
    }

    fn parse(_origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let [cap, month] = split_key::<2>(Self::KIND, key)?;
        let (cap, month) = parse_cap_month(Self::KIND, cap, month)?;
        let p: CapTargetPayload = from_payload(Self::KIND, payload)?;
        Ok(Self {
            cap,
            month,
            target_micros: p.target_micros,
        })
    }
}

// --------------------------------------------------------------- cap.rights

/// `cap.rights`, key = `<cap_id>/<YYYY-MM>/<to>` where `to` is a device id or
/// `burn`. `amount_micros` is the origin's *cumulative* amount to `to` for
/// that month. `to == origin` is a mint; a non-owner's mint is a labelled
/// local override.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapRights {
    pub cap: CapId,
    pub month: Month,
    pub to: Recipient,
    pub amount_micros: u64,
    /// Display hint for a non-owner self-mint. Views classify overrides by
    /// origin vs. owner, not by this flag.
    pub is_override: bool,
}

#[derive(Serialize, Deserialize)]
struct CapRightsPayload {
    amount_micros: u64,
    #[serde(default, rename = "override")]
    is_override: bool,
}

impl ItemKind for CapRights {
    const KIND: &'static str = names::CAP_RIGHTS;

    fn item_key(&self) -> String {
        format!("{}/{}/{}", self.cap, self.month, self.to)
    }

    fn payload(&self) -> Value {
        to_value(&CapRightsPayload {
            amount_micros: self.amount_micros,
            is_override: self.is_override,
        })
    }

    fn parse(origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let k = Self::KIND;
        let [cap, month, to] = split_key::<3>(k, key)?;
        let (cap, month) = parse_cap_month(k, cap, month)?;
        let to =
            Recipient::parse(to).ok_or(invalid(k, "key recipient is not a device id or 'burn'"))?;
        let p: CapRightsPayload = from_payload(k, payload)?;
        if p.is_override && to != Recipient::Device(*origin) {
            return Err(invalid(k, "only a self-mint can be an override"));
        }
        Ok(Self {
            cap,
            month,
            to,
            amount_micros: p.amount_micros,
            is_override: p.is_override,
        })
    }
}

// ----------------------------------------------------------------- cap.used

/// `cap.used`, key = `<cap_id>/<YYYY-MM>`: the origin's cumulative spend
/// against the cap that month.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapUsed {
    pub cap: CapId,
    pub month: Month,
    pub epoch: u32,
    pub used_micros: u64,
}

#[derive(Serialize, Deserialize)]
struct CapUsedPayload {
    epoch: u32,
    used_micros: u64,
}

impl ItemKind for CapUsed {
    const KIND: &'static str = names::CAP_USED;

    fn item_key(&self) -> String {
        format!("{}/{}", self.cap, self.month)
    }

    fn payload(&self) -> Value {
        to_value(&CapUsedPayload {
            epoch: self.epoch,
            used_micros: self.used_micros,
        })
    }

    fn parse(_origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let [cap, month] = split_key::<2>(Self::KIND, key)?;
        let (cap, month) = parse_cap_month(Self::KIND, cap, month)?;
        let p: CapUsedPayload = from_payload(Self::KIND, payload)?;
        Ok(Self {
            cap,
            month,
            epoch: p.epoch,
            used_micros: p.used_micros,
        })
    }
}

// ------------------------------------------------------------- share.sealed

fn parse_share_key(kind: &'static str, key: &str) -> Result<(CredentialRef, DeviceId), MeshError> {
    let [cred, recipient] = split_key::<2>(kind, key)?;
    let cred =
        CredentialRef::parse(cred).map_err(|_| invalid(kind, "key has no credential ref"))?;
    let recipient =
        DeviceId::parse(recipient).map_err(|_| invalid(kind, "key has no recipient device"))?;
    Ok((cred, recipient))
}

/// `share.sealed`, key = `<credential_ref>/<recipient>` (Increment 11). The
/// credential value exists only inside `sealed`, a `crypto_box` sealed box
/// to the recipient's sealing key.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareSealed {
    pub credential: CredentialRef,
    pub recipient: DeviceId,
    pub share_id: ShareId,
    pub mesh_project_id: MeshProjectId,
    pub credential_name: String,
    pub provider: String,
    pub value_version: u64,
    pub sealed: Vec<u8>,
}

impl fmt::Debug for ShareSealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareSealed")
            .field("credential", &self.credential)
            .field("recipient", &self.recipient)
            .field("share_id", &self.share_id)
            .field("sealed_len", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct ShareSealedPayload {
    credential_name: String,
    mesh_project_id: MeshProjectId,
    provider: String,
    recipient: DeviceId,
    sealed: String,
    share_id: ShareId,
    value_version: u64,
}

impl ItemKind for ShareSealed {
    const KIND: &'static str = names::SHARE_SEALED;

    fn item_key(&self) -> String {
        format!("{}/{}", self.credential, self.recipient)
    }

    fn payload(&self) -> Value {
        to_value(&ShareSealedPayload {
            credential_name: self.credential_name.clone(),
            mesh_project_id: self.mesh_project_id,
            provider: self.provider.clone(),
            recipient: self.recipient,
            sealed: base64::engine::general_purpose::STANDARD.encode(&self.sealed),
            share_id: self.share_id,
            value_version: self.value_version,
        })
    }

    fn parse(_origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let k = Self::KIND;
        let (credential, recipient) = parse_share_key(k, key)?;
        let p: ShareSealedPayload = from_payload(k, payload)?;
        if p.recipient != recipient {
            return Err(invalid(k, "payload recipient does not match the key"));
        }
        if !valid_name(&p.credential_name) || !valid_slug(&p.provider) {
            return Err(invalid(k, "credential name or provider is malformed"));
        }
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(p.sealed.as_bytes())
            .map_err(|_| invalid(k, "sealed is not base64"))?;
        if sealed.is_empty() || sealed.len() > MAX_SEALED_BYTES {
            return Err(invalid(k, "sealed box is empty or too large"));
        }
        Ok(Self {
            credential,
            recipient,
            share_id: p.share_id,
            mesh_project_id: p.mesh_project_id,
            credential_name: p.credential_name,
            provider: p.provider,
            value_version: p.value_version,
            sealed,
        })
    }
}

// ------------------------------------------------------------- share.revoke

/// `share.revoke`, key = `<credential_ref>/<recipient>` (Increment 11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRevoke {
    pub credential: CredentialRef,
    pub recipient: DeviceId,
    pub share_id: ShareId,
}

#[derive(Serialize, Deserialize)]
struct ShareRevokePayload {
    share_id: ShareId,
}

impl ItemKind for ShareRevoke {
    const KIND: &'static str = names::SHARE_REVOKE;

    fn item_key(&self) -> String {
        format!("{}/{}", self.credential, self.recipient)
    }

    fn payload(&self) -> Value {
        to_value(&ShareRevokePayload {
            share_id: self.share_id,
        })
    }

    fn parse(_origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let (credential, recipient) = parse_share_key(Self::KIND, key)?;
        let p: ShareRevokePayload = from_payload(Self::KIND, payload)?;
        Ok(Self {
            credential,
            recipient,
            share_id: p.share_id,
        })
    }
}

// -------------------------------------------------------------- fork.report

/// `fork.report`, key = the forked device's id. Minted by a device that found
/// two different item hashes for one dot of that device (PROTOCOL.md §7): the
/// forked device's items at or above `seq` stop counting everywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkReport {
    pub device: DeviceId,
    /// The lowest seq at which the two hashes differ.
    pub seq: u64,
    pub hash_a: ItemHash,
    pub hash_b: ItemHash,
}

#[derive(Serialize, Deserialize)]
struct ForkReportPayload {
    hash_a: ItemHash,
    hash_b: ItemHash,
    seq: u64,
}

impl ItemKind for ForkReport {
    const KIND: &'static str = names::FORK_REPORT;

    fn item_key(&self) -> String {
        self.device.to_hex()
    }

    fn payload(&self) -> Value {
        to_value(&ForkReportPayload {
            hash_a: self.hash_a,
            hash_b: self.hash_b,
            seq: self.seq,
        })
    }

    fn parse(_origin: &DeviceId, key: &str, payload: &Value) -> Result<Self, MeshError> {
        let k = Self::KIND;
        let device = DeviceId::parse(key).map_err(|_| invalid(k, "key is not a device id"))?;
        let p: ForkReportPayload = from_payload(k, payload)?;
        if p.seq == 0 || p.hash_a == p.hash_b {
            return Err(invalid(
                k,
                "a fork needs a seq of at least 1 and two different hashes",
            ));
        }
        Ok(Self {
            device,
            seq: p.seq,
            hash_a: p.hash_a,
            hash_b: p.hash_b,
        })
    }
}

item_kind_try_from!(
    RosterAdd,
    RosterRemove,
    DeviceInfo,
    MeshSetting,
    ProjectMeta,
    UsageCounter,
    CapDef,
    CapTarget,
    CapRights,
    CapUsed,
    ShareSealed,
    ShareRevoke,
    ForkReport,
);

/// Any item, typed by its kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypedItem {
    RosterAdd(RosterAdd),
    RosterRemove(RosterRemove),
    DeviceInfo(DeviceInfo),
    MeshSetting(MeshSetting),
    ProjectMeta(ProjectMeta),
    UsageCounter(UsageCounter),
    CapDef(CapDef),
    CapTarget(CapTarget),
    CapRights(CapRights),
    CapUsed(CapUsed),
    ShareSealed(ShareSealed),
    ShareRevoke(ShareRevoke),
    ForkReport(ForkReport),
    /// A kind this version does not understand: stored and relayed opaquely.
    Unknown,
}

impl TypedItem {
    /// Parse `body` by its kind. A known kind with an invalid key or payload
    /// is an error; an unknown kind is [`TypedItem::Unknown`].
    pub fn parse(body: &ItemBody) -> Result<Self, MeshError> {
        Ok(match body.kind.as_str() {
            names::ROSTER_ADD => Self::RosterAdd(body.try_into()?),
            names::ROSTER_REMOVE => Self::RosterRemove(body.try_into()?),
            names::DEVICE_INFO => Self::DeviceInfo(body.try_into()?),
            names::MESH_SETTING => Self::MeshSetting(body.try_into()?),
            names::PROJECT_META => Self::ProjectMeta(body.try_into()?),
            names::USAGE_COUNTER => Self::UsageCounter(body.try_into()?),
            names::CAP_DEF => Self::CapDef(body.try_into()?),
            names::CAP_TARGET => Self::CapTarget(body.try_into()?),
            names::CAP_RIGHTS => Self::CapRights(body.try_into()?),
            names::CAP_USED => Self::CapUsed(body.try_into()?),
            names::SHARE_SEALED => Self::ShareSealed(body.try_into()?),
            names::SHARE_REVOKE => Self::ShareRevoke(body.try_into()?),
            names::FORK_REPORT => Self::ForkReport(body.try_into()?),
            _ => Self::Unknown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::codec::{decode_body, encode_body};
    use crate::mesh::sign::SigningKeyPair;
    use serde_json::json;

    fn mesh() -> MeshId {
        MeshId::from_bytes([0x11; 16])
    }
    fn dev(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    /// Encode, decode and re-parse: what a receiver would see.
    fn round_trip<T>(value: &T, origin: DeviceId) -> T
    where
        T: ItemKind + PartialEq + fmt::Debug + for<'a> TryFrom<&'a ItemBody, Error = MeshError>,
    {
        let body = value.to_body(mesh(), origin, 3, Hlc::new(1_000, 0));
        let bytes = encode_body(&body).unwrap();
        let back = decode_body(&bytes).unwrap();
        let typed = T::try_from(&back).unwrap();
        assert!(TypedItem::parse(&back).is_ok());
        typed
    }

    /// A valid add: the device id is derived from its keys.
    fn sample_add(origin: DeviceId) -> RosterAdd {
        let sign_pub = SigningKeyPair::from_secret_bytes(&[7; 32]).public_key();
        let (noise_pub, seal_pub) = (PublicKeyBytes([8; 32]), PublicKeyBytes([9; 32]));
        RosterAdd {
            device: derive_device_id(&sign_pub, &noise_pub, &seal_pub),
            name: "work laptop".into(),
            sign_pub,
            noise_pub,
            seal_pub,
            added_by: origin,
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let o = dev(1);
        let add = sample_add(o);
        assert_eq!(round_trip(&add, o), add);
        let rm = RosterRemove {
            device: dev(2),
            cutoff_seq: 41,
        };
        assert_eq!(round_trip(&rm, o), rm);
        let info = DeviceInfo {
            device: o,
            name: "desk".into(),
            listen_addrs: vec!["100.64.0.2:7420".into(), "laptop.tail1.ts.net:7420".into()],
        };
        assert_eq!(round_trip(&info, o), info);
        let setting = MeshSetting {
            name: "retention_days".into(),
            value: json!(400),
        };
        assert_eq!(round_trip(&setting, o), setting);
        let proj = ProjectMeta {
            project: MeshProjectId::from_bytes([3; 16]),
            name: "Billing".into(),
            archived: false,
            merged_into: Some(MeshProjectId::from_bytes([4; 16])),
        };
        assert_eq!(round_trip(&proj, o), proj);
        let usage = UsageCounter {
            key: UsageKey {
                project: MeshProjectId::from_bytes([3; 16]),
                day: Day::parse("2026-10-26").unwrap(),
                provider: "fireworks".into(),
                model: "accounts/fireworks/models/llama-v3".into(),
            },
            epoch: 2,
            totals: UsageTotals {
                requests: 10,
                priced_requests: 8,
                unpriced_requests: 1,
                unextracted_requests: 1,
                input_tokens: 1_000,
                output_tokens: 500,
                cached_input_tokens: 0,
                estimated_cost_micros: 12_345,
            },
        };
        assert_eq!(round_trip(&usage, o), usage);
        let cap = CapId::from_bytes([5; 16]);
        let def = CapDef {
            cap,
            mesh_project_id: MeshProjectId::from_bytes([3; 16]),
            owner_device: o,
            created_hlc: Hlc::new(1_000, 0),
        };
        assert_eq!(round_trip(&def, o), def);
        let month = Month::parse("2026-10").unwrap();
        let target = CapTarget {
            cap,
            month,
            target_micros: 50_000_000,
        };
        assert_eq!(round_trip(&target, o), target);
        for to in [
            Recipient::Burn,
            Recipient::Device(dev(2)),
            Recipient::Device(o),
        ] {
            let rights = CapRights {
                cap,
                month,
                to,
                amount_micros: 1_000,
                is_override: false,
            };
            assert_eq!(round_trip(&rights, o), rights);
        }
        let over = CapRights {
            cap,
            month,
            to: Recipient::Device(o),
            amount_micros: 9,
            is_override: true,
        };
        assert_eq!(round_trip(&over, o), over);
        let used = CapUsed {
            cap,
            month,
            epoch: 0,
            used_micros: 77,
        };
        assert_eq!(round_trip(&used, o), used);
        let sealed = ShareSealed {
            credential: CredentialRef::from_bytes([6; 16]),
            recipient: dev(2),
            share_id: ShareId::from_bytes([7; 16]),
            mesh_project_id: MeshProjectId::from_bytes([3; 16]),
            credential_name: "OPENAI_API_KEY".into(),
            provider: "openai".into(),
            value_version: 3,
            sealed: vec![0xEE; 80],
        };
        assert_eq!(round_trip(&sealed, o), sealed);
        let revoke = ShareRevoke {
            credential: CredentialRef::from_bytes([6; 16]),
            recipient: dev(2),
            share_id: ShareId::from_bytes([7; 16]),
        };
        assert_eq!(round_trip(&revoke, o), revoke);
        let fork = ForkReport {
            device: dev(2),
            seq: 11,
            hash_a: ItemHash([1; 32]),
            hash_b: ItemHash([2; 32]),
        };
        assert_eq!(round_trip(&fork, o), fork);
    }

    #[test]
    fn origin_bindings_are_enforced() {
        let add = sample_add(dev(1));
        let body = add.to_body(mesh(), dev(9), 1, Hlc::ZERO);
        assert!(matches!(
            RosterAdd::try_from(&body),
            Err(MeshError::InvalidPayload { .. })
        ));
        let info = DeviceInfo {
            device: dev(1),
            name: "x".into(),
            listen_addrs: vec![],
        };
        let body = info.to_body(mesh(), dev(2), 1, Hlc::ZERO);
        assert!(
            DeviceInfo::try_from(&body).is_err(),
            "a device describes only itself"
        );
        let def = CapDef {
            cap: CapId::from_bytes([5; 16]),
            mesh_project_id: MeshProjectId::from_bytes([3; 16]),
            owner_device: dev(1),
            created_hlc: Hlc::ZERO,
        };
        assert!(CapDef::try_from(&def.to_body(mesh(), dev(2), 1, Hlc::ZERO)).is_err());
        let over = CapRights {
            cap: CapId::from_bytes([5; 16]),
            month: Month::parse("2026-10").unwrap(),
            to: Recipient::Device(dev(2)),
            amount_micros: 1,
            is_override: true,
        };
        assert!(CapRights::try_from(&over.to_body(mesh(), dev(1), 1, Hlc::ZERO)).is_err());
    }

    #[test]
    fn a_roster_add_whose_id_is_not_derived_from_its_keys_is_refused() {
        let mut add = sample_add(dev(1));
        add.device = dev(2);
        assert!(RosterAdd::try_from(&add.to_body(mesh(), dev(1), 1, Hlc::ZERO)).is_err());
        let mut add = sample_add(dev(1));
        add.seal_pub = PublicKeyBytes([10; 32]); // same id, other keys: a hijack attempt
        assert!(RosterAdd::try_from(&add.to_body(mesh(), dev(1), 1, Hlc::ZERO)).is_err());
    }

    #[test]
    fn a_fork_report_needs_two_different_hashes() {
        let same = ForkReport {
            device: dev(2),
            seq: 3,
            hash_a: ItemHash([1; 32]),
            hash_b: ItemHash([1; 32]),
        };
        assert!(ForkReport::try_from(&same.to_body(mesh(), dev(1), 1, Hlc::ZERO)).is_err());
    }

    #[test]
    fn weak_signing_key_in_roster_add_is_refused() {
        let mut add = sample_add(dev(1));
        let mut identity = [0u8; 32];
        identity[0] = 1;
        add.sign_pub = PublicKeyBytes(identity);
        let body = add.to_body(mesh(), dev(1), 1, Hlc::ZERO);
        assert!(RosterAdd::try_from(&body).is_err());
    }

    #[test]
    fn kind_mismatch_and_unknown_kinds() {
        let rm = RosterRemove {
            device: dev(2),
            cutoff_seq: 1,
        };
        let body = rm.to_body(mesh(), dev(1), 1, Hlc::ZERO);
        assert!(matches!(
            RosterAdd::try_from(&body),
            Err(MeshError::KindMismatch { .. })
        ));
        let future = ItemBody::new(
            mesh(),
            dev(1),
            1,
            Hlc::ZERO,
            "alert.rule",
            "whatever",
            json!({"anything": [1, 2, 3]}),
        );
        assert_eq!(TypedItem::parse(&future).unwrap(), TypedItem::Unknown);
        assert!(!is_known_kind("alert.rule"));
        assert!(KNOWN_KINDS.iter().all(|k| is_known_kind(k)));
    }

    #[test]
    fn extra_payload_fields_are_tolerated_for_forward_compatibility() {
        let body = ItemBody::new(
            mesh(),
            dev(1),
            1,
            Hlc::ZERO,
            names::ROSTER_REMOVE,
            dev(2).to_hex(),
            json!({"cutoff_seq": 5, "reason": "lost"}),
        );
        assert_eq!(RosterRemove::try_from(&body).unwrap().cutoff_seq, 5);
    }

    #[test]
    fn malformed_keys_and_payloads_are_refused() {
        let cases = [
            (names::USAGE_COUNTER, "nothex/2026-10-26/openai/gpt"),
            (
                names::USAGE_COUNTER,
                "03030303030303030303030303030303/2026-13-01/openai/gpt",
            ),
            (
                names::USAGE_COUNTER,
                "03030303030303030303030303030303/2026-10-26/OpenAI/gpt",
            ),
            (
                names::USAGE_COUNTER,
                "03030303030303030303030303030303/2026-10-26/openai",
            ),
            (names::CAP_TARGET, "05050505050505050505050505050505/2026-1"),
            (
                names::CAP_RIGHTS,
                "05050505050505050505050505050505/2026-10/nobody",
            ),
            (names::MESH_SETTING, "Retention Days"),
            (names::PROJECT_META, "03030303030303030303030303030303"),
        ];
        for (kind, key) in cases {
            let body = ItemBody::new(mesh(), dev(1), 1, Hlc::ZERO, kind, key, json!({}));
            assert!(TypedItem::parse(&body).is_err(), "{kind} {key}");
        }
    }

    #[test]
    fn days_and_months_are_canonical() {
        assert_eq!(Day::parse("2024-02-29").unwrap().to_string(), "2024-02-29");
        assert!(Day::parse("2023-02-29").is_none());
        assert!(Day::parse("2026-1-01").is_none());
        assert!(Day::parse("+2026-01-01").is_none());
        assert_eq!(
            Day::parse("2026-10-26").unwrap().month(),
            Month::parse("2026-10").unwrap()
        );
        assert_eq!(
            Month::parse("2026-12").unwrap().next().unwrap().to_string(),
            "2027-01"
        );
        assert!(Month::parse("2026-00").is_none());
        assert!(Month::parse("2026-13").is_none());
        assert!(Month::parse("26-10").is_none());
    }

    #[test]
    fn share_debug_never_prints_the_sealed_bytes() {
        let sealed = ShareSealed {
            credential: CredentialRef::from_bytes([6; 16]),
            recipient: dev(2),
            share_id: ShareId::from_bytes([7; 16]),
            mesh_project_id: MeshProjectId::from_bytes([3; 16]),
            credential_name: "KEY".into(),
            provider: "openai".into(),
            value_version: 1,
            sealed: vec![0xAB; 48],
        };
        let rendered = format!("{sealed:?}");
        assert!(!rendered.contains("171"), "{rendered}");
        assert!(!rendered.contains("abab"), "{rendered}");
    }
}
