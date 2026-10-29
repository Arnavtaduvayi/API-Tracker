//! Spend caps (Increment 07, DESIGN §D15, ADR 0032): a replicated monthly
//! ceiling on **gateway-estimated** cost for one mesh project, kept across
//! every paired device without coordination by the bounded counter of
//! [`crate::mesh::crdt::bounded`] (Balegas et al., SRDS 2015).
//!
//! Each device holds *rights* (micro-USD it may spend this month) and spends
//! only its own. The cap's owner, the device that created it, mints the
//! month's target and pre-distributes equal shares to the devices active in
//! the last 30 days; from the 20th it mints next month in advance, so a
//! device offline across the month boundary is not stranded. Devices low on
//! rights ask a peer for some (`RightsRequest`, a point-to-point message);
//! a peer with a surplus grants part of it. A partitioned device stays
//! capped: it can spend only what it holds (safety over liveness).
//!
//! **Raise** adds (the owner mints more; elsewhere it is a labelled local
//! override). **Lower** sets the last-writer-wins target; holders burn what
//! they hold above their new share, and the owner reclaims the rest.
//! **Freeze**: when the owner device is removed nobody mints for the cap
//! again.
//!
//! Every decision is made inside the write transaction that publishes it
//! ([`crate::mesh::sqlite_store::SqliteStore::mint_with`]), from the state
//! and the local gateway figures as they are then, so a running node and a
//! CLI command can never both act on one snapshot. Every transfer and burn
//! goes through the escrow fence ([`escrow`], MESH-SI-10).
//!
//! Caps raise alerts on every device ([`alerts`]). Where the user switches
//! enforcement on (reauthenticated, per cap, per device), the local gateway
//! refuses requests over the cap from the snapshot [`gate`] provides
//! (Increment 08). Caps are a self-limit, not a security
//! boundary: anything that does not pass through the gateway is not capped.
//! They are never budgets: `crate::budget` is the separate provider and
//! manual-usage alert feature, and the two never share figures (SI-19).

pub mod alerts;
pub mod escrow;
pub mod gate;
pub mod ops;
pub mod period;
pub mod policy;
pub mod reconcile;
pub mod view;

pub use escrow::{AssumeNotRunning, AssumeRunning, Fence, GatewayProbe};
pub use ops::{create, lower, raise, reclaim, resolve, try_spend, CapCreated, SpendDecision};
pub use reconcile::{grant, reconcile, rights_requests, ReconcileReport, RightsAsk};
pub use view::{report, CapInfo, CapReport};
