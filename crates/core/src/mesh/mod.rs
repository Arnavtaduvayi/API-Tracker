//! Tethra Mesh: peer-to-peer replication between one user's own paired
//! devices (ADR 0031).
//!
//! The protocol layer is **sans-IO**: `proto`, `views`, `store`, `memstore`,
//! `chain` and the CRDTs open no sockets, files or threads, and read time
//! only through the injected [`clock::Clock`]. Only the storage modules
//! (`sqlite_store`, `marker`, `identity`, `membership`) touch the disk; no
//! module here touches the network. The network code
//! lives in its own crate and drives these types; the simulator drives them
//! over a simulated network. The normative specification is
//! `docs/mesh/PROTOCOL.md`; where this code and that document disagree, it
//! is a bug in one of them.
//!
//! What is here today:
//! - Increment 01: identifiers and dots ([`dot`]), version vectors ([`vv`]),
//!   the hybrid logical clock ([`hlc`]), the canonical item codec
//!   ([`codec`]), Ed25519 item signing ([`sign`], [`item`]), typed payloads
//!   for every kind ([`kinds`]) and the four CRDTs ([`crdt`]).
//! - Increment 02: the replication session as a pure state machine
//!   ([`proto`]) over the [`store::MeshStore`] trait and its in-memory
//!   implementation ([`memstore`]), dot chains ([`chain`]), the materialized
//!   views ([`views`]), and — behind the `mesh-sim` feature — the
//!   deterministic simulator and the independent oracle (`sim`).
//!
//! - Increment 03: the SQLite store ([`sqlite_store`], migration v21), the
//!   device identity with its encrypted keys and the restore wipe
//!   ([`identity`]), and the clone/rollback marker ([`marker`]).
//!
//! - Increment 04: invites and pairing messages ([`invite`]), and membership
//!   ([`membership`]): joining, the inviter's single-use claim, devices,
//!   removal with access-key rotation, leave, the exchange log, and the
//!   `MeshVault` capability a node holds. The network code that uses them is
//!   the `api-tracker-mesh` crate.
//!
//! The node runtime follows in Increment 05; see
//! `docs/mesh/increments/STATUS.md`.

pub mod chain;
pub mod clock;
pub mod codec;
pub mod crdt;
pub mod dot;
pub mod error;
pub mod hlc;
pub mod identity;
pub mod invite;
pub mod item;
pub mod kinds;
pub mod marker;
pub mod membership;
pub mod memstore;
pub mod proto;
pub mod sign;
pub mod sqlite_store;
pub mod store;
pub mod views;
pub mod vv;

#[cfg(any(test, feature = "mesh-sim"))]
pub mod sim;

pub use dot::{DeviceId, Dot, MeshId};
pub use error::MeshError;
pub use hlc::Hlc;
pub use item::{ItemHash, SignedItem};
pub use vv::VersionVector;
