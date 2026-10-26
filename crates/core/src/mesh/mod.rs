//! Tethra Mesh: peer-to-peer replication between one user's own paired
//! devices (ADR 0031).
//!
//! This layer is **sans-IO**: it opens no sockets, files or threads, and it
//! reads time only through the injected [`clock::Clock`]. The network code
//! lives in its own crate and drives these types; the simulator drives them
//! over a simulated network. The normative specification is
//! `docs/mesh/PROTOCOL.md`; where this code and that document disagree, it
//! is a bug in one of them.
//!
//! What is here today (Increment 01): identifiers and dots ([`dot`]),
//! version vectors ([`vv`]), the hybrid logical clock ([`hlc`]), the
//! canonical item codec ([`codec`]), Ed25519 item signing ([`sign`],
//! [`item`]), typed payloads for every v1 kind ([`kinds`]), and the four
//! CRDTs ([`crdt`]). Replication sessions, storage and views follow in later
//! increments; see `docs/mesh/increments/STATUS.md`.

pub mod clock;
pub mod codec;
pub mod crdt;
pub mod dot;
pub mod error;
pub mod hlc;
pub mod item;
pub mod kinds;
pub mod sign;
pub mod vv;

#[cfg(any(test, feature = "mesh-sim"))]
pub mod sim;

pub use dot::{DeviceId, Dot, MeshId};
pub use error::MeshError;
pub use hlc::Hlc;
pub use item::{ItemHash, SignedItem};
pub use vv::VersionVector;
