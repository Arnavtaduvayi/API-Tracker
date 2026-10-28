//! api-tracker-mesh: the network side of Tethra Mesh (ADR 0031).
//!
//! `api-tracker-core::mesh` holds the protocol as a pure state machine and the
//! SQLite store; this crate carries it over Noise on TCP between the user's
//! own paired devices. There is no server, relay or rendezvous: devices dial
//! each other directly, on a LAN or a VPN the user runs.
//!
//! - [`bind`]: the only socket-binding function (MESH-SI-1).
//! - [`noise`]: the session (`XXpsk0`) and pairing (`XXpsk3`) handshakes.
//! - [`wire`]: preamble, length-prefixed Noise messages, 1 MiB frames.
//! - [`handshake`]: member-session authentication against the active roster
//!   (MESH-SI-2).
//! - [`session`]: one replication exchange over an authenticated channel.
//! - [`pair`]: joining with an invite, and the inviter's answer.
//! - [`serve`]: the accept loop; [`replicate`]: a one-shot outbound exchange.
//! - [`directs`]: point-to-point messages (access-key rotation).
//! - [`node`]: the state every connection shares, and the transport limits.

#![forbid(unsafe_code)]

pub mod bind;
pub mod directs;
pub mod error;
pub mod handshake;
pub mod node;
pub mod noise;
pub mod pair;
pub mod replicate;
pub mod serve;
pub mod session;
pub mod wire;

pub use error::{NetError, NetResult};
pub use node::{MeshNode, TransportLimits};
