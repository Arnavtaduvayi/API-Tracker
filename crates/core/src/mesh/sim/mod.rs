//! Test and simulation support for the mesh (feature `mesh-sim`).
//!
//! Compiled only for this crate's unit tests and when the `mesh-sim` feature
//! is on (the self dev-dependency in `Cargo.toml` turns it on for
//! `tests/`). Release builds carry none of it.
//!
//! - [`rng`]: the seeded PRNG every randomized test uses.
//! - [`oracle_api`]: the contract between the simulator and the oracle.
//! - [`oracle`]: the independent oracle.

pub mod oracle;
pub mod oracle_api;
pub mod rng;
