//! Test and simulation support for the mesh (feature `mesh-sim`).
//!
//! Compiled only for this crate's unit tests and when the `mesh-sim` feature
//! is on (the self dev-dependency in `Cargo.toml` turns it on for
//! `tests/`). Release builds carry none of it. Increment 02 adds the
//! deterministic network simulator and the independent oracle here.

pub mod rng;
