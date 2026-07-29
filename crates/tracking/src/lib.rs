//! The tracking orchestrator (ADR 0022): one engine behind the desktop's
//! "Track API activity" flow and the `tethra track` CLI family.
//!
//! This crate composes proven components — it does not reimplement them.
//! Detection fuses `stackdetect`, `envgov`, the scanner's manifest
//! knowledge, and vault-side signals over ONE user-selected folder; the
//! plan aggregates `envlink` link plans, route actions, and service
//! actions; apply drives the existing lifecycle/routes/envlink/control
//! APIs in their required order; verification separates the synthetic path
//! proof (keyless probe) from the real traffic proof (`traffic_observed`
//! requires a recorded gateway observation). The persisted state machine
//! (`tracking_setups`, migration v15) is re-derived on every read so a
//! stale row can never overclaim.
//!
//! Boundaries (ADR 0022 D10): this crate never opens a listening socket,
//! never parses HTTP, never reads credential values, never edits files
//! outside approved `envlink` plans, never deletes recorded history, and
//! performs no network calls other than the keyless probe through the
//! local gateway.

#![forbid(unsafe_code)]

pub mod apply;
pub mod detect;
pub mod diagnose;
pub mod health;
pub mod origin;
pub mod plan;
pub mod state;
pub mod undo;
pub mod verify;

pub use api_tracker_core::{CoreError, Result};
