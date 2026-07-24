//! Runtime API observability: local, metadata-only storage and analysis of
//! traffic observed by the [`api-tracker-observe`](../../../observe) proxy.
//!
//! This module tree owns everything about observed traffic that is NOT the
//! network path itself: the sanitizer at the persistence boundary
//! ([`sanitize`]), the encrypted-at-rest data model and SQLite access, the
//! credential attribution logic, bounded-memory aggregation, the API
//! inventory, retention, and the observability alert rules.
//!
//! Invariants enforced across this module tree:
//! - Nothing here stores request/response bodies, header values, cookies,
//!   authorization values, query strings, or raw URLs. Only the fields in
//!   `docs/observability/RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md` §1 are
//!   persisted, and only after [`sanitize::sanitize_path`].
//! - Locally observed traffic is stored in the `runtime_*` /
//!   `observation_*` / `observed_*` tables and is NEVER written into
//!   `usage_snapshots` (whose totals would then double-count against
//!   provider-reported sync).

pub mod model;
pub mod sanitize;
pub mod store;
