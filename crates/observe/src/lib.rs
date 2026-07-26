//! `api-tracker-observe`: the runtime-observation proxy and local certificate
//! authority.
//!
//! This crate provides an OPT-IN, loopback-only, per-session, authenticated
//! HTTP/HTTPS interception proxy used to observe the API traffic of a single
//! explicitly-launched child process (and its descendants), extracting only
//! sanitized metadata. It never records request or response bodies, header
//! values, cookies, authorization values, query strings, or raw URLs — see
//! `docs/observability/RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md`.
//!
//! # Security surface
//! Unlike the rest of the workspace this crate opens listening sockets,
//! terminates TLS, and handles a certificate-authority private key. It is a
//! separate crate precisely so that surface has its own review boundary. Like
//! the core crate it forbids `unsafe`.
//!
//! # Module map
//! - [`policy`] — destination policy: the SSRF / private-range / cloud-metadata
//!   denial applied to every CONNECT target both before and after DNS.
//!
//! Further modules (certificate authority, TLS, wire parsing, streaming relay,
//! proxy listener, scoped-trust adapters, diagnostics) are added on top of this
//! foundation.

#![forbid(unsafe_code)]

pub mod ca;
pub mod clienthello;
pub mod diagnostics;
pub mod policy;
pub mod proxy;
pub mod relay;
pub mod session;
pub mod systemtrust;
pub mod tls;
pub mod trust;
pub mod wire;

/// User-agent-style identity for any diagnostic self-probe this crate makes.
/// A request header, not a persisted identifier, so it follows the product
/// name (matching `tethra/0.1 (+local)` in the core HTTP client) rather than
/// the preserved `api-tracker` data namespace — see
/// `docs/rebrand/TETHRA_COMPATIBILITY_MATRIX.md`.
pub const OBSERVE_CLIENT_TAG: &str = "tethra-observe/0.1 (+local)";
