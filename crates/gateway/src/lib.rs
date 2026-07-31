//! `api-tracker-gateway`: the Local Gateway — an OPTIONAL, loopback-only,
//! path-prefix reverse gateway for local API observation (ADR 0019).
//!
//! `http://127.0.0.1:<port>/openai/v1/...` forwards to
//! `https://api.openai.com/v1/...` over certificate-verified rustls with the
//! caller's OWN credential passed through untouched. The gateway records
//! sanitized metadata and bounded, best-effort usage through the existing
//! runtime funnel — never request/response bodies, header values, cookies,
//! query strings, credential values, or raw URLs
//! (`docs/gateway/PRIVACY_MODEL.md`).
//!
//! # What this crate deliberately is NOT
//! - Not a TLS terminator toward clients and not a certificate authority:
//!   it never links observe's CA/server-TLS modules (SI-6).
//! - Not an open relay: no CONNECT, no absolute-form targets, no
//!   client-supplied upstream; only registered provider origins (SI-2).
//! - Not vault-dependent: forwarding continues while the vault is locked
//!   because the forward path holds no vault key material (SI-11/13, ADR
//!   0019 D4).
//!
//! # Security surface
//! This is the first Tethra component that terminates client connections
//! carrying live third-party credentials. Its invariants live in
//! `docs/gateway/SECURITY_INVARIANTS.md`; every named SI-N is enforced by
//! construction here and verified by the test suite. Like core and observe,
//! this crate forbids `unsafe`.

#![forbid(unsafe_code)]

pub mod attribution;
pub mod control;
pub mod doctor;
pub mod envlink;
pub mod forward;
pub mod head;
pub mod lifecycle;
pub mod record;
pub mod routes;
pub mod server;
pub mod service;
pub mod store;
pub mod stream;
pub mod upstream;
pub mod usage;
pub mod writer;
