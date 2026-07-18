//! api-tracker-core: shared security-sensitive core for the API Tracker
//! desktop application and CLI.
//!
//! This crate owns the encrypted vault, the SQLite database and migrations,
//! the project and credential models, credential status evaluation, reuse
//! detection, encrypted backups, and the CLI session mechanism. The desktop
//! app and the CLI must both go through this crate so that they share exactly
//! the same vault format and business rules.
//!
//! Security invariants enforced here:
//! - Credential values only exist in plaintext inside [`secret::SecretString`]
//!   buffers, which redact themselves in `Debug`/`Display`/`Serialize` output
//!   and zeroize their memory on drop.
//! - All ciphertext is produced with XChaCha20-Poly1305 (authenticated
//!   encryption) and bound to contextual associated data (vault, project and
//!   credential identifiers plus a schema version).
//! - Passwords are never stored; they are stretched with Argon2id and used
//!   only to wrap random keys.
//! - This crate performs no network I/O and no logging of secret material.

#![forbid(unsafe_code)]

pub mod access;
pub mod activity;
pub mod alerts;
pub mod audit;
pub mod backup;
pub mod budget;
pub mod clock;
pub mod connectors;
pub mod crypto;
pub mod db;
pub mod destinations;
pub mod docwatch;
pub mod envfile;
pub mod envgov;
pub mod error;
pub mod gitrepo;
pub mod hooks;
pub mod http;
pub mod inject;
pub mod model;
pub mod monitor;
pub mod openai;
pub mod permissions;
pub mod pricing;
pub mod providers;
pub mod reuse;
pub mod rotation;
pub mod scanner;
pub mod secret;
pub mod session;
pub mod settings;
pub mod status;
pub mod syncplan;
pub mod usage;
pub mod vault;

pub use error::{CoreError, Result};
