//! Typed errors for the mesh layer.
//!
//! Like [`crate::error::CoreError`], messages carry identifiers, sizes and
//! static context only. They never carry key material, invite tokens, item
//! payloads or credential values — a malformed item's bytes are attacker
//! controlled, so even parse errors are reduced to a static description
//! instead of echoing what the parser saw.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MeshError {
    #[error("mesh item is {size} bytes; the limit is {max}")]
    ItemTooLarge { size: usize, max: usize },

    #[error("mesh item is malformed: {0}")]
    Malformed(&'static str),

    #[error("mesh item is not in canonical form")]
    NonCanonical,

    #[error("mesh item format v{0} is not supported by this version of Tethra")]
    UnsupportedFormat(u64),

    #[error("mesh item belongs to a different mesh")]
    WrongMesh,

    #[error("mesh item signature does not verify")]
    BadSignature,

    #[error("invalid {kind} item: {reason}")]
    InvalidPayload {
        kind: &'static str,
        reason: &'static str,
    },

    #[error("item kind is '{found}', expected '{expected}'")]
    KindMismatch {
        expected: &'static str,
        found: String,
    },

    #[error("invalid mesh identifier: expected 32 lowercase hexadecimal characters")]
    InvalidId,

    #[error("invalid public key")]
    InvalidKey,

    #[error("the two rosters belong to different meshes (genesis devices differ)")]
    GenesisMismatch,

    #[error("not enough spend-cap rights: {available} micro-USD available, {requested} requested")]
    InsufficientRights { available: i128, requested: u64 },

    #[error("invalid spend-cap operation: {0}")]
    InvalidOperation(&'static str),

    /// The local mesh database failed. The context is static; SQLite's own
    /// message is not carried, so a value from a row can never surface here.
    #[error("local mesh storage failed: {0}")]
    Storage(&'static str),

    #[error("this device is not part of a mesh; run `tethra mesh init` to start one")]
    NotInitialized,

    #[error("this device is already part of a mesh; run `tethra mesh leave` before starting or joining another")]
    AlreadyInMesh,

    /// The identity marker does not vouch for this database: it is missing,
    /// belongs to another installation, or records seqs the database does
    /// not have (DESIGN §D5, PROTOCOL.md §7.5).
    #[error("this device's mesh identity cannot be trusted: {0}; run `tethra mesh leave` and pair again")]
    IdentityMismatch(&'static str),

    #[error("a device name must be 1-64 characters without control characters")]
    InvalidDeviceName,

    #[error("this device's mesh identity has forked (another installation used the same identity); run `tethra mesh leave` and pair again")]
    Forked,
}

impl MeshError {
    /// Stable machine-readable code, surfaced through
    /// [`crate::error::CoreError::code`] for the CLI's `--json` mode and the
    /// desktop frontend.
    pub fn code(&self) -> &'static str {
        match self {
            MeshError::ItemTooLarge { .. } => "mesh_item_too_large",
            MeshError::Malformed(_) => "mesh_item_malformed",
            MeshError::NonCanonical => "mesh_item_non_canonical",
            MeshError::UnsupportedFormat(_) => "mesh_item_unsupported_format",
            MeshError::WrongMesh => "mesh_wrong_mesh",
            MeshError::BadSignature => "mesh_bad_signature",
            MeshError::InvalidPayload { .. } => "mesh_invalid_payload",
            MeshError::KindMismatch { .. } => "mesh_kind_mismatch",
            MeshError::InvalidId => "mesh_invalid_id",
            MeshError::InvalidKey => "mesh_invalid_key",
            MeshError::GenesisMismatch => "mesh_genesis_mismatch",
            MeshError::InsufficientRights { .. } => "mesh_insufficient_rights",
            MeshError::InvalidOperation(_) => "mesh_invalid_operation",
            MeshError::Storage(_) => "mesh_storage",
            MeshError::NotInitialized => "mesh_not_initialized",
            MeshError::AlreadyInMesh => "mesh_already_in_mesh",
            MeshError::IdentityMismatch(_) => "mesh_identity_mismatch",
            MeshError::InvalidDeviceName => "mesh_invalid_device_name",
            MeshError::Forked => "mesh_forked",
        }
    }
}
