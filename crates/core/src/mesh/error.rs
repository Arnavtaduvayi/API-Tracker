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
        }
    }
}
