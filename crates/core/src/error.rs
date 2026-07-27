use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

/// Typed errors for the Tethra core.
///
/// Error messages must never contain secret material. Variants carry
/// identifiers, names, and paths only; cryptographic failures carry a static
/// context string describing *what* failed, never key or plaintext bytes.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("incorrect password")]
    WrongPassword,

    #[error("a vault already exists at {0}")]
    VaultExists(PathBuf),

    #[error("no vault found at {0} (create one with `tethra init` or the desktop app)")]
    VaultNotFound(PathBuf),

    #[error("the vault is locked; unlock it first")]
    VaultLocked,

    #[error("project '{0}' is password-locked; unlock it first")]
    ProjectLocked(String),

    #[error("no active session; run `tethra unlock` first")]
    SessionMissing,

    #[error("the session has expired (auto-lock); run `tethra unlock` again")]
    SessionExpired,

    #[error("the session token is not valid for the current session")]
    SessionInvalid,

    #[error("{kind} '{ident}' was not found")]
    NotFound { kind: &'static str, ident: String },

    #[error("{kind} '{ident}' is ambiguous; use its full id")]
    Ambiguous { kind: &'static str, ident: String },

    #[error("{kind} named '{ident}' already exists")]
    AlreadyExists { kind: &'static str, ident: String },

    #[error("credential is referenced by {0} linked credential(s); remove the references first")]
    HasLinkedReferences(usize),

    #[error("cannot create reference: {0}")]
    InvalidLink(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("decryption failed for {context}: wrong key/password, corrupted data, or tampering")]
    Crypto { context: &'static str },

    #[error("another Tethra process is writing to the vault; try again")]
    Busy,

    #[error("backup file is not valid: {0}")]
    BackupInvalid(String),

    #[error("the vault database is damaged: {0}")]
    VaultCorrupted(&'static str),

    #[error(
        "this vault uses database schema v{found}, but this build supports up to v{supported} — \
         it was created or upgraded by a newer version of Tethra; upgrade this installation \
         instead of opening the vault with an older build"
    )]
    SchemaTooNew { found: i64, supported: i64 },

    #[error(
        "the vault database is at schema v{found}, but this component requires v{supported}; \
         unlock the vault with the app or CLI once to apply pending migrations"
    )]
    SchemaNotCurrent { found: i64, supported: i64 },

    #[error("{provider} does not support '{capability}' this way: {hint}")]
    Unsupported {
        provider: String,
        capability: &'static str,
        hint: String,
    },

    #[error("provider request failed: {0}")]
    Provider(String),

    #[error("{provider} rejected the credential ({detail}); reconnect with a valid admin key")]
    ProviderAuth { provider: String, detail: String },

    #[error("{provider} is rate limiting requests; try again later")]
    ProviderRateLimited {
        provider: String,
        retry_after_secs: Option<u64>,
    },

    #[error("network unavailable: {0}")]
    Network(String),

    #[error("key derivation failed (unsupported KDF parameters)")]
    Kdf,

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl CoreError {
    /// Stable machine-readable code, used by the desktop frontend and the
    /// CLI's JSON output mode.
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::WrongPassword => "wrong_password",
            CoreError::VaultExists(_) => "vault_exists",
            CoreError::VaultNotFound(_) => "vault_not_found",
            CoreError::VaultLocked => "vault_locked",
            CoreError::ProjectLocked(_) => "project_locked",
            CoreError::SessionMissing => "session_missing",
            CoreError::SessionExpired => "session_expired",
            CoreError::SessionInvalid => "session_invalid",
            CoreError::NotFound { .. } => "not_found",
            CoreError::Ambiguous { .. } => "ambiguous",
            CoreError::AlreadyExists { .. } => "already_exists",
            CoreError::HasLinkedReferences(_) => "has_linked_references",
            CoreError::InvalidLink(_) => "invalid_link",
            CoreError::InvalidInput(_) => "invalid_input",
            CoreError::Crypto { .. } => "crypto_error",
            CoreError::Busy => "vault_busy",
            CoreError::BackupInvalid(_) => "backup_invalid",
            CoreError::VaultCorrupted(_) => "vault_corrupted",
            CoreError::SchemaTooNew { .. } => "schema_too_new",
            CoreError::SchemaNotCurrent { .. } => "schema_not_current",
            CoreError::Unsupported { .. } => "unsupported",
            CoreError::Provider(_) => "provider_error",
            CoreError::ProviderAuth { .. } => "provider_auth_error",
            CoreError::ProviderRateLimited { .. } => "provider_rate_limited",
            CoreError::Network(_) => "network_error",
            CoreError::Kdf => "kdf_error",
            CoreError::Db(_) => "db_error",
            CoreError::Io(_) => "io_error",
            CoreError::Serde(_) => "serde_error",
        }
    }
}
