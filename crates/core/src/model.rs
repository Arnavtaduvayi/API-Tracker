//! Data model types shared by the desktop app and CLI.
//!
//! These are the *presentation* records returned by the vault API. Secret
//! values never appear here: credentials expose only a masked value.

use crate::error::{CoreError, Result};
use crate::status::StatusReport;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Environment classification for projects and credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Test,
    Staging,
    Production,
}

impl Environment {
    pub const ALL: [Environment; 4] = [
        Environment::Development,
        Environment::Test,
        Environment::Staging,
        Environment::Production,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Development => "development",
            Environment::Test => "test",
            Environment::Staging => "staging",
            Environment::Production => "production",
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Environment {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Environment::Development),
            "test" => Ok(Environment::Test),
            "staging" => Ok(Environment::Staging),
            "production" | "prod" => Ok(Environment::Production),
            other => Err(CoreError::InvalidInput(format!(
                "unknown environment '{other}'; expected development, test, staging, or production"
            ))),
        }
    }
}

/// A project: a folder of credential records.
#[derive(Debug, Clone, Serialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: String,
    pub notes: String,
    pub environments: Vec<Environment>,
    pub repo_paths: Vec<String>,
    pub archived: bool,
    /// Whether this project has an additional password lock configured.
    pub password_locked: bool,
    /// For password-locked projects: whether its key is currently available
    /// in this session. Always `true` for projects without a password lock.
    pub unlocked: bool,
    pub created_at: String,
    pub updated_at: String,
    pub credential_count: i64,
}

/// A credential record. `masked_value` is the only representation of the
/// secret that ever leaves the core outside an explicit reveal.
#[derive(Debug, Clone, Serialize)]
pub struct Credential {
    pub id: String,
    pub project_id: String,
    pub project_name: String,
    pub provider: String,
    pub name: String,
    pub environment: Environment,
    pub credential_type: String,
    pub masked_value: String,
    /// True when this record references another credential's encrypted value
    /// instead of storing its own copy.
    pub is_reference: bool,
    pub linked_credential_id: Option<String>,
    /// "project/name" of the link target, when this is a reference.
    pub linked_target: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub key_created_at: Option<String>,
    pub expires_at: Option<String>,
    /// Expiration reported by the provider (recorded during validation).
    pub provider_expires_at: Option<String>,
    pub last_validated_at: Option<String>,
    pub last_used_at: Option<String>,
    pub docs_url: String,
    pub notes: String,
    pub manually_disabled: bool,
    pub revoked: bool,
    pub marked_invalid: bool,
    pub possibly_exposed: bool,
    pub exposure_note: String,
    pub status: StatusReport,
}

/// Derive the masked display form of a secret value.
/// Short values are fully masked; longer values keep a small prefix/suffix
/// (mirrors how providers display keys, e.g. `sk-a…f3`).
pub fn mask_value(value: &str) -> String {
    let v: Vec<char> = value.trim().chars().collect();
    let n = v.len();
    if n >= 12 {
        let prefix: String = v[..4].iter().collect();
        let suffix: String = v[n - 2..].iter().collect();
        format!("{prefix}…{suffix}")
    } else if n >= 8 {
        let prefix: String = v[..2].iter().collect();
        format!("{prefix}…")
    } else {
        "••••".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_parses_aliases() {
        assert_eq!(
            Environment::from_str("dev").unwrap(),
            Environment::Development
        );
        assert_eq!(
            Environment::from_str("PROD").unwrap(),
            Environment::Production
        );
        assert!(Environment::from_str("qa").is_err());
    }

    #[test]
    fn mask_hides_most_of_the_value() {
        let fake = "FAKE-TEST-NOT-A-REAL-KEY-000001";
        let masked = mask_value(fake);
        assert_eq!(masked, "FAKE…01");
        assert!(!masked.contains("NOT-A-REAL"));
        assert_eq!(mask_value("shortkey"), "sh…");
        assert_eq!(mask_value("tiny"), "••••");
        // Non-ASCII values must not panic on char boundaries.
        assert_eq!(mask_value("ключключключ"), "ключ…юч");
    }
}
