//! Duplicate/reuse detection via a vault-specific keyed fingerprint.
//!
//! Fingerprints are BLAKE3 keyed hashes under a random 32-byte key that is
//! itself encrypted with the vault key. A plain public hash (SHA-256 etc.)
//! would let anyone with database access confirm guesses of credential
//! values offline; the keyed construction makes fingerprints useless without
//! unlocking the vault.

use crate::error::{CoreError, Result};
use crate::model::Environment;
use crate::secret::{SecretBytes, SecretString};
use serde::Serialize;
use std::fmt;

/// Compute the keyed fingerprint of a credential value. The value is trimmed
/// so trailing-whitespace paste accidents do not defeat duplicate detection.
pub fn fingerprint(fingerprint_key: &SecretBytes, value: &SecretString) -> Result<Vec<u8>> {
    let key: &[u8; 32] = fingerprint_key
        .expose()
        .try_into()
        .map_err(|_| CoreError::Crypto {
            context: "fingerprint key length",
        })?;
    Ok(blake3::keyed_hash(key, value.expose().trim().as_bytes())
        .as_bytes()
        .to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseKind {
    /// Same value stored twice inside one project.
    DuplicateInProject,
    /// Same value stored independently in different projects.
    AcrossProjects,
    /// Same value shared between a production credential and a
    /// development/test credential.
    ProductionSharedWithDevelopment,
    /// The other record is an intentional reference to the same stored value.
    IntentionalReference,
}

impl fmt::Display for ReuseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ReuseKind::DuplicateInProject => "duplicate within the same project",
            ReuseKind::AcrossProjects => "reused across projects",
            ReuseKind::ProductionSharedWithDevelopment => {
                "production credential shared with development"
            }
            ReuseKind::IntentionalReference => "intentional reference",
        };
        f.write_str(s)
    }
}

/// Another credential in the vault that carries the same fingerprint.
#[derive(Debug, Clone, Serialize)]
pub struct ReuseMatch {
    pub credential_id: String,
    pub credential_name: String,
    pub project_id: String,
    pub project_name: String,
    pub environment: Environment,
    pub is_reference: bool,
}

/// One warning shown to the user when a value they are storing (or have
/// stored) matches another credential.
#[derive(Debug, Clone, Serialize)]
pub struct ReuseWarning {
    pub kind: ReuseKind,
    pub other: ReuseMatch,
    pub message: String,
    pub recommendation: String,
}

fn is_prod_dev_pair(a: Environment, b: Environment) -> bool {
    let dev_like = |e: Environment| matches!(e, Environment::Development | Environment::Test);
    (a == Environment::Production && dev_like(b)) || (b == Environment::Production && dev_like(a))
}

/// Classify each match relative to the credential being added/inspected.
pub fn classify(
    target_project_id: &str,
    target_environment: Environment,
    matches: Vec<ReuseMatch>,
) -> Vec<ReuseWarning> {
    matches
        .into_iter()
        .map(|m| {
            let kind = if m.is_reference {
                ReuseKind::IntentionalReference
            } else if m.project_id == target_project_id {
                ReuseKind::DuplicateInProject
            } else if is_prod_dev_pair(target_environment, m.environment) {
                ReuseKind::ProductionSharedWithDevelopment
            } else {
                ReuseKind::AcrossProjects
            };
            let location = format!("{}/{}", m.project_name, m.credential_name);
            let (message, recommendation) = match kind {
                ReuseKind::DuplicateInProject => (
                    format!("this exact secret value is already stored in this project as '{}'", m.credential_name),
                    "avoid storing the same value twice; reference the existing credential instead".to_owned(),
                ),
                ReuseKind::ProductionSharedWithDevelopment => (
                    format!(
                        "this value is shared between production and development/test: it is also stored as '{location}' ({}); a leak in the lower environment would compromise production",
                        m.environment
                    ),
                    "create separate provider credentials for production and development, and rotate this one".to_owned(),
                ),
                ReuseKind::AcrossProjects => (
                    format!("this exact secret value is also stored in another project as '{location}'"),
                    "prefer one provider credential per project; either create a separate credential at the provider, or intentionally reference the existing entry instead of storing a copy".to_owned(),
                ),
                ReuseKind::IntentionalReference => (
                    format!("'{location}' intentionally references this same stored value"),
                    "intentional sharing; no separate secret copy is stored".to_owned(),
                ),
            };
            ReuseWarning { kind, other: m, message, recommendation }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::new_key;

    const FAKE_A: &str = "FAKE-TEST-NOT-A-REAL-KEY-000001";
    const FAKE_B: &str = "FAKE-TEST-NOT-A-REAL-KEY-000002";

    #[test]
    fn fingerprint_is_keyed_and_deterministic() {
        let key_one = new_key();
        let key_two = new_key();
        let value = SecretString::from(FAKE_A);
        let fp1 = fingerprint(&key_one, &value).unwrap();
        let fp2 = fingerprint(&key_one, &value).unwrap();
        let fp_other_key = fingerprint(&key_two, &value).unwrap();
        let fp_other_value = fingerprint(&key_one, &SecretString::from(FAKE_B)).unwrap();
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp_other_key, "fingerprints must be vault-specific");
        assert_ne!(fp1, fp_other_value);
    }

    #[test]
    fn fingerprint_normalizes_whitespace() {
        let key = new_key();
        let a = fingerprint(&key, &SecretString::from(FAKE_A)).unwrap();
        let b = fingerprint(&key, &SecretString::from(format!("  {FAKE_A}\n"))).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_is_not_a_plain_hash() {
        let key = new_key();
        let fp = fingerprint(&key, &SecretString::from(FAKE_A)).unwrap();
        let plain = blake3::hash(FAKE_A.trim().as_bytes());
        assert_ne!(fp, plain.as_bytes().to_vec());
    }

    fn make_match(project_id: &str, env: Environment, is_reference: bool) -> ReuseMatch {
        ReuseMatch {
            credential_id: "cred-2".into(),
            credential_name: "other-key".into(),
            project_id: project_id.into(),
            project_name: "other-project".into(),
            environment: env,
            is_reference,
        }
    }

    #[test]
    fn classifies_duplicate_in_project() {
        let warnings = classify(
            "p1",
            Environment::Development,
            vec![make_match("p1", Environment::Development, false)],
        );
        assert_eq!(warnings[0].kind, ReuseKind::DuplicateInProject);
    }

    #[test]
    fn classifies_prod_dev_sharing_both_directions() {
        let warnings = classify(
            "p1",
            Environment::Production,
            vec![make_match("p2", Environment::Development, false)],
        );
        assert_eq!(warnings[0].kind, ReuseKind::ProductionSharedWithDevelopment);
        let warnings = classify(
            "p1",
            Environment::Test,
            vec![make_match("p2", Environment::Production, false)],
        );
        assert_eq!(warnings[0].kind, ReuseKind::ProductionSharedWithDevelopment);
    }

    #[test]
    fn classifies_cross_project_and_reference() {
        let warnings = classify(
            "p1",
            Environment::Staging,
            vec![
                make_match("p2", Environment::Staging, false),
                make_match("p2", Environment::Staging, true),
            ],
        );
        assert_eq!(warnings[0].kind, ReuseKind::AcrossProjects);
        assert_eq!(warnings[1].kind, ReuseKind::IntentionalReference);
        for w in &warnings {
            assert!(!w.message.is_empty());
            assert!(!w.recommendation.is_empty());
        }
    }
}
