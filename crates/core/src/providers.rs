//! Local, version-controlled provider catalog.
//!
//! Provider manifests live as TOML files under `provider-manifests/` and are
//! embedded at compile time (see `MANIFEST_SOURCES`). Each manifest carries:
//! official links, environment-variable names, credential types, secret
//! detection patterns (used by the [`crate::scanner`]), documentation-watch
//! URLs, and an honest capability matrix.
//!
//! The capability matrix never fabricates provider functionality. Each
//! capability records a primary [`SupportLevel`] plus orthogonal facts —
//! whether an administrative credential is required and the attribution
//! granularity — so account-level usage is never presented as exact per-key
//! usage. Nothing in this module performs network I/O; it only describes
//! providers. Actual provider connectors are a later milestone, so no
//! capability is marked [`SupportLevel::Implemented`] yet.

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// How well API Tracker (and the provider) support a capability today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// Supported by the provider and implemented in API Tracker.
    Implemented,
    /// The provider offers this through an official API, but API Tracker does
    /// not implement it yet.
    SupportedNotImplemented,
    /// The provider does not offer this capability.
    Unsupported,
    /// Only possible through a manual action (e.g. the provider dashboard).
    ManualOnly,
}

impl SupportLevel {
    pub fn label(&self) -> &'static str {
        match self {
            SupportLevel::Implemented => "implemented",
            SupportLevel::SupportedNotImplemented => "supported, not implemented",
            SupportLevel::Unsupported => "unsupported",
            SupportLevel::ManualOnly => "manual action required",
        }
    }
}

/// The precision at which a capability (mainly usage/cost) can be attributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    NotApplicable,
    AccountLevel,
    ProviderProjectLevel,
    ExactCredential,
}

impl Attribution {
    pub fn label(&self) -> &'static str {
        match self {
            Attribution::NotApplicable => "n/a",
            Attribution::AccountLevel => "account level only",
            Attribution::ProviderProjectLevel => "provider-project level only",
            Attribution::ExactCredential => "exact credential level",
        }
    }
}

fn default_attribution() -> Attribution {
    Attribution::NotApplicable
}

/// One capability's honest status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEntry {
    pub support: SupportLevel,
    #[serde(default)]
    pub requires_admin_credential: bool,
    #[serde(default = "default_attribution")]
    pub attribution: Attribution,
    #[serde(default)]
    pub note: String,
}

/// The full capability matrix. Fields mirror the product spec's list so the
/// matrix is exhaustive and type-checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub validate_credential: CapabilityEntry,
    pub fetch_metadata: CapabilityEntry,
    pub fetch_usage: CapabilityEntry,
    pub read_permissions: CapabilityEntry,
    pub change_permissions: CapabilityEntry,
    pub create_credential: CapabilityEntry,
    pub disable_credential: CapabilityEntry,
    pub revoke_credential: CapabilityEntry,
    pub rotate_credential: CapabilityEntry,
    pub fetch_pricing: CapabilityEntry,
}

impl Capabilities {
    /// Capabilities in a fixed display order.
    pub fn entries(&self) -> Vec<(&'static str, &CapabilityEntry)> {
        vec![
            ("validate credential", &self.validate_credential),
            ("fetch metadata", &self.fetch_metadata),
            ("fetch usage", &self.fetch_usage),
            ("read permissions", &self.read_permissions),
            ("change permissions", &self.change_permissions),
            ("create credential", &self.create_credential),
            ("disable credential", &self.disable_credential),
            ("revoke credential", &self.revoke_credential),
            ("rotate credential", &self.rotate_credential),
            ("fetch pricing", &self.fetch_pricing),
        ]
    }
}

/// A secret-detection pattern contributed by a provider manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionPattern {
    /// Stable rule name (e.g. `openai-project-key`).
    pub name: String,
    /// Regular expression matching the provider's key format. These are
    /// public format markers (prefixes/shapes), never secrets.
    pub regex: String,
    /// Baseline confidence when this pattern matches.
    pub confidence: Confidence,
}

/// Confidence of a detection or finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// A provider manifest (parsed from TOML).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderManifest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub website: String,
    pub api_docs_url: String,
    pub auth_docs_url: String,
    pub manage_url: String,
    #[serde(default)]
    pub env_vars: Vec<String>,
    #[serde(default)]
    pub credential_types: Vec<String>,
    /// General expiration behavior, human-readable.
    #[serde(default)]
    pub expiration: String,
    /// Official changelog / release-notes page.
    #[serde(default)]
    pub changelog_url: String,
    /// Official pricing documentation.
    #[serde(default)]
    pub pricing_url: String,
    /// Official permission/scope documentation.
    #[serde(default)]
    pub permissions_docs_url: String,
    /// Official documentation URLs the user may watch for changes.
    #[serde(default)]
    pub watch_docs: Vec<String>,
    #[serde(default)]
    pub detection: Vec<DetectionPattern>,
    pub capabilities: Capabilities,
}

/// Back-compat lightweight view used by older call sites and simple listings.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    pub id: String,
    pub name: String,
    pub docs_url: String,
    pub manage_url: String,
    pub common_env_vars: Vec<String>,
}

impl ProviderManifest {
    pub fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            docs_url: self.api_docs_url.clone(),
            manage_url: self.manage_url.clone(),
            common_env_vars: self.env_vars.clone(),
        }
    }
}

/// Embedded manifest sources. Adding a provider = adding a TOML file here.
const MANIFEST_SOURCES: &[(&str, &str)] = &[
    (
        "openai",
        include_str!("../../../provider-manifests/openai.toml"),
    ),
    (
        "anthropic",
        include_str!("../../../provider-manifests/anthropic.toml"),
    ),
    (
        "github",
        include_str!("../../../provider-manifests/github.toml"),
    ),
    (
        "stripe",
        include_str!("../../../provider-manifests/stripe.toml"),
    ),
    (
        "supabase",
        include_str!("../../../provider-manifests/supabase.toml"),
    ),
];

static MANIFESTS: OnceLock<Vec<ProviderManifest>> = OnceLock::new();

/// Parse and validate a single manifest source.
pub fn parse_manifest(source: &str) -> Result<ProviderManifest> {
    let manifest: ProviderManifest = toml::from_str(source)
        .map_err(|e| CoreError::InvalidInput(format!("invalid provider manifest: {e}")))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &ProviderManifest) -> Result<()> {
    if manifest.id.trim().is_empty() {
        return Err(CoreError::InvalidInput(
            "provider manifest has an empty id".into(),
        ));
    }
    if manifest.id != manifest.id.to_lowercase() {
        return Err(CoreError::InvalidInput(format!(
            "provider id '{}' must be lowercase",
            manifest.id
        )));
    }
    if manifest.name.trim().is_empty() {
        return Err(CoreError::InvalidInput(format!(
            "provider '{}' has an empty name",
            manifest.id
        )));
    }
    // Every detection regex must compile.
    for pattern in &manifest.detection {
        regex::Regex::new(&pattern.regex).map_err(|e| {
            CoreError::InvalidInput(format!(
                "provider '{}' pattern '{}' is not a valid regex: {e}",
                manifest.id, pattern.name
            ))
        })?;
    }
    Ok(())
}

/// All manifests, parsed once. Panics only if an embedded manifest is
/// malformed, which a unit test guarantees cannot happen in a shipped build.
pub fn manifests() -> &'static [ProviderManifest] {
    MANIFESTS.get_or_init(|| {
        MANIFEST_SOURCES
            .iter()
            .map(|(id, source)| {
                parse_manifest(source)
                    .unwrap_or_else(|e| panic!("embedded manifest '{id}' is invalid: {e}"))
            })
            .collect()
    })
}

pub fn find(id: &str) -> Option<&'static ProviderManifest> {
    let needle = id.trim();
    manifests()
        .iter()
        .find(|m| m.id.eq_ignore_ascii_case(needle))
}

/// Normalize a user-supplied provider string: known ids map to their stable
/// id; anything else is kept as a trimmed lowercase custom provider name.
pub fn normalize(input: &str) -> String {
    match find(input) {
        Some(m) => m.id.clone(),
        None => input.trim().to_lowercase(),
    }
}

/// Back-compat: the simple info list some callers still use.
pub fn provider_infos() -> Vec<ProviderInfo> {
    manifests().iter().map(|m| m.info()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_embedded_manifests_parse_and_validate() {
        let all = manifests();
        assert_eq!(all.len(), 5);
        for m in all {
            assert!(!m.id.is_empty());
            assert!(!m.name.is_empty());
            assert!(!m.api_docs_url.is_empty(), "{} missing api docs", m.id);
            assert!(!m.manage_url.is_empty(), "{} missing manage url", m.id);
            // Capability matrix is exhaustive (10 entries).
            assert_eq!(m.capabilities.entries().len(), 10);
            // Credential validation is implemented for every provider.
            assert_eq!(
                m.capabilities.validate_credential.support,
                SupportLevel::Implemented,
                "{} must implement validation",
                m.id
            );
        }
    }

    #[test]
    fn known_providers_resolve_and_customs_preserved() {
        assert_eq!(find("OpenAI").unwrap().id, "openai");
        assert_eq!(normalize("Anthropic"), "anthropic");
        assert_eq!(normalize("  My Internal API  "), "my internal api");
        assert!(find("my internal api").is_none());
    }

    #[test]
    fn every_detection_regex_compiles() {
        for m in manifests() {
            for p in &m.detection {
                assert!(regex::Regex::new(&p.regex).is_ok(), "{}/{}", m.id, p.name);
            }
        }
    }

    #[test]
    fn parse_rejects_uppercase_id() {
        let bad = r#"
id = "OpenAI"
name = "x"
description = ""
website = ""
api_docs_url = "x"
auth_docs_url = "x"
manage_url = "x"
[capabilities]
validate_credential = { support = "unsupported" }
fetch_metadata = { support = "unsupported" }
fetch_usage = { support = "unsupported" }
read_permissions = { support = "unsupported" }
change_permissions = { support = "unsupported" }
create_credential = { support = "unsupported" }
disable_credential = { support = "unsupported" }
revoke_credential = { support = "unsupported" }
rotate_credential = { support = "unsupported" }
fetch_pricing = { support = "unsupported" }
"#;
        assert!(parse_manifest(bad).is_err());
    }
}
