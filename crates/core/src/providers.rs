//! Built-in informational provider catalog.
//!
//! This is deliberately minimal in this milestone: it exists so users can
//! pick a provider when adding a credential and find the official
//! documentation/management pages. It makes **no capability claims** (usage,
//! permissions, rotation, validation): the provider connector architecture
//! with an explicit capability matrix is a later milestone. Nothing here
//! triggers network requests.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    /// Stable identifier stored in credential records.
    pub id: &'static str,
    pub name: &'static str,
    /// Official documentation entry point.
    pub docs_url: &'static str,
    /// Official page where credentials are managed.
    pub manage_url: &'static str,
    /// Environment variable names commonly used for this provider's keys.
    pub common_env_vars: &'static [&'static str],
}

pub const PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        id: "openai",
        name: "OpenAI",
        docs_url: "https://platform.openai.com/docs",
        manage_url: "https://platform.openai.com/api-keys",
        common_env_vars: &["OPENAI_API_KEY"],
    },
    ProviderInfo {
        id: "anthropic",
        name: "Anthropic",
        docs_url: "https://docs.anthropic.com",
        manage_url: "https://console.anthropic.com/settings/keys",
        common_env_vars: &["ANTHROPIC_API_KEY"],
    },
    ProviderInfo {
        id: "github",
        name: "GitHub",
        docs_url: "https://docs.github.com/en/authentication",
        manage_url: "https://github.com/settings/tokens",
        common_env_vars: &["GITHUB_TOKEN", "GH_TOKEN"],
    },
    ProviderInfo {
        id: "stripe",
        name: "Stripe",
        docs_url: "https://docs.stripe.com/keys",
        manage_url: "https://dashboard.stripe.com/apikeys",
        common_env_vars: &["STRIPE_SECRET_KEY", "STRIPE_API_KEY"],
    },
    ProviderInfo {
        id: "supabase",
        name: "Supabase",
        docs_url: "https://supabase.com/docs",
        manage_url: "https://supabase.com/dashboard/project/_/settings/api",
        common_env_vars: &["SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ANON_KEY"],
    },
    ProviderInfo {
        id: "aws",
        name: "Amazon Web Services",
        docs_url:
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        manage_url: "https://console.aws.amazon.com/iam/home#/security_credentials",
        common_env_vars: &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
    },
    ProviderInfo {
        id: "google-cloud",
        name: "Google Cloud",
        docs_url: "https://cloud.google.com/docs/authentication/api-keys",
        manage_url: "https://console.cloud.google.com/apis/credentials",
        common_env_vars: &["GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"],
    },
    ProviderInfo {
        id: "other",
        name: "Other / custom",
        docs_url: "",
        manage_url: "",
        common_env_vars: &[],
    },
];

pub fn find(id: &str) -> Option<&'static ProviderInfo> {
    PROVIDERS
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(id.trim()))
}

/// Normalize a user-supplied provider string: known ids map to their stable
/// id; anything else is kept as a trimmed lowercase custom provider name.
pub fn normalize(input: &str) -> String {
    match find(input) {
        Some(p) => p.id.to_owned(),
        None => input.trim().to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_providers_resolve() {
        assert_eq!(find("OpenAI").unwrap().id, "openai");
        assert_eq!(normalize("Anthropic"), "anthropic");
    }

    #[test]
    fn custom_providers_are_preserved() {
        assert_eq!(normalize("  My Internal API  "), "my internal api");
        assert!(find("my internal api").is_none());
    }
}
