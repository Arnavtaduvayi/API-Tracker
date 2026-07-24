//! Automatic API inventory helpers: resolve observed hostnames to known
//! providers and classify internal-looking hosts. Unknown hosts are still
//! first-class inventory entries — they just have no `provider_id`.

use crate::providers;

/// Known provider API hostnames → manifest provider id. A leading `.` in the
/// needle marks a suffix match (any subdomain).
const HOST_PROVIDERS: &[(&str, &str)] = &[
    ("api.openai.com", "openai"),
    ("api.anthropic.com", "anthropic"),
    ("api.github.com", "github"),
    ("github.com", "github"),
    ("uploads.github.com", "github"),
    ("api.stripe.com", "stripe"),
    ("files.stripe.com", "stripe"),
    (".supabase.co", "supabase"),
    (".supabase.in", "supabase"),
];

/// Resolve a hostname to a known provider id, or `None` for an unknown/custom
/// API. Only returns a provider whose manifest actually exists.
pub fn provider_for_host(host: &str) -> Option<&'static str> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    for (needle, provider) in HOST_PROVIDERS {
        let matched = if let Some(suffix) = needle.strip_prefix('.') {
            h == suffix || h.ends_with(&format!(".{suffix}"))
        } else {
            h == *needle
        };
        if matched && providers::find(provider).is_some() {
            return Some(*provider);
        }
    }
    None
}

/// Heuristic: does a hostname look like an internal/private destination?
/// (A single-label name, `.local`/`.internal`, or an IP literal in a private
/// range.) Used only to tag inventory; the proxy policy is the real gate.
pub fn looks_internal(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if h.parse::<std::net::IpAddr>().is_ok() {
        // The proxy already blocks private IPs unless allowlisted, so an IP
        // that was actually observed and allowlisted is internal.
        return true;
    }
    !h.contains('.') || h.ends_with(".local") || h.ends_with(".internal")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_providers_including_subdomains() {
        assert_eq!(provider_for_host("api.openai.com"), Some("openai"));
        assert_eq!(provider_for_host("API.OpenAI.com"), Some("openai"));
        assert_eq!(provider_for_host("xyz.supabase.co"), Some("supabase"));
        assert_eq!(provider_for_host("supabase.co"), Some("supabase"));
        assert_eq!(provider_for_host("api.stripe.com"), Some("stripe"));
        assert_eq!(provider_for_host("api.unknown-saas.example"), None);
    }

    #[test]
    fn internal_detection() {
        assert!(looks_internal("localhost"));
        assert!(looks_internal("db.internal"));
        assert!(looks_internal("printer.local"));
        assert!(looks_internal("10.0.0.5"));
        assert!(!looks_internal("api.openai.com"));
    }
}
