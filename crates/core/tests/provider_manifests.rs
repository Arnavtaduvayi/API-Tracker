//! Conformance tests for the provider catalog (`provider-manifests/*.toml`).
//!
//! ZFT-011 found the catalog had five manifests of which only three declared a
//! `[gateway]` section, so everything else a developer actually uses reported
//! "No trackable APIs detected in this folder." Growing the catalog is cheap;
//! growing it *honestly* is the hard part, because a manifest is a set of
//! claims about a third party. These tests pin the claims that can be checked
//! mechanically:
//!
//! * the directory is the source of truth — every `.toml` in it is parsed with
//!   the real schema, not a test-local copy of it;
//! * a `[gateway]` origin is a bare https host that the gateway's own SSRF
//!   policy would accept, so a manifest can never become a route to somewhere
//!   the policy would refuse;
//! * base-URL variable names are unique across the catalog, so linking one
//!   provider can never silently repoint another provider's traffic;
//! * the trackable count is asserted against a literal, so the number in the
//!   documentation cannot drift away from the number in the tree;
//! * `implemented` is reserved for providers that really do have a connector.
//!
//! Deliberate deviation: the task asked for `api_tracker_gateway::routes::
//! validate_origin` here. `api-tracker-gateway` depends on `api-tracker-core`,
//! so calling it from a core test is a dependency cycle. The origin checks are
//! replicated inline below and are STRICTER than `validate_origin` (they reject
//! IP-literal hosts outright, which subsumes the loopback/private/link-local/
//! metadata denials the destination policy performs) — anything passing here
//! passes there.

use std::collections::BTreeMap;
use std::path::PathBuf;

use api_tracker_core::connectors;
use api_tracker_core::providers::{self, ProviderManifest, SupportLevel};

/// Total number of manifests in `provider-manifests/`.
const EXPECTED_TOTAL: usize = 21;
/// Manifests that declare a `[gateway]` section — the providers Tethra can
/// actually observe through a base-URL environment variable. This literal is
/// the number the README and the coverage docs quote.
const EXPECTED_GATEWAY_CAPABLE: usize = 13;
/// Manifests with no `[gateway]` section: detected and honestly labelled
/// "no configurable base URL", never silently dropped.
const EXPECTED_DETECTED_UNSUPPORTED: usize = 8;
/// Of the gateway-capable manifests, those with a fixed upstream origin
/// (zero-interaction linking).
const EXPECTED_FIXED_ORIGIN: usize = 11;
/// Of the gateway-capable manifests, those declaring `origins = []` because
/// the provider's data plane is per-project/per-resource (Supabase, Azure
/// OpenAI). These can only be routed through the MAC'd custom-origin flow.
const EXPECTED_CUSTOM_ORIGIN: usize = 2;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("provider-manifests")
}

/// Every manifest file, parsed through the shipping parser (`parse_manifest`),
/// paired with its file stem. Sorted for deterministic failure output.
fn load_all() -> Vec<(String, ProviderManifest)> {
    let dir = manifest_dir();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|e| e.expect("directory entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
        .collect();
    entries.sort();
    assert!(
        !entries.is_empty(),
        "no manifests found in {}",
        dir.display()
    );
    entries
        .into_iter()
        .map(|path| {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .expect("utf-8 file stem")
                .to_string();
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let manifest = providers::parse_manifest(&source)
                .unwrap_or_else(|e| panic!("{} does not parse under the real schema: {e}", stem));
            (stem, manifest)
        })
        .collect()
}

fn matches_full(pattern: &str, subject: &str) -> bool {
    regex::Regex::new(&format!("^(?:{pattern})$"))
        .expect("test pattern compiles")
        .is_match(subject)
}

#[test]
fn every_manifest_parses_and_carries_the_required_fields() {
    for (stem, m) in load_all() {
        assert!(!m.name.trim().is_empty(), "{stem}: empty name");
        assert!(
            !m.description.trim().is_empty(),
            "{stem}: empty description"
        );
        assert!(!m.website.trim().is_empty(), "{stem}: empty website");
        assert!(
            !m.api_docs_url.trim().is_empty(),
            "{stem}: empty api_docs_url"
        );
        assert!(
            !m.auth_docs_url.trim().is_empty(),
            "{stem}: empty auth_docs_url"
        );
        assert!(!m.manage_url.trim().is_empty(), "{stem}: empty manage_url");
        // The capability matrix is exhaustive by construction; if a field is
        // ever added to `Capabilities` this catches manifests that skipped it.
        assert_eq!(
            m.capabilities.entries().len(),
            10,
            "{stem}: capability matrix is not exhaustive"
        );
        // Every user-facing URL must be https: these are rendered as links and
        // opened in the user's browser.
        for (label, url) in [
            ("website", &m.website),
            ("api_docs_url", &m.api_docs_url),
            ("auth_docs_url", &m.auth_docs_url),
            ("manage_url", &m.manage_url),
        ] {
            assert!(
                url.starts_with("https://"),
                "{stem}: {label} '{url}' is not https"
            );
        }
    }
}

#[test]
fn ids_are_unique_nonempty_lowercase_kebab_and_name_their_file() {
    let all = load_all();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for (stem, m) in &all {
        assert!(!m.id.trim().is_empty(), "{stem}: empty id");
        assert!(
            matches_full("[a-z][a-z0-9]*(-[a-z0-9]+)*", &m.id),
            "{}: id '{}' is not lowercase-kebab",
            stem,
            m.id
        );
        // The id must name the file: `MANIFEST_SOURCES` wires each manifest in
        // by path, and a mismatch there is a silent "provider is in the tree
        // but not in the binary" bug.
        assert_eq!(&m.id, stem, "manifest {stem}.toml declares id '{}'", m.id);
        if let Some(other) = seen.insert(m.id.clone(), stem.clone()) {
            panic!("duplicate provider id '{}' in {other} and {stem}", m.id);
        }
    }
}

/// Inline replication of `api_tracker_gateway::routes::validate_origin` plus
/// the destination policy's host denials (see the module header for why it is
/// replicated rather than called). Returns the reason a host is unroutable.
fn origin_rejection_reason(origin: &str) -> Option<String> {
    let Some(host) = origin.strip_prefix("https://") else {
        return Some("must be https".into());
    };
    if host.is_empty() {
        return Some("empty host".into());
    }
    if host.contains('@') {
        return Some("carries userinfo".into());
    }
    if host.contains('/') {
        return Some("carries a path".into());
    }
    if host.contains('?') {
        return Some("carries a query".into());
    }
    if host.contains('#') {
        return Some("carries a fragment".into());
    }
    if host.contains(':') {
        return Some("carries a port (443 is implied and enforced)".into());
    }
    if host != host.to_lowercase() {
        return Some("is not lowercase".into());
    }
    if !host.contains('.') || host.ends_with('.') {
        return Some("is not a fully-qualified DNS name".into());
    }
    // Rejecting IP literals outright is stricter than the gateway's policy and
    // subsumes its loopback / private / link-local / cloud-metadata denials: a
    // manifest origin is a vendor's public hostname, never an address.
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') || host.starts_with('[') {
        return Some("is an IP literal, not a vendor hostname".into());
    }
    if host.ends_with(".local") || host.ends_with(".internal") || host == "localhost" {
        return Some("is a local/internal name".into());
    }
    None
}

#[test]
fn gateway_origins_are_routable_bare_https_hosts() {
    for (stem, m) in load_all() {
        let Some(gw) = &m.gateway else { continue };
        for origin in &gw.origins {
            if let Some(reason) = origin_rejection_reason(origin) {
                panic!("{stem}: gateway origin '{origin}' {reason}");
            }
        }
        // base_path is appended to the loopback route URL by the .env writer;
        // a trailing slash or a query would produce a double slash or a
        // malformed URL in the user's project.
        assert!(
            gw.base_path.is_empty()
                || (gw.base_path.starts_with('/')
                    && !gw.base_path.ends_with('/')
                    && !gw.base_path.contains(['?', '#'])),
            "{stem}: base_path '{}' is not a clean path prefix",
            gw.base_path
        );
        assert!(
            matches!(gw.usage_shape.as_str(), "" | "openai" | "anthropic"),
            "{stem}: usage_shape '{}' is not a known extraction shape",
            gw.usage_shape
        );
    }
}

/// The origin check above only proves something if it actually rejects. A
/// catalog of well-formed origins would pass a check that always returned
/// `None`, so the checker itself is pinned against the shapes it exists to
/// stop.
#[test]
fn the_inline_origin_check_rejects_what_the_gateway_policy_rejects() {
    for bad in [
        "http://api.openai.com",       // not https
        "api.openai.com",              // no scheme
        "https://",                    // empty host
        "https://user@api.openai.com", // userinfo
        "https://api.openai.com/v1",   // path
        "https://api.openai.com?x=1",  // query
        "https://api.openai.com#frag", // fragment
        "https://api.openai.com:8443", // non-443 port
        "https://API.OpenAI.com",      // not lowercase
        "https://localhost",           // loopback name
        "https://127.0.0.1",           // loopback literal
        "https://169.254.169.254",     // cloud metadata
        "https://10.0.0.5",            // private range
        "https://db.internal",         // internal name
        "https://printer.local",       // link-local name
    ] {
        assert!(
            origin_rejection_reason(bad).is_some(),
            "origin '{bad}' should have been rejected"
        );
    }
    // …and accepts the shape every manifest is required to use.
    assert!(origin_rejection_reason("https://api.openai.com").is_none());
}

#[test]
fn declared_env_var_names_are_plausible_env_vars() {
    for (stem, m) in load_all() {
        for var in &m.env_vars {
            assert!(
                matches_full("[A-Z][A-Z0-9_]*", var),
                "{stem}: secret env var '{var}' is not a plausible variable name"
            );
        }
        if let Some(gw) = &m.gateway {
            for var in &gw.env_vars {
                assert!(
                    matches_full("[A-Z][A-Z0-9_]*", var),
                    "{stem}: gateway env var '{var}' is not a plausible variable name"
                );
            }
        }
    }
}

#[test]
fn a_gateway_section_always_declares_a_base_url_env_var() {
    for (stem, m) in load_all() {
        let Some(gw) = &m.gateway else { continue };
        assert!(
            !gw.env_vars.is_empty(),
            "{stem}: [gateway] declares no base-URL env var, so linking it \
             could never write anything"
        );
    }
}

#[test]
fn base_url_vars_are_non_secret_and_unique_across_the_catalog() {
    let all = load_all();
    let mut base_url_owner: BTreeMap<&str, &str> = BTreeMap::new();
    let mut secret_owner: BTreeMap<&str, &str> = BTreeMap::new();
    for (stem, m) in &all {
        for var in &m.env_vars {
            if let Some(other) = secret_owner.insert(var, stem) {
                panic!(
                    "secret env var '{var}' is claimed by both {other} and {stem}; \
                     one secret cannot honestly be attributed to two providers"
                );
            }
        }
    }
    for (stem, m) in &all {
        let Some(gw) = &m.gateway else { continue };
        for var in &gw.env_vars {
            // `detect.rs` reads the VALUE of a base-URL variable for
            // custom-origin providers. A name that is also a secret variable
            // would put a secret on that path.
            assert!(
                !m.env_vars.iter().any(|s| s == var),
                "{stem}: '{var}' is declared both as a secret and as a base-URL variable"
            );
            if let Some(other) = base_url_owner.insert(var, stem) {
                panic!(
                    "base-URL var '{var}' is claimed by both {other} and {stem}; \
                     linking one would silently repoint the other's traffic"
                );
            }
        }
    }
}

#[test]
fn trackable_provider_counts_match_the_documented_numbers() {
    let all = load_all();
    let gateway_capable = all.iter().filter(|(_, m)| m.gateway.is_some()).count();
    let fixed_origin = all
        .iter()
        .filter(|(_, m)| m.gateway.as_ref().is_some_and(|g| !g.origins.is_empty()))
        .count();
    let custom_origin = all
        .iter()
        .filter(|(_, m)| m.gateway.as_ref().is_some_and(|g| g.origins.is_empty()))
        .count();
    let unsupported = all.iter().filter(|(_, m)| m.gateway.is_none()).count();

    assert_eq!(all.len(), EXPECTED_TOTAL, "total manifest count changed");
    assert_eq!(
        gateway_capable, EXPECTED_GATEWAY_CAPABLE,
        "trackable (gateway-capable) provider count changed — update the README \
         and the coverage docs in the same commit"
    );
    assert_eq!(
        unsupported, EXPECTED_DETECTED_UNSUPPORTED,
        "detected-but-unsupported provider count changed"
    );
    assert_eq!(fixed_origin, EXPECTED_FIXED_ORIGIN);
    assert_eq!(custom_origin, EXPECTED_CUSTOM_ORIGIN);
    assert_eq!(gateway_capable + unsupported, all.len());
    assert_eq!(fixed_origin + custom_origin, gateway_capable);
}

#[test]
fn detection_regexes_compile_and_reject_placeholders() {
    // Values a developer commits INSTEAD of a secret. A rule that fires on
    // these teaches users to ignore findings, which is worse than no rule.
    const PLACEHOLDERS: &[&str] = &[
        "",
        "...",
        "TODO",
        "changeme",
        "dummy",
        "example-key",
        "replace-me",
        "REPLACE_WITH_YOUR_KEY",
        "YOUR_API_KEY",
        "your-api-key-here",
        "<your key>",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "sk-...",
        "hf_...",
        "r8_...",
    ];
    // A 64-char hex blob: a commit hash, a checksum, a session id. Any rule
    // matching this is an entropy heuristic, not a provider format marker.
    const HEX_BLOB: &str = "3f2a91c47be05d8619af730cd214e6b5093f8ac1de627540bb98e30172ac4d69";

    let mut declared = 0usize;
    for (stem, m) in load_all() {
        for p in &m.detection {
            let re = regex::Regex::new(&p.regex)
                .unwrap_or_else(|e| panic!("{stem}/{}: regex does not compile: {e}", p.name));
            declared += 1;
            for placeholder in PLACEHOLDERS {
                assert!(
                    !re.is_match(placeholder),
                    "{stem}/{}: matches placeholder {placeholder:?}",
                    p.name
                );
            }
            assert!(
                !re.is_match(HEX_BLOB),
                "{stem}/{}: matches a bare hex blob — a format marker must \
                 require the provider's literal prefix",
                p.name
            );
        }
    }
    assert!(
        declared >= 10,
        "only {declared} detection rules across the catalog; the scanner lost coverage"
    );
}

#[test]
fn implemented_capabilities_require_a_real_connector() {
    // "implemented" means Tethra performs the call. `connectors::for_provider`
    // is the only thing that can perform it, so a manifest claiming
    // `implemented` without one is a lie the UI would repeat verbatim.
    for (stem, m) in load_all() {
        let has_connector = connectors::for_provider(&m.id).is_some();
        for (label, entry) in m.capabilities.entries() {
            if entry.support == SupportLevel::Implemented {
                assert!(
                    has_connector,
                    "{stem}: claims '{label}' is implemented but there is no \
                     connector for provider '{}'",
                    m.id
                );
            }
        }
    }
}

#[test]
fn embedded_catalog_agrees_with_the_manifest_directory() {
    let on_disk: BTreeMap<String, ProviderManifest> = load_all().into_iter().collect();
    for embedded in providers::manifests() {
        let disk = on_disk.get(&embedded.id).unwrap_or_else(|| {
            panic!(
                "manifest '{}' is compiled into the binary but has no file in \
                 provider-manifests/",
                embedded.id
            )
        });
        // Catches a stale `include_str!` path pointing at the wrong file.
        assert_eq!(
            disk, embedded,
            "embedded manifest '{}' differs from its file on disk",
            embedded.id
        );
    }
}
