//! Source-level security guard for the gateway crate, duplicating the observe
//! crate's guard scoped to `crates/gateway/src` (SECURITY_INVARIANTS SI-5,
//! KNOWN_CONFLICTS C9 — the observe guard scans only `crates/observe/src`, so
//! a new networked crate gets ZERO coverage unless it carries its own copy).
//!
//! A future change that adds `.dangerous().with_custom_certificate_verifier()`
//! (or sets a verification-disabling env var) in this crate fails the build
//! here.

use api_tracker_observe::trust::FORBIDDEN_VARS;
use std::fs;
use std::path::{Path, PathBuf};

fn src_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    assert!(!out.is_empty(), "found no source files to scan");
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(p);
        }
    }
}

/// Strip `//` line comments so a comment that legitimately names a forbidden
/// API does not trip the scan.
fn code_only(src: &str) -> String {
    src.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn gateway_src_contains_no_tls_verification_bypass() {
    const FORBIDDEN: &[&str] = &[
        ".dangerous(",
        "with_custom_certificate_verifier",
        "danger_accept_invalid",
        "NoCertificateVerification",
        "set_certificate_verifier",
        "ServerCertVerifier for", // a hand-rolled verifier impl
    ];
    for file in src_files() {
        let code = code_only(&fs::read_to_string(&file).unwrap());
        for pat in FORBIDDEN {
            assert!(
                !code.contains(pat),
                "TLS-verification bypass `{pat}` found in {} — upstream provider \
                 certificates must always be fully verified (SI-5)",
                file.display()
            );
        }
    }
}

#[test]
fn gateway_src_never_sets_a_verification_disabling_env_var() {
    for file in src_files() {
        let code = code_only(&fs::read_to_string(&file).unwrap());
        for var in FORBIDDEN_VARS {
            for set_form in [
                format!("env(\"{var}\""),
                format!("(\"{var}\".into()"),
                format!("(\"{var}\".to_string()"),
                format!("(\"{var}\", "),
            ] {
                assert!(
                    !code.contains(&set_form),
                    "the gateway must never SET the verification-disabling var {var} ({} in {})",
                    set_form,
                    file.display()
                );
            }
        }
    }
}

#[test]
fn gateway_src_never_binds_a_non_loopback_listener() {
    // SI-1: the listener binds loopback only, with no host-configuration
    // surface. Any appearance of a wildcard bind address in gateway source is
    // a build failure.
    const FORBIDDEN: &[&str] = &["0.0.0.0", "INADDR_ANY", "[::]:", "\"::\""];
    for file in src_files() {
        let code = code_only(&fs::read_to_string(&file).unwrap());
        for pat in FORBIDDEN {
            assert!(
                !code.contains(pat),
                "non-loopback bind pattern `{pat}` found in {} — the gateway \
                 listener is loopback-only by construction (SI-1)",
                file.display()
            );
        }
    }
}

#[test]
fn the_test_only_plain_connector_is_never_used_by_production_code() {
    // `InsecurePlainConnectorForTests` exists so the exchange engine can be
    // exercised against synthetic loopback upstreams. Production forwarding
    // must always go through `TlsConnector` (two-phase SSRF + verified TLS),
    // so no module other than its own definition may name it.
    for file in src_files() {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        if name == "upstream.rs" {
            continue; // the definition itself
        }
        let code = code_only(&fs::read_to_string(&file).unwrap());
        assert!(
            !code.contains("InsecurePlainConnectorForTests"),
            "the test-only plain connector must never be referenced by {} \
             — production upstreams are always TLS (SI-5)",
            file.display()
        );
    }
    // And the default a running gateway gets is the TLS connector.
    let forward =
        fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/forward.rs"))
            .unwrap();
    assert!(
        forward.contains("connector: Arc::new(TlsConnector)"),
        "Gateway::new must default to the verified-TLS connector"
    );
}

#[test]
fn the_crate_never_links_the_certificate_authority_or_server_tls_modules() {
    // SI-6: the gateway terminates NO TLS toward clients and holds no CA
    // key. The structural guarantee is that it never references observe's
    // CA / MITM surface — this guard is what keeps that true.
    const FORBIDDEN: &[&str] = &[
        "observe::ca",
        "observe::clienthello",
        "observe::systemtrust",
        "observe::proxy",
        "observe::session",
        "server_config_for",
        "CertAuthority",
        "ResolvesServerCert",
        "ServerConfig",
        "rcgen",
    ];
    for file in src_files() {
        let code = code_only(&fs::read_to_string(&file).unwrap());
        for pat in FORBIDDEN {
            assert!(
                !code.contains(pat),
                "`{pat}` found in {} — the gateway must never link the \
                 certificate-authority or server-side TLS surface (SI-6)",
                file.display()
            );
        }
    }
}

#[test]
fn no_gateway_debug_impl_can_print_a_request_target_with_query_material() {
    // The wire.rs redaction pattern: any Debug that touches a target must
    // sever the query first. Pin that the two types carrying wire strings
    // redact, and that no Debug derive was added to them.
    let head =
        fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/head.rs"))
            .unwrap();
    for ty in ["RequestHead", "HeaderField"] {
        assert!(
            head.contains(&format!("impl std::fmt::Debug for {ty}")),
            "{ty} must carry a hand-written redacting Debug, not a derive"
        );
        assert!(
            !head.contains(&format!("#[derive(Debug)]\npub struct {ty}")),
            "{ty} must not derive Debug"
        );
    }
    assert!(
        head.contains("&\"<redacted>\""),
        "header values must print as <redacted>"
    );
    let record =
        fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/record.rs"))
            .unwrap();
    assert!(
        record.contains("impl std::fmt::Debug for CredentialDigest"),
        "the credential digest must carry a redacting Debug"
    );
}
