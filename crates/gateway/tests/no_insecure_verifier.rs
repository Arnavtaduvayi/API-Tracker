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
