//! Source-level security guard: the observation proxy must NEVER contain a TLS
//! verification bypass, and must NEVER set a verification-disabling environment
//! variable on the monitored child.
//!
//! This is the test referenced by RUNTIME_OBSERVABILITY_THREAT_MODEL.md,
//! RUNTIME_OBSERVABILITY_ARCHITECTURE.md, DEVELOPER_GUIDE.md, and ADR
//! docs/decisions/0017-runtime-observability.md — a future change that adds
//! `.dangerous().with_custom_certificate_verifier(...)` (or exports
//! `NODE_TLS_REJECT_UNAUTHORIZED=0`) fails the build here.

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
/// API (e.g. the "No dangerous() call, ever" reminder in tls.rs) does not trip
/// the scan. Block comments are not used for these strings in this crate.
fn code_only(src: &str) -> String {
    src.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn observe_src_contains_no_tls_verification_bypass() {
    // The exact rustls / common bypass surfaces. `.dangerous()` is the gate that
    // unlocks rustls's permissive-verifier API; the rest are custom permissive
    // verifiers or accept-invalid switches.
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
                 certificates must always be fully verified",
                file.display()
            );
        }
    }
}

#[test]
fn observe_src_never_sets_a_verification_disabling_env_var() {
    for file in src_files() {
        let code = code_only(&fs::read_to_string(&file).unwrap());
        for var in FORBIDDEN_VARS {
            // The list may NAME the variables (the FORBIDDEN_VARS declaration and
            // this crate's own guards); what is forbidden is SETTING one.
            for set_form in [
                format!("env(\"{var}\""),
                format!("(\"{var}\".into()"),
                format!("(\"{var}\".to_string()"),
                format!("(\"{var}\", "),
            ] {
                assert!(
                    !code.contains(&set_form),
                    "scoped trust must never SET the verification-disabling var {var} ({} in {})",
                    set_form,
                    file.display()
                );
            }
        }
    }
}
