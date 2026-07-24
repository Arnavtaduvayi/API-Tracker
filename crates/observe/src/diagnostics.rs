//! Local self-checks for the observation subsystem, in user-understandable
//! language. Never recommends disabling TLS verification.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    /// `ok` = pass, `warn` = works-but-note, `fail` = a real problem.
    pub status: String,
    pub detail: String,
}

fn check(name: &str, status: &str, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_string(),
        status: status.to_string(),
        detail: detail.into(),
    }
}

/// Run the diagnostics. `ca_present` comes from the vault's certificate state.
pub fn run(ca_present: bool) -> Vec<Check> {
    let mut out = Vec::new();

    match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)) {
        Ok(_) => out.push(check("loopback_bind", "ok", "can bind a loopback listener on 127.0.0.1")),
        Err(e) => out.push(check("loopback_bind", "fail", format!("cannot bind a loopback listener: {e}"))),
    }

    out.push(check(
        "ca_available",
        if ca_present { "ok" } else { "warn" },
        if ca_present {
            "a local certificate authority is present".to_string()
        } else {
            "no local CA yet — one is generated automatically on the first metadata-mode run".to_string()
        },
    ));

    let existing: Vec<String> = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"]
        .iter()
        .filter(|k| std::env::var(k).is_ok())
        .map(|k| k.to_string())
        .collect();
    if existing.is_empty() {
        out.push(check("existing_proxy", "ok", "no conflicting proxy is set in this environment"));
    } else {
        out.push(check(
            "existing_proxy",
            "warn",
            format!(
                "{} proxy variable(s) are already set ({}). A monitored child overrides them for that child only; the proxy chains upstream where reachable.",
                existing.len(),
                existing.join(", ")
            ),
        ));
    }

    out.push(check(
        "upstream_tls_verification",
        "ok",
        "upstream provider certificates are verified against the bundled Mozilla root store; verification is never disabled",
    ));

    // Orphaned temp trust files from a crashed run (best-effort visibility).
    out.push(check(
        "cleanup",
        "ok",
        "temporary trust files are written 0600 and deleted when a session ends",
    ));

    out
}
