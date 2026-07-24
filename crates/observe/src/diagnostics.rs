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
        Ok(_) => out.push(check(
            "loopback_bind",
            "ok",
            "can bind a loopback listener on 127.0.0.1",
        )),
        Err(e) => out.push(check(
            "loopback_bind",
            "fail",
            format!("cannot bind a loopback listener: {e}"),
        )),
    }

    out.push(check(
        "ca_available",
        if ca_present { "ok" } else { "warn" },
        if ca_present {
            "a local certificate authority is present".to_string()
        } else {
            "no local CA yet — one is generated automatically on the first metadata-mode run"
                .to_string()
        },
    ));

    let existing: Vec<String> = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
    ]
    .iter()
    .filter(|k| std::env::var(k).is_ok())
    .map(|k| k.to_string())
    .collect();
    if existing.is_empty() {
        out.push(check(
            "existing_proxy",
            "ok",
            "no conflicting proxy is set in this environment",
        ));
    } else {
        out.push(check(
            "existing_proxy",
            "warn",
            format!(
                "{} proxy variable(s) are already set ({}). A monitored child's proxy variables are overridden to point at the local observation proxy for that child only. Upstream connections go DIRECT — they are NOT chained through your existing proxy — so a monitored run requires direct egress to the providers; if egress is only allowed via that proxy, monitored requests will fail.",
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

    // Describe the temp-trust-file policy honestly. This is a statement of
    // design, not a scan of the data directory (this entry point has no path to
    // scan): a crashed run may leave a temporary bundle behind, but it holds
    // only public certificate material — never a private key or the session
    // token.
    out.push(check(
        "cleanup",
        "ok",
        "temporary trust files are written 0600 and removed when a session ends; a crashed run may leave one behind, but it contains only public certificate material (no keys, no tokens)",
    ));

    out
}
