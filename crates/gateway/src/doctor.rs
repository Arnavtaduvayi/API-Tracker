//! Gateway diagnostics: one engine behind `tethra gateway doctor`, the
//! desktop Diagnostics tab, and the failure banners.
//!
//! Everything here is LOCK-FREE: diagnosis reads the schema-checked
//! database, the service definition, the control channel, and the
//! listener-identity probe — never the vault. A locked desktop is never
//! silent about the gateway's state (PRODUCT_BEHAVIOR).
//!
//! Findings are facts with a repair hint, not interpretations: the same
//! report renders in the CLI, the desktop, and `--json` unchanged.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::control::{self, ListenerIdentity};
use crate::lifecycle::{self, OsWillRun};
use crate::routes;
use crate::store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Ok,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable machine id (`service_not_installed`, `port_collision`, ...).
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// The action that fixes it, when one exists.
    pub repair: Option<String>,
}

/// A linked project's health, from the recorded link state.
#[derive(Debug, Clone, Serialize)]
pub struct LinkHealth {
    pub project_id: String,
    pub route_prefix: String,
    pub env_path: Option<String>,
    pub env_file_exists: bool,
    /// The linked file still carries this link's slug URL.
    pub env_points_at_gateway: bool,
    pub issues: Vec<String>,
}

/// The complete diagnosis. `overall` is the worst severity present.
#[derive(Debug, Clone, Serialize)]
pub struct Doctor {
    pub overall: Severity,
    pub findings: Vec<Finding>,
    pub service: lifecycle::ServiceStatus,
    /// Live status over the control channel, when reachable.
    pub gateway: Option<control::Status>,
    pub listener: Option<ListenerIdentity>,
    pub configured_port: Option<u16>,
    pub enabled: bool,
    pub links: Vec<LinkHealth>,
    pub cli_version: String,
}

fn finding(
    id: &'static str,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
    repair: Option<&str>,
) -> Finding {
    Finding {
        id,
        severity,
        title: title.into(),
        detail: detail.into(),
        repair: repair.map(|r| r.to_string()),
    }
}

/// Run the full diagnosis for a data directory (host service state).
pub fn diagnose(data_dir: &Path) -> Doctor {
    let service = lifecycle::Lifecycle::for_host(data_dir)
        .map(|lc| lc.status())
        .unwrap_or_else(|e| placeholder_service(e.to_string()));
    diagnose_with(data_dir, service)
}

fn placeholder_service(why: String) -> lifecycle::ServiceStatus {
    lifecycle::ServiceStatus {
        platform: "unknown",
        // We could not build a lifecycle at all, so we cannot say which
        // installation this would have controlled. Empty is the honest
        // answer; diagnostics render it as "unknown", never as "default".
        installation_id: String::new(),
        service_name: String::new(),
        installed: false,
        definition_path: String::new(),
        definition: None,
        matches_data_dir: false,
        binary_exists: false,
        binary_version: None,
        registered: false,
        running: false,
        pid: None,
        os_will_run: OsWillRun::Unknown { why },
        owned_artifacts: Vec::new(),
        notes: Vec::new(),
    }
}

/// The diagnosis with an explicit service state — the seam tests use so
/// `cargo test` never depends on (or touches) the developer machine's real
/// service registration.
pub fn diagnose_with(data_dir: &Path, service: lifecycle::ServiceStatus) -> Doctor {
    let mut findings = Vec::new();

    // --- configuration (schema-checked, lock-free) ---
    let conn = api_tracker_core::db::open_at_current_version(&data_dir.join("vault.db")).ok();
    let config = conn
        .as_ref()
        .and_then(|c| store::load_config(c).ok())
        .unwrap_or_default();
    if conn.is_none() {
        findings.push(finding(
            "database_unavailable",
            Severity::Warn,
            "vault database unavailable",
            "the vault database is missing, busy, or at a different schema version; \
             configuration and history reads are degraded (forwarding by a running \
             gateway is unaffected)",
            None,
        ));
    }
    if matches!(service.os_will_run, OsWillRun::Unknown { .. }) && service.platform == "unknown" {
        findings.push(finding(
            "service_query_failed",
            Severity::Warn,
            "service state could not be determined",
            match &service.os_will_run {
                OsWillRun::Unknown { why } => why.clone(),
                _ => String::new(),
            },
            None,
        ));
    }

    // --- live gateway (control channel + identity probe) ---
    let control_live = control::instance_is_live(data_dir);
    let gateway_status = if control_live {
        match control::read_nonce(data_dir) {
            Ok(nonce) => match control::send(
                data_dir,
                &control::Request::Status {
                    nonce: nonce.to_string(),
                },
            ) {
                Ok(control::Response::Status(s)) => Some(*s),
                Ok(control::Response::Error { code, message }) => {
                    findings.push(finding(
                        "control_auth_failed",
                        Severity::Error,
                        "control channel refused this session",
                        format!(
                            "the running gateway answered `{code}: {message}` — its nonce \
                             does not match this data directory's nonce file (usually a \
                             stale file after a crash, or two gateways fighting over one \
                             directory)"
                        ),
                        Some("tethra gateway restart"),
                    ));
                    None
                }
                Ok(other) => {
                    findings.push(finding(
                        "control_protocol_mismatch",
                        Severity::Error,
                        "unexpected control response",
                        format!("{other:?} — the running service likely predates this CLI"),
                        Some("tethra gateway repair"),
                    ));
                    None
                }
                Err(e) => {
                    findings.push(finding(
                        "control_unreachable",
                        Severity::Warn,
                        "control channel present but unresponsive",
                        e.to_string(),
                        Some("tethra gateway restart"),
                    ));
                    None
                }
            },
            Err(_) => {
                findings.push(finding(
                    "control_nonce_missing",
                    Severity::Warn,
                    "a gateway is listening but its nonce file is gone",
                    "status and graceful stop are unavailable without the nonce; the \
                     process is probably from a previous boot of this directory",
                    Some("tethra gateway restart"),
                ));
                None
            }
        }
    } else {
        None
    };

    // --- forwarding-port identity ---
    let listener = config
        .port
        .map(|port| control::verify_listener(data_dir, port));
    if let (Some(port), Some(identity)) = (config.port, listener.as_ref()) {
        match identity {
            ListenerIdentity::NotOurs => findings.push(finding(
                "port_collision",
                Severity::Error,
                format!("port {port} is held by something else"),
                "a process is listening on the persisted gateway port but could not \
                 prove it is this data directory's gateway. Linked projects would send \
                 their API traffic to whatever owns that port.",
                Some("tethra gateway restart (or free the port and repair)"),
            )),
            ListenerIdentity::NoNonce => findings.push(finding(
                "listener_unverifiable",
                Severity::Warn,
                format!("a listener on port {port} cannot be verified"),
                "something answers on the gateway port but no nonce file exists to \
                 verify it against",
                Some("tethra gateway restart"),
            )),
            _ => {}
        }
    }

    // --- state classification ---
    let live =
        matches!(listener, Some(ListenerIdentity::Verified { .. })) || gateway_status.is_some();
    if !service.installed && !live {
        findings.push(finding(
            "not_installed",
            Severity::Info,
            "gateway not installed",
            "no service is installed and nothing is running for this data directory",
            Some("tethra gateway install"),
        ));
    } else if service.installed && live {
        findings.push(finding(
            "running",
            Severity::Ok,
            "installed and running",
            format!(
                "the service is installed and the gateway is serving on port {}",
                gateway_status
                    .as_ref()
                    .map(|s| s.port)
                    .or(config.port)
                    .unwrap_or(0)
            ),
            None,
        ));
    } else if service.installed && !live {
        findings.push(finding(
            "installed_but_stopped",
            Severity::Warn,
            "installed but not running",
            "the service is installed but no gateway is serving; linked projects get \
             connection-refused until it starts",
            Some("tethra gateway start"),
        ));
    } else if live && !service.installed {
        findings.push(finding(
            "running_manually",
            Severity::Info,
            "running manually (no service installed)",
            "a gateway is serving for this data directory but no login service is \
             installed; it will not survive this terminal session",
            Some("tethra gateway install"),
        ));
    }

    if service.installed && !service.matches_data_dir {
        findings.push(finding(
            "stale_service_path",
            Severity::Error,
            "the installed service belongs to a different data directory",
            format!(
                "{} points at {:?}",
                service.definition_path,
                service
                    .definition
                    .as_ref()
                    .map(|d| d.data_dir.display().to_string())
            ),
            Some("tethra gateway install --force (or uninstall the other vault's service)"),
        ));
    }
    if service.installed && service.matches_data_dir && !service.binary_exists {
        findings.push(finding(
            "service_binary_missing",
            Severity::Error,
            "the service points at a binary that no longer exists",
            "the installed gateway binary was moved or deleted; the service cannot \
             start at login",
            Some("tethra gateway repair"),
        ));
    }
    if matches!(service.os_will_run, OsWillRun::OnlyWhileLoggedIn) {
        findings.push(finding(
            "linger_off",
            Severity::Info,
            "runs only while logged in",
            "systemd user services stop at logout unless lingering is enabled; Tethra \
             never changes that setting for you",
            Some("loginctl enable-linger (optional, your call)"),
        ));
    }
    if matches!(service.os_will_run, OsWillRun::RegisteredButNeverValidated) {
        findings.push(finding(
            "windows_never_validated",
            Severity::Warn,
            "Windows lifecycle has never been executed on Windows",
            "the registration exists, but Tethra's Windows service support is \
             compile-validated only; treat foreground `tethra gateway serve` as the \
             supported mode",
            None,
        ));
    }

    // --- version handshake ---
    let cli_version = env!("CARGO_PKG_VERSION").to_string();
    if let Some(status) = &gateway_status {
        if status.version != cli_version {
            findings.push(finding(
                "version_mismatch",
                Severity::Warn,
                "running service version differs from this CLI",
                format!(
                    "service {} vs CLI {cli_version}; behavior may differ until the \
                     service is upgraded",
                    status.version
                ),
                Some("tethra gateway repair"),
            ));
        }
    }
    if let (Some(bin_ver), Some(cfg_ver)) = (
        service.binary_version.as_ref(),
        config.service_version.as_ref(),
    ) {
        if bin_ver != cfg_ver {
            findings.push(finding(
                "recorded_version_drift",
                Severity::Info,
                "installed binary and recorded version differ",
                format!("binary {bin_ver}, recorded {cfg_ver}"),
                Some("tethra gateway repair"),
            ));
        }
    }

    // --- running-gateway health ---
    if let Some(status) = &gateway_status {
        if status.routes == 0 {
            findings.push(finding(
                "no_routes",
                Severity::Warn,
                "no forwardable routes",
                "the gateway is running but nothing can be forwarded; every request \
                 answers 404",
                Some("tethra gateway route add <provider>"),
            ));
        } else {
            findings.push(finding(
                "forwarding_active",
                Severity::Ok,
                "forwarding active",
                format!(
                    "{} route(s) forwardable{}",
                    status.routes,
                    if status.routes_unavailable > 0 {
                        format!(
                            ", {} unavailable (vault locked since boot)",
                            status.routes_unavailable
                        )
                    } else {
                        String::new()
                    }
                ),
                None,
            ));
        }
        if status.routes_disabled > 0 {
            findings.push(finding(
                "routes_disabled",
                Severity::Info,
                format!("{} route(s) disabled", status.routes_disabled),
                "disabled routes answer 404 exactly like removed ones",
                Some("tethra gateway route enable <prefix>"),
            ));
        }
        if !status.routes_skipped.is_empty() {
            let detail = status
                .routes_skipped
                .iter()
                .map(|(p, why)| format!("{p}: {why}"))
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(finding(
                "invalid_route_snapshot",
                Severity::Error,
                "route rows that cannot be loaded",
                detail,
                Some("remove and re-add the affected route"),
            ));
        }
        if status.routes_degraded {
            findings.push(finding(
                "route_reads_degraded",
                Severity::Warn,
                "route configuration cannot be re-read",
                "forwarding continues on the last-known-good table; recent route \
                 changes are not live",
                None,
            ));
        }
        if status.recording_paused {
            findings.push(finding(
                "recording_paused",
                Severity::Warn,
                "recording paused",
                "forwarding continues but nothing is recorded — this window will be a \
                 coverage gap",
                Some("tethra gateway recording resume"),
            ));
        } else if status.recording_degraded {
            findings.push(finding(
                "recording_degraded",
                Severity::Warn,
                "recording degraded",
                format!(
                    "observation persistence is failing ({} persist failure(s){}); \
                     forwarding is unaffected",
                    status.persist_failures,
                    status
                        .last_error
                        .as_ref()
                        .map(|e| format!(", last error {e}"))
                        .unwrap_or_default()
                ),
                None,
            ));
        } else {
            findings.push(finding(
                "recording_active",
                Severity::Ok,
                "recording active",
                format!(
                    "{} event(s) written{}",
                    status.written_events,
                    status
                        .last_observation_at
                        .as_ref()
                        .map(|t| format!(", last at {t}"))
                        .unwrap_or_else(|| ", none yet (absence of recorded traffic is \
                                            not evidence of absence of traffic)"
                            .into())
                ),
                None,
            ));
        }
        if status.queue_depth > 0 {
            findings.push(finding(
                "buffering",
                Severity::Info,
                format!("{} event(s) queued", status.queue_depth),
                "observations are buffered ahead of the writer; normal under load",
                None,
            ));
        }
        if status.dropped_events > 0 {
            findings.push(finding(
                "buffer_overflow",
                Severity::Warn,
                format!("{} event(s) dropped", status.dropped_events),
                "the observation queue overflowed; forwarding was protected, but those \
                 exchanges are a permanent coverage gap",
                None,
            ));
        }
        if status.dropped_events > 0 || status.recording_paused || status.recording_degraded {
            findings.push(finding(
                "coverage_gap",
                Severity::Warn,
                "recorded history has gaps",
                "dropped, paused, or unpersisted windows mean the local record \
                 understates real traffic; never read gateway history as complete",
                None,
            ));
        }
        if !status.matching_key_present {
            findings.push(finding(
                "vault_locked_attribution",
                Severity::Info,
                "credential attribution off (no matching key)",
                "exchanges record `unavailable_no_key` until a key is pushed; \
                 forwarding and metadata recording continue",
                Some("tethra gateway push-key"),
            ));
        }
    } else if live {
        findings.push(finding(
            "unhealthy_process",
            Severity::Error,
            "gateway reachable but not healthy",
            "the listener answers its identity probe but the control channel gives no \
             status; the process is degraded",
            Some("tethra gateway restart"),
        ));
    }

    // --- linked projects ---
    let mut links = Vec::new();
    if let Some(conn) = &conn {
        if let Ok(rows) = routes::list_project_links(conn) {
            for row in rows {
                links.push(link_health(&row, &config, live));
            }
        }
    }
    let at_risk: Vec<&LinkHealth> = links.iter().filter(|l| !l.issues.is_empty()).collect();
    if !at_risk.is_empty() {
        let detail = at_risk
            .iter()
            .map(|l| {
                format!(
                    "{} → {} ({})",
                    l.project_id,
                    l.route_prefix,
                    l.issues.join(", ")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        findings.push(finding(
            "linked_projects_at_risk",
            Severity::Warn,
            format!("{} linked project(s) need attention", at_risk.len()),
            detail,
            None,
        ));
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let overall = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Ok);
    Doctor {
        overall,
        findings,
        service,
        gateway: gateway_status,
        listener,
        configured_port: config.port,
        enabled: config.enabled,
        links,
        cli_version,
    }
}

/// Drift checks for one link, from its recorded state.
fn link_health(
    row: &routes::ProjectLinkRow,
    config: &store::GatewayConfig,
    live: bool,
) -> LinkHealth {
    let mut issues = Vec::new();
    let env_path = row.env_path.clone();
    let mut file_exists = false;
    let mut points_at_gateway = false;

    if let Some(path) = &env_path {
        let p = PathBuf::from(path);
        file_exists = p.exists();
        if !file_exists {
            issues.push("linked .env file is missing".into());
        } else if let Ok(content) = std::fs::read_to_string(&p) {
            let expected_fragment = format!("/p/{}/", row.link_slug);
            points_at_gateway = content.contains(&expected_fragment);
            if !points_at_gateway {
                issues.push(
                    "the .env no longer carries this link's gateway URL (edited or \
                     restored by hand)"
                        .into(),
                );
            }
            if points_at_gateway {
                if let Some(port) = config.port {
                    if !content.contains(&format!("127.0.0.1:{port}/")) {
                        issues.push(format!(
                            "the .env points at a different port than the persisted {port} \
                             (the gateway moved; re-link the project)"
                        ));
                    }
                }
                let has_no_proxy = content
                    .lines()
                    .any(|l| l.trim_start().to_ascii_lowercase().starts_with("no_proxy"));
                if !has_no_proxy {
                    issues.push("NO_PROXY is gone; a proxy could capture loopback traffic".into());
                }
            }
        }
        if points_at_gateway && !config.enabled && !live {
            issues.push(
                "the .env points at the gateway but the gateway is disabled and not \
                 running — SDK calls will get connection-refused"
                    .into(),
            );
        }
    }

    LinkHealth {
        project_id: row.project_id.clone(),
        route_prefix: row.route_prefix.clone(),
        env_path,
        env_file_exists: file_exists,
        env_points_at_gateway: points_at_gateway,
        issues,
    }
}
