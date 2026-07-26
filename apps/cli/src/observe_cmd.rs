//! `tethra observe` — inspect and manage runtime API observability.

use crate::ctx::Ctx;
use crate::render;
use anyhow::{anyhow, bail, Result};
use api_tracker_core::runtime::model::ObservationMode;
use api_tracker_core::runtime::{aggregate, model};
use api_tracker_core::vault::UnlockedVault;
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum ObserveCmd {
    /// Overview of all observed APIs (request volume, error rate, latency).
    Overview,
    /// List every observed API (the automatic inventory).
    Apis,
    /// Show one observed API's metrics, endpoints, and recent sanitized events.
    Api {
        /// Service id (or host).
        selector: String,
    },
    /// List observation sessions.
    Sessions {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Show one session's metrics, credential attributions, and compatibility.
    Show {
        /// Session id (or unambiguous prefix).
        session: String,
    },
    /// Delete one session and its events.
    DeleteSession {
        session: String,
        #[arg(long)]
        yes: bool,
    },
    /// Delete all observability data for one project.
    DeleteProject {
        project: String,
        #[arg(long)]
        yes: bool,
    },
    /// Delete ALL observability data (reauthentication required).
    DeleteAll {
        #[arg(long)]
        yes: bool,
    },
    /// Run local diagnostics for the observation subsystem.
    Diagnostics,
    /// Local certificate authority management.
    #[command(subcommand)]
    Cert(CertCmd),
    /// Observability settings.
    #[command(subcommand)]
    Settings(SettingsCmd),
    /// Internal-destination allowlist management.
    #[command(subcommand)]
    Allow(AllowCmd),
}

#[derive(Subcommand)]
pub enum CertCmd {
    /// Show the local CA status (fingerprint, dates, system-trust state).
    Status,
    /// Rotate the local CA (reauthentication required).
    Rotate,
    /// Remove the local CA (reauthentication required).
    Remove,
    /// Install the CA into the OS trust store (Mode C — reauthentication + an
    /// OS prompt; off by default).
    Install {
        #[arg(long)]
        yes: bool,
    },
    /// Remove the CA from the OS trust store.
    Uninstall,
}

#[derive(Subcommand)]
pub enum SettingsCmd {
    Show,
    Set(SettingsSetArgs),
}

#[derive(Args)]
pub struct SettingsSetArgs {
    /// Default observation mode for Tethra-launched runs (off|connection|metadata).
    #[arg(long)]
    pub default_mode: Option<String>,
    #[arg(long)]
    pub event_days: Option<u32>,
    #[arg(long)]
    pub aggregate_days: Option<u32>,
}

#[derive(Subcommand)]
pub enum AllowCmd {
    List {
        project: String,
    },
    Add {
        project: String,
        host: String,
        port: u16,
        #[arg(long, default_value = "")]
        note: String,
    },
    Remove {
        project: String,
        host: String,
        port: u16,
    },
}

pub fn run(ctx: &Ctx, cmd: ObserveCmd) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    match cmd {
        ObserveCmd::Overview => overview(ctx, &vault),
        ObserveCmd::Apis => apis(ctx, &vault),
        ObserveCmd::Api { selector } => api_detail(ctx, &vault, &selector),
        ObserveCmd::Sessions { project, limit } => sessions(ctx, &vault, project.as_deref(), limit),
        ObserveCmd::Show { session } => show_session(ctx, &vault, &session),
        ObserveCmd::DeleteSession { session, yes } => {
            if !crate::ctx::confirm(
                &format!("Delete observation session '{session}' and its events?"),
                yes,
            )? {
                bail!("aborted");
            }
            vault.observe_delete_session(&session)?;
            println!("Deleted session '{session}'.");
            Ok(())
        }
        ObserveCmd::DeleteProject { project, yes } => {
            if !crate::ctx::confirm(
                &format!("Delete ALL observability data for project '{project}'?"),
                yes,
            )? {
                bail!("aborted");
            }
            vault.observe_delete_project(&project)?;
            println!("Deleted observability data for project '{project}'.");
            Ok(())
        }
        ObserveCmd::DeleteAll { yes } => {
            if !crate::ctx::confirm("Delete ALL observability data? This cannot be undone.", yes)? {
                bail!("aborted");
            }
            let pw = crate::ctx::prompt_secret("Master password")?;
            vault.observe_delete_all(&pw)?;
            println!("All observability data deleted.");
            Ok(())
        }
        ObserveCmd::Diagnostics => diagnostics(ctx, &vault),
        ObserveCmd::Cert(c) => cert(ctx, &vault, c),
        ObserveCmd::Settings(s) => settings(ctx, &vault, s),
        ObserveCmd::Allow(a) => allow(ctx, &vault, a),
    }
}

fn overview(ctx: &Ctx, vault: &UnlockedVault) -> Result<()> {
    let services = vault.observe_services()?;
    let mut rows = Vec::new();
    for s in &services {
        let m = aggregate::service_metrics(vault.connection(), &s.id, None)?;
        rows.push(vec![
            s.host.clone(),
            s.provider_id.clone().unwrap_or_else(|| "(unknown)".into()),
            m.total.to_string(),
            format!("{:.0}%", m.error_rate * 100.0),
            m.p95_ms
                .map(|v| format!("{v}ms"))
                .unwrap_or_else(|| "-".into()),
        ]);
    }
    render::emit(ctx.json, &services, || {
        if services.is_empty() {
            println!("No API traffic observed yet. Run `tethra run --observe -- <command>`.");
        } else {
            render::table(&["API", "PROVIDER", "REQUESTS", "ERROR RATE", "p95"], &rows);
            println!("\nMetadata only — endpoint paths are sanitized; no bodies, headers, or query strings are stored.");
        }
    });
    Ok(())
}

fn apis(ctx: &Ctx, vault: &UnlockedVault) -> Result<()> {
    let services = vault.observe_services()?;
    let rows: Vec<Vec<String>> = services
        .iter()
        .map(|s| {
            vec![
                s.id[..8.min(s.id.len())].to_string(),
                s.host.clone(),
                s.user_provider
                    .clone()
                    .or_else(|| s.provider_id.clone())
                    .unwrap_or_else(|| "(unknown)".into()),
                s.source.clone(),
                s.classification.clone(),
                s.last_seen_at.clone(),
            ]
        })
        .collect();
    render::emit(ctx.json, &services, || {
        render::table(
            &["ID", "HOST", "PROVIDER", "SOURCE", "CLASS", "LAST SEEN"],
            &rows,
        );
    });
    Ok(())
}

fn resolve_service(vault: &UnlockedVault, selector: &str) -> Result<model::ObservedServiceRow> {
    let services = vault.observe_services()?;
    services
        .into_iter()
        .find(|s| {
            s.id == selector
                || s.id.starts_with(selector)
                || s.host == selector.to_ascii_lowercase()
        })
        .ok_or_else(|| anyhow!("no observed API matches '{selector}'"))
}

fn api_detail(ctx: &Ctx, vault: &UnlockedVault, selector: &str) -> Result<()> {
    let svc = resolve_service(vault, selector)?;
    let metrics = aggregate::service_metrics(vault.connection(), &svc.id, None)?;
    let endpoints = vault.observe_service_endpoints(&svc.id)?;
    let events = vault.observe_service_events(&svc.id, 20)?;
    if ctx.json {
        render::emit(
            true,
            &serde_json::json!({
                "service": svc, "metrics": metrics, "endpoints": endpoints, "recent_events": events,
            }),
            || {},
        );
        return Ok(());
    }
    println!("API:        {}", svc.host);
    println!(
        "Provider:   {} (source: {})",
        svc.user_provider
            .or(svc.provider_id)
            .unwrap_or_else(|| "(unknown)".into()),
        svc.source
    );
    println!("Class:      {}", svc.classification);
    println!("First seen: {}", svc.first_seen_at);
    println!("Last seen:  {}", svc.last_seen_at);
    print_metrics(&metrics);
    println!("\nEndpoints (sanitized):");
    let ep_rows: Vec<Vec<String>> = endpoints
        .iter()
        .map(|e| {
            vec![
                e.method.clone(),
                e.path_template.clone(),
                e.template_confidence.clone(),
            ]
        })
        .collect();
    render::table(&["METHOD", "PATH TEMPLATE", "CONFIDENCE"], &ep_rows);
    println!("\nRecent events (sanitized):");
    let ev_rows: Vec<Vec<String>> = events
        .iter()
        .map(|e| {
            vec![
                e.at.clone(),
                e.method.clone(),
                e.path_template.clone(),
                e.status_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into()),
                e.outcome.clone(),
                e.latency_ms
                    .map(|l| format!("{l}ms"))
                    .unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    render::table(
        &["AT", "METHOD", "PATH", "STATUS", "OUTCOME", "LATENCY"],
        &ev_rows,
    );
    Ok(())
}

fn print_metrics(m: &aggregate::Metrics) {
    println!("\nMetrics:");
    println!(
        "  requests:   {}  (success {}, errors {}, {:.1}% error rate)",
        m.total,
        m.success,
        m.errors,
        m.error_rate * 100.0
    );
    println!(
        "  4xx/5xx:    {} / {}   auth(401) {}  forbidden(403) {}  rate-limited(429) {}",
        m.c4xx, m.c5xx, m.auth_errors, m.forbidden, m.rate_limited
    );
    println!(
        "  transport:  {}   tls: {}   (transport/TLS failures are NOT counted as HTTP errors)",
        m.transport_errors, m.tls_errors
    );
    let fmt = |v: Option<i64>| v.map(|x| format!("{x}ms")).unwrap_or_else(|| "-".into());
    println!(
        "  latency:    p50 {}  p95 {}  p99 {}  (approximate, from a histogram)",
        fmt(m.p50_ms),
        fmt(m.p95_ms),
        fmt(m.p99_ms)
    );
    println!(
        "  bytes:      req {}  resp {}",
        m.request_bytes, m.response_bytes
    );
}

fn sessions(ctx: &Ctx, vault: &UnlockedVault, project: Option<&str>, limit: u32) -> Result<()> {
    let sessions = vault.observe_sessions(project, limit)?;
    let rows: Vec<Vec<String>> = sessions
        .iter()
        .map(|s| {
            vec![
                s.id[..8.min(s.id.len())].to_string(),
                s.mode.clone(),
                s.status.clone(),
                s.runtime_detected.clone().unwrap_or_else(|| "-".into()),
                s.request_count.to_string(),
                s.error_count.to_string(),
                if s.partial_coverage {
                    "PARTIAL".into()
                } else {
                    "full".into()
                },
                s.started_at.clone(),
            ]
        })
        .collect();
    render::emit(ctx.json, &sessions, || {
        render::table(
            &[
                "ID", "MODE", "STATUS", "RUNTIME", "REQ", "ERR", "COVERAGE", "STARTED",
            ],
            &rows,
        );
    });
    Ok(())
}

fn show_session(ctx: &Ctx, vault: &UnlockedVault, ident: &str) -> Result<()> {
    let session = vault.observe_session(ident)?;
    let metrics = aggregate::session_metrics(vault.connection(), &session.id)?;
    let attributions = vault.observe_session_attributions(&session.id)?;
    let compat = vault.observe_session_compat(&session.id)?;
    let events = vault.observe_session_events(&session.id, 20)?;
    if ctx.json {
        render::emit(
            true,
            &serde_json::json!({
                "session": session, "metrics": metrics, "attributions": attributions,
                "compatibility": compat, "recent_events": events,
            }),
            || {},
        );
        return Ok(());
    }
    println!("Session:    {}", session.id);
    println!("Command:    {}", session.command);
    println!(
        "Mode:       {}   status: {}{}",
        session.mode,
        session.status,
        session
            .interrupt_reason
            .map(|r| format!(" ({r})"))
            .unwrap_or_default()
    );
    println!(
        "Runtime:    {}   trust: {}",
        session.runtime_detected.unwrap_or_else(|| "-".into()),
        session.trust_level.unwrap_or_else(|| "-".into())
    );
    if session.partial_coverage {
        println!(
            "COVERAGE:   PARTIAL — some traffic bypassed monitoring (see compatibility below)."
        );
    }
    print_metrics(&metrics);
    if !attributions.is_empty() {
        println!("\nCredential attribution:");
        let rows: Vec<Vec<String>> = attributions
            .iter()
            .map(|a| {
                vec![
                    a.host.clone(),
                    a.confidence.clone(),
                    a.request_count.to_string(),
                    a.credential_version
                        .map(|v| format!("v{v}"))
                        .unwrap_or_else(|| "-".into()),
                    a.evidence.clone(),
                ]
            })
            .collect();
        render::table(
            &["API", "CONFIDENCE", "REQUESTS", "VERSION", "EVIDENCE"],
            &rows,
        );
    }
    if !compat.is_empty() {
        println!("\nCompatibility:");
        for c in &compat {
            println!("  [{}] {}: {}", c.status, c.check, c.detail);
        }
    }
    Ok(())
}

fn diagnostics(ctx: &Ctx, vault: &UnlockedVault) -> Result<()> {
    let ca_present = vault.observe_ca_status()?.present;
    let checks = api_tracker_observe::diagnostics::run(ca_present);
    render::emit(ctx.json, &checks, || {
        for c in &checks {
            println!("  [{}] {}: {}", c.status.to_uppercase(), c.name, c.detail);
        }
    });
    Ok(())
}

fn cert(ctx: &Ctx, vault: &UnlockedVault, cmd: CertCmd) -> Result<()> {
    match cmd {
        CertCmd::Status => {
            let status = vault.observe_ca_status()?;
            render::emit(ctx.json, &status, || {
                if !status.present {
                    println!(
                        "No local CA yet — generated automatically on the first metadata-mode run."
                    );
                } else {
                    println!("Local CA present.");
                    println!(
                        "  fingerprint (SHA-256): {}",
                        status.fingerprint_sha256.as_deref().unwrap_or("")
                    );
                    println!(
                        "  created:   {}",
                        status.created_at.as_deref().unwrap_or("")
                    );
                    println!("  expires:   {}", status.not_after.as_deref().unwrap_or(""));
                    println!("  system trust: {}", status.system_trust);
                }
            });
            Ok(())
        }
        CertCmd::Rotate => {
            let pw = crate::ctx::prompt_secret("Master password")?;
            vault.observe_ca_remove(&pw)?; // reauth + clear
            let g = api_tracker_observe::ca::generate_ca(vault.vault_id())
                .map_err(|e| anyhow!("{e}"))?;
            vault.observe_ca_store(
                &g.cert_pem,
                &g.key_der,
                &g.fingerprint_sha256,
                &g.serial_hex,
                &g.not_after,
            )?;
            println!(
                "CA rotated. New fingerprint (SHA-256): {}",
                g.fingerprint_sha256
            );
            println!("If you had installed the previous CA in your system trust store, remove it and reinstall this one.");
            Ok(())
        }
        CertCmd::Remove => {
            let pw = crate::ctx::prompt_secret("Master password")?;
            vault.observe_ca_remove(&pw)?;
            println!("Local CA removed. If it was installed in your system trust store, run `observe cert uninstall`.");
            Ok(())
        }
        CertCmd::Install { yes } => cert_install(vault, yes),
        CertCmd::Uninstall => {
            api_tracker_observe::systemtrust::remove().map_err(|e| anyhow!("{e}"))?;
            vault.observe_ca_set_system_trust("absent", None)?;
            println!("Removed the Tethra CA from the OS trust store (if present).");
            Ok(())
        }
    }
}

fn cert_install(vault: &UnlockedVault, yes: bool) -> Result<()> {
    // The explanation screen (Mode C). Explicit, informed consent.
    println!("Mode C — install the Tethra CA into your operating-system trust store.");
    println!();
    println!("  • This lets programs that ignore scoped trust variables be monitored.");
    println!("  • EVERY application on this machine will then trust certificates signed");
    println!("    by this CA. That is powerful — only proceed if you understand it.");
    println!("  • The CA private key stays on this device, encrypted under your vault.");
    println!("  • Observation still records METADATA ONLY — never bodies or secrets.");
    println!("  • Your operating system will show its OWN authorization prompt.");
    println!("  • You can remove it any time with `observe cert uninstall`.");
    println!();
    if !crate::ctx::confirm("Proceed with system-trust installation?", yes)? {
        bail!("aborted");
    }
    let pw = crate::ctx::prompt_secret("Master password")?;
    vault.verify_master_password(&pw)?;
    let (pem, _key, fp) = vault
        .observe_ca_material()?
        .ok_or_else(|| anyhow!("no local CA yet — run a metadata-mode observation first"))?;
    let dir = vault.paths().data_dir.clone();
    api_tracker_observe::systemtrust::install(&dir, &pem).map_err(|e| anyhow!("{e}"))?;
    vault
        .observe_ca_set_system_trust("installed", Some(&api_tracker_core::clock::now_rfc3339()))?;
    println!("Installed. Fingerprint (SHA-256): {fp}");
    Ok(())
}

fn settings(ctx: &Ctx, vault: &UnlockedVault, cmd: SettingsCmd) -> Result<()> {
    match cmd {
        SettingsCmd::Show => {
            let s = vault.observe_settings()?;
            render::emit(ctx.json, &s, || {
                println!("default mode:       {}", s.default_mode);
                println!("event retention:    {} days", s.event_retention_days);
                println!("aggregate retention:{} days", s.aggregate_retention_days);
            });
            Ok(())
        }
        SettingsCmd::Set(args) => {
            let mut s = vault.observe_settings()?;
            if let Some(m) = &args.default_mode {
                s.default_mode =
                    ObservationMode::parse(m).ok_or_else(|| anyhow!("invalid mode '{m}'"))?;
            }
            if let Some(d) = args.event_days {
                s.event_retention_days = d;
            }
            if let Some(d) = args.aggregate_days {
                s.aggregate_retention_days = d;
            }
            vault.observe_settings_set(&s)?;
            println!("Updated observability settings.");
            Ok(())
        }
    }
}

fn allow(ctx: &Ctx, vault: &UnlockedVault, cmd: AllowCmd) -> Result<()> {
    match cmd {
        AllowCmd::List { project } => {
            let list = vault.observe_allowlist(&project)?;
            let rows: Vec<Vec<String>> = list
                .iter()
                .map(|(h, p, n)| vec![h.clone(), p.to_string(), n.clone()])
                .collect();
            render::emit(ctx.json, &list, || {
                render::table(&["HOST", "PORT", "NOTE"], &rows);
            });
            Ok(())
        }
        AllowCmd::Add {
            project,
            host,
            port,
            note,
        } => {
            vault.observe_allowlist_add(&project, &host, port, &note)?;
            println!("Allowlisted {host}:{port} for project '{project}'. WARNING: traffic to it bypasses the private-address block.");
            Ok(())
        }
        AllowCmd::Remove {
            project,
            host,
            port,
        } => {
            if vault.observe_allowlist_remove(&project, &host, port)? {
                println!("Removed {host}:{port} from project '{project}'.");
            } else {
                println!("No such allowlist entry.");
            }
            Ok(())
        }
    }
}
