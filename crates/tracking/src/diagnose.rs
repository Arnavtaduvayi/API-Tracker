//! Ranked, evidence-based no-traffic diagnosis. Never a blank screen: if
//! every check passes, the result says so explicitly.
//!
//! Each diagnosis has a stable id (mirroring `doctor::Finding.id`) so
//! tests can pin them and the UI can deep-link help.

use std::path::Path;

use api_tracker_core::envfile::EnvDocument;
use api_tracker_gateway::{doctor, store};
use rusqlite::Connection;
use serde::Serialize;

use api_tracker_core::Result;

use crate::detect::ProjectDetection;
use crate::state::{configured_providers, TrackingSetup};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosisSeverity {
    Hint,
    Warn,
    Error,
    AllClear,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnosis {
    pub id: &'static str,
    pub severity: DiagnosisSeverity,
    pub message: String,
}

/// Diagnose with live host state (production path).
pub fn diagnose(
    conn: &Connection,
    data_dir: &Path,
    setup: &TrackingSetup,
) -> Result<Vec<Diagnosis>> {
    let report = doctor::diagnose(data_dir);
    diagnose_with(conn, setup, &report)
}

/// Diagnose against a supplied doctor report (the test seam, mirroring
/// `doctor::diagnose_with`).
pub fn diagnose_with(
    conn: &Connection,
    setup: &TrackingSetup,
    report: &doctor::Doctor,
) -> Result<Vec<Diagnosis>> {
    let mut out = Vec::new();
    let detection: Option<ProjectDetection> = serde_json::from_str(&setup.detection_json).ok();
    let folder = Path::new(&setup.folder_path);

    // 1. Gateway availability problems outrank everything else — nothing
    //    can arrive while the service is down.
    let blocking = [
        "not_installed",
        "installed_but_stopped",
        "port_collision",
        "service_binary_missing",
        "stale_service_path",
        "database_unavailable",
    ];
    for finding in &report.findings {
        if blocking.contains(&finding.id) {
            out.push(Diagnosis {
                id: "gateway_unavailable",
                severity: DiagnosisSeverity::Error,
                message: format!("{} — {}", finding.title, finding.detail),
            });
        }
    }

    // 2. Link drift: the env file no longer points at the gateway.
    for link in &report.links {
        if link.project_id != setup.project_id {
            continue;
        }
        if !link.env_file_exists || !link.env_points_at_gateway || !link.issues.is_empty() {
            let detail = if link.issues.is_empty() {
                "the linked file no longer points at the gateway".to_string()
            } else {
                link.issues.join("; ")
            };
            out.push(Diagnosis {
                id: "env_drifted",
                severity: DiagnosisSeverity::Error,
                message: format!(
                    "{}: {detail}. Re-run tracking setup to restore it.",
                    link.env_path.as_deref().unwrap_or("the linked env file")
                ),
            });
        }
    }

    // 3. Docker / Compose: containers see neither this machine's .env
    //    change nor 127.0.0.1. Re-checked live, not from stale detection.
    let compose_live = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ]
    .iter()
    .any(|f| folder.join(f).is_file());
    if compose_live {
        out.push(Diagnosis {
            id: "docker_compose",
            severity: DiagnosisSeverity::Warn,
            message: "This project runs with Docker Compose (compose file found). Containers \
                      don't see this machine's .env change or 127.0.0.1."
                .to_string(),
        });
    }

    // 4. Restart hint — the default first cause when nothing contradicts
    //    it: configuration was applied and no traffic arrived.
    if out.iter().all(|d| d.severity != DiagnosisSeverity::Error) {
        out.insert(
            0,
            Diagnosis {
                id: "not_restarted",
                severity: DiagnosisSeverity::Hint,
                message: "The project may not have been restarted — a running process keeps \
                          its old configuration. Restart it, then make one request."
                    .to_string(),
            },
        );
    }

    // 5. Variable overridden in a later-loaded env file.
    if let Some(detection) = &detection {
        let mut linked_vars: Vec<(String, String)> = Vec::new(); // (var, file)
        for provider in detection.configurable() {
            if let Some(manifest) = api_tracker_core::providers::find(&provider.provider_id) {
                if let Some(gw) = &manifest.gateway {
                    for var in &gw.env_vars {
                        for file in &provider.target_env_files {
                            linked_vars.push((var.clone(), file.clone()));
                        }
                    }
                }
            }
        }
        // dotenv-flow style load order: later entries override earlier.
        let load_order = [".env", ".env.local", ".env.development", ".env.production"];
        for (var, linked_file) in &linked_vars {
            let linked_rank = load_order.iter().position(|f| f == linked_file);
            for candidate in &detection.env_files {
                if candidate.class != "values" || candidate.rel_path == *linked_file {
                    continue;
                }
                let candidate_rank = load_order.iter().position(|f| *f == candidate.rel_path);
                let later_loaded = match (linked_rank, candidate_rank) {
                    (Some(a), Some(b)) => b > a,
                    _ => true, // unknown files: flag as possible override
                };
                if !later_loaded {
                    continue;
                }
                let path = folder.join(&candidate.rel_path);
                let Ok(content) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let doc = EnvDocument::parse(&content);
                if doc.get(var).is_some() {
                    out.push(Diagnosis {
                        id: "var_overridden",
                        severity: DiagnosisSeverity::Warn,
                        message: format!(
                            "{var} is also set in {}, which may override the file Tethra \
                             edited ({linked_file}).",
                            candidate.rel_path
                        ),
                    });
                }
            }
        }

        // 6. No dotenv loader detected.
        if detection.project_signals.dotenv_loader == Some(false) {
            out.push(Diagnosis {
                id: "no_dotenv_loader",
                severity: DiagnosisSeverity::Warn,
                message: "No dotenv loader was detected in the project's manifests — if the \
                          app doesn't read .env files, set the variable in the environment \
                          that runs it."
                    .to_string(),
            });
        }

        // 7. Remote / container execution indicators.
        if detection.project_signals.devcontainer {
            out.push(Diagnosis {
                id: "remote_execution",
                severity: DiagnosisSeverity::Warn,
                message: "A .devcontainer configuration was found — if the project runs in a \
                          container or remote environment, it cannot reach this machine's \
                          127.0.0.1 (possible cause, not certain)."
                    .to_string(),
            });
        }

        // 8. Unsupported providers, honestly restated.
        for provider in &detection.providers {
            if matches!(
                provider.configurability,
                crate::detect::Configurability::Unsupported { .. }
            ) {
                out.push(Diagnosis {
                    id: "provider_unsupported",
                    severity: DiagnosisSeverity::Hint,
                    message: format!(
                        "{} was detected but is not currently observable this way{}",
                        provider.display_name,
                        provider
                            .limitations
                            .first()
                            .map(|l| format!(": {l}"))
                            .unwrap_or_else(|| ".".to_string())
                    ),
                });
            }
        }
    }

    // 9. Traffic reached the gateway without this project's link slug —
    //    inference from route counters, labeled as such.
    for prefix in configured_providers(setup) {
        if let Ok(n) = store::counter_total(conn, &prefix, "unlinked_requests") {
            if n > 0 {
                out.push(Diagnosis {
                    id: "unlinked_traffic",
                    severity: DiagnosisSeverity::Warn,
                    message: format!(
                        "{n} request(s) reached the '{prefix}' route without this project's \
                         link — something may be using the gateway's base URL without the \
                         project-scoped path (inference, not certainty)."
                    ),
                });
                break;
            }
        }
    }

    // 10. Path check status: report gateway-side health explicitly.
    let gateway_healthy = report
        .findings
        .iter()
        .any(|f| f.id == "running" || f.id == "forwarding_active");
    if gateway_healthy && out.iter().all(|d| d.severity == DiagnosisSeverity::Hint) {
        out.push(Diagnosis {
            id: "all_clear",
            severity: DiagnosisSeverity::AllClear,
            message: "Everything on Tethra's side checks out. The gateway is running and \
                      routes are live — no request has arrived yet."
                .to_string(),
        });
    }

    Ok(out)
}
