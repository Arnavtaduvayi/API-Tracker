//! Plan assembly: one combined, previewable `TrackingPlan` from a
//! `ProjectDetection` plus the user's review-screen selections.
//!
//! Planning is read-only against the user's files. The single DB write a
//! non-dry-run caller performs first is [`ensure_port`] — persisting the
//! gateway port a stable base URL requires (the same bind-port-0 dance the
//! existing installers do, ADR 0019 O3). Nothing listens on the port until
//! apply installs or starts the service.

use std::collections::{BTreeMap, BTreeSet};

use api_tracker_core::{CoreError, Result};
use api_tracker_gateway::{envlink, lifecycle, store};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

use crate::detect::{Configurability, DetectionConfidence, ProjectDetection, UnsupportedReason};

/// The Tethra project this plan configures: an existing row, or one to be
/// created at apply (named after the folder unless the user renames it).
#[derive(Debug, Clone, Serialize)]
pub struct ProjectRef {
    pub id: Option<String>,
    pub name: String,
}

/// Review-screen output: which detected providers to configure, and the
/// verbatim user-confirmed origin for each custom-origin provider.
#[derive(Debug, Clone, Default)]
pub struct Selections {
    pub include: BTreeSet<String>,
    pub confirmed_origins: BTreeMap<String, String>,
}

impl Selections {
    /// The default selection: every **`Automatic`** Confirmed or Likely
    /// provider — that is, every provider whose destination comes from a
    /// compiled-in Tethra manifest and cannot be influenced by the project.
    ///
    /// `NeedsOriginConfirm` is deliberately NOT included. It used to be:
    /// the arm inserted the provider into `include` AND pre-filled
    /// `confirmed_origins` with the origin read from the project's own
    /// files, so the confirmation the variant is named for was satisfied by
    /// the code that was supposed to ask for it. A repository containing
    /// nothing but a committed `package.json` and a committed
    /// `SUPABASE_URL` therefore produced an enabled, MAC'd route to an
    /// attacker-chosen host under a single bulk "Proceed?" that `--yes`
    /// answered (ZFT-004).
    ///
    /// Callers add repository-discovered origins through
    /// [`Selections::approve_origin`] only after the user has approved that
    /// exact destination — see [`crate::origin`].
    pub fn defaults(detection: &ProjectDetection) -> Self {
        let mut sel = Selections::default();
        for p in detection.providers.iter() {
            if matches!(p.configurability, Configurability::Automatic)
                && p.confidence >= DetectionConfidence::Likely
            {
                sel.include.insert(p.provider_id.clone());
            }
        }
        sel
    }

    /// Providers whose destination was read from project content and which
    /// therefore need a separate, explicit approval before they can be
    /// configured. Returned in a stable order so one review screen can list
    /// them all with individually unchecked boxes.
    pub fn pending_origin_approvals(detection: &ProjectDetection) -> Vec<(String, String)> {
        detection
            .providers
            .iter()
            .filter_map(|p| match &p.configurability {
                Configurability::NeedsOriginConfirm { inferred_origin }
                    if p.confidence >= DetectionConfidence::Likely =>
                {
                    Some((p.provider_id.clone(), inferred_origin.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Record the user's approval of one exact origin for one provider.
    /// This is the ONLY way a repository-discovered destination enters a
    /// plan.
    pub fn approve_origin(&mut self, provider_id: &str, origin: &str) {
        self.include.insert(provider_id.to_string());
        self.confirmed_origins
            .insert(provider_id.to_string(), origin.to_string());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceAction {
    InstallService,
    StartService,
    /// Installed service binary is older than this build; repair is a
    /// named step in the apply report (O-22-2), never silent.
    RepairService {
        installed: String,
        current: String,
    },
    AlreadyRunning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteAction {
    CreateManifestRoute {
        prefix: String,
        provider_id: String,
    },
    CreateCustomRoute {
        prefix: String,
        provider_id: String,
        origin: String,
    },
    ReuseRoute {
        prefix: String,
        provider_id: String,
    },
    ReEnableRoute {
        prefix: String,
        provider_id: String,
    },
}

impl RouteAction {
    pub fn prefix(&self) -> &str {
        match self {
            RouteAction::CreateManifestRoute { prefix, .. }
            | RouteAction::CreateCustomRoute { prefix, .. }
            | RouteAction::ReuseRoute { prefix, .. }
            | RouteAction::ReEnableRoute { prefix, .. } => prefix,
        }
    }

    pub fn provider_id(&self) -> &str {
        match self {
            RouteAction::CreateManifestRoute { provider_id, .. }
            | RouteAction::CreateCustomRoute { provider_id, .. }
            | RouteAction::ReuseRoute { provider_id, .. }
            | RouteAction::ReEnableRoute { provider_id, .. } => provider_id,
        }
    }

    pub fn creates(&self) -> bool {
        matches!(
            self,
            RouteAction::CreateManifestRoute { .. } | RouteAction::CreateCustomRoute { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanWarning {
    /// A `LinkWarning` from an aggregated file plan, pre-rendered.
    File { message: String },
    /// No persisted port yet and the caller asked for a display-only plan:
    /// the port shown is provisional until tracking actually starts.
    ProvisionalPort { port: u16 },
    /// An existing custom route for this provider points at a different
    /// origin than the one confirmed now; the existing route is kept.
    ExistingOriginKept {
        prefix: String,
        existing_origin: String,
    },
    /// Honest note for providers detected but not configurable.
    UnsupportedProvider { provider_id: String, reason: String },
}

impl PlanWarning {
    pub fn describe(&self) -> String {
        match self {
            PlanWarning::File { message } => message.clone(),
            PlanWarning::ProvisionalPort { port } => format!(
                "port {port} is provisional; the final port is assigned when tracking starts"
            ),
            PlanWarning::ExistingOriginKept {
                prefix,
                existing_origin,
            } => format!(
                "route '{prefix}' already forwards to {existing_origin}; the existing \
                 destination was kept. Change it under Advanced if that is wrong."
            ),
            PlanWarning::UnsupportedProvider {
                provider_id,
                reason,
            } => {
                format!("{provider_id}: {reason}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartExpectation {
    /// Env files changed and the project loads them at startup.
    RequiredLikely,
    /// Env files changed but no loader was detected — a restart may not be
    /// enough; diagnosis will say so.
    Unknown,
    /// Nothing changed on disk (already linked).
    NotNeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionPlan {
    /// The user will be asked for the master password at apply.
    Requested,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrackingPlan {
    pub project: ProjectRef,
    pub folder: String,
    pub service_actions: Vec<ServiceAction>,
    pub route_actions: Vec<RouteAction>,
    pub link_plans: Vec<envlink::LinkPlan>,
    pub attribution: AttributionPlan,
    pub warnings: Vec<PlanWarning>,
    pub restart_expectation: RestartExpectation,
    pub port: u16,
    pub port_provisional: bool,
}

/// Persist the gateway port when none exists yet (the stable base URL
/// requires it). Idempotent; does NOT enable the gateway or start anything.
pub fn ensure_port(conn: &Connection) -> Result<u16> {
    let config = store::load_config(conn)?;
    if let Some(port) = config.port {
        return Ok(port);
    }
    let port = free_port()?;
    let mut config = config;
    config.port = Some(port);
    store::save_config(conn, &config)?;
    Ok(port)
}

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| CoreError::InvalidInput(format!("no loopback port available: {e}")))?;
    Ok(listener
        .local_addr()
        .map_err(|e| CoreError::InvalidInput(format!("no loopback port available: {e}")))?
        .port())
}

struct RouteRowLite {
    provider_id: String,
    enabled: bool,
    custom_origin: Option<String>,
    custom_origin_port: Option<u16>,
}

fn route_row(conn: &Connection, prefix: &str) -> Result<Option<RouteRowLite>> {
    Ok(conn
        .query_row(
            "SELECT provider_id, enabled, custom_origin, custom_origin_port
             FROM gateway_routes WHERE route_prefix = ?1",
            [prefix],
            |r| {
                Ok(RouteRowLite {
                    provider_id: r.get(0)?,
                    enabled: r.get::<_, i64>(1)? != 0,
                    custom_origin: r.get(2)?,
                    custom_origin_port: r.get::<_, Option<i64>>(3)?.map(|p| p as u16),
                })
            },
        )
        .optional()?)
}

/// Build the combined plan. Read-only. `service` comes from
/// `Lifecycle::for_host(..).status()` in production and from a fixture in
/// tests (the same seam `doctor::diagnose_with` uses); `listener_live` is
/// whether a verified gateway listener already answers on the persisted
/// port (`control::verify_listener`) — a manually-run `gateway serve`
/// counts as running, so tracking never installs a service over it.
pub fn plan(
    conn: &Connection,
    detection: &ProjectDetection,
    selections: &Selections,
    project: ProjectRef,
    service: &lifecycle::ServiceStatus,
    listener_live: bool,
) -> Result<TrackingPlan> {
    let mut warnings = Vec::new();

    // Port: persisted, else provisional for display-only plans.
    let config = store::load_config(conn)?;
    let (port, port_provisional) = match config.port {
        Some(p) => (p, false),
        None => {
            let p = free_port()?;
            warnings.push(PlanWarning::ProvisionalPort { port: p });
            (p, true)
        }
    };

    // Service actions.
    let mut service_actions = Vec::new();
    if service.installed && !service.matches_data_dir {
        // The login slot is occupied by a definition pointing at a DIFFERENT
        // Tethra data directory. `installed` alone used to be enough to fall
        // through to Repair or Start, both of which act on that other
        // installation's service — repair by replacing its definition, start
        // by bootstrapping it into this session. Neither is something an
        // automatic `track` run may do to another environment (ZFT-014).
        //
        // A hard stop, with the other data directory named, so the user can
        // decide rather than discovering it when their other gateway dies.
        return Err(CoreError::InvalidInput(format!(
            "the login slot for the local tracking service is held by another Tethra              installation ({}). Tethra will not reconfigure it. Use that installation, or              uninstall its service first: `tethra gateway uninstall --data-dir {}`.",
            service
                .definition
                .as_ref()
                .map(|d| d.data_dir.display().to_string())
                .unwrap_or_else(|| "unknown data directory".to_string()),
            service
                .definition
                .as_ref()
                .map(|d| d.data_dir.display().to_string())
                .unwrap_or_else(|| "<its data dir>".to_string()),
        )));
    }
    if listener_live {
        // A verified gateway already answers on the port (service or a
        // foreground `gateway serve`); nothing to install or start.
        service_actions.push(ServiceAction::AlreadyRunning);
    } else if !service.installed {
        service_actions.push(ServiceAction::InstallService);
    } else {
        let current = env!("CARGO_PKG_VERSION").to_string();
        let drifted = service
            .binary_version
            .as_ref()
            .map(|v| v != &current)
            .unwrap_or(false);
        if drifted {
            service_actions.push(ServiceAction::RepairService {
                installed: service.binary_version.clone().unwrap_or_default(),
                current,
            });
        } else if service.running {
            service_actions.push(ServiceAction::AlreadyRunning);
        }
        if !service.running {
            service_actions.push(ServiceAction::StartService);
        }
    }

    // Route actions + link plans per selected provider. Link plans are
    // CHAINED: provider N plans over provider N−1's projected output, so
    // several providers sharing one .env produce one coherent combined
    // diff whose apply (same order) satisfies every digest check.
    let mut route_actions = Vec::new();
    let mut link_plans = Vec::new();
    let mut projected: BTreeMap<String, String> = BTreeMap::new();
    for provider in detection.providers.iter() {
        let pid = &provider.provider_id;
        match &provider.configurability {
            Configurability::Unsupported { reason } => {
                if selections.include.contains(pid) {
                    return Err(CoreError::InvalidInput(format!(
                        "{pid} cannot be configured (unsupported)"
                    )));
                }
                warnings.push(PlanWarning::UnsupportedProvider {
                    provider_id: pid.clone(),
                    reason: match reason {
                        UnsupportedReason::NoConfigurableBaseUrl => provider
                            .limitations
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "no configurable base URL".to_string()),
                        UnsupportedReason::UnknownProvider => {
                            "not a provider Tethra knows yet".to_string()
                        }
                    },
                });
                continue;
            }
            _ if !selections.include.contains(pid) => continue,
            Configurability::Automatic => match route_row(conn, pid)? {
                Some(row) if !row.enabled => route_actions.push(RouteAction::ReEnableRoute {
                    prefix: pid.clone(),
                    provider_id: row.provider_id,
                }),
                Some(row) => route_actions.push(RouteAction::ReuseRoute {
                    prefix: pid.clone(),
                    provider_id: row.provider_id,
                }),
                None => route_actions.push(RouteAction::CreateManifestRoute {
                    prefix: pid.clone(),
                    provider_id: pid.clone(),
                }),
            },
            Configurability::NeedsOriginConfirm { .. } | Configurability::NeedsOriginInput => {
                let Some(origin) = selections.confirmed_origins.get(pid) else {
                    return Err(CoreError::InvalidInput(format!(
                        "{pid} needs a confirmed origin before it can be tracked"
                    )));
                };
                // Validate now so a bad origin fails at review, not apply.
                let (host, oport) = api_tracker_gateway::routes::validate_origin(origin)?;
                match route_row(conn, pid)? {
                    Some(row) => {
                        let same = row.custom_origin.as_deref() == Some(host.as_str())
                            && row.custom_origin_port == Some(oport);
                        if !same {
                            if let Some(existing) = &row.custom_origin {
                                warnings.push(PlanWarning::ExistingOriginKept {
                                    prefix: pid.clone(),
                                    existing_origin: existing.clone(),
                                });
                            }
                        }
                        if row.enabled {
                            route_actions.push(RouteAction::ReuseRoute {
                                prefix: pid.clone(),
                                provider_id: row.provider_id,
                            });
                        } else {
                            route_actions.push(RouteAction::ReEnableRoute {
                                prefix: pid.clone(),
                                provider_id: row.provider_id,
                            });
                        }
                    }
                    None => route_actions.push(RouteAction::CreateCustomRoute {
                        prefix: pid.clone(),
                        provider_id: pid.clone(),
                        origin: format!("https://{host}"),
                    }),
                }
            }
        }

        // Link plan for this provider (route row may not exist yet).
        let files: Vec<std::path::PathBuf> = provider
            .target_env_files
            .iter()
            .map(|rel| detection.folder.join(rel))
            .collect();
        let req = envlink::LinkRequest {
            project_id: project.id.clone().unwrap_or_default(),
            project_name: project.name.clone(),
            route_prefix: pid.clone(),
            project_dir: Some(detection.folder.clone()),
            files,
            var_override: None,
        };
        let link_plan = envlink::plan_link_as_provider_projected(
            conn,
            &req,
            pid,
            if port_provisional { Some(port) } else { None },
            &projected,
        )?;
        for w in &link_plan.warnings {
            warnings.push(PlanWarning::File {
                message: render_link_warning(w),
            });
        }
        for file in &link_plan.files {
            projected.insert(file.path.clone(), file.new_content.clone());
        }
        link_plans.push(link_plan);
    }

    if route_actions.is_empty() && link_plans.is_empty() {
        return Err(CoreError::InvalidInput(
            "nothing to configure: no supported provider was selected".to_string(),
        ));
    }

    let any_file_changed = link_plans
        .iter()
        .any(|lp| lp.files.iter().any(|f| f.changed));
    let restart_expectation = if !any_file_changed {
        RestartExpectation::NotNeeded
    } else if detection.project_signals.dotenv_loader == Some(true) {
        RestartExpectation::RequiredLikely
    } else if detection.project_signals.docker_compose {
        RestartExpectation::Unknown
    } else {
        // Fail toward showing the restart instruction: a restart is the
        // most common missing step even when no loader was provable.
        RestartExpectation::RequiredLikely
    };

    Ok(TrackingPlan {
        project,
        folder: detection.folder.display().to_string(),
        service_actions,
        route_actions,
        link_plans,
        attribution: AttributionPlan::Requested,
        warnings,
        restart_expectation,
        port,
        port_provisional,
    })
}

/// Render a `LinkWarning` as one sentence with its consequence (the
/// desktop and CLI share these strings).
pub fn render_link_warning(w: &envlink::LinkWarning) -> String {
    use envlink::LinkWarning::*;
    match w {
        GitTracked { path } => format!(
            "{path} is tracked by Git — the gateway line would be committed. Consider a \
             local override file."
        ),
        GitHistory { path } => {
            format!("{path} appears in Git history; its past contents are already recorded.")
        }
        TemplateFile { path } => format!(
            "{path} looks like a template (.env.example-style); it is a documentation file, \
             not runtime configuration."
        ),
        SharedConfiguration { path } => {
            format!("{path} looks like shared configuration; teammates would inherit this change.")
        }
        OutsideProject { path } => {
            format!("{path} is outside the selected project folder.")
        }
        ReadOnly { path } => format!("{path} is read-only; the write will fail as-is."),
        ProxyVariablePresent { path, key } => format!(
            "{key} in {path}: a proxy variable is set — traffic may bypass the local gateway."
        ),
        ExistingValueRecorded { path, key } => format!(
            "{key} in {path} already had a value; it was recorded and will be restored on undo."
        ),
        PriorValueWithheld { path, key } => format!(
            "{key} in {path} already had a value that looks sensitive; it will NOT be stored \
             in the undo record."
        ),
        DuplicateKey { path, key } => {
            format!("{key} appears more than once in {path}; the later value usually wins.")
        }
        MalformedLines { path, count } => {
            format!("{path} has {count} unparseable line(s); they are preserved untouched.")
        }
        DockerComposePresent { path } => format!(
            "docker-compose file present ({path}) — containers will not see this machine's \
             .env change or 127.0.0.1."
        ),
        NoDotenvLoaderDetected { path } => format!(
            "no dotenv loader was detected for {path} — if the app doesn't read .env files, \
             set the variable in the environment that runs it."
        ),
    }
}
