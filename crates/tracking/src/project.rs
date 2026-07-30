//! The projects-first facade: one folder selection, one disclosure, one
//! confirmation, then tracking (ADR 0029).
//!
//! This is a *facade*, not a second orchestrator. Detection, planning,
//! applying, health resolution and undo all stay where they already are —
//! [`crate::detect`], [`crate::plan`], [`crate::apply`], [`crate::health`],
//! [`crate::undo`]. What this module adds is the projects-first sequencing and
//! the product-level linkage that `tracking_setups` cannot express, plus two
//! things the folder-first flow did not need:
//!
//! ## A consent artifact
//!
//! `apply` is reachable today from any caller holding a plan, with no proof a
//! human saw the diff: the desktop's `tracking_apply` requires only that a
//! plan exists. Folder-first, a multi-screen wizard supplied that proof
//! implicitly. Projects-first collapses the wizard, so the proof has to become
//! explicit or it disappears — and what disappears with it is the user's
//! knowledge that selecting a folder installs a login service, creates routes
//! and rewrites `.env` files.
//!
//! [`prepare_link`] therefore returns a [`FolderLinkPreview`] carrying a
//! `digest` over exactly what will be done, and [`confirm_link`] refuses a
//! digest that does not match what it re-plans. This is the same shape
//! `gateway_link_apply` already uses, for the same reason. It also fixes a
//! second problem: the desktop's single in-memory tracking session survives a
//! vault lock, so a plan previewed before locking was still applyable
//! afterwards. A digest re-checked against a fresh plan cannot be.
//!
//! ## Reads that do not write
//!
//! [`overview`] never calls `state::upsert_setup`. That function is destructive
//! by design — new verification session, `config_generation + 1`,
//! `plan_summary_json`/`applied_at`/`first_traffic_at` cleared — so calling it
//! from a page load would un-verify a healthy setup every time the page
//! opened. Present-tense health comes from [`crate::health::resolve_with`] and
//! nowhere else, because `tracking_setups.state` is a cache that survives the
//! gateway being killed.
//!
//! Note that `health::resolve*` is itself not free: it compare-and-swaps up to
//! `REFRESH_CAS_ATTEMPTS` times per setup. It belongs on page open, manual
//! refresh and focus — not on a five-second timer. [`activity_only`] exists for
//! the timer: it reads observations and touches no tracking state at all.

use std::path::{Path, PathBuf};

use api_tracker_core::projectactivity::{self, ActivityFilter, Granularity};
use api_tracker_core::projectcost::{self, ProjectCostCoverage};
use api_tracker_core::projectlink::{
    self, DetectedCredential, DetectedSource, NewDetection, ProjectFolderLink,
};
use api_tracker_core::runtime::aggregate::{self, Metrics};
use api_tracker_core::vault::UnlockedVault;
use api_tracker_core::{clock, CoreError, Result};
use rusqlite::Connection;
use serde::Serialize;

use crate::detect::{self, ProjectDetection};
use crate::health;
use crate::plan::{self, Selections, TrackingPlan};
use crate::state::{self, GatewayLiveness, TrackingSetup, TrackingStatusReport};

/// Filenames whose size and modification time make up a folder's scan
/// fingerprint: the dependency manifests and env-class files whose contents
/// decide what detection finds.
///
/// Stat-only and name-matched, so computing a fingerprint reads no file
/// contents and costs a fraction of the bounded scan it is there to avoid.
const FINGERPRINT_NAMES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.example",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
];

/// How deep the fingerprint walk goes, and how many directories it will visit.
/// Far tighter than the detection scan because it only needs the manifests a
/// project keeps near its root.
const FINGERPRINT_MAX_DEPTH: usize = 3;
const FINGERPRINT_MAX_DIRS: usize = 400;

/// Directory names the fingerprint walk never enters. Matches the spirit of
/// the detection scan's ignores: dependency and build trees are not the
/// project's own configuration.
const FINGERPRINT_SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".cache",
    "vendor",
];

/// What selecting a folder will do, and the token that binds a confirmation to
/// it.
#[derive(Debug, Clone, Serialize)]
pub struct FolderLinkPreview {
    pub project_id: String,
    pub folder: String,
    pub detection: ProjectDetection,
    /// The plan itself is NOT serialized across IPC. It is an orchestrator
    /// value with its own enums and an embedded per-link CSPRNG slug, and a
    /// frontend has no use for it: `confirm_link` re-plans from scratch and
    /// compares the digest, so nothing needs to be sent back. What a surface
    /// needs is in [`FolderLinkPreview::summary`].
    #[serde(skip)]
    pub plan: Option<TrackingPlan>,
    /// What the plan would do, in terms a screen can render. `None` when
    /// nothing is auto-configurable yet — typically because every detected
    /// destination is still awaiting the user's approval. A preview with no
    /// summary has an empty `digest` and cannot be confirmed.
    pub summary: Option<PlanSummaryView>,
    /// Binds this preview to the apply that follows it. [`confirm_link`]
    /// re-plans and refuses a mismatch, so a stale preview — including one
    /// prepared before a vault lock — cannot be applied.
    pub digest: String,
    /// The ONE disclosure shown before the first configuration-changing
    /// action. Generated from the plan, so it cannot describe less than the
    /// plan does.
    pub disclosure: Vec<String>,
    /// Destinations read from project files that need their own explicit
    /// approval before they can be configured. Repository content is evidence,
    /// never authorization (ADR 0024), so these are NOT pre-approved and the
    /// plan below excludes them until they are.
    pub pending_origin_approvals: Vec<PendingOrigin>,
    /// The credential records that will be created as "needs details". No
    /// value is read, carried, or stored for any of them.
    pub detected_credentials: Vec<DetectedPreview>,
    /// Whether this folder is already linked to this project with an
    /// up-to-date configuration, in which case confirming changes nothing.
    pub already_configured: bool,
    pub scan_fingerprint: String,
}

/// What confirming a folder link would change, for display.
///
/// Derived from the plan rather than restated, so it cannot describe less than
/// the plan will do.
#[derive(Debug, Clone, Serialize)]
pub struct PlanSummaryView {
    /// Whether the master password will be asked for, to enable
    /// per-credential attribution. Tracking works without it.
    pub attribution_requested: bool,
    /// Project files that will be edited, folder-relative as the plan names
    /// them.
    pub files_to_edit: Vec<String>,
    /// Routes that will be created (as opposed to reused).
    pub routes_to_create: usize,
    /// Whether the local helper will be installed or started.
    pub service_change: bool,
    /// Whether the user must restart their own project for tracking to take
    /// effect.
    pub restart_expected: bool,
    pub port: u16,
    /// Non-fatal cautions, already rendered as sentences by the planner.
    pub warnings: Vec<String>,
}

/// A destination inferred from project content, awaiting its own approval.
#[derive(Debug, Clone, Serialize)]
pub struct PendingOrigin {
    pub provider_id: String,
    pub origin: String,
}

/// A credential record that will be created, with no value.
#[derive(Debug, Clone, Serialize)]
pub struct DetectedPreview {
    pub env_var: String,
    pub suggested_provider: Option<String>,
    pub suggested_name: String,
    pub source_file: String,
    pub source_kind: DetectedSource,
    /// True when the project already holds a credential for this provider, so
    /// nothing is unfinished and no row is created.
    pub already_have_credential: bool,
}

/// Everything a project page shows, in one read.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectOverview {
    pub project_id: String,
    /// `None` when the project has never had a folder selected — the state the
    /// "Select project folder" call to action exists for.
    pub link: Option<ProjectFolderLink>,
    /// Present-tense health from [`crate::health`], or `None` when there is no
    /// setup for the linked folder yet.
    pub status: Option<TrackingStatusReport>,
    /// True when the folder's manifests have changed since the last scan, so a
    /// rescan is worth offering. A hint; it authorizes nothing.
    pub scan_stale: bool,
    /// True when the configuration an apply reached is behind the setup's
    /// current generation.
    pub configuration_behind: bool,
    pub detected_credentials: Vec<DetectedCredential>,
    /// How many detections still want the user's attention.
    pub credentials_needing_details: usize,
    pub attribution_paused: bool,
}

/// The live half of a project page: observations only, no tracking state.
///
/// This is what a five-second timer calls. It performs no compare-and-swap, no
/// service probe, and no file access, so polling it cannot un-verify a setup,
/// cannot stall on a network probe, and — when invoked through a background
/// command — cannot defeat inactivity auto-lock.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectActivitySnapshot {
    pub project_id: String,
    pub since: String,
    pub until: Option<String>,
    pub granularity: Granularity,
    pub metrics: Metrics,
    /// True when nothing at all was observed in the window, so a surface can
    /// say "waiting for the first request" instead of showing zeroes.
    pub no_observations: bool,
    pub series: Vec<projectactivity::ProjectSeriesPoint>,
    pub integrations: Vec<projectactivity::ObservedIntegration>,
    pub recent: Vec<projectactivity::ActivityRow>,
    pub cost: ProjectCostCoverage,
    pub facets: projectactivity::ActivityFacets,
    /// When this snapshot was taken, for "last updated".
    pub refreshed_at: String,
}

/// A named window the project page offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRange {
    LastHour,
    Last24Hours,
    Last7Days,
    Last30Days,
}

impl TimeRange {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LastHour => "1h",
            Self::Last24Hours => "24h",
            Self::Last7Days => "7d",
            Self::Last30Days => "30d",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "1h" => Self::LastHour,
            "7d" => Self::Last7Days,
            "30d" => Self::Last30Days,
            _ => Self::Last24Hours,
        }
    }

    fn seconds(self) -> i64 {
        match self {
            Self::LastHour => 3_600,
            Self::Last24Hours => 86_400,
            Self::Last7Days => 7 * 86_400,
            Self::Last30Days => 30 * 86_400,
        }
    }

    /// The bucket width that keeps a window's point count useful and bounded:
    /// 60 minute-buckets for an hour, 24 hour-buckets for a day, days beyond.
    pub fn granularity(self) -> Granularity {
        match self {
            Self::LastHour => Granularity::Minute,
            Self::Last24Hours => Granularity::Hour,
            Self::Last7Days | Self::Last30Days => Granularity::Day,
        }
    }

    /// The RFC 3339 lower bound for this window, relative to now.
    pub fn since(self) -> String {
        clock::rfc3339_minus_seconds(&clock::now_rfc3339(), self.seconds())
    }
}

// ---------------------------------------------------------------------------
// Folder selection
// ---------------------------------------------------------------------------

/// Scan a folder and plan what linking it to `project_id` would do.
///
/// Read-only with respect to the user's files and to tracking state. The one
/// write it performs is [`plan::ensure_port`], which persists a free loopback
/// port so the previewed base URL is the one that will actually be used —
/// exactly what the folder-first flow does, and it starts nothing.
///
/// Detection is bounded by [`detect::detect`]'s own limits and refuses the
/// filesystem root, the home directory and `/Users` — this facade adds no way
/// to widen that.
pub fn prepare_link(
    conn: &Connection,
    data_dir: &Path,
    project_id: &str,
    project_name: &str,
    folder: &Path,
    service: &api_tracker_gateway::lifecycle::ServiceStatus,
    listener_live: bool,
) -> Result<FolderLinkPreview> {
    let detection = detect::detect(
        conn,
        &detect::DetectionInput {
            folder,
            project_id: Some(project_id),
        },
    )?;

    // Only providers Tethra can configure on its own are selected. A
    // destination read from project files is deliberately excluded until the
    // user approves that exact destination (ADR 0024 / ZFT-004).
    let selections = Selections::defaults(&detection);
    let pending_origin_approvals = Selections::pending_origin_approvals(&detection)
        .into_iter()
        .map(|(provider_id, origin)| PendingOrigin {
            provider_id,
            origin,
        })
        .collect();

    plan::ensure_port(conn)?;
    // `plan` refuses outright when no provider is auto-configurable, which is
    // the NORMAL outcome for a folder whose only integrations are destinations
    // awaiting the user's approval. Propagating that as an error would turn
    // "select folder" into a dead end that says nothing about the approval it
    // is waiting for, so it becomes a state instead: there is a preview, it has
    // no plan, and it carries the approvals that would unblock one.
    let planned = match plan::plan(
        conn,
        &detection,
        &selections,
        plan::ProjectRef {
            id: Some(project_id.to_string()),
            name: project_name.to_string(),
        },
        service,
        listener_live,
    ) {
        Ok(p) => Some(p),
        Err(CoreError::InvalidInput(msg)) if msg.starts_with("nothing to configure") => None,
        Err(e) => return Err(e),
    };

    let detected_credentials = derive_detections(conn, project_id, &detection)?;
    let fingerprint = folder_fingerprint(folder);
    let digest = match &planned {
        Some(p) => link_digest(project_id, &detection.folder, p),
        // No plan means nothing to confirm; an empty digest cannot be mistaken
        // for one that authorizes an apply.
        None => String::new(),
    };
    let already_configured = is_configured(conn, data_dir, project_id, folder, &fingerprint)?;
    let summary = planned.as_ref().map(|p| PlanSummaryView {
        attribution_requested: matches!(p.attribution, plan::AttributionPlan::Requested),
        files_to_edit: p
            .link_plans
            .iter()
            .flat_map(|lp| lp.files.iter().map(|f| f.path.clone()))
            .collect(),
        routes_to_create: p.route_actions.iter().filter(|r| r.creates()).count(),
        service_change: !p.service_actions.is_empty(),
        restart_expected: !matches!(p.restart_expectation, plan::RestartExpectation::NotNeeded),
        port: p.port,
        warnings: p.warnings.iter().map(|w| w.describe()).collect(),
    });
    let disclosure = match &planned {
        Some(p) => disclosure_for(p, &detection),
        None => vec![
            "Tethra found API integrations in this folder, but none of them is one it can \
             configure on its own. Every destination it found was read from this project's \
             own files, and Tethra will not route traffic to a destination it discovered \
             rather than one it ships."
                .to_string(),
            // Deliberately NOT "approve it and select the folder again":
            // `prepare_link` builds its plan from `Selections::defaults`, which
            // includes only `Configurability::Automatic` providers. An approved
            // repository-discovered origin still needs `approve_origin`, which
            // only the advanced flow calls — so re-selecting the folder here
            // would change nothing, and saying otherwise would send the user
            // round a loop that cannot terminate.
            "Configuring one of these is an advanced action: open Tracking setup (advanced), \
             where approving a destination and configuring it happen together."
                .to_string(),
        ],
    };

    Ok(FolderLinkPreview {
        project_id: project_id.to_string(),
        folder: detection.folder.display().to_string(),
        disclosure,
        detection,
        plan: planned,
        summary,
        digest,
        pending_origin_approvals,
        detected_credentials,
        already_configured,
        scan_fingerprint: fingerprint,
    })
}

/// The one disclosure shown before the first configuration-changing action.
///
/// Every line is derived from the plan, so the disclosure cannot understate
/// what will happen. It names the three categories of change a user would
/// otherwise discover afterwards: a login service, route registration, and
/// edits to their own `.env` files.
fn disclosure_for(plan: &TrackingPlan, detection: &ProjectDetection) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "Tethra will observe API traffic from {} and record request metadata \
         locally. Request and response bodies are never stored.",
        plan.folder
    ));
    if !plan.service_actions.is_empty() {
        lines.push(
            "A local helper will run in the background so tracking continues after \
             this window closes. It listens only on this computer."
                .to_string(),
        );
    }
    let creating: Vec<&str> = plan
        .route_actions
        .iter()
        .filter(|r| r.creates())
        .map(|r| r.provider_id())
        .collect();
    if !creating.is_empty() {
        // Named, not just counted: "2 destinations will be registered" does not
        // tell the user WHICH, and the point of a disclosure is that they can
        // recognise what they are agreeing to.
        lines.push(format!(
            "Traffic to these APIs will be routed through Tethra so it can be measured: {}.",
            creating.join(", ")
        ));
    }
    let files: Vec<String> = plan
        .link_plans
        .iter()
        .flat_map(|lp| lp.files.iter().map(|f| f.path.clone()))
        .collect();
    if !files.is_empty() {
        lines.push(format!(
            "These files in your project will be edited so requests go through Tethra: \
             {}. The previous values are recorded encrypted so this can be undone.",
            files.join(", ")
        ));
    }
    if !detection.unrecognized.is_empty() {
        lines.push(format!(
            "{} credential variable(s) were seen by name only. Their values are not \
             read and are not saved.",
            detection.unrecognized.len()
        ));
    }
    lines.push(
        "Nothing is sent to Tethra. You can unlink this folder and undo these changes \
         at any time."
            .to_string(),
    );
    lines
}

/// Bind a preview to the exact configuration it described.
///
/// Fields are length-prefixed so no two different plans serialize to the same
/// byte stream, matching `envlink::plan_digest`. The envlink digest already
/// binds the FILE bytes; this one binds the service, route and link actions
/// that digest says nothing about.
fn link_digest(project_id: &str, folder: &Path, plan: &TrackingPlan) -> String {
    fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    let mut hasher = blake3::Hasher::new();
    field(&mut hasher, project_id.as_bytes());
    field(&mut hasher, folder.display().to_string().as_bytes());
    field(&mut hasher, &plan.port.to_le_bytes());
    for action in &plan.service_actions {
        field(&mut hasher, format!("{action:?}").as_bytes());
    }
    for action in &plan.route_actions {
        // The whole Debug form, not prefix + provider_id + creates. Those three
        // accessors skip `CreateCustomRoute::origin`, which would make the
        // consent token origin-blind: two plans differing ONLY in the
        // destination host would hash identically. No such plan can reach here
        // today, because `prepare_link` uses `Selections::defaults` and never
        // approves an origin — but a digest whose correctness depends on a
        // caller elsewhere not changing is not a guarantee. Hashing the variant
        // and all its fields also covers any field a future variant gains.
        field(&mut hasher, format!("{action:?}").as_bytes());
    }
    for lp in &plan.link_plans {
        // NOT `lp.digest`. That digest covers each file's previewed input and
        // planned output — and the planned output embeds a per-link CSPRNG
        // slug, so it is a different value on every `plan()` call. Binding it
        // here would make `confirm_link` reject every confirmation, including
        // an immediate one.
        //
        // What this binds instead is the DECISION: which files will be touched,
        // whether each exists, and whether each will actually change. The file
        // BYTES stay bound by `envlink::apply_link`, which independently
        // refuses when its own digest no longer matches at apply time — so
        // nothing is unguarded, and the two digests answer different questions.
        for f in &lp.files {
            field(&mut hasher, f.path.as_bytes());
            field(&mut hasher, &[u8::from(f.exists), u8::from(f.changed)]);
        }
    }
    hasher.finalize().to_hex().to_string()
}

/// The credential records a detection implies.
///
/// Two sources, neither of which carries a value:
///
/// * a provider Tethra recognized, whose manifest names the variables it uses
///   (`ProviderDetection::credential_candidates`);
/// * a credential-shaped variable the scan saw and could not attribute
///   (`ProjectDetection::unrecognized`), which carries the variable name and
///   the file and nothing else.
///
/// A provider the project already holds a credential for produces no
/// unfinished record: there is nothing unfinished about it, and asking for
/// details Tethra already has would be a false alarm. It is still reported in
/// the preview, marked `already_have_credential`, so the user can see the
/// detection happened.
fn derive_detections(
    conn: &Connection,
    project_id: &str,
    detection: &ProjectDetection,
) -> Result<Vec<DetectedPreview>> {
    let existing = existing_providers(conn, project_id)?;
    let mut out = Vec::new();

    for provider in &detection.providers {
        // `credential_candidates` is the detection's S4 signal: the names of
        // credentials this project ALREADY holds for this provider. A non-empty
        // list means nothing here is unfinished. It is NOT a list of variables
        // found in the project — that is what the evidence below carries.
        let have = !provider.credential_candidates.is_empty()
            || existing.contains(&provider.provider_id.to_lowercase());
        for evidence in &provider.evidence {
            // The only evidence variant that names a credential-shaped variable
            // the scan actually saw in a file. Its own doc is explicit that the
            // value never leaves the parse, which is why a record derived from
            // it cannot carry one.
            let detect::Evidence::SecretEnvVarName { var, file } = evidence else {
                continue;
            };
            out.push(DetectedPreview {
                env_var: var.clone(),
                suggested_provider: Some(provider.provider_id.clone()),
                suggested_name: suggest_name(var),
                source_file: file.clone(),
                source_kind: DetectedSource::Manifest,
                already_have_credential: have,
            });
        }
    }

    for unknown in &detection.unrecognized {
        // A name hint is derived from the variable name alone and is
        // presentation only — it selects no provider and creates no route.
        let hint = unknown.name_hint.clone();
        let have = hint
            .as_deref()
            .map(|h| existing.contains(&h.to_lowercase()))
            .unwrap_or(false);
        out.push(DetectedPreview {
            env_var: unknown.var.clone(),
            suggested_provider: hint,
            suggested_name: suggest_name(&unknown.var),
            source_file: unknown.file.clone(),
            source_kind: DetectedSource::EnvFile,
            already_have_credential: have,
        });
    }

    // A variable can be named by a manifest AND seen in a file. Keep the first
    // occurrence, which is the manifest-attributed one, so the better
    // suggestion wins and the list has one row per (variable, file).
    out.dedup_by(|a, b| a.env_var == b.env_var && a.source_file == b.source_file);
    Ok(out)
}

/// The lowercase providers this project already holds a credential for.
fn existing_providers(conn: &Connection, project_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT lower(provider) FROM credentials
         WHERE project_id = ?1 AND revoked = 0",
    )?;
    let rows = stmt.query_map([project_id], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// `ANTHROPIC_API_KEY` -> `anthropic-api-key`.
fn suggest_name(var: &str) -> String {
    var.trim()
        .to_lowercase()
        .replace('_', "-")
        .trim_matches('-')
        .to_string()
}

/// Apply the previewed configuration and record the linkage.
///
/// Refuses when `digest` does not match a freshly built plan: the folder, its
/// files, the service state or the route table changed since the preview, and
/// the user consented to the old picture. This is the projects-first
/// equivalent of the confirmation the folder-first wizard collected across
/// several screens, and it is the only thing standing between "select a folder"
/// and "install a login service, register routes and rewrite `.env`".
#[allow(clippy::too_many_arguments)]
pub fn confirm_link(
    vault: &mut UnlockedVault,
    data_dir: &Path,
    project_id: &str,
    project_name: &str,
    folder: &Path,
    digest: &str,
    service: &api_tracker_gateway::lifecycle::ServiceStatus,
    listener_live: bool,
    options: &crate::apply::ApplyOptions,
    ops: &dyn crate::apply::ServiceOps,
) -> Result<LinkOutcome> {
    let preview = prepare_link(
        vault.connection(),
        data_dir,
        project_id,
        project_name,
        folder,
        service,
        listener_live,
    )?;
    let Some(plan) = preview.plan.as_ref() else {
        return Err(CoreError::InvalidInput(
            "there is nothing to configure for this folder yet. Approve a destination \
             first, then confirm."
                .into(),
        ));
    };
    // An empty digest never authorizes anything, so a caller cannot confirm a
    // preview that had no plan by echoing what it was given.
    if digest.is_empty() || preview.digest != digest {
        return Err(CoreError::InvalidInput(
            "this project's folder or configuration changed since it was reviewed. \
             Look at the new summary and confirm again."
                .into(),
        ));
    }

    let report = crate::apply::apply(vault, &preview.detection, plan, options, ops);

    // Persist the linkage and the detections only against an apply that got far
    // enough to have configured something. A failed apply leaves the setup row
    // carrying its own attention reason (apply.rs); recording "this folder is
    // linked and tracking" on top of that would contradict it.
    let conn = vault.connection();
    let mut link = projectlink::upsert_link(conn, project_id, &preview.folder)?;
    // The fingerprint must be recomputed HERE, not carried from the preview.
    // Apply rewrites the project's `.env`, and `.env` is one of the files the
    // fingerprint covers — so storing the pre-apply value made every successful
    // setup immediately report "your files changed since the last scan" about a
    // change Tethra had just made itself, on every page open until the user
    // clicked Rescan.
    let applied_fingerprint = folder_fingerprint(Path::new(&preview.folder));
    projectlink::record_scan(conn, &mut link, Some(&applied_fingerprint))?;
    if report.failed_step().is_none() {
        if let Some(setup) = state::find_setup(conn, project_id, Path::new(&preview.folder))? {
            projectlink::record_applied_generation(conn, &mut link, setup.config_generation)?;
        }
    }
    let created = persist_detections(conn, project_id, &preview.detected_credentials)?;

    Ok(LinkOutcome {
        link,
        report: ApplyReportView::of(&report),
        detected_credentials: created,
    })
}

/// What a confirmed folder link produced.
#[derive(Debug, Serialize)]
pub struct LinkOutcome {
    pub link: ProjectFolderLink,
    pub report: ApplyReportView,
    pub detected_credentials: Vec<DetectedCredential>,
}

/// One apply step, flattened for display.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyStepView {
    pub title: String,
    /// `"done" | "skipped" | "failed"` — a flat string, deliberately.
    pub outcome: String,
    pub detail: String,
}

/// The apply result in terms a screen can check.
///
/// `apply::ApplyReport` is NOT sent across IPC. Its `StepOutcome` is a nested
/// Rust enum, so a frontend testing `step.outcome === "failed"` silently never
/// matches — which is exactly the bug this type exists to make impossible: a
/// partially failed apply would have reported "Tracking is on". `failed_step` is
/// computed here by `ApplyReport::failed_step`, which is the orchestrator's own
/// definition of failure rather than a second one.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyReportView {
    /// The title of the first failed step, or `None` when every step got
    /// through. A caller checks THIS, not a string comparison on an enum.
    pub failed_step: Option<String>,
    pub failed_detail: Option<String>,
    pub install_blocked: bool,
    pub attribution_enabled: bool,
    pub setup_id: Option<String>,
    pub steps: Vec<ApplyStepView>,
}

impl ApplyReportView {
    fn of(report: &crate::apply::ApplyReport) -> Self {
        use crate::apply::StepOutcome;
        let failed = report.failed_step();
        Self {
            failed_step: failed.map(|s| s.title.to_string()),
            failed_detail: failed.and_then(|s| match &s.outcome {
                StepOutcome::Failed { error } => Some(error.clone()),
                _ => None,
            }),
            install_blocked: report.install_blocked,
            attribution_enabled: report.attribution_enabled,
            setup_id: report.setup_id.clone(),
            steps: report
                .steps
                .iter()
                .map(|s| {
                    let (outcome, detail) = match &s.outcome {
                        StepOutcome::Done { detail } => ("done", detail.clone()),
                        StepOutcome::Skipped { reason } => ("skipped", reason.clone()),
                        StepOutcome::Failed { error } => ("failed", error.clone()),
                    };
                    ApplyStepView {
                        title: s.title.to_string(),
                        outcome: outcome.to_string(),
                        detail,
                    }
                })
                .collect(),
        }
    }

    /// Whether the apply got all the way through.
    pub fn succeeded(&self) -> bool {
        self.failed_step.is_none()
    }
}

/// Write the unfinished credential records, skipping the ones the project
/// already has a credential for.
fn persist_detections(
    conn: &Connection,
    project_id: &str,
    previews: &[DetectedPreview],
) -> Result<Vec<DetectedCredential>> {
    let mut out = Vec::new();
    for p in previews {
        if p.already_have_credential {
            continue;
        }
        out.push(projectlink::upsert_detection(
            conn,
            project_id,
            &NewDetection {
                env_var: &p.env_var,
                suggested_provider: p.suggested_provider.as_deref(),
                suggested_name: Some(&p.suggested_name),
                // The environment a variable belongs to is not derivable from
                // its name, and guessing it would put a wrong answer in front
                // of the user as though Tethra knew. It stays unknown until
                // they choose.
                suggested_environment: None,
                source_kind: p.source_kind,
                source_file: &p.source_file,
            },
        )?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Everything a project page needs about its own configuration and health.
///
/// Resolves present-tense health, which performs guarded writes, so this is a
/// page-open / manual-refresh / focus operation. The five-second timer calls
/// [`activity_only`] instead.
pub fn overview(conn: &Connection, data_dir: &Path, project_id: &str) -> Result<ProjectOverview> {
    let link = projectlink::get_link(conn, project_id)?;
    let detected_credentials = projectlink::list_detections(conn, project_id)?;
    let credentials_needing_details = detected_credentials
        .iter()
        .filter(|d| d.status.needs_attention())
        .count();

    let mut status = None;
    let mut configuration_behind = false;
    let mut scan_stale = false;

    if let Some(link) = &link {
        let folder = PathBuf::from(&link.folder_path);
        scan_stale = match &link.scan_fingerprint {
            Some(previous) => folder_fingerprint(&folder) != *previous,
            // Never scanned: not "stale", just not done yet.
            None => false,
        };
        if let Some(mut setup) = state::find_setup(conn, project_id, Path::new(&link.folder_path))?
        {
            configuration_behind = setup.config_generation > link.applied_generation;
            // Present-tense health has exactly one resolver. Reading
            // `setup.state` here would report a setup as tracking after the
            // service was killed.
            let liveness = health::probe_liveness(conn, data_dir);
            status = Some(health::resolve_with(conn, &mut setup, liveness)?);
        }
    }

    Ok(ProjectOverview {
        project_id: project_id.to_string(),
        link,
        status,
        scan_stale,
        configuration_behind,
        detected_credentials,
        credentials_needing_details,
        attribution_paused: health::attribution_is_paused(data_dir),
    })
}

/// The live activity snapshot: observations only.
///
/// Deliberately performs no tracking-state write, no service probe and no
/// filesystem access, so it is safe on a short timer.
pub fn activity_only(
    conn: &Connection,
    project_id: &str,
    range: TimeRange,
    filter: &ActivityFilter<'_>,
    recent_limit: usize,
) -> Result<ProjectActivitySnapshot> {
    let since = range.since();
    let granularity = range.granularity();
    let metrics = aggregate::project_metrics(conn, project_id, Some(&since))?;
    let series =
        projectactivity::project_series(conn, project_id, &since, None, granularity, filter)?;
    let integrations = projectactivity::observed_integrations(conn, project_id, &since, None)?;
    let recent =
        projectactivity::recent_activity(conn, project_id, &since, None, filter, recent_limit)?;
    let cost = projectcost::project_cost_coverage(conn, project_id, &since, None)?;
    let facets = projectactivity::activity_facets(conn, project_id, &since)?;

    Ok(ProjectActivitySnapshot {
        project_id: project_id.to_string(),
        no_observations: metrics.total == 0,
        since,
        until: None,
        granularity,
        metrics,
        series,
        integrations,
        recent,
        cost,
        facets,
        refreshed_at: clock::now_rfc3339(),
    })
}

/// Stamp a successful activity refresh on the linkage row, best effort.
///
/// A refresh that read fine but could not record that it did is still a
/// successful refresh, so a conflict here is swallowed rather than turned into
/// a failed refresh the user would see.
pub fn note_activity_refresh(conn: &Connection, project_id: &str) {
    if let Ok(Some(mut link)) = projectlink::get_link(conn, project_id) {
        let _ = projectlink::record_activity_refresh(conn, &mut link);
    }
}

/// Whether this folder is already linked, scanned and applied at the current
/// generation — i.e. whether confirming would change anything.
fn is_configured(
    conn: &Connection,
    _data_dir: &Path,
    project_id: &str,
    folder: &Path,
    fingerprint: &str,
) -> Result<bool> {
    let Some(link) = projectlink::get_link(conn, project_id)? else {
        return Ok(false);
    };
    if link.folder_path != folder.display().to_string() || !link.tracking_enabled {
        return Ok(false);
    }
    if link.scan_fingerprint.as_deref() != Some(fingerprint) {
        return Ok(false);
    }
    let Some(setup) = state::find_setup(conn, project_id, Path::new(&link.folder_path))? else {
        return Ok(false);
    };
    Ok(setup.config_generation == link.applied_generation && link.applied_generation > 0)
}

/// Re-run detection for a linked folder and refresh its credential records.
///
/// Explicitly NOT an apply: it updates what Tethra knows about the project and
/// records a new fingerprint. Nothing is written to the user's files, no
/// service is touched, and no route is created. When the new detection implies
/// configuration the current setup does not have, that shows up as
/// `configuration_behind` on the next [`overview`], and the user decides.
pub fn rescan(conn: &Connection, project_id: &str) -> Result<Vec<DetectedCredential>> {
    let Some(mut link) = projectlink::get_link(conn, project_id)? else {
        return Err(CoreError::NotFound {
            kind: "project folder link",
            ident: project_id.to_string(),
        });
    };
    let folder = PathBuf::from(&link.folder_path);
    let detection = detect::detect(
        conn,
        &detect::DetectionInput {
            folder: &folder,
            project_id: Some(project_id),
        },
    )?;
    let previews = derive_detections(conn, project_id, &detection)?;
    let created = persist_detections(conn, project_id, &previews)?;
    let fingerprint = folder_fingerprint(&folder);
    projectlink::record_scan(conn, &mut link, Some(&fingerprint))?;
    Ok(created)
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Turn tracking off for this project without deleting anything.
///
/// The linkage, the credentials, the detections and every recorded observation
/// stay. Only future automatic configuration stops. Restoring the managed file
/// changes is a separate, explicit act ([`crate::undo::undo`]) so that
/// "stop tracking" never silently edits the user's project.
pub fn set_tracking_enabled(conn: &Connection, project_id: &str, enabled: bool) -> Result<()> {
    let Some(mut link) = projectlink::get_link(conn, project_id)? else {
        return Err(CoreError::NotFound {
            kind: "project folder link",
            ident: project_id.to_string(),
        });
    };
    projectlink::set_tracking_enabled(conn, &mut link, enabled)
}

/// Forget the folder association.
///
/// Removes the linkage row and nothing else: the project, its credentials, its
/// detections and its history survive, and so does the folder on disk. The
/// caller undoes managed file changes first when the user asked for that —
/// they are separate decisions, and doing both here would make "unlink" edit
/// files without being asked.
pub fn unlink(conn: &Connection, project_id: &str) -> Result<bool> {
    projectlink::delete_link(conn, project_id)
}

/// The setup row for a project's linked folder, when there is one.
pub fn linked_setup(conn: &Connection, project_id: &str) -> Result<Option<TrackingSetup>> {
    let Some(link) = projectlink::get_link(conn, project_id)? else {
        return Ok(None);
    };
    state::find_setup(conn, project_id, Path::new(&link.folder_path))
}

/// Restore what was being observed, without touching any of it.
///
/// This is the launch path. It reads the linkage rows and resolves health once
/// per setup against a single liveness probe — it does not rescan any folder,
/// does not re-apply any configuration, and does not write to any project file.
/// A folder whose manifests changed while the app was closed shows up as
/// `scan_stale` on its overview, which offers a rescan rather than performing
/// one.
pub fn restore_on_launch(
    conn: &Connection,
    data_dir: &Path,
) -> Result<Vec<(String, Option<TrackingStatusReport>)>> {
    let links = projectlink::list_links(conn)?;
    if links.is_empty() {
        return Ok(Vec::new());
    }
    // Liveness is a property of the machine, not of a row: probe once for the
    // whole list rather than once per project.
    let liveness = health::probe_liveness(conn, data_dir);
    let mut out = Vec::new();
    for link in links {
        if !link.tracking_enabled {
            out.push((link.project_id, None));
            continue;
        }
        let report = match state::find_setup(conn, &link.project_id, Path::new(&link.folder_path))?
        {
            Some(mut setup) => resolve_quietly(conn, &mut setup, liveness),
            None => None,
        };
        out.push((link.project_id, report));
    }
    Ok(out)
}

/// Resolve health, treating a compare-and-swap conflict as "somebody else just
/// wrote a fresher answer" rather than as a launch failure.
fn resolve_quietly(
    conn: &Connection,
    setup: &mut TrackingSetup,
    liveness: GatewayLiveness,
) -> Option<TrackingStatusReport> {
    health::resolve_with(conn, setup, liveness).ok()
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// A non-secret digest over the dependency and env manifests in `folder`.
///
/// Stat-only: it reads names, byte lengths and modification times, never file
/// contents. That is the whole point — it answers "is a rescan worth offering?"
/// without paying for the bounded content scan, so relaunching the app does not
/// re-read a project.
///
/// A missing or unreadable folder yields a stable sentinel rather than an
/// error: an unavailable folder is a state the project page reports, not a
/// failure that stops it loading.
pub fn folder_fingerprint(folder: &Path) -> String {
    fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }

    let mut entries: Vec<(String, u64, i64)> = Vec::new();
    let mut dirs_visited = 0usize;
    let mut queue: Vec<(PathBuf, usize)> = vec![(folder.to_path_buf(), 0)];

    while let Some((dir, depth)) = queue.pop() {
        if depth > FINGERPRINT_MAX_DEPTH || dirs_visited >= FINGERPRINT_MAX_DIRS {
            continue;
        }
        dirs_visited += 1;
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            // `symlink_metadata` rather than `metadata`: following a symlink
            // here would let a link inside the project pull in a file outside
            // it, which is the escape the detection readers refuse by the same
            // means.
            let Ok(meta) = entry.metadata() else { continue };
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if file_type.is_dir() {
                if !FINGERPRINT_SKIP_DIRS.contains(&name.as_str()) {
                    queue.push((entry.path(), depth + 1));
                }
                continue;
            }
            if !FINGERPRINT_NAMES.contains(&name.as_str()) {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(folder)
                .map(|p| p.display().to_string())
                .unwrap_or(name);
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(-1);
            entries.push((rel, meta.len(), mtime));
        }
    }

    // Directory iteration order is not defined, so sort before hashing or the
    // same folder fingerprints differently between runs.
    entries.sort();
    let mut hasher = blake3::Hasher::new();
    field(&mut hasher, b"tethra-folder-fingerprint-v1");
    for (rel, len, mtime) in &entries {
        field(&mut hasher, rel.as_bytes());
        field(&mut hasher, &len.to_le_bytes());
        field(&mut hasher, &mtime.to_le_bytes());
    }
    hasher.finalize().to_hex().to_string()
}
