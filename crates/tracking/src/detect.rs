//! Selected-folder provider detection (ADR 0022 D5).
//!
//! Fuses the repository's existing detection signals over one
//! user-selected folder into per-provider confidence × configurability.
//! Everything here is bounded and value-free:
//!
//! * Reads only under the selected folder, canonicalized first; refuses
//!   filesystem roots and home directories outright.
//! * Reuses `envgov::discover`'s bounds for `.env` inventory (depth ≤ 6,
//!   skip dirs, symlinks never followed) and `stackdetect`'s per-file
//!   byte cap for everything read here.
//! * Parse-only: nothing is executed, no `.env` value is interpolated,
//!   no network request is made (pinned by a source-level test).
//! * Evidence carries variable NAMES, file paths, dependency names, and
//!   provider ids — never a value. The single, narrow exception is the
//!   manifest-declared NON-secret base-URL variable of a custom-origin
//!   provider (e.g. `SUPABASE_URL`), whose value may be read to infer an
//!   origin that is then validated by the unchanged `routes::validate_origin`
//!   + SSRF policy and shown verbatim for explicit confirmation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use api_tracker_core::{envfile::EnvDocument, envgov, providers, scanner, stackdetect};
use api_tracker_core::{CoreError, Result};
use api_tracker_gateway::routes;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// Per-file byte cap, mirroring `stackdetect::MAX_FILE_BYTES`. Oversized
/// files are counted in `skipped_oversized`, never silently ignored.
pub const MAX_FILE_BYTES: u64 = 262_144;

#[derive(Debug, Clone)]
pub struct DetectionInput<'a> {
    /// The user-selected folder. Canonicalized before any read.
    pub folder: &'a Path,
    /// When known, enables vault-side signals (assigned credentials).
    pub project_id: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionConfidence {
    Possible,
    Likely,
    Confirmed,
}

impl DetectionConfidence {
    pub fn label(self) -> &'static str {
        match self {
            DetectionConfidence::Confirmed => "confirmed",
            DetectionConfidence::Likely => "likely",
            DetectionConfidence::Possible => "possible",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    /// The provider's SDK has no configurable base-URL environment
    /// variable in its manifest (no `[gateway]` section).
    NoConfigurableBaseUrl,
    /// Detected only through a generic mention; Tethra has no manifest
    /// for it at all.
    UnknownProvider,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Configurability {
    /// Manifest `[gateway]` with a fixed origin — zero-interaction setup.
    Automatic,
    /// Custom-origin provider with exactly one inferable origin; shown
    /// pre-filled, requires explicit confirmation.
    NeedsOriginConfirm { inferred_origin: String },
    /// Custom-origin provider with no (or conflicting) inferable origin.
    NeedsOriginInput,
    /// Honestly listed, never configured, never blocks other providers.
    Unsupported { reason: UnsupportedReason },
}

/// Human-renderable, value-free evidence. Rendered to sentences in the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// A known secret env-var NAME with a non-placeholder value. The value
    /// itself never leaves the parse.
    SecretEnvVarName {
        var: String,
        file: String,
    },
    SdkDependency {
        dep: String,
        manifest: String,
    },
    BaseUrlVar {
        var: String,
        file: String,
    },
    AssignedCredential {
        credential_name: String,
    },
    LockfileMention {
        file: String,
    },
    ConfigFile {
        file: String,
    },
}

impl Evidence {
    /// One plain-language sentence per evidence item (target journeys A4).
    pub fn describe(&self) -> String {
        match self {
            Evidence::SecretEnvVarName { var, file } => {
                format!("Found {var} in {file} (value not read)")
            }
            Evidence::SdkDependency { dep, manifest } => {
                format!("Found the {dep} package in {manifest}")
            }
            Evidence::BaseUrlVar { var, file } => format!("Found {var} in {file}"),
            Evidence::AssignedCredential { credential_name } => {
                format!("The credential '{credential_name}' is assigned to this project")
            }
            Evidence::LockfileMention { file } => format!("Mentioned in {file}"),
            Evidence::ConfigFile { file } => format!("Referenced in {file}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDetection {
    pub provider_id: String,
    /// Manifest display name when known, else the id.
    pub display_name: String,
    pub confidence: DetectionConfidence,
    pub configurability: Configurability,
    pub evidence: Vec<Evidence>,
    /// Names of vault credentials for this provider assigned to the
    /// project (never values).
    pub credential_candidates: Vec<String>,
    /// Values-class env files where this provider's configuration lives
    /// (where the base URL would be written). Relative to the folder.
    pub target_env_files: Vec<String>,
    /// Honest, per-provider caveats ("SDK may ignore the base URL", …).
    pub limitations: Vec<String>,
}

/// Folder-level signals that feed restart guidance and diagnosis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSignals {
    pub docker_compose: bool,
    pub dockerfile: bool,
    pub devcontainer: bool,
    /// `Some(true)`: a dotenv loader (or env-loading framework) was seen.
    /// `Some(false)`: a manifest was read and none was seen.
    /// `None`: nothing conclusive (no supported manifest present).
    pub dotenv_loader: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvFileSummary {
    pub rel_path: String,
    /// "values" or "template" (templates are never edited as runtime
    /// configuration).
    pub class: String,
    pub git_tracked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDetection {
    pub folder: PathBuf,
    pub providers: Vec<ProviderDetection>,
    pub env_files: Vec<EnvFileSummary>,
    pub project_signals: ProjectSignals,
    pub scanned_files: u32,
    pub skipped_oversized: u32,
}

impl ProjectDetection {
    /// Providers that can actually be configured (not `Unsupported`).
    pub fn configurable(&self) -> impl Iterator<Item = &ProviderDetection> {
        self.providers
            .iter()
            .filter(|p| !matches!(p.configurability, Configurability::Unsupported { .. }))
    }
}

/// Refuse folders whose scan could never be what the user meant: the
/// filesystem root, a home directory, or the container of home
/// directories. A misclick must not become a broad scan.
fn refuse_dangerous_roots(canonical: &Path) -> Result<()> {
    let refuse = |why: &str| {
        Err(CoreError::InvalidInput(format!(
            "refusing to scan {}: {why}. Select the project folder itself.",
            canonical.display()
        )))
    };
    if canonical.parent().is_none() {
        return refuse("it is the filesystem root");
    }
    // Every spelling of "the user's home directory" this platform uses.
    // `HOME` alone is Unix-biased: Windows sets `USERPROFILE` (and
    // `HOMEDRIVE`+`HOMEPATH`) instead, so checking only `HOME` let a
    // Windows home directory through and scanned it — caught by CI, not
    // by inspection.
    let mut homes: Vec<PathBuf> = Vec::new();
    for var in ["HOME", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(var) {
            homes.push(PathBuf::from(value));
        }
    }
    if let (Some(drive), Some(path)) = (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
    {
        let mut joined = drive;
        joined.push(path);
        homes.push(PathBuf::from(joined));
    }
    for home in homes {
        let home = home.canonicalize().unwrap_or(home);
        if canonical == home {
            return refuse("it is your home directory");
        }
    }
    let is_root_child = canonical
        .parent()
        .map(|p| p.parent().is_none())
        .unwrap_or(false);
    if is_root_child {
        let name = canonical
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if matches!(name, "Users" | "home") {
            return refuse("it contains every user's home directory");
        }
    }
    Ok(())
}

/// Read a file under `root` with the byte cap and without ever following a
/// symlink out of the folder. Returns `Ok(None)` when absent or refused,
/// bumping the counters honestly.
fn read_bounded(
    root: &Path,
    path: &Path,
    scanned: &mut u32,
    skipped_oversized: &mut u32,
) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        // A symlink could point anywhere; the canonical check below would
        // follow it, so refuse it outright.
        return None;
    }
    if !meta.is_file() {
        return None;
    }
    let canon = path.canonicalize().ok()?;
    if !canon.starts_with(root) {
        return None;
    }
    if meta.len() > MAX_FILE_BYTES {
        *skipped_oversized += 1;
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    *scanned += 1;
    Some(content)
}

/// Provider id → stack template id, mirroring `stackdetect`'s private map,
/// for the `stack_preferences` learning-loop adjustment.
fn provider_template(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("openai-app"),
        "anthropic" => Some("anthropic-app"),
        "stripe" => Some("stripe-app"),
        "supabase" => Some("supabase-web"),
        "github" => Some("github-automation"),
        _ => None,
    }
}

/// Dependency names whose presence in a lockfile counts as an S5 mention.
const LOCKFILE_NEEDLES: &[(&str, &str)] = &[
    ("openai", "\"openai\""),
    ("anthropic", "\"@anthropic-ai/"),
    ("anthropic", "\"anthropic\""),
    ("supabase", "\"@supabase/"),
    ("stripe", "\"stripe\""),
    ("github", "\"@octokit/"),
];

const LOCKFILES: &[&str] = &["package-lock.json", "pnpm-lock.yaml", "yarn.lock"];

/// Frameworks/loaders that read `.env` at startup without explicit dotenv.
const NODE_ENV_LOADERS: &[&str] = &[
    "dotenv",
    "dotenv-flow",
    "next",
    "vite",
    "nuxt",
    "@remix-run/node",
    "@sveltejs/kit",
];
const PYTHON_ENV_LOADERS: &[&str] = &["python-dotenv", "pydantic-settings", "environs", "dynaconf"];

#[derive(Default)]
struct Signals {
    s1_secret_env: Vec<Evidence>,
    s2_sdk_dep: Vec<Evidence>,
    s3_base_url: Vec<Evidence>,
    s4_credential: Vec<Evidence>,
    s5_mention: Vec<Evidence>,
    credential_names: Vec<String>,
    target_env_files: BTreeSet<String>,
    /// Distinct candidate origins read from manifest-declared base-URL
    /// vars (custom-origin providers only), already policy-validated.
    inferred_origins: BTreeSet<String>,
    /// Origin candidates that FAILED validation (count is enough; the
    /// value is deliberately not carried).
    rejected_origins: u32,
}

/// Detect providers in one bounded, canonicalized folder.
pub fn detect(conn: &Connection, input: &DetectionInput) -> Result<ProjectDetection> {
    let canonical = input.folder.canonicalize().map_err(|e| {
        CoreError::InvalidInput(format!("cannot access {}: {e}", input.folder.display()))
    })?;
    if !canonical.is_dir() {
        return Err(CoreError::InvalidInput(format!(
            "{} is not a folder",
            canonical.display()
        )));
    }
    refuse_dangerous_roots(&canonical)?;

    let mut scanned: u32 = 0;
    let mut skipped_oversized: u32 = 0;
    let mut signals: BTreeMap<String, Signals> = BTreeMap::new();

    // --- .env inventory (envgov bounds: depth ≤ 6, no symlinks) ---------
    let env_files = envgov::discover(&canonical)?;
    let env_summaries: Vec<EnvFileSummary> = env_files
        .iter()
        .map(|f| EnvFileSummary {
            rel_path: f.rel_path.clone(),
            class: match f.class {
                envgov::EnvFileClass::Values => "values".to_string(),
                envgov::EnvFileClass::Template => "template".to_string(),
            },
            git_tracked: matches!(f.git_status, envgov::GitStatus::Tracked),
        })
        .collect();

    // Names of NON-secret base-URL vars any gateway-capable manifest
    // declares — the only vars whose values detection may read (§5).
    let mut base_url_vars: BTreeMap<String, Vec<&'static providers::ProviderManifest>> =
        BTreeMap::new();
    for manifest in providers::manifests() {
        if let Some(gw) = &manifest.gateway {
            for var in &gw.env_vars {
                base_url_vars.entry(var.clone()).or_default().push(manifest);
            }
        }
    }

    for file in &env_files {
        if file.class != envgov::EnvFileClass::Values {
            continue;
        }
        let path = Path::new(&file.path);
        let Some(content) = read_bounded(&canonical, path, &mut scanned, &mut skipped_oversized)
        else {
            continue;
        };
        let doc = EnvDocument::parse(&content);
        for entry in doc.entries() {
            // S1: known secret env-var name with a non-placeholder value.
            // The value is inspected only through `is_placeholder_value`
            // and never stored or rendered.
            for manifest in providers::manifests() {
                if manifest
                    .env_vars
                    .iter()
                    .any(|v| v.eq_ignore_ascii_case(&entry.key))
                    && !scanner::is_placeholder_value(entry.value.expose())
                {
                    let sig = signals.entry(manifest.id.clone()).or_default();
                    sig.s1_secret_env.push(Evidence::SecretEnvVarName {
                        var: entry.key.clone(),
                        file: file.rel_path.clone(),
                    });
                    sig.target_env_files.insert(file.rel_path.clone());
                }
            }
            // S3: base-URL variable present by NAME…
            if let Some(manifests) = base_url_vars.get(&entry.key) {
                for manifest in manifests {
                    let sig = signals.entry(manifest.id.clone()).or_default();
                    sig.s3_base_url.push(Evidence::BaseUrlVar {
                        var: entry.key.clone(),
                        file: file.rel_path.clone(),
                    });
                    sig.target_env_files.insert(file.rel_path.clone());
                    // The one value-read exception: infer a custom origin
                    // from the manifest-declared base-URL var. Values are
                    // validated by the full origin policy before they are
                    // ever surfaced; failures increment a counter only.
                    let gw = manifest.gateway.as_ref();
                    if gw.map(|g| g.origins.is_empty()).unwrap_or(false) {
                        let value = entry.value.expose().trim();
                        if value.is_empty() || value.contains("127.0.0.1:") {
                            // Empty, or already pointing at a local
                            // gateway (a previous link) — not an origin.
                            continue;
                        }
                        match routes::validate_origin(value) {
                            Ok((host, port)) => {
                                sig.inferred_origins
                                    .insert(format!("https://{host}:{port}"));
                            }
                            Err(_) => sig.rejected_origins += 1,
                        }
                    }
                }
            }
            // …or a value whose host names a provider. Only base-URL vars
            // may be value-read, so this stays inside the same branch: for
            // fixed-origin providers the var name itself was decisive; for
            // everything else we do NOT read values of arbitrary vars.
        }
    }

    // --- stackdetect signals (root manifests, own byte caps) ------------
    let stack_signals = stackdetect::detect(&canonical)?;
    for sig in &stack_signals {
        let Some(provider) = &sig.provider else {
            continue;
        };
        let entry = signals.entry(provider.clone()).or_default();
        let is_manifest_dep = matches!(
            sig.file.as_str(),
            "package.json" | "requirements.txt" | "pyproject.toml"
        );
        if is_manifest_dep && sig.confidence == providers::Confidence::High {
            // Evidence text looks like `npm dependency "openai"`.
            let dep = sig
                .evidence
                .split('"')
                .nth(1)
                .unwrap_or(&sig.evidence)
                .to_string();
            entry.s2_sdk_dep.push(Evidence::SdkDependency {
                dep,
                manifest: sig.file.clone(),
            });
        } else if sig.file.starts_with(".env") {
            // stackdetect's env-name signal duplicates our S1 (but without
            // the placeholder check); ignore to keep S1 authoritative.
        } else {
            entry.s5_mention.push(Evidence::ConfigFile {
                file: sig.file.clone(),
            });
        }
    }

    // --- lockfile mentions (S5), bounded ---------------------------------
    for lockfile in LOCKFILES {
        let path = canonical.join(lockfile);
        let Some(content) = read_bounded(&canonical, &path, &mut scanned, &mut skipped_oversized)
        else {
            continue;
        };
        for (provider, needle) in LOCKFILE_NEEDLES {
            if content.contains(needle) {
                let entry = signals.entry((*provider).to_string()).or_default();
                if !entry
                    .s5_mention
                    .iter()
                    .any(|e| matches!(e, Evidence::LockfileMention { file } if file == lockfile))
                {
                    entry.s5_mention.push(Evidence::LockfileMention {
                        file: (*lockfile).to_string(),
                    });
                }
            }
        }
    }

    // --- vault-side signals (S4): credentials assigned to the project ---
    if let Some(project_id) = input.project_id {
        let mut stmt = conn.prepare(
            "SELECT provider, name FROM credentials WHERE project_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map([project_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (provider, name) = row?;
            let provider = providers::normalize(&provider);
            if provider.is_empty() {
                continue;
            }
            let entry = signals.entry(provider).or_default();
            entry.s4_credential.push(Evidence::AssignedCredential {
                credential_name: name.clone(),
            });
            entry.credential_names.push(name);
        }
    }

    // --- project signals -------------------------------------------------
    let mut project_signals = ProjectSignals {
        docker_compose: [
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ]
        .iter()
        .any(|f| canonical.join(f).is_file()),
        dockerfile: canonical.join("Dockerfile").is_file(),
        devcontainer: canonical.join(".devcontainer").is_dir()
            || canonical.join(".devcontainer.json").is_file(),
        dotenv_loader: None,
    };
    if let Some(pkg) = read_bounded(
        &canonical,
        &canonical.join("package.json"),
        &mut scanned,
        &mut skipped_oversized,
    ) {
        let has_loader = NODE_ENV_LOADERS
            .iter()
            .any(|dep| pkg.contains(&format!("\"{dep}\"")));
        project_signals.dotenv_loader = Some(has_loader);
    }
    for pyfile in ["requirements.txt", "pyproject.toml"] {
        if let Some(content) = read_bounded(
            &canonical,
            &canonical.join(pyfile),
            &mut scanned,
            &mut skipped_oversized,
        ) {
            let has_loader = PYTHON_ENV_LOADERS.iter().any(|dep| content.contains(dep));
            project_signals.dotenv_loader =
                Some(project_signals.dotenv_loader.unwrap_or(false) || has_loader);
        }
    }

    // --- prior stack decisions (learning loop) ---------------------------
    let repo_key = canonical.display().to_string();
    let mut prior: BTreeMap<String, String> = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT template_id, decision FROM stack_preferences WHERE repo_path = ?1")?;
        let rows = stmt.query_map([&repo_key], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (template, decision) = row?;
            prior.insert(template, decision);
        }
    }

    // --- fusion ----------------------------------------------------------
    let mut detections = Vec::new();
    for (provider_id, sig) in signals {
        let s1 = !sig.s1_secret_env.is_empty();
        let s2 = !sig.s2_sdk_dep.is_empty();
        let s3 = !sig.s3_base_url.is_empty();
        let s4 = !sig.s4_credential.is_empty();
        let s5 = !sig.s5_mention.is_empty();
        if !(s1 || s2 || s3 || s4 || s5) {
            continue;
        }

        let mut confidence = if ((s1 || s4) && (s2 || s3)) || (s1 && s4) {
            DetectionConfidence::Confirmed
        } else if [s1, s2, s4].iter().filter(|x| **x).count() == 1 {
            DetectionConfidence::Likely
        } else {
            DetectionConfidence::Possible
        };

        // Prior user decisions adjust one step up (confirmed earlier) or
        // down (dismissed earlier) — the existing stackdetect loop.
        if let Some(template) = provider_template(&provider_id) {
            match prior.get(template).map(String::as_str) {
                Some("confirmed") => {
                    confidence = match confidence {
                        DetectionConfidence::Possible => DetectionConfidence::Likely,
                        _ => DetectionConfidence::Confirmed,
                    }
                }
                Some("dismissed") => {
                    confidence = match confidence {
                        DetectionConfidence::Confirmed => DetectionConfidence::Likely,
                        _ => DetectionConfidence::Possible,
                    }
                }
                _ => {}
            }
        }

        let manifest = providers::find(&provider_id);
        let mut limitations = Vec::new();
        let configurability = match manifest {
            None => Configurability::Unsupported {
                reason: UnsupportedReason::UnknownProvider,
            },
            Some(m) => match &m.gateway {
                None => {
                    limitations.push(format!(
                        "The {} SDK does not read a base-URL environment variable, so Tethra \
                         cannot observe it this way yet. Everything else still works.",
                        m.name
                    ));
                    Configurability::Unsupported {
                        reason: UnsupportedReason::NoConfigurableBaseUrl,
                    }
                }
                Some(gw) if !gw.origins.is_empty() => Configurability::Automatic,
                Some(_) => {
                    if sig.rejected_origins > 0 {
                        limitations.push(format!(
                            "{} base-URL value(s) found in this project failed origin \
                             validation and were not used.",
                            sig.rejected_origins
                        ));
                    }
                    let mut origins: Vec<&String> = sig.inferred_origins.iter().collect();
                    if origins.len() == 1 {
                        Configurability::NeedsOriginConfirm {
                            inferred_origin: origins.remove(0).clone(),
                        }
                    } else {
                        if origins.len() > 1 {
                            limitations.push(
                                "Multiple conflicting project URLs were found; pick one."
                                    .to_string(),
                            );
                        }
                        Configurability::NeedsOriginInput
                    }
                }
            },
        };

        let mut evidence = Vec::new();
        evidence.extend(sig.s1_secret_env);
        evidence.extend(sig.s2_sdk_dep);
        evidence.extend(sig.s4_credential);
        evidence.extend(sig.s3_base_url);
        evidence.extend(sig.s5_mention);

        detections.push(ProviderDetection {
            display_name: manifest
                .map(|m| m.name.clone())
                .unwrap_or_else(|| provider_id.clone()),
            provider_id,
            confidence,
            configurability,
            evidence,
            credential_candidates: sig.credential_names,
            target_env_files: sig.target_env_files.into_iter().collect(),
            limitations,
        });
    }

    // Confirmed first, then Likely, then Possible; unsupported last within
    // each band; stable by id. Unsupported providers never suppress
    // supported ones — they are simply listed after them.
    detections.sort_by(|a, b| {
        let unsupported = |p: &ProviderDetection| {
            matches!(p.configurability, Configurability::Unsupported { .. })
        };
        b.confidence
            .cmp(&a.confidence)
            .then(unsupported(a).cmp(&unsupported(b)))
            .then(a.provider_id.cmp(&b.provider_id))
    });

    Ok(ProjectDetection {
        folder: canonical,
        providers: detections,
        env_files: env_summaries,
        project_signals,
        scanned_files: scanned,
        skipped_oversized,
    })
}
