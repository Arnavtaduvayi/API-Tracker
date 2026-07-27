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

/// A secret-shaped variable the scan saw but could not attribute to any
/// provider Tethra knows about.
///
/// The screen headed `Detected:` used to list only manifest-matched
/// providers. In a 30-API project that meant twenty-six credentials —
/// `GROQ_API_KEY`, `MISTRAL_API_KEY`, `SENDGRID_API_KEY`, … — appeared
/// nowhere at all: not detected, not unsupported, not unknown, not counted.
/// A user reading that screen would reasonably conclude Tethra had seen
/// their whole project (ZFT-010).
///
/// Carries the variable NAME and the file, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnrecognizedCredential {
    /// The environment-variable name, e.g. `GROQ_API_KEY`.
    pub var: String,
    /// Folder-relative file it was found in.
    pub file: String,
    /// A guess at the service, derived from the variable name alone
    /// (`GROQ_API_KEY` -> "groq"). Presentation only — it never selects a
    /// provider, creates a route, or raises confidence.
    pub name_hint: Option<String>,
}

/// The honest coverage summary a review screen must render.
///
/// Every integration the scan saw lands in exactly one bucket, and the
/// buckets sum to the total. A project with thirty APIs gets thirty
/// accounted for, not four listed and twenty-six invisible.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSummary {
    /// Supported, high enough confidence, destination from a Tethra
    /// manifest — configured automatically.
    pub tracked_automatically: usize,
    /// Supported, but the destination comes from project content and needs
    /// the user's explicit approval.
    pub needs_origin_confirmation: usize,
    /// Recognised provider, but its SDK exposes no base-URL variable, so
    /// Tethra cannot observe it this way.
    pub detected_unsupported: usize,
    /// Secret-shaped variables Tethra has no manifest for.
    pub unrecognized: usize,
    /// Detected at only `Possible` confidence — real evidence, not enough
    /// of it to act on.
    pub low_confidence: usize,
}

impl CoverageSummary {
    pub fn total(&self) -> usize {
        self.tracked_automatically
            + self.needs_origin_confirmation
            + self.detected_unsupported
            + self.unrecognized
            + self.low_confidence
    }

    /// The headline lines, in the order the audit brief specifies.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!("{} API integrations found", self.total())];
        if self.tracked_automatically > 0 {
            out.push(format!(
                "{} can be tracked automatically",
                self.tracked_automatically
            ));
        }
        if self.needs_origin_confirmation > 0 {
            out.push(format!(
                "{} need you to confirm where their traffic goes",
                self.needs_origin_confirmation
            ));
        }
        if self.detected_unsupported > 0 {
            out.push(format!(
                "{} use an SDK configuration Tethra cannot observe yet",
                self.detected_unsupported
            ));
        }
        if self.low_confidence > 0 {
            out.push(format!(
                "{} were detected but not confidently enough to configure",
                self.low_confidence
            ));
        }
        if self.unrecognized > 0 {
            out.push(format!(
                "{} could not be identified — Tethra has no provider definition for them",
                self.unrecognized
            ));
        }
        out
    }
}

/// Every file the scan touched, in exactly one bucket each.
///
/// The pre-remediation scan reported `scanned_files` only for the reader in
/// this module, so a folder whose manifests were all read through
/// `stackdetect` printed "0 file(s) read" while their contents drove the
/// plan (ZFT-002), and an oversized `.env` was never counted at all
/// (ZFT-003). Every reader now reports into the same accounting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanAccounting {
    /// Files read in full.
    pub read: u32,
    /// Refused for exceeding the per-file byte cap; bytes never loaded.
    pub skipped_oversized: u32,
    /// Refused as a symlink, or because the path resolves outside the
    /// selected folder.
    pub skipped_outside_folder: u32,
    /// In bounds, but not valid UTF-8.
    pub skipped_not_utf8: u32,
    /// The walk stopped before exhausting the folder; the reason is
    /// rendered to the user verbatim.
    pub truncated: Option<String>,
    /// Bounds hit inside the non-executing Git reader.
    pub git_warnings: Vec<String>,
}

impl ScanAccounting {
    /// Files that exist and matched a scan rule but were not inspected.
    pub fn skipped_total(&self) -> u32 {
        self.skipped_oversized + self.skipped_outside_folder + self.skipped_not_utf8
    }

    /// One line for the review screen, or `None` when nothing was skipped
    /// and nothing was truncated.
    pub fn describe_gaps(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.skipped_oversized > 0 {
            parts.push(format!("{} too large to read", self.skipped_oversized));
        }
        if self.skipped_outside_folder > 0 {
            parts.push(format!(
                "{} outside the selected folder (symlink)",
                self.skipped_outside_folder
            ));
        }
        if self.skipped_not_utf8 > 0 {
            parts.push(format!("{} not readable as text", self.skipped_not_utf8));
        }
        if let Some(reason) = &self.truncated {
            parts.push(reason.clone());
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDetection {
    pub folder: PathBuf,
    pub providers: Vec<ProviderDetection>,
    pub env_files: Vec<EnvFileSummary>,
    pub project_signals: ProjectSignals,
    pub scanned_files: u32,
    pub skipped_oversized: u32,
    /// Full accounting for every file the scan touched.
    #[serde(default)]
    pub accounting: ScanAccounting,
    /// Secret-shaped variables with no matching provider manifest. Listed
    /// explicitly so the review screen never implies complete coverage
    /// (ZFT-010).
    #[serde(default)]
    pub unrecognized: Vec<UnrecognizedCredential>,
    /// Per-bucket counts; every integration lands in exactly one.
    #[serde(default)]
    pub coverage: CoverageSummary,
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
    not_utf8: &mut u32,
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
    // Read bytes, then decode: a file that exists but is not UTF-8 must be
    // COUNTED, not silently dropped (ZFT-040).
    let bytes = std::fs::read(path).ok()?;
    match String::from_utf8(bytes) {
        Ok(content) => {
            *scanned += 1;
            Some(content)
        }
        Err(_) => {
            *not_utf8 += 1;
            None
        }
    }
}

/// Whether a variable NAME looks like it holds a credential.
///
/// Deliberately name-only: the value is inspected solely through
/// `scanner::is_placeholder_value`, never stored or rendered. This decides
/// whether an unattributed variable is worth telling the user about — a
/// wrong answer costs a line on a review screen, never a route.
fn looks_like_credential_name(name: &str) -> bool {
    const SUBSTRINGS: &[&str] = &[
        "API_KEY",
        "APIKEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "AUTH",
        "_PAT",
    ];
    // A trailing `_KEY` catches the shapes a substring list keeps missing —
    // `ALGOLIA_ADMIN_KEY`, `SEGMENT_WRITE_KEY`, `SUPABASE_ANON_KEY`. It is a
    // SUFFIX rather than a substring so `KEYCLOAK_URL` and `KEYWORDS` do not
    // qualify. Over-inclusion costs one line on a review screen; the failure
    // this replaces was a credential appearing nowhere at all.
    let upper = name.to_ascii_uppercase();
    upper.ends_with("_KEY") || SUBSTRINGS.iter().any(|n| upper.contains(n))
}

/// A presentation-only guess at the service behind an unrecognised
/// variable, from the name alone: `GROQ_API_KEY` -> "groq".
///
/// This NEVER selects a provider, creates a route, or raises confidence —
/// inferring a real integration from a variable name is exactly the kind of
/// evidence inflation the audit flagged elsewhere. It exists so the user
/// can recognise their own service in a list.
fn name_hint(var: &str) -> Option<String> {
    const SUFFIXES: &[&str] = &[
        "_API_KEY",
        "_APIKEY",
        "_SECRET_KEY",
        "_ACCESS_KEY",
        "_SECRET",
        "_TOKEN",
        "_AUTH_TOKEN",
        "_API_TOKEN",
        "_KEY",
    ];
    let upper = var.to_ascii_uppercase();
    for suffix in SUFFIXES {
        if let Some(head) = upper.strip_suffix(suffix) {
            let head = head.trim_start_matches("NEXT_PUBLIC_").trim_matches('_');
            if head.len() >= 2 {
                return Some(head.to_ascii_lowercase());
            }
        }
    }
    None
}

/// The bare authority of a base URL, for the origin policy.
///
/// SDK base URLs carry a path (`https://litellm.corp.example/v1`), but
/// `routes::validate_origin` deliberately accepts only a bare authority —
/// a route's destination is a host, never a host plus a path an attacker
/// chose. Trimming here keeps that rule intact while still letting a real
/// SDK value be understood.
fn origin_authority(value: &str) -> String {
    let Some(rest) = value.strip_prefix("https://") else {
        // Anything that is not https fails `validate_origin` anyway; return
        // it unchanged so the refusal names what was actually configured.
        return value.to_string();
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();
    format!("https://{authority}")
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
        // Every other manifest-backed provider groups under the generic
        // OpenAI-compatible template, which is the one `stackdetect` maps
        // them to. Returning None here would silently disable the
        // confirm/dismiss learning loop for them.
        "groq" | "together" | "cerebras" | "cohere" | "replicate" | "langsmith" | "mistral"
        | "google-gemini" | "huggingface" | "aws-bedrock" | "deepseek" | "xai" | "openrouter"
        | "fireworks" | "perplexity" | "azure-openai" => Some("openai-app"),
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
    ("groq", "\"groq-sdk\""),
    ("groq", "\"groq\""),
    ("together", "\"together-ai\""),
    ("together", "\"together\""),
    ("cerebras", "\"@cerebras/"),
    ("cerebras", "\"cerebras-cloud-sdk\""),
    ("cohere", "\"cohere-ai\""),
    ("cohere", "\"cohere\""),
    ("replicate", "\"replicate\""),
    ("langsmith", "\"langsmith\""),
    ("mistral", "\"@mistralai/"),
    ("mistral", "\"mistralai\""),
    ("google-gemini", "\"@google/genai\""),
    ("google-gemini", "\"google-genai\""),
    ("huggingface", "\"@huggingface/"),
    ("huggingface", "\"huggingface-hub\""),
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
    /// A value under a manifest-declared secret variable matched that
    /// provider's published key format. Raises confidence; never lowers it.
    s1_key_format_confirmed: bool,
    /// For a FIXED-origin provider: base-URL values already present in the
    /// project that do NOT match the manifest origin. Their presence means
    /// the project already points somewhere else, so the provider must not
    /// be reconfigured automatically (ZFT-012).
    existing_base_urls: BTreeSet<String>,
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
    let mut not_utf8: u32 = 0;
    // Credential-shaped variables no manifest claimed. Keyed by name so the
    // same variable in several env files is reported once.
    let mut unattributed: BTreeMap<String, UnrecognizedCredential> = BTreeMap::new();
    let mut signals: BTreeMap<String, Signals> = BTreeMap::new();

    // --- .env inventory (envgov bounds; NON-EXECUTING git status) -------
    // `discover_bounded` spawns nothing: repository status comes from
    // `gitsafe`'s byte reader, and the per-file size check happens before
    // any file is opened (ADR 0023; ZFT-001, ZFT-003, ZFT-028).
    let discovery = envgov::discover_bounded(
        &canonical,
        envgov::DiscoveryLimits::default(),
        envgov::HistoryProbe::Skip,
    )?;
    let env_files = discovery.files;
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
        let Some(content) = read_bounded(
            &canonical,
            path,
            &mut scanned,
            &mut skipped_oversized,
            &mut not_utf8,
        ) else {
            continue;
        };
        let doc = EnvDocument::parse(&content);
        for entry in doc.entries() {
            // Every credential-shaped variable is remembered up front. The
            // manifest loops below REMOVE the ones they claim, so whatever
            // is left is genuinely unattributed and gets listed rather than
            // dropped (ZFT-010).
            if looks_like_credential_name(&entry.key)
                && !scanner::is_placeholder_value(entry.value.expose())
            {
                unattributed.insert(
                    entry.key.clone(),
                    UnrecognizedCredential {
                        var: entry.key.clone(),
                        file: file.rel_path.clone(),
                        name_hint: name_hint(&entry.key),
                    },
                );
            }
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
                    // The manifest's own key-format patterns are the
                    // provider's PUBLIC shape markers (`sk-proj-…`,
                    // `sk-ant-…`). They already existed and were never
                    // consulted, so the placeholder filter was the only
                    // check a value ever got: `OPENAI_API_KEY=abcdefgh`
                    // reached `likely` and was auto-selected (ZFT-027).
                    //
                    // A match RAISES confidence; a non-match does not
                    // lower it, because a provider may issue a format
                    // Tethra's manifest predates and refusing on that
                    // would be worse than the false positive. The value is
                    // tested and discarded — never stored or rendered.
                    if !manifest.detection.is_empty()
                        && scanner::value_matches_provider_format(
                            &manifest.id,
                            entry.value.expose(),
                        )
                    {
                        sig.s1_key_format_confirmed = true;
                    }
                    // Claimed by a manifest: no longer unattributed.
                    unattributed.remove(&entry.key);
                }
            }
            // S3: base-URL variable present by NAME…
            //
            // …unless the value is Tethra's OWN loopback writing. After the
            // first link, `OPENAI_BASE_URL=http://127.0.0.1:<port>/p/<slug>/…`
            // sat in the file, and its mere presence counted as the second
            // "independent signal class" that promotes a detection to
            // Confirmed — so Tethra's output became Tethra's evidence
            // (ZFT-025). The value was already excluded from ORIGIN
            // inference for this reason; excluding it from the SIGNAL too is
            // the same rule applied consistently.
            let is_our_own_writing = entry.value.expose().trim().contains("127.0.0.1:");
            if let Some(manifests) = base_url_vars
                .get(&entry.key)
                .filter(|_| !is_our_own_writing)
            {
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
                    let custom_origin_provider = gw.map(|g| g.origins.is_empty()).unwrap_or(false);
                    if !custom_origin_provider {
                        // A FIXED-origin provider whose base-URL variable
                        // already holds a value. The value used to be
                        // ignored entirely: its mere presence became a
                        // second "independent" signal that pushed the
                        // detection to Confirmed, and the route was then
                        // built to the manifest origin — so a user behind
                        // LiteLLM, a corporate LLM gateway, Azure OpenAI or
                        // a self-hosted proxy had their traffic silently
                        // re-pointed at the provider, carrying their key,
                        // with nothing on screen saying the destination
                        // changed (ZFT-012).
                        //
                        // An already-customised endpoint is now evidence
                        // that Tethra does NOT know where this project's
                        // traffic should go, so it is surfaced for the same
                        // explicit approval a custom-origin provider gets.
                        let value = entry.value.expose().trim();
                        if !value.is_empty() && !value.contains("127.0.0.1:") {
                            let manifest_origins: Vec<String> = gw
                                .map(|g| g.origins.clone())
                                .unwrap_or_default()
                                .iter()
                                .map(|o| o.trim_end_matches('/').to_ascii_lowercase())
                                .collect();
                            let bare = value.trim_end_matches('/').to_ascii_lowercase();
                            let matches_manifest = manifest_origins
                                .iter()
                                .any(|o| bare == *o || bare.starts_with(&format!("{o}/")));
                            if !matches_manifest {
                                match routes::validate_origin(&origin_authority(value)) {
                                    Ok((host, port)) => {
                                        sig.existing_base_urls
                                            .insert(format!("https://{host}:{port}"));
                                    }
                                    // Unparseable or policy-refused: still a
                                    // customisation Tethra must not silently
                                    // overwrite, so it downgrades the
                                    // provider without offering an origin.
                                    Err(_) => sig.rejected_origins += 1,
                                }
                            }
                        }
                        continue;
                    }
                    {
                        let value = entry.value.expose().trim();
                        if value.is_empty() || value.contains("127.0.0.1:") {
                            // Empty, or already pointing at a local
                            // gateway (a previous link) — not an origin.
                            continue;
                        }
                        match routes::validate_origin(&origin_authority(value)) {
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
    let (stack_signals, stack_counters) = stackdetect::detect_counted(&canonical)?;
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
        let Some(content) = read_bounded(
            &canonical,
            &path,
            &mut scanned,
            &mut skipped_oversized,
            &mut not_utf8,
        ) else {
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
        .any(|f| stackdetect::is_contained_file(&canonical, &canonical.join(f))),
        // `is_file`/`is_dir` follow symlinks; containment checks keep a
        // symlinked marker from asserting facts about content outside the
        // selected folder (ZFT-002).
        dockerfile: stackdetect::is_contained_file(&canonical, &canonical.join("Dockerfile")),
        devcontainer: stackdetect::is_contained_dir(&canonical, &canonical.join(".devcontainer"))
            || stackdetect::is_contained_file(&canonical, &canonical.join(".devcontainer.json")),
        dotenv_loader: None,
    };
    if let Some(pkg) = read_bounded(
        &canonical,
        &canonical.join("package.json"),
        &mut scanned,
        &mut skipped_oversized,
        &mut not_utf8,
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
            &mut not_utf8,
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

        // A key whose VALUE matches the provider's published format is
        // strong, independent evidence — much stronger than the variable
        // name alone, which anyone can type. It promotes a lone S1 from
        // Likely to Confirmed, and a value that matches NO known format
        // holds a lone S1 at Possible rather than the auto-select
        // threshold (ZFT-027).
        let key_format = sig.s1_key_format_confirmed;
        let two_independent_classes = ((s1 || s4) && (s2 || s3)) || (s1 && s4);
        let mut confidence = if two_independent_classes || (s1 && key_format) {
            // Two independent signal classes, OR one signal class whose
            // VALUE matches the provider's published key format — a shape
            // no one types by accident.
            DetectionConfidence::Confirmed
        } else if s1 && !key_format && !(s2 || s3 || s4) {
            // A recognised variable NAME holding a value of no recognised
            // shape. Real evidence, not enough of it to configure without
            // being asked.
            DetectionConfidence::Possible
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
                Some(gw) if !gw.origins.is_empty() => {
                    // Fixed-origin provider — automatic, UNLESS the project
                    // already points its base-URL variable somewhere else.
                    let mut existing: Vec<&String> = sig.existing_base_urls.iter().collect();
                    if existing.len() == 1 {
                        let inferred = existing.remove(0).clone();
                        limitations.push(format!(
                            "This project already sets {}'s base URL to {inferred}. Tethra will \
                             not silently re-point it at {}: approve {inferred} to keep sending \
                             traffic there through the gateway, or remove the variable to use \
                             the provider directly.",
                            m.name,
                            gw.origins.first().cloned().unwrap_or_default()
                        ));
                        Configurability::NeedsOriginConfirm {
                            inferred_origin: inferred,
                        }
                    } else if !existing.is_empty() {
                        limitations.push(format!(
                            "This project sets {}'s base URL to more than one destination; pick \
                             one before tracking it.",
                            m.name
                        ));
                        Configurability::NeedsOriginInput
                    } else if sig.rejected_origins > 0 {
                        limitations.push(format!(
                            "This project already customises {}'s base URL to a destination \
                             Tethra cannot route to safely, so it was left alone.",
                            m.name
                        ));
                        Configurability::NeedsOriginInput
                    } else {
                        Configurability::Automatic
                    }
                }
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

    // Base-URL variables are configuration, not credentials, so they never
    // become "unrecognised credentials" even when their provider is known.
    for var in base_url_vars.keys() {
        unattributed.remove(var);
    }
    let unrecognized: Vec<UnrecognizedCredential> = unattributed.into_values().collect();

    // Every integration lands in exactly one bucket, and the buckets sum to
    // the number the screen reports.
    let mut coverage = CoverageSummary {
        unrecognized: unrecognized.len(),
        ..CoverageSummary::default()
    };
    for p in &detections {
        match &p.configurability {
            _ if p.confidence < DetectionConfidence::Likely => coverage.low_confidence += 1,
            Configurability::Automatic => coverage.tracked_automatically += 1,
            Configurability::NeedsOriginConfirm { .. } | Configurability::NeedsOriginInput => {
                coverage.needs_origin_confirmation += 1
            }
            Configurability::Unsupported { .. } => coverage.detected_unsupported += 1,
        }
    }

    // One accounting across BOTH readers. `scanned_files` keeps its old
    // meaning for compatibility but is now the true total, so the review
    // screen can no longer print "0 file(s) read" over content that drove
    // the plan.
    let accounting = ScanAccounting {
        read: scanned + stack_counters.read,
        skipped_oversized: skipped_oversized
            + stack_counters.skipped_oversized
            + discovery.skipped_oversized.len() as u32,
        skipped_outside_folder: stack_counters.skipped_outside_folder,
        skipped_not_utf8: not_utf8 + stack_counters.skipped_not_utf8,
        truncated: discovery.truncated.map(|t| t.describe().to_string()),
        git_warnings: discovery.git_warnings,
    };

    Ok(ProjectDetection {
        folder: canonical,
        providers: detections,
        env_files: env_summaries,
        project_signals,
        scanned_files: accounting.read,
        skipped_oversized: accounting.skipped_oversized,
        accounting,
        unrecognized,
        coverage,
    })
}
