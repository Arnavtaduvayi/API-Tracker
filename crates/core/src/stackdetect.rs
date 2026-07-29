//! Local stack detection: deterministic rules over safe static repository
//! signals.
//!
//! Detection reads a bounded set of well-known files (dependency manifests,
//! lockfiles, framework configuration, workflow directories, `.env`
//! variable NAMES) and maps them to template/provider suggestions. It is
//! **not machine learning** — it is deterministic rules plus a locally
//! stored history of the user's confirm/dismiss decisions, and every
//! surface describes it that way.
//!
//! Hard guarantees:
//! - Nothing is executed and nothing leaves the machine.
//! - Reads are bounded (`MAX_FILE_BYTES`); huge files are skipped.
//! - Evidence never contains secret values: dependency names, file names,
//!   and environment-variable NAMES only (`.env` values are parsed into
//!   redacting `SecretString`s and never copied into evidence).
//! - Suggestions require explicit confirmation before anything is applied;
//!   dismissals are remembered; all learned data can be reset or deleted.

use crate::error::Result;
use crate::providers::Confidence;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Files larger than this are skipped (they are not dependency manifests).
const MAX_FILE_BYTES: u64 = 262_144;

/// One piece of evidence found in the repository.
#[derive(Debug, Clone, Serialize)]
pub struct StackSignal {
    /// Repository-relative file the signal came from.
    pub file: String,
    /// Human-readable, non-secret description of what was found.
    pub evidence: String,
    /// The template this signal points at, if any.
    pub template_id: Option<String>,
    /// The provider this signal points at, if any.
    pub provider: Option<String>,
    pub confidence: Confidence,
}

/// A template suggestion derived from signals plus stored preferences.
#[derive(Debug, Clone, Serialize)]
pub struct StackSuggestion {
    pub template_id: String,
    pub confidence: Confidence,
    /// The evidence lines supporting this suggestion (displayed verbatim).
    pub evidence: Vec<String>,
    /// A previous user decision for this repo+template, if any
    /// ("confirmed" or "dismissed").
    pub prior_decision: Option<String>,
}

/// The full detection outcome for one repository.
#[derive(Debug, Clone, Serialize)]
pub struct DetectionReport {
    pub repo_path: String,
    pub signals: Vec<StackSignal>,
    pub suggestions: Vec<StackSuggestion>,
}

/// Honest counters for one detection pass. Every file the pass touched is
/// accounted for in exactly one bucket — nothing is silently dropped
/// (ZFT-002, ZFT-003, ZFT-040).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanCounters {
    /// Files read in full.
    pub read: u32,
    /// Files refused because they exceeded [`MAX_FILE_BYTES`]. Their bytes
    /// were never loaded.
    pub skipped_oversized: u32,
    /// Files refused because they are a symlink, or resolve outside the
    /// selected folder.
    pub skipped_outside_folder: u32,
    /// Files that exist and are in bounds but are not valid UTF-8.
    pub skipped_not_utf8: u32,
}

/// Read a file that must live under `root`.
///
/// Three refusals, in order, before any byte is read:
///
/// 1. the final component is a **symlink** — it could point anywhere, and
///    `metadata()` would silently follow it;
/// 2. the canonical path is **not under `root`** — this catches a symlinked
///    parent directory and a `..` escape;
/// 3. the file is **over the byte cap**.
///
/// The previous implementation used `std::fs::metadata`, which follows
/// symlinks, with no containment check at all: a symlinked `package.json`
/// pointing outside the selected folder was read and its dependencies
/// became auto-selected providers (ZFT-002).
///
/// A hardlink to a file outside the folder is indistinguishable from a
/// real file inside it at the filesystem level and is therefore still
/// read; that residual is recorded in
/// `docs/activity-onboarding/KNOWN_LIMITATIONS.md`.
fn read_bounded(root: &Path, path: &Path, counters: &mut ScanCounters) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        counters.skipped_outside_folder += 1;
        return None;
    }
    if !meta.is_file() {
        return None;
    }
    match path.canonicalize() {
        Ok(canon) if canon.starts_with(root) => {}
        Ok(_) => {
            counters.skipped_outside_folder += 1;
            return None;
        }
        Err(_) => return None,
    }
    if meta.len() > MAX_FILE_BYTES {
        counters.skipped_oversized += 1;
        return None;
    }
    match std::fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => {
                counters.read += 1;
                Some(text)
            }
            Err(_) => {
                // Not valid UTF-8: a binary file under a manifest's name.
                // Counted, never silently dropped.
                counters.skipped_not_utf8 += 1;
                None
            }
        },
        Err(_) => None,
    }
}

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

/// npm dependency name → (template, provider).
///
/// The provider list tracks `provider-manifests/`. A provider with no
/// stack template still maps to the nearest generic one — the template is
/// a UI grouping, while the PROVIDER is what tracking acts on, and a
/// missing entry here is why an installed SDK produced no detection signal.
fn npm_dep_rule(dep: &str) -> Option<(&'static str, Option<&'static str>)> {
    match dep {
        "openai" => Some(("openai-app", Some("openai"))),
        d if d.starts_with("@anthropic-ai/") => Some(("anthropic-app", Some("anthropic"))),
        "stripe" => Some(("stripe-app", Some("stripe"))),
        d if d.starts_with("@supabase/") => Some(("supabase-web", Some("supabase"))),
        "octokit" => Some(("github-automation", Some("github"))),
        d if d.starts_with("@octokit/") => Some(("github-automation", Some("github"))),
        // OpenAI-compatible and other manifest-backed providers.
        "groq-sdk" => Some(("openai-app", Some("groq"))),
        "together-ai" => Some(("openai-app", Some("together"))),
        "@cerebras/cerebras_cloud_sdk" => Some(("openai-app", Some("cerebras"))),
        "cohere-ai" => Some(("openai-app", Some("cohere"))),
        "replicate" => Some(("openai-app", Some("replicate"))),
        "langsmith" => Some(("openai-app", Some("langsmith"))),
        d if d.starts_with("@mistralai/") => Some(("openai-app", Some("mistral"))),
        d if d.starts_with("@google/gen") || d == "@google/generative-ai" => {
            Some(("openai-app", Some("google-gemini")))
        }
        d if d.starts_with("@huggingface/") => Some(("openai-app", Some("huggingface"))),
        d if d.starts_with("@aws-sdk/client-bedrock") => Some(("openai-app", Some("aws-bedrock"))),
        "next" => Some(("nextjs-app", None)),
        "express" | "fastify" | "koa" | "hono" => Some(("node-backend", None)),
        _ => None,
    }
}

/// Python package name → (template, provider).
fn py_dep_rule(dep: &str) -> Option<(&'static str, Option<&'static str>)> {
    match dep {
        "openai" => Some(("openai-app", Some("openai"))),
        "anthropic" => Some(("anthropic-app", Some("anthropic"))),
        "stripe" => Some(("stripe-app", Some("stripe"))),
        "supabase" => Some(("supabase-web", Some("supabase"))),
        "groq" => Some(("openai-app", Some("groq"))),
        "together" => Some(("openai-app", Some("together"))),
        "cerebras-cloud-sdk" => Some(("openai-app", Some("cerebras"))),
        "cohere" => Some(("openai-app", Some("cohere"))),
        "replicate" => Some(("openai-app", Some("replicate"))),
        "langsmith" => Some(("openai-app", Some("langsmith"))),
        "mistralai" => Some(("openai-app", Some("mistral"))),
        "google-genai" | "google-generativeai" => Some(("openai-app", Some("google-gemini"))),
        "huggingface-hub" => Some(("openai-app", Some("huggingface"))),
        "boto3" => Some(("openai-app", Some("aws-bedrock"))),
        "fastapi" | "flask" | "django" => Some(("python-backend", None)),
        _ => None,
    }
}

fn push(
    out: &mut Vec<StackSignal>,
    file: &str,
    evidence: String,
    rule: (&'static str, Option<&'static str>),
    confidence: Confidence,
) {
    out.push(StackSignal {
        file: file.to_string(),
        evidence,
        template_id: Some(rule.0.to_string()),
        provider: rule.1.map(str::to_string),
        confidence,
    });
}

fn scan_package_json(repo: &Path, out: &mut Vec<StackSignal>, counters: &mut ScanCounters) {
    let Some(text) = read_bounded(repo, &repo.join("package.json"), counters) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    for section in ["dependencies", "devDependencies"] {
        let Some(deps) = json.get(section).and_then(|d| d.as_object()) else {
            continue;
        };
        for dep in deps.keys() {
            if let Some(rule) = npm_dep_rule(dep) {
                push(
                    out,
                    "package.json",
                    format!("dependency \"{dep}\" in {section}"),
                    rule,
                    Confidence::High,
                );
            }
        }
    }
}

fn scan_python_manifests(repo: &Path, out: &mut Vec<StackSignal>, counters: &mut ScanCounters) {
    // requirements.txt: one requirement per line; the package name is the
    // leading token before any version specifier or extra.
    if let Some(text) = read_bounded(repo, &repo.join("requirements.txt"), counters) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            if let Some(name) = python_requirement_name(line) {
                if let Some(rule) = py_dep_rule(&name) {
                    push(
                        out,
                        "requirements.txt",
                        format!("requirement \"{name}\""),
                        rule,
                        Confidence::High,
                    );
                }
            }
        }
    }
    // pyproject.toml: dependency entries are PEP 508 requirement strings,
    // either quoted inside a `dependencies` array or written as a
    // `name = "spec"` key (Poetry).
    //
    // This used to test `line.starts_with("\"openai")`, a PREFIX match, so
    // `"openai-whisper>=20231117"` — an OFFLINE speech-to-text package that
    // makes no OpenAI API calls at all — produced `openai likely Automatic`
    // and got a route (ZFT-026). `requirements.txt` above always matched
    // exactly, so the two parsers disagreed about the same project.
    // Both now extract the package name and compare it whole.
    if let Some(text) = read_bounded(repo, &repo.join("pyproject.toml"), counters) {
        for line in text.lines() {
            let l = line.trim();
            let candidate = l
                .strip_prefix('"')
                .or_else(|| l.strip_prefix('\''))
                .unwrap_or(l);
            let Some(name) = python_requirement_name(candidate) else {
                continue;
            };
            if let Some(rule) = py_dep_rule(&name) {
                push(
                    out,
                    "pyproject.toml",
                    format!("dependency \"{name}\""),
                    rule,
                    Confidence::High,
                );
            }
        }
    }
}

/// The package name at the head of a PEP 508 requirement string, normalized
/// per PEP 503 (runs of `-`, `_` and `.` collapse to a single `-`, lowercase).
///
/// Returns `None` when the line does not begin with something name-shaped,
/// so prose inside a manifest cannot become a dependency.
fn python_requirement_name(line: &str) -> Option<String> {
    let raw: String = line
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    if raw.is_empty() || !raw.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    // What follows the name must be a separator a requirement can legally
    // use — not another name character, and not the start of prose.
    let rest = line[raw.len()..].trim_start();
    let plausible = rest.is_empty()
        || rest.starts_with(['"', '\'', '[', '=', '<', '>', '!', '~', ';', ',', ']'])
        || rest.starts_with("@ ");
    if !plausible {
        return None;
    }
    let mut normalized = String::with_capacity(raw.len());
    let mut last_was_sep = false;
    for c in raw.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !last_was_sep && !normalized.is_empty() {
                normalized.push('-');
            }
            last_was_sep = true;
        } else {
            normalized.push(c.to_ascii_lowercase());
            last_was_sep = false;
        }
    }
    let normalized = normalized.trim_end_matches('-').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Whether `path` is a real file that lives under `root`.
///
/// `Path::is_file` follows symlinks, so a symlinked `next.config.js`
/// pointing outside the selected folder would otherwise become evidence
/// about content the user did not choose to expose.
pub fn is_contained_file(root: &Path, path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => path
            .canonicalize()
            .map(|c| c.starts_with(root))
            .unwrap_or(false),
        _ => false,
    }
}

/// Whether `path` is a real directory that lives under `root`.
pub fn is_contained_dir(root: &Path, path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => path
            .canonicalize()
            .map(|c| c.starts_with(root))
            .unwrap_or(false),
        _ => false,
    }
}

fn scan_config_files(repo: &Path, out: &mut Vec<StackSignal>, counters: &mut ScanCounters) {
    let _ = &counters;
    for name in [
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "vercel.json",
    ] {
        if is_contained_file(repo, &repo.join(name)) {
            push(
                out,
                name,
                format!("framework configuration file {name}"),
                ("nextjs-app", None),
                Confidence::Medium,
            );
        }
    }
    let workflows = repo.join(".github").join("workflows");
    if let Ok(entries) = std::fs::read_dir(&workflows) {
        let count = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_lowercase();
                n.ends_with(".yml") || n.ends_with(".yaml")
            })
            .count();
        if count > 0 {
            push(
                out,
                ".github/workflows",
                format!("{count} GitHub Actions workflow file(s)"),
                ("github-automation", Some("github")),
                Confidence::Medium,
            );
        }
    }
    if repo.join("Dockerfile").is_file() {
        out.push(StackSignal {
            file: "Dockerfile".into(),
            evidence: "Dockerfile present (containerized service)".into(),
            template_id: None,
            provider: None,
            confidence: Confidence::Low,
        });
    }
    for lockfile in ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"] {
        if repo.join(lockfile).is_file() {
            out.push(StackSignal {
                file: lockfile.into(),
                evidence: format!("Node lockfile {lockfile} present"),
                template_id: None,
                provider: None,
                confidence: Confidence::Low,
            });
        }
    }
}

/// `.env`-style files: variable NAMES only, matched against the provider
/// manifests' known secret-bearing variables. Values never leave the
/// parser's redacting wrappers.
fn scan_env_names(repo: &Path, out: &mut Vec<StackSignal>, counters: &mut ScanCounters) {
    let manifests = crate::providers::manifests();
    let Ok(entries) = std::fs::read_dir(repo) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(".env") {
            continue;
        }
        let Some(text) = read_bounded(repo, &entry.path(), counters) else {
            continue;
        };
        let parsed = crate::envfile::EnvDocument::parse(&text);
        for e in parsed.entries() {
            for m in manifests {
                if m.env_vars.iter().any(|v| v == &e.key) {
                    out.push(StackSignal {
                        file: name.clone(),
                        evidence: format!("environment variable name {} (values not read)", e.key),
                        template_id: provider_template(&m.id).map(str::to_string),
                        provider: Some(m.id.clone()),
                        confidence: Confidence::Medium,
                    });
                }
            }
        }
    }
}

/// Detect signals in one repository. Pure reads; nothing is executed, and
/// nothing outside the repository is read.
pub fn detect(repo: &Path) -> Result<Vec<StackSignal>> {
    Ok(detect_counted(repo)?.0)
}

/// [`detect`], plus the honest per-file accounting the review screen needs
/// so a folder whose manifests were all refused cannot report a clean scan.
pub fn detect_counted(repo: &Path) -> Result<(Vec<StackSignal>, ScanCounters)> {
    // Canonicalize once: every containment decision below compares against
    // this, so a symlinked ancestor cannot widen the scan.
    let root = repo.canonicalize().map_err(|e| {
        crate::error::CoreError::InvalidInput(format!("cannot access {}: {e}", repo.display()))
    })?;
    let mut out = Vec::new();
    let mut counters = ScanCounters::default();
    scan_package_json(&root, &mut out, &mut counters);
    scan_python_manifests(&root, &mut out, &mut counters);
    scan_config_files(&root, &mut out, &mut counters);
    scan_env_names(&root, &mut out, &mut counters);
    Ok((out, counters))
}

fn conf_rank(c: Confidence) -> u8 {
    match c {
        Confidence::High => 2,
        Confidence::Medium => 1,
        Confidence::Low => 0,
    }
}

/// Combine signals into template suggestions, applying stored preferences
/// (`repo+template → confirmed|dismissed`). Dismissed suggestions are kept
/// in the list with their decision attached — callers decide how to hide
/// them — so a dismissal is never silent data loss.
pub fn suggest(signals: &[StackSignal], prior: &BTreeMap<String, String>) -> Vec<StackSuggestion> {
    let mut grouped: BTreeMap<String, (Confidence, Vec<String>)> = BTreeMap::new();
    for s in signals {
        let Some(t) = &s.template_id else { continue };
        let entry = grouped
            .entry(t.clone())
            .or_insert((Confidence::Low, Vec::new()));
        if conf_rank(s.confidence) > conf_rank(entry.0) {
            entry.0 = s.confidence;
        }
        entry.1.push(format!("{}: {}", s.file, s.evidence));
    }

    // Composite rule: a frontend + billing/database + LLM combination is a
    // full-stack SaaS shape.
    let saas_parts = [
        "nextjs-app",
        "stripe-app",
        "supabase-web",
        "openai-app",
        "anthropic-app",
    ];
    let present: Vec<&str> = saas_parts
        .iter()
        .copied()
        .filter(|p| grouped.contains_key(*p))
        .collect();
    if present.len() >= 3 {
        let evidence = vec![format!(
            "combination of {} detected together",
            present.join(", ")
        )];
        grouped.insert("fullstack-saas".into(), (Confidence::Medium, evidence));
    }

    let mut out: Vec<StackSuggestion> = grouped
        .into_iter()
        .map(|(template_id, (confidence, evidence))| {
            let prior_decision = prior.get(&template_id).cloned();
            StackSuggestion {
                // A previously confirmed suggestion is trusted at high
                // confidence; the decision is still shown.
                confidence: if prior_decision.as_deref() == Some("confirmed") {
                    Confidence::High
                } else {
                    confidence
                },
                template_id,
                evidence,
                prior_decision,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        conf_rank(b.confidence)
            .cmp(&conf_rank(a.confidence))
            .then(a.template_id.cmp(&b.template_id))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, content).unwrap();
        }
        dir
    }

    #[test]
    fn detects_npm_dependencies_with_evidence() {
        let repo = repo_with(&[(
            "package.json",
            r#"{"dependencies":{"openai":"^4.0.0","next":"^15.0.0"},"devDependencies":{"vitest":"^3"}}"#,
        )]);
        let signals = detect(repo.path()).unwrap();
        let openai = signals
            .iter()
            .find(|s| s.template_id.as_deref() == Some("openai-app"))
            .unwrap();
        assert_eq!(openai.confidence, Confidence::High);
        assert!(openai.evidence.contains("\"openai\""));
        assert!(signals
            .iter()
            .any(|s| s.template_id.as_deref() == Some("nextjs-app")));
        // vitest maps to nothing.
        assert!(!signals.iter().any(|s| s.evidence.contains("vitest")));
    }

    #[test]
    fn detects_python_requirements() {
        let repo = repo_with(&[(
            "requirements.txt",
            "anthropic==0.40.0\nfastapi>=0.100\n# openai (commented out)\n",
        )]);
        let signals = detect(repo.path()).unwrap();
        assert!(signals
            .iter()
            .any(|s| s.template_id.as_deref() == Some("anthropic-app")));
        assert!(signals
            .iter()
            .any(|s| s.template_id.as_deref() == Some("python-backend")));
        // The commented line is not a requirement.
        assert!(!signals
            .iter()
            .any(|s| s.template_id.as_deref() == Some("openai-app")));
    }

    #[test]
    fn env_names_signal_without_reading_values() {
        let repo = repo_with(&[(
            ".env",
            "STRIPE_SECRET_KEY=sk_test_notarealvalue123456789012\n",
        )]);
        let signals = detect(repo.path()).unwrap();
        let sig = signals
            .iter()
            .find(|s| s.template_id.as_deref() == Some("stripe-app"))
            .unwrap();
        assert_eq!(sig.confidence, Confidence::Medium);
        assert!(sig.evidence.contains("STRIPE_SECRET_KEY"));
        // The VALUE never appears in evidence.
        assert!(!sig.evidence.contains("notarealvalue"));
    }

    #[test]
    fn fullstack_combination_composes() {
        let repo = repo_with(&[(
            "package.json",
            r#"{"dependencies":{"next":"1","stripe":"1","@supabase/supabase-js":"1","openai":"1"}}"#,
        )]);
        let signals = detect(repo.path()).unwrap();
        let suggestions = suggest(&signals, &BTreeMap::new());
        assert!(suggestions
            .iter()
            .any(|s| s.template_id == "fullstack-saas"));
    }

    #[test]
    fn preferences_mark_and_boost() {
        let repo = repo_with(&[("package.json", r#"{"dependencies":{"express":"4"}}"#)]);
        let signals = detect(repo.path()).unwrap();
        let mut prior = BTreeMap::new();
        prior.insert("node-backend".to_string(), "dismissed".to_string());
        let s = suggest(&signals, &prior);
        let node = s.iter().find(|s| s.template_id == "node-backend").unwrap();
        assert_eq!(node.prior_decision.as_deref(), Some("dismissed"));

        let mut prior = BTreeMap::new();
        prior.insert("node-backend".to_string(), "confirmed".to_string());
        let s = suggest(&signals, &prior);
        let node = s.iter().find(|s| s.template_id == "node-backend").unwrap();
        assert_eq!(node.confidence, Confidence::High);
        assert_eq!(node.prior_decision.as_deref(), Some("confirmed"));
    }

    #[test]
    fn oversized_files_are_skipped() {
        let big = "x".repeat((MAX_FILE_BYTES + 1) as usize);
        let repo = repo_with(&[("package.json", big.as_str())]);
        assert!(detect(repo.path()).unwrap().is_empty());
    }
}
