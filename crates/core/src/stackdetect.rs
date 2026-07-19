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

fn read_bounded(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
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
fn npm_dep_rule(dep: &str) -> Option<(&'static str, Option<&'static str>)> {
    match dep {
        "openai" => Some(("openai-app", Some("openai"))),
        d if d.starts_with("@anthropic-ai/") => Some(("anthropic-app", Some("anthropic"))),
        "stripe" => Some(("stripe-app", Some("stripe"))),
        d if d.starts_with("@supabase/") => Some(("supabase-web", Some("supabase"))),
        "octokit" => Some(("github-automation", Some("github"))),
        d if d.starts_with("@octokit/") => Some(("github-automation", Some("github"))),
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

fn scan_package_json(repo: &Path, out: &mut Vec<StackSignal>) {
    let Some(text) = read_bounded(&repo.join("package.json")) else {
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

fn scan_python_manifests(repo: &Path, out: &mut Vec<StackSignal>) {
    // requirements.txt: one requirement per line; the package name is the
    // leading token before any version specifier or extra.
    if let Some(text) = read_bounded(&repo.join("requirements.txt")) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            let name: String = line
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect::<String>()
                .to_lowercase();
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
    // pyproject.toml: look for the dependency name as a quoted token on a
    // line inside a dependencies-ish context. Parsed leniently but
    // line-anchored so a mention in prose does not count.
    if let Some(text) = read_bounded(&repo.join("pyproject.toml")) {
        for line in text.lines() {
            let l = line.trim();
            for name in [
                "openai",
                "anthropic",
                "stripe",
                "supabase",
                "fastapi",
                "flask",
                "django",
            ] {
                let quoted = l.starts_with(&format!("\"{name}"))
                    || l.starts_with(&format!("'{name}"))
                    || l.starts_with(&format!("{name} ="))
                    || l.starts_with(&format!("{name}="));
                if quoted {
                    if let Some(rule) = py_dep_rule(name) {
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
    }
}

fn scan_config_files(repo: &Path, out: &mut Vec<StackSignal>) {
    for name in [
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "vercel.json",
    ] {
        if repo.join(name).is_file() {
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
fn scan_env_names(repo: &Path, out: &mut Vec<StackSignal>) {
    let manifests = crate::providers::manifests();
    let Ok(entries) = std::fs::read_dir(repo) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(".env") {
            continue;
        }
        let Some(text) = read_bounded(&entry.path()) else {
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

/// Detect signals in one repository. Pure reads; nothing is executed.
pub fn detect(repo: &Path) -> Result<Vec<StackSignal>> {
    let mut out = Vec::new();
    scan_package_json(repo, &mut out);
    scan_python_manifests(repo, &mut out);
    scan_config_files(repo, &mut out);
    scan_env_names(repo, &mut out);
    Ok(out)
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
