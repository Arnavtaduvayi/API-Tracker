//! Local secret-detection engine.
//!
//! This module is pure and offline: it takes text and returns findings. It
//! never modifies files, never touches the network, and never emits a
//! plaintext secret — every [`Finding`] carries a redacted preview and keeps
//! the raw value in a self-redacting [`SecretString`] that is skipped during
//! serialization. Vault matching, suppression, and exposure marking are
//! layered on top by the vault (which owns the keyed fingerprint and the
//! database).
//!
//! Detection combines three signals:
//! 1. Provider key patterns declared in the manifests (high/medium).
//! 2. Assignments to well-known secret environment-variable names (medium).
//! 3. Generic high-entropy tokens in a secret-like assignment (low), tuned to
//!    keep false positives down.

use crate::model::mask_value;
use crate::providers::{self, Confidence};
use crate::secret::SecretString;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::OnceLock;

/// A single detected potential secret. Serializes without the raw value.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Detection rule name (e.g. `openai-project-key`, `env-var:STRIPE_SECRET_KEY`,
    /// `high-entropy`).
    pub rule: String,
    /// Best-guess provider id, when the rule identifies one.
    pub provider: Option<String>,
    pub confidence: Confidence,
    /// File path label (repository-relative where possible).
    pub file: String,
    /// 1-based line number, or 0 when unavailable.
    pub line: usize,
    /// Redacted preview safe to display and log.
    pub redacted: String,
    /// Why this was flagged.
    pub reason: String,
    /// Recommended next step.
    pub recommended: String,
    /// Stable key for suppression (no secret material).
    pub suppression_key: String,
    /// Whether this finding matches a credential already in the vault. Set by
    /// the vault layer.
    pub vault_match: Option<VaultMatch>,
    /// The raw detected value, kept for vault fingerprinting. Never
    /// serialized; redacts in Debug.
    #[serde(skip)]
    pub secret: SecretString,
}

/// A finding that matches a credential stored in the vault.
#[derive(Debug, Clone, Serialize)]
pub struct VaultMatch {
    pub credential_id: String,
    pub credential_name: String,
    pub project_id: String,
    pub project_name: String,
    /// Other projects that also hold a credential with this value.
    pub other_projects: Vec<String>,
}

/// Options controlling a scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Run generic entropy detection (disabled for lockfiles etc.).
    pub entropy: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { entropy: true }
    }
}

struct CompiledPattern {
    provider: String,
    rule: String,
    regex: Regex,
    confidence: Confidence,
}

fn compiled_patterns() -> &'static [CompiledPattern] {
    static PATTERNS: OnceLock<Vec<CompiledPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let mut out = Vec::new();
        for manifest in providers::manifests() {
            for pattern in &manifest.detection {
                if let Ok(regex) = Regex::new(&pattern.regex) {
                    out.push(CompiledPattern {
                        provider: manifest.id.clone(),
                        rule: pattern.name.clone(),
                        regex,
                        confidence: pattern.confidence,
                    });
                }
            }
        }
        out
    })
}

/// Secret-bearing env-var names → provider id, built from the manifests.
fn env_var_index() -> &'static [(String, String)] {
    static INDEX: OnceLock<Vec<(String, String)>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut out = Vec::new();
        for manifest in providers::manifests() {
            for var in &manifest.env_vars {
                out.push((var.clone(), manifest.id.clone()));
            }
        }
        out
    })
}

/// Placeholder values that should never be treated as real secrets.
/// Public so `.env` governance can exclude placeholders from import.
pub fn is_placeholder_value(value: &str) -> bool {
    let v = value.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    if v.len() < 8 {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    const NEEDLES: [&str; 12] = [
        "your",
        "example",
        "placeholder",
        "changeme",
        "change-me",
        "xxxx",
        "todo",
        "dummy",
        "sample",
        "redacted",
        "notreal",
        "fixme",
    ];
    if NEEDLES.iter().any(|n| lower.contains(n)) {
        return true;
    }
    // Angle-bracket / mustache / template placeholders: <token>, ${TOKEN},
    // {{TOKEN}}, {TOKEN}, %TOKEN%.
    if v.starts_with('<') || v.starts_with("${") || v.starts_with("{{") {
        return true;
    }
    if (v.starts_with('{') && v.ends_with('}')) || (v.starts_with('%') && v.ends_with('%')) {
        return true;
    }
    // A single repeated character (e.g. xxxxxxxx, ********).
    if v.chars().collect::<HashSet<_>>().len() <= 2 {
        return true;
    }
    false
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Recognizable non-secret prefixes (publishable keys) that must never be
/// treated as secrets by the generic heuristics.
fn is_publishable_value(value: &str) -> bool {
    const PUBLISHABLE_PREFIXES: [&str; 5] =
        ["pk_live_", "pk_test_", "pk-", "pub_", "sb_publishable_"];
    PUBLISHABLE_PREFIXES.iter().any(|p| value.starts_with(p))
}

/// True when a value is a plausible secret *token* rather than a code
/// expression: only the characters real keys/tokens use, no code punctuation
/// (parens, colons, quotes, spaces). This is the main entropy false-positive
/// filter — it rejects things like `SecretString::from("...")`.
fn is_token_like(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-+/=.~".contains(c))
}

/// True for the secret-like left-hand side of an assignment.
fn is_secret_var_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const NEEDLES: [&str; 11] = [
        "key",
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "apikey",
        "auth",
        "credential",
        "private",
        "access",
    ];
    NEEDLES.iter().any(|needle| n.contains(needle))
}

/// Split `NAME = value` / `NAME: value` (env, YAML, TOML-ish). Returns
/// (name, value) with surrounding quotes/whitespace trimmed from the value.
fn split_assignment(line: &str) -> Option<(&str, String)> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }
    // Prefer '=' (env/TOML), then ':' (YAML/JSON).
    let idx = trimmed.find('=').or_else(|| trimmed.find(':'))?;
    let (name_raw, rest) = trimmed.split_at(idx);
    let name = name_raw
        .trim()
        .trim_start_matches(|c: char| c == '-' || c.is_whitespace())
        .trim_matches(|c: char| c == '"' || c == '\'')
        .trim();
    let value = rest[1..]
        .trim()
        .trim_end_matches([',', ';'])
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_string();
    if name.is_empty() || value.is_empty() {
        return None;
    }
    Some((name, value))
}

fn suppression_key(rule: &str, file: &str, value: &str) -> String {
    // A one-way BLAKE3 hash of rule + file + the full value. Hashing the whole
    // value (not the lossy masked preview) means two distinct secrets never
    // collide, so a scan never silently drops a second real secret and a
    // suppression never hides a different value. The hash is not the secret
    // (it never contains the literal), and it is line-independent so a
    // suppression survives the secret moving within a file.
    let material = format!("{rule}|{file}|{value}");
    hex::encode(blake3::hash(material.as_bytes()).as_bytes())
}

fn provider_pattern_finding(
    rule: &str,
    provider: &str,
    confidence: Confidence,
    file: &str,
    line: usize,
    matched: &str,
) -> Finding {
    let redacted = mask_value(matched);
    Finding {
        rule: rule.to_string(),
        provider: Some(provider.to_string()),
        confidence,
        file: file.to_string(),
        line,
        redacted: redacted.clone(),
        reason: format!("matches the {provider} key pattern '{rule}'"),
        recommended:
            "confirm it is a real credential; if committed, rotate it at the provider and remove it"
                .to_string(),
        suppression_key: suppression_key(rule, file, matched),
        vault_match: None,
        secret: SecretString::from(matched),
    }
}

/// Scan a block of text. `file` is the label used in findings.
pub fn scan_text(content: &str, file: &str, options: &ScanOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        // Skip absurdly long lines (minified assets); they explode entropy
        // scanning and are rarely hand-written secrets.
        if line.len() > 2000 {
            continue;
        }

        // 1. Provider key patterns. Collect every match, then keep only the
        // highest-confidence pattern per overlapping span so a specific rule
        // (e.g. anthropic-api-key) wins over a broad one (sk-ant- generic).
        let mut matches: Vec<(usize, usize, &CompiledPattern)> = Vec::new();
        for pattern in compiled_patterns() {
            for m in pattern.regex.find_iter(line) {
                matches.push((m.start(), m.end(), pattern));
            }
        }
        matches.sort_by(|a, b| {
            b.2.confidence
                .cmp(&a.2.confidence)
                .then((b.1 - b.0).cmp(&(a.1 - a.0)))
        });
        let mut accepted: Vec<(usize, usize)> = Vec::new();
        for (start, end, pattern) in matches {
            if accepted.iter().any(|&(s, e)| start < e && s < end) {
                continue; // overlaps an already-accepted, preferred match
            }
            accepted.push((start, end));
            let finding = provider_pattern_finding(
                &pattern.rule,
                &pattern.provider,
                pattern.confidence,
                file,
                line_no,
                &line[start..end],
            );
            if seen.insert(finding.suppression_key.clone()) {
                findings.push(finding);
            }
        }

        // 2/3. Assignment-based detection.
        if let Some((name, value)) = split_assignment(line) {
            if is_placeholder_value(&value) || is_publishable_value(&value) {
                continue;
            }
            // Already caught by a provider pattern on this line? Skip.
            if compiled_patterns().iter().any(|p| p.regex.is_match(&value)) {
                continue;
            }

            // 2. Known secret env-var name.
            if let Some((_, provider)) = env_var_index()
                .iter()
                .find(|(var, _)| var.eq_ignore_ascii_case(name))
            {
                let redacted = mask_value(&value);
                let finding = Finding {
                    rule: format!("env-var:{name}"),
                    provider: Some(provider.clone()),
                    confidence: Confidence::Medium,
                    file: file.to_string(),
                    line: line_no,
                    redacted: redacted.clone(),
                    reason: format!(
                        "'{name}' is a known {provider} secret variable and has a non-placeholder value"
                    ),
                    recommended: "verify and, if real, move it out of source control".to_string(),
                    suppression_key: suppression_key(&format!("env-var:{name}"), file, &value),
                    vault_match: None,
                    secret: SecretString::from(value.as_str()),
                };
                if seen.insert(finding.suppression_key.clone()) {
                    findings.push(finding);
                }
                continue;
            }

            // 3. Generic high-entropy value in a secret-like assignment.
            // Threshold 3.5 catches hex-encoded secrets (max entropy 4.0)
            // while the secret-like-name gate and length keep noise down.
            if options.entropy
                && is_secret_var_name(name)
                && value.len() >= 20
                && is_token_like(&value)
                && shannon_entropy(&value) >= 3.5
            {
                let redacted = mask_value(&value);
                let entropy = shannon_entropy(&value);
                let finding = Finding {
                    rule: "high-entropy".to_string(),
                    provider: None,
                    confidence: Confidence::Low,
                    file: file.to_string(),
                    line: line_no,
                    redacted: redacted.clone(),
                    reason: format!(
                        "'{name}' looks secret-like and holds a high-entropy value ({entropy:.1} bits/char)"
                    ),
                    recommended: "review manually; suppress with a reason if it is not a secret"
                        .to_string(),
                    suppression_key: suppression_key("high-entropy", file, &value),
                    vault_match: None,
                    secret: SecretString::from(value.as_str()),
                };
                if seen.insert(finding.suppression_key.clone()) {
                    findings.push(finding);
                }
            }
        }
    }
    findings
}

/// Whether a file name/extension should skip entropy scanning (lockfiles,
/// checksums — full of high-entropy hashes that are not secrets).
pub fn skip_entropy_for(file: &str) -> bool {
    let name = file
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(file)
        .to_ascii_lowercase();
    const LOCKFILES: [&str; 9] = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "cargo.lock",
        "poetry.lock",
        "go.sum",
        "composer.lock",
        "gemfile.lock",
        "flake.lock",
    ];
    LOCKFILES.contains(&name.as_str())
}

/// Whether a path looks like a binary/asset we should not scan at all.
pub fn is_probably_binary(file: &str) -> bool {
    let name = file
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(file)
        .to_ascii_lowercase();
    const BINARY_EXT: [&str; 22] = [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".mp4",
        ".mp3", ".woff", ".woff2", ".ttf", ".eot", ".class", ".jar", ".wasm", ".so", ".dylib",
        ".dll",
    ];
    BINARY_EXT.iter().any(|ext| name.ends_with(ext))
}

/// Content with a NUL byte is treated as binary.
pub fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8000).any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENAI_FAKE: &str = "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000";
    const ANTHROPIC_FAKE: &str =
        "sk-ant-api03-FAKE00000000000000000000000000000000000000000000000000000000000000000000000000000000AA";
    const GITHUB_FAKE: &str = "ghp_FAKE0000000000000000000000000000000000";
    const STRIPE_FAKE: &str = "sk_live_FAKE0000000000000000000000000000";

    #[test]
    fn detects_provider_key_patterns() {
        let content = format!(
            "OPENAI_API_KEY={OPENAI_FAKE}\nANTHROPIC_API_KEY={ANTHROPIC_FAKE}\ntoken = {GITHUB_FAKE}\nstripe: {STRIPE_FAKE}\n"
        );
        let findings = scan_text(&content, ".env", &ScanOptions::default());
        let providers: HashSet<_> = findings.iter().filter_map(|f| f.provider.clone()).collect();
        assert!(providers.contains("openai"));
        assert!(providers.contains("anthropic"));
        assert!(providers.contains("github"));
        assert!(providers.contains("stripe"));
        for f in &findings {
            assert_eq!(f.confidence, Confidence::High);
        }
    }

    #[test]
    fn findings_never_serialize_the_secret() {
        let findings = scan_text(
            &format!("OPENAI_API_KEY={OPENAI_FAKE}"),
            ".env",
            &ScanOptions::default(),
        );
        let json = serde_json::to_string(&findings).unwrap();
        assert!(
            !json.contains(OPENAI_FAKE),
            "serialized finding leaked the secret"
        );
        assert!(json.contains(&mask_value(OPENAI_FAKE)));
        // The raw value is still available in-process for fingerprinting.
        assert_eq!(findings[0].secret.expose(), OPENAI_FAKE);
    }

    #[test]
    fn detects_known_env_var_assignments() {
        let content = "SUPABASE_SERVICE_ROLE_KEY=an-entirely-madeup-nonpattern-value-1234567890";
        let findings = scan_text(content, ".env", &ScanOptions::default());
        assert!(findings
            .iter()
            .any(|f| f.rule.starts_with("env-var:SUPABASE_SERVICE_ROLE_KEY")));
    }

    #[test]
    fn ignores_placeholders() {
        for placeholder in [
            "OPENAI_API_KEY=your-key-here",
            "OPENAI_API_KEY=<YOUR_KEY>",
            "OPENAI_API_KEY=changeme",
            "OPENAI_API_KEY=xxxxxxxxxxxx",
            "TOKEN=${GITHUB_TOKEN}",
            "SECRET=",
        ] {
            let findings = scan_text(placeholder, ".env", &ScanOptions::default());
            assert!(findings.is_empty(), "flagged placeholder: {placeholder}");
        }
    }

    #[test]
    fn non_secret_env_vars_are_not_flagged() {
        // These were pruned from the manifests precisely to avoid false
        // positives on non-secret configuration.
        for line in [
            "OPENAI_ORG_ID=org-abcdef123456",
            "SUPABASE_URL=https://abcdefgh.supabase.co",
            "STRIPE_PUBLISHABLE_KEY=pk_live_abcdefghijklmnop",
        ] {
            let findings = scan_text(line, ".env", &ScanOptions::default());
            assert!(
                findings.is_empty(),
                "false positive on non-secret var: {line}"
            );
        }
    }

    #[test]
    fn entropy_detection_needs_a_secret_like_name() {
        // High-entropy value but a boring name → not flagged by entropy.
        let boring = "commit_hash=9f8e7d6c5b4a39281706fedcba98765432100abc";
        assert!(scan_text(boring, "notes.txt", &ScanOptions::default()).is_empty());
        // Same-shaped value under a secret-like name → flagged (low).
        let secretish = "API_SECRET=9f8e7d6c5b4a39281706fedcba98765432100abc";
        let findings = scan_text(secretish, "notes.txt", &ScanOptions::default());
        assert!(findings.iter().any(|f| f.rule == "high-entropy"));
        assert!(findings.iter().all(|f| f.confidence <= Confidence::Medium));
    }

    #[test]
    fn code_expressions_are_not_flagged_as_entropy_secrets() {
        // Rust/other source lines with a secret-ish word in scope but a code
        // expression as the "value" must not be flagged (the value is not a
        // token). These are exactly the dogfooding false positives.
        for line in [
            "        SecretString::from(\"test-backup-password\")",
            "    let key: SecretString = load_secret();",
            "        let token = compute_secret(&some, &args);",
            "TOKEN={OPENAI_FAKE}",
        ] {
            let findings = scan_text(line, "src/lib.rs", &ScanOptions::default());
            assert!(findings.is_empty(), "false positive on code: {line}");
        }
    }

    #[test]
    fn low_entropy_values_are_not_flagged() {
        let low = "PASSWORD=aaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(scan_text(low, ".env", &ScanOptions::default()).is_empty());
    }

    #[test]
    fn entropy_can_be_disabled() {
        let secretish = "API_SECRET=9f8e7d6c5b4a39281706fedcba98765432100abc";
        let findings = scan_text(secretish, "x", &ScanOptions { entropy: false });
        assert!(findings.is_empty());
    }

    #[test]
    fn line_numbers_are_reported() {
        let content = format!("line one\nline two\nOPENAI_API_KEY={OPENAI_FAKE}\n");
        let findings = scan_text(&content, ".env", &ScanOptions::default());
        assert_eq!(findings[0].line, 3);
    }

    #[test]
    fn two_distinct_same_provider_secrets_are_both_reported() {
        // Regression: dedup must key on the full value, not the lossy preview,
        // so two distinct GitHub PATs sharing their last two characters are
        // both reported rather than the second being silently dropped.
        let a = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZZ";
        let b = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBZZ";
        assert_eq!(
            mask_value(a),
            mask_value(b),
            "preconditions: same masked preview"
        );
        let content = format!("TOKEN_A={a}\nTOKEN_B={b}\n");
        let findings = scan_text(&content, ".env", &ScanOptions::default());
        assert_eq!(findings.len(), 2, "both distinct secrets must be reported");
        assert_ne!(findings[0].suppression_key, findings[1].suppression_key);
    }

    #[test]
    fn suppression_key_has_no_secret() {
        let findings = scan_text(
            &format!("OPENAI_API_KEY={OPENAI_FAKE}"),
            ".env",
            &ScanOptions::default(),
        );
        assert!(!findings[0].suppression_key.contains(OPENAI_FAKE));
        assert_eq!(findings[0].suppression_key.len(), 64);
    }

    #[test]
    fn entropy_helpers() {
        assert!(shannon_entropy("aaaaaaaa") < 1.0);
        assert!(shannon_entropy("A1b2C3d4E5f6G7h8") > 3.0);
        assert!(skip_entropy_for("path/to/package-lock.json"));
        assert!(!skip_entropy_for(".env"));
        assert!(is_probably_binary("logo.png"));
        assert!(looks_binary(b"abc\0def"));
    }
}
