//! `.env` governance: discovery, classification, `.env.example` generation,
//! atomic writes, and export bookkeeping.
//!
//! Everything here is local and non-executing. Vault-coupled operations
//! (import, drift against stored credentials, reauthenticated export) live in
//! `vault.rs` and call into this module. No function here ever logs, prints,
//! or serializes a secret value.

use crate::envfile::{EnvDocument, EnvProblem};
use crate::error::{CoreError, Result};
use crate::model::{mask_value, Environment};
use crate::secret::SecretString;
use rusqlite::{params, Connection, Row};
use serde::Serialize;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// How a discovered file participates in governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvFileClass {
    /// A real environment file that may hold secrets.
    Values,
    /// A committed template (`.env.example`, `.env.sample`, `.env.template`,
    /// `.env.dist`): names only by convention, never imported.
    Template,
}

/// Git's view of a discovered file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitStatus {
    /// Committed on the current branch (worst case for a values file).
    Tracked,
    /// Matched by .gitignore.
    Ignored,
    /// Present but neither tracked nor ignored — one `git add` from leaking.
    Untracked,
    /// The directory is not a Git repository.
    NotInRepo,
    /// Inside a repository whose index or ignore rules could not be read
    /// within Tethra's bounds. Never guessed in either direction.
    Unknown,
}

/// Whether a file appears in Git history.
///
/// Answering this requires walking the object database, which the
/// non-executing reader deliberately does not do (ADR 0023). Discovery
/// therefore reports [`GitHistory::NotChecked`] unless the caller asked
/// for the hardened probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHistory {
    /// The path appears in at least one commit reachable from any ref.
    Present,
    /// It does not.
    Absent,
    /// Not asked. The UI must not render this as "no".
    NotChecked,
}

/// Whether discovery may run the hardened `git` probe for history.
///
/// [`HistoryProbe::Skip`] — the default for every automatic path
/// (folder selection, provider detection, planning, apply, undo,
/// diagnostics) — spawns nothing at all, so no repository-controlled Git
/// configuration can execute (ZFT-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryProbe {
    /// Never spawn a process.
    Skip,
    /// Ask `git` under [`crate::gitrepo`]'s argument and environment
    /// hardening. Only for commands the user explicitly invoked against a
    /// folder they chose for that purpose.
    HardenedGit,
}

/// A discovered environment file.
#[derive(Debug, Clone, Serialize)]
pub struct EnvFileInfo {
    /// Absolute path.
    pub path: String,
    /// Path relative to the searched root.
    pub rel_path: String,
    pub class: EnvFileClass,
    /// Environment inferred from the file name, if any.
    pub environment: Option<Environment>,
    pub git_status: GitStatus,
    /// Whether the file (at this path) appears in Git history — deleting
    /// it from the working tree does not remove past commits.
    pub git_history: GitHistory,
    pub entry_count: usize,
    pub problems: Vec<EnvProblem>,
    /// The file was larger than the per-file byte cap, so `entry_count`
    /// and `problems` were not computed. Its bytes were never read.
    pub oversized: bool,
}

impl EnvFileInfo {
    /// True only when history was checked AND the path is present. Callers
    /// that need to distinguish "no" from "not asked" must read
    /// [`Self::git_history`] directly.
    pub fn in_git_history(&self) -> bool {
        matches!(self.git_history, GitHistory::Present)
    }
}

const TEMPLATE_SUFFIXES: [&str; 4] = ["example", "sample", "template", "dist"];
const SKIP_DIRS: [&str; 6] = [".git", "node_modules", "target", "dist", "build", ".venv"];
const MAX_DISCOVERY_DEPTH: usize = 6;

/// Bounds one discovery pass must respect. Depth alone is not enough: a
/// folder can hold unbounded files, unbounded bytes, and take unbounded
/// time (ZFT-003, ZFT-028).
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryLimits {
    pub max_depth: usize,
    /// Candidate `.env*` files inspected.
    pub max_files: usize,
    /// Directories descended into.
    pub max_dirs: usize,
    /// Bytes read from any single file. Checked from the directory entry's
    /// metadata BEFORE the file is opened.
    pub max_file_bytes: u64,
    /// Bytes read across the whole pass.
    pub max_total_bytes: u64,
    /// Wall-clock budget for the whole pass.
    pub max_duration: std::time::Duration,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        DiscoveryLimits {
            max_depth: MAX_DISCOVERY_DEPTH,
            max_files: 2_000,
            max_dirs: 20_000,
            max_file_bytes: 262_144,
            max_total_bytes: 64 * 1024 * 1024,
            max_duration: std::time::Duration::from_secs(20),
        }
    }
}

/// Why a discovery pass stopped early. Always reported — a truncated scan
/// is never presented as a complete one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryTruncation {
    FileBudget,
    DirectoryBudget,
    ByteBudget,
    TimeBudget,
}

impl DiscoveryTruncation {
    pub fn describe(self) -> &'static str {
        match self {
            DiscoveryTruncation::FileBudget => {
                "this folder holds more environment files than Tethra reads in one pass; \
                 the rest were not inspected"
            }
            DiscoveryTruncation::DirectoryBudget => {
                "this folder holds more directories than Tethra walks in one pass; \
                 the rest were not inspected"
            }
            DiscoveryTruncation::ByteBudget => {
                "the scan reached its total read budget; later files were not inspected"
            }
            DiscoveryTruncation::TimeBudget => {
                "the scan reached its time budget; later files were not inspected"
            }
        }
    }
}

/// Everything one discovery pass found, plus every bound it hit.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryReport {
    pub files: Vec<EnvFileInfo>,
    /// Files skipped because they exceeded [`DiscoveryLimits::max_file_bytes`].
    /// Their bytes were never read.
    pub skipped_oversized: Vec<String>,
    /// Set when the pass stopped before exhausting the folder.
    pub truncated: Option<DiscoveryTruncation>,
    /// Bounds hit inside the Git reader (index too large, ignore budget).
    pub git_warnings: Vec<String>,
}

/// Whether `file_name` is an environment file we govern, and its class.
pub fn classify_file_name(file_name: &str) -> Option<EnvFileClass> {
    if file_name == ".env" {
        return Some(EnvFileClass::Values);
    }
    let rest = file_name.strip_prefix(".env.")?;
    if rest.is_empty() {
        return None;
    }
    let last = rest.rsplit('.').next().unwrap_or(rest);
    if TEMPLATE_SUFFIXES.contains(&last) || TEMPLATE_SUFFIXES.contains(&rest) {
        Some(EnvFileClass::Template)
    } else {
        Some(EnvFileClass::Values)
    }
}

/// Environment inferred from a file name (`.env.production` → Production).
pub fn environment_from_name(file_name: &str) -> Option<Environment> {
    let rest = file_name.strip_prefix(".env.")?;
    for part in rest.split('.') {
        let inferred = match part {
            "development" | "dev" | "local" => Some(Environment::Development),
            "test" | "testing" | "ci" => Some(Environment::Test),
            "staging" | "stage" | "preview" => Some(Environment::Staging),
            "production" | "prod" | "live" => Some(Environment::Production),
            _ => None,
        };
        if inferred.is_some() {
            return inferred;
        }
    }
    None
}

/// History lookup for one path, under [`crate::gitrepo`]'s hardening.
///
/// Only reachable from [`HistoryProbe::HardenedGit`]. Every automatic
/// scan path uses [`HistoryProbe::Skip`] and never gets here.
fn history_probe(dir: &Path, rel: &str) -> GitHistory {
    match crate::gitrepo::run_git_probe(dir, &["log", "--oneline", "-n", "1", "--all", "--", rel]) {
        Ok(out) if out.success && !out.stdout.is_empty() => GitHistory::Present,
        Ok(out) if out.success => GitHistory::Absent,
        // A repository we cannot query is "not checked", never "no".
        _ => GitHistory::NotChecked,
    }
}

/// Discover environment files under `root`.
///
/// Bounded depth, common build directories skipped, symlinks never
/// followed, per-file and whole-pass byte caps, and **no subprocess**:
/// Git status comes from [`crate::gitsafe`]'s byte reader. Reads each
/// file to count entries and problems but never returns values.
pub fn discover(root: &Path) -> Result<Vec<EnvFileInfo>> {
    Ok(discover_bounded(root, DiscoveryLimits::default(), HistoryProbe::Skip)?.files)
}

/// [`discover`] with explicit bounds and an explicit history policy.
pub fn discover_bounded(
    root: &Path,
    limits: DiscoveryLimits,
    probe: HistoryProbe,
) -> Result<DiscoveryReport> {
    let root = root
        .canonicalize()
        .map_err(|e| CoreError::InvalidInput(format!("cannot access {}: {e}", root.display())))?;
    let started = std::time::Instant::now();

    // One repository open for the whole pass: an index parse and an ignore
    // load, instead of four process spawns per file (ZFT-001, ZFT-028).
    let repo = crate::gitsafe::RepoView::open(&root);
    let mut git_warnings: Vec<String> = repo
        .as_ref()
        .map(|r| r.limits().iter().map(|l| l.describe()).collect())
        .unwrap_or_default();
    // The scanned folder may sit below the work-tree root; ignore rules and
    // index paths are repo-relative, so carry that offset.
    let root_rel = repo
        .as_ref()
        .and_then(|r| r.repo_relative(&root))
        .unwrap_or_default();

    let mut found = Vec::new();
    let mut skipped_oversized = Vec::new();
    let mut truncated: Option<DiscoveryTruncation> = None;
    let mut dirs_visited = 0usize;
    let mut total_bytes = 0u64;
    let mut stack = vec![(root.clone(), 0usize)];

    'walk: while let Some((dir, depth)) = stack.pop() {
        if started.elapsed() > limits.max_duration {
            truncated = Some(DiscoveryTruncation::TimeBudget);
            break;
        }
        dirs_visited += 1;
        if dirs_visited > limits.max_dirs {
            truncated = Some(DiscoveryTruncation::DirectoryBudget);
            break;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        // Ignore rules are per-directory; load them once for this directory
        // rather than once per candidate file.
        let dir_rel_from_root = dir
            .strip_prefix(&root)
            .unwrap_or(Path::new(""))
            .to_string_lossy()
            .replace('\\', "/");
        let dir_rel_in_repo = join_rel(&root_rel, &dir_rel_from_root);
        let dir_view = repo.as_ref().map(|r| r.dir_view(&dir_rel_in_repo));

        for entry in entries.flatten() {
            // The per-directory check above cannot preempt a single
            // directory holding thousands of entries, each of which costs a
            // metadata call, a read and an ignore-rule evaluation. Without a
            // check here the 20-second budget was advisory for any wide
            // folder, so a slow per-entry step ran to completion however
            // long it took (RA-009).
            if started.elapsed() > limits.max_duration {
                truncated = Some(DiscoveryTruncation::TimeBudget);
                break 'walk;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                if depth < limits.max_depth && !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !file_type.is_file() {
                continue; // never follow symlinks out of the tree
            }
            let Some(class) = classify_file_name(&name) else {
                continue;
            };
            if found.len() + skipped_oversized.len() >= limits.max_files {
                truncated = Some(DiscoveryTruncation::FileBudget);
                break 'walk;
            }
            // Relative paths are displayed and stored — normalize to
            // forward slashes so behaviour is identical across platforms.
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");

            let git_status = match &dir_view {
                None => GitStatus::NotInRepo,
                Some(view) => match view.status_of_name(&name, false) {
                    crate::gitsafe::PathStatus::Tracked => GitStatus::Tracked,
                    crate::gitsafe::PathStatus::Ignored => GitStatus::Ignored,
                    crate::gitsafe::PathStatus::Untracked => GitStatus::Untracked,
                    crate::gitsafe::PathStatus::Unknown => GitStatus::Unknown,
                },
            };
            let git_history = match probe {
                HistoryProbe::Skip => GitHistory::NotChecked,
                HistoryProbe::HardenedGit => history_probe(&root, &rel),
            };

            // The size check happens BEFORE the file is opened: a 2 GB file
            // named `.env` must never enter memory (ZFT-003).
            let size = entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
            if size > limits.max_file_bytes {
                skipped_oversized.push(rel.clone());
                found.push(EnvFileInfo {
                    path: path.to_string_lossy().into_owned(),
                    rel_path: rel,
                    class,
                    environment: environment_from_name(&name),
                    git_status,
                    git_history,
                    entry_count: 0,
                    problems: Vec::new(),
                    oversized: true,
                });
                continue;
            }
            if total_bytes.saturating_add(size) > limits.max_total_bytes {
                truncated = Some(DiscoveryTruncation::ByteBudget);
                break 'walk;
            }
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            total_bytes = total_bytes.saturating_add(content.len() as u64);
            let doc = EnvDocument::parse(&content);
            found.push(EnvFileInfo {
                path: path.to_string_lossy().into_owned(),
                rel_path: rel,
                class,
                environment: environment_from_name(&name),
                git_status,
                git_history,
                entry_count: doc.entries().count(),
                problems: doc.problems(),
                oversized: false,
            });
        }
        if let Some(view) = &dir_view {
            for limit in view.limits() {
                let text = limit.describe();
                if !git_warnings.contains(&text) {
                    git_warnings.push(text);
                }
            }
        }
    }
    found.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    skipped_oversized.sort();
    Ok(DiscoveryReport {
        files: found,
        skipped_oversized,
        truncated,
        git_warnings,
    })
}

/// Join two forward-slash relative fragments, either of which may be empty.
fn join_rel(base: &str, rest: &str) -> String {
    match (base.is_empty(), rest.is_empty()) {
        (true, _) => rest.to_string(),
        (false, true) => base.to_string(),
        (false, false) => format!("{base}/{rest}"),
    }
}

/// One variable in a preview: everything displayable, nothing secret.
#[derive(Debug, Clone, Serialize)]
pub struct VarPreview {
    pub key: String,
    pub line: usize,
    pub masked: String,
    /// Provider suggested by the scanner (name or value pattern), if any.
    pub provider: Option<String>,
    /// The scanner considers the value a likely secret.
    pub looks_secret: bool,
    /// The value looks like a placeholder (never imported by default).
    pub is_placeholder: bool,
    /// Set by the vault layer: this exact value is already stored.
    pub vault_credential: Option<String>,
    /// Set by the vault layer: an injection mapping already covers this name.
    pub mapped_credential: Option<String>,
}

/// A detected mismatch between `.env` files, the vault, and mappings.
#[derive(Debug, Clone, Serialize)]
pub struct DriftFinding {
    pub kind: DriftKind,
    /// Repository-relative file path ('' when the finding is not about one
    /// specific file).
    pub file: String,
    pub key: String,
    pub credential: Option<String>,
    pub detail: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// A mapped variable's file value differs from the vault credential.
    ValueDiffersFromVault,
    /// A template lists a variable that nothing provides.
    MissingExpectedVariable,
    /// A likely secret in a file with no vault counterpart.
    UnmappedSecret,
    /// A mapping exists but no file carries the variable (normal under
    /// `tethra run`; informational).
    MappingNotInFiles,
    /// A production credential's value sits in a development/test file.
    ProductionValueInDevFile,
    /// One value is copied into several environment files.
    SameValueInMultipleFiles,
}

impl DriftKind {
    /// Severity used for display ordering; informational kinds last.
    pub fn severity(&self) -> &'static str {
        match self {
            DriftKind::ProductionValueInDevFile | DriftKind::UnmappedSecret => "high",
            DriftKind::ValueDiffersFromVault | DriftKind::SameValueInMultipleFiles => "medium",
            DriftKind::MissingExpectedVariable => "low",
            DriftKind::MappingNotInFiles => "info",
        }
    }
}

/// Generate or update a `.env.example` document from a values document:
/// names and comments only, never values. Existing example entries are
/// preserved verbatim; missing keys are appended with empty values.
/// Keys under a `tethra-gateway` marker comment are skipped — a gateway base
/// URL is machine-local wiring (port and link slug are specific to one
/// machine), not a variable collaborators should copy (TEST_PLAN §10).
pub fn generate_example(values: &EnvDocument, existing_example: Option<&EnvDocument>) -> String {
    let mut example = existing_example.cloned().unwrap_or_else(|| {
        EnvDocument::parse("# Environment variables for this project.\n# Copy to .env and fill in values, or use `tethra run`.\n")
    });
    let gateway_owned = values.keys_with_gateway_marker();
    for entry in values.entries() {
        if gateway_owned.contains(&entry.key) {
            continue;
        }
        if example.get(&entry.key).is_none() {
            example.set(&entry.key, SecretString::new(String::new()));
        }
    }
    example.render()
}

/// A unified-style diff of two small text files, with values masked on
/// changed lines that look like assignments carrying secrets. Safe to print.
pub fn render_diff(label: &str, old: &str, new: &str) -> String {
    render_diff_with_unmasked(label, old, new, &[])
}

/// [`render_diff`] with an allowlist of keys whose values print VERBATIM
/// **on added lines only**.
///
/// The gateway `.env` writer must show the lines it is ADDING unmasked (ADR
/// 0019 D9: the user is approving an exact base URL, and a masked loopback
/// URL would hide the very thing being consented to). Removed and context
/// lines are always masked, whatever their key: the allowlist says "I am
/// about to write this value", not "whatever was previously under this name
/// is safe to print". A prior value under an allowlisted key is arbitrary
/// user content — `--var OPENAI_API_KEY`, or a base URL with embedded
/// credentials — and printing it unmasked would leak a secret to the
/// terminal and its scrollback.
pub fn render_diff_with_unmasked(
    label: &str,
    old: &str,
    new: &str,
    unmasked_keys: &[&str],
) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut out = format!("--- {label} (current)\n+++ {label} (proposed)\n");
    let masked = |line: &str| -> String { mask_assignment(line) };
    let unmasked_if_allowed = |line: &str| -> String {
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().trim_start_matches("export ").trim();
            if unmasked_keys.contains(&key) {
                return line.to_string();
            }
        }
        mask_assignment(line)
    };
    // Simple LCS-free diff: show removed lines then added lines for each
    // hunk of consecutive difference. Fine for the small files involved.
    let common_prefix = old_lines
        .iter()
        .zip(new_lines.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let common_suffix = old_lines
        .iter()
        .rev()
        .zip(new_lines.iter().rev())
        .take_while(|(a, b)| a == b)
        .count()
        .min(old_lines.len().saturating_sub(common_prefix))
        .min(new_lines.len().saturating_sub(common_prefix));
    for line in &old_lines[..common_prefix] {
        out.push_str(&format!("  {}\n", masked(line)));
    }
    for line in &old_lines[common_prefix..old_lines.len() - common_suffix] {
        out.push_str(&format!("- {}\n", masked(line)));
    }
    for line in &new_lines[common_prefix..new_lines.len() - common_suffix] {
        out.push_str(&format!("+ {}\n", unmasked_if_allowed(line)));
    }
    for line in &old_lines[old_lines.len() - common_suffix..] {
        out.push_str(&format!("  {}\n", masked(line)));
    }
    out
}

/// Mask the value part of a `KEY=value` line when it plausibly holds a
/// secret; leave comments/blank lines/empty values untouched.
fn mask_assignment(line: &str) -> String {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return line.to_string();
    }
    let Some(eq) = line.find('=') else {
        // A non-comment line without '=' (malformed) may be a bare pasted
        // secret; mask it whole rather than risk printing it.
        return mask_value(trimmed);
    };
    let value = line[eq + 1..]
        .trim()
        .trim_matches(|c| c == '"' || c == '\'');
    if value.is_empty() {
        return line.to_string();
    }
    // The exemption here used to be `is_placeholder_value`, a SUBSTRING
    // test: a `DATABASE_URL` whose host merely contained the word
    // "example" was printed verbatim, credentials and all, to stdout and
    // across IPC (ZFT-017).
    //
    // The first replacement for it was worse. "Short AND not key-shaped"
    // is a DENYLIST wearing a length limit, and it let `DB_PASSWORD=Tr0ub4dor3`
    // and `SHORT_KEY=9f2c8a71e45b30d6` through — values the ORIGINAL code
    // masked. A rule that leaks more than the defect it replaces is not a
    // fix, and it was caught by an adversarial reviewer running the two
    // trees side by side, not by any test written for it.
    //
    // So: mask by DEFAULT, and exempt only values that are structurally
    // incapable of carrying a secret. That is an allowlist, and an
    // allowlist is the only shape that fails safe when someone invents a
    // new secret format.
    let name = line[..eq].trim();
    if name_suggests_a_credential(name) {
        // A variable NAMED for a secret is masked whatever its value looks
        // like. No allowlist entry can override this.
        return format!("{}={}", &line[..eq], mask_value(value));
    }
    if value_is_structurally_not_a_secret(value) {
        return line.to_string();
    }
    format!("{}={}", &line[..eq], mask_value(value))
}

/// Whether a variable NAME is one whose value must always be masked,
/// regardless of shape.
fn name_suggests_a_credential(name: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "CREDENTIAL",
        "PRIVATE",
        "AUTH",
        "SIGNING",
        "CERT",
        "SALT",
        "SESSION",
        "COOKIE",
    ];
    let upper = name.to_ascii_uppercase();
    upper.ends_with("_KEY") || NEEDLES.iter().any(|n| upper.contains(n))
}

/// Whether a value belongs to one of the few shapes that cannot be a
/// credential, and may therefore stay legible in a diff.
///
/// The diff exists so a user can see what is about to change, so masking
/// literally everything would damage the consent surface it serves —
/// `NODE_ENV=production` and `PORT=3000` have to stay readable. This is
/// the whole exemption, and it is deliberately tiny: an over-masked
/// configuration value costs a reader one glance at the file, while an
/// under-masked one prints a credential.
fn value_is_structurally_not_a_secret(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    // A number, with optional sign, decimal point or unit-ish suffix.
    if v.len() <= 12
        && v.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | '+' | '.'))
    {
        return true;
    }
    // A boolean or a common single-word setting. Compared WHOLE, never as
    // a substring — a substring test is what produced ZFT-017.
    const WORDS: &[&str] = &[
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "none",
        "null",
        "development",
        "dev",
        "production",
        "prod",
        "staging",
        "stage",
        "test",
        "testing",
        "local",
        "debug",
        "info",
        "warn",
        "error",
        "trace",
        "silent",
        "verbose",
    ];
    let lower = v.to_ascii_lowercase();
    if WORDS.contains(&lower.as_str()) {
        return true;
    }
    // A bare origin or base URL: scheme + host + optional port + a path of
    // ordinary path words. No userinfo, no query, no fragment, and no
    // segment that could be key material — all of which
    // `looks_like_key_material` already rejects.
    if (v.starts_with("https://") || v.starts_with("http://"))
        && !crate::scanner::looks_like_key_material(v)
    {
        let rest = v.split_once("://").map(|(_, r)| r).unwrap_or(v);
        let ordinary = rest
            .split(['/', ':'])
            .filter(|seg| !seg.is_empty())
            .all(|seg| {
                seg.len() <= 24
                    && seg
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            });
        if ordinary {
            return true;
        }
    }
    false
}

/// Create `path` fresh with owner-only permissions, failing if it already
/// exists (`create_new` closes the check-then-write race for exports that
/// must not clobber).
pub fn write_new(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CoreError::InvalidInput(format!(
                "{} already exists; pass the overwrite flag to replace it",
                path.display()
            ))
        } else {
            CoreError::Io(e)
        }
    })?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Write `content` to `path` atomically with owner-only permissions: write
/// to a same-directory temp file (0600), sync, then rename over the target.
pub fn atomic_write(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| CoreError::InvalidInput("path has no parent directory".into()))?;
    let tmp = dir.join(format!(
        ".{}.api-tracker-tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "env".to_string()),
        Uuid::new_v4()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    let result: Result<()> = (|| {
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// BLAKE3 hash of file content, used to detect out-of-band modification of
/// an exported file before cleanup. Not secret material.
pub fn content_hash(content: &str) -> String {
    blake3::hash(content.as_bytes()).to_hex().to_string()
}

/// A recorded export (values never stored).
#[derive(Debug, Clone, Serialize)]
pub struct EnvExport {
    pub id: String,
    pub project_id: String,
    pub path: String,
    pub var_names: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub cleaned_at: Option<String>,
}

pub fn record_export(
    conn: &Connection,
    project_id: &str,
    path: &Path,
    var_names: &[String],
    content_hash: &str,
    expires_at: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO env_exports (id, project_id, path, var_names, content_hash, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            project_id,
            path.to_string_lossy(),
            var_names.join(","),
            content_hash,
            crate::clock::now_rfc3339(),
            expires_at,
        ],
    )?;
    Ok(id)
}

pub fn list_exports(conn: &Connection, include_cleaned: bool) -> Result<Vec<EnvExport>> {
    let sql = if include_cleaned {
        "SELECT id, project_id, path, var_names, created_at, expires_at, cleaned_at
         FROM env_exports ORDER BY created_at DESC"
    } else {
        "SELECT id, project_id, path, var_names, created_at, expires_at, cleaned_at
         FROM env_exports WHERE cleaned_at IS NULL ORDER BY created_at DESC"
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |r: &Row<'_>| {
        Ok(EnvExport {
            id: r.get(0)?,
            project_id: r.get(1)?,
            path: r.get(2)?,
            var_names: r.get(3)?,
            created_at: r.get(4)?,
            expires_at: r.get(5)?,
            cleaned_at: r.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// The result of attempting to clean one export.
#[derive(Debug, Clone, Serialize)]
pub struct CleanupResult {
    pub export_id: String,
    pub path: String,
    pub outcome: CleanupOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupOutcome {
    Removed,
    AlreadyGone,
    /// The file changed since export; refused to delete without `force`.
    ModifiedSinceExport,
    NotYetExpired,
}

/// Remove expired temporary exports (or all exports with `all=true`). A file
/// whose content changed since export is only removed with `force`.
pub fn cleanup_exports(
    conn: &Connection,
    all: bool,
    force: bool,
    now: &str,
) -> Result<Vec<CleanupResult>> {
    let exports = list_exports(conn, false)?;
    let mut results = Vec::new();
    for export in exports {
        let expired = export
            .expires_at
            .as_deref()
            .map(|e| e <= now)
            .unwrap_or(false);
        if !all && !expired {
            if export.expires_at.is_some() {
                results.push(CleanupResult {
                    export_id: export.id.clone(),
                    path: export.path.clone(),
                    outcome: CleanupOutcome::NotYetExpired,
                });
            }
            continue;
        }
        let path = PathBuf::from(&export.path);
        let outcome = if !path.exists() {
            CleanupOutcome::AlreadyGone
        } else {
            let current = std::fs::read_to_string(&path).unwrap_or_default();
            let stored: String = conn.query_row(
                "SELECT content_hash FROM env_exports WHERE id = ?1",
                [&export.id],
                |r| r.get(0),
            )?;
            if content_hash(&current) != stored && !force {
                CleanupOutcome::ModifiedSinceExport
            } else {
                std::fs::remove_file(&path)?;
                CleanupOutcome::Removed
            }
        };
        if matches!(
            outcome,
            CleanupOutcome::Removed | CleanupOutcome::AlreadyGone
        ) {
            conn.execute(
                "UPDATE env_exports SET cleaned_at = ?1 WHERE id = ?2",
                params![now, export.id],
            )?;
        }
        results.push(CleanupResult {
            export_id: export.id,
            path: export.path,
            outcome,
        });
    }
    sweep_orphaned_temp_files(conn);
    Ok(results)
}

/// Remove `.NAME.api-tracker-tmp-UUID` files orphaned by a crash between
/// `atomic_write`'s write and rename. The sweep is tightly bounded: only
/// the parent directories of RECORDED exports are examined (never a general
/// filesystem walk), only files matching the temp-name pattern are touched,
/// and only when they are over an hour old so an in-flight export in
/// another process is never raced. Best-effort by design.
fn sweep_orphaned_temp_files(conn: &Connection) {
    let dirs: Vec<String> = conn
        .prepare("SELECT DISTINCT path FROM env_exports")
        .and_then(|mut stmt| {
            stmt.query_map([], |r| r.get::<_, String>(0))
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    let mut parents: Vec<PathBuf> = dirs
        .iter()
        .filter_map(|p| PathBuf::from(p).parent().map(|d| d.to_path_buf()))
        .collect();
    parents.sort();
    parents.dedup();
    let hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    for dir in parents {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_temp = name.starts_with('.') && name.contains(".api-tracker-tmp-");
            if !is_temp {
                continue;
            }
            let old_enough = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(|m| m < hour_ago)
                .unwrap_or(false);
            if old_enough {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Whether `path` inside `repo_dir` is protected by .gitignore (or the
/// directory is not a repository, in which case Git cannot leak it).
///
/// Non-executing: the answer comes from [`crate::gitsafe`], so asking it
/// about a hostile repository cannot run that repository's code.
pub fn gitignore_protects(repo_dir: &Path, rel: &str) -> GitStatus {
    let Ok(canonical) = repo_dir.canonicalize() else {
        return GitStatus::NotInRepo;
    };
    let Some(view) = crate::gitsafe::RepoView::open(&canonical) else {
        return GitStatus::NotInRepo;
    };
    match view.status_of(&canonical.join(rel)) {
        crate::gitsafe::PathStatus::Tracked => GitStatus::Tracked,
        crate::gitsafe::PathStatus::Ignored => GitStatus::Ignored,
        crate::gitsafe::PathStatus::Untracked => GitStatus::Untracked,
        crate::gitsafe::PathStatus::Unknown => GitStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    /// The allowlist means "show what I am about to WRITE", never "whatever
    /// was previously under this name is safe to print". `--var` accepts any
    /// variable name, so a prior value under an allowlisted key can be an API
    /// key — and a declared base-URL variable can hold a URL with userinfo.
    #[test]
    fn unmasked_keys_never_unmask_the_removed_side_of_the_diff() {
        let old = "OPENAI_BASE_URL=https://user:SUPERSECRET-CANARY@api.openai.com/v1\n";
        let new = "OPENAI_BASE_URL=http://127.0.0.1:49723/openai\n";
        let diff = render_diff_with_unmasked("/p/.env", old, new, &["OPENAI_BASE_URL"]);
        assert!(
            !diff.contains("SUPERSECRET-CANARY"),
            "a prior value must never print verbatim: {diff}"
        );
        assert!(
            diff.contains("+ OPENAI_BASE_URL=http://127.0.0.1:49723/openai"),
            "the value being WRITTEN must print verbatim so consent is exact: {diff}"
        );
    }

    /// Context (unchanged) lines are masked too — an allowlisted key that is
    /// not being changed is not being consented to.
    #[test]
    fn unmasked_keys_do_not_unmask_context_lines() {
        let old = "NO_PROXY=CANARY-NOT-A-PROXY-LIST\nA=1\n";
        let new = "NO_PROXY=CANARY-NOT-A-PROXY-LIST\nA=2\n";
        let diff = render_diff_with_unmasked("/p/.env", old, new, &["NO_PROXY"]);
        assert!(
            !diff.contains("CANARY-NOT-A-PROXY-LIST"),
            "unchanged lines stay masked: {diff}"
        );
    }

    use super::*;
    use std::process::Command;

    #[test]
    fn classifies_env_file_names() {
        assert_eq!(classify_file_name(".env"), Some(EnvFileClass::Values));
        assert_eq!(classify_file_name(".env.local"), Some(EnvFileClass::Values));
        assert_eq!(
            classify_file_name(".env.production"),
            Some(EnvFileClass::Values)
        );
        assert_eq!(
            classify_file_name(".env.development.local"),
            Some(EnvFileClass::Values)
        );
        assert_eq!(
            classify_file_name(".env.example"),
            Some(EnvFileClass::Template)
        );
        assert_eq!(
            classify_file_name(".env.sample"),
            Some(EnvFileClass::Template)
        );
        assert_eq!(classify_file_name("config.json"), None);
        assert_eq!(classify_file_name("env"), None);
    }

    #[test]
    fn infers_environments_from_names() {
        assert_eq!(
            environment_from_name(".env.production"),
            Some(Environment::Production)
        );
        assert_eq!(
            environment_from_name(".env.development.local"),
            Some(Environment::Development)
        );
        assert_eq!(environment_from_name(".env.test"), Some(Environment::Test));
        assert_eq!(
            environment_from_name(".env.staging"),
            Some(Environment::Staging)
        );
        assert_eq!(environment_from_name(".env"), None);
    }

    #[test]
    fn discovers_env_files_and_skips_build_dirs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        std::fs::write(dir.path().join(".env.example"), "A=\n").unwrap();
        let sub = dir.path().join("web");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(".env.production"), "B=2\nB=3\nbroken\n").unwrap();
        let nm = dir.path().join("node_modules").join("pkg");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join(".env"), "IGNORED=1\n").unwrap();

        let found = discover(dir.path()).unwrap();
        let rels: Vec<&str> = found.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(rels, vec![".env", ".env.example", "web/.env.production"]);
        assert_eq!(found[0].class, EnvFileClass::Values);
        assert_eq!(found[0].git_status, GitStatus::NotInRepo);
        assert_eq!(found[1].class, EnvFileClass::Template);
        let prod = &found[2];
        assert_eq!(prod.environment, Some(Environment::Production));
        assert_eq!(prod.entry_count, 2);
        assert_eq!(prod.problems.len(), 2); // duplicate + malformed
    }

    #[test]
    fn git_status_reports_tracked_ignored_untracked_and_history() {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "t@example.invalid"]);
        run(&["config", "user.name", "t"]);
        std::fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        std::fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        std::fs::write(dir.path().join(".env.staging"), "B=1\n").unwrap();
        std::fs::write(dir.path().join(".env.local"), "C=1\n").unwrap();
        run(&["add", ".gitignore", ".env.staging"]);
        run(&["commit", "-q", "-m", "init"]);
        // .env.local was committed once, then deleted from tracking.
        run(&["add", "-f", ".env.local"]);
        run(&["commit", "-q", "-m", "oops"]);
        run(&["rm", "-q", "--cached", ".env.local"]);
        run(&["commit", "-q", "-m", "untrack"]);

        // The default (automatic) path is NON-EXECUTING: status is read
        // from `.git/index` and the ignore files, and history is not asked
        // for at all — reported as NotChecked, never as "no".
        let found = discover(dir.path()).unwrap();
        let by_name = |n: &str| found.iter().find(|f| f.rel_path == n).unwrap();
        assert_eq!(by_name(".env").git_status, GitStatus::Ignored);
        assert_eq!(by_name(".env.staging").git_status, GitStatus::Tracked);
        assert_eq!(by_name(".env.local").git_status, GitStatus::Untracked);
        for name in [".env", ".env.staging", ".env.local"] {
            assert_eq!(
                by_name(name).git_history,
                GitHistory::NotChecked,
                "{name}: the automatic path must not claim a history answer it never asked for"
            );
            assert!(
                !by_name(name).in_git_history(),
                "{name}: NotChecked must never read as Present"
            );
        }

        // The explicitly requested, hardened probe answers for real.
        let probed = discover_bounded(
            dir.path(),
            DiscoveryLimits::default(),
            HistoryProbe::HardenedGit,
        )
        .unwrap()
        .files;
        let probed_by = |n: &str| probed.iter().find(|f| f.rel_path == n).unwrap();
        assert_eq!(probed_by(".env").git_history, GitHistory::Absent);
        assert_eq!(probed_by(".env.staging").git_history, GitHistory::Present);
        assert_eq!(
            probed_by(".env.local").git_history,
            GitHistory::Present,
            "deleting from tracking must not hide history"
        );
    }

    /// The time budget used to be checked once per DIRECTORY, so a folder
    /// holding many files ran its whole entry loop however long that took —
    /// which is what made a single slow `is_ignored` call unpreemptable
    /// (RA-009). A budget that only fires between directories is not a
    /// budget for a wide folder.
    #[test]
    fn the_time_budget_is_enforced_inside_a_single_directory() {
        let dir = tempfile::tempdir().unwrap();
        // One directory, no subdirectories: the ONLY places the walk can
        // stop are the per-directory check (before any file is inspected)
        // and the per-entry check. A non-empty result therefore proves the
        // per-entry check is what stopped it.
        let mut body = String::new();
        while body.len() < 64 * 1024 {
            body.push_str("SOME_KEY_NAME_HERE=some-value-goes-here-0123456789\n");
        }
        let total = 200;
        for i in 0..total {
            std::fs::write(dir.path().join(format!(".env.f{i:04}")), &body).unwrap();
        }
        // Big enough that no OTHER bound can be the one that fires.
        let generous = DiscoveryLimits {
            max_files: 100_000,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_duration: std::time::Duration::from_secs(3600),
            ..DiscoveryLimits::default()
        };

        // Negative control first: with time to spare the same fixture is
        // read completely and reports no truncation at all.
        let full = discover_bounded(dir.path(), generous, HistoryProbe::Skip).unwrap();
        assert_eq!(full.files.len(), total);
        assert_eq!(full.truncated, None);

        let budgeted = DiscoveryLimits {
            max_duration: std::time::Duration::from_millis(25),
            ..generous
        };
        let report = discover_bounded(dir.path(), budgeted, HistoryProbe::Skip).unwrap();
        assert_eq!(
            report.truncated,
            Some(DiscoveryTruncation::TimeBudget),
            "reading {total} files must not overrun the budget silently"
        );
        assert!(
            report.files.len() < total,
            "the pass must have stopped early"
        );
        assert!(
            !report.files.is_empty(),
            "the walk reached the entry loop and stopped inside it, so some files must have \
             been inspected; an empty result would mean only the per-directory check ran"
        );
    }

    #[test]
    fn example_generation_never_includes_values_and_preserves_existing() {
        let values = EnvDocument::parse(
            "# db\nDB_URL=postgres://u:supersecret@x/db\nAPI_KEY=sk-test-FAKE-1234567890abcdef\n",
        );
        let existing = EnvDocument::parse("API_KEY= # get one at example.com\n");
        let out = generate_example(&values, Some(&existing));
        assert!(!out.contains("supersecret"));
        assert!(!out.contains("sk-test-FAKE"));
        assert!(out.contains("API_KEY= # get one at example.com"));
        assert!(out.contains("DB_URL="));

        let fresh = generate_example(&values, None);
        assert!(!fresh.contains("supersecret"));
        assert!(fresh.contains("DB_URL=\n") || fresh.contains("DB_URL="));
    }

    #[test]
    fn example_generation_skips_gateway_marked_lines() {
        // A gateway base URL is machine-local wiring (port + link slug are
        // specific to one machine); .env.example must not propagate it
        // (TEST_PLAN §10).
        let values = EnvDocument::parse(
            "API_KEY=sk-test-FAKE-1234567890abcdef\n\
             # tethra-gateway route: openai (project: app) — remove this line if 127.0.0.1 refuses connections\n\
             OPENAI_BASE_URL=http://127.0.0.1:49723/p/0123abcd/openai/v1\n",
        );
        let out = generate_example(&values, None);
        assert!(out.contains("API_KEY="));
        assert!(!out.contains("OPENAI_BASE_URL"), "{out}");
        assert!(!out.contains("tethra-gateway"), "{out}");

        // ...but a base URL the USER wrote (no marker) still propagates.
        let user_values = EnvDocument::parse("OPENAI_BASE_URL=https://corp.example/v1\n");
        let out = generate_example(&user_values, None);
        assert!(out.contains("OPENAI_BASE_URL="));
    }

    #[test]
    fn diff_masks_secret_values() {
        let old = "A=1\nSECRET_KEY=sk-test-FAKE-1234567890abcdefgh\n";
        let new = "A=1\n";
        let diff = render_diff(".env", old, new);
        assert!(!diff.contains("1234567890abcdefgh"));
        assert!(diff.contains("- SECRET_KEY=sk-t…gh"));
        assert!(diff.contains("  A=1"));
    }

    #[test]
    fn diff_masks_bare_lines_without_assignments() {
        // A hand-pasted bare token (no KEY=) is a malformed line; the diff
        // must mask it rather than print it.
        let old = "GOOD=1\nsk-test-FAKE-bare-token-1234567890abcdef\n";
        let diff = render_diff(".env", old, "GOOD=1\n");
        assert!(!diff.contains("bare-token-1234567890abcdef"), "{diff}");
    }

    #[test]
    fn write_new_refuses_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        write_new(&path, "A=1\n").unwrap();
        let err = write_new(&path, "A=2\n").unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=1\n");
    }

    #[test]
    fn atomic_write_sets_restrictive_permissions_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        atomic_write(&path, "A=1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=1\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "exported file must be owner-only");
        }
        atomic_write(&path, "A=2\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=2\n");
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("api-tracker-tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
