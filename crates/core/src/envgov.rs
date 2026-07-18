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
use std::process::Command;
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
    /// The file (at this path) appears in Git history — deleting it from the
    /// working tree does not remove past commits.
    pub in_git_history: bool,
    pub entry_count: usize,
    pub problems: Vec<EnvProblem>,
}

const TEMPLATE_SUFFIXES: [&str; 4] = ["example", "sample", "template", "dist"];
const SKIP_DIRS: [&str; 6] = [".git", "node_modules", "target", "dist", "build", ".venv"];
const MAX_DISCOVERY_DEPTH: usize = 6;

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

fn git_output(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

fn git_status_of(dir: &Path, rel: &str) -> (GitStatus, bool) {
    let inside = git_output(dir, &["rev-parse", "--is-inside-work-tree"])
        .map(|s| s.trim() == "true")
        .unwrap_or(false);
    if !inside {
        return (GitStatus::NotInRepo, false);
    }
    let tracked = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["ls-files", "--error-unmatch", "--", rel])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let in_history = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["log", "--oneline", "-n", "1", "--all", "--", rel])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false);
    if tracked {
        return (GitStatus::Tracked, true);
    }
    let ignored = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["check-ignore", "-q", "--", rel])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ignored {
        (GitStatus::Ignored, in_history)
    } else {
        (GitStatus::Untracked, in_history)
    }
}

/// Discover environment files under `root` (bounded depth, common build
/// directories skipped). Reads each file to count entries and problems but
/// never returns values.
pub fn discover(root: &Path) -> Result<Vec<EnvFileInfo>> {
    let root = root
        .canonicalize()
        .map_err(|e| CoreError::InvalidInput(format!("cannot access {}: {e}", root.display())))?;
    let mut found = Vec::new();
    let mut stack = vec![(root.clone(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                if depth < MAX_DISCOVERY_DEPTH && !SKIP_DIRS.contains(&name.as_str()) {
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
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            let doc = EnvDocument::parse(&content);
            let (git_status, in_history) = git_status_of(&root, &rel);
            found.push(EnvFileInfo {
                path: path.to_string_lossy().into_owned(),
                rel_path: rel,
                class,
                environment: environment_from_name(&name),
                git_status,
                in_git_history: in_history,
                entry_count: doc.entries().count(),
                problems: doc.problems(),
            });
        }
    }
    found.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(found)
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
    /// `api-tracker run`; informational).
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
pub fn generate_example(values: &EnvDocument, existing_example: Option<&EnvDocument>) -> String {
    let mut example = existing_example.cloned().unwrap_or_else(|| {
        EnvDocument::parse("# Environment variables for this project.\n# Copy to .env and fill in values, or use `api-tracker run`.\n")
    });
    for entry in values.entries() {
        if example.get(&entry.key).is_none() {
            example.set(&entry.key, SecretString::new(String::new()));
        }
    }
    example.render()
}

/// A unified-style diff of two small text files, with values masked on
/// changed lines that look like assignments carrying secrets. Safe to print.
pub fn render_diff(label: &str, old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut out = format!("--- {label} (current)\n+++ {label} (proposed)\n");
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
        out.push_str(&format!("  {}\n", mask_assignment(line)));
    }
    for line in &old_lines[common_prefix..old_lines.len() - common_suffix] {
        out.push_str(&format!("- {}\n", mask_assignment(line)));
    }
    for line in &new_lines[common_prefix..new_lines.len() - common_suffix] {
        out.push_str(&format!("+ {}\n", mask_assignment(line)));
    }
    for line in &old_lines[old_lines.len() - common_suffix..] {
        out.push_str(&format!("  {}\n", mask_assignment(line)));
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
        return line.to_string();
    };
    let value = line[eq + 1..]
        .trim()
        .trim_matches(|c| c == '"' || c == '\'');
    if value.is_empty() || crate::scanner::is_placeholder_value(value) {
        return line.to_string();
    }
    format!("{}={}", &line[..eq], mask_value(value))
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
    Ok(results)
}

/// Whether `path` inside `repo_dir` is protected by .gitignore (or the
/// directory is not a repository, in which case Git cannot leak it).
pub fn gitignore_protects(repo_dir: &Path, rel: &str) -> GitStatus {
    git_status_of(repo_dir, rel).0
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let found = discover(dir.path()).unwrap();
        let by_name = |n: &str| found.iter().find(|f| f.rel_path == n).unwrap();
        assert_eq!(by_name(".env").git_status, GitStatus::Ignored);
        assert!(!by_name(".env").in_git_history);
        assert_eq!(by_name(".env.staging").git_status, GitStatus::Tracked);
        assert!(by_name(".env.staging").in_git_history);
        assert_eq!(by_name(".env.local").git_status, GitStatus::Untracked);
        assert!(
            by_name(".env.local").in_git_history,
            "deleting from tracking must not hide history"
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
    fn diff_masks_secret_values() {
        let old = "A=1\nSECRET_KEY=sk-test-FAKE-1234567890abcdefgh\n";
        let new = "A=1\n";
        let diff = render_diff(".env", old, new);
        assert!(!diff.contains("1234567890abcdefgh"));
        assert!(diff.contains("- SECRET_KEY=sk-t…gh"));
        assert!(diff.contains("  A=1"));
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
