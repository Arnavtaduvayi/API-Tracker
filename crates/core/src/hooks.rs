//! Local Git pre-commit hook management.
//!
//! Installs a small shell hook that runs `api-tracker scan --staged --hook`
//! before each commit — into the directory GIT WILL ACTUALLY USE: the
//! effective `core.hooksPath` (local, global, or system scope; the same
//! merged value git resolves) or the default `.git/hooks`. The hook is
//! marked with sentinel lines so we can recognize, update, and cleanly
//! remove exactly our block:
//! - if no hook exists, we write a standalone hook;
//! - if a foreign hook exists, we refuse to clobber it and tell the user how
//!   to chain ours (we never silently overwrite unrelated work);
//! - when chaining, OUR block runs FIRST, so a pre-existing hook's `exit`
//!   or `exec` cannot skip the scan (GScan-02) — the foreign hook then runs
//!   unchanged when the scan passes;
//! - a non-text (binary) or unreadable existing hook is refused as
//!   unsupported rather than corrupted;
//! - removal restores the prior state where practical;
//! - status reports whether git will genuinely execute our scan (active),
//!   and reports a stale install shadowed by `core.hooksPath` as
//!   overridden instead of installed (GScan-01).
//!
//! The hook never prints secret values; it delegates to the scanner, which
//! redacts everything.

use crate::error::{CoreError, Result};
use crate::gitrepo;
use std::path::{Path, PathBuf};

const SENTINEL: &str = "# >>> api-tracker pre-commit hook >>>";
const SENTINEL_END: &str = "# <<< api-tracker pre-commit hook <<<";

fn hook_body() -> String {
    format!(
        "{SENTINEL}\n\
# Managed by API Tracker. Blocks commits containing high-confidence secrets.\n\
# Remove with: api-tracker hooks remove <path>\n\
if command -v api-tracker >/dev/null 2>&1; then\n\
  api-tracker scan --staged --hook \"$(git rev-parse --show-toplevel)\" || exit 1\n\
else\n\
  echo 'api-tracker not found on PATH; skipping secret pre-commit scan' >&2\n\
fi\n\
{SENTINEL_END}\n"
    )
}

/// The default hook location when no `core.hooksPath` is configured.
fn default_hook_path(root: &Path) -> PathBuf {
    root.join(".git").join("hooks").join("pre-commit")
}

/// Where git will actually look for the pre-commit hook: the effective
/// `core.hooksPath` (relative values resolve against the worktree top,
/// matching githooks(5) for pre-commit) or the default `.git/hooks`.
/// Returns (hook file path, raw override value when set).
fn effective_hook_path(root: &Path) -> Result<(PathBuf, Option<String>)> {
    match gitrepo::config_get(root, "core.hooksPath")? {
        Some(raw) if !raw.is_empty() => {
            let dir = PathBuf::from(&raw);
            let dir = if dir.is_absolute() {
                dir
            } else {
                root.join(dir)
            };
            Ok((dir.join("pre-commit"), Some(raw)))
        }
        _ => Ok((default_hook_path(root), None)),
    }
}

/// Current state of the pre-commit hook.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookState {
    /// No pre-commit hook file exists where git looks.
    Absent,
    /// Our managed hook is installed where git looks.
    Installed,
    /// A foreign (non-API-Tracker) hook exists where git looks.
    Foreign,
    /// The hook where git looks contains our chained block plus foreign
    /// content; ours runs first.
    ChainedIntoForeign,
    /// Our block exists only in a location git will NOT use (a stale
    /// install shadowed by `core.hooksPath`): protection is NOT active.
    Overridden,
    /// The hook where git looks is unreadable or not a text script; API
    /// Tracker cannot manage or truthfully assess it.
    Unsupported,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HookStatus {
    pub repo: String,
    /// The hook file GIT WILL USE (honouring `core.hooksPath`).
    pub hook_path: String,
    /// Raw `core.hooksPath` value when configured (any scope).
    pub hooks_path_override: Option<String>,
    pub state: HookState,
    /// True only when git will genuinely execute our scan on commit: our
    /// block is present in the file git uses and that file is executable.
    pub active: bool,
    /// Honest human-readable explanation of the state.
    pub detail: String,
}

fn require_git_dir(repo: &Path) -> Result<PathBuf> {
    let root = gitrepo::repo_root(repo)?;
    let git_dir = root.join(".git");
    // In a worktree or submodule, `.git` is a regular FILE (containing a
    // `gitdir:` pointer), so we require an actual directory here — `.exists()`
    // would be true for the file and let us write hooks to the wrong place.
    if !git_dir.is_dir() {
        return Err(CoreError::InvalidInput(format!(
            "{} has no .git directory (worktrees/submodules are not supported yet)",
            root.display()
        )));
    }
    Ok(root)
}

/// Read a hook file as text. `Ok(None)` = file absent; `Err` = the file
/// exists but is unreadable or not UTF-8 text (unsupported: we can neither
/// manage it nor truthfully assess what it does).
fn read_hook_text(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CoreError::InvalidInput(format!(
            "cannot read existing hook {}: {e}",
            path.display()
        ))),
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => Ok(Some(text)),
            Err(_) => Err(CoreError::InvalidInput(format!(
                "existing hook {} is not a text script (binary?); API Tracker \
                 cannot chain into it. Remove or relocate it, then re-run.",
                path.display()
            ))),
        },
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    // Windows: git for Windows executes hooks via sh regardless of an
    // execute bit; there is no equivalent inertness signal to check.
    true
}

pub fn status(repo: &Path) -> Result<HookStatus> {
    let root = require_git_dir(repo)?;
    let (path, hooks_path_override) = effective_hook_path(&root)?;
    let default_path = default_hook_path(&root);

    // A stale install in the default location that git no longer consults.
    let stale_ours_in_default = hooks_path_override.is_some()
        && path != default_path
        && matches!(read_hook_text(&default_path), Ok(Some(c)) if c.contains(SENTINEL));

    let (state, active, detail) = match read_hook_text(&path) {
        Err(_) => (
            HookState::Unsupported,
            false,
            format!(
                "the hook file git would run ({}) is unreadable or not a text \
                 script; API Tracker cannot assess or chain into it",
                path.display()
            ),
        ),
        Ok(None) => {
            if stale_ours_in_default {
                (
                    HookState::Overridden,
                    false,
                    format!(
                        "core.hooksPath = {:?} makes git ignore the API Tracker hook \
                         installed at {}; protection is NOT active. Re-run install to \
                         move it where git looks.",
                        hooks_path_override.as_deref().unwrap_or_default(),
                        default_path.display()
                    ),
                )
            } else {
                (
                    HookState::Absent,
                    false,
                    "no pre-commit hook is installed".to_string(),
                )
            }
        }
        Ok(Some(content)) => {
            let has_ours = content.contains(SENTINEL);
            let executable = is_executable(&path);
            if has_ours {
                let managed_only = content.trim_start().starts_with("#!")
                    && content.lines().filter(|l| !l.trim().is_empty()).count() > 0
                    && is_managed_only(&content);
                let state = if managed_only {
                    HookState::Installed
                } else {
                    HookState::ChainedIntoForeign
                };
                let detail = if !executable {
                    format!(
                        "the hook file {} is not executable, so git will NOT run it; \
                         protection is inactive until it is made executable",
                        path.display()
                    )
                } else if state == HookState::ChainedIntoForeign {
                    "the API Tracker scan runs first, then the pre-existing hook".to_string()
                } else {
                    "the API Tracker scan runs on every commit".to_string()
                };
                (state, executable, detail)
            } else if stale_ours_in_default {
                (
                    HookState::Overridden,
                    false,
                    format!(
                        "core.hooksPath = {:?} points git at a different hook; the API \
                         Tracker hook at {} never runs. Protection is NOT active.",
                        hooks_path_override.as_deref().unwrap_or_default(),
                        default_path.display()
                    ),
                )
            } else {
                (
                    HookState::Foreign,
                    false,
                    "a non-API-Tracker pre-commit hook exists; install with force to \
                     chain the scan in front of it"
                        .to_string(),
                )
            }
        }
    };
    Ok(HookStatus {
        repo: root.display().to_string(),
        hook_path: path.display().to_string(),
        hooks_path_override,
        state,
        active,
        detail,
    })
}

/// True when the file is (shebang + our block) and nothing else meaningful.
fn is_managed_only(content: &str) -> bool {
    let without_shebang: String = content
        .lines()
        .filter(|l| !l.trim_start().starts_with("#!"))
        .collect::<Vec<_>>()
        .join("\n");
    let start = without_shebang.find(SENTINEL);
    let end = without_shebang.find(SENTINEL_END);
    match (start, end) {
        (Some(s), Some(e)) => {
            let before = without_shebang[..s].trim();
            let after = without_shebang[e + SENTINEL_END.len()..].trim();
            before.is_empty() && after.is_empty()
        }
        _ => false,
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Content of `content` with our sentinel block removed (start sentinel to
/// end sentinel inclusive; to end-of-file when the end sentinel was
/// hand-deleted). Returns the input unchanged when no block is present.
fn strip_our_block(content: &str) -> String {
    let Some(s) = content.find(SENTINEL) else {
        return content.to_string();
    };
    let e = content
        .find(SENTINEL_END)
        .map(|i| i + SENTINEL_END.len())
        .unwrap_or(content.len());
    let mut out = String::new();
    out.push_str(content[..s].trim_end());
    out.push('\n');
    out.push_str(content[e..].trim_start());
    // A stripped file that is only a shebang/whitespace reduces to nothing
    // meaningful; keep it textually tidy.
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Chain our block IN FRONT of foreign hook content so a pre-existing
/// `exit` or `exec` cannot skip the scan (GScan-02). The foreign hook's own
/// shebang stays on line 1 (its interpreter still runs the whole file; our
/// block is plain POSIX sh, valid under sh/bash/dash/zsh). When the foreign
/// content has no shebang we add `#!/bin/sh`, matching how git falls back
/// to sh for hooks without one.
fn chain_ours_first(foreign: &str) -> String {
    let ours = hook_body();
    let trimmed = foreign.trim_start();
    if trimmed.starts_with("#!") {
        let mut lines = foreign.splitn(2, '\n');
        let shebang = lines.next().unwrap_or_default();
        let rest = lines.next().unwrap_or_default();
        format!("{shebang}\n{ours}{rest}")
    } else {
        format!("#!/bin/sh\n{ours}{foreign}")
    }
}

/// Install the hook into the directory git actually uses (honouring
/// `core.hooksPath`). Refuses to overwrite a foreign hook unless `force`;
/// with `force`, our scan is chained IN FRONT of the existing hook, which
/// is otherwise preserved. Refuses binary/unreadable hooks and existing
/// hooks git currently ignores (not executable) instead of silently
/// changing their semantics. Re-running is idempotent, and a stale install
/// in the default location shadowed by `core.hooksPath` is cleaned up and
/// relocated. Returns the resulting state.
pub fn install(repo: &Path, force: bool) -> Result<HookState> {
    let root = require_git_dir(repo)?;
    let (path, hooks_path_override) = effective_hook_path(&root)?;
    let default_path = default_hook_path(&root);
    std::fs::create_dir_all(path.parent().expect("hook path has a parent"))?;

    // Relocation: our block in `.git/hooks/pre-commit` while git looks
    // elsewhere protects nothing (GScan-01). Strip it from the stale
    // location; the install below places it where git looks.
    if hooks_path_override.is_some() && path != default_path {
        if let Ok(Some(stale)) = read_hook_text(&default_path) {
            if stale.contains(SENTINEL) {
                let remaining = strip_our_block(&stale);
                if remaining.trim().is_empty() || is_shebang_only(&remaining) {
                    std::fs::remove_file(&default_path)?;
                } else {
                    std::fs::write(&default_path, remaining)?;
                }
            }
        }
    }

    match read_hook_text(&path)? {
        Some(existing) if existing.contains(SENTINEL) => {
            // Idempotent refresh — and canonicalization: strip our block
            // wherever it sits (older builds appended it), then re-chain it
            // in front so ordering is always scan-first.
            let foreign = strip_our_block(&existing);
            let rebuilt = if foreign.trim().is_empty() || is_shebang_only(&foreign) {
                format!("#!/bin/sh\n{}", hook_body())
            } else {
                chain_ours_first(&foreign)
            };
            std::fs::write(&path, rebuilt)?;
            make_executable(&path)?;
            status(repo).map(|s| s.state)
        }
        Some(existing) => {
            if !force {
                return Err(CoreError::InvalidInput(format!(
                    "a pre-commit hook already exists at {}. Re-run with --force to chain \
                     the API Tracker scan IN FRONT of it (your existing hook is preserved \
                     and still runs when the scan passes).",
                    path.display()
                )));
            }
            if !is_executable(&path) {
                return Err(CoreError::InvalidInput(format!(
                    "the existing hook {} is not executable, so git currently ignores it. \
                     Chaining into it would silently activate it. Make it executable (or \
                     remove it), then re-run.",
                    path.display()
                )));
            }
            std::fs::write(&path, chain_ours_first(&existing))?;
            make_executable(&path)?;
            status(repo).map(|s| s.state)
        }
        None => {
            let standalone = format!("#!/bin/sh\n{}", hook_body());
            std::fs::write(&path, standalone)?;
            make_executable(&path)?;
            status(repo).map(|s| s.state)
        }
    }
}

/// True when the content is nothing but a shebang line and whitespace.
fn is_shebang_only(content: &str) -> bool {
    let mut lines = content.lines().filter(|l| !l.trim().is_empty());
    match (lines.next(), lines.next()) {
        (None, _) => true,
        (Some(first), None) => first.trim_start().starts_with("#!"),
        _ => false,
    }
}

/// Remove our hook block from the location git uses AND from a stale
/// default-location install. If ours was the only content, delete the
/// file; otherwise strip just our block and keep the foreign hook.
pub fn remove(repo: &Path) -> Result<HookState> {
    let root = require_git_dir(repo)?;
    let (path, hooks_path_override) = effective_hook_path(&root)?;
    let default_path = default_hook_path(&root);

    // Clean a stale default-location install first (best-effort honesty:
    // "remove" must not leave a hidden copy behind).
    let mut removed_any = false;
    if hooks_path_override.is_some() && path != default_path {
        if let Ok(Some(stale)) = read_hook_text(&default_path) {
            if stale.contains(SENTINEL) {
                let remaining = strip_our_block(&stale);
                if remaining.trim().is_empty() || is_shebang_only(&remaining) {
                    std::fs::remove_file(&default_path)?;
                } else {
                    std::fs::write(&default_path, remaining)?;
                }
                removed_any = true;
            }
        }
    }

    let content = match read_hook_text(&path)? {
        None => return Ok(HookState::Absent),
        Some(content) => content,
    };
    if !content.contains(SENTINEL) {
        if removed_any {
            // We removed our stale copy; the effective hook was never ours.
            return Ok(if content.trim().is_empty() {
                HookState::Absent
            } else {
                HookState::Foreign
            });
        }
        return Err(CoreError::InvalidInput(
            "the pre-commit hook is not managed by API Tracker; leaving it untouched".into(),
        ));
    }
    if is_managed_only(&content) {
        std::fs::remove_file(&path)?;
        return Ok(HookState::Absent);
    }
    let out = strip_our_block(&content);
    std::fs::write(&path, &out)?;
    Ok(HookState::Foreign)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .arg("init")
            .output()
            .unwrap();
        dir
    }

    #[test]
    fn install_status_remove_cycle() {
        if !gitrepo::git_available() {
            return;
        }
        let dir = init_repo();
        assert_eq!(status(dir.path()).unwrap().state, HookState::Absent);

        assert_eq!(install(dir.path(), false).unwrap(), HookState::Installed);
        assert_eq!(status(dir.path()).unwrap().state, HookState::Installed);
        let content = std::fs::read_to_string(default_hook_path(dir.path())).unwrap();
        assert!(content.contains("api-tracker scan --staged --hook"));

        // Re-install is idempotent.
        assert_eq!(install(dir.path(), false).unwrap(), HookState::Installed);

        assert_eq!(remove(dir.path()).unwrap(), HookState::Absent);
        assert_eq!(status(dir.path()).unwrap().state, HookState::Absent);
    }

    #[test]
    fn refuses_to_clobber_foreign_hook_then_chains_with_force() {
        if !gitrepo::git_available() {
            return;
        }
        let dir = init_repo();
        let path = default_hook_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "#!/bin/sh\necho existing-hook\n").unwrap();
        // A live foreign hook is executable (a non-executable one is
        // refused as inert — covered in tests/gscan_hooks.rs).
        make_executable(&path).unwrap();

        // Without force we refuse.
        assert!(install(dir.path(), false).is_err());

        // With force we chain OUR block FIRST and preserve the original.
        assert_eq!(
            install(dir.path(), true).unwrap(),
            HookState::ChainedIntoForeign
        );
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("echo existing-hook"),
            "foreign hook preserved"
        );
        assert!(content.contains(SENTINEL));
        assert!(
            content.find(SENTINEL).unwrap() < content.find("echo existing-hook").unwrap(),
            "the scan block must run before the foreign hook (GScan-02)"
        );

        // Removal keeps the foreign hook.
        assert_eq!(remove(dir.path()).unwrap(), HookState::Foreign);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("echo existing-hook"));
        assert!(!content.contains(SENTINEL));
    }

    #[test]
    fn remove_refuses_unmanaged_hook() {
        if !gitrepo::git_available() {
            return;
        }
        let dir = init_repo();
        let path = default_hook_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "#!/bin/sh\necho not-ours\n").unwrap();
        assert!(remove(dir.path()).is_err());
    }

    #[test]
    fn remove_does_not_panic_on_truncated_block() {
        // A hand-edited hook with the start sentinel but no end sentinel must
        // not panic; the block is stripped to end-of-file.
        if !gitrepo::git_available() {
            return;
        }
        let dir = init_repo();
        let path = default_hook_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!("#!/bin/sh\n{SENTINEL}\napi-tracker scan ...\n"),
        )
        .unwrap();
        // Must return Ok, not panic.
        let state = remove(dir.path()).unwrap();
        assert!(matches!(state, HookState::Absent | HookState::Foreign));
    }

    #[test]
    fn rejects_worktree_whose_git_is_a_file() {
        if !gitrepo::git_available() {
            return;
        }
        let dir = init_repo();
        // A commit is required before adding a worktree.
        std::fs::write(dir.path().join("f.txt"), "x").unwrap();
        for args in [
            vec!["add", "."],
            vec![
                "-c",
                "user.email=t@e.com",
                "-c",
                "user.name=T",
                "commit",
                "-m",
                "init",
            ],
        ] {
            Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(&args)
                .output()
                .unwrap();
        }
        let wt = dir.path().join("wt");
        let out = Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["worktree", "add", wt.to_str().unwrap()])
            .output()
            .unwrap();
        if !out.status.success() {
            return; // worktree unsupported in this environment; skip
        }
        // In the worktree, `.git` is a FILE — hook operations must error, not
        // write to the wrong place or panic.
        assert!(wt.join(".git").is_file());
        assert!(status(&wt).is_err());
        assert!(install(&wt, false).is_err());
    }
}
