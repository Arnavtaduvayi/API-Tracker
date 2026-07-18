//! Local Git pre-commit hook management.
//!
//! Installs a small shell hook into `.git/hooks/pre-commit` that runs
//! `api-tracker scan --staged --hook` before each commit. The hook is
//! marked with sentinel lines so we can recognize, update, and cleanly
//! remove exactly our block:
//! - if no hook exists, we write a standalone hook;
//! - if a foreign hook exists, we refuse to clobber it and tell the user how
//!   to chain ours (we never silently overwrite unrelated work);
//! - removal restores the prior state where practical.
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

fn hook_path(repo: &Path) -> PathBuf {
    repo.join(".git").join("hooks").join("pre-commit")
}

/// Current state of the pre-commit hook.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookState {
    /// No pre-commit hook file exists.
    Absent,
    /// Our managed hook is installed.
    Installed,
    /// A foreign (non-API-Tracker) hook exists.
    Foreign,
    /// A foreign hook exists but contains our chained block.
    ChainedIntoForeign,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HookStatus {
    pub repo: String,
    pub hook_path: String,
    pub state: HookState,
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

pub fn status(repo: &Path) -> Result<HookStatus> {
    let root = require_git_dir(repo)?;
    let path = hook_path(&root);
    let state = if !path.exists() {
        HookState::Absent
    } else {
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let has_ours = content.contains(SENTINEL);
        let managed_only = content.trim_start().starts_with("#!")
            && content.lines().filter(|l| !l.trim().is_empty()).count() > 0
            && is_managed_only(&content);
        if has_ours && managed_only {
            HookState::Installed
        } else if has_ours {
            HookState::ChainedIntoForeign
        } else {
            HookState::Foreign
        }
    };
    Ok(HookStatus {
        repo: root.display().to_string(),
        hook_path: path.display().to_string(),
        state,
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

/// Install the hook. Refuses to overwrite a foreign hook unless `force`.
/// Returns the resulting state.
pub fn install(repo: &Path, force: bool) -> Result<HookState> {
    let root = require_git_dir(repo)?;
    let path = hook_path(&root);
    std::fs::create_dir_all(path.parent().expect("hook path has a parent"))?;

    if path.exists() {
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if existing.contains(SENTINEL) {
            // Refresh our block in place (idempotent).
            let refreshed = replace_our_block(&existing);
            std::fs::write(&path, refreshed)?;
            make_executable(&path)?;
            return status(repo).map(|s| s.state);
        }
        if !force {
            return Err(CoreError::InvalidInput(format!(
                "a pre-commit hook already exists at {}. Re-run with --force to append the \
                 API Tracker block to it (your existing hook is preserved).",
                path.display()
            )));
        }
        // Append our block to the existing hook, preserving it.
        let mut appended = existing;
        if !appended.ends_with('\n') {
            appended.push('\n');
        }
        appended.push('\n');
        appended.push_str(&hook_body());
        std::fs::write(&path, appended)?;
        make_executable(&path)?;
        return status(repo).map(|s| s.state);
    }

    let standalone = format!("#!/bin/sh\n{}", hook_body());
    std::fs::write(&path, standalone)?;
    make_executable(&path)?;
    Ok(HookState::Installed)
}

fn replace_our_block(content: &str) -> String {
    let (Some(s), Some(e)) = (content.find(SENTINEL), content.find(SENTINEL_END)) else {
        return content.to_string();
    };
    let end = e + SENTINEL_END.len();
    let mut out = String::new();
    out.push_str(&content[..s]);
    out.push_str(hook_body().trim_end());
    out.push_str(&content[end..]);
    out
}

/// Remove our hook block. If ours was the only content, delete the file;
/// otherwise strip just our block and keep the foreign hook.
pub fn remove(repo: &Path) -> Result<HookState> {
    let root = require_git_dir(repo)?;
    let path = hook_path(&root);
    if !path.exists() {
        return Ok(HookState::Absent);
    }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    if !content.contains(SENTINEL) {
        return Err(CoreError::InvalidInput(
            "the pre-commit hook is not managed by API Tracker; leaving it untouched".into(),
        ));
    }
    if is_managed_only(&content) {
        std::fs::remove_file(&path)?;
        return Ok(HookState::Absent);
    }
    // Strip our block (and any lone shebang we may have shared), keep the rest.
    // If the end sentinel is missing (a hand-edited/corrupted hook), treat
    // everything from the start sentinel to end-of-file as ours rather than
    // panicking.
    let s = content
        .find(SENTINEL)
        .expect("start sentinel present (checked)");
    let e = content
        .find(SENTINEL_END)
        .map(|i| i + SENTINEL_END.len())
        .unwrap_or(content.len());
    let mut out = String::new();
    out.push_str(content[..s].trim_end());
    out.push('\n');
    out.push_str(content[e..].trim_start());
    if !out.ends_with('\n') {
        out.push('\n');
    }
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
        let content = std::fs::read_to_string(hook_path(dir.path())).unwrap();
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
        let path = hook_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "#!/bin/sh\necho existing-hook\n").unwrap();

        // Without force we refuse.
        assert!(install(dir.path(), false).is_err());

        // With force we append and preserve the original.
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
        let path = hook_path(dir.path());
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
        let path = hook_path(dir.path());
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
