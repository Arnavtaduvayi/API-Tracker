//! Local Git integration for the scanner.
//!
//! All operations shell out to the user's `git` binary and run entirely
//! locally — no source code, diffs, or findings ever leave the machine. We
//! avoid a heavy libgit2 dependency; the trade-off is that `git` must be on
//! PATH (checked via [`git_available`]).
//!
//! For staged and historical content we read blobs/diffs through git so the
//! scanner sees exactly what is committed, not just the working tree.

use crate::error::{CoreError, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A unit of text to scan, with a label for findings.
pub struct ScanUnit {
    pub label: String,
    pub content: String,
}

fn run_git(repo: &Path, args: &[&str]) -> Result<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CoreError::InvalidInput(
                    "git is not installed or not on PATH; repository scanning needs it".into(),
                )
            } else {
                CoreError::Io(e)
            }
        })
}

/// Whether `git` is usable.
pub fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The repository root containing `path`, or an error if it is not a repo.
pub fn repo_root(path: &Path) -> Result<PathBuf> {
    let out = run_git(path, &["rev-parse", "--show-toplevel"])?;
    if !out.status.success() {
        return Err(CoreError::InvalidInput(format!(
            "{} is not inside a Git repository",
            path.display()
        )));
    }
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(PathBuf::from(root))
}

/// Names of files staged for commit (added/copied/modified).
pub fn staged_files(repo: &Path) -> Result<Vec<String>> {
    let out = run_git(
        repo,
        &["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
    )?;
    if !out.status.success() {
        return Err(CoreError::InvalidInput(
            "could not list staged files (is this a Git repository?)".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect())
}

/// The staged content of a file (the version that would be committed).
/// Blobs above the scanner's working-tree size cap are skipped (returning
/// `None`) instead of being buffered whole — the same bound the
/// working-tree scan applies, so a multi-GB staged file cannot OOM the
/// pre-commit hook.
pub fn staged_blob(repo: &Path, path: &str) -> Result<Option<Vec<u8>>> {
    let size = run_git(repo, &["cat-file", "-s", &format!(":{path}")])?;
    if size.status.success() {
        if let Ok(bytes) = String::from_utf8_lossy(&size.stdout).trim().parse::<u64>() {
            if bytes > MAX_FILE_BYTES {
                return Ok(None);
            }
        }
    }
    let out = run_git(repo, &["show", &format!(":{path}")])?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(Some(out.stdout))
}

/// Scan units for everything currently staged.
pub fn staged_units(repo: &Path) -> Result<Vec<ScanUnit>> {
    let mut units = Vec::new();
    for path in staged_files(repo)? {
        if let Some(bytes) = staged_blob(repo, &path)? {
            if crate::scanner::looks_binary(&bytes) {
                continue;
            }
            units.push(ScanUnit {
                label: path.clone(),
                content: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
    }
    Ok(units)
}

/// Added lines across the last `n` commits (or all history when `n` is None),
/// as scan units labelled `commit <short>:<file>`.
/// The current HEAD commit hash of a repository.
pub fn head_commit(repo: &Path) -> Result<String> {
    let out = run_git(repo, &["rev-parse", "HEAD"])?;
    if !out.status.success() {
        return Err(CoreError::InvalidInput(
            "could not read the repository HEAD (no commits yet?)".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Added lines from the commits in `old..new` only (incremental scanning).
pub fn range_added_units(repo: &Path, old: &str, new: &str) -> Result<Vec<ScanUnit>> {
    // Both endpoints are commit hashes we recorded/resolved ourselves, but
    // require them to be plain hex so a tampered stored value (e.g.
    // `--output=…`) can never be parsed by git as an option, and pass
    // `--end-of-options` before the range for defense in depth.
    for endpoint in [old, new] {
        if endpoint.is_empty() || !endpoint.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CoreError::InvalidInput(
                "commit range endpoints must be hex commit ids".into(),
            ));
        }
    }
    let range = format!("{old}..{new}");
    let out = run_git(
        repo,
        &[
            "log",
            "-p",
            "--no-color",
            "-U0",
            "--no-merges",
            "--end-of-options",
            &range,
        ],
    )?;
    if !out.status.success() {
        return Err(CoreError::InvalidInput(
            "could not read the Git commit range (was history rewritten?)".into(),
        ));
    }
    Ok(parse_log_added_lines(&String::from_utf8_lossy(&out.stdout)))
}

pub fn history_added_units(repo: &Path, n: Option<usize>) -> Result<Vec<ScanUnit>> {
    let count = n.map(|c| format!("-n{c}"));
    let mut args: Vec<&str> = vec!["log", "-p", "--no-color", "-U0", "--no-merges"];
    if let Some(c) = &count {
        args.push(c);
    } else {
        args.push("--all");
    }
    let out = run_git(repo, &args)?;
    if !out.status.success() {
        return Err(CoreError::InvalidInput("could not read Git history".into()));
    }
    Ok(parse_log_added_lines(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `git log -p -U0` output into per-file scan units of added lines.
/// Grouping added lines per (commit,file) preserves line numbers from the
/// hunk headers so findings can point at the right place.
fn parse_log_added_lines(log: &str) -> Vec<ScanUnit> {
    let mut units: Vec<ScanUnit> = Vec::new();
    let mut commit = String::new();
    let mut file = String::new();
    let mut new_line_no = 0usize;
    let mut buffer: Vec<(usize, String)> = Vec::new();

    let flush =
        |units: &mut Vec<ScanUnit>, commit: &str, file: &str, buffer: &mut Vec<(usize, String)>| {
            if buffer.is_empty() || file.is_empty() {
                buffer.clear();
                return;
            }
            // Reconstruct a sparse text where each added line sits at its real
            // line number so scanner line numbers stay meaningful. A hunk
            // header carries the line NUMBER, which is decoupled from the
            // number of buffered lines: with `-U0` one changed line deep in a
            // huge file yields a large line number but a single entry. Cap the
            // reconstructed length so a crafted diff cannot amplify one line
            // into a multi-hundred-MB allocation; beyond the cap, real line
            // numbers no longer matter for scanning.
            const MAX_RECONSTRUCTED_LINES: usize = 200_000;
            let raw_max = buffer.iter().map(|(n, _)| *n).max().unwrap_or(0);
            if raw_max > MAX_RECONSTRUCTED_LINES {
                // Fall back to dense packing (line numbers become approximate)
                // rather than allocating a vector sized by the line number.
                let content = buffer
                    .iter()
                    .map(|(_, text)| text.clone())
                    .collect::<Vec<_>>()
                    .join("\n");
                units.push(ScanUnit {
                    label: format!("commit {}:{}", commit.get(..8).unwrap_or(commit), file),
                    content,
                });
                buffer.clear();
                return;
            }
            let max = raw_max;
            let mut lines = vec![String::new(); max];
            for (n, text) in buffer.iter() {
                if *n >= 1 && *n <= max {
                    lines[*n - 1] = text.clone();
                }
            }
            units.push(ScanUnit {
                label: format!("commit {}:{}", commit.get(..8).unwrap_or(commit), file),
                content: lines.join("\n"),
            });
            buffer.clear();
        };

    for line in log.lines() {
        if let Some(rest) = line.strip_prefix("commit ") {
            flush(&mut units, &commit, &file, &mut buffer);
            commit = rest.trim().to_string();
            file.clear();
        } else if let Some(rest) = line.strip_prefix("+++ b/") {
            flush(&mut units, &commit, &file, &mut buffer);
            file = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("@@ ") {
            // @@ -a,b +c,d @@ ; take c as the starting new-file line number.
            if let Some(plus) = rest.split('+').nth(1) {
                let num: String = plus.chars().take_while(|c| c.is_ascii_digit()).collect();
                new_line_no = num.parse().unwrap_or(0);
            }
        } else if let Some(rest) = line.strip_prefix('+') {
            // Diff headers are `+++ b/...` (consumed above) and `+++ /dev/null`,
            // both of which have a space after `+++`. Only skip those — an
            // added *content* line like `++i;` becomes `+++i;` (no space) and
            // must still be scanned.
            if !line.starts_with("+++ ") {
                buffer.push((new_line_no, rest.to_string()));
                new_line_no += 1;
            }
        }
    }
    flush(&mut units, &commit, &file, &mut buffer);
    units
}

/// Directories never worth scanning (VCS internals, dependencies, build
/// output). Their contents are skipped entirely.
const SKIP_DIRS: [&str; 10] = [
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    "vendor",
];

const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Scan units for a working-tree directory (or a single file). Skips VCS/dep
/// directories, binary files, and files larger than 5 MiB. Labels are
/// relative to `root` when possible.
pub fn working_tree_units(root: &Path) -> Result<Vec<ScanUnit>> {
    let mut units = Vec::new();
    if root.is_file() {
        if let Some(unit) = read_file_unit(root, root) {
            units.push(unit);
        }
        return Ok(units);
    }
    let walker = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            if entry.file_type().is_dir() {
                let name = entry.file_name().to_string_lossy();
                !SKIP_DIRS.contains(&name.as_ref())
            } else {
                true
            }
        });
    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(unit) = read_file_unit(root, entry.path()) {
            units.push(unit);
        }
    }
    Ok(units)
}

fn read_file_unit(root: &Path, path: &Path) -> Option<ScanUnit> {
    let label = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();
    let label = if label.is_empty() {
        path.file_name()?.to_string_lossy().to_string()
    } else {
        label
    };
    if crate::scanner::is_probably_binary(&label) {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if crate::scanner::looks_binary(&bytes) {
        return None;
    }
    Some(ScanUnit {
        label,
        content: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_added_lines_with_line_numbers() {
        let log = "\
commit abcdef1234567890
diff --git a/.env b/.env
--- /dev/null
+++ b/.env
@@ -0,0 +1,2 @@
+OPENAI_API_KEY=sk-proj-FAKE
+SAFE=1
";
        let units = parse_log_added_lines(log);
        assert_eq!(units.len(), 1);
        assert!(units[0].label.contains(".env"));
        assert!(units[0].content.contains("OPENAI_API_KEY=sk-proj-FAKE"));
        // Line 1 is the key.
        assert_eq!(
            units[0].content.lines().next().unwrap(),
            "OPENAI_API_KEY=sk-proj-FAKE"
        );
    }

    #[test]
    fn huge_line_number_does_not_allocate_a_giant_vector() {
        // A hunk header claiming line 50,000,000 with a single added line must
        // not allocate a 50M-entry vector; it falls back to dense packing.
        let log = "\
commit abcdef1234567890
diff --git a/big.txt b/big.txt
--- a/big.txt
+++ b/big.txt
@@ -49999999,0 +50000000,1 @@
+OPENAI_API_KEY=sk-proj-FAKE
";
        let units = parse_log_added_lines(log);
        assert_eq!(units.len(), 1);
        // The content is present (dense-packed) rather than sitting behind
        // 50M blank lines.
        assert!(units[0].content.contains("OPENAI_API_KEY=sk-proj-FAKE"));
        assert!(units[0].content.lines().count() < 10);
    }

    #[test]
    fn range_endpoints_must_be_hex() {
        let dir = tempfile::tempdir().unwrap();
        // Option-looking endpoints are refused before git ever runs.
        for (old, new) in [("--output=/tmp/x", "HEAD"), ("abc123", "..evil")] {
            match range_added_units(dir.path(), old, new) {
                Err(CoreError::InvalidInput(_)) => {}
                _ => panic!("expected InvalidInput for {old:?}..{new:?}, got Ok/other"),
            }
        }
    }

    #[test]
    fn keeps_added_content_lines_starting_with_plus_plus() {
        // A `++i;` content line renders as `+++i;` in the diff and must not be
        // mistaken for a `+++ b/...` header.
        let log = "\
commit abcdef1234567890
diff --git a/main.c b/main.c
--- /dev/null
+++ b/main.c
@@ -0,0 +1,2 @@
+++i;
+int x = 1;
";
        let units = parse_log_added_lines(log);
        assert_eq!(units.len(), 1);
        assert!(
            units[0].content.contains("++i;"),
            "the ++i; line must be scanned"
        );
        assert!(units[0].content.contains("int x = 1;"));
    }
}
