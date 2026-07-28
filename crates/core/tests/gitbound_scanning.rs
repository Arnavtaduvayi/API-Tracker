//! CONC-06 / GScan-03 / CONC-05 regression suite: every git subprocess is
//! bounded (timeout, output caps) and history scanning streams under
//! explicit per-line / per-unit / total-retained / duration limits. Any
//! limit hit is reported as INCOMPLETE COVERAGE — never a clean scan — and
//! the git child is killed and reaped, never orphaned.
//!
//! Determinism: misbehaving gits are tiny `sh` stubs selected via the
//! debug-build-only `API_TRACKER_GIT_BINARY` override; no arbitrary sleeps
//! are used for synchronization — stubs either hang forever (bounded by the
//! runner's timeout under test) or produce unbounded output (bounded by the
//! byte caps under test).
//!
//! Baseline evidence (`033f747`): a hung git blocked `scan_history`
//! indefinitely — see
//! `docs/remediation-phase-2/evidence/conc06_baseline_fail.log.txt`.

#![cfg(unix)]

mod common;

use api_tracker_core::gitrepo::{self, GitLimits};
use api_tracker_core::inject::{probe_process_identity, IdentityProbe};
use common::{add_key, add_project, new_vault, FAKE_KEY_1};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tempfile::TempDir;

/// Serializes tests: they set process-wide env vars (the git-binary and
/// limit overrides) that production code reads.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// RAII guard: sets env vars, restores (removes) them on drop even if the
/// test panics, so later tests in this binary see a clean environment.
struct EnvGuard(Vec<&'static str>);

impl EnvGuard {
    fn set(pairs: &[(&'static str, String)]) -> Self {
        for (k, v) in pairs {
            std::env::set_var(k, v);
        }
        EnvGuard(pairs.iter().map(|(k, _)| *k).collect())
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for k in &self.0 {
            std::env::remove_var(k);
        }
    }
}

/// Write an executable stub "git" whose behavior is chosen by STUB_MODE.
/// It always writes its PID to $STUB_PID_FILE first so tests can verify
/// the child was killed and reaped.
fn write_stub(dir: &Path) -> PathBuf {
    let stub = dir.join("fake-git");
    std::fs::write(
        &stub,
        r#"#!/bin/sh
[ -n "$STUB_PID_FILE" ] && echo $$ > "$STUB_PID_FILE"
# Invocations look like:
#   git --no-pager -c k=v ... --git-dir <sealed> <subcommand> ...
# and, for the one read-through caller (config --get),
#   git --no-pager -C <repo> config --get <key>
# The hardening options (ADR 0023) and the sealed-directory selector
# (ADR 0027) both sit before the subcommand, so the repository and the
# subcommand are found by scanning argv rather than by position — a
# positional stub would silently stop matching the moment the option list
# changes, which is exactly how a fixture starts lying.
REPO=""
SUB=""
SUBARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-pager) shift ;;
    -c) shift 2 ;;
    -C) REPO="$2"; shift 2 ;;
    --git-dir) REPO="$2"; shift 2 ;;
    *)
      SUB="$1"; shift
      SUBARG="$1"
      break
      ;;
  esac
done
if [ "$SUB" = "rev-parse" ] && [ "$SUBARG" = "--show-toplevel" ]; then
  echo "$REPO"
  exit 0
fi
case "$STUB_MODE" in
  hang)
    exec sleep 3600
    ;;
  slow-secret)
    printf 'commit 1234567890abcdef\n'
    printf '+++ b/leak.env\n'
    printf '@@ -0,0 +1 @@\n'
    printf '+OPENAI_API_KEY=sk-proj-FAKE0000000000000000000000000000FAKE\n'
    exec sleep 3600
    ;;
  flood)
    printf 'commit 1234567890abcdef\n'
    printf '+++ b/big.txt\n'
    printf '@@ -0,0 +1 @@\n'
    while :; do
      printf '+xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n'
    done
    ;;
  bigline)
    printf 'commit 1234567890abcdef\n'
    printf '+++ b/mixed.txt\n'
    printf '@@ -0,0 +1,2 @@\n'
    printf '+'
    i=0
    while [ $i -lt 4000 ]; do printf 'aaaaaaaaaaaaaaaaaaaaaaaaa'; i=$((i+1)); done
    printf '\n'
    printf '+OPENAI_API_KEY=sk-proj-FAKE0000000000000000000000000000FAKE\n'
    exit 0
    ;;
  *)
    exit 1
    ;;
esac
"#,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    stub
}

fn tight_history_limits() -> GitLimits {
    GitLimits {
        timeout: Duration::from_millis(600),
        max_output_bytes: 10 * 1024 * 1024,
        max_line_bytes: 64 * 1024,
        max_unit_bytes: 5 * 1024 * 1024,
        max_retained_bytes: 64 * 1024 * 1024,
    }
}

/// After the bounded runner returns, its child must be dead AND reaped.
fn assert_stub_reaped(pid_file: &Path) {
    let pid: i64 = std::fs::read_to_string(pid_file)
        .expect("stub wrote its pid")
        .trim()
        .parse()
        .expect("stub pid parses");
    assert_eq!(
        probe_process_identity(pid),
        IdentityProbe::NotFound,
        "the stub git child (pid {pid}) must be killed and reaped"
    );
}

fn git(repo: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q"]);
    git(dir, &["config", "user.email", "t@example.invalid"]);
    git(dir, &["config", "user.name", "t"]);
}

// ------------------------------------------------------------ hung / slow

#[test]
fn hung_git_times_out_incomplete_and_child_is_reaped() {
    let _l = lock();
    let dir = TempDir::new().unwrap();
    // A real repository, so the sealed-directory isolation (ADR 0027) has
    // something to seal. The stub git is still what the product executes;
    // this only gives the seal a genuine `.git` to mirror.
    init_repo(dir.path());
    let stub = write_stub(dir.path());
    let pid_file = dir.path().join("stub.pid");
    let _env = EnvGuard::set(&[
        ("API_TRACKER_GIT_BINARY", stub.display().to_string()),
        ("STUB_MODE", "hang".into()),
        ("STUB_PID_FILE", pid_file.display().to_string()),
    ]);

    let started = std::time::Instant::now();
    let scan = gitrepo::history_added_units_with_limits(dir.path(), None, &tight_history_limits())
        .expect("bounded scan returns instead of hanging");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the bounded scan must return promptly"
    );
    assert!(!scan.complete, "a timed-out scan is INCOMPLETE");
    assert!(
        scan.warnings.iter().any(|w| w.contains("time")),
        "the warnings must say time ran out: {:?}",
        scan.warnings
    );
    assert_stub_reaped(&pid_file);
}

#[test]
fn short_git_commands_error_loudly_on_timeout() {
    let _l = lock();
    let dir = TempDir::new().unwrap();
    // A real repository, so the sealed-directory isolation (ADR 0027) has
    // something to seal. The stub git is still what the product executes;
    // this only gives the seal a genuine `.git` to mirror.
    init_repo(dir.path());
    let stub = write_stub(dir.path());
    let pid_file = dir.path().join("stub.pid");
    let _env = EnvGuard::set(&[
        ("API_TRACKER_GIT_BINARY", stub.display().to_string()),
        ("STUB_MODE", "hang".into()),
        ("STUB_PID_FILE", pid_file.display().to_string()),
        ("API_TRACKER_GIT_TIMEOUT_MS", "500".into()),
    ]);

    let err = gitrepo::staged_files(dir.path()).expect_err("a hung git must be a loud error");
    let msg = err.to_string();
    assert!(
        msg.contains("did not finish"),
        "the error must say git timed out: {msg}"
    );
    assert_stub_reaped(&pid_file);
}

#[test]
fn slow_git_yields_partial_findings_and_incomplete_coverage() {
    // The stub emits a valid diff containing a fake secret, then hangs: the
    // findings already streamed must be reported together with INCOMPLETE
    // coverage (never presented as a clean or full scan).
    let _l = lock();
    let (_vault_dir, _paths, vault) = new_vault();
    let dir = TempDir::new().unwrap();
    // A real repository, so the sealed-directory isolation (ADR 0027) has
    // something to seal. The stub git is still what the product executes;
    // this only gives the seal a genuine `.git` to mirror.
    init_repo(dir.path());
    let stub = write_stub(dir.path());
    let pid_file = dir.path().join("stub.pid");
    let _env = EnvGuard::set(&[
        ("API_TRACKER_GIT_BINARY", stub.display().to_string()),
        ("STUB_MODE", "slow-secret".into()),
        ("STUB_PID_FILE", pid_file.display().to_string()),
        ("API_TRACKER_GIT_HISTORY_TIMEOUT_MS", "700".into()),
    ]);

    let outcome = vault
        .scan_history(dir.path(), None)
        .expect("partial results, not an error");
    assert!(!outcome.complete, "a timed-out history scan is INCOMPLETE");
    assert!(
        outcome
            .findings
            .iter()
            .any(|f| f.provider.as_deref() == Some("openai")),
        "findings streamed before the timeout must be reported: {:?}",
        outcome.findings.len()
    );
    assert_stub_reaped(&pid_file);
}

// ------------------------------------------------------- unbounded output

#[test]
fn infinite_output_hits_byte_cap_incomplete_and_reaped() {
    let _l = lock();
    let dir = TempDir::new().unwrap();
    // A real repository, so the sealed-directory isolation (ADR 0027) has
    // something to seal. The stub git is still what the product executes;
    // this only gives the seal a genuine `.git` to mirror.
    init_repo(dir.path());
    let stub = write_stub(dir.path());
    let pid_file = dir.path().join("stub.pid");
    let _env = EnvGuard::set(&[
        ("API_TRACKER_GIT_BINARY", stub.display().to_string()),
        ("STUB_MODE", "flood".into()),
        ("STUB_PID_FILE", pid_file.display().to_string()),
    ]);
    let limits = GitLimits {
        max_output_bytes: 200_000,
        timeout: Duration::from_secs(30),
        ..tight_history_limits()
    };

    let scan = gitrepo::history_added_units_with_limits(dir.path(), None, &limits)
        .expect("bounded scan returns");
    assert!(!scan.complete, "a capped scan is INCOMPLETE");
    assert!(
        scan.warnings
            .iter()
            .any(|w| w.contains("limit") || w.contains("bytes")),
        "warnings must state the cap: {:?}",
        scan.warnings
    );
    // Memory stays bounded: retained unit content cannot exceed what was
    // streamed under the cap.
    let retained: usize = scan.units.iter().map(|u| u.content.len()).sum();
    assert!(
        retained as u64 <= limits.max_output_bytes,
        "retained {retained} bytes exceeds the stream cap"
    );
    assert_stub_reaped(&pid_file);
}

#[test]
fn retained_content_cap_stops_the_scan_honestly() {
    let _l = lock();
    let dir = TempDir::new().unwrap();
    // A real repository, so the sealed-directory isolation (ADR 0027) has
    // something to seal. The stub git is still what the product executes;
    // this only gives the seal a genuine `.git` to mirror.
    init_repo(dir.path());
    let stub = write_stub(dir.path());
    let pid_file = dir.path().join("stub.pid");
    let _env = EnvGuard::set(&[
        ("API_TRACKER_GIT_BINARY", stub.display().to_string()),
        ("STUB_MODE", "flood".into()),
        ("STUB_PID_FILE", pid_file.display().to_string()),
    ]);
    let limits = GitLimits {
        max_retained_bytes: 50_000,
        timeout: Duration::from_secs(30),
        ..tight_history_limits()
    };

    let scan = gitrepo::history_added_units_with_limits(dir.path(), None, &limits)
        .expect("bounded scan returns");
    assert!(!scan.complete);
    assert!(
        scan.warnings.iter().any(|w| w.contains("retained")),
        "warnings must state the retained-content cap: {:?}",
        scan.warnings
    );
    assert_stub_reaped(&pid_file);
}

#[test]
fn oversized_line_is_truncated_but_normal_findings_survive() {
    // One 100 KB line (over the 64 KiB per-line cap) must not break the
    // stream: the following normal-size secret line is still scanned. The
    // scanner skips over-long lines regardless, so truncation does not
    // reduce detection.
    let _l = lock();
    let (_vault_dir, _paths, vault) = new_vault();
    let dir = TempDir::new().unwrap();
    // A real repository, so the sealed-directory isolation (ADR 0027) has
    // something to seal. The stub git is still what the product executes;
    // this only gives the seal a genuine `.git` to mirror.
    init_repo(dir.path());
    let stub = write_stub(dir.path());
    let _env = EnvGuard::set(&[
        ("API_TRACKER_GIT_BINARY", stub.display().to_string()),
        ("STUB_MODE", "bigline".into()),
    ]);

    let outcome = vault.scan_history(dir.path(), None).expect("scan");
    assert!(
        outcome.complete,
        "line truncation alone is not incompleteness"
    );
    assert!(
        outcome
            .findings
            .iter()
            .any(|f| f.provider.as_deref() == Some("openai")),
        "the finding after the oversized line must be detected"
    );
}

// -------------------------------------------------- real-git bounded runs

#[test]
fn large_blob_in_history_truncates_unit_with_honest_warning() {
    let _l = lock();
    let repo = TempDir::new().unwrap();
    init_repo(repo.path());
    // 6 MiB of text: over the 5 MiB per-unit cap.
    let big = "A]&x0f-line-of-filler-content-with-no-secrets\n".repeat(140_000);
    assert!(big.len() > 5 * 1024 * 1024);
    std::fs::write(repo.path().join("big.txt"), &big).unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "big"]);

    let scan = gitrepo::history_added_units(repo.path(), None).expect("scan");
    assert!(
        scan.warnings.iter().any(|w| w.contains("truncated")),
        "a truncated unit must produce a coverage warning: {:?}",
        scan.warnings
    );
    assert!(
        !scan.complete,
        "truncated content means the scan is NOT complete coverage"
    );
    let retained: usize = scan.units.iter().map(|u| u.content.len()).sum();
    // Cap margin: reconstruction adds one newline per line (bounded by the
    // reconstructed-lines cap).
    assert!(
        retained <= 5 * 1024 * 1024 + 200_000,
        "unit content must be capped, got {retained}"
    );
}

#[test]
fn repository_with_many_commits_scans_completely() {
    let _l = lock();
    let repo = TempDir::new().unwrap();
    init_repo(repo.path());
    for i in 0..60 {
        std::fs::write(repo.path().join("f.txt"), format!("content {i}\n")).unwrap();
        git(repo.path(), &["add", "."]);
        git(repo.path(), &["commit", "-q", "-m", &format!("c{i}")]);
    }
    let scan = gitrepo::history_added_units(repo.path(), None).expect("scan");
    assert!(scan.complete, "an ordinary history must scan completely");
    assert!(scan.warnings.is_empty(), "no warnings: {:?}", scan.warnings);
    assert_eq!(scan.units.len(), 60);
}

// --------------------------------------- incremental monitor + reverify

#[test]
fn incomplete_incremental_scan_leaves_persistent_coverage_gap_alert() {
    let _l = lock();
    let (_dir, _paths, mut v) = new_vault();
    let repo = TempDir::new().unwrap();
    init_repo(repo.path());
    std::fs::write(repo.path().join("README.md"), "hello\n").unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "init"]);

    let project = add_project(&mut v, "app");
    v.update_project(
        &project.id,
        api_tracker_core::vault::UpdateProject {
            add_repo_paths: vec![repo.path().to_string_lossy().into_owned()],
            ..Default::default()
        },
    )
    .unwrap();
    add_key(
        &mut v,
        "app",
        "openai",
        FAKE_KEY_1,
        api_tracker_core::model::Environment::Production,
    );

    // Baseline run.
    let reports = v.scan_repos_incremental().unwrap();
    assert!(reports[0].baseline_only);

    // A new commit whose diff exceeds a (test-tightened) retained cap makes
    // the range scan INCOMPLETE.
    let filler = "no-secret-content-line\n".repeat(20_000);
    std::fs::write(repo.path().join("big.txt"), &filler).unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "big change"]);
    {
        let _env = EnvGuard::set(&[("API_TRACKER_GIT_HISTORY_MAX_RETAINED_BYTES", "10000".into())]);
        let _ = v.scan_repos_incremental().unwrap();
    }

    let open_gap = |v: &api_tracker_core::vault::UnlockedVault| {
        api_tracker_core::alerts::list(v.connection(), false)
            .unwrap()
            .into_iter()
            .filter(|a| {
                a.resolved_at.is_none()
                    && format!("{:?}", a.kind).contains("repo_scan_coverage_gap")
            })
            .count()
    };
    assert_eq!(
        open_gap(&v),
        1,
        "an incomplete range scan must raise a persistent coverage-gap alert"
    );

    // The warning persists across later runs (no auto-resolve).
    let _ = v.scan_repos_incremental().unwrap();
    assert_eq!(open_gap(&v), 1, "the coverage gap must persist");

    // A COMPLETE clean re-verification (normal limits restored) resolves it.
    let report = v.reverify_repo_exposure(repo.path()).unwrap();
    assert!(report.coverage_complete);
    assert!(report.clean);
    assert_eq!(
        open_gap(&v),
        0,
        "a complete clean full scan resolves the gap"
    );
}

#[test]
fn incomplete_reverify_never_resolves_alerts() {
    let _l = lock();
    let (_dir, _paths, mut v) = new_vault();
    let repo = TempDir::new().unwrap();
    init_repo(repo.path());
    std::fs::write(repo.path().join("README.md"), "hello\n").unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "init"]);

    let project = add_project(&mut v, "app");
    v.update_project(
        &project.id,
        api_tracker_core::vault::UpdateProject {
            add_repo_paths: vec![repo.path().to_string_lossy().into_owned()],
            ..Default::default()
        },
    )
    .unwrap();

    // A big history + a tiny retained cap → the reverify scan is incomplete
    // and must refuse to resolve anything or claim cleanliness.
    let filler = "no-secret-content-line\n".repeat(20_000);
    std::fs::write(repo.path().join("big.txt"), &filler).unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "big"]);

    let _env = EnvGuard::set(&[("API_TRACKER_GIT_HISTORY_MAX_RETAINED_BYTES", "10000".into())]);
    let report = v.reverify_repo_exposure(repo.path()).unwrap();
    assert!(!report.coverage_complete);
    assert!(
        !report.clean,
        "an incomplete scan must NEVER be presented as clean"
    );
    assert_eq!(report.resolved_alerts, 0);
    assert!(!report.coverage_warnings.is_empty());
}
