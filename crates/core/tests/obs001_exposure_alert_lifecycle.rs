//! OBS-001 regression: a repository-scan exposure alert must remain open
//! until an explicit remediation or a qualifying clean full re-scan — never
//! auto-resolved just because a later incremental monitor run stopped
//! re-emitting the finding. Covers: unchanged repo, unavailable repo, scan
//! failure (non-repo), secret removed from the working tree but still in
//! history, explicit resolution, a clean full re-scan, and rebaseline
//! coverage-gap persistence.
//!
//! At baseline `7d81090` the alert used a head-commit-keyed
//! `AlertKind::PossibleExposure` in the auto-resolve managed set, so the
//! second (unchanged/unavailable/failed) run silently resolved it, and the
//! rebaseline warning auto-resolved in the very same run it was raised.

mod common;

use api_tracker_core::alerts;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, AddCredential, UnlockedVault};
use common::{add_project, new_vault};
use std::path::Path;
use std::process::Command;

const FAKE_OPENAI: &str = "sk-proj-FAKE0000000000000000000000000000FAKE";

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo(dir: &Path) {
    git(dir, &["init"]);
    git(dir, &["config", "user.email", "test@example.com"]);
    git(dir, &["config", "user.name", "Test"]);
}

fn commit(dir: &Path, file: &str, contents: &str, message: &str) {
    std::fs::write(dir.join(file), contents).unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-m", message]);
}

fn register_repo(vault: &mut UnlockedVault, project: &str, repo: &Path) {
    vault
        .update_project(
            project,
            vault::UpdateProject {
                add_repo_paths: vec![repo.to_string_lossy().into_owned()],
                ..Default::default()
            },
        )
        .unwrap();
}

/// A vault + registered repo whose FIRST monitor run only baselines HEAD
/// (the incremental scanner never scans history on first sight), then a
/// second run scans the new commit that introduces the fake secret and
/// raises the exposure alert. Returns (dir handle, repo path, vault).
fn setup_with_open_exposure() -> (tempfile::TempDir, std::path::PathBuf, UnlockedVault) {
    let (dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    // A stored credential so the leaked secret matches the vault (not required
    // for the alert, but mirrors the real scenario).
    vault
        .add_credential(AddCredential {
            project: "app".into(),
            provider: "openai".into(),
            name: "main".into(),
            environment: Environment::Production,
            value: SecretString::from(FAKE_OPENAI),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();

    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_repo(&repo);
    commit(&repo, "README.md", "# clean\n", "initial clean commit");
    register_repo(&mut vault, "app", &repo);

    // Run 1: first sight → baseline HEAD only, no exposure yet.
    vault.run_monitor().unwrap();
    assert!(
        !exposure_open(&vault),
        "baseline run must not raise exposure"
    );

    // A new commit introduces the secret; the next run scans that new commit.
    commit(
        &repo,
        ".env",
        &format!("OPENAI_API_KEY={FAKE_OPENAI}\n"),
        "leak",
    );
    vault.run_monitor().unwrap();
    assert!(
        exposure_open(&vault),
        "the new-commit scan must raise a repo exposure alert"
    );
    (dir, repo, vault)
}

/// Detect the repository-scan exposure alert by its TITLE, which is
/// identical at baseline (`AlertKind::PossibleExposure`) and after the fix
/// (`AlertKind::RepoSecretExposure`). Keying on the stable title rather than
/// the kind lets the same test faithfully demonstrate the baseline
/// auto-resolve bug and verify the fix, and avoids confusing the repo-scan
/// alert with the per-credential exposure alert (a different title).
fn exposure_open(vault: &UnlockedVault) -> bool {
    alerts::list(vault.connection(), false)
        .unwrap()
        .iter()
        .any(|a| a.title.starts_with("likely secret(s) in new commits"))
}

fn coverage_gap_open(vault: &UnlockedVault) -> bool {
    alerts::list(vault.connection(), false)
        .unwrap()
        .iter()
        .any(|a| a.title.starts_with("repository re-baselined"))
}

#[test]
fn exposure_survives_unchanged_second_monitor_run() {
    if !api_tracker_core::gitrepo::git_available() {
        return;
    }
    let (_dir, _repo, vault) = setup_with_open_exposure();
    // The repo is unchanged; the incremental scan skips it (last == head).
    vault.run_monitor().unwrap();
    assert!(
        exposure_open(&vault),
        "OBS-001: exposure alert was auto-resolved by an unchanged monitor run"
    );
    // And again, to be sure it is structurally stable, not one-cycle-delayed.
    vault.run_monitor().unwrap();
    assert!(
        exposure_open(&vault),
        "OBS-001: exposure alert cleared on a later cycle"
    );
}

#[test]
fn exposure_survives_when_repository_is_unavailable() {
    if !api_tracker_core::gitrepo::git_available() {
        return;
    }
    let (_dir, repo, vault) = setup_with_open_exposure();
    // Make the repository disappear (e.g. unmounted / deleted checkout).
    std::fs::remove_dir_all(&repo).unwrap();
    vault.run_monitor().unwrap();
    assert!(
        exposure_open(&vault),
        "OBS-001: making the repo unavailable 'cleared' the exposure signal"
    );
}

#[test]
fn exposure_survives_scan_failure_on_non_repo() {
    if !api_tracker_core::gitrepo::git_available() {
        return;
    }
    let (_dir, repo, vault) = setup_with_open_exposure();
    // Destroy the git metadata so head_commit() fails but the path still
    // exists: the scanner cannot read it (scan failure), and must not resolve.
    std::fs::remove_dir_all(repo.join(".git")).unwrap();
    vault.run_monitor().unwrap();
    assert!(
        exposure_open(&vault),
        "OBS-001: a scan failure auto-resolved the exposure alert"
    );
}

#[test]
fn exposure_survives_secret_removed_from_working_tree_but_kept_in_history() {
    if !api_tracker_core::gitrepo::git_available() {
        return;
    }
    let (_dir, repo, vault) = setup_with_open_exposure();
    // Remove the secret from the working tree in a NEW commit; the leaked
    // value is still present in the earlier commit's history.
    commit(
        &repo,
        ".env",
        "OPENAI_API_KEY=\n",
        "scrub working tree only",
    );
    vault.run_monitor().unwrap();
    assert!(
        exposure_open(&vault),
        "OBS-001: exposure resolved when the secret left the working tree but \
         remained in git history"
    );
    // A full re-verify must still find it (history) and keep the alert open.
    let report = vault.reverify_repo_exposure(&repo).unwrap();
    assert!(!report.clean, "the secret is still in history");
    assert!(exposure_open(&vault));
}

#[test]
fn explicit_resolution_clears_the_exposure_alert() {
    if !api_tracker_core::gitrepo::git_available() {
        return;
    }
    let (_dir, _repo, vault) = setup_with_open_exposure();
    let open = alerts::list(vault.connection(), false).unwrap();
    let id = open
        .iter()
        .find(|a| a.title.starts_with("likely secret(s) in new commits"))
        .unwrap()
        .id
        .clone();
    alerts::resolve(vault.connection(), &id).unwrap();
    assert!(
        !exposure_open(&vault),
        "explicit resolution must clear the alert"
    );
    // A subsequent unchanged monitor run must not resurrect it.
    vault.run_monitor().unwrap();
    assert!(!exposure_open(&vault));
}

#[test]
fn clean_full_rescan_resolves_the_exposure_alert() {
    if !api_tracker_core::gitrepo::git_available() {
        return;
    }
    let (_dir, repo, vault) = setup_with_open_exposure();
    // Genuinely remediate: rewrite ALL history so the secret is nowhere (the
    // full-history scan uses `git log --all`, so an orphan branch alone would
    // leave the secret reachable). Re-initialising the repo is the cleanest
    // total scrub.
    std::fs::remove_dir_all(repo.join(".git")).unwrap();
    std::fs::remove_file(repo.join(".env")).ok();
    init_repo(&repo);
    commit(&repo, "README.md", "# clean\n", "clean history");

    let report = vault.reverify_repo_exposure(&repo).unwrap();
    assert!(
        report.clean,
        "the scrubbed repo must scan clean: {report:?}"
    );
    assert!(report.resolved_alerts >= 1);
    assert!(
        !exposure_open(&vault),
        "a clean full re-scan must resolve the exposure alert"
    );
}

#[test]
fn rebaseline_coverage_gap_persists_across_runs() {
    if !api_tracker_core::gitrepo::git_available() {
        return;
    }
    let (dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_repo(&repo);
    commit(&repo, "a.txt", "one\n", "c1");
    register_repo(&mut vault, "app", &repo);
    vault.run_monitor().unwrap(); // baseline records last_scanned = c1

    // Rewrite history so the recorded last-scanned commit no longer exists as
    // an object: re-initialising the repo makes `c1..head` an unknown-revision
    // range, so range_added_units fails → rebaseline coverage gap.
    std::fs::remove_dir_all(repo.join(".git")).unwrap();
    init_repo(&repo);
    commit(&repo, "b.txt", "two\n", "rewritten history");
    vault.run_monitor().unwrap();
    assert!(
        coverage_gap_open(&vault),
        "a re-baseline must raise a coverage-gap alert"
    );

    // The gap must SURVIVE the same run and later unchanged runs (baseline bug:
    // it auto-resolved in the same run because its key was never active).
    vault.run_monitor().unwrap();
    assert!(
        coverage_gap_open(&vault),
        "OBS-001: the rebaseline coverage-gap alert did not persist"
    );
}
