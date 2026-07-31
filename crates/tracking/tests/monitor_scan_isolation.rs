//! RA-001, end to end through product code only.
//!
//! This is the previous auditor's own reproduction
//! (`fable-final-reaudit-20260727/repro/scanner_rce.rs`), kept as a permanent
//! regression test rather than quoted. It drives the exact chain the audit
//! used to decide its verdict, with no harness shortcuts:
//!
//! ```text
//! vault.create_project(repo_paths=[hostile])   <- what tracking apply does
//!   -> vault.scan_repos_incremental()          <- what run_monitor_cycle calls
//!     -> gitrepo::range_added_units()          <- `git log -p`
//!       -> the repo's own .git/config runs a program
//! ```
//!
//! The registration step is real: all three branches of
//! `tracking::apply::ensure_project` register the folder the user picks in the
//! desktop Track flow as a monitored repo. The scan step is real: it is what
//! `run_monitor_cycle` calls on the desktop's background timer. Nothing in
//! between requires the user to be present.
//!
//! At `4a89ced` this panicked with `canary contents: "FIRED\n"`.

#![cfg(unix)]

mod common;

use common::*;
use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .expect("git runs")
}

/// A repository that ships a hostile `.git/config` plus a payload, and whose
/// HEAD carries a fabricated `gpgsig` header.
fn hostile_repo(dir: &Path, canary: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    git(dir, &["init", "-q", "."]);
    git(dir, &["config", "user.email", "t@example.invalid"]);
    git(dir, &["config", "user.name", "t"]);

    std::fs::write(dir.join(".env"), "OPENAI_API_KEY=sk-proj-FAKE-0001\n").unwrap();
    git(dir, &["add", ".env"]);
    git(dir, &["commit", "-qm", "initial"]);

    let payload = dir.join("payload.sh");
    std::fs::write(
        &payload,
        format!("#!/bin/sh\necho FIRED >> {}\nexit 0\n", canary.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();

    // The attacker's repo-local config. Nothing in the `-c` enumeration
    // neutralised the repository's OWN `.git/config`; the sealed directory
    // (ADR 0027) removes it from the repository Git reads at all.
    let mut cfg = std::fs::read_to_string(dir.join(".git/config")).unwrap();
    cfg.push_str("[log]\n\tshowSignature = true\n[gpg]\n\tprogram = ./payload.sh\n");
    cfg.push_str("[gpg \"ssh\"]\n\tprogram = ./payload.sh\n");
    std::fs::write(dir.join(".git/config"), cfg).unwrap();

    sign_head(dir);
}

/// Move HEAD onto a commit carrying a `gpgsig` header. The signature does not
/// have to be valid: Git pattern-matches the header and then hands the blob to
/// the configured program.
fn sign_head(dir: &Path) -> String {
    let tree = String::from_utf8(git(dir, &["rev-parse", "HEAD^{tree}"]).stdout).unwrap();
    let parent = String::from_utf8(git(dir, &["rev-parse", "HEAD"]).stdout).unwrap();
    let commit = format!(
        "tree {}\nparent {}\nauthor t <t@example.invalid> 1700000000 +0000\n\
         committer t <t@example.invalid> 1700000000 +0000\n\
         gpgsig -----BEGIN PGP SIGNATURE-----\n \n iHUEABYKAB0WIQT\n \
         -----END PGP SIGNATURE-----\n\nsigned\n",
        tree.trim(),
        parent.trim()
    );
    let mut child = Command::new("git")
        .args(["hash-object", "-t", "commit", "-w", "--stdin"])
        .current_dir(dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(commit.as_bytes())
            .unwrap();
    }
    let oid = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    let oid = oid.trim().to_string();
    git(dir, &["update-ref", "HEAD", &oid]);
    oid
}

#[test]
fn the_background_monitor_never_executes_repository_controlled_code() {
    let tv = test_vault();
    let work = tv._dir.path();
    let repo = work.join("hostile");
    let canary = work.join("CANARY_FIRED");
    hostile_repo(&repo, &canary);
    assert!(!canary.exists(), "the canary must not be pre-fired");

    // Exactly what tracking apply does with the folder the user selects.
    let mut vault = tv.vault;
    vault
        .create_project(api_tracker_core::vault::NewProject {
            name: "victim".into(),
            repo_paths: vec![repo.display().to_string()],
            ..Default::default()
        })
        .unwrap();

    // First tick: baseline only.
    let first = vault.scan_repos_incremental();
    assert!(
        !canary.exists(),
        "the baseline scan executed repository-controlled code: {:?}",
        std::fs::read_to_string(&canary)
    );

    // The attacker pushes a commit carrying a gpgsig header onto the repo the
    // victim already tracks; the victim pulls. HEAD advances onto it.
    let pushed = sign_head(&repo);

    // The next monitor tick scans the new range. This is where it fired.
    let second = vault.scan_repos_incremental();
    assert!(
        !canary.exists(),
        "SECURITY: repository-controlled code EXECUTED on the background monitor \
         path after HEAD advanced onto {pushed}. Canary contents: {:?}",
        std::fs::read_to_string(&canary).unwrap_or_default()
    );

    // Not vacuous: the scan has to have actually looked at the repository.
    // A monitor that silently stopped scanning would also never fire a canary.
    assert!(
        first.is_ok(),
        "the baseline scan must succeed on a hostile repository: {first:?}"
    );
    assert!(
        second.is_ok(),
        "the incremental scan must succeed on a hostile repository: {second:?}"
    );
    assert_eq!(
        second.unwrap().len(),
        1,
        "the monitor must still report on the registered repository"
    );
    assert_eq!(
        api_tracker_core::gitrepo::head_commit(&repo).unwrap(),
        pushed,
        "and it must see the commit the attacker pushed, not a stale one"
    );
}
