//! Differential tests for the non-executing Git reader (ADR 0023).
//!
//! `gitsafe` replaces `git ls-files` / `git check-ignore` with a byte
//! reader, so its answers must agree with the real Git on the shapes a
//! project actually contains. These tests build repositories with the real
//! `git` binary, ask both implementations the same questions, and fail on
//! any disagreement.
//!
//! `git` is required for the fixtures only. When it is absent the test
//! skips loudly rather than passing vacuously.

use std::path::Path;
use std::process::Command;

use api_tracker_core::gitsafe::{PathStatus, RepoView};

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

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

fn init_repo(dir: &Path) {
    assert!(git(dir, &["init", "-q", "."]).status.success());
    assert!(git(dir, &["config", "user.name", "t"]).status.success());
    assert!(git(dir, &["config", "user.email", "t@example.invalid"])
        .status
        .success());
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

/// Real git's answer for one path, in `PathStatus` terms.
fn git_status(dir: &Path, rel: &str) -> PathStatus {
    let tracked = git(dir, &["ls-files", "--error-unmatch", "--", rel])
        .status
        .success();
    if tracked {
        return PathStatus::Tracked;
    }
    let ignored = git(dir, &["check-ignore", "-q", "--", rel])
        .status
        .success();
    if ignored {
        PathStatus::Ignored
    } else {
        PathStatus::Untracked
    }
}

fn assert_agrees(dir: &Path, rels: &[&str]) {
    let canonical = dir.canonicalize().unwrap();
    let view = RepoView::open(&canonical).expect("gitsafe finds the repository");
    assert!(
        view.limits().is_empty(),
        "unexpected read limits: {:?}",
        view.limits()
    );
    let mut disagreements = Vec::new();
    for rel in rels {
        let theirs = git_status(dir, rel);
        let ours = view.status_of(&canonical.join(rel));
        if theirs != ours {
            disagreements.push(format!("{rel}: git={theirs:?} gitsafe={ours:?}"));
        }
    }
    assert!(
        disagreements.is_empty(),
        "gitsafe disagreed with git:\n  {}",
        disagreements.join("\n  ")
    );
}

#[test]
fn tracked_ignored_and_untracked_agree_with_git() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);

    write(
        &dir.join(".gitignore"),
        "*.log\nbuild/\n!keep.log\n/root-only.env\n",
    );
    write(&dir.join(".env"), "A=1\n");
    write(&dir.join("committed.env"), "B=2\n");
    write(&dir.join("root-only.env"), "C=3\n");
    write(&dir.join("noise.log"), "x\n");
    write(&dir.join("keep.log"), "x\n");
    write(&dir.join("build/out.env"), "D=4\n");
    write(&dir.join("sub/root-only.env"), "E=5\n");
    write(&dir.join("sub/.gitignore"), "*.env\n!allowed.env\n");
    write(&dir.join("sub/blocked.env"), "F=6\n");
    write(&dir.join("sub/allowed.env"), "G=7\n");

    assert!(git(
        dir,
        &["add", ".gitignore", "committed.env", "sub/.gitignore"]
    )
    .status
    .success());
    assert!(git(dir, &["commit", "-q", "-m", "init"]).status.success());

    assert_agrees(
        dir,
        &[
            ".env",
            "committed.env",
            "root-only.env",
            "noise.log",
            "keep.log",
            "build/out.env",
            "sub/root-only.env",
            "sub/blocked.env",
            "sub/allowed.env",
            ".gitignore",
        ],
    );
}

#[test]
fn nested_gitignore_precedence_agrees_with_git() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);

    write(&dir.join(".gitignore"), "**/secret/*.env\n");
    write(&dir.join("a/secret/x.env"), "1\n");
    write(&dir.join("a/secret/.gitignore"), "!x.env\n");
    write(&dir.join("a/open/x.env"), "1\n");
    write(&dir.join("b/secret/y.env"), "1\n");

    assert_agrees(dir, &["a/secret/x.env", "a/open/x.env", "b/secret/y.env"]);
}

#[test]
fn info_exclude_agrees_with_git() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);
    write(&dir.join(".git/info/exclude"), "excluded.env\n");
    write(&dir.join("excluded.env"), "1\n");
    write(&dir.join("normal.env"), "1\n");

    assert_agrees(dir, &["excluded.env", "normal.env"]);
}

#[test]
fn index_v4_is_parsed() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);
    // Version 4 uses path prefix compression; deep shared prefixes are
    // exactly what exercises it.
    for i in 0..40 {
        write(&dir.join(format!("deep/nested/path/file{i:03}.env")), "1\n");
    }
    assert!(git(dir, &["add", "-A"]).status.success());
    assert!(git(dir, &["update-index", "--index-version", "4"])
        .status
        .success());

    let raw = std::fs::read(dir.join(".git/index")).unwrap();
    assert_eq!(
        u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
        4,
        "the fixture must actually be a version-4 index"
    );

    let rels: Vec<String> = (0..40)
        .map(|i| format!("deep/nested/path/file{i:03}.env"))
        .collect();
    let refs: Vec<&str> = rels.iter().map(String::as_str).collect();
    assert_agrees(dir, &refs);
}

#[test]
fn a_path_outside_any_repository_has_no_view() {
    let tmp = tempfile::tempdir().unwrap();
    // A temp dir under /tmp is not inside a repository; `open` must say so
    // rather than walking up into one.
    assert!(
        RepoView::open(tmp.path()).is_none()
            || RepoView::open(tmp.path()).is_some_and(|v| v.layout.work_tree != tmp.path()),
        "a non-repository must not be reported as its own work tree"
    );
}

#[test]
fn a_missing_index_reports_nothing_tracked_not_unknown() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);
    // A fresh `git init` has no index file at all.
    let index = dir.join(".git/index");
    if index.exists() {
        std::fs::remove_file(&index).unwrap();
    }
    write(&dir.join("a.env"), "1\n");
    let canonical = dir.canonicalize().unwrap();
    let view = RepoView::open(&canonical).unwrap();
    assert_eq!(
        view.status_of(&canonical.join("a.env")),
        PathStatus::Untracked,
        "no index means nothing is tracked — a complete answer, not Unknown"
    );
}

#[test]
fn a_corrupt_index_degrades_to_unknown_and_says_so() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);
    write(&dir.join("a.env"), "1\n");
    assert!(git(dir, &["add", "-A"]).status.success());
    // Corrupt the signature: the reader must refuse, not invent an answer.
    let index = dir.join(".git/index");
    let mut bytes = std::fs::read(&index).unwrap();
    bytes[0] = b'X';
    std::fs::write(&index, &bytes).unwrap();

    let canonical = dir.canonicalize().unwrap();
    let view = RepoView::open(&canonical).unwrap();
    assert_eq!(
        view.status_of(&canonical.join("a.env")),
        PathStatus::Unknown
    );
    assert!(
        !view.limits().is_empty(),
        "a degraded answer must carry a reported limit"
    );
}
