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

/// A split index moves every path out of `.git/index` and into
/// `.git/sharedindex.<oid>`, leaving the main index full of name-less
/// placeholders and one `link` extension. The old tail check accepted any
/// four alphabetic bytes as "an extension", so `link` passed unexamined and
/// a three-file repository read as one tracked path and no reported limit —
/// silently disabling the product's only committed-secret control (RA-007).
#[test]
fn split_index_agrees_with_git() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);
    // A hundred entries so that removing one is under `splitIndex`'s
    // rewrite threshold: below it Git simply rewrites the shared index and
    // the delete bitmap — the part of the extension that actually changes
    // the answer — is never exercised.
    for i in 0..100 {
        write(&dir.join(format!("f{i:03}.env")), "X=1\n");
    }
    assert!(git(dir, &["add", "-A"]).status.success());
    assert!(git(dir, &["update-index", "--split-index"])
        .status
        .success());
    assert!(git(dir, &["rm", "-q", "--cached", "f007.env"])
        .status
        .success());
    write(&dir.join("added.env"), "N=1\n");
    assert!(git(dir, &["add", "added.env"]).status.success());

    // Prove the fixture is the shape the finding describes rather than a
    // repository Git quietly un-split: one shared index, still naming the
    // path that `git ls-files` no longer reports.
    let shared: Vec<_> = std::fs::read_dir(dir.join(".git"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("sharedindex."))
        .collect();
    assert_eq!(shared.len(), 1, "the fixture must be a split index");
    let shared_bytes = std::fs::read(shared[0].path()).unwrap();
    assert!(
        shared_bytes.windows(9).any(|w| w == b"f007.env\0"),
        "the shared index must still carry the entry the delete bitmap removes"
    );
    let main = std::fs::read(dir.join(".git/index")).unwrap();
    assert!(
        main.windows(4).any(|w| w == b"link"),
        "the main index must carry the link extension"
    );

    let mut rels: Vec<String> = (0..100).map(|i| format!("f{i:03}.env")).collect();
    rels.push("added.env".to_string());
    let refs: Vec<&str> = rels.iter().map(String::as_str).collect();
    assert_agrees(dir, &refs);
}

/// Split index and index version 4 compose: the placeholders are prefix
/// compressed too, so an empty name is "strip the whole previous path and
/// append nothing".
#[test]
fn split_index_version_4_agrees_with_git() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);
    for i in 0..100 {
        write(&dir.join(format!("deep/nested/path/f{i:03}.env")), "X=1\n");
    }
    assert!(git(dir, &["add", "-A"]).status.success());
    assert!(git(dir, &["update-index", "--index-version", "4"])
        .status
        .success());
    assert!(git(dir, &["update-index", "--split-index"])
        .status
        .success());
    assert!(
        git(dir, &["rm", "-q", "--cached", "deep/nested/path/f007.env"])
            .status
            .success()
    );

    let raw = std::fs::read(dir.join(".git/index")).unwrap();
    assert_eq!(
        u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
        4,
        "the fixture must actually be a version-4 index"
    );
    assert!(
        raw.windows(4).any(|w| w == b"link"),
        "the fixture must actually be a split index"
    );

    let rels: Vec<String> = (0..100)
        .map(|i| format!("deep/nested/path/f{i:03}.env"))
        .collect();
    let refs: Vec<&str> = rels.iter().map(String::as_str).collect();
    assert_agrees(dir, &refs);
}

/// An index that exists but cannot be read is not the same fact as "this
/// repository tracks nothing". Both used to return an empty set with
/// `index_readable` still true, so a committed `.env` read `Untracked` and
/// no warning was raised (RA-007).
#[test]
fn an_index_that_cannot_be_read_is_unknown_not_untracked() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    // `.git/index` replaced by a directory — the `!is_file()` branch.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);
    write(&dir.join("a.env"), "1\n");
    assert!(git(dir, &["add", "-A"]).status.success());
    std::fs::remove_file(dir.join(".git/index")).unwrap();
    std::fs::create_dir(dir.join(".git/index")).unwrap();
    let canonical = dir.canonicalize().unwrap();
    let view = RepoView::open(&canonical).expect("the repository is still discoverable");
    assert_eq!(
        view.status_of(&canonical.join("a.env")),
        PathStatus::Unknown,
        "an index that is not a regular file must not read as nothing tracked"
    );
    assert!(
        !view.limits().is_empty(),
        "a degraded answer must carry a reported limit"
    );

    // `.git/index` replaced by a symlink — this module never reads through
    // a symlink at the final component, so it must refuse, not answer.
    #[cfg(unix)]
    {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        init_repo(dir);
        write(&dir.join("a.env"), "1\n");
        assert!(git(dir, &["add", "-A"]).status.success());
        let index = dir.join(".git/index");
        let elsewhere = dir.join(".git/real-index");
        std::fs::rename(&index, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &index).unwrap();
        let canonical = dir.canonicalize().unwrap();
        let view = RepoView::open(&canonical).expect("the repository is still discoverable");
        assert_eq!(
            view.status_of(&canonical.join("a.env")),
            PathStatus::Unknown,
            "a symlinked index must not read as nothing tracked"
        );
        assert!(
            !view.limits().is_empty(),
            "a degraded answer must carry a reported limit"
        );
    }
}

/// macOS hands back decomposed (NFD) names from `readdir` while Git's index
/// stores the precomposed (NFC) form, so the exact-bytes lookup reported a
/// COMMITTED `.env` under an accented directory as `Untracked` (RA-018).
///
/// The fixture builds both halves explicitly — the directory is created with
/// NFD bytes and the index entry is inserted with NFC bytes — so the test
/// exercises the same mismatch on every platform rather than depending on
/// the filesystem to produce it.
#[test]
fn a_decomposed_path_still_finds_its_precomposed_index_entry() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    // "café": U+0065 U+0301 on disk, U+00E9 in the index.
    let nfd_dir = "caf\u{65}\u{301}";
    let nfc_dir = "caf\u{e9}";
    assert_ne!(nfd_dir, nfc_dir, "the two forms must differ bytewise");

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);
    write(&dir.join(nfd_dir).join(".env"), "A=1\n");
    let hashed = git(dir, &["hash-object", "-w", &format!("{nfd_dir}/.env")]);
    assert!(hashed.status.success());
    let blob = String::from_utf8(hashed.stdout).unwrap().trim().to_string();
    assert!(git(
        dir,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("100644,{blob},{nfc_dir}/.env"),
        ]
    )
    .status
    .success());

    // The index really does hold the precomposed form and nothing else.
    // `core.quotepath=false` keeps Git from octal-escaping the bytes back.
    let listed = git(dir, &["-c", "core.quotepath=false", "ls-files"]);
    let listed = String::from_utf8_lossy(&listed.stdout).trim().to_string();
    assert_eq!(listed, format!("{nfc_dir}/.env"));

    let canonical = dir.canonicalize().unwrap();
    let view = RepoView::open(&canonical).unwrap();
    assert!(view.limits().is_empty(), "{:?}", view.limits());
    assert_eq!(
        view.status_of(&canonical.join(nfd_dir).join(".env")),
        PathStatus::Tracked,
        "a committed .env must not read Untracked because the directory name arrived decomposed"
    );
    assert_eq!(
        view.dir_view(nfd_dir).status_of_name(".env", false),
        PathStatus::Tracked,
        "the per-directory view must agree with the whole-path view"
    );

    // The fold must not collapse names that are genuinely different: an
    // accent-insensitive comparison would report this one Tracked too.
    assert_eq!(
        view.dir_view("cafe").status_of_name(".env", false),
        PathStatus::Untracked,
        "canonical equivalence must not degrade into ignoring accents"
    );
}

/// The `**` evaluator was rewritten from recursion over every split point
/// to the same greedy backtracking `*` already used, because the recursive
/// form explored an exponential search space (RA-009). Rewriting a matcher
/// is exactly the change that needs Git as the oracle rather than the
/// author's belief about what `**` means.
#[test]
fn double_star_patterns_agree_with_git() {
    if !git_available() {
        eprintln!("SKIP: git is not on PATH; the differential fixture needs it");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    init_repo(dir);
    write(
        &dir.join(".gitignore"),
        "**/secret/*.env\n\
         a/**/x.env\n\
         vendor/**\n\
         **/**/twice.env\n\
         logs/**/*.env\n\
         !a/keep/x.env\n",
    );
    let rels = [
        "secret/x.env",
        "a/secret/x.env",
        "a/b/c/secret/x.env",
        "a/secret/deep/x.env",
        "a/x.env",
        "a/b/c/x.env",
        "b/a/x.env",
        "vendor/pkg/deep/x.env",
        "vendor.env",
        "twice.env",
        "p/q/twice.env",
        "logs/x.env",
        "logs/a/b/x.env",
        "a/keep/x.env",
        "plain.env",
    ];
    for rel in rels {
        write(&dir.join(rel), "1\n");
    }
    assert_agrees(dir, &rels);
}
