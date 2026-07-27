//! ZFT-002 / ZFT-003 / ZFT-028 / ZFT-040 regression suite: what the scan
//! reads, and what it refuses to read.
//!
//! `tests/bounds.rs` already covers depth, the home-directory refusal and a
//! symlinked `.env`. It did NOT cover the two readers disagreeing, which is
//! how the defects got in:
//!
//! * `stackdetect::read_bounded` used `std::fs::metadata` — which follows
//!   symlinks — with no containment check at all, so a symlinked
//!   `package.json` pointing outside the selected folder was read and its
//!   dependencies became auto-selected providers. The existing symlink test
//!   covered only `.env`, then certified the broader bound (ZFT-002).
//! * `envgov::discover` read every `.env*` in full before consulting any
//!   cap: a 64 MB file named `.env` cost 447 MB RSS, and the run reported
//!   "0 file(s) read" while doing it. The existing oversized test exercised
//!   the OTHER reader, which did check its cap, and passed either way
//!   (ZFT-003).
//!
//! Each test here asserts the specific mechanism, not a downstream symptom,
//! so removing the protection fails it (`scripts/mutation_checks.sh`).

mod common;

use api_tracker_core::envgov;
use api_tracker_tracking::detect::{self, ProjectDetection};
use common::*;
use std::path::Path;

fn detect_folder(dir: &Path) -> ProjectDetection {
    let (_db, conn) = test_conn();
    detect::detect(
        &conn,
        &detect::DetectionInput {
            folder: dir,
            project_id: None,
        },
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// ZFT-002 — nothing outside the selected folder is read
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_symlinked_package_manifest_outside_the_folder_is_never_read() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        outside.join("secret-package.json"),
        r#"{"dependencies":{"openai":"^4","@anthropic-ai/sdk":"^0.30"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(
        outside.join("secret-package.json"),
        proj.join("package.json"),
    )
    .unwrap();
    std::fs::write(proj.join(".env"), "# no keys here\n").unwrap();

    let detection = detect_folder(&proj);
    assert!(
        detection.providers.is_empty(),
        "the folder contains NO provider content of its own; everything here came \
         from outside it: {:?}",
        detection
            .providers
            .iter()
            .map(|p| &p.provider_id)
            .collect::<Vec<_>>()
    );
    assert!(
        detection.accounting.skipped_outside_folder >= 1,
        "the refusal must be COUNTED, not silent: {:?}",
        detection.accounting
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_python_manifest_outside_the_folder_is_never_read() {
    for (name, content) in [
        ("requirements.txt", "openai==1.2.3\n"),
        (
            "pyproject.toml",
            "[project]\ndependencies = [\"stripe>=1.0\"]\n",
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(outside.join(name), content).unwrap();
        std::os::unix::fs::symlink(outside.join(name), proj.join(name)).unwrap();

        let detection = detect_folder(&proj);
        assert!(
            detection.providers.is_empty(),
            "{name}: content from outside the folder became a detection: {:?}",
            detection
                .providers
                .iter()
                .map(|p| &p.provider_id)
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_marker_file_does_not_assert_facts_about_outside_content() {
    // `Path::is_file`/`is_dir` follow symlinks too. A symlinked Dockerfile
    // pointing outside the folder must not change the restart guidance.
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(outside.join("Dockerfile"), "FROM scratch\n").unwrap();
    std::os::unix::fs::symlink(outside.join("Dockerfile"), proj.join("Dockerfile")).unwrap();
    std::fs::write(proj.join(".env"), "OPENAI_API_KEY=sk-proj-FAKE0000000000\n").unwrap();

    let detection = detect_folder(&proj);
    assert!(
        !detection.project_signals.dockerfile,
        "a symlinked marker must not assert a fact about content outside the folder"
    );
}

#[cfg(unix)]
#[test]
fn a_real_manifest_inside_the_folder_is_still_read() {
    // The control. Every assertion above would also pass if the reader had
    // simply stopped reading manifests.
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"dependencies":{"openai":"^4"}}"#,
    )
    .unwrap();
    std::fs::write(
        proj.join(".env"),
        "OPENAI_API_KEY=sk-proj-FAKE000000000000000000000000000000\n",
    )
    .unwrap();

    let detection = detect_folder(&proj);
    assert!(
        detection
            .providers
            .iter()
            .any(|p| p.provider_id == "openai"),
        "a REAL manifest inside the folder must still be read: {:?}",
        detection.providers
    );
    assert_eq!(detection.accounting.skipped_outside_folder, 0);
}

// ---------------------------------------------------------------------------
// ZFT-003 — an oversized `.env` never enters memory
// ---------------------------------------------------------------------------

#[test]
fn an_oversized_env_file_is_never_read_into_memory() {
    let tmp = tempfile::tempdir().unwrap();
    let big = tmp.path().join(".env");
    // One byte over the cap is enough: the assertion is about WHERE the
    // check happens, not about how much memory a huge file would cost.
    let limits = envgov::DiscoveryLimits::default();
    let size = (limits.max_file_bytes + 1) as usize;
    std::fs::write(&big, "A=1\n".repeat(size / 4 + 1)).unwrap();
    assert!(std::fs::metadata(&big).unwrap().len() > limits.max_file_bytes);

    let report = envgov::discover_bounded(tmp.path(), limits, envgov::HistoryProbe::Skip).unwrap();

    let entry = report
        .files
        .iter()
        .find(|f| f.rel_path == ".env")
        .expect("the file is still INVENTORIED — it is not hidden, only unread");
    assert!(entry.oversized, "it must be marked oversized");
    assert_eq!(
        entry.entry_count, 0,
        "an entry count > 0 could only come from having parsed the file — which \
         means its bytes were read"
    );
    assert!(
        entry.problems.is_empty(),
        "problems could only come from having parsed the file"
    );
    assert!(
        report.skipped_oversized.contains(&".env".to_string()),
        "the skip must be reported: {:?}",
        report.skipped_oversized
    );
}

#[test]
fn an_oversized_env_file_is_counted_by_the_tracking_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let size = (envgov::DiscoveryLimits::default().max_file_bytes + 1) as usize;
    std::fs::write(tmp.path().join(".env"), "A=1\n".repeat(size / 4 + 1)).unwrap();

    let detection = detect_folder(tmp.path());
    assert!(
        detection.accounting.skipped_oversized >= 1,
        "the review screen must be able to say the file was skipped: {:?}",
        detection.accounting
    );
    assert!(
        detection
            .accounting
            .describe_gaps()
            .is_some_and(|g| g.contains("too large")),
        "and it must say so in words: {:?}",
        detection.accounting.describe_gaps()
    );
}

#[test]
fn an_env_file_just_under_the_cap_is_still_read() {
    // The control: the cap must not have become "read nothing".
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(".env"), "OPENAI_API_KEY=sk-proj-FAKE0000\n").unwrap();
    let report = envgov::discover_bounded(
        tmp.path(),
        envgov::DiscoveryLimits::default(),
        envgov::HistoryProbe::Skip,
    )
    .unwrap();
    let entry = report.files.iter().find(|f| f.rel_path == ".env").unwrap();
    assert!(!entry.oversized);
    assert_eq!(entry.entry_count, 1, "a normal file is still parsed");
    assert!(report.skipped_oversized.is_empty());
}

// ---------------------------------------------------------------------------
// ZFT-028 — the walk is bounded in more than depth
// ---------------------------------------------------------------------------

#[test]
fn the_file_budget_stops_the_walk_and_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    for i in 0..40 {
        let dir = tmp.path().join(format!("svc{i:03}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), "A=1\n").unwrap();
    }
    let limits = envgov::DiscoveryLimits {
        max_files: 10,
        ..envgov::DiscoveryLimits::default()
    };
    let report = envgov::discover_bounded(tmp.path(), limits, envgov::HistoryProbe::Skip).unwrap();
    assert!(report.files.len() <= 10);
    assert_eq!(
        report.truncated,
        Some(envgov::DiscoveryTruncation::FileBudget),
        "a truncated scan must never be presented as a complete one"
    );
    assert!(report
        .truncated
        .unwrap()
        .describe()
        .contains("were not inspected"));
}

#[test]
fn an_ordinary_project_is_never_truncated() {
    // The control: the budgets must be generous enough that a real project
    // never trips them.
    let tmp = tempfile::tempdir().unwrap();
    for i in 0..12 {
        let dir = tmp.path().join(format!("packages/app{i}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), "A=1\nB=2\n").unwrap();
    }
    let report = envgov::discover_bounded(
        tmp.path(),
        envgov::DiscoveryLimits::default(),
        envgov::HistoryProbe::Skip,
    )
    .unwrap();
    assert_eq!(report.truncated, None);
    assert_eq!(report.files.len(), 12);
}

// ---------------------------------------------------------------------------
// ZFT-040 — a file that exists but cannot be decoded is counted
// ---------------------------------------------------------------------------

#[test]
fn a_non_utf8_manifest_is_counted_not_silently_dropped() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    // Valid UTF-8 would parse; these bytes cannot be decoded at all.
    std::fs::write(proj.join("package.json"), [0xff, 0xfe, 0x00, 0x01, 0xff]).unwrap();
    std::fs::write(proj.join(".env"), "OPENAI_API_KEY=sk-proj-FAKE0000\n").unwrap();

    let detection = detect_folder(&proj);
    assert!(
        detection.accounting.skipped_not_utf8 >= 1,
        "a file that exists and is in bounds but cannot be decoded must be counted, \
         not vanish: {:?}",
        detection.accounting
    );
    assert!(detection
        .accounting
        .describe_gaps()
        .is_some_and(|g| g.contains("not readable as text")));
}
