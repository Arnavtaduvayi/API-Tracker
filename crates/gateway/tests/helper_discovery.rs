//! Packaged-helper discovery (PACKAGING_PLAN §3, TEST_PLAN §"packaged
//! resources"): the bundled-sidecar candidate path, and the exec-probe
//! gate against missing, corrupted, impostor, and version-drifted
//! helpers. Uses the real `HostRunner` with stub scripts — no network, no
//! real service, nothing outside the temp dir.

#![cfg(unix)]

use api_tracker_gateway::lifecycle::{
    bundled_helper_candidate, helper_answers_probe, HostRunner, PROBE_MARKER,
};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

fn write_stub(path: &Path, body: &str, mode: u32) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn the_candidate_sits_beside_the_executable() {
    let exe = Path::new("/Applications/Tethra.app/Contents/MacOS/api-tracker-desktop");
    let candidate = bundled_helper_candidate(exe).unwrap();
    assert_eq!(
        candidate,
        Path::new("/Applications/Tethra.app/Contents/MacOS/tethra")
    );
    // A rootless path (no parent) has no candidate rather than a panic.
    assert!(bundled_helper_candidate(Path::new("/")).is_none());
}

#[test]
fn a_missing_helper_fails_discovery() {
    let dir = TempDir::new().unwrap();
    let candidate = dir.path().join("tethra");
    assert!(!helper_answers_probe(&HostRunner, &candidate));
}

#[test]
fn a_genuine_helper_passes_the_probe() {
    let dir = TempDir::new().unwrap();
    let candidate = dir.path().join("tethra");
    write_stub(
        &candidate,
        &format!("#!/bin/sh\necho '{PROBE_MARKER} 0.1.0'\n"),
        0o755,
    );
    assert!(helper_answers_probe(&HostRunner, &candidate));
}

#[test]
fn a_corrupted_helper_fails_the_probe() {
    let dir = TempDir::new().unwrap();
    // Garbage bytes with the executable bit: exec fails.
    let corrupted = dir.path().join("tethra");
    write_stub(&corrupted, "\u{0}\u{1}not an executable\u{2}", 0o755);
    assert!(!helper_answers_probe(&HostRunner, &corrupted));
    // Valid script WITHOUT the executable bit: also refused.
    let unexecutable = dir.path().join("tethra2");
    write_stub(
        &unexecutable,
        &format!("#!/bin/sh\necho '{PROBE_MARKER}'\n"),
        0o644,
    );
    assert!(!helper_answers_probe(&HostRunner, &unexecutable));
}

#[test]
fn an_impostor_binary_without_the_marker_is_refused() {
    let dir = TempDir::new().unwrap();
    let impostor = dir.path().join("tethra");
    write_stub(&impostor, "#!/bin/sh\necho 'i am not tethra'\n", 0o755);
    assert!(!helper_answers_probe(&HostRunner, &impostor));
    // Exit-code honesty: marker printed but nonzero exit is still a refusal.
    let failing = dir.path().join("tethra3");
    write_stub(
        &failing,
        &format!("#!/bin/sh\necho '{PROBE_MARKER}'\nexit 3\n"),
        0o755,
    );
    assert!(!helper_answers_probe(&HostRunner, &failing));
}

#[test]
fn a_version_drifted_helper_still_passes_discovery() {
    // Drift is repaired by the tracking apply step (O-22-2) and surfaced
    // by doctor — discovery must not hide a runnable helper over it.
    let dir = TempDir::new().unwrap();
    let stale = dir.path().join("tethra");
    write_stub(
        &stale,
        &format!("#!/bin/sh\necho '{PROBE_MARKER} 0.0.1-ancient'\n"),
        0o755,
    );
    assert!(helper_answers_probe(&HostRunner, &stale));
}
