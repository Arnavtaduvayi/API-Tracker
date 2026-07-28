//! Packaged-helper discovery (PACKAGING_PLAN §3, TEST_PLAN §"packaged
//! resources"): the bundled-sidecar candidate path, and the exec-probe
//! gate against missing, corrupted, impostor, and version-drifted
//! helpers. Uses the real `HostRunner` with stub scripts — no network, no
//! real service, nothing outside the temp dir.

#![cfg(unix)]

use api_tracker_gateway::lifecycle::{
    bundled_helper_candidate, helper_answers_probe, CommandRunner, HostRunner, PROBE_MARKER,
};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

fn write_stub(path: &Path, body: &str, mode: u32) {
    // Written, flushed and CLOSED before the mode is set, so no writable
    // descriptor to this file outlives this call in THIS thread. See
    // `probe_expecting_success` for why that is not sufficient on its own.
    {
        use std::io::Write;
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.sync_all().unwrap();
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Probe a stub that MUST answer, tolerating the write-then-exec race.
///
/// `a_genuine_helper_passes_the_probe` failed once in CI (run 30327166597) on
/// code identical to a green run — a flake, not a regression. The mechanism is
/// `ETXTBSY`: these tests run as threads in ONE process, and `fork`/`posix_spawn`
/// gives the child a copy of every descriptor open at that instant. While
/// thread A sits between creating its stub and closing it, thread B can spawn;
/// B's child then holds a writable descriptor to A's file until it execs, and
/// A's own exec in that window returns "Text file busy". Closing the file
/// promptly (above) narrows the window; it cannot close it, because the race is
/// between threads.
///
/// So a negative result is retried briefly, and ONLY where the expected answer
/// is `true`. The negative cases below must never retry: a "must be refused"
/// assertion that retries until it agrees is not an assertion.
///
/// The retry does not weaken the test. A genuinely broken helper returns false
/// on every attempt and still fails, one second later. What it removes is a
/// required check that goes red for a reason unrelated to the product — which,
/// on a branch whose entire subject is evidence integrity, is worth more than
/// the second it costs.
fn probe_expecting_success(candidate: &Path) -> bool {
    for _ in 0..20 {
        if helper_answers_probe(&HostRunner, candidate) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // Surface WHY, once, instead of a bare `assertion failed`. The product's
    // `helper_answers_probe` deliberately collapses every failure to `false`
    // (`unwrap_or(false)`), which is right for a discovery predicate and
    // useless for a post-mortem — the CI failure above reported nothing but
    // the assertion line.
    let direct = HostRunner.run(
        &candidate.display().to_string(),
        &["gateway", "service-probe"],
    );
    eprintln!(
        "probe never succeeded for {}; last direct result: {direct:?}",
        candidate.display()
    );
    false
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
    assert!(probe_expecting_success(&candidate));
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
    assert!(probe_expecting_success(&stale));
}
