//! The security-critical detection-bounds suite (TEST_PLAN §2): scan
//! boundaries are pinned by tests, not by prose.

mod common;

use api_tracker_tracking::detect::{detect, Configurability, DetectionInput};
use common::*;
use std::path::Path;
use tempfile::TempDir;

fn try_detect(
    conn: &rusqlite::Connection,
    folder: &Path,
) -> api_tracker_core::Result<api_tracker_tracking::detect::ProjectDetection> {
    detect(
        conn,
        &DetectionInput {
            folder,
            project_id: None,
        },
    )
}

#[test]
fn refuses_the_filesystem_root() {
    let (_db, conn) = test_conn();
    let err = try_detect(&conn, Path::new("/")).unwrap_err();
    // The root must never be scanned. Either honest refusal counts: the
    // bound itself ("refusing to scan"), or an inability to open it at
    // all on a platform where "/" is not a real directory. What must
    // NOT happen is a successful scan.
    let text = err.to_string();
    assert!(
        text.contains("refusing to scan") || text.contains("cannot access"),
        "{text}"
    );
}

#[test]
fn refuses_the_home_directory_and_its_container() {
    let (_db, conn) = test_conn();
    let Some(home) = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
    else {
        // No home variable in this environment: the refusal cannot be
        // exercised, and pretending otherwise would be a vacuous pass.
        eprintln!("skipped: neither HOME nor USERPROFILE is set");
        return;
    };
    let err = try_detect(&conn, Path::new(&home)).unwrap_err();
    assert!(err.to_string().contains("refusing to scan"), "{err}");
    // The container of home directories, via a path that canonicalizes to
    // it (bounds must hold post-canonicalization).
    let users = Path::new(&home).parent().unwrap().to_path_buf();
    if users
        .parent()
        .map(|p| p.parent().is_none())
        .unwrap_or(false)
    {
        let dodged = users.join("..").join(users.file_name().unwrap());
        let err = try_detect(&conn, &dodged).unwrap_err();
        assert!(err.to_string().contains("refusing to scan"), "{err}");
    }
}

/// Unix-only: `std::os::unix::fs::symlink` has no portable equivalent, and
/// creating a symlink on Windows needs elevation or developer mode. The
/// bound it proves (never read through a symlink out of the folder) is
/// enforced by the same `symlink_metadata` check on every platform.
#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_folder_is_never_followed() {
    let (_db, conn) = test_conn();
    let outside = TempDir::new().unwrap();
    let secret_path = outside.path().join("outside.env");
    std::fs::write(&secret_path, format!("OPENAI_API_KEY={CANARY}12345678\n")).unwrap();

    let dir = TempDir::new().unwrap();
    std::os::unix::fs::symlink(&secret_path, dir.path().join(".env")).unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("linked-dir")).unwrap();

    let detection = try_detect(&conn, dir.path()).unwrap();
    let serialized = serde_json::to_string(&detection).unwrap();
    assert!(
        !serialized.contains(CANARY),
        "a symlinked file's content leaked into detection"
    );
    assert!(
        detection.providers.is_empty(),
        "no provider may be detected through a symlink escape"
    );
}

#[test]
fn depth_cap_is_honored() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    // envgov::discover walks depth ≤ 6; a file at depth 7 must be invisible.
    let deep = dir.path().join("a/b/c/d/e/f/g");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(
        deep.join(".env"),
        format!("OPENAI_API_KEY={FAKE_OPENAI_KEY}\n"),
    )
    .unwrap();
    let detection = try_detect(&conn, dir.path()).unwrap();
    assert!(
        detection.providers.is_empty(),
        "a depth-7 .env must not be scanned"
    );
}

#[test]
fn oversized_files_are_counted_not_silently_ignored() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    let big = "x".repeat(300 * 1024);
    std::fs::write(dir.path().join("package-lock.json"), &big).unwrap();
    let detection = try_detect(&conn, dir.path()).unwrap();
    assert!(
        detection.skipped_oversized >= 1,
        "an oversized lockfile must be counted as skipped"
    );
}

#[test]
fn env_files_are_parsed_never_executed() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    let pwned = dir.path().join("pwned");
    write_project(
        dir.path(),
        &[(
            ".env",
            "OPENAI_API_KEY=$(touch pwned)\nOTHER=`touch pwned`\n",
        )],
    );
    let _ = try_detect(&conn, dir.path()).unwrap();
    assert!(
        !pwned.exists(),
        ".env content was executed — parse-only invariant broken"
    );
}

#[test]
fn secret_classified_vars_are_never_value_read_for_origins() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    // A URL planted in a SECRET var must never become an origin candidate.
    write_project(
        dir.path(),
        &[(
            ".env",
            "SUPABASE_SERVICE_ROLE_KEY=https://attacker.example\nSUPABASE_URL=https://xyzcompany.supabase.co\n",
        )],
    );
    let detection = try_detect(&conn, dir.path()).unwrap();
    let serialized = serde_json::to_string(&detection).unwrap();
    assert!(
        !serialized.contains("attacker.example"),
        "a secret var's value was read for origin inference"
    );
}

#[test]
fn invalid_origins_are_rejected_never_auto_confirmed() {
    let (_db, conn) = test_conn();
    for bad in [
        "http://xyzcompany.supabase.co",       // not https
        "https://xyzcompany.supabase.co:8080", // non-443 port
        "https://127.0.0.1",                   // loopback
        "https://10.0.0.8",                    // RFC1918
        "https://169.254.169.254",             // cloud metadata
    ] {
        let dir = TempDir::new().unwrap();
        write_project(dir.path(), &[(".env", &format!("SUPABASE_URL={bad}\n"))]);
        let detection = try_detect(&conn, dir.path()).unwrap();
        let supabase = detection
            .providers
            .iter()
            .find(|p| p.provider_id == "supabase");
        if let Some(supabase) = supabase {
            assert_eq!(
                supabase.configurability,
                Configurability::NeedsOriginInput,
                "{bad} must not be auto-confirmable"
            );
        }
    }
}

#[test]
fn detection_source_makes_no_network_calls() {
    // Source-level guard, mirroring the gateway's no_insecure_verifier
    // pattern: the detection module must contain no socket, resolver, or
    // HTTP-client construct. (The verify module's keyless probe is the one
    // sanctioned network act in this crate, and only through the local
    // gateway.)
    let src = include_str!("../src/detect.rs");
    for needle in [
        "TcpStream",
        "UdpSocket",
        "ToSocketAddrs",
        "reqwest",
        "ureq",
        "hyper",
        "curl",
    ] {
        assert!(!src.contains(needle), "detect.rs must not contain {needle}");
    }
}
