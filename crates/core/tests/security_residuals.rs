//! Tests for the security-residual closures: master-password change,
//! project-key rotation on password changes, symlink export refusal,
//! orphaned temp-file sweeps, and dead injection-session sweeps.

mod common;

use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, AddCredential};
use common::*;

fn add_cred(v: &mut vault::UnlockedVault, project: &str, name: &str, value: &str) {
    v.add_credential(AddCredential {
        project: project.into(),
        provider: "other".into(),
        name: name.into(),
        environment: Environment::Development,
        value: SecretString::from(value),
        credential_type: None,
        key_created_at: None,
        expires_at: None,
        docs_url: String::new(),
        notes: String::new(),
    })
    .unwrap();
}

#[test]
fn master_password_change_rewraps_and_old_password_stops_working() {
    let (_dir, paths, mut v) = new_vault();
    add_project(&mut v, "app");
    add_cred(&mut v, "app", "k", "FAKE-TEST-NOT-A-REAL-KEY-000001");

    // Wrong current password is rejected; nothing changes.
    assert!(v
        .change_master_password(
            &SecretString::from("wrong-password-123"),
            &SecretString::from("new-master-password-123")
        )
        .is_err());

    v.change_master_password(&master_pw(), &SecretString::from("new-master-password-123"))
        .unwrap();
    drop(v);

    // The old password no longer unlocks; the new one does, and values
    // still decrypt (the vault key itself never changed).
    assert!(vault::unlock_vault(&paths, &master_pw()).is_err());
    let mut v2 =
        vault::unlock_vault(&paths, &SecretString::from("new-master-password-123")).unwrap();
    let revealed = v2
        .reveal_credential("app/k", &SecretString::from("new-master-password-123"))
        .unwrap();
    assert_eq!(revealed.expose(), "FAKE-TEST-NOT-A-REAL-KEY-000001");

    // Too-short new passwords are rejected.
    assert!(v2
        .change_master_password(
            &SecretString::from("new-master-password-123"),
            &SecretString::from("short")
        )
        .is_err());
}

fn credential_ciphertext(
    v: &vault::UnlockedVault,
    paths: &vault::VaultPaths,
    name: &str,
) -> Vec<u8> {
    let _ = v;
    let conn = rusqlite::Connection::open(paths.db_path()).unwrap();
    conn.query_row(
        "SELECT ciphertext FROM credentials WHERE name = ?1",
        [name],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn project_password_changes_rotate_the_project_key() {
    let (_dir, paths, mut v) = new_vault();
    add_project(&mut v, "prod");
    add_cred(&mut v, "prod", "k1", "FAKE-TEST-NOT-A-REAL-KEY-000002");
    // A retained version exists too (value replacement).
    v.replace_credential_value(
        "prod/k1",
        &master_pw(),
        SecretString::from("FAKE-TEST-NOT-A-REAL-KEY-000003"),
    )
    .unwrap();

    let before = credential_ciphertext(&v, &paths, "k1");

    // Setting a password rotates the key: every ciphertext changes.
    let project_pw = SecretString::from("prod-project-password-1");
    v.set_project_password("prod", &project_pw, &master_pw())
        .unwrap();
    let after_set = credential_ciphertext(&v, &paths, "k1");
    assert_ne!(before, after_set, "ciphertext unchanged — key not rotated");

    // Values still decrypt (project is unlocked in this session).
    let revealed = v.reveal_credential("prod/k1", &master_pw()).unwrap();
    assert_eq!(revealed.expose(), "FAKE-TEST-NOT-A-REAL-KEY-000003");
    // The retained version still decrypts through the reauth-gated listing.
    let versions = v
        .credential_version_history("prod/k1", &master_pw())
        .unwrap();
    assert!(!versions.is_empty());

    // A fresh session needs BOTH passwords, exactly as before.
    drop(v);
    let mut v2 = vault::unlock_vault(&paths, &master_pw()).unwrap();
    assert!(v2.reveal_credential("prod/k1", &master_pw()).is_err());
    v2.unlock_project("prod", &project_pw).unwrap();
    assert_eq!(
        v2.reveal_credential("prod/k1", &master_pw())
            .unwrap()
            .expose(),
        "FAKE-TEST-NOT-A-REAL-KEY-000003"
    );

    // Removing the password rotates again.
    let before_remove = credential_ciphertext(&v2, &paths, "k1");
    v2.remove_project_password("prod", &project_pw).unwrap();
    let after_remove = credential_ciphertext(&v2, &paths, "k1");
    assert_ne!(before_remove, after_remove);
    assert_eq!(
        v2.reveal_credential("prod/k1", &master_pw())
            .unwrap()
            .expose(),
        "FAKE-TEST-NOT-A-REAL-KEY-000003"
    );
}

#[cfg(unix)]
#[test]
fn env_export_refuses_symlink_targets() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    add_cred(&mut v, "app", "k", "FAKE-TEST-NOT-A-REAL-KEY-000004");
    v.set_env_mapping("app", "app/k", "MY_VAR").unwrap();

    let out = tempfile::tempdir().unwrap();
    let real = out.path().join("real.env");
    std::fs::write(&real, "").unwrap();
    let link = out.path().join("link.env");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let err = v
        .env_export("app", &link, None, &master_pw(), true, None)
        .unwrap_err();
    assert!(err.to_string().contains("symbolic link"), "got: {err}");
}

#[test]
fn cleanup_sweeps_orphaned_atomic_write_temp_files() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    add_cred(&mut v, "app", "k", "FAKE-TEST-NOT-A-REAL-KEY-000005");
    v.set_env_mapping("app", "app/k", "MY_VAR").unwrap();

    let out = tempfile::tempdir().unwrap();
    let target = out.path().join("app.env");
    v.env_export("app", &target, None, &master_pw(), true, None)
        .unwrap();

    // Simulate a crash between write and rename: an orphaned temp file in
    // the export's directory, older than the sweep threshold.
    let orphan = out.path().join(".app.env.api-tracker-tmp-deadbeef");
    std::fs::write(&orphan, "leftover").unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 3600);
    let file = std::fs::File::options().write(true).open(&orphan).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(old))
        .unwrap();
    drop(file);

    // A fresh one must NOT be raced.
    let fresh = out.path().join(".app.env.api-tracker-tmp-cafef00d");
    std::fs::write(&fresh, "in-flight").unwrap();

    v.env_cleanup(false, false).unwrap();
    assert!(!orphan.exists(), "old orphan was not swept");
    assert!(fresh.exists(), "fresh temp file must not be raced");
    let _ = std::fs::remove_file(&fresh);
}

/// `NEW-29`: the orphan sweep was reachable only from export cleanup, which
/// reads the directories to sweep from `env_exports`. Tracking's link and
/// unlink paths call the same `atomic_write` on the user's `.env` and never
/// write that table, so their orphans — each holding the COMPLETE new file,
/// credential values included — were collected by nothing at all.
#[test]
fn the_orphan_sweep_is_reachable_for_a_directory_no_export_ever_touched() {
    let dir = tempfile::tempdir().unwrap();
    let orphan = dir.path().join("..env.api-tracker-tmp-deadbeef");
    std::fs::write(&orphan, "OPENAI_API_KEY=FAKE-TEST-NOT-A-REAL-KEY-000029\n").unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 3600);
    let file = std::fs::File::options().write(true).open(&orphan).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(old))
        .unwrap();
    drop(file);

    // An in-flight write in another process must never be raced.
    let fresh = dir.path().join("..env.api-tracker-tmp-cafef00d");
    std::fs::write(&fresh, "in-flight").unwrap();
    // Nor may an ordinary file that merely lives beside them.
    let real = dir.path().join(".env");
    std::fs::write(&real, "KEEP=1\n").unwrap();

    api_tracker_core::envgov::sweep_orphaned_temp_files_in(dir.path());

    assert!(!orphan.exists(), "the old orphan was not swept");
    assert!(fresh.exists(), "a fresh temp file must not be raced");
    assert!(real.exists(), "the sweep must touch only temp names");
}

/// The temp name for `.env` is `..env.api-tracker-tmp-<uuid>`, which neither
/// `.env` nor `.env.*` matches. Committing one would publish a complete set
/// of the project's credentials.
#[test]
fn the_atomic_write_temp_name_is_gitignored() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root");
    let ignore = std::fs::read_to_string(root.join(".gitignore")).unwrap();
    assert!(
        ignore.lines().any(|l| l.trim() == ".*.api-tracker-tmp-*"),
        ".gitignore must exclude atomic-write temp files (NEW-29); it reads:\n{ignore}"
    );
}

#[cfg(unix)]
#[test]
fn dead_injection_sessions_are_swept_by_monitor() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");

    // A child that has already exited gives us a definitely-dead PID.
    let child = std::process::Command::new("true").spawn().unwrap();
    let dead_pid = child.id() as i64;
    let _ = std::process::Command::new("true")
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    let mut child = child;
    child.wait().unwrap();

    add_cred(&mut v, "app", "k", "FAKE-TEST-NOT-A-REAL-KEY-000006");
    let (_env, session_id) = v
        .build_injection("app", &[("app/k".into(), "MY_VAR".into())], "test-cmd")
        .unwrap();
    v.record_session_pid(&session_id, dead_pid as u32, None)
        .unwrap();
    let open_before = v.list_process_sessions(50, true).unwrap();
    assert_eq!(open_before.len(), 1);

    v.run_monitor().unwrap();
    let open_after = v.list_process_sessions(50, true).unwrap();
    assert!(
        open_after.is_empty(),
        "dead-PID session row was not closed by the sweep"
    );
}

#[test]
fn stale_cached_project_key_is_rejected_after_rotation() {
    // Two vault instances over the same database: A holds the project
    // unlocked; B changes the project password (rotating the key). A's
    // cached key is now stale and must be REFUSED — not silently used to
    // encrypt new data under a key that no longer has any wrap.
    let (_dir, paths, mut a) = new_vault();
    add_project(&mut a, "prod");
    add_cred(&mut a, "prod", "k1", "FAKE-TEST-NOT-A-REAL-KEY-000007");
    let pw1 = SecretString::from("prod-project-password-1");
    a.set_project_password("prod", &pw1, &master_pw()).unwrap();
    // A has the project unlocked (set keeps it unlocked in-session).

    let mut b = vault::unlock_vault(&paths, &master_pw()).unwrap();
    b.unlock_project("prod", &pw1).unwrap();
    let pw2 = SecretString::from("prod-project-password-2");
    b.set_project_password("prod", &pw2, &master_pw()).unwrap();
    drop(b);

    // A's cached key predates the rotation: adding a credential must fail
    // with ProjectLocked instead of writing unrecoverable ciphertext.
    let err = a
        .add_credential(AddCredential {
            project: "prod".into(),
            provider: "other".into(),
            name: "k2".into(),
            environment: Environment::Development,
            value: SecretString::from("FAKE-TEST-NOT-A-REAL-KEY-000008"),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap_err();
    assert!(
        matches!(err, api_tracker_core::error::CoreError::ProjectLocked(_)),
        "expected ProjectLocked, got: {err}"
    );
    // Re-unlocking with the NEW password restores full function.
    a.unlock_project("prod", &pw2).unwrap();
    assert_eq!(
        a.reveal_credential("prod/k1", &master_pw())
            .unwrap()
            .expose(),
        "FAKE-TEST-NOT-A-REAL-KEY-000007"
    );
}
