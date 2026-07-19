//! Direct authorization coverage for the security-sensitive Tauri command
//! layer.
//!
//! The Tauri command wrappers in `apps/desktop/src-tauri/src/main.rs` are
//! thin: each `#[tauri::command]` unlocks the vault via `with_vault` and
//! then calls a method on `UnlockedVault` (in `crates/core`). Authorization
//! for every destructive or secret-bearing command is enforced INSIDE that
//! core method via `verify_master_password` (or a project-password KDF
//! unwrap), NOT in the wrapper and NOT in React. This suite invokes those
//! exact core methods — the backend path a hostile `invoke` reaches without
//! any UI sequencing — and asserts:
//!
//!   * missing/incorrect reauthentication is refused (`WrongPassword`);
//!   * correct reauthentication succeeds;
//!   * malformed IDs/paths are refused cleanly (no panic, no secret leak);
//!   * error messages never contain the secret value.
//!
//! It does NOT duplicate the production authorization rules; it asserts on
//! the real behavior of the shared core the commands delegate to. The
//! machine-readable command inventory in
//! `docs/remediation-phase-2/tauri_command_inventory.json` records, for
//! every one of the 137 commands, whether enforcement is in core (tested
//! here) or in the wrapper.

mod common;

use api_tracker_core::error::CoreError;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use common::{add_key, add_project, master_pw, new_vault, FAKE_KEY_1};

const WRONG_PW: &str = "not-the-master-password";
const SECRET: &str = "FAKE-TEST-NOT-A-REAL-KEY-SECRET01";

fn wrong() -> SecretString {
    SecretString::from(WRONG_PW)
}

/// Every message an error produces over IPC must be free of the secret.
fn assert_no_secret_leak(err: &CoreError, secret: &str) {
    let msg = err.to_string();
    assert!(
        !msg.contains(secret),
        "error message leaked the secret value: {msg}"
    );
    // The `#` alternate form is what the desktop stringifies over IPC.
    let alt = format!("{err:#}");
    assert!(!alt.contains(secret), "alt error leaked the secret: {alt}");
}

// ------------------------------------------------------------ credential ops

#[test]
fn credential_reveal_requires_correct_reauth() {
    // Commands: credential_reveal (52), credential_copy (53).
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(&mut vault, "app", "k", SECRET, Environment::Production);

    let err = vault.reveal_credential(&cred.id, &wrong()).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert_no_secret_leak(&err, SECRET);

    let value = vault.reveal_credential(&cred.id, &master_pw()).unwrap();
    assert_eq!(value.expose(), SECRET);

    // Malformed selector: clean NotFound, never a panic or a leak.
    let err = vault
        .reveal_credential("no/such/cred", &master_pw())
        .unwrap_err();
    assert!(matches!(err, CoreError::NotFound { .. }), "{err:?}");
    assert_no_secret_leak(&err, SECRET);
}

#[test]
fn credential_delete_requires_correct_reauth() {
    // Command: credential_delete (51) — IPC-02 (delete without core reauth).
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(&mut vault, "app", "k", SECRET, Environment::Production);

    let err = vault.delete_credential(&cred.id, &wrong()).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    // The credential must survive a failed-auth delete.
    assert!(vault.get_credential(&cred.id).is_ok());

    vault.delete_credential(&cred.id, &master_pw()).unwrap();
    assert!(vault.get_credential(&cred.id).is_err());
}

#[test]
fn credential_replace_value_requires_correct_reauth() {
    // Command: credential_replace_value (50).
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(&mut vault, "app", "k", SECRET, Environment::Production);
    let new_secret = "FAKE-TEST-NOT-A-REAL-KEY-SECRET02";

    let err = vault
        .replace_credential_value(&cred.id, &wrong(), SecretString::from(new_secret))
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert_no_secret_leak(&err, new_secret);
    // The old value is unchanged.
    assert_eq!(
        vault
            .reveal_credential(&cred.id, &master_pw())
            .unwrap()
            .expose(),
        SECRET
    );

    vault
        .replace_credential_value(&cred.id, &master_pw(), SecretString::from(new_secret))
        .unwrap();
    assert_eq!(
        vault
            .reveal_credential(&cred.id, &master_pw())
            .unwrap()
            .expose(),
        new_secret
    );
}

#[test]
fn credential_versions_require_correct_reauth() {
    // Command: credential_versions (99).
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(&mut vault, "app", "k", SECRET, Environment::Production);
    let err = vault
        .credential_version_history(&cred.id, &wrong())
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert!(vault
        .credential_version_history(&cred.id, &master_pw())
        .is_ok());
}

// ------------------------------------------------------------- passwords

#[test]
fn master_password_change_requires_correct_current() {
    // Command: vault_change_password (6).
    let (_d, _p, mut vault) = new_vault();
    let err = vault
        .change_master_password(&wrong(), &SecretString::from("brand-new-pass"))
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    // The original password still works.
    assert!(vault.verify_master_password(&master_pw()).is_ok());

    vault
        .change_master_password(&master_pw(), &SecretString::from("brand-new-pass"))
        .unwrap();
    assert!(vault
        .verify_master_password(&SecretString::from("brand-new-pass"))
        .is_ok());
}

#[test]
fn project_password_set_requires_master_reauth() {
    // Command: project_set_password (39).
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let proj_pw = SecretString::from("project-secret-pw");
    let err = vault
        .set_project_password("app", &proj_pw, &wrong())
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    vault
        .set_project_password("app", &proj_pw, &master_pw())
        .unwrap();
}

#[test]
fn project_password_remove_requires_the_project_password() {
    // Command: project_remove_password (40) — auth is the project pw KDF unwrap.
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let proj_pw = SecretString::from("project-secret-pw");
    vault
        .set_project_password("app", &proj_pw, &master_pw())
        .unwrap();
    // Wrong project password cannot remove the lock.
    let err = vault
        .remove_project_password("app", &SecretString::from("wrong-project-pw"))
        .unwrap_err();
    assert!(
        matches!(
            err,
            CoreError::WrongPassword | CoreError::InvalidInput(_) | CoreError::Crypto { .. }
        ),
        "{err:?}"
    );
    vault.remove_project_password("app", &proj_pw).unwrap();
}

// --------------------------------------------------- filesystem-writing cmds

#[test]
fn env_example_write_requires_reauth_and_confines_path() {
    // Command: env_example_write (95) — IPC-01/FS-09.
    let (_d, _p, mut vault) = new_vault();
    let project = add_project(&mut vault, "app");
    // Register a repo so the confinement has a valid root.
    let repo = tempfile::tempdir().unwrap();
    vault
        .update_project(
            &project.id,
            api_tracker_core::vault::UpdateProject {
                add_repo_paths: vec![repo.path().to_string_lossy().into_owned()],
                ..Default::default()
            },
        )
        .unwrap();
    let target = repo.path().join(".env.example");

    // Wrong password: refused, and nothing written.
    let err = vault
        .env_example_write("app", &target, "X=1\n", &wrong())
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert!(
        !target.exists(),
        "a failed-auth write must not touch the file"
    );

    // Correct password: writes the confined .env.example.
    vault
        .env_example_write("app", &target, "X=1\n", &master_pw())
        .unwrap();
    assert!(target.exists());

    // Out-of-tree path is refused even with correct reauth.
    let outside = tempfile::tempdir().unwrap();
    let escape = outside.path().join(".env.example");
    let err = vault
        .env_example_write("app", &escape, "X=1\n", &master_pw())
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
    assert!(!escape.exists());
}

#[test]
fn plaintext_export_requires_reauth() {
    // Command: env_export (96) — writes plaintext secrets to disk.
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (_c, _) = add_key(&mut vault, "app", "k", SECRET, Environment::Production);
    vault.set_env_mapping("app", "k", "OPENAI_API_KEY").unwrap();
    let out = tempfile::tempdir().unwrap();
    let path = out.path().join(".env");

    let err = vault
        .env_export("app", &path, None, &wrong(), false, None)
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert!(
        !path.exists(),
        "no plaintext file may be written on failed auth"
    );
    assert_no_secret_leak(&err, SECRET);

    vault
        .env_export("app", &path, None, &master_pw(), false, None)
        .unwrap();
    assert!(path.exists());
    // Clean up the plaintext export immediately.
    vault.env_cleanup(true, true).unwrap();
}

// ------------------------------------------------------------- backup restore

#[test]
fn backup_restore_requires_the_backup_password() {
    // Command: backup_restore (56) — replaces the vault; callable while locked,
    // so the backup password is the authorization.
    use api_tracker_core::backup;
    let (_d, _p, vault) = new_vault();
    let backup_pw = SecretString::from("backup-secret-pw");
    let backup_dir = tempfile::tempdir().unwrap();
    let backup_path = backup_dir.path().join("vault.backup");
    backup::create_backup(&vault, &backup_path, &backup_pw, false).unwrap();
    drop(vault);

    // Verify with the wrong password is refused.
    let err = backup::verify_backup(&backup_path, &wrong()).unwrap_err();
    // A wrong backup password fails AEAD verification (Crypto) — the whole
    // point is that it is indistinguishable from tampering/corruption.
    assert!(
        matches!(
            err,
            CoreError::WrongPassword | CoreError::InvalidInput(_) | CoreError::Crypto { .. }
        ),
        "{err:?}"
    );

    // Restore into a fresh location with the wrong password is refused.
    let restore_dir = tempfile::tempdir().unwrap();
    let target = api_tracker_core::vault::VaultPaths::new(restore_dir.path().join("data"));
    let err = backup::restore_backup(&backup_path, &wrong(), &target, false).unwrap_err();
    // A wrong backup password fails AEAD verification (Crypto) — the whole
    // point is that it is indistinguishable from tampering/corruption.
    assert!(
        matches!(
            err,
            CoreError::WrongPassword | CoreError::InvalidInput(_) | CoreError::Crypto { .. }
        ),
        "{err:?}"
    );
    assert!(
        !target.vault_exists(),
        "no vault must be written on failed auth"
    );

    // Correct password restores.
    backup::restore_backup(&backup_path, &backup_pw, &target, false).unwrap();
    assert!(target.vault_exists());
}

// -------------------------------------------------------------- destinations

#[test]
fn destination_remove_requires_reauth() {
    // Command: destination_remove (102).
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    vault
        .destination_add(
            "github_actions",
            "ci",
            serde_json::json!({"owner": "o", "repo": "r"}),
            Some(&SecretString::from(
                "ghp_FAKE0000000000000000000000000000000000",
            )),
        )
        .unwrap();
    let err = vault.destination_remove("ci", &wrong()).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert_eq!(vault.destination_list().unwrap().len(), 1, "not removed");
    vault.destination_remove("ci", &master_pw()).unwrap();
    assert!(vault.destination_list().unwrap().is_empty());
}

#[test]
fn destination_delete_secret_requires_reauth() {
    // Command: destination_delete_secret (105) — remote delete.
    use api_tracker_core::destinations::CommandRunner;
    struct NullRunner;
    impl CommandRunner for NullRunner {
        fn run(
            &self,
            _p: &str,
            _a: &[&str],
            _s: Option<&[u8]>,
        ) -> api_tracker_core::error::Result<(i32, Vec<u8>, Vec<u8>)> {
            Ok((0, Vec::new(), Vec::new()))
        }
    }
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    vault
        .destination_add(
            "github_actions",
            "ci",
            serde_json::json!({"owner": "o", "repo": "r"}),
            Some(&SecretString::from(
                "ghp_FAKE0000000000000000000000000000000000",
            )),
        )
        .unwrap();
    // Wrong password must be refused BEFORE any network/delete happens: no
    // HTTP responses are queued, so a bypass would error differently.
    let http = api_tracker_core::http::MockHttpClient::new(vec![]);
    let err = vault
        .destination_delete_secret("ci", "SECRET_NAME", &wrong(), &http, &NullRunner)
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert!(
        http.last_request().is_none(),
        "reauth must be verified before any destination request"
    );
}

// ---------------------------------------------------------- provider connect

#[test]
fn provider_admin_disconnect_requires_reauth_in_core() {
    // Command: provider_admin_disconnect (62). Reauth is now enforced in
    // core (moved out of the wrapper this phase), so a direct invoke cannot
    // delete the provider connection without the master password.
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "admin",
        FAKE_KEY_1,
        Environment::Production,
    );
    vault
        .provider_admin_connect("openai", &SecretString::from(FAKE_KEY_1), None, None)
        .ok();
    let _ = cred;

    let err = vault
        .provider_admin_disconnect("openai", &wrong())
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    // Still connected after a failed-auth disconnect.
    assert!(
        vault
            .provider_connection_status("openai")
            .unwrap()
            .connected,
        "a failed-auth disconnect must not remove the connection"
    );
    vault
        .provider_admin_disconnect("openai", &master_pw())
        .unwrap();
    assert!(
        !vault
            .provider_connection_status("openai")
            .unwrap()
            .connected
    );
}

// -------------------------------------------------------------- rotation

/// Helper: build an approved-manual rotation to exercise the reauth guards.
fn rotation_setup() -> (
    tempfile::TempDir,
    api_tracker_core::vault::VaultPaths,
    api_tracker_core::vault::UnlockedVault,
    String,
) {
    let (d, p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(&mut vault, "app", "k", SECRET, Environment::Production);
    let rotation = vault.rotation_plan(&cred.id, 0, None, None, "").unwrap();
    (d, p, vault, rotation.rotation.id)
}

#[test]
fn rotation_approve_and_cancel_require_reauth() {
    // Commands: rotation_approve (116), rotation_cancel (120).
    let (_d, _p, vault, id) = rotation_setup();
    let err = vault.rotation_approve(&id, &wrong()).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    let err = vault.rotation_cancel(&id, &wrong()).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    // Correct password is accepted (approve).
    vault.rotation_approve(&id, &master_pw()).unwrap();
}

#[test]
fn rotation_manual_completion_requires_reauth() {
    // Command: rotation_complete_manual (119).
    let (_d, _p, vault, id) = rotation_setup();
    let err = vault
        .rotation_complete_manual(&id, &wrong(), "done")
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
}

#[test]
fn rotation_advance_and_rollback_require_reauth() {
    // Commands: rotation_advance (117), rotation_rollback (118).
    use api_tracker_core::destinations::CommandRunner;
    struct NullRunner;
    impl CommandRunner for NullRunner {
        fn run(
            &self,
            _p: &str,
            _a: &[&str],
            _s: Option<&[u8]>,
        ) -> api_tracker_core::error::Result<(i32, Vec<u8>, Vec<u8>)> {
            Ok((0, Vec::new(), Vec::new()))
        }
    }
    let (_d, _p, mut vault, id) = rotation_setup();
    let http = api_tracker_core::http::MockHttpClient::new(vec![]);
    let err = vault
        .rotation_advance(&id, &wrong(), &http, &NullRunner, None, false)
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    let err = vault
        .rotation_rollback(&id, &wrong(), &http, &NullRunner, false)
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert!(
        http.last_request().is_none(),
        "reauth must precede any provider mutation"
    );
}

// ---------------------------------------------------- sync plan execution

#[test]
fn sync_plan_execute_requires_reauth() {
    // Command: sync_plan_execute (113) — pushes secrets to remote destinations.
    use api_tracker_core::destinations::CommandRunner;
    struct NullRunner;
    impl CommandRunner for NullRunner {
        fn run(
            &self,
            _p: &str,
            _a: &[&str],
            _s: Option<&[u8]>,
        ) -> api_tracker_core::error::Result<(i32, Vec<u8>, Vec<u8>)> {
            Ok((0, Vec::new(), Vec::new()))
        }
    }
    let (_d, _p, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(&mut vault, "app", "k", SECRET, Environment::Production);
    vault
        .destination_add(
            "github_actions",
            "ci",
            serde_json::json!({"owner": "o", "repo": "r"}),
            Some(&SecretString::from(
                "ghp_FAKE0000000000000000000000000000000000",
            )),
        )
        .unwrap();
    vault
        .destination_attach(&cred.id, "ci", "K", "production")
        .unwrap();
    vault
        .replace_credential_value(
            &cred.id,
            &master_pw(),
            SecretString::from("FAKE-TEST-NOT-A-REAL-KEY-SECRET03"),
        )
        .unwrap();
    let plan = vault.sync_plan_create(&cred.id, "").unwrap();

    let http = api_tracker_core::http::MockHttpClient::new(vec![]);
    let err = vault
        .sync_plan_execute(&plan.id, None, &wrong(), &http, &NullRunner)
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert!(
        http.last_request().is_none(),
        "reauth must precede pushing any secret to a destination"
    );
}

// ----------------------------------------------- temporary access termination

#[test]
fn temporary_access_termination_is_identity_guarded() {
    // Command: access_session_kill (131) — verified termination (Phase 1).
    // A recorded session with no launch identity must be refused, not
    // signalled (covered in depth in pi02_process_identity.rs; this asserts
    // the command-layer path returns the truthful outcome type).
    let (_d, _p, vault) = new_vault();
    let conn = vault.connection();
    let session = api_tracker_core::inject::start_session(conn, "proj", "demo", &[]).unwrap();
    // No PID recorded → termination refused cleanly.
    let err = vault.terminate_process_session(&session).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
}
