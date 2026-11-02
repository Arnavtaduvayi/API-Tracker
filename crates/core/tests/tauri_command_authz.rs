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
//! each command it lists, whether enforcement is in core (tested here) or in
//! the wrapper: the 137 commands of the Phase 2 inventory, plus the 15
//! Tethra Mesh commands Increment 09 appended (`mesh_cmds.rs`; their
//! reauth-gated core methods are covered at the end of this file). It is not
//! a full re-inventory: main.rs registers commands added since Phase 2 that
//! it does not list.

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

// ------------------------------------------------- Tethra Mesh (Increment 09)
//
// The desktop's Devices view (`apps/desktop/src-tauri/src/mesh_cmds.rs`)
// passes the master password straight through to these core methods; the
// check lives here, so a hostile `invoke` cannot skip it.

mod mesh {
    use super::{assert_no_secret_leak, wrong, WRONG_PW};
    use crate::common::{master_pw, new_vault, MASTER_PW};
    use api_tracker_core::error::CoreError;
    use api_tracker_core::mesh::clock::{Clock, SystemClock};
    use api_tracker_core::mesh::invite::{format_invite, parse_invite};
    use api_tracker_core::mesh::membership::{self, PendingIdentity};
    use api_tracker_core::mesh::node_settings::NodeSettings;
    use api_tracker_core::mesh::MeshError;
    use api_tracker_core::vault::UnlockedVault;

    /// No master or wrong password in any error the desktop could show.
    fn assert_clean(err: &CoreError) {
        assert_no_secret_leak(err, MASTER_PW);
        assert_no_secret_leak(err, WRONG_PW);
    }

    fn count(v: &UnlockedVault, sql: &str) -> i64 {
        v.connection().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn audit_count(v: &UnlockedVault, event: &str) -> i64 {
        v.connection()
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE event = ?1",
                [event],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn epoch(v: &UnlockedVault) -> u32 {
        v.connection()
            .query_row("SELECT access_key_epoch FROM mesh_self", [], |r| r.get(0))
            .unwrap()
    }

    /// The base32 code inside an invite string (between the prefix and `@`):
    /// the bearer secret.
    fn invite_code(invite: &str) -> String {
        let rest = invite.split_once("v1:").unwrap().1;
        rest.split_once('@').unwrap().0.to_owned()
    }

    #[test]
    fn mesh_invite_create_requires_correct_reauth() {
        // Command: mesh_invite_create.
        let (_d, _p, v) = new_vault();
        v.mesh_init("dev-a").unwrap();

        let err = v.mesh_invite_create(&wrong(), None).unwrap_err();
        assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
        assert_clean(&err);
        // Refused before anything was stored or audited.
        assert_eq!(count(&v, "SELECT COUNT(*) FROM mesh_invites"), 0);
        assert_eq!(audit_count(&v, "mesh_invite_created"), 0);

        let inv = v.mesh_invite_create(&master_pw(), Some(10)).unwrap();
        assert_eq!(inv.ttl_minutes, 10);
        assert_eq!(count(&v, "SELECT COUNT(*) FROM mesh_invites"), 1);
        assert_eq!(audit_count(&v, "mesh_invite_created"), 1);
        let text = format_invite(&inv.token, &["127.0.0.1:7700".to_owned()]).unwrap();
        let code = invite_code(text.expose());
        assert_eq!(code.len(), 34, "token plus checksum");

        // No error or debug output carries the token, once it exists.
        let debug = format!("{inv:?}");
        assert!(!debug.contains(&code), "Invite's Debug leaked the token");
        let err = v.mesh_invite_create(&wrong(), None).unwrap_err();
        assert_clean(&err);
        assert!(!err.to_string().contains(&code));
        assert!(!format!("{err:#}").contains(&code));
        let mut typo = text.expose().to_owned();
        let at = typo.find('@').unwrap() - 1;
        let flipped = if typo.as_bytes()[at] == b'a' {
            "b"
        } else {
            "a"
        };
        typo.replace_range(at..=at, flipped);
        for bad in [typo.as_str(), text.expose().split('@').next().unwrap()] {
            let e = parse_invite(bad).unwrap_err();
            assert!(
                !e.to_string().contains(&code),
                "parse error echoed the token: {e}"
            );
        }
        assert_eq!(count(&v, "SELECT COUNT(*) FROM mesh_invites"), 1);
    }

    /// Admit a second device into `v`'s roster with core's pairing step (no
    /// network): the inviter's side of a join.
    fn admit(v: &UnlockedVault, name: &str) -> api_tracker_core::mesh::DeviceId {
        let inv = v.mesh_invite_create(&master_pw(), None).unwrap();
        let pending = PendingIdentity::generate(name).unwrap();
        let req = pending.request();
        let access = v
            .mesh_vault()
            .access_keys(v.connection(), SystemClock.now_ms())
            .unwrap()
            .current;
        let keys = v.mesh_keys().unwrap();
        let mut store = v.mesh_open_store().unwrap();
        membership::accept_pairing(
            &mut store,
            keys.signing_key(),
            &inv.token.hash(),
            &req,
            &req.noise_pub,
            &access,
        )
        .unwrap();
        pending.device_id()
    }

    #[test]
    fn mesh_device_remove_requires_correct_reauth() {
        // Command: mesh_device_remove.
        let (_d, _p, v) = new_vault();
        v.mesh_init("dev-a").unwrap();
        let unknown = "0123456789abcdef";

        // The password is checked before the device is even resolved.
        let err = v.mesh_device_remove(&wrong(), unknown).unwrap_err();
        assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
        assert_clean(&err);
        // The right password with an unknown id: a clean refusal.
        let err = v.mesh_device_remove(&master_pw(), unknown).unwrap_err();
        assert!(
            matches!(err, CoreError::Mesh(MeshError::NotAMember)),
            "{err:?}"
        );
        assert_clean(&err);
        assert_eq!(epoch(&v), 1);

        // A real second member.
        let b = admit(&v, "dev-b");
        let row = |v: &UnlockedVault| {
            v.mesh_devices()
                .unwrap()
                .into_iter()
                .find(|d| d.device_id == b)
                .unwrap()
        };
        assert!(!row(&v).removed);
        let err = v.mesh_device_remove(&wrong(), &b.to_hex()).unwrap_err();
        assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
        assert_clean(&err);
        assert!(!row(&v).removed, "a refused removal removes nothing");
        assert_eq!(epoch(&v), 1, "and rotates nothing");
        assert_eq!(audit_count(&v, "mesh_device_removed"), 0);

        let (removed, new_epoch) = v.mesh_device_remove(&master_pw(), &b.to_hex()).unwrap();
        assert_eq!(removed, b);
        assert_eq!(new_epoch, 2);
        assert!(row(&v).removed);
        assert_eq!(epoch(&v), 2);
        assert_eq!(audit_count(&v, "mesh_device_removed"), 1);
    }

    #[test]
    fn mesh_leave_requires_correct_reauth() {
        // Command: mesh_leave (through `api_tracker_mesh::replicate::leave_mesh`).
        let (_d, _p, v) = new_vault();
        v.mesh_init("dev-a").unwrap();
        let before = v.mesh_status().unwrap().detail.unwrap();
        let mut tried = 0;

        let err = v
            .mesh_leave(&wrong(), &mut |_| {
                tried += 1;
                false
            })
            .unwrap_err();
        assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
        assert_clean(&err);
        assert_eq!(tried, 0, "nothing is delivered before the password");
        let after = v.mesh_status().unwrap();
        assert!(after.initialized, "a refused leave keeps the mesh");
        let after = after.detail.unwrap();
        assert_eq!(after.device_id, before.device_id);
        assert_eq!(after.next_seq, before.next_seq, "no self-removal minted");
        assert_eq!(audit_count(&v, "mesh_left"), 0);

        let report = v.mesh_leave(&master_pw(), &mut |_| false).unwrap();
        assert!(!report.delivered);
        assert!(!v.mesh_status().unwrap().initialized);
        assert_eq!(audit_count(&v, "mesh_left"), 1);
    }

    fn settings(listen: &[&str], all_interfaces: bool, discover: bool) -> NodeSettings {
        NodeSettings {
            run_while_open: true,
            listen: listen.iter().map(|a| (*a).to_owned()).collect(),
            all_interfaces,
            discover,
        }
    }

    const WIDENED: &str = "mesh_node_exposure_widened";

    #[test]
    fn mesh_node_settings_widening_the_lan_surface_requires_reauth() {
        // Command: mesh_node_set_settings.
        let (_d, _p, v) = new_vault();
        // Not in a mesh: nothing to configure, nothing stored.
        let err = v
            .mesh_node_settings_set(None, &settings(&["127.0.0.1:7700"], false, false))
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Mesh(MeshError::NotInitialized)),
            "{err:?}"
        );
        v.mesh_init("dev-a").unwrap();
        assert_eq!(v.mesh_node_settings().unwrap(), NodeSettings::default());

        // Loopback: no password, and no exposure audit.
        let narrow = settings(&["127.0.0.1:7700"], false, false);
        assert_eq!(v.mesh_node_settings_set(None, &narrow).unwrap(), narrow);
        let more_loopback = settings(&["127.0.0.1:7700", "[::1]:7701"], false, false);
        assert_eq!(
            v.mesh_node_settings_set(None, &more_loopback).unwrap(),
            more_loopback
        );
        assert_eq!(audit_count(&v, WIDENED), 0);
        assert_eq!(v.mesh_node_settings_set(None, &narrow).unwrap(), narrow);

        let widenings = [
            ("all interfaces", settings(&["127.0.0.1:7700"], true, false)),
            ("mDNS discovery", settings(&["127.0.0.1:7700"], false, true)),
            (
                "a LAN address",
                settings(&["127.0.0.1:7700", "192.168.1.20:7700"], false, false),
            ),
            (
                "a VPN address",
                settings(&["100.64.1.2:7700"], false, false),
            ),
        ];
        for (n, (what, wide)) in widenings.iter().enumerate() {
            // No password: refused with its own code, nothing stored.
            let err = v.mesh_node_settings_set(None, wide).unwrap_err();
            assert!(
                matches!(err, CoreError::Mesh(MeshError::ReauthRequired)),
                "{what}: {err:?}"
            );
            assert_eq!(err.code(), "mesh_reauth_required");
            assert_clean(&err);
            assert_eq!(v.mesh_node_settings().unwrap(), narrow, "{what}");
            // A wrong password: refused, nothing stored.
            let err = v.mesh_node_settings_set(Some(&wrong()), wide).unwrap_err();
            assert!(matches!(err, CoreError::WrongPassword), "{what}: {err:?}");
            assert_clean(&err);
            assert_eq!(v.mesh_node_settings().unwrap(), narrow, "{what}");
            assert_eq!(audit_count(&v, WIDENED), n as i64, "{what}");
            // The right password: stored and audited.
            assert_eq!(
                v.mesh_node_settings_set(Some(&master_pw()), wide).unwrap(),
                *wide
            );
            assert_eq!(v.mesh_node_settings().unwrap(), *wide);
            assert_eq!(audit_count(&v, WIDENED), n as i64 + 1, "{what}");
            // Keeping it needs no password; narrowing back needs none either.
            assert_eq!(v.mesh_node_settings_set(None, wide).unwrap(), *wide);
            assert_eq!(v.mesh_node_settings_set(None, &narrow).unwrap(), narrow);
            assert_eq!(audit_count(&v, WIDENED), n as i64 + 1, "{what}");
        }
        // The audit detail names what widened, never a password.
        let details: Vec<String> = {
            let mut st = v
                .connection()
                .prepare("SELECT detail FROM audit_events WHERE event = ?1 ORDER BY id")
                .unwrap();
            st.query_map([WIDENED], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(
            details,
            vec![
                "all interfaces allowed",
                "mDNS discovery on",
                "a non-loopback listen address added",
                "a non-loopback listen address added",
            ]
        );
        assert!(details
            .iter()
            .all(|d| !d.contains(MASTER_PW) && !d.contains(WRONG_PW)));
        // Turning the node off is a narrowing.
        let off = NodeSettings {
            run_while_open: false,
            ..narrow.clone()
        };
        assert_eq!(v.mesh_node_settings_set(None, &off).unwrap(), off);
    }
}
