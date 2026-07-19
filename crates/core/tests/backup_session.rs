//! Encrypted backups (create/verify/restore) and CLI session behavior.

mod common;

use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::session::{self, SessionToken};
use api_tracker_core::vault::{self, VaultPaths};
use api_tracker_core::{backup, CoreError};
use common::*;

fn backup_pw() -> SecretString {
    SecretString::from("test-backup-password")
}

#[test]
fn backup_create_verify_restore_roundtrip() {
    let (dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "alpha");
    add_project(&mut vault, "beta");
    add_key(
        &mut vault,
        "alpha",
        "api",
        FAKE_KEY_1,
        Environment::Production,
    );
    add_key(
        &mut vault,
        "beta",
        "api",
        FAKE_KEY_2,
        Environment::Development,
    );
    vault
        .set_project_password("beta", &SecretString::from(PROJECT_PW), &master_pw())
        .unwrap();

    let backup_path = dir.path().join("vault-backup.json");
    let info = backup::create_backup(&vault, &backup_path, &backup_pw(), false).unwrap();
    assert_eq!(info.project_count, 2);
    assert_eq!(info.credential_count, 2);

    // Refuses to overwrite an existing backup file without the flag.
    let err = backup::create_backup(&vault, &backup_path, &backup_pw(), false).unwrap_err();
    assert!(matches!(err, CoreError::AlreadyExists { .. }));

    // Verification decrypts and validates without restoring.
    let verified = backup::verify_backup(&backup_path, &backup_pw()).unwrap();
    assert_eq!(verified.credential_count, 2);
    assert_eq!(verified.vault_id, vault.vault_id());

    // The backup file itself never contains plaintext secrets.
    let raw = std::fs::read_to_string(&backup_path).unwrap();
    assert!(!raw.contains(FAKE_KEY_1));
    assert!(!raw.contains(FAKE_KEY_2));
    vault.lock();

    // Restore into a fresh location.
    let restore_paths = VaultPaths::new(dir.path().join("restored"));
    backup::restore_backup(&backup_path, &backup_pw(), &restore_paths, false).unwrap();

    // The restored vault unlocks with the ORIGINAL master password.
    let mut restored = vault::unlock_vault(&restore_paths, &master_pw()).unwrap();
    let projects = restored.list_projects(true).unwrap();
    assert_eq!(projects.len(), 2);
    assert_eq!(
        restored
            .reveal_credential("alpha/api", &master_pw())
            .unwrap()
            .expose(),
        FAKE_KEY_1
    );

    // The password-locked project is still locked after restore.
    let beta = restored.get_project("beta").unwrap();
    assert!(beta.password_locked);
    assert!(!beta.unlocked);
    restored
        .unlock_project("beta", &SecretString::from(PROJECT_PW))
        .unwrap();
    assert_eq!(
        restored
            .reveal_credential("beta/api", &master_pw())
            .unwrap()
            .expose(),
        FAKE_KEY_2
    );
}

#[test]
fn wrong_backup_password_fails() {
    let (dir, _paths, vault) = new_vault();
    let backup_path = dir.path().join("b.json");
    backup::create_backup(&vault, &backup_path, &backup_pw(), false).unwrap();
    let err =
        backup::verify_backup(&backup_path, &SecretString::from("wrong-password-123")).unwrap_err();
    assert!(matches!(err, CoreError::Crypto { .. }));
}

#[test]
fn tampered_backup_fails_verification() {
    let (dir, _paths, vault) = new_vault();
    let backup_path = dir.path().join("b.json");
    backup::create_backup(&vault, &backup_path, &backup_pw(), false).unwrap();

    let raw = std::fs::read_to_string(&backup_path).unwrap();
    let mut file: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let payload = file["payload_b64"].as_str().unwrap().to_owned();
    // Corrupt one character in the middle of the ciphertext.
    let mid = payload.len() / 2;
    let mut chars: Vec<char> = payload.chars().collect();
    chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
    file["payload_b64"] = serde_json::Value::String(chars.into_iter().collect());
    std::fs::write(&backup_path, serde_json::to_string(&file).unwrap()).unwrap();

    let err = backup::verify_backup(&backup_path, &backup_pw()).unwrap_err();
    assert!(matches!(
        err,
        CoreError::Crypto { .. } | CoreError::BackupInvalid(_)
    ));
}

#[test]
fn short_backup_password_rejected() {
    let (dir, _paths, vault) = new_vault();
    let err = backup::create_backup(
        &vault,
        &dir.path().join("b.json"),
        &SecretString::from("short"),
        false,
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn restore_refuses_to_overwrite_without_force_and_preserves_old_vault_with_force() {
    let (dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "original");
    let backup_path = dir.path().join("b.json");
    backup::create_backup(&vault, &backup_path, &backup_pw(), false).unwrap();
    add_project(&mut vault, "added-after-backup");
    vault.lock();

    let err = backup::restore_backup(&backup_path, &backup_pw(), &paths, false).unwrap_err();
    assert!(matches!(err, CoreError::VaultExists(_)));

    backup::restore_backup(&backup_path, &backup_pw(), &paths, true).unwrap();
    // The pre-restore database was renamed aside, not destroyed.
    let kept: Vec<_> = std::fs::read_dir(&paths.data_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("vault.db.replaced-")
        })
        .collect();
    assert_eq!(kept.len(), 1);

    let restored = vault::unlock_vault(&paths, &master_pw()).unwrap();
    let names: Vec<String> = restored
        .list_projects(true)
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(names, vec!["original".to_owned()]);
}

#[test]
fn repeated_force_restores_never_clobber_a_previous_aside() {
    // Two `restore --force` runs (a plausible retry) must each set the
    // existing vault aside under a DISTINCT name, even if they land in the
    // same wall-clock second — otherwise the second restore would rename its
    // vault over the first aside and silently destroy it.
    let (dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "generation-one");
    let backup_path = dir.path().join("b.json");
    backup::create_backup(&vault, &backup_path, &backup_pw(), false).unwrap();
    vault.lock();

    // First force restore: sets generation-one aside.
    backup::restore_backup(&backup_path, &backup_pw(), &paths, true).unwrap();
    // Mutate the freshly restored vault so the next aside differs in content.
    {
        let mut v = vault::unlock_vault(&paths, &master_pw()).unwrap();
        add_project(&mut v, "generation-two");
    }
    // Second force restore: must set generation-two aside under a new name,
    // leaving generation-one's aside intact.
    backup::restore_backup(&backup_path, &backup_pw(), &paths, true).unwrap();

    let asides: Vec<_> = std::fs::read_dir(&paths.data_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with("vault.db.replaced-") && !n.ends_with("-wal") && !n.ends_with("-shm")
        })
        .collect();
    assert_eq!(
        asides.len(),
        2,
        "both replaced vaults must be preserved under distinct names"
    );
}

#[cfg(unix)] // POSIX rename-while-open semantics; see the Windows test below.
#[test]
fn force_restore_preserves_a_still_open_vault_including_uncheckpointed_wal() {
    // Reproduces the data-loss case: a concurrent connection (e.g. the
    // desktop app) holds committed-but-uncheckpointed transactions in the
    // WAL. Force-restore must keep the aside copy fully openable.
    //
    // On Windows this scenario cannot occur the same way: the OS refuses to
    // rename an open database file (sharing violation), so a force-restore
    // against an in-use vault fails cleanly before anything changes — the
    // companion test below pins that behavior.
    let (dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "live-project");
    add_key(
        &mut vault,
        "live-project",
        "api",
        FAKE_KEY_1,
        Environment::Development,
    );
    let backup_path = dir.path().join("b.json");
    backup::create_backup(&vault, &backup_path, &backup_pw(), false).unwrap();

    // Keep the vault OPEN across the restore (its WAL may be uncheckpointed).
    backup::restore_backup(&backup_path, &backup_pw(), &paths, true).unwrap();
    drop(vault);

    // The aside database must still be a complete, openable vault.
    let aside = std::fs::read_dir(&paths.data_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| {
            n.starts_with("vault.db.replaced-") && !n.ends_with("-wal") && !n.ends_with("-shm")
        })
        .expect("aside database exists");
    let aside_paths = VaultPaths::new(dir.path().join("reopen"));
    std::fs::create_dir_all(&aside_paths.data_dir).unwrap();
    std::fs::copy(paths.data_dir.join(&aside), aside_paths.db_path()).unwrap();
    for suffix in ["-wal", "-shm"] {
        let src = paths.data_dir.join(format!("{aside}{suffix}"));
        if src.exists() {
            std::fs::copy(
                &src,
                aside_paths.db_path().with_extension(format!("db{suffix}")),
            )
            .unwrap();
        }
    }
    let reopened = vault::unlock_vault(&aside_paths, &master_pw()).unwrap();
    let names: Vec<String> = reopened
        .list_projects(true)
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(
        names,
        vec!["live-project".to_owned()],
        "aside vault must retain its data"
    );
}

#[cfg(windows)]
#[test]
fn force_restore_against_an_open_vault_fails_cleanly_on_windows() {
    // Windows file locking refuses to rename an open database file, so a
    // force-restore while the vault is in use must fail with a clean error
    // BEFORE anything is modified — the live vault keeps working.
    let (dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "live-project");
    let backup_path = dir.path().join("b.json");
    backup::create_backup(&vault, &backup_path, &backup_pw(), false).unwrap();

    let err = backup::restore_backup(&backup_path, &backup_pw(), &paths, true);
    assert!(
        err.is_err(),
        "restore over an open vault must fail on Windows"
    );
    // The open vault is untouched and fully functional.
    let names: Vec<String> = vault
        .list_projects(true)
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(names, vec!["live-project".to_owned()]);
    drop(vault);
    // Closed, the restore succeeds normally.
    backup::restore_backup(&backup_path, &backup_pw(), &paths, true).unwrap();
}

#[test]
fn session_roundtrip_and_wrong_token() {
    let (_dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "locked");
    add_key(
        &mut vault,
        "locked",
        "api",
        FAKE_KEY_1,
        Environment::Development,
    );
    vault
        .set_project_password("locked", &SecretString::from(PROJECT_PW), &master_pw())
        .unwrap();

    let token = SessionToken::generate();
    vault.save_session(&token).unwrap();
    vault.lock();

    // Resume: the vault key AND the unlocked project key come back.
    let mut resumed = vault::resume_session(&paths, &token).unwrap();
    assert!(resumed.get_project("locked").unwrap().unlocked);
    assert_eq!(
        resumed
            .reveal_credential("locked/api", &master_pw())
            .unwrap()
            .expose(),
        FAKE_KEY_1
    );

    // A wrong token cannot resume.
    let other = SessionToken::generate();
    assert!(matches!(
        vault::resume_session(&paths, &other).unwrap_err(),
        CoreError::SessionInvalid
    ));

    // Destroy = lock.
    assert!(session::destroy(&paths).unwrap());
    assert!(matches!(
        vault::resume_session(&paths, &token).unwrap_err(),
        CoreError::SessionMissing
    ));
}

#[test]
fn expired_session_is_rejected_and_deleted() {
    let (_dir, paths, vault) = new_vault();
    let token = SessionToken::generate();
    vault.save_session(&token).unwrap();
    vault.lock();

    // Age the session artificially: expires_at is plaintext metadata.
    let raw = std::fs::read_to_string(paths.session_path()).unwrap();
    let mut file: serde_json::Value = serde_json::from_str(&raw).unwrap();
    file["expires_at"] = serde_json::Value::String("2000-01-01T00:00:00Z".into());
    std::fs::write(paths.session_path(), serde_json::to_string(&file).unwrap()).unwrap();

    assert!(matches!(
        vault::resume_session(&paths, &token).unwrap_err(),
        CoreError::SessionExpired
    ));
    assert!(
        !paths.session_path().exists(),
        "expired session file is removed"
    );
}

#[test]
fn session_file_does_not_contain_key_material_in_plaintext() {
    let (_dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "p");
    add_key(&mut vault, "p", "api", FAKE_KEY_1, Environment::Development);
    let token = SessionToken::generate();
    vault.save_session(&token).unwrap();

    let raw = std::fs::read_to_string(paths.session_path()).unwrap();
    assert!(!raw.contains(FAKE_KEY_1));
    // The session file alone (without the token) must not allow resuming.
    let status = session::status(&paths).unwrap().unwrap();
    assert!(status.expires_at.is_some());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(paths.session_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "session file must be private");
    }
}

#[test]
fn backup_restore_invalidates_prior_session() {
    let (dir, paths, vault) = new_vault();
    let backup_path = dir.path().join("b.json");
    backup::create_backup(&vault, &backup_path, &backup_pw(), false).unwrap();
    let token = SessionToken::generate();
    vault.save_session(&token).unwrap();
    vault.lock();

    backup::restore_backup(&backup_path, &backup_pw(), &paths, true).unwrap();
    assert!(matches!(
        vault::resume_session(&paths, &token).unwrap_err(),
        CoreError::SessionMissing
    ));
}
