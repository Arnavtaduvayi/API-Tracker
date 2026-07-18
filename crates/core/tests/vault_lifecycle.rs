//! Vault creation, unlocking, corruption detection, and settings.

mod common;

use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::settings::VaultSettings;
use api_tracker_core::vault::{self, VaultPaths};
use api_tracker_core::CoreError;
use common::*;

#[test]
fn create_then_unlock_roundtrip() {
    let (_dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "alpha");
    vault.lock();

    let reopened = vault::unlock_vault(&paths, &master_pw()).expect("unlock");
    let projects = reopened.list_projects(true).unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "alpha");
}

#[test]
fn wrong_master_password_is_rejected() {
    let (_dir, paths, vault) = new_vault();
    vault.lock();
    let err = vault::unlock_vault(&paths, &SecretString::from("wrong-password-123")).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword));
}

#[test]
fn creating_over_an_existing_vault_is_rejected() {
    let (_dir, paths, vault) = new_vault();
    vault.lock();
    let err = vault::create_vault(&paths, &master_pw()).unwrap_err();
    assert!(matches!(err, CoreError::VaultExists(_)));
}

#[test]
fn unlock_missing_vault_reports_not_found() {
    fast_kdf();
    let dir = tempfile::TempDir::new().unwrap();
    let paths = VaultPaths::new(dir.path().join("nothing-here"));
    let err = vault::unlock_vault(&paths, &master_pw()).unwrap_err();
    assert!(matches!(err, CoreError::VaultNotFound(_)));
}

#[test]
fn short_master_password_is_rejected() {
    fast_kdf();
    let dir = tempfile::TempDir::new().unwrap();
    let paths = VaultPaths::new(dir.path().join("data"));
    let err = vault::create_vault(&paths, &SecretString::from("short")).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(
        !paths.vault_exists(),
        "no vault may be created with an invalid password"
    );
}

#[test]
fn master_password_minimum_is_exactly_twelve_characters() {
    fast_kdf();
    assert_eq!(vault::MIN_PASSWORD_LEN, 12);

    let dir = tempfile::TempDir::new().unwrap();
    let paths = VaultPaths::new(dir.path().join("eleven"));
    let err = vault::create_vault(&paths, &SecretString::from("elevenchars")).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(!paths.vault_exists());

    let paths = VaultPaths::new(dir.path().join("twelve"));
    let vault = vault::create_vault(&paths, &SecretString::from("twelve-chars")).expect("12 ok");
    vault.lock();
}

#[test]
fn corrupted_wrapped_vault_key_fails_to_unlock() {
    let (_dir, paths, vault) = new_vault();
    vault.lock();

    let conn = rusqlite::Connection::open(paths.db_path()).unwrap();
    let wrapped: String = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key='wrapped_vault_key'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // Flip the last ciphertext byte.
    let mut bytes = hex::decode(&wrapped).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    conn.execute(
        "UPDATE vault_meta SET value=?1 WHERE key='wrapped_vault_key'",
        [hex::encode(bytes)],
    )
    .unwrap();
    drop(conn);

    let err = vault::unlock_vault(&paths, &master_pw()).unwrap_err();
    assert!(
        matches!(err, CoreError::WrongPassword),
        "corruption surfaces as auth failure"
    );
}

#[test]
fn tampered_credential_ciphertext_is_detected() {
    let (_dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "alpha");
    let (cred, _) = add_key(
        &mut vault,
        "alpha",
        "api",
        FAKE_KEY_1,
        Environment::Development,
    );
    vault.lock();

    let conn = rusqlite::Connection::open(paths.db_path()).unwrap();
    let mut ct: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM credentials WHERE id=?1",
            [&cred.id],
            |r| r.get(0),
        )
        .unwrap();
    let mid = ct.len() / 2;
    ct[mid] ^= 0xFF;
    conn.execute(
        "UPDATE credentials SET ciphertext=?1 WHERE id=?2",
        rusqlite::params![ct, cred.id],
    )
    .unwrap();
    drop(conn);

    let mut vault = vault::unlock_vault(&paths, &master_pw()).unwrap();
    let err = vault.reveal_credential(&cred.id, &master_pw()).unwrap_err();
    assert!(matches!(err, CoreError::Crypto { .. }));
}

#[test]
fn swapping_ciphertext_between_credentials_is_detected() {
    // AAD binds each ciphertext to its credential id: swapping two encrypted
    // values in the database must fail, not decrypt to the wrong secret.
    let (_dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "alpha");
    let (a, _) = add_key(
        &mut vault,
        "alpha",
        "key-a",
        FAKE_KEY_1,
        Environment::Development,
    );
    let (b, _) = add_key(
        &mut vault,
        "alpha",
        "key-b",
        FAKE_KEY_2,
        Environment::Development,
    );
    vault.lock();

    let conn = rusqlite::Connection::open(paths.db_path()).unwrap();
    let ct_a: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM credentials WHERE id=?1",
            [&a.id],
            |r| r.get(0),
        )
        .unwrap();
    let ct_b: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM credentials WHERE id=?1",
            [&b.id],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute(
        "UPDATE credentials SET ciphertext=?1 WHERE id=?2",
        rusqlite::params![ct_b, a.id],
    )
    .unwrap();
    conn.execute(
        "UPDATE credentials SET ciphertext=?1 WHERE id=?2",
        rusqlite::params![ct_a, b.id],
    )
    .unwrap();
    drop(conn);

    let mut vault = vault::unlock_vault(&paths, &master_pw()).unwrap();
    assert!(vault.reveal_credential(&a.id, &master_pw()).is_err());
    assert!(vault.reveal_credential(&b.id, &master_pw()).is_err());
}

#[test]
fn settings_persist() {
    let (_dir, paths, mut vault) = new_vault();
    let settings = VaultSettings {
        auto_lock_minutes: 42,
        expiring_soon_days: 7,
        ..Default::default()
    };
    vault.update_settings(settings).unwrap();
    vault.lock();

    let vault = vault::unlock_vault(&paths, &master_pw()).unwrap();
    assert_eq!(vault.settings().auto_lock_minutes, 42);
    assert_eq!(vault.settings().expiring_soon_days, 7);
}

#[test]
fn reauthentication_verifies_master_password() {
    let (_dir, _paths, vault) = new_vault();
    vault
        .verify_master_password(&master_pw())
        .expect("correct password verifies");
    let err = vault
        .verify_master_password(&SecretString::from("wrong-password-123"))
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword));
}
