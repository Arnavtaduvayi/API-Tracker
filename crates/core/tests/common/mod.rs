//! Shared helpers for core integration tests.
// Each test binary compiles its own copy of this module; not every binary
// uses every helper.
#![allow(dead_code)]
//!
//! Tests use deliberately fake credential values and a weakened KDF profile
//! (debug builds only) so the suite stays fast. Vaults remember the KDF
//! parameters they were created with.

use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, UnlockedVault, VaultPaths};
use std::sync::Once;
use tempfile::TempDir;

pub const MASTER_PW: &str = "test-master-password";
pub const PROJECT_PW: &str = "test-project-password";
pub const FAKE_KEY_1: &str = "FAKE-TEST-NOT-A-REAL-KEY-000001";
pub const FAKE_KEY_2: &str = "FAKE-TEST-NOT-A-REAL-KEY-000002";

static INIT: Once = Once::new();

pub fn fast_kdf() {
    INIT.call_once(|| std::env::set_var("API_TRACKER_INSECURE_FAST_KDF", "1"));
}

pub fn master_pw() -> SecretString {
    SecretString::from(MASTER_PW)
}

pub fn new_vault() -> (TempDir, VaultPaths, UnlockedVault) {
    fast_kdf();
    let dir = TempDir::new().expect("temp dir");
    let paths = VaultPaths::new(dir.path().join("data"));
    let vault = vault::create_vault(&paths, &master_pw()).expect("create vault");
    (dir, paths, vault)
}

pub fn add_project(vault: &mut UnlockedVault, name: &str) -> api_tracker_core::model::Project {
    vault
        .create_project(vault::NewProject {
            name: name.to_owned(),
            ..Default::default()
        })
        .expect("create project")
}

pub fn add_key(
    vault: &mut UnlockedVault,
    project: &str,
    name: &str,
    value: &str,
    environment: api_tracker_core::model::Environment,
) -> (
    api_tracker_core::model::Credential,
    Vec<api_tracker_core::reuse::ReuseWarning>,
) {
    vault
        .add_credential(vault::AddCredential {
            project: project.to_owned(),
            provider: "openai".to_owned(),
            name: name.to_owned(),
            environment,
            value: SecretString::from(value),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .expect("add credential")
}
