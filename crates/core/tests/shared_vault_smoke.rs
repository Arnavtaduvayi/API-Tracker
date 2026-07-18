//! Cross-frontend compatibility check used by `scripts/smoke.sh`.
//!
//! The desktop app reaches the vault exclusively through `api-tracker-core`
//! (its Tauri layer is a thin adapter), so opening a CLI-created vault through
//! the same core APIs demonstrates that both frontends share one vault format
//! and one code path. The smoke harness points this test at a vault it just
//! created with the CLI binary; without those environment variables the test
//! is a no-op, so normal test runs never depend on external state.

use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, VaultPaths};
use std::path::PathBuf;

#[test]
fn desktop_core_opens_a_cli_created_vault() {
    let dir = match std::env::var_os("API_TRACKER_SMOKE_DIR") {
        Some(d) => PathBuf::from(d),
        None => return, // not running under scripts/smoke.sh
    };
    let password = std::env::var("API_TRACKER_SMOKE_PASSWORD")
        .expect("API_TRACKER_SMOKE_PASSWORD must be set with API_TRACKER_SMOKE_DIR");
    let expected_project = std::env::var("API_TRACKER_SMOKE_PROJECT")
        .expect("API_TRACKER_SMOKE_PROJECT must be set with API_TRACKER_SMOKE_DIR");

    let paths = VaultPaths::new(dir);
    let vault = vault::unlock_vault(&paths, &SecretString::new(password))
        .expect("the desktop core must unlock the CLI-created vault");
    let projects = vault.list_projects(true).expect("list projects");
    assert!(
        projects.iter().any(|p| p.name == expected_project),
        "the CLI-created project must be visible through the shared core"
    );
    // scripts/smoke.sh greps for this marker (with --nocapture) to prove the
    // env-gated body above actually ran rather than no-opping.
    println!("shared-vault-smoke: verified");
}
