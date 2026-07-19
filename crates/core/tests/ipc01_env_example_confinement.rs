//! IPC-01 / FS-09 regression: `env_example_write` must be reauthenticated
//! and confined to a `.env.example` inside a registered repository. These
//! tests call the core method directly — the same authorization boundary
//! the desktop IPC command uses — bypassing the React confirmation dialog,
//! and attempt the escapes the audit called out: unrelated absolute paths,
//! `..` traversal, symlink destinations, a path switched after preview,
//! and missing/incorrect reauthentication. At baseline `7d81090` the
//! command performed an unauthenticated arbitrary-path atomic write, so
//! every escape below succeeded.

mod common;

use api_tracker_core::error::CoreError;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, UnlockedVault};
use common::{add_project, master_pw, new_vault};
use std::path::{Path, PathBuf};

const EXAMPLE_CONTENT: &str = "# names only\nOPENAI_API_KEY=\n";

fn register_repo(vault: &mut UnlockedVault, project: &str, repo: &Path) {
    vault
        .update_project(
            project,
            vault::UpdateProject {
                add_repo_paths: vec![repo.to_string_lossy().into_owned()],
                ..Default::default()
            },
        )
        .unwrap();
}

fn write(
    vault: &UnlockedVault,
    project: &str,
    path: &Path,
    password: &SecretString,
) -> Result<PathBuf, CoreError> {
    vault.env_example_write(project, path, EXAMPLE_CONTENT, password)
}

#[test]
fn valid_in_project_example_write_succeeds() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    register_repo(&mut vault, "app", repo.path());

    let target = repo.path().join(".env.example");
    let written = write(&vault, "app", &target, &master_pw()).expect("valid in-project write");
    assert!(written.ends_with(".env.example"));
    let on_disk = std::fs::read_to_string(&written).unwrap();
    assert_eq!(on_disk, EXAMPLE_CONTENT);

    // A subdirectory of the repo is also in-tree and allowed.
    let sub = repo.path().join("service");
    std::fs::create_dir_all(&sub).unwrap();
    write(&vault, "app", &sub.join(".env.example"), &master_pw()).expect("in-subdir write");
}

#[test]
fn write_to_unrelated_absolute_path_is_refused() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    register_repo(&mut vault, "app", repo.path());

    // A world-writable location outside any registered repo.
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join(".env.example");
    let err = write(&vault, "app", &target, &master_pw()).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
    assert!(!target.exists(), "nothing may be written outside the repo");
}

#[test]
fn parent_traversal_out_of_tree_is_refused() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    let sub = repo.path().join("nested");
    std::fs::create_dir_all(&sub).unwrap();
    add_project(&mut vault, "app");
    register_repo(&mut vault, "app", &sub);

    // Escape the registered subdir back up to the repo root via `..`.
    let escape = sub.join("..").join(".env.example");
    let err = write(&vault, "app", &escape, &master_pw()).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
    assert!(
        !repo.path().join(".env.example").exists(),
        "traversal must not write above the registered repository"
    );
}

#[test]
fn non_example_file_name_is_refused() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    register_repo(&mut vault, "app", repo.path());

    // Even inside the repo, only `.env.example` may be written — never an
    // arbitrary file, so the primitive cannot overwrite e.g. `.env`.
    let err = write(&vault, "app", &repo.path().join(".env"), &master_pw()).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
    assert!(!repo.path().join(".env").exists());
}

#[cfg(unix)]
#[test]
fn symlink_destination_is_refused() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    register_repo(&mut vault, "app", repo.path());

    // A `.env.example` in the repo that is actually a symlink to a sensitive
    // file elsewhere: writing through it must be refused.
    let secret_target = tempfile::tempdir().unwrap();
    let sensitive = secret_target.path().join("victim");
    std::fs::write(&sensitive, "original\n").unwrap();
    let link = repo.path().join(".env.example");
    std::os::unix::fs::symlink(&sensitive, &link).unwrap();

    let err = write(&vault, "app", &link, &master_pw()).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(&sensitive).unwrap(),
        "original\n",
        "the symlink target must be untouched"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_parent_directory_escaping_the_repo_is_refused() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    register_repo(&mut vault, "app", repo.path());

    // A directory symlink inside the repo pointing outside it: canonicalizing
    // the parent resolves the link, so the containment check fails.
    let outside = tempfile::tempdir().unwrap();
    let link_dir = repo.path().join("linked");
    std::os::unix::fs::symlink(outside.path(), &link_dir).unwrap();

    let err = write(&vault, "app", &link_dir.join(".env.example"), &master_pw()).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
    assert!(!outside.path().join(".env.example").exists());
}

#[test]
fn path_switched_after_preview_to_out_of_tree_is_refused() {
    // Models the audit's "path switched after preview": a preview computes an
    // in-repo target, but the write is invoked with a different, out-of-tree
    // path. The core recomputes and confines, so the switch is refused.
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    register_repo(&mut vault, "app", repo.path());

    let elsewhere = tempfile::tempdir().unwrap();
    let switched = elsewhere.path().join(".env.example");
    let err = write(&vault, "app", &switched, &master_pw()).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
    assert!(!switched.exists());
}

#[test]
fn incorrect_or_missing_reauth_is_refused() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    register_repo(&mut vault, "app", repo.path());
    let target = repo.path().join(".env.example");

    // Wrong password: refused as WrongPassword, nothing written.
    let err = write(
        &vault,
        "app",
        &target,
        &SecretString::from("not-the-master-pw"),
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert!(!target.exists(), "a bad reauth must not write the file");

    // Empty password is likewise refused.
    let err = write(&vault, "app", &target, &SecretString::from("")).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword), "{err:?}");
    assert!(!target.exists());
}

#[test]
fn project_without_registered_repo_cannot_be_a_write_target() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    // No repo registered: even a plausible temp path is refused.
    let elsewhere = tempfile::tempdir().unwrap();
    let err = write(
        &vault,
        "app",
        &elsewhere.path().join(".env.example"),
        &master_pw(),
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)), "{err:?}");
}
