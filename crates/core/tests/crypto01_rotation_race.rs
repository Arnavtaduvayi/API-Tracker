//! CRYPTO-01 / CONC-03 regression: a credential add or value replacement
//! racing a project-key rotation must either commit under the currently
//! persisted project key or fail with a typed error. It must never persist
//! ciphertext under a rotated-away key (silent, permanent data loss) and must
//! never wedge future project-key rotations.
//!
//! Adopted from the deep-audit reproduction harness (baseline `7d81090`
//! orphaned 25/25 in race mode). Determinism: the racing writer is released
//! only after a lock probe confirms the rotation already holds SQLite's
//! single write lock, so the interleaving under test is forced, not timed.
//! The multi-process test drives the racing writer from a spawned child
//! process (its own connection, cache, and address space), matching the
//! supported desktop+CLI shared-vault configuration.

mod common;

use api_tracker_core::error::CoreError;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, AddCredential, UnlockedVault, VaultPaths};
use std::path::Path;
use std::time::{Duration, Instant};

/// Credentials the rotation must re-encrypt while holding the write lock.
/// Sized so the lock is held for orders of magnitude longer than the racing
/// writer needs to reach its own write.
const PAD: usize = 600;
const RACE_ITERATIONS: usize = 6;
const PROCESS_ITERATIONS: usize = 4;
const FAKE_RACED: &str = "FAKE-TEST-NOT-A-REAL-KEY-RACED01";

fn spw(s: &str) -> SecretString {
    SecretString::from(s)
}

fn make_add(project: &str, name: &str, value: &str) -> AddCredential {
    AddCredential {
        project: project.to_owned(),
        provider: "openai".to_owned(),
        name: name.to_owned(),
        environment: Environment::Development,
        value: SecretString::from(value),
        credential_type: None,
        key_created_at: None,
        expires_at: None,
        docs_url: String::new(),
        notes: String::new(),
    }
}

/// A vault whose project `p` is password-locked, holding sentinel `c0` and
/// `PAD` filler credentials (so rotation holds the write lock long enough).
fn build_raced_vault(dir: &Path) -> VaultPaths {
    let paths = VaultPaths::new(dir.join("data"));
    let mut s = vault::create_vault(&paths, &common::master_pw()).expect("create vault");
    s.create_project(vault::NewProject {
        name: "p".into(),
        ..Default::default()
    })
    .expect("create project");
    s.set_project_password("p", &spw(common::PROJECT_PW), &common::master_pw())
        .expect("set project password");
    s.add_credential(make_add("p", "c0", common::FAKE_KEY_1))
        .expect("add c0");
    for k in 0..PAD {
        s.add_credential(make_add(
            "p",
            &format!("pad{k}"),
            &format!("FAKE-TEST-PAD-{k:06}"),
        ))
        .expect("add pad credential");
    }
    paths
}

fn unlock(paths: &VaultPaths) -> UnlockedVault {
    let mut v = vault::unlock_vault(paths, &common::master_pw()).expect("unlock vault");
    v.unlock_project("p", &spw(common::PROJECT_PW))
        .expect("unlock project");
    v
}

/// Block until another connection holds the vault's write lock (the rotation
/// is mid-transaction), or until `done` reports the rotation already
/// finished. Deterministic arming for the race: the racing writer is only
/// released while the rotation provably holds the lock.
fn wait_for_write_lock(db: &Path, done: &std::sync::atomic::AtomicBool) -> bool {
    let probe = rusqlite::Connection::open(db).expect("open probe connection");
    probe
        .busy_timeout(Duration::ZERO)
        .expect("probe busy timeout");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if done.load(std::sync::atomic::Ordering::SeqCst) {
            return false; // rotation already committed; iteration is unarmed
        }
        match probe.execute_batch("BEGIN IMMEDIATE") {
            Err(_) => return true, // busy: the rotation holds the write lock
            Ok(()) => probe.execute_batch("ROLLBACK").expect("probe rollback"),
        }
        assert!(
            Instant::now() < deadline,
            "the rotation neither took the write lock nor finished"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// A refusal is acceptable only as an explicit typed error: the stale-key
/// guard (`ProjectLocked`) or the concurrent-writer signal (`vault_busy`).
fn is_clean_refusal(e: &CoreError) -> bool {
    matches!(e, CoreError::ProjectLocked(_)) || e.code() == "vault_busy"
}

/// Assert the safety invariant after a raced write, whatever the interleave:
/// - a write that reported success must decrypt under the CURRENT key;
/// - a refused write must be a typed refusal and must not have persisted;
/// - the sentinel credential must still decrypt;
/// - a follow-up rotation must succeed — which re-encrypts every stored
///   ciphertext and therefore proves no row anywhere is orphaned.
fn assert_invariant(paths: &VaultPaths, raced_name: &str, raced: Result<(), CoreError>) {
    let mut c = unlock(paths);
    match raced {
        Ok(()) => {
            let revealed = c
                .reveal_credential(&format!("p/{raced_name}"), &common::master_pw())
                .unwrap_or_else(|e| {
                    panic!(
                        "CRYPTO-01 regression: the raced write reported success but its \
                         ciphertext does not decrypt under the persisted project key \
                         (orphaned): {e:?}"
                    )
                });
            assert_eq!(revealed.expose(), FAKE_RACED, "raced value round-trips");
        }
        Err(e) => {
            assert!(
                is_clean_refusal(&e),
                "a raced write must fail with a typed refusal, got: {e:?}"
            );
            assert!(
                c.get_credential(&format!("p/{raced_name}")).is_err(),
                "a refused add must not leave a partial row behind"
            );
        }
    }
    c.reveal_credential("p/c0", &common::master_pw())
        .expect("the sentinel credential must remain recoverable");
    // The rotation decrypts every credential and retained version; success
    // here proves the whole project is recoverable and rotation never wedges.
    c.set_project_password("p", &spw(common::PROJECT_PW), &common::master_pw())
        .expect("CRYPTO-01 regression: a later project-key rotation is wedged");
}

/// Run one armed race: start `rotate` on its own session, wait until it
/// holds the write lock, then run `racer`. Returns (racer result, armed).
fn run_race(
    paths: &VaultPaths,
    racer: impl FnOnce(&mut UnlockedVault) -> Result<(), CoreError> + Send,
) -> (Result<(), CoreError>, bool) {
    let mut a = unlock(paths);
    let mut b = unlock(paths);
    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let rotator = scope.spawn(|| {
            let r = b.set_project_password("p", &spw(common::PROJECT_PW), &common::master_pw());
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            r
        });
        let armed = wait_for_write_lock(&paths.db_path(), &done);
        let raced = racer(&mut a);
        rotator
            .join()
            .expect("rotation thread")
            .expect("the concurrent rotation itself must succeed");
        (raced, armed)
    })
}

#[test]
fn concurrent_rotation_during_add_never_orphans() {
    common::fast_kdf();
    let mut armed_iterations = 0;
    for i in 0..RACE_ITERATIONS {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let paths = build_raced_vault(dir.path());
        let (raced, armed) = run_race(&paths, |a| {
            a.add_credential(make_add("p", "cnew", FAKE_RACED))
                .map(|_| ())
        });
        if armed {
            armed_iterations += 1;
        }
        println!(
            "add-race iter {i}: armed={armed} outcome={}",
            match &raced {
                Ok(()) => "committed".to_owned(),
                Err(e) => format!("refused ({})", e.code()),
            }
        );
        assert_invariant(&paths, "cnew", raced);
    }
    assert!(
        armed_iterations > 0,
        "no iteration armed the race; the harness lost its determinism"
    );
}

#[test]
fn concurrent_rotation_during_replace_never_orphans() {
    common::fast_kdf();
    let mut armed_iterations = 0;
    for i in 0..RACE_ITERATIONS {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let paths = build_raced_vault(dir.path());
        let (raced, armed) = run_race(&paths, |a| {
            a.replace_credential_value("p/c0", &common::master_pw(), spw(FAKE_RACED))
                .map(|_| ())
        });
        if armed {
            armed_iterations += 1;
        }
        println!(
            "replace-race iter {i}: armed={armed} outcome={}",
            match &raced {
                Ok(()) => "committed".to_owned(),
                Err(e) => format!("refused ({})", e.code()),
            }
        );
        // The replace raced c0 itself: on success the new value must be
        // recoverable; on refusal the OLD value must be.
        let mut c = unlock(&paths);
        let expected = match &raced {
            Ok(()) => FAKE_RACED,
            Err(e) => {
                assert!(
                    is_clean_refusal(e),
                    "a raced replace must fail with a typed refusal, got: {e:?}"
                );
                common::FAKE_KEY_1
            }
        };
        let revealed = c
            .reveal_credential("p/c0", &common::master_pw())
            .unwrap_or_else(|e| {
                panic!(
                    "CRYPTO-01 regression: the raced replacement left c0 undecryptable \
                     under the persisted project key (orphaned): {e:?}"
                )
            });
        assert_eq!(revealed.expose(), expected, "c0 holds a recoverable value");
        c.set_project_password("p", &spw(common::PROJECT_PW), &common::master_pw())
            .expect("CRYPTO-01 regression: a later project-key rotation is wedged");
    }
    assert!(
        armed_iterations > 0,
        "no iteration armed the race; the harness lost its determinism"
    );
}

// ---------------------------------------------------------------------------
// Multi-process variant: the racing add runs in a spawned child process with
// its own vault session (connection, key cache, address space).
// ---------------------------------------------------------------------------

const CHILD_DIR_VAR: &str = "API_TRACKER_TEST_CRYPTO01_CHILD_DIR";

fn wait_for_file(path: &Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Child worker: a no-op in normal runs; when spawned by the test below it
/// unlocks the shared vault, signals readiness, waits for the go signal
/// (sent only once the parent's rotation holds the write lock), performs the
/// racing add, and reports the outcome through a file.
#[test]
fn crypto01_multiprocess_child_worker() {
    let Some(dir) = std::env::var_os(CHILD_DIR_VAR) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let paths = VaultPaths::new(dir.join("data"));
    let mut a = unlock(&paths);
    std::fs::write(dir.join("ready"), b"ready").expect("write ready marker");
    wait_for_file(&dir.join("go"), "the parent's go signal");
    let outcome = match a.add_credential(make_add("p", "cnew", FAKE_RACED)) {
        Ok(_) => "ok".to_owned(),
        Err(e) if is_clean_refusal(&e) => "refused".to_owned(),
        Err(e) => format!("error:{}", e.code()),
    };
    std::fs::write(dir.join("outcome"), outcome).expect("write outcome");
}

#[test]
fn concurrent_rotation_during_add_never_orphans_across_processes() {
    common::fast_kdf();
    let exe = std::env::current_exe().expect("test binary path");
    let mut armed_iterations = 0;
    for i in 0..PROCESS_ITERATIONS {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let paths = build_raced_vault(dir.path());

        let mut child = std::process::Command::new(&exe)
            .args([
                "crypto01_multiprocess_child_worker",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD_DIR_VAR, dir.path())
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn child process");
        wait_for_file(&dir.path().join("ready"), "the child's ready marker");

        let mut b = unlock(&paths);
        let done = std::sync::atomic::AtomicBool::new(false);
        let armed = std::thread::scope(|scope| {
            let rotator = scope.spawn(|| {
                let r = b.set_project_password("p", &spw(common::PROJECT_PW), &common::master_pw());
                done.store(true, std::sync::atomic::Ordering::SeqCst);
                r
            });
            let armed = wait_for_write_lock(&paths.db_path(), &done);
            std::fs::write(dir.path().join("go"), b"go").expect("write go marker");
            rotator
                .join()
                .expect("rotation thread")
                .expect("the concurrent rotation itself must succeed");
            armed
        });
        if armed {
            armed_iterations += 1;
        }

        wait_for_file(&dir.path().join("outcome"), "the child's outcome report");
        let status = child.wait().expect("child exit status");
        assert!(status.success(), "the child test process must not crash");
        let outcome = std::fs::read_to_string(dir.path().join("outcome")).expect("read outcome");
        println!("process-race iter {i}: armed={armed} outcome={outcome}");
        let raced = match outcome.as_str() {
            "ok" => Ok(()),
            "refused" => Err(CoreError::ProjectLocked("p".into())),
            other => panic!("the raced child add failed without a typed refusal: {other}"),
        };
        assert_invariant(&paths, "cnew", raced);
    }
    assert!(
        armed_iterations > 0,
        "no iteration armed the race; the harness lost its determinism"
    );
}
