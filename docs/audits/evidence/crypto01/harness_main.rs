//! CRYPTO-01 / CONC-03 reproduction harness (audit-only).
//!
//! Claim under test: `add_credential` / `replace_credential_value` read the
//! project row and derive the project key, then encrypt and INSERT/UPDATE in a
//! SEPARATE (autocommit) statement with no enclosing transaction. A concurrent
//! `set_project_password` (project-key rotation) that commits inside that
//! window makes the write land encrypted under the OLD project key, whose wrap
//! the rotation has destroyed -> permanently undecryptable ciphertext (silent
//! data loss), and a "sticky" failure that also wedges future rotations.
//!
//! The BLAKE3 wrap-hash freshness check in `project_key_for_row` is validated
//! here too: when A reads a POST-rotation row, the check refuses (ProjectLocked)
//! and NO bad data is written. That is the case the first reviewer called
//! "SOLID". The residual window is the intra-operation TOCTOU below.
//!
//! Determinism: a raw SQLite connection holds the write lock so thread A
//! reliably parks AT its INSERT, having already read the pre-rotation wrap and
//! cached key. The only per-iteration coin flip is which of {A-insert,
//! B-rotate} grabs the freed lock first; B-first => orphan. Every reproduced
//! orphan is then subjected to a DETERMINISTIC consequence check: the value is
//! unrecoverable and a further rotation fails 100% of the time.
//!
//! Uses only fake test credential values. Debug-only weak KDF for speed; the
//! defect is in key management, not KDF strength.

use api_tracker_core::error::CoreError;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, AddCredential, NewProject, VaultPaths};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const MASTER: &str = "audit-master-password"; // >= 12 chars
const PROJECT_PW: &str = "audit-project-password"; // >= 12 chars
const FAKE: &str = "FAKE-AUDIT-NOT-A-REAL-KEY-000001";

fn spw(s: &str) -> SecretString {
    SecretString::from(s)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
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

fn main() {
    std::env::set_var("API_TRACKER_INSECURE_FAST_KDF", "1");

    let iters: usize = env_usize("ITERS", 15);
    let pad: usize = env_usize("PAD", 1200); // credentials B must re-encrypt (widens B's lock hold)
    let delay_ms: u64 = env_usize("DELAY_MS", 20) as u64; // head start so B holds the write lock
    let tmp_root = std::env::var("TMP_ROOT").unwrap_or_else(|_| "/tmp/crypto01".to_string());

    let mut orphans = 0usize;
    let mut wedges = 0usize;
    let mut c0_survived = 0usize;
    let mut a_refused = 0usize; // freshness check caught the stale case: NO data written
    let mut a_ok_clean = 0usize;
    let mut other = 0usize;

    for i in 0..iters {
        let dir = PathBuf::from(format!("{tmp_root}/iter{i}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = VaultPaths::new(dir.join("data"));

        // ---- setup: password-locked project. Pad with many credentials so
        //      B's rotation (which re-encrypts every value) HOLDS the write
        //      lock long enough for A to read the pre-rotation wrap and block
        //      at its INSERT while B is still mid-transaction. ----
        {
            let mut s = vault::create_vault(&paths, &spw(MASTER)).expect("create_vault");
            s.create_project(NewProject {
                name: "p".into(),
                ..Default::default()
            })
            .expect("create_project");
            s.set_project_password("p", &spw(PROJECT_PW), &spw(MASTER))
                .expect("set_project_password");
            s.add_credential(make_add("p", "c0", FAKE)).expect("add c0");
            for k in 0..pad {
                // distinct values -> distinct fingerprints, so A's reuse scan
                // stays cheap (A must reach its INSERT quickly); B still has to
                // re-encrypt them all.
                s.add_credential(make_add("p", &format!("pad{k}"), &format!("FAKE-AUDIT-PAD-{k:06}")))
                    .expect("add pad");
            }
        }

        // ---- two independent sessions on the same vault DB (desktop + CLI) ----
        let mut a = vault::unlock_vault(&paths, &spw(MASTER)).expect("unlock A");
        a.unlock_project("p", &spw(PROJECT_PW)).expect("A unlock_project");
        let mut b = vault::unlock_vault(&paths, &spw(MASTER)).expect("unlock B");
        b.unlock_project("p", &spw(PROJECT_PW)).expect("B unlock_project");

        let add = make_add("p", "cnew", FAKE);
        let ppw = spw(PROJECT_PW);
        let mpw = spw(MASTER);

        let ra = thread::scope(|scope| {
            // B: rotate the project key. Acquires the single SQLite write lock
            // and holds it for the whole re-encrypt loop (all `pad` values),
            // updating the project wrap LAST, then committing (destroys W1/K1).
            let tb = scope.spawn(|| b.set_project_password("p", &ppw, &mpw));
            thread::sleep(Duration::from_millis(delay_ms)); // let B take the write lock mid-rotation
                                                            // A: reads the projects row = W1 (B uncommitted -> snapshot is
                                                            // pre-rotation), freshness OK -> K1, encrypts "cnew" under K1,
                                                            // then blocks at its INSERT behind B's held write lock.
            let ta = scope.spawn(|| a.add_credential(add));
            let rb = tb.join().unwrap();
            let ra = ta.join().unwrap(); // unblocks after B commits: INSERT lands under orphaned K1
            let _ = rb;
            ra
        });

        // ---- detection: fresh session; is "cnew" recoverable under CURRENT key? ----
        let mut c = vault::unlock_vault(&paths, &spw(MASTER)).expect("unlock C");
        let unlocked = c.unlock_project("p", &spw(PROJECT_PW));
        match (&ra, &unlocked) {
            (Ok(_), Ok(_)) => match c.reveal_credential("p/cnew", &spw(MASTER)) {
                Err(CoreError::Crypto { .. }) => {
                    orphans += 1;
                    // c0 must still decrypt: the vault is not generally broken,
                    // ONLY the raced write is lost.
                    if c.reveal_credential("p/c0", &spw(MASTER)).is_ok() {
                        c0_survived += 1;
                    }
                    // Deterministic consequence: a further rotation cannot
                    // decrypt the orphan, so it fails and the project is wedged.
                    let w = c.set_project_password("p", &spw(PROJECT_PW), &spw(MASTER));
                    if w.is_err() {
                        wedges += 1;
                    }
                    println!(
                        "iter {i}: ORPHAN | add=Ok reveal(cnew)=Crypto c0_ok={} rotate_wedge={}",
                        c.reveal_credential("p/c0", &spw(MASTER)).is_ok(),
                        w.is_err()
                    );
                }
                Ok(_) => {
                    a_ok_clean += 1;
                }
                Err(e) => {
                    other += 1;
                    println!("iter {i}: reveal-other {e:?}");
                }
            },
            (Err(CoreError::ProjectLocked(_)), _) => {
                a_refused += 1; // freshness DEFENSE worked: A read post-rotation wrap, refused
            }
            (Err(e), _) => {
                other += 1;
                println!("iter {i}: A-err {e:?}");
            }
            (Ok(_), Err(e)) => {
                other += 1;
                println!("iter {i}: C-unlock-err {e:?}");
            }
        }
    }

    println!("\n==== CRYPTO-01 / CONC-03 reproduction summary ====");
    println!("iterations                    : {iters}");
    println!("ORPHANED ciphertext (dataloss): {orphans}");
    println!("  ... c0 still recoverable    : {c0_survived}  (loss is scoped to the raced write)");
    println!("  ... future rotation WEDGED  : {wedges}  (deterministic: orphan cannot be re-encrypted)");
    println!("A refused via freshness check : {a_refused}  (stale-cache case handled cleanly, no data written)");
    println!("A committed, no orphan        : {a_ok_clean}");
    println!("other                         : {other}");
    if orphans > 0 {
        println!("\nRESULT: REPRODUCED unrecoverable ciphertext from a concurrent project-key rotation.");
    } else {
        println!("\nRESULT: no orphan this run (timing); see transaction proof in the report.");
    }
}
