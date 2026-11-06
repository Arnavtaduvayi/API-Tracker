//! Tethra Mesh store conformance (Increment 03, DESIGN §D21): the Increment
//! 02 simulator, its invariants and the independent oracle, run with every
//! device on a `SqliteStore` in its own temp directory.
//!
//! On top of the simulator's own faults, SQLite devices crash between the
//! chunks of a commit, reopen from disk on every restart, and are cloned by
//! copying their data directory (database and identity marker). At every
//! quiescence each device's in-memory mirror is compared with a fresh load of
//! its database.
//!
//! Replay one seed: `MESH_SIM_SEED=<seed> MESH_SIM_STEPS=<steps> cargo test
//! -p api-tracker-core --test mesh_store_conformance replay`.

use api_tracker_core::db;
use api_tracker_core::mesh::clock::{Clock, ManualClock};
use api_tracker_core::mesh::dot::{DeviceId, MeshId};
use api_tracker_core::mesh::kinds::{MeshSetting, RosterAdd};
use api_tracker_core::mesh::proto::{Action, Limits, Session};
use api_tracker_core::mesh::sign::{derive_device_id, PublicKeyBytes, SigningKeyPair};
use api_tracker_core::mesh::sim::oracle::Oracle;
use api_tracker_core::mesh::sim::sqlite::SqliteFactory;
use api_tracker_core::mesh::sim::world::{run, run_with, SimConfig, SimFailure};
use api_tracker_core::mesh::sqlite_store::{SqliteStore, StoreParams};
use api_tracker_core::mesh::store::{Draft, GenesisInfo, HlcPolicy, MeshStore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

fn run_sqlite(
    cfg: &SimConfig,
    crash_pm: u64,
) -> Result<api_tracker_core::mesh::sim::world::SimReport, SimFailure> {
    let dir = tempfile::tempdir().expect("temp dir");
    let factory = SqliteFactory::new(dir.path(), cfg.seed).commit_crash_pm(crash_pm);
    run_with::<Oracle, _>(cfg, factory)
}

/// Run `configs` over SQLite on all cores; return the failures by seed.
fn run_all(configs: Vec<SimConfig>, crash_pm: u64) -> Vec<SimFailure> {
    let next = AtomicU64::new(0);
    let failures = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst) as usize;
                let Some(cfg) = configs.get(i) else { break };
                if let Err(f) = run_sqlite(cfg, crash_pm) {
                    failures.lock().expect("no poisoned lock").push(f);
                }
            });
        }
    });
    let mut f = failures.into_inner().expect("no poisoned lock");
    f.sort_by_key(|x| x.seed);
    f
}

fn report(failures: &[SimFailure]) -> String {
    failures
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// 30 seeds × 1 500 steps with every simulator fault and adversary plus
/// SQLite crashes between commit chunks (a quarter of the commits that can
/// split): every invariant and the oracle.
#[test]
fn thirty_seeds_with_crashes_between_chunks() {
    let started = Instant::now();
    let configs: Vec<SimConfig> = (0..30).map(|s| SimConfig::from_seed(s, 1_500)).collect();
    let failures = run_all(configs, 250);
    eprintln!(
        "mesh_store_conformance: 30 seeds in {:?}",
        started.elapsed()
    );
    assert!(
        failures.is_empty(),
        "{} failing seed(s):\n{}",
        failures.len(),
        report(&failures)
    );
}

/// With store crashes off, a SQLite run is the same run as a `MemStore` run:
/// the same events, the same minted items (hence the same HLCs and views),
/// the same trace hash.
#[test]
fn without_crashes_sqlite_runs_are_identical_to_memstore_runs() {
    for seed in [3u64, 11, 27, 163] {
        let cfg = SimConfig::from_seed(seed, 800);
        let mem = run::<Oracle>(&cfg).unwrap_or_else(|f| panic!("{f}"));
        let sql = run_sqlite(&cfg, 0).unwrap_or_else(|f| panic!("{f}"));
        assert_eq!(
            mem.trace_hash, sql.trace_hash,
            "MESH_SIM_SEED={seed}: SQLite diverged from MemStore\nmem {mem:?}\nsql {sql:?}"
        );
        assert_eq!(mem.mints, sql.mints);
        assert_eq!(sql.commit_crashes, 0);
    }
}

/// The crash fault really fires, and devices recover from it.
#[test]
fn crashes_between_chunks_happen_and_are_survived() {
    let mut crashes = 0;
    for seed in 100..106u64 {
        let cfg = SimConfig::from_seed(seed, 1_500);
        let r = run_sqlite(&cfg, 1_000).unwrap_or_else(|f| panic!("{f}"));
        crashes += r.commit_crashes;
    }
    assert!(
        crashes >= 6,
        "only {crashes} commits crashed; the fault is barely exercised"
    );
}

/// Long soak (ignored): `MESH_SIM_START`, `MESH_SIM_COUNT`, `MESH_SIM_STEPS`,
/// `MESH_SIM_CRASH_PM`. Run in release.
#[test]
#[ignore]
fn soak() {
    let start = env_u64("MESH_SIM_START").unwrap_or(10_000);
    let count = env_u64("MESH_SIM_COUNT").unwrap_or(500);
    let steps = env_u64("MESH_SIM_STEPS").unwrap_or(2_000);
    let crash = env_u64("MESH_SIM_CRASH_PM").unwrap_or(250);
    let started = Instant::now();
    let configs: Vec<SimConfig> = (start..start + count)
        .map(|s| SimConfig::from_seed(s, steps))
        .collect();
    let failures = run_all(configs, crash);
    eprintln!(
        "mesh_store_conformance soak: {count} seeds x {steps} steps in {:?}",
        started.elapsed()
    );
    assert!(failures.is_empty(), "{}", report(&failures));
}

#[test]
fn replay() {
    let Some(seed) = env_u64("MESH_SIM_SEED") else {
        return;
    };
    let steps = env_u64("MESH_SIM_STEPS").unwrap_or(1_500);
    let crash = env_u64("MESH_SIM_CRASH_PM").unwrap_or(250);
    let cfg = SimConfig::from_seed(seed, steps);
    let mut failing = match run_sqlite(&cfg, crash) {
        Ok(r) => {
            eprintln!("seed {seed}: ok {r:?}");
            return;
        }
        Err(f) => f,
    };
    // Shrink to the shortest failing step count.
    let (mut lo, mut hi) = (0u64, steps);
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        match run_sqlite(&SimConfig::from_seed(seed, mid), crash) {
            Err(f) => {
                hi = mid;
                failing = f;
            }
            Ok(_) => lo = mid,
        }
    }
    panic!("{failing}");
}

// ------------------------------------------------------------- contention

fn device(seed: u8, genesis: Option<GenesisInfo>) -> (SigningKeyPair, DeviceId, GenesisInfo) {
    let key = SigningKeyPair::from_secret_bytes(&[seed; 32]);
    let id = derive_device_id(
        &key.public_key(),
        &PublicKeyBytes([seed; 32]),
        &PublicKeyBytes([seed.wrapping_add(1); 32]),
    );
    let g = genesis.unwrap_or(GenesisInfo {
        mesh_id: MeshId::from_bytes([42; 16]),
        genesis: id,
    });
    (key, id, g)
}

fn open_store(path: &std::path::Path, g: GenesisInfo, id: DeviceId) -> SqliteStore {
    let mut conn = db::open(path).unwrap();
    db::migrate(&mut conn).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(1_700_000_000_000));
    SqliteStore::open(
        conn,
        StoreParams {
            genesis: g,
            self_id: id,
            marker: None,
        },
        clock,
    )
    .unwrap()
}

/// Another connection holds SQLite's write lock for a second (the gateway
/// writer, say). The store's commit waits within `busy_timeout` instead of
/// failing, and nothing is corrupted.
#[test]
fn commits_wait_for_a_busy_writer_and_stay_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let (gk, gid, g) = device(1, None);
    let (bk, bid, _) = device(2, Some(g));
    let mut a = open_store(&dir.path().join("a.db"), g, gid);
    let path_b = dir.path().join("b.db");
    let mut b = open_store(&path_b, g, bid);

    let add = |target_key: &SigningKeyPair, target: DeviceId, seed: u8| RosterAdd {
        device: target,
        name: format!("dev {seed}"),
        sign_pub: target_key.public_key(),
        noise_pub: PublicKeyBytes([seed; 32]),
        seal_pub: PublicKeyBytes([seed.wrapping_add(1); 32]),
        added_by: gid,
    };
    a.mint(&gk, Draft::of(&add(&gk, gid, 1), HlcPolicy::Now))
        .unwrap();
    a.mint(&gk, Draft::of(&add(&bk, bid, 2), HlcPolicy::Now))
        .unwrap();
    for v in 0..20u64 {
        let m = MeshSetting {
            name: format!("s{v}"),
            value: serde_json::json!(v),
        };
        a.mint(&gk, Draft::of(&m, HlcPolicy::After(None))).unwrap();
    }

    // Run one session a -> b, but hold b's database write lock from another
    // connection while b commits.
    let mut sa = Session::new(Limits::default(), Some(bid));
    let mut sb = Session::new(Limits::default(), Some(gid));
    let mut to_b = Vec::new();
    let mut to_a = Vec::new();
    let mut commit = None;
    for act in sa.start(&a) {
        if let Action::Send(f) = act {
            to_b.push(f);
        }
    }
    for act in sb.start(&b) {
        if let Action::Send(f) = act {
            to_a.push(f);
        }
    }
    for _ in 0..20 {
        for f in std::mem::take(&mut to_b) {
            for act in sb.on_frame(f, &b) {
                match act {
                    Action::Send(f) => to_a.push(f),
                    Action::Commit(batch) => commit = Some(batch),
                    _ => {}
                }
            }
        }
        for f in std::mem::take(&mut to_a) {
            for act in sa.on_frame(f, &a) {
                if let Action::Send(f) = act {
                    to_b.push(f);
                }
            }
        }
    }
    let batch = commit.expect("b received a commit");

    let holder = rusqlite::Connection::open(&path_b).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    holder
        .execute(
            "INSERT INTO mesh_meta (key, value) VALUES ('contention_probe', 1)",
            [],
        )
        .unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1_000));
        holder.execute_batch("COMMIT").unwrap();
    });
    let started = Instant::now();
    let out = b
        .commit(batch)
        .expect("the commit waits for the lock, then succeeds");
    let waited = started.elapsed();
    release.join().unwrap();
    assert!(
        waited >= Duration::from_millis(900),
        "it waited: {waited:?}"
    );
    assert!(out.stored >= 22);
    assert_eq!(b.vv(), a.vv());
    assert_eq!(b.state().expected(), a.state().expected());
    b.verify_against_disk().unwrap();
    // The other writer's row is intact too.
    let probe: i64 = b
        .connection()
        .query_row(
            "SELECT value FROM mesh_meta WHERE key='contention_probe'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(probe, 1);
}

/// Commit cost on this machine (ignored; run in release): one origin's range
/// of N items is one transaction, so this is the longest a chunk can hold
/// SQLite's write lock for that range. Prints the timings; asserts nothing
/// about speed.
#[test]
#[ignore]
fn commit_timing() {
    let dir = tempfile::tempdir().unwrap();
    for n in [500u64, 2_000, 10_000] {
        let (gk, gid, g) = device(1, None);
        let (bk, bid, _) = device(2, Some(g));
        let sub = dir.path().join(format!("n{n}"));
        std::fs::create_dir_all(&sub).unwrap();
        let mut a = open_store(&sub.join("a.db"), g, gid);
        // Only the receiving store's commit is measured, at full durability;
        // the sender's thousands of single mints need not be F_FULLFSYNCed.
        a.relax_fsync_for_tests().unwrap();
        let mut b = open_store(&sub.join("b.db"), g, bid);
        let add = |k: &SigningKeyPair, d: DeviceId, s: u8| RosterAdd {
            device: d,
            name: format!("dev {s}"),
            sign_pub: k.public_key(),
            noise_pub: PublicKeyBytes([s; 32]),
            seal_pub: PublicKeyBytes([s.wrapping_add(1); 32]),
            added_by: gid,
        };
        a.mint(&gk, Draft::of(&add(&gk, gid, 1), HlcPolicy::Now))
            .unwrap();
        a.mint(&gk, Draft::of(&add(&bk, bid, 2), HlcPolicy::Now))
            .unwrap();
        for v in 0..n {
            let m = MeshSetting {
                name: format!("s{v}"),
                value: serde_json::json!(v),
            };
            a.mint(&gk, Draft::of(&m, HlcPolicy::After(None))).unwrap();
        }
        let mut sa = Session::new(Limits::default(), Some(bid));
        let mut sb = Session::new(Limits::default(), Some(gid));
        let mut to_b: Vec<_> = sa
            .start(&a)
            .into_iter()
            .filter_map(|x| match x {
                Action::Send(f) => Some(f),
                _ => None,
            })
            .collect();
        let mut to_a: Vec<_> = sb
            .start(&b)
            .into_iter()
            .filter_map(|x| match x {
                Action::Send(f) => Some(f),
                _ => None,
            })
            .collect();
        let mut batch = None;
        for _ in 0..50 {
            for f in std::mem::take(&mut to_a) {
                for act in sa.on_frame(f, &a) {
                    if let Action::Send(f) = act {
                        to_b.push(f);
                    }
                }
            }
            for f in std::mem::take(&mut to_b) {
                for act in sb.on_frame(f, &b) {
                    match act {
                        Action::Send(f) => to_a.push(f),
                        Action::Commit(c) => batch = Some(c),
                        _ => {}
                    }
                }
            }
        }
        let batch = batch.expect("a commit");
        let started = Instant::now();
        b.commit(batch).unwrap();
        eprintln!(
            "commit_timing: {n} items of one origin in {:?} (one transaction)",
            started.elapsed()
        );
    }
}
