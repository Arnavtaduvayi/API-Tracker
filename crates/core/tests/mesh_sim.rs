//! Tethra Mesh: the deterministic simulator against the independent oracle
//! (Increment 02, DESIGN §D21, docs/mesh/TEST_PLAN.md).
//!
//! Every run is fixed by its seed. A failure prints
//! `MESH_SIM_SEED=<seed> MESH_SIM_STEPS=<steps>`, and
//! `MESH_SIM_SEED=<seed> MESH_SIM_STEPS=<steps> cargo test -p api-tracker-core
//! --test mesh_sim replay` reproduces it exactly (same event trace hash), then
//! shrinks it to the shortest failing step count.
//!
//! Long soaks: `scripts/mesh_soak.sh` (runs the ignored `soak` test in release).

use api_tracker_core::mesh::sim::oracle::Oracle;
use api_tracker_core::mesh::sim::world::{run, shrink, Adversary, SimConfig, SimFailure};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

/// Run `configs` on all cores; return every failure (shrunk), sorted by seed.
fn run_all(configs: Vec<SimConfig>) -> Vec<SimFailure> {
    let next = AtomicU64::new(0);
    let failures = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst) as usize;
                let Some(cfg) = configs.get(i) else { break };
                if run::<Oracle>(cfg).is_err() {
                    let f = shrink::<Oracle>(cfg).expect("a failing run still fails");
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

/// CI: 200 seeds × 2 000 steps, 3-6 devices, every fault and adversary mix.
#[test]
fn ci_200_seeds() {
    let started = Instant::now();
    let configs: Vec<SimConfig> = (0..200).map(|s| SimConfig::from_seed(s, 2_000)).collect();
    let failures = run_all(configs);
    eprintln!("mesh_sim: 200 seeds in {:?}", started.elapsed());
    assert!(
        failures.is_empty(),
        "{} failing seed(s):\n{}",
        failures.len(),
        report(&failures)
    );
}

/// Seeds that found real bugs while Increment 02 was built (STATUS.md, the
/// Increment 02 disagreement log). Each must keep passing.
#[test]
fn regression_seeds() {
    let at_2000 = [4u64, 15, 34, 163, 1000, 1004, 1178];
    let at_3000 = [
        1_008_114u64,
        1_008_759,
        1_011_053,
        1_012_130,
        1_015_682,
        1_016_234,
        1_017_206,
        1_017_426,
        1_018_365,
        1_019_427,
        1_021_656,
    ];
    let configs: Vec<SimConfig> = at_2000
        .iter()
        .map(|s| SimConfig::from_seed(*s, 2_000))
        .chain(at_3000.iter().map(|s| SimConfig::from_seed(*s, 3_000)))
        .collect();
    let failures = run_all(configs);
    assert!(failures.is_empty(), "{}", report(&failures));
}

/// Replay one seed (`MESH_SIM_SEED`, `MESH_SIM_STEPS`): it must reproduce
/// exactly, and a failure is shrunk to its shortest failing prefix.
#[test]
fn replay() {
    let seed = env_u64("MESH_SIM_SEED").unwrap_or(12_345);
    let steps = env_u64("MESH_SIM_STEPS").unwrap_or(2_000);
    let cfg = SimConfig::from_seed(seed, steps);
    match (run::<Oracle>(&cfg), run::<Oracle>(&cfg)) {
        (Ok(a), Ok(b)) => {
            assert_eq!(
                a.trace_hash, b.trace_hash,
                "the same seed must replay identically"
            );
            eprintln!(
                "MESH_SIM_SEED={seed} MESH_SIM_STEPS={steps}: ok, trace {}",
                a.trace_hash
            );
        }
        (Err(a), Err(b)) => {
            assert_eq!(a, b, "a failure must reproduce identically");
            let shortest = shrink::<Oracle>(&cfg).expect("still fails");
            panic!("{a}\nshortest failing prefix: {shortest}");
        }
        (a, b) => panic!("nondeterministic replay: {a:?} vs {b:?}"),
    }
}

/// Each adversarial injection, alone, actually happens and is defended.
#[test]
fn each_adversary_alone_is_exercised_and_defended() {
    let only = |a: Adversary| -> Vec<SimConfig> {
        (0..12u64)
            .map(|s| SimConfig {
                adversary: a,
                ..SimConfig::from_seed(10_000 + s, 2_000)
            })
            .collect()
    };
    let none = Adversary::default();
    let cases = [
        (
            "forged origin",
            Adversary {
                forged_origin: true,
                ..none
            },
        ),
        (
            "replay",
            Adversary {
                replay: true,
                ..none
            },
        ),
        ("fork", Adversary { fork: true, ..none }),
        (
            "huge seq",
            Adversary {
                huge_seq: true,
                ..none
            },
        ),
        (
            "far-future HLC",
            Adversary {
                far_future_hlc: true,
                ..none
            },
        ),
    ];
    for (name, adv) in cases {
        let configs = only(adv);
        let injections: u64 = configs
            .iter()
            .filter_map(|c| run::<Oracle>(c).ok())
            .map(|r| r.injections + r.forks_reported)
            .sum();
        let failures = run_all(configs);
        assert!(failures.is_empty(), "{name}:\n{}", report(&failures));
        if name != "far-future HLC" {
            assert!(injections > 0, "{name}: no injection happened in 12 seeds");
        }
    }
}

/// Long soak (ignored in CI): `MESH_SIM_SEEDS` seeds starting at
/// `MESH_SIM_START`, `MESH_SIM_STEPS` steps each. Prints every failing seed.
#[test]
#[ignore]
fn soak() {
    let count = env_u64("MESH_SIM_SEEDS").unwrap_or(1_000);
    let start = env_u64("MESH_SIM_START").unwrap_or(1_000_000);
    let steps = env_u64("MESH_SIM_STEPS").unwrap_or(3_000);
    let began = Instant::now();
    let configs: Vec<SimConfig> = (start..start + count)
        .map(|s| SimConfig::from_seed(s, steps))
        .collect();
    let failures = run_all(configs);
    eprintln!(
        "mesh soak: {count} seeds from {start} ({steps} steps) in {:?}, {} failing",
        began.elapsed(),
        failures.len()
    );
    for f in &failures {
        eprintln!("SOAK-FAIL {f}");
    }
    assert!(failures.is_empty(), "{}", report(&failures));
}

// ------------------------------------------------- spend caps (Increment 07)
//
// The caps scenario family (`mesh::sim::caps`): 3-5 SQLite devices running
// the real cap policy. Fewer seeds than the protocol simulator: every step
// writes to real databases. Long runs: `scripts/mesh_soak.sh --scenario caps`.

use api_tracker_core::mesh::sim::caps::{
    run_caps, CapsConfig, CapsFailure, CapsInjections, CapsReport,
};

fn caps_run(cfg: &CapsConfig) -> Result<CapsReport, CapsFailure> {
    let dir = tempfile::TempDir::new().expect("temp dir");
    run_caps(cfg, dir.path())
}

fn caps_run_all(configs: Vec<CapsConfig>) -> (Vec<CapsReport>, Vec<CapsFailure>) {
    let next = AtomicU64::new(0);
    let out = Mutex::new((Vec::new(), Vec::new()));
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst) as usize;
                let Some(cfg) = configs.get(i) else { break };
                let r = caps_run(cfg);
                let mut o = out.lock().expect("no poisoned lock");
                match r {
                    Ok(rep) => o.0.push(rep),
                    Err(f) => o.1.push(f),
                }
            });
        }
    });
    let (reports, mut failures) = out.into_inner().expect("no poisoned lock");
    failures.sort_by_key(|f| f.seed);
    (reports, failures)
}

fn caps_report(failures: &[CapsFailure]) -> String {
    failures
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// CI: 16 seeds × 240 two-hour steps (2027-01-18 to 2027-02-07, across day
/// 20 and the month boundary), every injection mix.
#[test]
fn caps_ci_seeds() {
    let started = Instant::now();
    let configs: Vec<CapsConfig> = (0..16).map(|s| CapsConfig::from_seed(s, 240)).collect();
    let (reports, failures) = caps_run_all(configs);
    eprintln!("mesh_sim caps: 16 seeds in {:?}", started.elapsed());
    assert!(failures.is_empty(), "{}", caps_report(&failures));
    let refused: u64 = reports.iter().map(|r| r.spends_refused).sum();
    let grants: u64 = reports.iter().map(|r| r.grants).sum();
    assert!(refused > 0, "the workload never reached a cap");
    assert!(grants > 0, "no rights request was ever granted");
}

/// One injection: its name, how to switch it on, and how a report shows it
/// ran.
type InjectionCase = (
    &'static str,
    fn(&mut CapsInjections),
    fn(&CapsReport) -> bool,
);

/// Each injection on its own, on a few seeds, does what it says.
#[test]
fn caps_each_injection_alone_is_exercised_and_defended() {
    let only = |f: fn(&mut CapsInjections)| {
        (100..103u64)
            .map(|seed| {
                let mut cfg = CapsConfig::from_seed(seed, 240);
                cfg.inject = CapsInjections::default();
                f(&mut cfg.inject);
                cfg
            })
            .collect::<Vec<_>>()
    };
    let cases: [InjectionCase; 5] = [
        (
            "owner offline across the boundary",
            |i| i.owner_offline_across_boundary = true,
            |r| r.boundary_checked,
        ),
        (
            "concurrent lowers",
            |i| i.concurrent_lowers = true,
            |r| r.lowers >= 2,
        ),
        (
            "partitioned override",
            |i| i.partitioned_override = true,
            |r| r.overrides == 1,
        ),
        ("owner removal", |i| i.owner_removal = true, |r| r.frozen),
        ("forged transfer", |i| i.forged_transfer = true, |_| true),
    ];
    for (name, set, exercised) in cases {
        let (reports, failures) = caps_run_all(only(set));
        assert!(failures.is_empty(), "{name}: {}", caps_report(&failures));
        assert!(reports.iter().all(exercised), "{name} was not exercised");
    }
}

/// The same seed gives the same decisions: `MESH_SIM_SEED` (default 7).
#[test]
fn caps_replay_is_deterministic() {
    let seed = env_u64("MESH_SIM_SEED").unwrap_or(7);
    let steps = env_u64("MESH_SIM_STEPS").unwrap_or(240);
    let cfg = CapsConfig::from_seed(seed, steps);
    let a = caps_run(&cfg).unwrap_or_else(|f| panic!("{f}"));
    let b = caps_run(&cfg).unwrap_or_else(|f| panic!("{f}"));
    assert_eq!(a.trace_hash, b.trace_hash);
    assert_eq!(a, b);
}

/// Long run (ignored in CI; `scripts/mesh_soak.sh --scenario caps`):
/// `MESH_SIM_SEEDS` seeds from `MESH_SIM_START`, `MESH_SIM_STEPS` steps.
#[test]
#[ignore]
fn caps_family_long() {
    let count = env_u64("MESH_SIM_SEEDS").unwrap_or(100);
    let start = env_u64("MESH_SIM_START").unwrap_or(5_000_000);
    let steps = env_u64("MESH_SIM_STEPS").unwrap_or(240);
    let began = Instant::now();
    let configs: Vec<CapsConfig> = (start..start + count)
        .map(|s| CapsConfig::from_seed(s, steps))
        .collect();
    let (_, failures) = caps_run_all(configs);
    eprintln!(
        "mesh soak: {count} caps seeds from {start} ({steps} steps) in {:?}, {} failing",
        began.elapsed(),
        failures.len()
    );
    for f in &failures {
        eprintln!("SOAK-FAIL {f}");
    }
    assert!(failures.is_empty(), "{}", caps_report(&failures));
}
