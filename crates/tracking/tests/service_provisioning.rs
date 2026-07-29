//! Step 3 of the apply engine, driven through the ordered install primitive
//! (`NEW-02`).
//!
//! `apply` used to call `lc.install` / `lc.repair` directly. Its own step
//! order was right — the port is persisted at step 2, the service starts at
//! step 3 — but it inherited both gaps the primitive exists to close: nothing
//! proved the started service had bound the port the plan was built against,
//! and `repair` restarted a service that resolves its port from the database
//! without first guaranteeing a port was there to resolve. `tethra track`
//! reaches that repair path automatically, with no user decision behind it.
//!
//! Everything here runs against a mock `CommandRunner`, a fake `InstallHost`
//! and a temporary directory: no port is bound, no service definition reaches
//! `~/Library/LaunchAgents`, and no launchd verb is ever executed.

#![cfg(unix)] // Unix service-manager (LaunchAgent) behavior

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_tracker_core::db;
use api_tracker_gateway::control::{ListenerIdentity, Status};
use api_tracker_gateway::lifecycle::provision::{InstallHost, InstallStage, PortReservation};
use api_tracker_gateway::lifecycle::{macos::LaunchAgent, CommandRunner, Lifecycle, RunOutput};
use api_tracker_gateway::store::{self, PortState};
use api_tracker_tracking::apply::ensure_service_steps;
use api_tracker_tracking::plan::ServiceAction;
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// Fakes — the same seams `crates/gateway/tests/lifecycle_provision.rs` uses,
// so the tracking caller is exercised against the real algorithm rather than
// against a re-implementation of it.
// ---------------------------------------------------------------------------

/// Records every OS interaction and samples the persisted port at the exact
/// instant the OS would act — which is the only instant NEW-02 is about.
struct SpyRunner {
    data_dir: PathBuf,
    calls: Mutex<Vec<String>>,
    observed: Mutex<Vec<(String, PortState)>>,
}

impl SpyRunner {
    fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            calls: Mutex::new(Vec::new()),
            observed: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// What a service booting at each OS interaction would have read.
    fn observed_at(&self, needle: &str) -> Vec<PortState> {
        self.observed
            .lock()
            .unwrap()
            .iter()
            .filter(|(cmd, _)| cmd.contains(needle))
            .map(|(_, state)| state.clone())
            .collect()
    }
}

impl CommandRunner for SpyRunner {
    fn run(&self, program: &str, args: &[&str]) -> api_tracker_core::error::Result<RunOutput> {
        let mut call = vec![program.to_string()];
        call.extend(args.iter().map(|s| s.to_string()));
        let joined = call.join(" ");
        self.calls.lock().unwrap().push(joined.clone());
        self.observed
            .lock()
            .unwrap()
            .push((joined, store::port_state(&self.data_dir)));

        if args == ["gateway", "service-probe"] {
            return Ok(RunOutput {
                status: 0,
                stdout: format!("{} 0.1.0\n", api_tracker_gateway::lifecycle::PROBE_MARKER),
                stderr: String::new(),
            });
        }
        if program == "id" {
            return Ok(RunOutput {
                status: 0,
                stdout: "501\n".into(),
                stderr: String::new(),
            });
        }
        if program == "launchctl" && args.first() == Some(&"print") {
            // Nothing registered: install starts rather than restarts.
            return Ok(RunOutput {
                status: 113,
                stdout: String::new(),
                stderr: "Could not find service".into(),
            });
        }
        Ok(RunOutput {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    fn spawn_detached(&self, program: &str, args: &[&str]) -> api_tracker_core::error::Result<()> {
        let mut call = vec!["spawn".to_string(), program.to_string()];
        call.extend(args.iter().map(|s| s.to_string()));
        self.calls.lock().unwrap().push(call.join(" "));
        Ok(())
    }
}

/// A host with no sockets, no control channel and no clock.
struct FakeHost {
    reservable: u16,
    probe: ListenerIdentity,
    stages: Mutex<Vec<InstallStage>>,
}

impl FakeHost {
    fn healthy(port: u16) -> Self {
        Self {
            reservable: port,
            probe: ListenerIdentity::Verified {
                version: "0.1.0".into(),
            },
            stages: Mutex::new(Vec::new()),
        }
    }

    /// The service starts and then never answers — an exit code claiming
    /// success with nothing behind it.
    fn silent(port: u16) -> Self {
        Self {
            probe: ListenerIdentity::NoListener,
            ..Self::healthy(port)
        }
    }

    fn saw_port_commit(&self) -> bool {
        self.stages
            .lock()
            .unwrap()
            .iter()
            .any(|s| matches!(s, InstallStage::PortCommitted { .. }))
    }
}

impl InstallHost for FakeHost {
    fn reserve_port(&self) -> api_tracker_core::error::Result<PortReservation> {
        // `adopted`, never `fresh`: this suite binds no sockets.
        Ok(PortReservation::adopted(self.reservable))
    }

    fn verify_listener(&self, _data_dir: &Path, _port: u16) -> ListenerIdentity {
        self.probe.clone()
    }

    fn control_status(&self, _data_dir: &Path) -> Option<Status> {
        None
    }

    fn sleep(&self, _d: Duration) {}

    fn observe(&self, stage: InstallStage) {
        self.stages.lock().unwrap().push(stage);
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Rig {
    _dir: tempfile::TempDir,
    runner: Arc<SpyRunner>,
    lc: Lifecycle,
    conn: Connection,
    src: PathBuf,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let runner = Arc::new(SpyRunner::new(&data_dir));
    let agent = LaunchAgent::new(
        &data_dir,
        // A temp directory, NOT ~/Library/LaunchAgents: this suite must not
        // be able to touch a real user's services even if it goes wrong.
        dir.path().join("LaunchAgents"),
        "501".into(),
        runner.clone(),
    );
    let lc = Lifecycle {
        data_dir: data_dir.clone(),
        manager: Box::new(agent),
        runner: runner.clone(),
        version: "0.1.0".into(),
    };
    let mut conn = db::open(&data_dir.join("vault.db")).unwrap();
    db::migrate(&mut conn).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('vault_id', 'vault-test-0001')",
        [],
    )
    .unwrap();
    let src = dir.path().join("tethra");
    std::fs::write(&src, b"#!/bin/true\nfake-binary-bytes").unwrap();
    Rig {
        _dir: dir,
        runner,
        lc,
        conn,
        src,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The repair gap, at the caller `tethra track` reaches on its own.
///
/// `lc.repair` starts a service that reads `gateway_config.port` at boot. On
/// an installation where that column is still NULL — the state
/// `plan::ensure_port` deliberately produces, and the one a re-run after a
/// failed apply lands in — the direct call started a service that bound an
/// unrelated ephemeral port and reported success. Restoring the direct
/// `lc.repair` call in `apply.rs` fails this test on the first assertion.
#[test]
fn a_repair_from_apply_commits_a_port_before_the_service_starts() {
    let r = rig();
    assert_eq!(
        store::load_config(&r.conn).unwrap().port,
        None,
        "the fixture must start with the NULL port this test is about"
    );
    let host = FakeHost::healthy(45_201);

    ensure_service_steps(
        &r.lc,
        &r.conn,
        &host,
        &r.src,
        &[ServiceAction::RepairService {
            installed: "0.0.9".into(),
            current: "0.1.0".into(),
        }],
    )
    .unwrap();

    assert_eq!(
        store::load_config(&r.conn).unwrap().port,
        Some(45_201),
        "a repair that starts a port-reading service must commit the port first"
    );
    assert!(host.saw_port_commit());
    let at_launchctl = r.runner.observed_at("launchctl");
    assert!(
        !at_launchctl.is_empty(),
        "the service manager was never invoked, so this test proved nothing"
    );
    for observed in &at_launchctl {
        assert_eq!(
            observed,
            &PortState::Persisted(45_201),
            "a service booting at this instant would have read {observed:?} and bound a \
             DIFFERENT port from the one the apply's .env writes point at (NEW-02)"
        );
    }
}

/// The verification gap, on the install action. The engine's exit code says
/// the service was registered and started; only the identity probe says
/// anything answered. Step 3 must fail when nothing did.
#[test]
fn an_install_whose_service_never_answers_is_an_error_not_a_started_service() {
    let r = rig();
    let host = FakeHost::silent(45_202);

    let err = ensure_service_steps(
        &r.lc,
        &r.conn,
        &host,
        &r.src,
        &[ServiceAction::InstallService],
    )
    .expect_err("an unverified service must not report success from an exit code alone");

    let text = err.to_string();
    assert!(
        text.contains("identity probe"),
        "the failure must name what was not proved, got: {text}"
    );
    assert!(
        !text.contains("execution probe"),
        "a silent listener is not the Gatekeeper signature, and must not be \
         reported as one (ZFT-039): {text}"
    );
    assert!(
        !store::load_config(&r.conn).unwrap().enabled,
        "an install that could not be verified must not leave the gateway enabled"
    );
}

/// The two actions that install nothing must not reach the installer at all:
/// a plan that only needs the existing service started has no definition to
/// write and no port to decide.
#[test]
fn start_and_already_running_never_reach_the_installer() {
    let r = rig();
    let host = FakeHost::healthy(45_203);

    ensure_service_steps(
        &r.lc,
        &r.conn,
        &host,
        &r.src,
        &[ServiceAction::AlreadyRunning, ServiceAction::StartService],
    )
    .unwrap();

    assert!(!host.saw_port_commit());
    assert_eq!(
        store::load_config(&r.conn).unwrap().port,
        None,
        "starting an installed service decides nothing about the port"
    );
    let calls = r.runner.calls();
    assert!(
        calls.iter().all(|c| !c.contains("bootstrap")),
        "nothing was installed, so nothing may be registered: {calls:?}"
    );
}
