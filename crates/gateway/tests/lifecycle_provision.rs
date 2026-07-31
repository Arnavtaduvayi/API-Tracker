//! The ordered install primitive (NEW-02).
//!
//! Everything here runs against a mock command runner, a faked
//! [`InstallHost`] and temporary directories: `cargo test` never installs,
//! starts, stops, or queries a REAL service on the developer's machine, and
//! never binds a port it did not choose deliberately.
//!
//! The load-bearing test is
//! `install_commits_the_port_before_the_service_is_registered_or_started`.
//! It works by making the MOCK be the service's boot-time read: the runner
//! reads `gateway_config.port` at the exact instant launchd would spawn the
//! process, and records what a service booting right then would have seen.
//! On the old ordering (start, then persist) that read returns `None` on
//! every run, on every machine, with no sleeps, threads or sockets involved
//! — so the test is a pure happens-before assertion, and no amount of
//! retrying, waiting or after-the-fact repair can make it pass. Only moving
//! the commit earlier does.

#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_tracker_core::db;
use api_tracker_gateway::control::{ListenerIdentity, Status};
use api_tracker_gateway::lifecycle::provision::{
    self, InstallHost, InstallRequest, InstallStage, PortReservation,
};
use api_tracker_gateway::lifecycle::{
    self, macos::LaunchAgent, CommandRunner, DefinitionState, Lifecycle, RunOutput,
};
use api_tracker_gateway::store::{self, PortState};
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/// Which launchctl verbs the mock should fail, so a test can put the engine
/// into each of its rollback paths without a real service manager.
#[derive(Default, Clone, Copy)]
struct Failures {
    bootstrap: bool,
    kickstart: bool,
}

/// Records every invocation and — crucially — reads the persisted port at
/// the moment the OS would act, which is the only instant that matters for
/// NEW-02.
struct SpyRunner {
    data_dir: PathBuf,
    calls: Mutex<Vec<Vec<String>>>,
    /// `store::port_state` sampled at every runner invocation, paired with
    /// the command that triggered the sample.
    observed: Mutex<Vec<(String, PortState)>>,
    fail: Failures,
}

impl SpyRunner {
    fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            calls: Mutex::new(Vec::new()),
            observed: Mutex::new(Vec::new()),
            fail: Failures::default(),
        }
    }

    fn failing(data_dir: &Path, fail: Failures) -> Self {
        Self {
            fail,
            ..Self::new(data_dir)
        }
    }

    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }

    fn call_index(&self, needle: &str) -> Option<usize> {
        self.calls()
            .iter()
            .position(|c| c.join(" ").contains(needle))
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

    fn all_observations(&self) -> Vec<(String, PortState)> {
        self.observed.lock().unwrap().clone()
    }
}

impl CommandRunner for SpyRunner {
    fn run(&self, program: &str, args: &[&str]) -> api_tracker_core::error::Result<RunOutput> {
        let mut call = vec![program.to_string()];
        call.extend(args.iter().map(|s| s.to_string()));
        let joined = call.join(" ");
        self.calls.lock().unwrap().push(call);
        // The service's boot-time read, executed at the only instant that
        // matters. No sleeping, no threads, no flakiness.
        self.observed
            .lock()
            .unwrap()
            .push((joined, store::port_state(&self.data_dir)));

        if args == ["gateway", "service-probe"] {
            return Ok(RunOutput {
                status: 0,
                stdout: format!("{} 0.1.0\n", lifecycle::PROBE_MARKER),
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
            // Nothing is running: `install` therefore starts rather than
            // restarts, which is the fresh-machine path the bug lived on.
            return Ok(RunOutput {
                status: 113,
                stdout: String::new(),
                stderr: "Could not find service".into(),
            });
        }
        if program == "launchctl" && args.first() == Some(&"bootstrap") && self.fail.bootstrap {
            return Ok(RunOutput {
                status: 112,
                stdout: String::new(),
                stderr: "Bootstrap failed: 112: could not bind to port".into(),
            });
        }
        if program == "launchctl" && args.first() == Some(&"kickstart") && self.fail.kickstart {
            return Ok(RunOutput {
                status: 118,
                stdout: String::new(),
                stderr: "Could not kickstart service".into(),
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
        self.calls.lock().unwrap().push(call);
        Ok(())
    }
}

/// A host with no sockets, no control channel and no clock.
struct FakeHost {
    /// The port `reserve_port` hands out, or an error to simulate a failure
    /// before anything has been persisted.
    reservable: Option<u16>,
    /// What the identity probe answers, in order; the last entry repeats.
    probe: Mutex<Vec<ListenerIdentity>>,
    /// What the running gateway says its own port is.
    live_port: Option<u16>,
    stages: Mutex<Vec<InstallStage>>,
    sleeps: Mutex<u32>,
}

impl FakeHost {
    fn healthy(port: Option<u16>) -> Self {
        Self {
            reservable: port,
            probe: Mutex::new(vec![ListenerIdentity::Verified {
                version: "0.1.0".into(),
            }]),
            live_port: None,
            stages: Mutex::new(Vec::new()),
            sleeps: Mutex::new(0),
        }
    }

    fn with_probe(mut self, identities: Vec<ListenerIdentity>) -> Self {
        self.probe = Mutex::new(identities);
        self
    }

    fn with_live_port(mut self, port: u16) -> Self {
        self.live_port = Some(port);
        self
    }

    fn stages(&self) -> Vec<InstallStage> {
        self.stages.lock().unwrap().clone()
    }

    fn stage_names(&self) -> Vec<&'static str> {
        self.stages()
            .iter()
            .map(|s| match s {
                InstallStage::PlanValidated => "PlanValidated",
                InstallStage::PortSelected { .. } => "PortSelected",
                InstallStage::PortCommitted { .. } => "PortCommitted",
                InstallStage::ServiceStarted { .. } => "ServiceStarted",
                InstallStage::ListenerVerified { .. } => "ListenerVerified",
                InstallStage::Enabled { .. } => "Enabled",
                InstallStage::RolledBack { .. } => "RolledBack",
                InstallStage::Note(_) => "Note",
            })
            .collect()
    }
}

impl InstallHost for FakeHost {
    fn reserve_port(&self) -> api_tracker_core::error::Result<PortReservation> {
        match self.reservable {
            Some(port) => Ok(PortReservation::adopted(port)),
            None => Err(api_tracker_core::error::CoreError::InvalidInput(
                "no port could be reserved".into(),
            )),
        }
    }

    fn verify_listener(&self, _data_dir: &Path, _port: u16) -> ListenerIdentity {
        let mut probe = self.probe.lock().unwrap();
        if probe.len() > 1 {
            probe.remove(0)
        } else {
            probe[0].clone()
        }
    }

    fn control_status(&self, _data_dir: &Path) -> Option<Status> {
        self.live_port.map(|port| Status {
            version: "0.1.0".into(),
            port,
            ..Status::default()
        })
    }

    fn sleep(&self, _d: Duration) {
        *self.sleeps.lock().unwrap() += 1;
    }

    fn observe(&self, stage: InstallStage) {
        self.stages.lock().unwrap().push(stage);
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn fake_source_binary(dir: &Path) -> PathBuf {
    let src = dir.join("tethra");
    std::fs::write(&src, b"#!/bin/true\nfake-binary-bytes").unwrap();
    src
}

fn mac_lifecycle(dir: &Path, runner: Arc<SpyRunner>) -> Lifecycle {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let agent = LaunchAgent::new(
        &data_dir,
        dir.join("LaunchAgents"),
        "501".into(),
        runner.clone(),
    );
    Lifecycle {
        data_dir,
        manager: Box::new(agent),
        runner,
        version: "0.1.0".into(),
    }
}

fn migrated(path: &Path) -> Connection {
    let mut conn = db::open(path).unwrap();
    db::migrate(&mut conn).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('vault_id', 'vault-test-0001')",
        [],
    )
    .unwrap();
    conn
}

/// A whole install rig: temp dir, spy runner, lifecycle, migrated vault.
struct Rig {
    _dir: tempfile::TempDir,
    runner: Arc<SpyRunner>,
    lc: Lifecycle,
    conn: Connection,
    src: PathBuf,
}

fn rig() -> Rig {
    rig_with(Failures::default())
}

fn rig_with(fail: Failures) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let runner = Arc::new(SpyRunner::failing(&data_dir, fail));
    let lc = mac_lifecycle(dir.path(), runner.clone());
    let conn = migrated(&lc.data_dir.join("vault.db"));
    let src = fake_source_binary(dir.path());
    Rig {
        _dir: dir,
        runner,
        lc,
        conn,
        src,
    }
}

fn request(src: &Path) -> InstallRequest<'_> {
    let mut req = InstallRequest::new(src, false, "0.1.0");
    // The fake clock makes the budget free; keep it small so a failing
    // probe test does not spin 40 times for nothing.
    req.verify_attempts = 4;
    req.probe_interval = Duration::from_millis(1);
    req
}

fn audit_rows(conn: &Connection, event: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM audit_events WHERE event = ?1",
        [event],
        |r| r.get(0),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// 1. The ordering invariant itself
// ---------------------------------------------------------------------------

/// THE regression test for NEW-02.
///
/// Fails deterministically on the old ordering (`lc.install` before
/// `save_config`), because the runner's read at bootstrap/kickstart time
/// would return `NoneYet` on a fresh vault and the assertion compares it
/// against `Persisted(port)`.
#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn install_commits_the_port_before_the_service_is_registered_or_started() {
    let r = rig();
    let host = FakeHost::healthy(Some(45_001));

    let outcome = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap();

    let at_bootstrap = r.runner.observed_at("launchctl bootstrap");
    assert!(
        !at_bootstrap.is_empty(),
        "the service was never registered, so this test proved nothing"
    );
    for observed in &at_bootstrap {
        assert_eq!(
            observed,
            &PortState::Persisted(outcome.port),
            "a service booting at this instant would have read {observed:?} and bound a \
             DIFFERENT ephemeral port (NEW-02)"
        );
    }
    let at_kickstart = r.runner.observed_at("launchctl kickstart");
    assert!(!at_kickstart.is_empty(), "the service was never started");
    for observed in &at_kickstart {
        assert_eq!(observed, &PortState::Persisted(outcome.port));
    }
}

/// The same invariant stated over EVERY OS interaction, not just the two
/// the audit happened to name: nothing this primitive does to the machine
/// may precede the commit the service depends on. This is the assertion
/// that also covers the desktop and tracking onboarding paths, since the
/// ordering is now a property of the primitive they call rather than of
/// each caller's hand-written sequence.
#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn no_os_interaction_precedes_the_port_commit() {
    let r = rig();
    let host = FakeHost::healthy(Some(45_002));

    let outcome = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap();

    let observations = r.runner.all_observations();
    assert!(observations.len() >= 3, "{observations:?}");
    for (command, state) in observations {
        assert_eq!(
            state,
            PortState::Persisted(outcome.port),
            "`{command}` ran while the persisted port was {state:?}"
        );
    }
}

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn install_reports_its_stages_in_the_specified_order() {
    let r = rig();
    let host = FakeHost::healthy(Some(45_003));

    provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap();

    assert!(r.runner.call_index("launchctl").is_some());
    let spine: Vec<&str> = host
        .stage_names()
        .into_iter()
        .filter(|s| *s != "Note")
        .collect();
    assert_eq!(
        spine,
        vec![
            "PlanValidated",
            "PortSelected",
            "PortCommitted",
            "ServiceStarted",
            "ListenerVerified",
            "Enabled",
        ],
        "the ordered algorithm is the specification; any reordered pair is NEW-02"
    );
}

// ---------------------------------------------------------------------------
// 2. Direct install: the complete happy path
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn a_direct_install_persists_port_enabled_version_and_exactly_one_audit_row() {
    let r = rig();
    let host = FakeHost::healthy(Some(45_010));

    let outcome = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap();

    assert_eq!(outcome.port, 45_010);
    assert!(outcome.port_was_new);
    assert!(outcome.report.started);
    let config = store::load_config(&r.conn).unwrap();
    assert_eq!(config.port, Some(45_010));
    assert!(config.enabled);
    assert_eq!(config.service_version.as_deref(), Some("0.1.0"));
    assert_eq!(audit_rows(&r.conn, "gateway_service_installed"), 1);
    assert!(matches!(
        r.lc.manager.read_definition_state().unwrap(),
        DefinitionState::Present(_)
    ));
}

// ---------------------------------------------------------------------------
// 3. Failure before the config commit
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn a_failure_before_the_port_commit_leaves_no_definition_and_no_launchctl_call() {
    let r = rig();
    // No port can be reserved, so the algorithm dies in step 2.
    let host = FakeHost::healthy(None);

    let err = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap_err();

    assert!(err.to_string().contains("no port"), "{err}");
    assert_eq!(store::load_config(&r.conn).unwrap().port, None);
    assert!(matches!(
        r.lc.manager.read_definition_state().unwrap(),
        DefinitionState::Absent
    ));
    assert!(
        r.runner.call_index("launchctl").is_none(),
        "nothing may reach the OS before the port is committed: {:?}",
        r.runner.calls()
    );
    assert_eq!(audit_rows(&r.conn, "gateway_service_installed"), 0);
}

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn a_missing_source_binary_is_refused_before_anything_is_written() {
    let r = rig();
    let host = FakeHost::healthy(Some(45_020));
    let missing = r.lc.data_dir.join("not-here");

    let err = provision::install_gateway(&r.lc, &r.conn, &host, &request(&missing)).unwrap_err();

    assert!(err.to_string().contains("does not exist"), "{err}");
    assert_eq!(store::load_config(&r.conn).unwrap().port, None);
    assert!(r.runner.call_index("launchctl").is_none());
}

// ---------------------------------------------------------------------------
// 4. Failure after the config commit, before/at the start
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn a_registration_failure_keeps_the_port_and_leaves_a_retryable_state() {
    let r = rig_with(Failures {
        bootstrap: true,
        ..Failures::default()
    });
    let host = FakeHost::healthy(Some(45_030));

    let err = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap_err();
    assert!(err.to_string().contains("bootstrap"), "{err}");

    // The port is KEPT: `.env` files may already carry it, and a retry that
    // picked a second port would be a re-link rather than a retry.
    let config = store::load_config(&r.conn).unwrap();
    assert_eq!(config.port, Some(45_030));
    assert!(!config.enabled, "an install that failed is not enabled");
    assert_eq!(audit_rows(&r.conn, "gateway_service_installed"), 0);
    assert!(
        matches!(
            r.lc.manager.read_definition_state().unwrap(),
            DefinitionState::Absent
        ),
        "the engine rolls its own definition back"
    );
    assert!(
        !r.lc.installed_binary_path().exists(),
        "no definition survived, so the helper this failed install wrote is an orphan"
    );
    assert!(
        err.to_string().contains("port was KEPT"),
        "rollback must be reported, never silent: {err}"
    );

    // The retry converges on the SAME port.
    let healthy = rig_retry(&r);
    let outcome = provision::install_gateway(
        &healthy.lc,
        &r.conn,
        &FakeHost::healthy(Some(45_099)),
        &request(&r.src),
    )
    .unwrap();
    assert_eq!(
        outcome.port, 45_030,
        "a retry must reuse the committed port, not choose a second one"
    );
    assert!(!outcome.port_was_new);
}

/// A second lifecycle over the SAME data directory and LaunchAgents dir,
/// with a healthy runner — the "user runs the command again" case.
#[cfg(unix)]
fn rig_retry(r: &Rig) -> Rig {
    let runner = Arc::new(SpyRunner::new(&r.lc.data_dir));
    let agent = LaunchAgent::new(
        &r.lc.data_dir,
        r.lc.manager
            .definition_path()
            .parent()
            .unwrap()
            .to_path_buf(),
        "501".into(),
        runner.clone(),
    );
    let lc = Lifecycle {
        data_dir: r.lc.data_dir.clone(),
        manager: Box::new(agent),
        runner: runner.clone(),
        version: "0.1.0".into(),
    };
    let conn = db::open(&r.lc.data_dir.join("vault.db")).unwrap();
    Rig {
        _dir: tempfile::tempdir().unwrap(),
        runner,
        lc,
        conn,
        src: r.src.clone(),
    }
}

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn a_start_failure_unregisters_before_the_definition_is_removed() {
    let r = rig_with(Failures {
        kickstart: true,
        ..Failures::default()
    });
    let host = FakeHost::healthy(Some(45_040));

    let err = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap_err();
    assert!(err.to_string().contains("kickstart"), "{err}");

    let bootout = r
        .runner
        .call_index("launchctl bootout")
        .expect("a registered job must be booted out before its definition is deleted");
    let last_bootstrap = r
        .runner
        .calls()
        .iter()
        .rposition(|c| c.join(" ").contains("launchctl bootstrap"))
        .unwrap();
    assert!(
        bootout > last_bootstrap,
        "the unregister must follow the registration it undoes: {:?}",
        r.runner.calls()
    );
    assert!(matches!(
        r.lc.manager.read_definition_state().unwrap(),
        DefinitionState::Absent
    ));
    assert_eq!(store::load_config(&r.conn).unwrap().port, Some(45_040));
    assert!(!store::load_config(&r.conn).unwrap().enabled);
}

// ---------------------------------------------------------------------------
// 5. Port conflict
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn install_refuses_when_a_stranger_holds_the_persisted_port() {
    let r = rig();
    store::commit_port(&r.conn, 45_050).unwrap();
    let host = FakeHost::healthy(Some(45_050)).with_probe(vec![ListenerIdentity::NotOurs]);

    let err = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap_err();

    assert!(err.to_string().contains("45050"), "{err}");
    assert!(
        r.runner.call_index("launchctl").is_none(),
        "the refusal must land before the service is touched, not as a doctor \
         finding after it is already registered and racing"
    );
    assert!(!store::load_config(&r.conn).unwrap().enabled);
}

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn install_reuses_the_persisted_port_when_our_own_gateway_holds_it() {
    let r = rig();
    store::commit_port(&r.conn, 45_060).unwrap();
    let host = FakeHost::healthy(Some(1)).with_live_port(45_060);

    let outcome = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap();

    assert_eq!(outcome.port, 45_060, "a persisted port is never re-chosen");
    assert!(!outcome.port_was_new);
}

// ---------------------------------------------------------------------------
// 6. Verification
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn a_gateway_that_bound_a_different_port_fails_the_install_with_that_diagnosis() {
    let r = rig();
    // The exact NEW-02 outcome: the service came up, answers its control
    // channel, and is serving a port nobody linked against.
    let host = FakeHost::healthy(Some(45_070))
        .with_probe(vec![ListenerIdentity::NoListener])
        .with_live_port(45_071);

    let err = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap_err();

    let msg = err.to_string();
    assert!(msg.contains("45071") && msg.contains("45070"), "{msg}");
    assert!(msg.contains("tethra gateway restart"), "{msg}");
    assert!(
        !store::load_config(&r.conn).unwrap().enabled,
        "an install whose service serves the wrong port is not a successful install"
    );
    assert_eq!(audit_rows(&r.conn, "gateway_service_installed"), 0);
}

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn an_unanswered_identity_probe_is_an_error_not_a_printed_note() {
    let r = rig();
    let host = FakeHost::healthy(Some(45_080)).with_probe(vec![ListenerIdentity::NoListener]);

    let err = provision::install_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap_err();

    // The old path printed a note and returned Ok(()), so every
    // exit-code-only caller — the packaged CI harness among them — recorded
    // a success. That is what let the incident through.
    assert!(err.to_string().contains("identity probe"), "{err}");
    assert!(!store::load_config(&r.conn).unwrap().enabled);
    assert!(
        matches!(
            r.lc.manager.read_definition_state().unwrap(),
            DefinitionState::Present(_)
        ),
        "a slow start must not cost the user their install; the state is left \
         inspectable, only the SILENCE is removed"
    );
}

// ---------------------------------------------------------------------------
// 7. Concurrency, idempotency, repair, uninstall
// ---------------------------------------------------------------------------

/// Two installers racing on one vault must converge on ONE port. Without
/// `BEGIN IMMEDIATE` in `commit_port` the two read-modify-writes interleave
/// and the loser overwrites the winner, leaving half the `.env` files
/// pointing at a port nothing serves.
#[test]
fn two_concurrent_installers_converge_on_one_port() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    drop(migrated(&db_path));

    // A barrier so both threads are inside `commit_port` at the same time;
    // without the `BEGIN IMMEDIATE` write lock their read-modify-writes
    // interleave and one silently overwrites the other.
    let gate = Arc::new(std::sync::Barrier::new(2));
    let (a, b) = (db_path.clone(), db_path.clone());
    let (ga, gb) = (gate.clone(), gate);
    let ta = std::thread::spawn(move || {
        let conn = db::open(&a).unwrap();
        ga.wait();
        store::commit_port(&conn, 46_001).unwrap()
    });
    let tb = std::thread::spawn(move || {
        let conn = db::open(&b).unwrap();
        gb.wait();
        store::commit_port(&conn, 46_002).unwrap()
    });
    let seen_a = ta.join().unwrap();
    let seen_b = tb.join().unwrap();

    assert_eq!(
        seen_a, seen_b,
        "both installers must be told the same authoritative port"
    );
    let conn = db::open(&db_path).unwrap();
    assert_eq!(store::load_config(&conn).unwrap().port, Some(seen_a));
    assert!(seen_a == 46_001 || seen_a == 46_002);
}

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn reinstalling_an_existing_valid_install_is_idempotent_and_keeps_the_port() {
    let r = rig();
    let first = provision::install_gateway(
        &r.lc,
        &r.conn,
        &FakeHost::healthy(Some(45_090)),
        &request(&r.src),
    )
    .unwrap();

    let second = provision::install_gateway(
        &r.lc,
        &r.conn,
        &FakeHost::healthy(Some(45_091)),
        &request(&r.src),
    )
    .unwrap();

    assert_eq!(second.port, first.port, "the port is decided once");
    assert!(!second.port_was_new);
    let rows: i64 = r
        .conn
        .query_row("SELECT COUNT(*) FROM gateway_config", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1, "upsert, never a second config row");
    assert_eq!(audit_rows(&r.conn, "gateway_service_installed"), 2);
}

/// The gap NEW-02 left in `repair`: it is `install(force = false)`
/// underneath, so repairing an installation with no persisted port started
/// a service that bound a random one — from a path `tethra track` reaches
/// automatically.
#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn repair_commits_a_port_when_none_exists_before_the_service_starts() {
    let r = rig();
    assert_eq!(store::load_config(&r.conn).unwrap().port, None);
    let host = FakeHost::healthy(Some(45_100));

    let outcome = provision::repair_gateway(&r.lc, &r.conn, &host, &request(&r.src)).unwrap();

    assert_eq!(outcome.port, 45_100);
    assert!(outcome.port_was_new);
    for observed in r.runner.observed_at("launchctl") {
        assert_eq!(observed, PortState::Persisted(45_100));
    }
    let config = store::load_config(&r.conn).unwrap();
    assert_eq!(config.port, Some(45_100));
    assert_eq!(config.service_version.as_deref(), Some("0.1.0"));
    assert!(
        !config.enabled,
        "repair re-aligns an installation; it does not enable one"
    );
    assert_eq!(
        audit_rows(&r.conn, "gateway_service_installed"),
        0,
        "a repair is not an install"
    );
}

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn uninstall_clears_enabled_and_deliberately_keeps_the_port() {
    let r = rig();
    provision::install_gateway(
        &r.lc,
        &r.conn,
        &FakeHost::healthy(Some(45_110)),
        &request(&r.src),
    )
    .unwrap();

    r.lc.uninstall(&r.conn, None, true).unwrap();

    let config = store::load_config(&r.conn).unwrap();
    assert!(!config.enabled);
    assert_eq!(
        config.port,
        Some(45_110),
        "the port outlives the service: `.env` files carry it, and a reinstall \
         that moved it would be a re-link"
    );
    assert!(matches!(
        r.lc.manager.read_definition_state().unwrap(),
        DefinitionState::Absent
    ));
}

// ---------------------------------------------------------------------------
// 8. Atomic definition writes (retry after a partial install)
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn a_definition_write_is_atomic_and_leaves_no_temp_file_behind() {
    let r = rig();
    let definition = r.lc.manager.definition_path();
    let dir = definition.parent().unwrap().to_path_buf();

    // A previous definition exists; the rewrite must never make the path
    // absent or truncated, because an `Unparseable` definition locks every
    // later verb out until the user removes it by hand.
    provision::install_gateway(
        &r.lc,
        &r.conn,
        &FakeHost::healthy(Some(45_120)),
        &request(&r.src),
    )
    .unwrap();
    let first = std::fs::read_to_string(&definition).unwrap();
    provision::install_gateway(
        &r.lc,
        &r.conn,
        &FakeHost::healthy(Some(45_121)),
        &request(&r.src),
    )
    .unwrap();

    assert_eq!(std::fs::read_to_string(&definition).unwrap(), first);
    let strays: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(strays.is_empty(), "temp files must not survive: {strays:?}");
    assert!(matches!(
        r.lc.manager.read_definition_state().unwrap(),
        DefinitionState::Present(_)
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&definition).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the rename must preserve owner-only");
    }
}

#[test]
fn atomic_write_definition_replaces_content_without_a_visible_gap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("thing.plist");
    lifecycle::atomic_write_definition(&path, "first").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
    lifecycle::atomic_write_definition(&path, "second").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
    let strays: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "thing.plist")
        .collect();
    assert!(strays.is_empty(), "{strays:?}");
}

// ---------------------------------------------------------------------------
// 9. `port_state` tells the three answers apart
// ---------------------------------------------------------------------------

#[test]
fn port_state_distinguishes_undecided_from_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        matches!(store::port_state(dir.path()), PortState::Unavailable(_)),
        "no database at all is NOT 'no port has been chosen'"
    );

    let conn = migrated(&dir.path().join("vault.db"));
    assert_eq!(store::port_state(dir.path()), PortState::NoneYet);
    assert_eq!(store::port_hint(dir.path()), None);

    store::commit_port(&conn, 47_000).unwrap();
    assert_eq!(store::port_state(dir.path()), PortState::Persisted(47_000));
    assert_eq!(store::port_hint(dir.path()), Some(47_000));

    // Never overwritten: the persisted port is the authority `.env` base
    // URLs were built from.
    assert_eq!(store::commit_port(&conn, 47_999).unwrap(), 47_000);
    assert_eq!(store::load_config(&conn).unwrap().port, Some(47_000));
}

#[test]
fn commit_port_does_not_clobber_the_consent_toggle() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    store::set_match_while_locked(&conn, true).unwrap();

    store::commit_port(&conn, 47_100).unwrap();

    let config = store::load_config(&conn).unwrap();
    assert_eq!(config.port, Some(47_100));
    assert!(
        config.match_while_locked,
        "choosing a port must not rewrite the whole row and undo a consent decision"
    );
}
