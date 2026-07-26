//! Service-lifecycle tests (TEST_PLAN §9). Everything runs against a mock
//! command runner and temporary directories: `cargo test` never installs,
//! starts, stops, or queries a REAL service on the developer's machine.

#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use api_tracker_core::db;
use api_tracker_gateway::lifecycle::{
    self, binary_name, linux::SystemdUser, macos::LaunchAgent, windows::RunKey, CommandRunner,
    Lifecycle, OsWillRun, RunOutput, ServiceManager,
};
use rusqlite::Connection;

/// Records every invocation; responds from a small rule table.
#[derive(Default)]
struct MockRunner {
    calls: Mutex<Vec<Vec<String>>>,
    /// (program-suffix, first-arg) -> (status, stdout). Probe rules match on
    /// args == ["gateway", "service-probe"].
    fail_probe: bool,
    launchctl_print_running: Mutex<bool>,
}

impl MockRunner {
    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
    fn call_index(&self, needle: &str) -> Option<usize> {
        self.calls()
            .iter()
            .position(|c| c.join(" ").contains(needle))
    }
}

impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> api_tracker_core::error::Result<RunOutput> {
        let mut call = vec![program.to_string()];
        call.extend(args.iter().map(|s| s.to_string()));
        self.calls.lock().unwrap().push(call);

        if args == ["gateway", "service-probe"] {
            if self.fail_probe {
                return Ok(RunOutput {
                    status: 137, // SIGKILL'd, as Gatekeeper would
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
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
            let running = *self.launchctl_print_running.lock().unwrap();
            if !running {
                return Ok(RunOutput {
                    status: 113,
                    stdout: String::new(),
                    stderr: "Could not find service".into(),
                });
            }
            return Ok(RunOutput {
                status: 0,
                stdout: "\tstate = running\n\tpid = 4242\n".into(),
                stderr: String::new(),
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

fn fake_source_binary(dir: &Path) -> PathBuf {
    let src = dir.join("tethra");
    std::fs::write(&src, b"#!/bin/true\nfake-binary-bytes").unwrap();
    src
}

fn mac_lifecycle(dir: &Path, runner: Arc<MockRunner>) -> Lifecycle {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let agent = LaunchAgent {
        data_dir: data_dir.clone(),
        launch_agents_dir: dir.join("LaunchAgents"),
        uid: "501".into(),
        runner: runner.clone(),
    };
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

// ---------------------------------------------------------------------------
// Definition rendering (golden behavior, all three platforms)
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent/systemd) behavior
#[test]
fn plist_renders_the_d8_shape_and_round_trips_with_xml_escaping() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    // A data dir with XML-hostile characters.
    let data_dir = dir.path().join("da<ta>&dir");
    std::fs::create_dir_all(&data_dir).unwrap();
    let agent = LaunchAgent {
        data_dir: data_dir.clone(),
        launch_agents_dir: dir.path().join("LaunchAgents"),
        uid: "501".into(),
        runner,
    };
    let bin = data_dir.join("bin").join(binary_name("0.1.0"));
    let plist = agent.render_plist(&bin);

    assert!(plist.contains("<string>dev.api-tracker.gateway</string>"));
    assert!(plist.contains("<key>RunAtLoad</key>"));
    assert!(
        plist.contains("<key>KeepAlive</key>\n\t<dict>\n\t\t<key>Crashed</key>\n\t\t<true/>"),
        "KeepAlive must be Crashed-only (a clean exit is terminal): {plist}"
    );
    assert!(plist.contains("<string>--data-dir</string>"));
    assert!(
        plist.contains("da&lt;ta&gt;&amp;dir"),
        "XML escaping: {plist}"
    );
    assert!(!plist.contains("TETHRA_PASSWORD"));

    agent.write_definition(&bin).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(agent.definition_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "plist must be owner-only");
    }
    let def = agent.read_definition().unwrap().unwrap();
    assert_eq!(def.binary, bin);
    assert_eq!(def.data_dir, data_dir, "escaped path round-trips");
}

#[cfg(unix)] // Unix service-manager (LaunchAgent/systemd) behavior
#[test]
fn systemd_unit_renders_user_scope_and_round_trips_spaced_paths() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data dir with spaces");
    std::fs::create_dir_all(&data_dir).unwrap();
    let unit = SystemdUser {
        data_dir: data_dir.clone(),
        unit_dir: dir.path().join("systemd-user"),
        runner: Arc::new(MockRunner::default()),
    };
    let bin = data_dir.join("bin").join(binary_name("0.1.0"));
    let text = unit.render_unit(&bin);
    assert!(text.contains("WantedBy=default.target"), "{text}");
    assert!(text.contains("Restart=on-failure"));
    assert!(text.contains("--service --data-dir \""));
    assert!(
        !text.contains("Environment="),
        "no env (and no secrets) in the unit"
    );

    unit.write_definition(&bin).unwrap();
    let def = unit.read_definition().unwrap().unwrap();
    assert_eq!(def.binary, bin);
    assert_eq!(def.data_dir, data_dir, "spaced path round-trips");
}

#[test]
fn windows_run_value_quotes_and_round_trips_spaced_paths() {
    let runner = Arc::new(MockRunner::default());
    let data_dir = PathBuf::from(r"C:\Users\Dev One\AppData\Roaming\api-tracker");
    let key = RunKey::new(data_dir.clone(), runner);
    let bin = data_dir.join("bin").join("tethra-gateway-0.1.0.exe");
    let value = key.run_value(&bin);
    assert!(
        value.starts_with('"'),
        "binary path must be quoted: {value}"
    );
    assert!(value.contains("--data-dir \""), "{value}");

    let parsed = RunKey::parse_run_value(&value).unwrap();
    assert_eq!(parsed.binary, bin);
    assert_eq!(parsed.data_dir, data_dir);
}

// ---------------------------------------------------------------------------
// Install flow (order, probe gate, foreign-install refusal, pruning)
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent/systemd) behavior
#[test]
fn install_byte_writes_dequarantines_probes_then_registers_in_that_order() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let lc = mac_lifecycle(dir.path(), runner.clone());
    let src = fake_source_binary(dir.path());

    let report = lc.install(&src, false).unwrap();

    // The binary is a fresh byte-write, executable, content-identical.
    let installed = lc.installed_binary_path();
    assert_eq!(
        std::fs::read(&installed).unwrap(),
        std::fs::read(&src).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&installed).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "must be executable");
    }

    // Order is the D8 order: de-quarantine, exec probe, THEN bootstrap.
    let xattr = runner
        .call_index("com.apple.quarantine")
        .expect("xattr ran");
    let probe = runner.call_index("service-probe").expect("probe ran");
    let bootstrap = runner
        .call_index("bootstrap gui/501")
        .expect("bootstrap ran");
    let kickstart = runner.call_index("kickstart").expect("start ran");
    assert!(xattr < probe, "de-quarantine before the probe");
    assert!(
        probe < bootstrap,
        "probe BEFORE any definition is registered"
    );
    assert!(bootstrap < kickstart);
    assert!(report.started);
    assert!(lc.manager.definition_path().exists());
}

#[cfg(unix)] // Unix service-manager (LaunchAgent/systemd) behavior
#[test]
fn a_failed_exec_probe_fails_install_without_writing_a_definition() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner {
        fail_probe: true,
        ..MockRunner::default()
    });
    let lc = mac_lifecycle(dir.path(), runner.clone());
    let src = fake_source_binary(dir.path());

    let err = lc.install(&src, false).unwrap_err();
    assert!(err.to_string().contains("probe"), "{err}");
    assert!(
        !lc.manager.definition_path().exists(),
        "no plist may exist for a binary the OS refuses to run (C12: that \
         would be a launchd crash loop)"
    );
    assert!(runner.call_index("bootstrap").is_none());
}

#[cfg(unix)] // Unix service-manager (LaunchAgent/systemd) behavior
#[test]
fn install_refuses_a_definition_owned_by_a_different_data_dir_unless_forced() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let lc = mac_lifecycle(dir.path(), runner.clone());
    let src = fake_source_binary(dir.path());

    // A plist for ANOTHER vault occupies the login slot.
    let other = LaunchAgent {
        data_dir: dir.path().join("other-vault"),
        launch_agents_dir: dir.path().join("LaunchAgents"),
        uid: "501".into(),
        runner: runner.clone(),
    };
    std::fs::create_dir_all(dir.path().join("other-vault")).unwrap();
    other
        .write_definition(&dir.path().join("other-vault/bin/tethra-gateway-0.0.9"))
        .unwrap();

    let err = lc.install(&src, false).unwrap_err();
    assert!(err.to_string().contains("different data"), "{err}");

    let report = lc.install(&src, true).unwrap();
    assert!(report.notes.iter().any(|n| n.contains("other-vault")));
    let def = lc.manager.read_definition().unwrap().unwrap();
    assert_eq!(def.data_dir, lc.data_dir);
}

#[cfg(unix)] // Unix service-manager (LaunchAgent/systemd) behavior
#[test]
fn upgrade_prunes_older_binaries_but_keeps_the_current_one() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let lc = mac_lifecycle(dir.path(), runner);
    let src = fake_source_binary(dir.path());

    // A stale previous version sits in bin/.
    let old = lifecycle::bin_dir(&lc.data_dir).join(binary_name("0.0.9"));
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    std::fs::write(&old, b"old").unwrap();
    // An unrelated file must not be touched.
    let unrelated = lifecycle::bin_dir(&lc.data_dir).join("user-notes.txt");
    std::fs::write(&unrelated, b"mine").unwrap();

    let report = lc.install(&src, false).unwrap();
    assert!(!old.exists(), "the old version is pruned");
    assert!(unrelated.exists(), "unrelated files are never deleted");
    assert!(report.pruned_binaries.iter().any(|n| n.contains("0.0.9")));
    assert!(lc.installed_binary_path().exists());
}

// ---------------------------------------------------------------------------
// Status facts
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent/systemd) behavior
#[test]
fn status_reports_uninstalled_then_installed_then_stale_binary() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let lc = mac_lifecycle(dir.path(), runner.clone());
    let src = fake_source_binary(dir.path());

    let s = lc.status();
    assert!(!s.installed);
    assert_eq!(s.os_will_run, OsWillRun::No);

    lc.install(&src, false).unwrap();
    *runner.launchctl_print_running.lock().unwrap() = true;
    let s = lc.status();
    assert!(s.installed && s.matches_data_dir && s.binary_exists);
    assert_eq!(s.binary_version.as_deref(), Some("0.1.0"));
    assert!(s.running);
    assert_eq!(s.pid, Some(4242));
    assert_eq!(s.os_will_run, OsWillRun::Yes);
    assert!(s
        .owned_artifacts
        .iter()
        .any(|a| a.contains("dev.api-tracker.gateway.plist")));

    // The binary moves away underneath the definition: stale-path note.
    std::fs::remove_file(lc.installed_binary_path()).unwrap();
    let s = lc.status();
    assert!(!s.binary_exists);
    assert!(
        s.notes.iter().any(|n| n.contains("repair")),
        "{:?}",
        s.notes
    );
}

// ---------------------------------------------------------------------------
// Disable / uninstall (ordered manifest, .env restore, DB rows kept)
// ---------------------------------------------------------------------------

fn linked_vault(lc: &Lifecycle) -> (Connection, PathBuf) {
    let conn = migrated(&lc.data_dir.join("vault.db"));
    conn.execute(
        "INSERT INTO projects (id, name, description, notes, environments, archived,
             created_at, updated_at, wrapped_project_key, key_wrap_mode)
         VALUES ('p1', 'app', '', '', 'development', 0,
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', x'00', 'vault')",
        [],
    )
    .unwrap();
    api_tracker_gateway::routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    let mut config = api_tracker_gateway::store::load_config(&conn).unwrap();
    config.port = Some(49723);
    config.enabled = true;
    api_tracker_gateway::store::save_config(&conn, &config).unwrap();

    let env = lc.data_dir.join("project.env");
    std::fs::write(&env, "OPENAI_BASE_URL=https://prior.example/v1\n").unwrap();
    let req = api_tracker_gateway::envlink::LinkRequest {
        project_id: "p1".into(),
        project_name: "app".into(),
        route_prefix: "openai".into(),
        project_dir: None,
        files: vec![env.clone()],
        var_override: None,
    };
    let plan = api_tracker_gateway::envlink::plan_link(&conn, &req).unwrap();
    api_tracker_gateway::envlink::apply_link(&conn, &req, &plan).unwrap();
    (conn, env)
}

#[cfg(unix)] // Unix service-manager (LaunchAgent/systemd) behavior
#[test]
fn disable_stops_unregisters_restores_env_and_keeps_binaries_and_rows() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let lc = mac_lifecycle(dir.path(), runner.clone());
    let src = fake_source_binary(dir.path());
    lc.install(&src, false).unwrap();
    let (conn, env) = linked_vault(&lc);
    assert!(std::fs::read_to_string(&env).unwrap().contains("127.0.0.1"));

    let report = lc.disable(&conn, false).unwrap();
    assert!(report.stopped && report.unregistered);
    assert_eq!(report.incomplete_restores, 0);
    assert_eq!(
        std::fs::read_to_string(&env).unwrap(),
        "OPENAI_BASE_URL=https://prior.example/v1\n",
        "disable restores every linked .env (PRODUCT_BEHAVIOR)"
    );
    assert!(runner.call_index("bootout").is_some());
    assert!(!lc.manager.definition_path().exists());
    assert!(
        lc.installed_binary_path().exists(),
        "disable keeps binaries (uninstall removes them)"
    );
    let config = api_tracker_gateway::store::load_config(&conn).unwrap();
    assert!(!config.enabled);
    // Route rows survive: disable is 'off', not 'gone'.
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM gateway_routes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

#[cfg(unix)] // Unix service-manager (LaunchAgent/systemd) behavior
#[test]
fn disable_keep_env_leaves_files_and_uninstall_removes_every_owned_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let lc = mac_lifecycle(dir.path(), runner);
    let src = fake_source_binary(dir.path());
    lc.install(&src, false).unwrap();
    let (conn, env) = linked_vault(&lc);

    // Stale runtime files exist (as after a crash).
    std::fs::write(lc.data_dir.join("gateway.nonce"), "aa").unwrap();
    std::fs::write(lc.data_dir.join("gateway.pid"), "1").unwrap();

    let report = lc.uninstall(&conn, true).unwrap();
    assert!(
        std::fs::read_to_string(&env).unwrap().contains("127.0.0.1"),
        "--keep-env leaves the linked file alone"
    );
    assert!(!lifecycle::bin_dir(&lc.data_dir).exists(), "bin/ removed");
    assert!(!lifecycle::logs_dir(&lc.data_dir).exists(), "logs/ removed");
    assert!(!lc.data_dir.join("gateway.nonce").exists());
    assert!(!lc.data_dir.join("gateway.pid").exists());
    assert!(report.removed_paths.iter().any(|p| p.contains("bin")));
    // DB rows are user data: kept.
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM gateway_project_links", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(n, 1, "--keep-env also keeps the link row for later restore");
}

// ---------------------------------------------------------------------------
// Service-mode run loop
// ---------------------------------------------------------------------------

#[test]
fn run_as_service_exits_cleanly_when_the_vault_disappears() {
    let dir = tempfile::tempdir().unwrap();
    // No vault.db at all: the service must refuse to spin and exit 0-style.
    let logs = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = logs.clone();
    let exit = api_tracker_gateway::service::run_as_service(dir.path(), 0, move |line| {
        sink.lock().unwrap().push(line.to_string());
    });
    assert_eq!(
        exit,
        api_tracker_gateway::service::ServiceExit::ExternalCondition
    );
    assert!(logs
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.contains("exiting cleanly")));
}

// The graceful control-plane stop rides the Unix control socket (SI-21:
// absent on Windows), so this end-to-end serve→stop path is Unix-only.
// Windows keeps the vanished-vault clean-exit test above, which needs no
// control channel.
#[cfg(unix)]
#[test]
fn run_as_service_serves_then_honors_a_control_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The control channel refuses a data dir that is not owner-only;
        // real data dirs are created 0700, tempfile's are 0755.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut conn = db::open(&dir.path().join("vault.db")).unwrap();
    db::migrate(&mut conn).unwrap();
    drop(conn);

    let data_dir = dir.path().to_path_buf();
    let logs = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = logs.clone();
    let handle = std::thread::spawn(move || {
        api_tracker_gateway::service::run_as_service(&data_dir, 0, move |line| {
            sink.lock().unwrap().push(line.to_string());
        })
    });

    // Wait for the listener, then stop it over the control channel.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if api_tracker_gateway::control::instance_is_live(dir.path()) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "gateway never came up"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let nonce = api_tracker_gateway::control::read_nonce(dir.path()).unwrap();
    let resp = api_tracker_gateway::control::send(
        dir.path(),
        &api_tracker_gateway::control::Request::Shutdown {
            nonce: nonce.to_string(),
        },
    )
    .unwrap();
    assert_eq!(resp, api_tracker_gateway::control::Response::Ok);

    let exit = handle.join().unwrap();
    assert_eq!(
        exit,
        api_tracker_gateway::service::ServiceExit::StopRequested
    );
    assert!(logs.lock().unwrap().iter().any(|l| l.contains("listening")));
}
