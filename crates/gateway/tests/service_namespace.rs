//! Service and test-environment NAMESPACING (audit finding ZFT-014).
//!
//! The defect these tests pin down: every OS login-start mechanism is a
//! single per-USER namespace, so while the launchd label, the systemd unit
//! name and the HKCU `Run` value were fixed constants, a second Tethra
//! environment — its own `TETHRA_DIR`, even its own `HOME` — addressed the
//! FIRST environment's job. Installing in one environment booted out the
//! other's RUNNING gateway, and uninstalling deleted its definition. That
//! happened to a live gateway during the audit; it is not hypothetical.
//!
//! Two properties are tested here, on all three platforms:
//!   1. the service name is derived from the data directory, so two
//!      environments never share a slot; and
//!   2. before any destructive verb, the definition about to be acted on is
//!      PROVEN to point at our own data directory — because a name is not
//!      ownership (a moved data directory or a hand-edited file leaves a
//!      foreign definition sitting under our name).
//!
//! Like `lifecycle.rs`, everything runs against a mock command runner in
//! temporary directories: `cargo test` never installs, starts, stops, or
//! queries a REAL service.

#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use api_tracker_core::db;
use api_tracker_gateway::lifecycle::{
    self, installation_id, linux::SystemdUser, macos::LaunchAgent, windows::RunKey, CommandRunner,
    Lifecycle, RunOutput, ServiceManager,
};
use rusqlite::Connection;

/// Every verb that can take another environment's gateway down. The
/// ownership-proof tests assert the mock recorded NONE of these against a
/// foreign target — the assertion that fails first if the proof is deleted.
const DESTRUCTIVE_VERBS: &[&str] = &[
    "bootout",
    "kickstart -k",
    "systemctl --user stop",
    "systemctl --user disable",
    "systemctl --user restart",
    "reg delete",
    "taskkill",
];

/// Records every invocation and answers the exec probe. Deliberately simpler
/// than `lifecycle.rs`'s runner: these tests care about which commands were
/// (not) issued, not about launchd state machines.
#[derive(Default)]
struct MockRunner {
    calls: Mutex<Vec<Vec<String>>>,
}

impl MockRunner {
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.join(" "))
            .collect()
    }

    fn ran(&self, needle: &str) -> bool {
        self.calls().iter().any(|c| c.contains(needle))
    }

    /// Forget everything recorded so far, so an assertion can be about the
    /// call under test rather than about the fixture that set it up.
    fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }

    /// Whole-command match. The legacy label is a PREFIX of every namespaced
    /// one, so `bootout gui/501/dev.api-tracker.gateway` would substring-match
    /// a bootout of our own job — an assertion about the legacy service has
    /// to be exact or it proves nothing.
    fn ran_exactly(&self, call: &str) -> bool {
        self.calls().iter().any(|c| c == call)
    }

    /// The mutation check in one call: no verb that could stop, unload,
    /// disable, restart or delete anything was issued at all.
    fn assert_no_destructive_verb_ran(&self) {
        let calls = self.calls();
        for verb in DESTRUCTIVE_VERBS {
            assert!(
                !calls.iter().any(|c| c.contains(verb)),
                "a refused command still ran `{verb}` against another \
                 installation's service: {calls:?}"
            );
        }
    }
}

impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> api_tracker_core::error::Result<RunOutput> {
        let mut call = vec![program.to_string()];
        call.extend(args.iter().map(|s| s.to_string()));
        self.calls.lock().unwrap().push(call);

        if args == ["gateway", "service-probe"] {
            return Ok(RunOutput {
                status: 0,
                stdout: format!("{} 0.1.0\n", lifecycle::PROBE_MARKER),
                stderr: String::new(),
            });
        }
        if program == "launchctl" && args.first() == Some(&"print") {
            // Nothing is running in these tests; `install` must therefore
            // start rather than restart.
            return Ok(RunOutput {
                status: 113,
                stdout: String::new(),
                stderr: "Could not find service".into(),
            });
        }
        Ok(RunOutput::default())
    }

    fn spawn_detached(&self, program: &str, args: &[&str]) -> api_tracker_core::error::Result<()> {
        let mut call = vec!["spawn".to_string(), program.to_string()];
        call.extend(args.iter().map(|s| s.to_string()));
        self.calls.lock().unwrap().push(call);
        Ok(())
    }
}

/// A mock `reg.exe`: an in-memory HKCU `Run` key, so the Windows manager can
/// be exercised (and its namespacing proven) from any host.
#[derive(Default)]
struct RegRunner {
    calls: Mutex<Vec<Vec<String>>>,
    values: Mutex<BTreeMap<String, String>>,
}

impl RegRunner {
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.join(" "))
            .collect()
    }

    fn set(&self, name: &str, value: String) {
        self.values.lock().unwrap().insert(name.to_string(), value);
    }

    fn has(&self, name: &str) -> bool {
        self.values.lock().unwrap().contains_key(name)
    }

    fn get(&self, name: &str) -> Option<String> {
        self.values.lock().unwrap().get(name).cloned()
    }

    fn assert_no_destructive_verb_ran(&self) {
        let calls = self.calls();
        for verb in DESTRUCTIVE_VERBS {
            assert!(
                !calls.iter().any(|c| c.contains(verb)),
                "a refused command still ran `{verb}`: {calls:?}"
            );
        }
    }
}

impl CommandRunner for RegRunner {
    fn run(&self, program: &str, args: &[&str]) -> api_tracker_core::error::Result<RunOutput> {
        let mut call = vec![program.to_string()];
        call.extend(args.iter().map(|s| s.to_string()));
        self.calls.lock().unwrap().push(call);

        if args == ["gateway", "service-probe"] {
            return Ok(RunOutput {
                status: 0,
                stdout: format!("{} 0.1.0\n", lifecycle::PROBE_MARKER),
                stderr: String::new(),
            });
        }
        if program != "reg" {
            return Ok(RunOutput::default());
        }
        match args {
            ["add", _key, "/v", name, "/t", "REG_SZ", "/d", value, "/f"] => {
                self.set(name, (*value).to_string());
                Ok(RunOutput::default())
            }
            ["query", _key, "/v", name] => match self.get(name) {
                // The real `reg query` prints the key, then an indented
                // `NAME<tab>TYPE<tab>VALUE` row.
                Some(value) => Ok(RunOutput {
                    status: 0,
                    stdout: format!("\r\nHKEY_CURRENT_USER\\...\\Run\r\n    {name}    REG_SZ    {value}\r\n\r\n"),
                    stderr: String::new(),
                }),
                None => Ok(RunOutput {
                    status: 1,
                    stdout: String::new(),
                    stderr: "ERROR: The system was unable to find the specified registry key or value.".into(),
                }),
            },
            ["delete", _key, "/v", name, "/f"] => {
                if self.values.lock().unwrap().remove(*name).is_some() {
                    Ok(RunOutput::default())
                } else {
                    Ok(RunOutput {
                        status: 1,
                        stdout: String::new(),
                        stderr: "ERROR: The system was unable to find the specified registry key or value.".into(),
                    })
                }
            }
            _ => Ok(RunOutput::default()),
        }
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

/// Two Tethra environments on ONE user account: separate data directories,
/// but the SAME `~/Library/LaunchAgents` and the same `gui/<uid>` domain —
/// the configuration the defect lived in.
fn mac_env(root: &Path, name: &str, runner: Arc<MockRunner>) -> Lifecycle {
    let data_dir = root.join(name);
    std::fs::create_dir_all(&data_dir).unwrap();
    let agent = LaunchAgent::new(
        &data_dir,
        root.join("LaunchAgents"),
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

fn linux_env(root: &Path, name: &str, runner: Arc<MockRunner>) -> Lifecycle {
    let data_dir = root.join(name);
    std::fs::create_dir_all(&data_dir).unwrap();
    let unit = SystemdUser::new(&data_dir, root.join("systemd-user"), runner.clone());
    Lifecycle {
        data_dir,
        manager: Box::new(unit),
        runner,
        version: "0.1.0".into(),
    }
}

/// Write a plist of the shape this crate parses, with an ARBITRARY label and
/// `--data-dir`. Models what the code must survive but would never write: a
/// pre-namespacing agent, or a stale definition left behind by a data
/// directory that moved.
fn write_plist(path: &Path, label: &str, binary: &Path, data_dir: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{bin}</string>
		<string>gateway</string>
		<string>serve</string>
		<string>--service</string>
		<string>--data-dir</string>
		<string>{dir}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
"#,
            bin = binary.display(),
            dir = data_dir.display(),
        ),
    )
    .unwrap();
}

/// The systemd counterpart of [`write_plist`].
fn write_unit(path: &Path, binary: &Path, data_dir: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        format!(
            "[Service]\nExecStart=\"{}\" gateway serve --service --data-dir \"{}\"\n\n\
             [Install]\nWantedBy=default.target\n",
            binary.display(),
            data_dir.display(),
        ),
    )
    .unwrap();
}

/// The registry counterpart of [`write_plist`].
fn run_value(binary: &Path, data_dir: &Path) -> String {
    format!(
        "\"{}\" gateway serve --service --data-dir \"{}\"",
        binary.display(),
        data_dir.display()
    )
}

// ---------------------------------------------------------------------------
// The namespace itself
// ---------------------------------------------------------------------------

#[test]
fn each_data_dir_gets_its_own_stable_service_name_on_every_platform() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("vault-a");
    let b = dir.path().join("vault-b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();

    let id_a = installation_id(&a);
    let id_b = installation_id(&b);
    assert_ne!(id_a, id_b, "two data dirs must not share one login slot");
    assert_eq!(id_a, installation_id(&a), "the id is stable for a data dir");
    assert_eq!(id_a.len(), 12, "short enough to read in launchctl output");
    assert!(
        id_a.chars().all(|c| c.is_ascii_hexdigit()),
        "the id must be safe in a label, a unit file name and a registry \
         value name: {id_a}"
    );

    // ...and every platform's name carries it, so none of the three
    // mechanisms can be addressed by another environment.
    for (label_a, label_b, legacy) in [
        (
            api_tracker_gateway::lifecycle::macos::label_for(&id_a),
            api_tracker_gateway::lifecycle::macos::label_for(&id_b),
            api_tracker_gateway::lifecycle::macos::LEGACY_LABEL.to_string(),
        ),
        (
            api_tracker_gateway::lifecycle::linux::unit_name_for(&id_a),
            api_tracker_gateway::lifecycle::linux::unit_name_for(&id_b),
            api_tracker_gateway::lifecycle::linux::LEGACY_UNIT_NAME.to_string(),
        ),
        (
            api_tracker_gateway::lifecycle::windows::value_name_for(&id_a),
            api_tracker_gateway::lifecycle::windows::value_name_for(&id_b),
            api_tracker_gateway::lifecycle::windows::LEGACY_VALUE_NAME.to_string(),
        ),
    ] {
        assert_ne!(label_a, label_b);
        assert!(label_a.contains(&id_a), "{label_a}");
        assert_ne!(
            label_a, legacy,
            "a namespaced name must never collide with the legacy one"
        );
    }
}

/// Canonicalization: the same directory reached by two spellings is ONE
/// installation, not two services fighting over one port.
#[cfg(unix)] // needs a symlink to a directory
#[test]
fn a_symlinked_path_to_the_same_directory_is_the_same_installation() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("vault");
    std::fs::create_dir_all(&real).unwrap();
    let link = dir.path().join("link-to-vault");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    assert_eq!(installation_id(&real), installation_id(&link));
    assert!(lifecycle::same_data_dir(&real, &link));
    assert!(!lifecycle::same_data_dir(&real, &dir.path().join("other")));
}

// ---------------------------------------------------------------------------
// Ownership proof (the mutation check lives here)
// ---------------------------------------------------------------------------

/// THE regression test. A definition that points at ANOTHER data directory
/// is sitting in our slot; every destructive verb must refuse it by name,
/// and — the mutation check — the runner must have issued no `bootout`,
/// `kickstart -k`, `stop`, `disable`, `restart` or `delete` at all. Remove
/// the ownership proof and this fails on the recorded commands, not just on
/// the error text.
#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn macos_refuses_every_destructive_verb_against_another_data_dirs_job() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let ours = mac_env(dir.path(), "vault-a", runner.clone());
    let theirs = dir.path().join("vault-b");
    std::fs::create_dir_all(&theirs).unwrap();

    // Their definition, under OUR name (a data directory that moved, or a
    // hand-edited plist).
    let path = ours.manager.definition_path();
    write_plist(
        &path,
        &ours.manager.service_name(),
        &theirs.join("bin/tethra-gateway-0.0.9"),
        &theirs,
    );

    for result in [
        ours.manager.stop(),
        ours.manager.unregister(),
        ours.manager.restart(),
        ours.manager.remove_definition(),
    ] {
        let err = result
            .expect_err("a foreign definition must be refused")
            .to_string();
        assert!(
            err.contains("belongs to a different Tethra data directory"),
            "{err}"
        );
        assert!(
            err.contains(&theirs.display().to_string()),
            "the refusal must name the other data directory: {err}"
        );
        assert!(
            err.contains(&ours.manager.service_name()),
            "the refusal must name the service it declined to touch: {err}"
        );
    }

    runner.assert_no_destructive_verb_ran();
    assert!(
        path.exists(),
        "a refused remove_definition must leave the other installation's \
         definition on disk"
    );
    let still = ours.manager.read_definition().unwrap().unwrap();
    assert_eq!(still.data_dir, theirs, "and unmodified");
}

#[cfg(unix)] // Unix service-manager (systemd) behavior
#[test]
fn linux_refuses_every_destructive_verb_against_another_data_dirs_unit() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let ours = linux_env(dir.path(), "vault-a", runner.clone());
    let theirs = dir.path().join("vault-b");
    std::fs::create_dir_all(&theirs).unwrap();

    let path = ours.manager.definition_path();
    write_unit(&path, &theirs.join("bin/tethra-gateway-0.0.9"), &theirs);

    for result in [
        ours.manager.stop(),
        ours.manager.unregister(),
        ours.manager.restart(),
        ours.manager.remove_definition(),
    ] {
        let err = result
            .expect_err("a foreign unit must be refused")
            .to_string();
        assert!(
            err.contains("belongs to a different Tethra data directory"),
            "{err}"
        );
        assert!(err.contains(&theirs.display().to_string()), "{err}");
    }

    runner.assert_no_destructive_verb_ran();
    assert!(path.exists(), "the other installation's unit survives");
}

#[test]
fn windows_refuses_every_destructive_verb_against_another_data_dirs_run_value() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(RegRunner::default());
    let ours = dir.path().join("vault-a");
    let theirs = dir.path().join("vault-b");
    std::fs::create_dir_all(&ours).unwrap();
    std::fs::create_dir_all(&theirs).unwrap();

    let key = RunKey::new(ours.clone(), runner.clone());
    runner.set(
        &key.value_name(),
        run_value(&theirs.join(r"bin\tethra-gateway-0.0.9.exe"), &theirs),
    );

    for result in [
        key.stop(),
        key.unregister(),
        key.restart(),
        key.remove_definition(),
    ] {
        let err = result
            .expect_err("a foreign Run value must be refused")
            .to_string();
        assert!(
            err.contains("belongs to a different Tethra data directory"),
            "{err}"
        );
        assert!(err.contains(&theirs.display().to_string()), "{err}");
    }

    runner.assert_no_destructive_verb_ran();
    assert!(
        runner.has(&key.value_name()),
        "the other installation's Run value survives"
    );
}

/// The mutation guard, stated at the level that actually matters: not "the
/// error text was right" but "no command capable of taking a service down
/// was ever handed to the OS". The verbs' results are deliberately
/// DISCARDED, so this test survives any rewording or restructuring of the
/// refusal and fails for exactly one reason — the ownership proof is gone.
#[test]
fn no_destructive_command_ever_reaches_a_foreign_target_on_any_platform() {
    let dir = tempfile::tempdir().unwrap();
    let theirs = dir.path().join("vault-b");
    std::fs::create_dir_all(&theirs).unwrap();
    let their_bin = theirs.join("bin/tethra-gateway-0.0.9");

    #[cfg(unix)]
    {
        let runner = Arc::new(MockRunner::default());
        let ours = mac_env(dir.path(), "mac-vault", runner.clone());
        write_plist(
            &ours.manager.definition_path(),
            &ours.manager.service_name(),
            &their_bin,
            &theirs,
        );
        let _ = ours.manager.stop();
        let _ = ours.manager.unregister();
        let _ = ours.manager.restart();
        let _ = ours.manager.remove_definition();
        runner.assert_no_destructive_verb_ran();

        let runner = Arc::new(MockRunner::default());
        let ours = linux_env(dir.path(), "linux-vault", runner.clone());
        write_unit(&ours.manager.definition_path(), &their_bin, &theirs);
        let _ = ours.manager.stop();
        let _ = ours.manager.unregister();
        let _ = ours.manager.restart();
        let _ = ours.manager.remove_definition();
        runner.assert_no_destructive_verb_ran();
    }

    let runner = Arc::new(RegRunner::default());
    let ours = dir.path().join("win-vault");
    std::fs::create_dir_all(&ours).unwrap();
    let key = RunKey::new(ours, runner.clone());
    runner.set(&key.value_name(), run_value(&their_bin, &theirs));
    let _ = key.stop();
    let _ = key.unregister();
    let _ = key.restart();
    let _ = key.remove_definition();
    runner.assert_no_destructive_verb_ran();
    assert!(
        runner.has(&key.value_name()),
        "the foreign Run value must still be there"
    );
}

// ---------------------------------------------------------------------------
// Two environments side by side
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn installing_and_uninstalling_one_environment_leaves_the_other_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let src = fake_source_binary(dir.path());
    let a = mac_env(dir.path(), "vault-a", runner.clone());
    let b = mac_env(dir.path(), "vault-b", runner.clone());

    a.install(&src, false).unwrap();
    b.install(&src, false).expect(
        "a second environment must install without colliding with the first \
         (before namespacing this refused, or worse, took the first one over)",
    );

    assert_ne!(a.manager.definition_path(), b.manager.definition_path());
    assert!(a.manager.definition_path().exists());
    assert!(b.manager.definition_path().exists());
    assert_eq!(
        b.manager.read_definition().unwrap().unwrap().data_dir,
        b.data_dir
    );

    // Uninstalling A must remove exactly A's definition.
    let conn = migrated(&a.data_dir.join("vault.db"));
    a.uninstall(&conn, true).unwrap();

    assert!(!a.manager.definition_path().exists(), "ours is gone");
    assert!(
        b.manager.definition_path().exists(),
        "the other environment's LaunchAgent must survive our uninstall"
    );
    assert_eq!(
        b.manager.read_definition().unwrap().unwrap().data_dir,
        b.data_dir,
        "and still point at its own vault"
    );
    assert!(
        !runner.ran(&format!("bootout gui/501/{}", b.manager.service_name())),
        "our uninstall must never bootout the other environment's job: {:?}",
        runner.calls()
    );
}

/// Install and repair must write, register and start the namespaced slot —
/// and repair must reuse it rather than accumulate a second definition.
#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn install_and_repair_target_this_installations_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let lc = mac_env(dir.path(), "vault-a", runner.clone());
    let src = fake_source_binary(dir.path());

    let report = lc.install(&src, false).unwrap();
    let expected = lc.manager.definition_path().display().to_string();
    assert_eq!(report.definition, expected);
    assert!(
        runner.ran(&format!("bootstrap gui/501 {expected}")),
        "bootstrap must name OUR plist: {:?}",
        runner.calls()
    );
    assert!(
        runner.ran(&format!("kickstart gui/501/{}", lc.manager.service_name())),
        "start must name OUR label: {:?}",
        runner.calls()
    );

    lc.repair(&src).unwrap();
    let plists: Vec<_> = std::fs::read_dir(dir.path().join("LaunchAgents"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        plists,
        vec![format!("{}.plist", lc.manager.service_name())],
        "repair reuses the namespaced slot instead of adding another"
    );
}

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn status_reports_the_installation_id_and_the_resolved_service_name() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let a = mac_env(dir.path(), "vault-a", runner.clone());
    let b = mac_env(dir.path(), "vault-b", runner);
    let src = fake_source_binary(dir.path());
    a.install(&src, false).unwrap();

    let s = a.status();
    assert_eq!(s.installation_id, installation_id(&a.data_dir));
    assert_eq!(
        s.service_name,
        api_tracker_gateway::lifecycle::macos::label_for(&s.installation_id)
    );
    assert!(
        s.definition_path
            .ends_with(&format!("{}.plist", s.service_name)),
        "the reported name must be the one on disk: {}",
        s.definition_path
    );
    assert!(s.installed && s.matches_data_dir);

    // The other environment reports a different identity and — crucially —
    // does not report OUR install as its own.
    let other = b.status();
    assert_ne!(other.installation_id, s.installation_id);
    assert_ne!(other.service_name, s.service_name);
    assert!(!other.installed);
}

// ---------------------------------------------------------------------------
// Legacy migration (existing users must not end up with two agents)
// ---------------------------------------------------------------------------

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn install_takes_over_a_legacy_launch_agent_that_points_at_our_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let lc = mac_env(dir.path(), "vault-a", runner.clone());
    let src = fake_source_binary(dir.path());

    let legacy_label = api_tracker_gateway::lifecycle::macos::LEGACY_LABEL;
    let legacy_plist = dir
        .path()
        .join("LaunchAgents")
        .join(format!("{legacy_label}.plist"));
    write_plist(
        &legacy_plist,
        legacy_label,
        &lc.data_dir.join("bin/tethra-gateway-0.0.9"),
        &lc.data_dir,
    );

    let report = lc.install(&src, false).unwrap();

    assert!(
        runner.ran_exactly(&format!("launchctl bootout gui/501/{legacy_label}")),
        "the legacy job must be unloaded before ours takes the port: {:?}",
        runner.calls()
    );
    assert!(
        !legacy_plist.exists(),
        "the legacy plist must be removed, or login starts TWO gateways \
         against one vault"
    );
    assert!(lc.manager.definition_path().exists());
    assert!(
        report.notes.iter().any(|n| n.contains(legacy_label)),
        "the takeover must be reported, not silent: {:?}",
        report.notes
    );
    // The bootout of the legacy label happens before we bootstrap ours.
    let calls = runner.calls();
    let legacy_out = calls
        .iter()
        .position(|c| *c == format!("launchctl bootout gui/501/{legacy_label}"))
        .unwrap();
    let bootstrap = calls
        .iter()
        .position(|c| c.contains("launchctl bootstrap"))
        .unwrap();
    assert!(legacy_out < bootstrap, "{calls:?}");
}

#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn install_leaves_a_legacy_launch_agent_for_another_data_dir_completely_alone() {
    let dir = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let lc = mac_env(dir.path(), "vault-a", runner.clone());
    let theirs = dir.path().join("vault-b");
    std::fs::create_dir_all(&theirs).unwrap();
    let src = fake_source_binary(dir.path());

    let legacy_label = api_tracker_gateway::lifecycle::macos::LEGACY_LABEL;
    let legacy_plist = dir
        .path()
        .join("LaunchAgents")
        .join(format!("{legacy_label}.plist"));
    write_plist(
        &legacy_plist,
        legacy_label,
        &theirs.join("bin/tethra-gateway-0.0.9"),
        &theirs,
    );
    let before = std::fs::read_to_string(&legacy_plist).unwrap();

    let report = lc
        .install(&src, false)
        .expect("someone else's legacy agent must not fail our install");

    assert!(
        legacy_plist.exists() && std::fs::read_to_string(&legacy_plist).unwrap() == before,
        "another installation's pre-namespacing agent is not ours to migrate"
    );
    assert!(
        !runner.ran_exactly(&format!("launchctl bootout gui/501/{legacy_label}")),
        "and must never be booted out: {:?}",
        runner.calls()
    );
    assert!(
        !report.notes.iter().any(|n| n.contains(legacy_label)),
        "nothing was migrated, so nothing may be claimed: {:?}",
        report.notes
    );
}

#[cfg(unix)] // Unix service-manager (systemd) behavior
#[test]
fn install_takes_over_a_legacy_unit_only_when_it_points_at_our_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = api_tracker_gateway::lifecycle::linux::LEGACY_UNIT_NAME;

    // (1) Legacy unit for ANOTHER data directory: untouched.
    let runner = Arc::new(MockRunner::default());
    let lc = linux_env(dir.path(), "vault-a", runner.clone());
    let theirs = dir.path().join("vault-b");
    std::fs::create_dir_all(&theirs).unwrap();
    let legacy_path = dir.path().join("systemd-user").join(legacy);
    write_unit(
        &legacy_path,
        &theirs.join("bin/tethra-gateway-0.0.9"),
        &theirs,
    );
    let src = fake_source_binary(dir.path());

    lc.install(&src, false).unwrap();
    assert!(legacy_path.exists(), "not ours to remove");
    assert!(
        !runner.ran(&format!("stop {legacy}")) && !runner.ran(&format!("disable {legacy}")),
        "not ours to stop: {:?}",
        runner.calls()
    );

    // (2) Same unit, now pointing at OUR data directory: taken over.
    write_unit(
        &legacy_path,
        &lc.data_dir.join("bin/tethra-gateway-0.0.9"),
        &lc.data_dir,
    );
    let report = lc.install(&src, false).unwrap();
    assert!(!legacy_path.exists(), "the legacy unit file is removed");
    assert!(
        runner.ran(&format!("systemctl --user stop {legacy}"))
            && runner.ran(&format!("systemctl --user disable {legacy}")),
        "the legacy unit must be stopped and disabled: {:?}",
        runner.calls()
    );
    assert!(lc.manager.definition_path().exists());
    assert!(report.notes.iter().any(|n| n.contains(legacy)));
}

#[test]
fn a_legacy_run_value_is_reclaimed_only_when_it_points_at_our_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = api_tracker_gateway::lifecycle::windows::LEGACY_VALUE_NAME;
    let ours = dir.path().join("vault-a");
    let theirs = dir.path().join("vault-b");
    std::fs::create_dir_all(&ours).unwrap();
    std::fs::create_dir_all(&theirs).unwrap();

    // (1) Legacy value for ANOTHER data directory: untouched.
    let runner = Arc::new(RegRunner::default());
    let key = RunKey::new(ours.clone(), runner.clone());
    let foreign = run_value(&theirs.join(r"bin\tethra-gateway-0.0.9.exe"), &theirs);
    runner.set(legacy, foreign.clone());

    assert_eq!(key.reclaim_legacy().unwrap(), None);
    assert_eq!(runner.get(legacy).as_deref(), Some(foreign.as_str()));
    runner.assert_no_destructive_verb_ran();

    // (2) Same value, now pointing at OUR data directory: reclaimed.
    runner.set(
        legacy,
        run_value(&ours.join(r"bin\tethra-gateway-0.0.9.exe"), &ours),
    );
    assert_eq!(
        key.reclaim_legacy().unwrap().as_deref(),
        Some(legacy),
        "our own pre-namespacing entry is migrated"
    );
    assert!(!runner.has(legacy), "the legacy Run value is deleted");

    // The namespaced value is a DIFFERENT entry, and reading it must not be
    // confused by the legacy name being a prefix of it.
    key.write_definition(&ours.join(r"bin\tethra-gateway-0.1.0.exe"))
        .unwrap();
    assert!(runner.has(&key.value_name()));
    assert_ne!(key.value_name(), legacy);
    assert_eq!(
        key.read_definition().unwrap().unwrap().data_dir,
        ours,
        "the namespaced value round-trips"
    );
}

/// Uninstall removes exactly ours: the namespaced definition, plus a legacy
/// one only when it points here. It must not leave an abandoned service
/// behind, and must not take one that is not ours.
#[cfg(unix)] // Unix service-manager (LaunchAgent) behavior
#[test]
fn uninstall_removes_our_legacy_definition_but_never_another_environments() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_label = api_tracker_gateway::lifecycle::macos::LEGACY_LABEL;
    let legacy_plist = dir
        .path()
        .join("LaunchAgents")
        .join(format!("{legacy_label}.plist"));

    // A legacy agent belonging to ANOTHER data directory survives our
    // uninstall untouched...
    let runner = Arc::new(MockRunner::default());
    let lc = mac_env(dir.path(), "vault-a", runner.clone());
    let theirs = dir.path().join("vault-b");
    std::fs::create_dir_all(&theirs).unwrap();
    let src = fake_source_binary(dir.path());
    lc.install(&src, false).unwrap();
    write_plist(
        &legacy_plist,
        legacy_label,
        &theirs.join("bin/tethra-gateway-0.0.9"),
        &theirs,
    );
    let conn = migrated(&lc.data_dir.join("vault.db"));
    let report = lc.uninstall(&conn, true).unwrap();
    assert!(legacy_plist.exists(), "not ours to delete");
    assert!(!runner.ran_exactly(&format!("launchctl bootout gui/501/{legacy_label}")));
    assert!(!lc.manager.definition_path().exists());

    // ...but one pointing HERE is cleaned up, so uninstall really does leave
    // nothing of ours registered.
    write_plist(
        &legacy_plist,
        legacy_label,
        &lc.data_dir.join("bin/tethra-gateway-0.0.9"),
        &lc.data_dir,
    );
    let report2 = lc.uninstall(&conn, true).unwrap();
    assert!(!legacy_plist.exists(), "our own legacy agent is removed");
    assert!(
        report2
            .disable
            .notes
            .iter()
            .any(|n| n.contains(legacy_label)),
        "{:?} (first pass: {:?})",
        report2.disable.notes,
        report.disable.notes
    );
}

/// `repair` must not force past the ownership refusal.
///
/// This is the follow-through the adversarial review of the namespacing fix
/// found missing. `Lifecycle::repair` used to call `install(binary, true)`,
/// and repair is reached AUTOMATICALLY from the `tethra track` apply path
/// whenever the installed helper's version differs from the running build —
/// no user decision behind it. Forced, it walked past the different-data-dir
/// refusal, wrote our definition over the other installation's, and then,
/// because the slot now parsed as ours, passed the ownership proof on the
/// way to booting that installation's gateway out. ZFT-014 again, from the
/// automatic path.
#[cfg(unix)]
#[test]
fn repair_refuses_a_slot_that_belongs_to_another_installation() {
    let root = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let ours = mac_env(root.path(), "ours", runner.clone());
    let src = fake_source_binary(root.path());

    // Another installation's definition occupies OUR namespaced slot.
    let foreign_data_dir = root.path().join("theirs");
    std::fs::create_dir_all(&foreign_data_dir).unwrap();
    let squatter = LaunchAgent::new(
        &foreign_data_dir,
        root.path().join("LaunchAgents"),
        "501".into(),
        runner.clone(),
    );
    // Write it under OUR file name, so only the parsed `--data-dir`
    // distinguishes it.
    std::fs::create_dir_all(root.path().join("LaunchAgents")).unwrap();
    std::fs::write(
        ours.manager.definition_path(),
        squatter.render_plist(&foreign_data_dir.join("bin/tethra-gateway-0.0.9")),
    )
    .unwrap();
    let before = std::fs::read_to_string(ours.manager.definition_path()).unwrap();
    runner.clear();

    let err = ours
        .repair(&src)
        .expect_err("repair must refuse a slot owned by another installation");
    assert!(
        err.to_string().contains("different data"),
        "the refusal must name the reason: {err}"
    );

    // Nothing was written, and nothing destructive ran.
    assert_eq!(
        std::fs::read_to_string(ours.manager.definition_path()).unwrap(),
        before,
        "repair must not have rewritten the other installation's definition"
    );
    runner.assert_no_destructive_verb_ran();

    // The control: repair on OUR OWN slot still works, so the guard is
    // about ownership rather than about disabling repair.
    let mine = mac_env(root.path(), "mine", runner.clone());
    mine.install(&src, false).expect("first install");
    runner.clear();
    mine.repair(&src).expect("repair of our own installation");
}

/// An unparseable definition in our slot is foreign, not absent.
///
/// `install` guarded only when `read_definition` returned `Some`, so a
/// definition file we cannot parse yielded `None` and was silently unlinked
/// and overwritten — the exact opposite of the rule `reclaim_legacy` states
/// in as many words two files over.
#[cfg(unix)]
#[test]
fn install_refuses_to_overwrite_a_definition_it_cannot_parse() {
    let root = tempfile::tempdir().unwrap();
    let runner = Arc::new(MockRunner::default());
    let ours = mac_env(root.path(), "ours", runner.clone());
    let src = fake_source_binary(root.path());

    std::fs::create_dir_all(root.path().join("LaunchAgents")).unwrap();
    std::fs::write(
        ours.manager.definition_path(),
        "<?xml version=\"1.0\"?>\n<!-- not a plist this parser understands -->\n",
    )
    .unwrap();
    let before = std::fs::read_to_string(ours.manager.definition_path()).unwrap();

    let err = ours
        .install(&src, false)
        .expect_err("an unparseable definition must not be silently replaced");
    assert!(
        err.to_string().contains("could not be parsed"),
        "the refusal must say WHY: {err}"
    );
    assert_eq!(
        std::fs::read_to_string(ours.manager.definition_path()).unwrap(),
        before,
        "the file must be left exactly as it was"
    );

    // …and `--force` is the documented way through, since the user may
    // genuinely be recovering from a corrupted file.
    let report = ours.install(&src, true).expect("forced install proceeds");
    assert!(
        report.notes.iter().any(|n| n.contains("unparseable")),
        "a forced overwrite must be reported: {:?}",
        report.notes
    );
}
