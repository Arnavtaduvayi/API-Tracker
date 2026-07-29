//! Shared harness for the CLI's integration tests.
//!
//! Everything here drives the REAL `tethra` binary against a throwaway vault
//! in a temp directory, with an isolated `HOME` and `TETHRA_DIR`. Nothing
//! touches the developer's own vault, and — deliberately — nothing installs
//! a launchd job:
//!
//! [`TestVault::spawn_gateway`] starts a **foreground** `tethra gateway
//! serve` child bound to its own ephemeral port under its own data
//! directory. `plan::plan` emits `ServiceAction::AlreadyRunning` when a
//! verified listener already answers, so `track --yes` then reaches its
//! verify loop without the apply engine ever calling `launchctl`. This is
//! the same technique `scripts/tracking_validate_macos.sh --foreground`
//! uses, and it is what makes the `NEW-01` regression suite safe to run on
//! a machine carrying a live production gateway.

#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use api_tracker_tracking::state::{self, PlanSummary, TrackingSetup, TrackingState};
use assert_cmd::Command;
use rusqlite::Connection;
use tempfile::TempDir;

pub const MASTER_PW: &str = "test-master-password";
pub const FAKE_OPENAI_KEY: &str = "sk-proj-FAKE-TEST-KEY-0000000000000001";

pub struct TestVault {
    pub _dir: TempDir,
    pub data_dir: PathBuf,
}

impl TestVault {
    pub fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        let tv = TestVault {
            _dir: dir,
            data_dir,
        };
        tv.cmd().arg("init").assert().success();
        tv
    }

    /// An isolated fake `HOME` so lifecycle code can never see (let alone
    /// touch) the real `~/Library/LaunchAgents`.
    pub fn home(&self) -> PathBuf {
        self._dir.path().join("home")
    }

    pub fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("tethra").unwrap();
        self.apply_env(&mut c);
        c
    }

    fn apply_env(&self, c: &mut Command) {
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home())
            .env("TETHRA_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("TETHRA_PASSWORD", MASTER_PW);
    }

    /// A raw `std::process::Command` for the same binary, for children the
    /// test needs to interleave with (`assert_cmd::Command` runs to
    /// completion).
    pub fn raw(&self) -> StdCommand {
        let mut c = self.raw_no_password();
        c.env("TETHRA_PASSWORD", MASTER_PW);
        c
    }

    /// The same, without `TETHRA_PASSWORD`. A command run this way unlocks
    /// from a persisted session (see [`TestVault::unlock_session`]) and so
    /// takes the "no password in a non-interactive run" branch — which is
    /// how attribution ends up switched off while forwarding stays healthy.
    pub fn raw_no_password(&self) -> StdCommand {
        let mut c = StdCommand::new(assert_cmd::cargo::cargo_bin("tethra"));
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home())
            .env("TETHRA_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1");
        c
    }

    /// Unlock and return the session token, so a later command can run with
    /// `TETHRA_SESSION` set and `TETHRA_PASSWORD` unset — the shape a user
    /// gets from `eval "$(tethra unlock --print-export)"`.
    pub fn unlock_session(&self) -> String {
        let out = self
            .cmd()
            .args(["unlock", "--print-export"])
            .output()
            .unwrap();
        assert!(out.status.success(), "tethra unlock failed");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        stdout
            .lines()
            .find_map(|l| l.strip_prefix("export TETHRA_SESSION=\""))
            .and_then(|rest| rest.strip_suffix('"'))
            .map(|s| s.to_string())
            .unwrap_or_else(|| panic!("no TETHRA_SESSION export in:\n{stdout}"))
    }

    pub fn project_dir(&self, name: &str) -> PathBuf {
        let p = self._dir.path().join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    pub fn conn(&self) -> Connection {
        api_tracker_core::db::open(&self.data_dir.join("vault.db")).unwrap()
    }

    pub fn port(&self) -> Option<u16> {
        api_tracker_gateway::store::load_config(&self.conn())
            .ok()
            .and_then(|c| c.port)
    }

    /// Start a foreground gateway and wait until it proves its identity on
    /// the port it persisted. Killed on drop.
    pub fn spawn_gateway(&self) -> GatewayChild {
        let child = self
            .raw()
            .args(["gateway", "serve"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning the foreground gateway");
        let mut gw = GatewayChild {
            child: Some(child),
            data_dir: self.data_dir.clone(),
            port: 0,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(p) = self.port() {
                if p != 0
                    && matches!(
                        api_tracker_gateway::control::verify_listener(&self.data_dir, p),
                        api_tracker_gateway::control::ListenerIdentity::Verified { .. }
                    )
                {
                    gw.port = p;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(gw.port != 0, "the foreground gateway never verified");
        gw
    }
}

pub struct GatewayChild {
    child: Option<Child>,
    data_dir: PathBuf,
    pub port: u16,
}

impl GatewayChild {
    /// Stop the gateway and wait until the port stops verifying, so a test
    /// that kills it can rely on the very next probe reading `Down`.
    pub fn kill(mut self) {
        self.stop();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if !matches!(
                api_tracker_gateway::control::verify_listener(&self.data_dir, self.port),
                api_tracker_gateway::control::ListenerIdentity::Verified { .. }
            ) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the foreground gateway kept answering after being killed");
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for GatewayChild {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Wait until a spawned `track` child has reached its verify loop, so the
/// test can act (kill the gateway, delete a route) at a known point.
///
/// Reads the child's stdout line by line and returns the reader so the
/// caller can go on consuming the rest of the output. Panics rather than
/// hanging forever if the marker never appears.
pub fn wait_for_line(child: &mut Child, marker: &str) -> BufReader<std::process::ChildStdout> {
    let stdout = child.stdout.take().expect("track child stdout");
    let mut reader = BufReader::new(stdout);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut seen = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("reading track stdout");
        if n == 0 {
            panic!("track exited before printing {marker:?}; output so far:\n{seen}");
        }
        seen.push_str(&line);
        if line.contains(marker) {
            return reader;
        }
        if Instant::now() >= deadline {
            panic!("track never printed {marker:?}; output so far:\n{seen}");
        }
    }
}

pub fn drain(mut reader: BufReader<std::process::ChildStdout>) -> String {
    let mut rest = String::new();
    use std::io::Read;
    let _ = reader.read_to_string(&mut rest);
    rest
}

pub fn write_fixture(dir: &Path) {
    std::fs::write(
        dir.join(".env"),
        format!("OPENAI_API_KEY={FAKE_OPENAI_KEY}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{ "dependencies": { "openai": "^4.0.0", "dotenv": "^16.0.0" } }"#,
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Synthesised state — the cheap layer, for cases that need no gateway process
// ---------------------------------------------------------------------------

/// A minimal project row (no vault crypto), for FK satisfaction.
pub fn insert_project(conn: &Connection, id: &str, name: &str) {
    conn.execute(
        "INSERT OR IGNORE INTO projects (id, name, description, notes, environments, archived,
                               created_at, updated_at, wrapped_project_key, key_wrap_mode,
                               project_kdf_params, project_salt)
         VALUES (?1, ?2, '', '', '[]', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                 X'00', 'vault', NULL, NULL)",
        rusqlite::params![id, name],
    )
    .unwrap();
}

/// A route + project link for `provider`, so the ground-truth checks in
/// `refresh_with` see a configuration that still exists.
pub fn wire_route_and_link(conn: &Connection, project_id: &str, provider: &str) {
    conn.execute(
        "INSERT OR REPLACE INTO gateway_routes
            (route_prefix, provider_id, enabled, created_at, updated_at)
         VALUES (?1, ?1, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        [provider],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO gateway_project_links
            (link_slug, project_id, route_prefix, created_at)
         VALUES (?1, ?2, ?3, '2026-01-01T00:00:00Z')",
        [&format!("slug-{provider}"), project_id, provider],
    )
    .unwrap();
}

/// An applied setup for `folder` with `providers` configured, their routes
/// and links present, and `applied_at` backdated two days so both bounds
/// under test — "at or after apply" and "inside the freshness window" — stay
/// independently reachable.
pub fn configured_setup(
    conn: &Connection,
    project_id: &str,
    folder: &Path,
    providers: &[&str],
) -> TrackingSetup {
    insert_project(conn, project_id, project_id);
    let mut setup = state::upsert_setup(
        conn,
        project_id,
        folder,
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    let summary = PlanSummary {
        providers: providers.iter().map(|s| s.to_string()).collect(),
        links: providers.iter().map(|s| s.to_string()).collect(),
        port: 49152,
        ..Default::default()
    };
    state::record_applied(conn, &mut setup, &summary).unwrap();
    let two_days_ago = api_tracker_core::clock::rfc3339_minus_seconds(
        &api_tracker_core::clock::now_rfc3339(),
        2 * 24 * 3600,
    );
    conn.execute(
        "UPDATE tracking_setups SET applied_at = ?2 WHERE id = ?1",
        rusqlite::params![setup.id, two_days_ago],
    )
    .unwrap();
    for p in providers {
        wire_route_and_link(conn, project_id, p);
    }
    state::get_setup(conn, &setup.id).unwrap().unwrap()
}

/// Insert one gateway-observed request event for a project.
pub fn plant_observation(conn: &Connection, project_id: &str, host: &str, at: &str) -> String {
    use api_tracker_core::runtime::model::*;
    use api_tracker_core::runtime::store as rstore;
    let (service_id, _known) = rstore::upsert_service(conn, host, None, false, at).unwrap();
    let session_id = rstore::insert_session(
        conn,
        &rstore::NewSession {
            project_id,
            mode: ObservationMode::Metadata,
            source: "gateway",
            command: "",
            credential_names: &[],
        },
    )
    .unwrap();
    let req = ObservedRequest {
        host: host.to_string(),
        port: 443,
        method: HttpMethod::Post,
        path_template: "/v1/x".to_string(),
        template_confidence: api_tracker_core::providers::Confidence::High,
        status_code: Some(200),
        req_content_kind: None,
        resp_content_kind: None,
        had_authorization: true,
        latency_ms: Some(201),
        request_bytes: Some(100),
        response_bytes: Some(200),
        protocol: Protocol::Http11,
        observation_source: ObservationSource::Gateway,
        transport_error: TransportError::None,
    };
    rstore::insert_request_event(
        conn,
        &session_id,
        project_id,
        &service_id,
        None,
        at,
        &req,
        false,
    )
    .unwrap()
}

/// Right now. Layer A plants observations AFTER a real apply, whose
/// `applied_at` watermark is the moment the test ran — an observation dated
/// even a minute earlier is correctly refused as evidence about this
/// session, which is the admissibility rule and not something to work
/// around.
pub fn now() -> String {
    api_tracker_core::clock::now_rfc3339()
}

/// `now` minus a minute: inside the freshness window whatever the wall
/// clock says.
pub fn recent() -> String {
    api_tracker_core::clock::rfc3339_minus_seconds(&api_tracker_core::clock::now_rfc3339(), 60)
}

/// Old enough to be outside the freshness window.
pub fn stale() -> String {
    api_tracker_core::clock::rfc3339_minus_seconds(
        &api_tracker_core::clock::now_rfc3339(),
        state::OBSERVATION_FRESHNESS_SECS + 3600,
    )
}

/// The single tracking setup registered for a folder.
pub fn setup_for(conn: &Connection, folder: &Path) -> TrackingSetup {
    state::setups_for_folder(conn, folder)
        .unwrap()
        .into_iter()
        .next()
        .expect("no tracking setup for that folder")
}
