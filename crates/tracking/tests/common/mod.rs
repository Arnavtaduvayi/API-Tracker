//! Shared harness for the tracking crate's tests. Mocks and fixtures only:
//! unmistakably fake credentials, throwaway temp vaults, no network, no
//! real service, never the developer's own vault.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, UnlockedVault, VaultPaths};
use api_tracker_core::{db, model};
use rusqlite::Connection;
use tempfile::TempDir;

/// Unmistakably fake; passes the placeholder filter (so S1 fires) while
/// obviously not a real credential.
pub const FAKE_OPENAI_KEY: &str = "sk-proj-FAKE-TEST-KEY-0000000000000001";
pub const FAKE_ANTHROPIC_KEY: &str = "sk-ant-api03-FAKE-TEST-KEY-000000000001";
/// Canary marker: if this ever shows up in serialized detection output or
/// logs, a value leaked.
pub const CANARY: &str = "CANARY-VALUE-MUST-NEVER-PERSIST-7f3a";

pub struct TestVault {
    pub _dir: TempDir,
    pub data_dir: PathBuf,
    pub vault: UnlockedVault,
}

pub fn master_password() -> SecretString {
    SecretString::new("test-master-password".to_string())
}

/// A real (fast-KDF) vault in a temp dir — needed by apply/undo tests that
/// exercise project creation and key derivation.
pub fn test_vault() -> TestVault {
    std::env::set_var("API_TRACKER_INSECURE_FAST_KDF", "1");
    let dir = TempDir::new().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = VaultPaths::new(data_dir.clone());
    let vault = vault::create_vault(&paths, &master_password()).unwrap();
    TestVault {
        _dir: dir,
        data_dir,
        vault,
    }
}

/// A bare migrated DB (no vault) for read-only planning/state tests.
pub fn test_conn() -> (TempDir, Connection) {
    let dir = TempDir::new().unwrap();
    let mut conn = db::open(&dir.path().join("vault.db")).unwrap();
    db::migrate(&mut conn).unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('vault_id', 'vault-test-0001')",
        [],
    )
    .unwrap();
    (dir, conn)
}

/// Minimal project row without vault crypto (for FK satisfaction in
/// state/verify tests that never unlock anything).
pub fn insert_project(conn: &Connection, id: &str, name: &str) {
    conn.execute(
        "INSERT INTO projects (id, name, description, notes, environments, archived,
                               created_at, updated_at, wrapped_project_key, key_wrap_mode,
                               project_kdf_params, project_salt)
         VALUES (?1, ?2, '', '', '[]', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                 X'00', 'vault', NULL, NULL)",
        rusqlite::params![id, name],
    )
    .unwrap();
}

/// Insert one gateway-observed request event for a project (all FK rows
/// included). Returns the event id.
pub fn insert_gateway_event(conn: &Connection, project_id: &str, host: &str, at: &str) -> String {
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

/// Write a fixture project folder. `files` maps relative path → content.
pub fn write_project(dir: &Path, files: &[(&str, &str)]) {
    for (rel, content) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }
}

/// A standard two-provider node fixture: OpenAI + Anthropic keys in .env,
/// openai npm dependency, dotenv loader present.
pub fn node_two_provider_fixture(dir: &Path) {
    write_project(
        dir,
        &[
            (
                ".env",
                &format!(
                    "OPENAI_API_KEY={FAKE_OPENAI_KEY}\nANTHROPIC_API_KEY={FAKE_ANTHROPIC_KEY}\n"
                ),
            ),
            (
                "package.json",
                r#"{ "name": "fixture", "dependencies": { "openai": "^4.0.0", "dotenv": "^16.0.0", "@anthropic-ai/sdk": "^0.30.0" } }"#,
            ),
        ],
    );
}

/// Default service status fixture: nothing installed.
pub fn service_absent() -> api_tracker_gateway::lifecycle::ServiceStatus {
    api_tracker_gateway::lifecycle::ServiceStatus {
        platform: "test",
        // Namespaced service identity (ADR 0025): fixtures use an explicit
        // test installation so nothing in this suite can be confused with a
        // real one.
        installation_id: "testinstall00".to_string(),
        service_name: "dev.api-tracker.gateway.testinstall00".to_string(),
        installed: false,
        definition_path: String::new(),
        definition: None,
        matches_data_dir: true,
        binary_exists: false,
        binary_version: None,
        binary_version_measured: false,
        registered: false,
        running: false,
        pid: None,
        os_will_run: api_tracker_gateway::lifecycle::OsWillRun::Unknown {
            why: "test fixture".to_string(),
        },
        owned_artifacts: Vec::new(),
        notes: Vec::new(),
    }
}

pub fn service_running() -> api_tracker_gateway::lifecycle::ServiceStatus {
    let mut s = service_absent();
    s.installed = true;
    s.registered = true;
    s.running = true;
    s.binary_exists = true;
    s.binary_version = Some(env!("CARGO_PKG_VERSION").to_string());
    s
}

/// Suppress unused warnings for model import used indirectly.
pub fn _touch(_: &model::Project) {}
