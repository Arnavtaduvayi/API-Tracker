//! The projects-first workflow: select a folder once, confirm one disclosure,
//! and have the association survive relaunches without re-running setup
//! (ADR 0029).
//!
//! Mocks and fixtures only. Nothing here installs a service, touches launchd,
//! or opens a socket: `MockOps` stands in for every host effect, exactly as
//! `plan_apply.rs` does. There is a live production gateway on the machine this
//! was developed on, and no test in this file can reach it.

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use api_tracker_core::projectlink::{self, DetectedStatus};
use api_tracker_core::secret::SecretBytes;
use api_tracker_tracking::apply::{ApplyOptions, ServiceEnsureOutcome, ServiceOps};
use api_tracker_tracking::plan::ServiceAction;
use api_tracker_tracking::verify::ProbeOutcome;
use api_tracker_tracking::{project, state};
use common::*;
use tempfile::TempDir;

/// Every host effect, recorded and neutralised.
struct MockOps {
    calls: Arc<Mutex<Vec<String>>>,
}

impl MockOps {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ServiceOps for MockOps {
    fn ensure_service(&self, _actions: &[ServiceAction]) -> ServiceEnsureOutcome {
        self.calls.lock().unwrap().push("ensure_service".into());
        ServiceEnsureOutcome::Verified
    }
    fn push_route_key(&self, _key: &SecretBytes) -> bool {
        true
    }
    fn push_matching_key(&self, _key: SecretBytes) -> api_tracker_core::Result<()> {
        Ok(())
    }
    fn reload_routes(&self) -> bool {
        true
    }
    fn probe_route(&self, _port: u16, _base_url: &str) -> ProbeOutcome {
        ProbeOutcome::GatewayAnswered {
            status: "204".into(),
        }
    }
}

/// A fixture project folder with two recognised providers.
fn fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    dir
}

/// A real vault-backed project, so apply's `ensure_project` has one to find.
fn new_project(tv: &mut TestVault) -> String {
    tv.vault
        .create_project(api_tracker_core::vault::NewProject {
            name: "web".into(),
            ..Default::default()
        })
        .unwrap()
        .id
}

// ---------------------------------------------------------------------------
// A project with no folder
// ---------------------------------------------------------------------------

#[test]
fn a_project_with_no_folder_has_no_link_and_no_status() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let overview = project::overview(&conn, tmp.path(), "p1").unwrap();
    assert!(overview.link.is_none(), "nothing selected yet");
    assert!(overview.status.is_none());
    assert!(!overview.scan_stale, "never scanned is not stale");
    assert!(overview.detected_credentials.is_empty());
    assert_eq!(overview.credentials_needing_details, 0);
}

// ---------------------------------------------------------------------------
// Selecting a folder
// ---------------------------------------------------------------------------

#[test]
fn preparing_a_link_detects_providers_and_returns_one_disclosure() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let folder = fixture();

    let preview = project::prepare_link(
        &conn,
        tmp.path(),
        "p1",
        "web",
        folder.path(),
        &service_absent(),
        false,
    )
    .unwrap();

    assert!(
        !preview.detection.providers.is_empty(),
        "the fixture declares openai and anthropic"
    );
    assert!(!preview.digest.is_empty());
    assert!(
        !preview.disclosure.is_empty(),
        "a configuration-changing action needs its disclosure"
    );
    let text = preview.disclosure.join(" ");
    assert!(
        text.contains("never stored"),
        "the disclosure must say bodies are not stored: {text}"
    );
    assert!(
        text.contains("unlink"),
        "the disclosure must say it can be undone: {text}"
    );
    assert!(!preview.already_configured);
}

/// The disclosure is derived from the plan, so it cannot describe less than the
/// plan will do. If the plan edits files, the disclosure names them.
#[test]
fn the_disclosure_names_the_files_that_will_be_edited() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let folder = fixture();
    let preview = project::prepare_link(
        &conn,
        tmp.path(),
        "p1",
        "web",
        folder.path(),
        &service_absent(),
        false,
    )
    .unwrap();

    let planned_files: Vec<String> = preview
        .plan
        .as_ref()
        .expect("the fixture is auto-configurable")
        .link_plans
        .iter()
        .flat_map(|lp| lp.files.iter().map(|f| f.path.clone()))
        .collect();
    let text = preview.disclosure.join(" ");
    for f in &planned_files {
        assert!(
            text.contains(f),
            "the plan edits {f} but the disclosure does not mention it: {text}"
        );
    }
    if !planned_files.is_empty() {
        assert!(text.contains("undone"), "an edit must be undoable: {text}");
    }
}

/// A disclosure that counts destinations without naming them does not let the
/// user recognise what they are agreeing to.
#[test]
fn the_disclosure_names_the_apis_that_will_be_routed() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let folder = fixture();
    let preview = project::prepare_link(
        &conn,
        tmp.path(),
        "p1",
        "web",
        folder.path(),
        &service_absent(),
        false,
    )
    .unwrap();

    let plan = preview.plan.as_ref().expect("the fixture is configurable");
    let creating: Vec<&str> = plan
        .route_actions
        .iter()
        .filter(|r| r.creates())
        .map(|r| r.provider_id())
        .collect();
    assert!(!creating.is_empty(), "the fixture registers routes");
    let text = preview.disclosure.join(" ");
    for provider in &creating {
        assert!(
            text.contains(provider),
            "the disclosure registers {provider} without naming it: {text}"
        );
    }
}

/// A destination read from project files is never pre-approved: repository
/// content is evidence, not authorization (ADR 0024 / ZFT-004).
#[test]
fn a_repository_discovered_destination_is_not_pre_approved() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[
            (
                ".env",
                &format!("SUPABASE_URL=https://attacker.example.com\nSUPABASE_ANON_KEY={FAKE_OPENAI_KEY}\n"),
            ),
            (
                "package.json",
                r#"{ "dependencies": { "@supabase/supabase-js": "^2.0.0" } }"#,
            ),
        ],
    );

    let preview = project::prepare_link(
        &conn,
        tmp.path(),
        "p1",
        "web",
        dir.path(),
        &service_absent(),
        false,
    )
    .unwrap();

    // Nothing is auto-configurable, because the only destination came from
    // repository content. That is a STATE with a pending approval, not an
    // error, and it must not have produced a plan.
    assert!(
        preview.plan.is_none(),
        "a repository-discovered destination produced a configurable plan"
    );
    assert!(
        preview.digest.is_empty(),
        "a preview with no plan must not carry a confirmable digest"
    );
    assert!(
        !preview.pending_origin_approvals.is_empty(),
        "the user should be told which destinations were found"
    );
    // `prepare_link` builds from `Selections::defaults`, which never includes a
    // repository-discovered destination — so the copy must not send the user
    // round a loop that cannot terminate.
    let text = preview.disclosure.join(" ");
    assert!(
        text.contains("advanced"),
        "the disclosure must point at the flow that can actually configure it: {text}"
    );
    assert!(
        !text.contains("select the folder again"),
        "re-selecting the folder changes nothing here, so it must not be suggested: {text}"
    );
    let approvals: i64 = conn
        .query_row("SELECT COUNT(*) FROM tracking_approved_origins", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(approvals, 0, "preparing a link approves nothing");
}

// ---------------------------------------------------------------------------
// The consent gate
// ---------------------------------------------------------------------------

#[test]
fn confirming_with_a_wrong_digest_is_refused_and_changes_nothing() {
    let mut tv = test_vault();
    let folder = fixture();
    let project_id = new_project(&mut tv);

    let err = project::confirm_link(
        &mut tv.vault,
        &tv.data_dir,
        &project_id,
        "web",
        folder.path(),
        "0000000000000000000000000000000000000000000000000000000000000000",
        &service_absent(),
        false,
        &ApplyOptions {
            master_password: None,
        },
        &MockOps::new(),
    )
    .expect_err("a digest that matches nothing must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("changed since it was reviewed"),
        "the refusal must say why: {msg}"
    );

    let conn = tv.vault.connection();
    assert!(
        projectlink::get_link(conn, &project_id).unwrap().is_none(),
        "a refused confirmation must not link the folder"
    );
    let setups: i64 = conn
        .query_row("SELECT COUNT(*) FROM tracking_setups", [], |r| r.get(0))
        .unwrap();
    assert_eq!(setups, 0, "a refused confirmation must not create a setup");
}

#[test]
fn confirming_the_previewed_digest_links_the_folder_and_records_detections() {
    let mut tv = test_vault();
    let folder = fixture();
    let project_id = new_project(&mut tv);

    let preview = project::prepare_link(
        tv.vault.connection(),
        &tv.data_dir,
        &project_id,
        "web",
        folder.path(),
        &service_absent(),
        false,
    )
    .unwrap();
    let digest = preview.digest.clone();

    let outcome = project::confirm_link(
        &mut tv.vault,
        &tv.data_dir,
        &project_id,
        "web",
        folder.path(),
        &digest,
        &service_absent(),
        false,
        &ApplyOptions {
            master_password: None,
        },
        &MockOps::new(),
    )
    .unwrap();

    assert_eq!(outcome.link.project_id, project_id);
    assert!(outcome.link.tracking_enabled);
    assert!(
        outcome.link.scan_fingerprint.is_some(),
        "the scan that informed the apply is recorded"
    );
    assert!(
        !outcome.detected_credentials.is_empty(),
        "the fixture's credential variables become unfinished records"
    );

    // The linkage survives being read back — this is what makes it persistent.
    let reread = projectlink::get_link(tv.vault.connection(), &project_id)
        .unwrap()
        .unwrap();
    assert_eq!(reread.folder_path, outcome.link.folder_path);

    // A successful setup must NOT immediately report the folder as changed.
    // Apply rewrites `.env`, which the fingerprint covers, so recording the
    // pre-apply fingerprint made every clean setup land on a page telling the
    // user their files had changed — about a change Tethra had just made.
    let overview = project::overview(tv.vault.connection(), &tv.data_dir, &project_id).unwrap();
    assert!(
        !overview.scan_stale,
        "a clean setup reported its own file edits as a change the user should rescan"
    );
}

// ---------------------------------------------------------------------------
// Unfinished credentials
// ---------------------------------------------------------------------------

/// The structural guarantee: a detected-credential row has nowhere to put a
/// value, so a value found in a project file cannot reach the database through
/// this path. The canary is written into the fixture and then hunted for in
/// every column of the table.
#[test]
fn no_secret_value_reaches_a_detected_credential_row() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[
            (
                ".env",
                &format!("OPENAI_API_KEY={CANARY}\nMYSTERY_API_KEY={CANARY}\n"),
            ),
            (
                "package.json",
                r#"{ "dependencies": { "openai": "^4.0.0", "dotenv": "^16.0.0" } }"#,
            ),
        ],
    );

    let preview = project::prepare_link(
        &conn,
        tmp.path(),
        "p1",
        "web",
        dir.path(),
        &service_absent(),
        false,
    )
    .unwrap();
    assert!(
        !preview.detected_credentials.is_empty(),
        "the fixture has credential variables to find"
    );

    // Persist them the way a confirmed link would, then sweep the whole table.
    for p in &preview.detected_credentials {
        if p.already_have_credential {
            continue;
        }
        projectlink::upsert_detection(
            &conn,
            "p1",
            &projectlink::NewDetection {
                env_var: &p.env_var,
                suggested_provider: p.suggested_provider.as_deref(),
                suggested_name: Some(&p.suggested_name),
                suggested_environment: None,
                source_kind: p.source_kind,
                source_file: &p.source_file,
            },
        )
        .unwrap();
    }

    let dumped = dump_table(&conn, "detected_credentials");
    assert!(
        !dumped.contains(CANARY),
        "a discovered value reached detected_credentials: {dumped}"
    );
    // The WHOLE preview, not just the credential list: `detection`,
    // `disclosure` and `summary` all cross IPC too, and `ProjectDetection` is
    // additionally serialized verbatim into `tracking_setups.detection_json`,
    // which is a plaintext column. Sweeping only the sub-list left every field
    // that actually carries risk unguarded.
    let serialized = serde_json::to_string(&preview).unwrap();
    assert!(
        !serialized.contains(CANARY),
        "a discovered value reached the preview DTO"
    );
    // And the same structure as it lands on disk.
    let detection_json = serde_json::to_string(&preview.detection).unwrap();
    assert!(
        !detection_json.contains(CANARY),
        "a discovered value would be written to tracking_setups.detection_json"
    );
    let disclosure = preview.disclosure.join(" ");
    assert!(
        !disclosure.contains(CANARY),
        "a discovered value reached the disclosure shown to the user"
    );

    let rows = projectlink::list_detections(&conn, "p1").unwrap();
    assert!(rows.iter().all(|r| r.status == DetectedStatus::Pending));
    for r in &rows {
        assert_eq!(r.value_status(), "Not saved in Tethra");
        assert_eq!(r.attribution_status(), "Pending exact key");
    }
}

/// Every value in every column of a table, as one string.
fn dump_table(conn: &rusqlite::Connection, table: &str) -> String {
    let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
    let cols = stmt.column_count();
    let mut out = String::new();
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        for i in 0..cols {
            if let Ok(v) = row.get::<_, rusqlite::types::Value>(i) {
                out.push_str(&format!("{v:?}|"));
            }
        }
    }
    out
}

#[test]
fn a_provider_the_project_already_has_a_credential_for_is_not_unfinished() {
    let mut tv = test_vault();
    let folder = fixture();
    let project_id = new_project(&mut tv);
    tv.vault
        .add_credential(api_tracker_core::vault::AddCredential {
            project: project_id.clone(),
            provider: "openai".into(),
            name: "openai-api-key".into(),
            environment: api_tracker_core::model::Environment::Development,
            value: api_tracker_core::secret::SecretString::new(FAKE_OPENAI_KEY.to_string()),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();

    let preview = project::prepare_link(
        tv.vault.connection(),
        &tv.data_dir,
        &project_id,
        "web",
        folder.path(),
        &service_absent(),
        false,
    )
    .unwrap();

    let openai: Vec<_> = preview
        .detected_credentials
        .iter()
        .filter(|d| d.suggested_provider.as_deref() == Some("openai"))
        .collect();
    assert!(
        !openai.is_empty(),
        "the detection is still reported, so the user can see it happened"
    );
    assert!(
        openai.iter().all(|d| d.already_have_credential),
        "a provider with a credential is not unfinished"
    );
}

#[test]
fn a_detection_can_be_renamed_reassigned_ignored_and_merged() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let row = projectlink::upsert_detection(
        &conn,
        "p1",
        &projectlink::NewDetection {
            env_var: "GROQ_API_KEY",
            suggested_provider: Some("groq"),
            suggested_name: Some("groq-api-key"),
            suggested_environment: None,
            source_kind: projectlink::DetectedSource::EnvFile,
            source_file: ".env",
        },
    )
    .unwrap();
    assert_eq!(row.suggested_environment, None, "unknown, never guessed");

    let renamed = projectlink::rename_detection(&conn, &row.id, "groq-prod").unwrap();
    assert_eq!(renamed.suggested_name.as_deref(), Some("groq-prod"));

    let reassigned = projectlink::reassign_detection_provider(&conn, &row.id, "openai").unwrap();
    assert_eq!(reassigned.suggested_provider.as_deref(), Some("openai"));

    let scoped = projectlink::set_detection_environment(&conn, &row.id, "production").unwrap();
    assert_eq!(scoped.suggested_environment.as_deref(), Some("production"));

    let ignored =
        projectlink::resolve_detection(&conn, &row.id, DetectedStatus::Ignored, None).unwrap();
    assert_eq!(ignored.status, DetectedStatus::Ignored);
    assert!(!ignored.status.needs_attention());
    assert_eq!(ignored.attribution_status(), "Not attributed (ignored)");

    // 'ignored' means there is no Tethra credential, so pointing it at one is
    // a contradiction rather than a silently dropped argument.
    let err = projectlink::resolve_detection(
        &conn,
        &row.id,
        DetectedStatus::Ignored,
        Some("some-credential"),
    )
    .expect_err("ignored cannot carry a credential");
    assert!(err.to_string().contains("no Tethra credential"));

    // Completing without the credential it resolved to is likewise refused.
    let err = projectlink::resolve_detection(&conn, &row.id, DetectedStatus::Completed, None)
        .expect_err("completed needs its credential");
    assert!(err.to_string().contains("needs the credential"));
}

/// Re-running detection must not resurrect a decision the user already made.
#[test]
fn re_detecting_does_not_resurrect_an_ignored_detection() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let new = projectlink::NewDetection {
        env_var: "GROQ_API_KEY",
        suggested_provider: Some("groq"),
        suggested_name: Some("groq-api-key"),
        suggested_environment: None,
        source_kind: projectlink::DetectedSource::EnvFile,
        source_file: ".env",
    };
    let row = projectlink::upsert_detection(&conn, "p1", &new).unwrap();
    projectlink::resolve_detection(&conn, &row.id, DetectedStatus::Ignored, None).unwrap();

    let again = projectlink::upsert_detection(&conn, "p1", &new).unwrap();
    assert_eq!(again.id, row.id, "one row per (project, var, file)");
    assert_eq!(
        again.status,
        DetectedStatus::Ignored,
        "the user's decision survives a rescan"
    );
    assert_eq!(projectlink::list_detections(&conn, "p1").unwrap().len(), 1);
}

#[test]
fn duplicate_detection_of_the_same_variable_updates_one_row() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let new = projectlink::NewDetection {
        env_var: "OPENAI_API_KEY",
        suggested_provider: Some("openai"),
        suggested_name: Some("openai-api-key"),
        suggested_environment: None,
        source_kind: projectlink::DetectedSource::EnvFile,
        source_file: ".env",
    };
    let a = projectlink::upsert_detection(&conn, "p1", &new).unwrap();
    let b = projectlink::upsert_detection(&conn, "p1", &new).unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(projectlink::list_detections(&conn, "p1").unwrap().len(), 1);

    // The same variable in a DIFFERENT file is a different finding.
    let other = projectlink::NewDetection {
        source_file: ".env.production",
        ..new
    };
    projectlink::upsert_detection(&conn, "p1", &other).unwrap();
    assert_eq!(projectlink::list_detections(&conn, "p1").unwrap().len(), 2);
}

/// Roughly thirty integrations must all survive to the review surface — none
/// silently dropped.
#[test]
fn about_thirty_detections_all_appear() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let vars: Vec<String> = (0..30).map(|i| format!("SERVICE{i:02}_API_KEY")).collect();
    for v in &vars {
        projectlink::upsert_detection(
            &conn,
            "p1",
            &projectlink::NewDetection {
                env_var: v,
                suggested_provider: None,
                suggested_name: Some("x"),
                suggested_environment: None,
                source_kind: projectlink::DetectedSource::EnvFile,
                source_file: ".env",
            },
        )
        .unwrap();
    }
    let rows = projectlink::list_detections(&conn, "p1").unwrap();
    assert_eq!(rows.len(), 30);
    assert_eq!(
        rows.iter().filter(|r| r.status.needs_attention()).count(),
        30
    );
    for v in &vars {
        assert!(
            rows.iter().any(|r| &r.env_var == v),
            "{v} was silently dropped"
        );
    }
}

// ---------------------------------------------------------------------------
// Linkage lifecycle
// ---------------------------------------------------------------------------

#[test]
fn re_selecting_the_same_folder_is_idempotent() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let first = projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    projectlink::record_scan(&conn, &mut first.clone(), Some("fp-1")).unwrap();

    let again = projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    assert_eq!(again.folder_path, "/tmp/x");
    assert_eq!(again.linked_at, first.linked_at, "the link is not re-made");
    assert_eq!(
        again.scan_fingerprint.as_deref(),
        Some("fp-1"),
        "nothing about the folder changed, so its scan state is kept"
    );
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM project_folder_links", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(rows, 1, "one folder per project, not an accumulating list");
}

#[test]
fn changing_folders_clears_the_previous_folders_scan_state() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let mut link = projectlink::upsert_link(&conn, "p1", "/tmp/a").unwrap();
    projectlink::record_scan(&conn, &mut link, Some("fp-a")).unwrap();
    projectlink::record_applied_generation(&conn, &mut link, 3).unwrap();

    let moved = projectlink::upsert_link(&conn, "p1", "/tmp/b").unwrap();
    assert_eq!(moved.folder_path, "/tmp/b");
    assert_eq!(
        moved.scan_fingerprint, None,
        "a fingerprint describes the old folder"
    );
    assert_eq!(moved.applied_generation, 0);
}

#[test]
fn disabling_tracking_keeps_the_link_the_detections_and_the_history() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    projectlink::upsert_detection(
        &conn,
        "p1",
        &projectlink::NewDetection {
            env_var: "OPENAI_API_KEY",
            suggested_provider: Some("openai"),
            suggested_name: Some("openai-api-key"),
            suggested_environment: None,
            source_kind: projectlink::DetectedSource::EnvFile,
            source_file: ".env",
        },
    )
    .unwrap();
    insert_gateway_event(&conn, "p1", "api.openai.com", "2026-07-24T10:00:00Z");

    project::set_tracking_enabled(&conn, "p1", false).unwrap();

    let overview = project::overview(&conn, tmp.path(), "p1").unwrap();
    let link = overview.link.expect("still linked");
    assert!(!link.tracking_enabled);
    assert_eq!(link.folder_path, "/tmp/x");
    assert_eq!(overview.detected_credentials.len(), 1);
    let events: i64 = conn
        .query_row("SELECT COUNT(*) FROM runtime_request_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(events, 1, "history is not deleted by disabling tracking");

    // And it can be turned back on.
    project::set_tracking_enabled(&conn, "p1", true).unwrap();
    assert!(
        project::overview(&conn, tmp.path(), "p1")
            .unwrap()
            .link
            .unwrap()
            .tracking_enabled
    );
}

/// Re-selecting a folder must not silently re-enable tracking the user turned
/// off.
#[test]
fn re_linking_does_not_re_enable_disabled_tracking() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    project::set_tracking_enabled(&conn, "p1", false).unwrap();

    let same = projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    assert!(!same.tracking_enabled);
    let moved = projectlink::upsert_link(&conn, "p1", "/tmp/y").unwrap();
    assert!(
        !moved.tracking_enabled,
        "changing folders is not consent to resume tracking"
    );
}

#[test]
fn unlinking_keeps_the_project_its_credentials_and_its_history() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    insert_gateway_event(&conn, "p1", "api.openai.com", "2026-07-24T10:00:00Z");

    assert!(project::unlink(&conn, "p1").unwrap());

    let projects: i64 = conn
        .query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        projects, 1,
        "unlinking a folder does not delete the project"
    );
    let events: i64 = conn
        .query_row("SELECT COUNT(*) FROM runtime_request_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(events, 1, "history survives unless the user deletes it");
    assert!(project::overview(&conn, tmp.path(), "p1")
        .unwrap()
        .link
        .is_none());

    // Unlinking again is not an error the user needs to see.
    assert!(!project::unlink(&conn, "p1").unwrap());
}

#[test]
fn deleting_a_project_removes_its_linkage_and_detections() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    projectlink::upsert_detection(
        &conn,
        "p1",
        &projectlink::NewDetection {
            env_var: "OPENAI_API_KEY",
            suggested_provider: Some("openai"),
            suggested_name: Some("openai-api-key"),
            suggested_environment: None,
            source_kind: projectlink::DetectedSource::EnvFile,
            source_file: ".env",
        },
    )
    .unwrap();

    conn.execute("DELETE FROM projects WHERE id = 'p1'", [])
        .unwrap();

    let links: i64 = conn
        .query_row("SELECT COUNT(*) FROM project_folder_links", [], |r| {
            r.get(0)
        })
        .unwrap();
    let dets: i64 = conn
        .query_row("SELECT COUNT(*) FROM detected_credentials", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        (links, dets),
        (0, 0),
        "ON DELETE CASCADE leaves no orphan linkage or detection"
    );
}

// ---------------------------------------------------------------------------
// Reads must not write
// ---------------------------------------------------------------------------

/// The invariant that makes a live project page safe: reading the overview
/// must not mint a new verification session or bump the configuration
/// generation. `state::upsert_setup` does both, which is why the read path may
/// never call it.
#[test]
fn reading_the_overview_repeatedly_does_not_disturb_the_setup() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/x"),
        state::TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();

    let before = state::find_setup(&conn, "p1", Path::new("/tmp/x"))
        .unwrap()
        .unwrap();

    for _ in 0..5 {
        project::overview(&conn, tmp.path(), "p1").unwrap();
    }

    let after = state::find_setup(&conn, "p1", Path::new("/tmp/x"))
        .unwrap()
        .unwrap();
    assert_eq!(
        after.config_generation, before.config_generation,
        "a page read re-configured the project"
    );
    assert_eq!(
        after.verification_session, before.verification_session,
        "a page read minted a new verification session"
    );
}

/// The five-second path touches no tracking state at all.
#[test]
fn the_activity_snapshot_writes_no_tracking_state() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/x"),
        state::TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    let before = state::find_setup(&conn, "p1", Path::new("/tmp/x"))
        .unwrap()
        .unwrap();

    for _ in 0..10 {
        project::activity_only(
            &conn,
            "p1",
            project::TimeRange::Last24Hours,
            &api_tracker_core::projectactivity::ActivityFilter::default(),
            50,
        )
        .unwrap();
    }

    let after = state::find_setup(&conn, "p1", Path::new("/tmp/x"))
        .unwrap()
        .unwrap();
    assert_eq!(after.row_version, before.row_version, "a poll wrote state");
    assert_eq!(after.config_generation, before.config_generation);
}

#[test]
fn an_activity_snapshot_with_no_traffic_says_so_rather_than_showing_zeroes() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let snap = project::activity_only(
        &conn,
        "p1",
        project::TimeRange::Last24Hours,
        &api_tracker_core::projectactivity::ActivityFilter::default(),
        50,
    )
    .unwrap();
    assert!(snap.no_observations);
    assert!(snap.series.is_empty(), "no fabricated zero points");
    assert!(snap.recent.is_empty());
    assert!(snap.cost.is_empty());
    assert!(!snap.refreshed_at.is_empty());
}

#[test]
fn an_activity_snapshot_reports_observed_traffic() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let at = api_tracker_core::clock::now_rfc3339();
    insert_gateway_event(&conn, "p1", "api.openai.com", &at);
    let snap = project::activity_only(
        &conn,
        "p1",
        project::TimeRange::Last24Hours,
        &api_tracker_core::projectactivity::ActivityFilter::default(),
        50,
    )
    .unwrap();
    assert!(!snap.no_observations);
    assert_eq!(snap.metrics.total, 1);
    assert_eq!(snap.series.len(), 1);
    assert_eq!(snap.recent.len(), 1);
    assert_eq!(snap.integrations.len(), 1);
    assert_eq!(snap.integrations[0].host, "api.openai.com");
}

/// Each named range picks a bucket width that keeps the point count useful.
#[test]
fn each_time_range_picks_a_sensible_granularity() {
    use api_tracker_core::projectactivity::Granularity;
    assert_eq!(
        project::TimeRange::LastHour.granularity(),
        Granularity::Minute
    );
    assert_eq!(
        project::TimeRange::Last24Hours.granularity(),
        Granularity::Hour
    );
    assert_eq!(
        project::TimeRange::Last7Days.granularity(),
        Granularity::Day
    );
    assert_eq!(
        project::TimeRange::Last30Days.granularity(),
        Granularity::Day
    );
    for r in ["1h", "24h", "7d", "30d"] {
        assert_eq!(project::TimeRange::parse(r).as_str(), r);
    }
}

// ---------------------------------------------------------------------------
// Relaunch
// ---------------------------------------------------------------------------

/// The relaunch path reads state and resolves health. It must not rescan a
/// folder or rewrite a project file — which is observable here as the
/// fingerprint being left exactly as it was.
#[test]
fn restoring_on_launch_does_not_rescan_or_reconfigure() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let mut link = projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    projectlink::record_scan(&conn, &mut link, Some("fp-1")).unwrap();
    state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/x"),
        state::TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    let before = state::find_setup(&conn, "p1", Path::new("/tmp/x"))
        .unwrap()
        .unwrap();

    let restored = project::restore_on_launch(&conn, tmp.path()).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].0, "p1");

    let after_link = projectlink::get_link(&conn, "p1").unwrap().unwrap();
    assert_eq!(
        after_link.scan_fingerprint.as_deref(),
        Some("fp-1"),
        "launch re-scanned the folder"
    );
    let after = state::find_setup(&conn, "p1", Path::new("/tmp/x"))
        .unwrap()
        .unwrap();
    assert_eq!(
        after.config_generation, before.config_generation,
        "launch re-applied the configuration"
    );
}

#[test]
fn a_disabled_project_is_not_resumed_on_launch() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    project::set_tracking_enabled(&conn, "p1", false).unwrap();
    let restored = project::restore_on_launch(&conn, tmp.path()).unwrap();
    assert_eq!(restored.len(), 1);
    assert!(
        restored[0].1.is_none(),
        "a disabled project reports no tracking status"
    );
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

#[test]
fn the_fingerprint_is_stable_and_changes_only_when_a_manifest_does() {
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[("package.json", r#"{"dependencies":{"openai":"^4.0.0"}}"#)],
    );
    let a = project::folder_fingerprint(dir.path());
    let b = project::folder_fingerprint(dir.path());
    assert_eq!(a, b, "the same folder must fingerprint the same way twice");

    // A file the fingerprint does not track leaves it alone.
    write_project(dir.path(), &[("src/main.ts", "console.log(1)")]);
    assert_eq!(
        project::folder_fingerprint(dir.path()),
        a,
        "source edits are not dependency changes"
    );

    // A manifest change moves it.
    write_project(
        dir.path(),
        &[(
            "package.json",
            r#"{"dependencies":{"openai":"^4.0.0","@anthropic-ai/sdk":"^0.30.0"}}"#,
        )],
    );
    assert_ne!(
        project::folder_fingerprint(dir.path()),
        a,
        "a dependency change must be visible"
    );
}

#[test]
fn a_missing_folder_fingerprints_without_erroring() {
    let fp = project::folder_fingerprint(Path::new("/nonexistent/tethra/test/folder"));
    assert!(
        !fp.is_empty(),
        "an unavailable folder is a state, not a panic"
    );
}

/// The fingerprint walk must not follow a symlink out of the project, for the
/// same reason the detection readers refuse to.
#[cfg(unix)]
#[test]
fn the_fingerprint_walk_does_not_follow_symlinks_out_of_the_folder() {
    let outside = TempDir::new().unwrap();
    write_project(outside.path(), &[("package.json", r#"{"a":1}"#)]);
    let dir = TempDir::new().unwrap();
    let empty = project::folder_fingerprint(dir.path());

    std::os::unix::fs::symlink(
        outside.path().join("package.json"),
        dir.path().join("package.json"),
    )
    .unwrap();
    assert_eq!(
        project::folder_fingerprint(dir.path()),
        empty,
        "a symlinked manifest was followed out of the project"
    );
}

/// A stale fingerprint surfaces as an offer to rescan, and offering is not
/// doing: nothing about the configuration changes.
#[test]
fn a_changed_manifest_marks_the_scan_stale_without_reconfiguring() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = TempDir::new().unwrap();
    write_project(dir.path(), &[("package.json", r#"{"a":1}"#)]);
    let folder = dir.path().display().to_string();

    let mut link = projectlink::upsert_link(&conn, "p1", &folder).unwrap();
    let fp = project::folder_fingerprint(dir.path());
    projectlink::record_scan(&conn, &mut link, Some(&fp)).unwrap();
    assert!(
        !project::overview(&conn, tmp.path(), "p1")
            .unwrap()
            .scan_stale
    );

    write_project(dir.path(), &[("package.json", r#"{"a":2,"b":3}"#)]);
    let overview = project::overview(&conn, tmp.path(), "p1").unwrap();
    assert!(
        overview.scan_stale,
        "a manifest change should offer a rescan"
    );

    // Reading that it is stale changed nothing about the recorded scan.
    assert_eq!(
        projectlink::get_link(&conn, "p1")
            .unwrap()
            .unwrap()
            .scan_fingerprint
            .as_deref(),
        Some(fp.as_str())
    );
}

#[test]
fn a_rescan_refreshes_the_fingerprint_and_the_detections() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let folder = dir.path().canonicalize().unwrap().display().to_string();
    let mut link = projectlink::upsert_link(&conn, "p1", &folder).unwrap();
    projectlink::record_scan(&conn, &mut link, Some("stale-fp")).unwrap();

    let created = project::rescan(&conn, "p1").unwrap();
    assert!(!created.is_empty(), "the fixture has credentials to find");
    let after = projectlink::get_link(&conn, "p1").unwrap().unwrap();
    assert_ne!(after.scan_fingerprint.as_deref(), Some("stale-fp"));
    assert!(
        !project::overview(&conn, tmp.path(), "p1")
            .unwrap()
            .scan_stale
    );
}

// ---------------------------------------------------------------------------
// Compare-and-swap
// ---------------------------------------------------------------------------

/// A linkage write carries the version it read, so a second writer working
/// from a stale row cannot silently overwrite the first.
#[test]
fn a_stale_linkage_write_is_refused_rather_than_losing_the_update() {
    let (dir, conn, path) = test_conn_at();
    let _ = dir;
    insert_project(&conn, "p1", "web");
    let mut a = projectlink::upsert_link(&conn, "p1", "/tmp/x").unwrap();
    let mut b = a.clone();

    // Writer A commits.
    projectlink::record_scan(&conn, &mut a, Some("fp-a")).unwrap();

    // Writer B decided from the pre-A row, in a separate connection.
    let other = second_conn(&path);
    let err = projectlink::record_scan(&other, &mut b, Some("fp-b"))
        .expect_err("a stale write must be refused");
    assert!(
        matches!(err, api_tracker_core::CoreError::StateConflict { .. }),
        "expected a state conflict, got {err}"
    );

    // A's value stands; B's conclusion did not overwrite it.
    assert_eq!(
        projectlink::get_link(&conn, "p1")
            .unwrap()
            .unwrap()
            .scan_fingerprint
            .as_deref(),
        Some("fp-a")
    );
}
