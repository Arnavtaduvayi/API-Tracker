//! Integration tests for the observability milestone: expanded rules,
//! incremental repository monitoring, notification channels, and
//! documentation-watch scheduling/history. Fake credentials only.

mod common;

use api_tracker_core::alerts;
use api_tracker_core::http::MockHttpClient;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use common::{add_key, add_project, new_vault};
use std::process::Command;

const FAKE_KEY: &str = "sk-proj-FAKE0000000000000000000000000000FAKE";

fn git(dir: &std::path::Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?} failed");
}

fn open_alert_kinds(v: &api_tracker_core::vault::UnlockedVault) -> Vec<String> {
    alerts::list(v.connection(), false)
        .unwrap()
        .into_iter()
        .map(|a| a.kind)
        .collect()
}

#[test]
fn incremental_repo_scan_baselines_then_flags_only_new_commits() {
    let (_dir, _paths, mut v) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "-q"]);
    git(repo.path(), &["config", "user.email", "t@example.invalid"]);
    git(repo.path(), &["config", "user.name", "t"]);
    std::fs::write(repo.path().join("README.md"), "hello\n").unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "init"]);

    let project = add_project(&mut v, "app");
    v.update_project(
        &project.id,
        api_tracker_core::vault::UpdateProject {
            add_repo_paths: vec![repo.path().to_string_lossy().into_owned()],
            ..Default::default()
        },
    )
    .unwrap();
    add_key(&mut v, "app", "openai", FAKE_KEY, Environment::Production);

    // First run: baseline only — existing history is NOT silently scanned.
    let reports = v.scan_repos_incremental().unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].baseline_only);
    assert_eq!(reports[0].findings, 0);

    // No new commits: nothing to do (repo skipped entirely).
    let reports = v.scan_repos_incremental().unwrap();
    assert!(reports.is_empty());

    // A new commit leaks the vault credential.
    std::fs::write(
        repo.path().join("config.py"),
        format!("OPENAI_API_KEY = \"{FAKE_KEY}\"\n"),
    )
    .unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "oops"]);

    let reports = v.scan_repos_incremental().unwrap();
    assert_eq!(reports.len(), 1);
    assert!(!reports[0].baseline_only);
    assert!(reports[0].findings >= 1, "the leaked key must be found");

    // The matched credential is marked possibly exposed, and the monitor
    // turns that into an exposure alert.
    let cred = v.get_credential("app/openai").unwrap();
    assert!(cred.possibly_exposed);
    v.run_monitor().unwrap();
    assert!(open_alert_kinds(&v).contains(&"possible_exposure".to_string()));
}

#[test]
fn observe_rules_fire_with_evidence_and_auto_resolve() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let (cred, _) = add_key(&mut v, "app", "openai", FAKE_KEY, Environment::Production);
    let conn = v.connection();

    // Request spike: 60 requests last month, 200 this month.
    let now = time::OffsetDateTime::now_utc();
    let this_month = format!("{:04}-{:02}-02T00:00:00Z", now.year(), now.month() as u8);
    let (py, pm) = match now.month() as u8 {
        1 => (now.year() - 1, 12),
        m => (now.year(), m - 1),
    };
    let last_month = format!("{py:04}-{pm:02}-02T00:00:00Z");
    for (id, window, requests) in [("s1", &last_month, 60), ("s2", &this_month, 200)] {
        conn.execute(
            "INSERT INTO usage_snapshots (id, credential_id, provider, window_start, window_end,
                 request_count, source, attribution, collected_at)
             VALUES (?1, ?2, 'openai', ?3, ?3, ?4, 'openai_usage_api', 'exact_credential', ?3)",
            rusqlite::params![id, cred.id, window, requests],
        )
        .unwrap();
    }

    // Repeated auth failures: three failed validations in 24h.
    for _ in 0..3 {
        conn.execute(
            "INSERT INTO audit_events (at, event, credential_id, detail)
             VALUES (?1, 'credential_validated', ?2, 'valid=false')",
            rusqlite::params![api_tracker_core::clock::now_rfc3339(), cred.id],
        )
        .unwrap();
    }

    // First-seen provider entities (within 7 days).
    conn.execute(
        "INSERT INTO provider_side_keys (provider, api_key_id, name, redacted_value, synced_at, first_seen_at)
         VALUES ('openai', 'key_fresh', 'mystery', 'sk-...x', ?1, ?1)",
        [api_tracker_core::clock::now_rfc3339()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO provider_side_projects (provider, project_id, name, status, synced_at, first_seen_at)
         VALUES ('openai', 'proj_fresh', 'new-proj', 'active', ?1, ?1)",
        [api_tracker_core::clock::now_rfc3339()],
    )
    .unwrap();

    // Destination drift.
    let dest = v
        .destination_add(
            "github_actions",
            "ci",
            serde_json::json!({"owner":"o","repo":"r"}),
            Some(&SecretString::from(
                "ghp_FAKE0000000000000000000000000000000000",
            )),
        )
        .unwrap();
    v.destination_attach(&cred.id, &dest.id, "OPENAI_API_KEY", "production")
        .unwrap();
    v.connection()
        .execute("UPDATE credential_destinations SET drift = 'drifted'", [])
        .unwrap();

    let summary = v.run_monitor().unwrap();
    assert!(summary.alerts_created >= 4);
    let kinds = open_alert_kinds(&v);
    for expected in [
        "request_spike",
        "repeated_auth_failure",
        "new_provider_key",
        "new_provider_project",
        "destination_drift",
    ] {
        assert!(
            kinds.contains(&expected.to_string()),
            "missing {expected}: {kinds:?}"
        );
    }

    // Alerts carry evidence and windows, never secret values.
    let all = alerts::list(v.connection(), false).unwrap();
    let spike = all.iter().find(|a| a.kind == "request_spike").unwrap();
    assert!(spike.evidence.contains("current_month=200"));
    assert!(spike.detail.contains("Attribution"));
    let serialized = serde_json::to_string(&all).unwrap();
    assert!(!serialized.contains(FAKE_KEY));

    // Conditions clear -> auto-resolve on the next run.
    v.connection()
        .execute("UPDATE credential_destinations SET drift = 'in_sync'", [])
        .unwrap();
    v.connection()
        .execute(
            "UPDATE provider_side_keys SET first_seen_at = '2000-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
    v.connection()
        .execute(
            "UPDATE provider_side_projects SET first_seen_at = '2000-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
    v.run_monitor().unwrap();
    let kinds = open_alert_kinds(&v);
    assert!(!kinds.contains(&"destination_drift".to_string()));
    assert!(!kinds.contains(&"new_provider_key".to_string()));
}

#[test]
fn rotation_attention_and_grant_expiry_alerts() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let (cred, _) = add_key(&mut v, "app", "gh", FAKE_KEY, Environment::Production);

    // A rotation parked in manual_required.
    let plan = v.rotation_plan(&cred.id, 0, None, None, "").unwrap();
    v.connection()
        .execute(
            "UPDATE rotations SET state = 'manual_required' WHERE id = ?1",
            [&plan.rotation.id],
        )
        .unwrap();

    // A grant that expired minutes ago.
    let grant = v
        .access_grant_create("app", "expired demo", &[], 60, 0, None, None)
        .unwrap();
    v.connection()
        .execute(
            "UPDATE access_grants SET expires_at = ?1 WHERE id = ?2",
            rusqlite::params![
                api_tracker_core::clock::to_rfc3339(
                    api_tracker_core::clock::now() - time::Duration::minutes(5)
                ),
                grant.id
            ],
        )
        .unwrap();

    v.run_monitor().unwrap();
    let kinds = open_alert_kinds(&v);
    assert!(
        kinds.contains(&"rotation_attention".to_string()),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&"access_grant_expired".to_string()),
        "{kinds:?}"
    );
}

#[test]
fn notification_channels_deliver_metadata_only_and_record_failures() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    // An expired credential produces a high-severity alert.
    v.add_credential(api_tracker_core::vault::AddCredential {
        project: "app".into(),
        provider: "openai".into(),
        name: "old".into(),
        environment: Environment::Production,
        value: SecretString::from(FAKE_KEY),
        credential_type: None,
        key_created_at: None,
        expires_at: Some("2020-01-01".into()),
        docs_url: String::new(),
        notes: String::new(),
    })
    .unwrap();

    // http URL is refused; https accepted; the URL is stored encrypted.
    let bad = SecretString::from("http://example.com/hook");
    assert!(v.notification_channel_add("bad", &bad, "high").is_err());
    let url = "https://hooks.example.com/T000/FAKE-token";
    let channel = v
        .notification_channel_add("team", &SecretString::from(url), "high")
        .unwrap();
    assert!(!channel.url_masked.contains("FAKE-token"));
    let raw_db = {
        let mut blob: Vec<u8> = Vec::new();
        let mut stmt = v
            .connection()
            .prepare("SELECT url_ciphertext FROM notification_channels")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap();
        for r in rows {
            blob = r.unwrap();
        }
        blob
    };
    let needle = url.as_bytes();
    assert!(
        !raw_db.windows(needle.len()).any(|w| w == needle),
        "the webhook URL must be encrypted at rest"
    );

    v.run_monitor().unwrap();

    // A failing webhook records the error, does not fail the caller, and
    // does NOT mark the alert delivered — so the next run retries it.
    let http = MockHttpClient::with(500, vec![], "{}");
    v.deliver_notifications(&http).unwrap();
    let channels = v.notification_channels().unwrap();
    assert!(channels[0].last_error.contains("500"));

    let http = MockHttpClient::json(r#"{"ok":true}"#);
    let delivered = v.deliver_notifications(&http).unwrap();
    assert!(delivered >= 1, "a failed delivery must be retried next run");
    let req = http.last_request().unwrap();
    assert_eq!(req.url, url);
    let body = String::from_utf8_lossy(req.body.as_ref().unwrap()).into_owned();
    assert!(body.contains("expired"));
    assert!(!body.contains(FAKE_KEY), "payloads carry metadata only");
    let channels = v.notification_channels().unwrap();
    assert!(
        channels[0].last_error.is_empty(),
        "success clears the error"
    );

    // Once-per-alert dedup: the same open alert at the same severity is NOT
    // re-delivered on the next run (regression test — the monitor runs every
    // `monitor_interval_minutes`, and each run used to re-send everything
    // observed within the previous hour).
    let http = MockHttpClient::json(r#"{"ok":true}"#);
    let delivered = v.deliver_notifications(&http).unwrap();
    assert_eq!(delivered, 0, "already-delivered alerts must not repeat");
    assert!(http.last_request().is_none(), "no request should be made");

    // Severity floor: a critical-floor channel delivers nothing for a high
    // alert (and 'team' stays deduplicated).
    v.notification_channel_add(
        "quiet",
        &SecretString::from("https://q.example.com/h"),
        "critical",
    )
    .unwrap();
    let http = MockHttpClient::new(vec![
        MockHttpClient::json_response("{}"),
        MockHttpClient::json_response("{}"),
    ]);
    let delivered = v.deliver_notifications(&http).unwrap();
    assert_eq!(delivered, 0);

    // The delivery history records both the failure and the success —
    // channel names and outcomes only, never the URL.
    let history = v.notification_history(20).unwrap();
    assert!(history.iter().any(|e| e.detail.contains("FAILED")));
    assert!(history
        .iter()
        .any(|e| e.detail.contains("delivered") && e.detail.contains("channel=team")));
    assert!(
        history.iter().all(|e| !e.detail.contains("FAKE-token")),
        "history must never contain the webhook URL"
    );
}

#[test]
fn doc_watch_scheduling_and_history() {
    let (_dir, _paths, v) = new_vault();
    v.watch_docs("openai", "https://platform.openai.com/docs/changelog")
        .unwrap();
    // Never checked -> due.
    let due = api_tracker_core::docwatch::due_watches(v.connection(), 24).unwrap();
    assert_eq!(due.len(), 1);
    // Interval 0 disables scheduling.
    assert!(api_tracker_core::docwatch::due_watches(v.connection(), 0)
        .unwrap()
        .is_empty());

    let fetcher = api_tracker_core::docwatch::MockFetcher::with(
        "https://platform.openai.com/docs/changelog",
        vec![api_tracker_core::docwatch::FetchOutcome::Body {
            bytes: b"v1 content".to_vec(),
            etag: Some("etag-1".into()),
            last_modified: None,
        }],
    );
    let results = v.check_due_doc_watches(&fetcher).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, "first_capture");

    // Freshly checked -> no longer due; history recorded.
    let due = api_tracker_core::docwatch::due_watches(v.connection(), 24).unwrap();
    assert!(due.is_empty());
    let history = v.doc_watch_history(None, 10).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].outcome, "first_capture");

    // A change lands in history too.
    let fetcher = api_tracker_core::docwatch::MockFetcher::with(
        "https://platform.openai.com/docs/changelog",
        vec![api_tracker_core::docwatch::FetchOutcome::Body {
            bytes: b"v2 content".to_vec(),
            etag: Some("etag-2".into()),
            last_modified: None,
        }],
    );
    let (result, _) = v
        .check_doc_watch(&fetcher, "https://platform.openai.com/docs/changelog")
        .unwrap();
    assert_eq!(result, api_tracker_core::docwatch::CheckResult::Changed);
    let history = v.doc_watch_history(None, 10).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].outcome, "changed");
}

#[test]
fn monitor_cycle_records_status_and_offline_skips_network() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");

    // Nothing recorded before the first cycle.
    let st = v.monitor_status().unwrap();
    assert!(st.last_run_at.is_none());
    assert!(st.last_success_at.is_none());

    // Offline cycle: no transports, network phases skipped, status recorded.
    let report = v.run_monitor_cycle(None).unwrap();
    assert!(report.offline);
    assert_eq!(report.doc_checks, 0);
    assert_eq!(report.webhooks_delivered, 0);
    let st = v.monitor_status().unwrap();
    assert!(st.last_run_at.is_some());
    assert!(st.last_success_at.is_some());
    assert!(st.last_failure_at.is_none());
    assert!(st.last_error.is_empty());
    assert!(st.last_detail.contains("offline"), "{}", st.last_detail);
}

#[test]
fn suppressions_can_be_listed_and_removed() {
    let (_dir, _paths, v) = new_vault();
    v.add_suppression("k1", "manual", "src/a.env", "test fixture")
        .unwrap();
    let listed = v.list_suppressions().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].suppression_key, "k1");

    v.remove_suppression("k1").unwrap();
    assert!(v.list_suppressions().unwrap().is_empty());
    // Removing an unknown key errors instead of silently succeeding.
    assert!(v.remove_suppression("k1").is_err());
}

#[test]
fn process_sessions_list_with_pids_and_termination_is_guarded() {
    let (_dir, _paths, mut v) = new_vault();
    let project = add_project(&mut v, "app");

    let conn = v.connection();
    let s1 = api_tracker_core::inject::start_session(
        conn,
        &project.id,
        "npm test",
        &["OPENAI_API_KEY".into()],
    )
    .unwrap();
    // A real child process we control, so SIGTERM has a live target.
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    api_tracker_core::inject::set_session_pid(conn, &s1, child.id(), None).unwrap();

    let s2 =
        api_tracker_core::inject::start_session(conn, &project.id, "npm run dev", &[]).unwrap();
    api_tracker_core::inject::end_session(conn, &s2, Some(0)).unwrap();

    // Active-only filtering hides the ended session.
    let active = v.list_process_sessions(50, true).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, s1);
    assert_eq!(active[0].pid, Some(i64::from(child.id())));
    let all = v.list_process_sessions(50, false).unwrap();
    assert_eq!(all.len(), 2);
    // Session rows never contain values — only names.
    assert!(all.iter().all(|s| !s.injected_vars.contains("sk-")));

    // Termination refuses ended sessions and unknown ids.
    assert!(v.terminate_process_session(&s2).is_err());
    assert!(v.terminate_process_session("no-such-session").is_err());

    // Terminating the live session verifies the identity captured at
    // set_session_pid time and signals the recorded PID.
    let (id, pid, outcome) = v.terminate_process_session(&s1).unwrap();
    assert_eq!(id, s1);
    assert_eq!(pid, i64::from(child.id()));
    assert_eq!(
        outcome,
        api_tracker_core::inject::TerminationOutcome::Signalled,
        "SIGTERM to a live, identity-verified child must be accepted"
    );
    // The child actually dies (SIGTERM), proving the signal was real.
    let mut child = child;
    let status = child.wait().unwrap();
    assert!(!status.success(), "sleep must have been terminated");
}

#[test]
#[cfg(unix)]
fn run_monitor_sweeps_orphaned_observation_sessions() {
    // Regression (PR #13): sweep_orphaned_sessions had no caller, so a crashed
    // launcher left the session 'running' forever. It is now wired into
    // run_monitor and must reconcile such a row to interrupted/launcher_gone.
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let sid = v
        .observe_open_session(
            "app",
            api_tracker_core::runtime::model::ObservationMode::Metadata,
            "cli_run",
            "node app.js",
            &[],
        )
        .unwrap();
    // A guaranteed-dead child pid: spawn a process, then reap it.
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg("exit 0")
        .spawn()
        .unwrap();
    let dead_pid = child.id() as i64;
    child.wait().unwrap();
    v.connection()
        .execute(
            "UPDATE observation_sessions SET pid = ?1, status = 'running' WHERE id = ?2",
            rusqlite::params![dead_pid, sid],
        )
        .unwrap();

    v.run_monitor().unwrap();

    let status: String = v
        .connection()
        .query_row(
            "SELECT status FROM observation_sessions WHERE id = ?1",
            [&sid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "interrupted", "an orphaned session must be swept");
}

#[test]
fn observe_injected_resolves_reference_to_the_root_credentials_version() {
    // Regression (PR #13): observe_injected read value_version from the injected
    // row. For a reference credential that is always the schema default 1, even
    // after the ROOT rotates — so old-version/revoked attribution was silently
    // inert for shared credentials. It must resolve to the value-bearing root.
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    add_project(&mut v, "app2");
    let (root, _) = add_key(
        &mut v,
        "app",
        "openai-main",
        FAKE_KEY,
        Environment::Production,
    );
    let reference = v
        .add_credential_reference(api_tracker_core::vault::AddReference {
            project: "app2".to_owned(),
            source: root.id.clone(),
            name: "openai-ref".to_owned(),
            environment: Environment::Production,
            docs_url: String::new(),
            notes: String::new(),
        })
        .expect("add reference");

    // Simulate a rotation of the ROOT: only the root's value_version advances.
    v.connection()
        .execute(
            "UPDATE credentials SET value_version = 2 WHERE id = ?1",
            [&root.id],
        )
        .unwrap();

    let injected = v
        .observe_injected(std::slice::from_ref(&reference.id))
        .unwrap();
    assert_eq!(injected.len(), 1);
    // Resolved to the root credential and its live version, not the reference's.
    assert_eq!(injected[0].credential_id, root.id);
    assert_eq!(
        injected[0].launch_version, 2,
        "reference must resolve to the ROOT's value_version, not the default 1"
    );
}
