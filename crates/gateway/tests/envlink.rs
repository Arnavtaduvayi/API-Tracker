//! `.env` link-writer tests (TEST_PLAN §10): lossless rewriting, marker
//! ownership, NO_PROXY handling, prior-state recording, exact restore,
//! user-edit preservation, idempotency, warnings, and scope policy.

use api_tracker_core::db;
use api_tracker_gateway::envlink::{self, LinkRequest, LinkWarning, RestoreOutcome};
use api_tracker_gateway::{routes, store};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

fn migrated(path: &std::path::Path) -> Connection {
    let mut conn = db::open(path).unwrap();
    db::migrate(&mut conn).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('vault_id', 'vault-test-0001')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO projects (id, name, description, notes, environments, archived,
             created_at, updated_at, wrapped_project_key, key_wrap_mode)
         VALUES ('p1', 'app', '', '', 'development', 0,
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', x'00', 'vault')",
        [],
    )
    .unwrap();
    conn
}

/// A vault with an openai route and a persisted port, ready to link.
fn linkable(dir: &Path) -> Connection {
    let conn = migrated(&dir.join("vault.db"));
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    let mut config = store::load_config(&conn).unwrap();
    config.port = Some(49723);
    store::save_config(&conn, &config).unwrap();
    conn
}

fn request(env_file: &Path, project_dir: Option<PathBuf>) -> LinkRequest {
    LinkRequest {
        project_id: "p1".into(),
        project_name: "app".into(),
        route_prefix: "openai".into(),
        project_dir,
        files: vec![env_file.to_path_buf()],
        var_override: None,
    }
}

fn plan_and_apply(conn: &Connection, req: &LinkRequest) -> envlink::LinkPlan {
    let plan = envlink::plan_link(conn, req).unwrap();
    envlink::apply_link(conn, req, &plan).unwrap();
    plan
}

#[test]
fn linking_writes_marked_vars_and_no_proxy_preserving_everything_else() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let env = dir.path().join("proj").join(".env");
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    std::fs::write(
        &env,
        "# my settings\n\nOPENAI_API_KEY='sk-test-FAKE-123'  # keep\nDB=x\n",
    )
    .unwrap();

    let req = request(&env, None);
    let plan = plan_and_apply(&conn, &req);

    let written = std::fs::read_to_string(&env).unwrap();
    // Everything the user had survives byte-for-byte.
    assert!(
        written.starts_with("# my settings\n\nOPENAI_API_KEY='sk-test-FAKE-123'  # keep\nDB=x\n")
    );
    // Both declared OpenAI variables point at the link-scoped URL, each
    // under its own marker, plus NO_PROXY.
    let url = format!("http://127.0.0.1:49723/p/{}/openai/v1", plan.link_slug);
    assert!(written.contains(&format!("OPENAI_BASE_URL={url}")));
    assert!(written.contains(&format!("OPENAI_API_BASE={url}")));
    assert!(written.contains("NO_PROXY=127.0.0.1,localhost,::1"));
    assert!(written.contains("# tethra-gateway route: openai (project: app)"));

    // The plan's diff shows the gateway lines UNMASKED and the user's
    // secret masked (D9).
    let file_plan = &plan.files[0];
    assert!(file_plan.diff.contains(&url), "{}", file_plan.diff);
    assert!(
        !file_plan.diff.contains("sk-test-FAKE-123"),
        "{}",
        file_plan.diff
    );

    // The link row records the file and the restore state.
    let link = routes::find_project_link(&conn, "p1", "openai")
        .unwrap()
        .unwrap();
    assert_eq!(link.env_path.as_deref(), Some(env.to_str().unwrap()));
    let prior: envlink::PriorEnv =
        serde_json::from_str(link.prior_env_json.as_deref().unwrap()).unwrap();
    assert_eq!(prior.port, 49723);
    assert_eq!(prior.files.len(), 1);
    let base = prior.files[0]
        .vars
        .iter()
        .find(|v| v.key == "OPENAI_BASE_URL")
        .unwrap();
    assert_eq!(base.prior, None, "the variable did not exist before");
}

#[test]
fn relinking_is_idempotent_and_preserves_the_original_prior() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let env = dir.path().join(".env");
    std::fs::write(&env, "OPENAI_BASE_URL=https://corp-proxy.example/v1\n").unwrap();

    let req = request(&env, None);
    plan_and_apply(&conn, &req);
    let first = std::fs::read_to_string(&env).unwrap();

    // Re-linking produces a no-op plan (same slug, same content).
    let replan = envlink::plan_link(&conn, &req).unwrap();
    assert!(replan.existing_link);
    assert!(!replan.files[0].changed, "idempotent re-link");
    envlink::apply_link(&conn, &req, &replan).unwrap();
    assert_eq!(std::fs::read_to_string(&env).unwrap(), first);

    // The recorded prior still holds the ORIGINAL pre-Tethra value.
    let link = routes::find_project_link(&conn, "p1", "openai")
        .unwrap()
        .unwrap();
    let prior: envlink::PriorEnv =
        serde_json::from_str(link.prior_env_json.as_deref().unwrap()).unwrap();
    let base = prior.files[0]
        .vars
        .iter()
        .find(|v| v.key == "OPENAI_BASE_URL")
        .unwrap();
    assert_eq!(base.prior.as_deref(), Some("https://corp-proxy.example/v1"));
}

#[test]
fn unlink_restores_prior_values_removes_created_lines_and_the_row() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let env = dir.path().join(".env");
    let original = "# app config\nOPENAI_BASE_URL=https://corp-proxy.example/v1\nKEY=v\n";
    std::fs::write(&env, original).unwrap();

    let req = request(&env, None);
    plan_and_apply(&conn, &req);
    assert_ne!(std::fs::read_to_string(&env).unwrap(), original);

    let report = envlink::unlink(&conn, "p1", "openai").unwrap();
    assert!(report.complete);
    let restored = std::fs::read_to_string(&env).unwrap();
    assert_eq!(
        restored, original,
        "unlink must restore the exact prior file"
    );
    assert!(routes::find_project_link(&conn, "p1", "openai")
        .unwrap()
        .is_none());
    assert!(report
        .outcomes
        .iter()
        .any(|o| matches!(o, RestoreOutcome::Restored { key, .. } if key == "OPENAI_BASE_URL")));
}

#[test]
fn unlink_never_overwrites_a_user_edit_made_after_linking() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let env = dir.path().join(".env");
    std::fs::write(&env, "").unwrap();

    let req = request(&env, None);
    plan_and_apply(&conn, &req);

    // The user replaces the gateway URL with their own after linking.
    let mut content = std::fs::read_to_string(&env).unwrap();
    content = content.replace(
        &format!(
            "OPENAI_BASE_URL=http://127.0.0.1:49723/p/{}/openai/v1",
            routes::find_project_link(&conn, "p1", "openai")
                .unwrap()
                .unwrap()
                .link_slug
        ),
        "OPENAI_BASE_URL=https://my-own-choice.example/v1",
    );
    std::fs::write(&env, &content).unwrap();

    let report = envlink::unlink(&conn, "p1", "openai").unwrap();
    assert!(report.complete);
    assert!(report.outcomes.iter().any(
        |o| matches!(o, RestoreOutcome::LeftUserEdit { key, .. } if key == "OPENAI_BASE_URL")
    ));
    assert!(std::fs::read_to_string(&env)
        .unwrap()
        .contains("OPENAI_BASE_URL=https://my-own-choice.example/v1"));
}

#[test]
fn existing_no_proxy_is_extended_and_restored_not_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let env = dir.path().join(".env");
    std::fs::write(&env, "no_proxy=internal.example\n").unwrap();

    let req = request(&env, None);
    plan_and_apply(&conn, &req);
    let written = std::fs::read_to_string(&env).unwrap();
    assert!(
        written.contains("no_proxy=internal.example,127.0.0.1,localhost,::1"),
        "existing spelling extended in place: {written}"
    );
    assert!(
        !written.contains("NO_PROXY=127.0.0.1"),
        "no duplicate uppercase variable when a lowercase one exists: {written}"
    );

    envlink::unlink(&conn, "p1", "openai").unwrap();
    assert!(std::fs::read_to_string(&env)
        .unwrap()
        .contains("no_proxy=internal.example\n"));
}

#[test]
fn crlf_duplicates_quoting_and_comments_survive_the_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let env = dir.path().join(".env");
    // CRLF file with a duplicate key and quoting to preserve.
    std::fs::write(
        &env,
        "A=\"quoted value\"\r\n# comment stays\r\nOPENAI_BASE_URL=one\r\nOPENAI_BASE_URL=two\r\n",
    )
    .unwrap();

    let req = request(&env, None);
    let plan = envlink::plan_link(&conn, &req).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| matches!(w, LinkWarning::DuplicateKey { key, .. } if key == "OPENAI_BASE_URL")));
    envlink::apply_link(&conn, &req, &plan).unwrap();

    let written = std::fs::read_to_string(&env).unwrap();
    assert!(written.contains("A=\"quoted value\"\r\n"));
    assert!(written.contains("# comment stays\r\n"));
    // EVERY duplicate occurrence is repointed (dotenv loaders read the last).
    let url = format!("http://127.0.0.1:49723/p/{}/openai/v1", plan.link_slug);
    assert_eq!(
        written.matches(&format!("OPENAI_BASE_URL={url}")).count(),
        2
    );
    assert!(written.contains("\r\n"), "CRLF endings preserved");
}

#[test]
fn warnings_cover_git_tracked_templates_ci_paths_scope_and_proxies() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());

    // A git repo with a TRACKED .env.
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&repo)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .unwrap()
    };
    run(&["init", "-q"]);
    std::fs::write(repo.join(".env"), "HTTP_PROXY=http://proxy.corp:3128\n").unwrap();
    run(&["add", ".env"]);
    run(&["commit", "-qm", "add env"]);

    let req = request(&repo.join(".env"), Some(repo.clone()));
    let plan = envlink::plan_link(&conn, &req).unwrap();
    assert!(
        plan.warnings
            .iter()
            .any(|w| matches!(w, LinkWarning::GitTracked { .. })),
        "{:?}",
        plan.warnings
    );
    assert!(plan.warnings.iter().any(
        |w| matches!(w, LinkWarning::ProxyVariablePresent { key, .. } if key == "HTTP_PROXY")
    ));

    // Template file.
    let tpl = dir.path().join(".env.example");
    std::fs::write(&tpl, "").unwrap();
    let plan = envlink::plan_link(&conn, &request(&tpl, None)).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| matches!(w, LinkWarning::TemplateFile { .. })));

    // CI path.
    let ci = dir.path().join(".github").join("workflows").join(".env");
    std::fs::create_dir_all(ci.parent().unwrap()).unwrap();
    std::fs::write(&ci, "").unwrap();
    let plan = envlink::plan_link(&conn, &request(&ci, None)).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| matches!(w, LinkWarning::SharedConfiguration { .. })));

    // Outside the selected project directory.
    let outside = dir.path().join("elsewhere.env");
    std::fs::write(&outside, "").unwrap();
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let plan = envlink::plan_link(&conn, &request(&outside, Some(proj))).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| matches!(w, LinkWarning::OutsideProject { .. })));
}

#[test]
fn symlinked_env_files_are_refused_outright() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let target = dir.path().join("real.env");
    std::fs::write(&target, "").unwrap();
    let link = dir.path().join(".env");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = envlink::plan_link(&conn, &request(&link, None)).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
    }
}

#[test]
fn multiple_files_link_and_restore_together() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let a = dir.path().join(".env");
    let b = dir.path().join(".env.development");
    std::fs::write(&a, "A=1\n").unwrap();
    std::fs::write(&b, "B=2\n").unwrap();

    let mut req = request(&a, None);
    req.files = vec![a.clone(), b.clone()];
    let plan = plan_and_apply(&conn, &req);
    assert_eq!(plan.files.len(), 2);
    for f in [&a, &b] {
        assert!(std::fs::read_to_string(f)
            .unwrap()
            .contains("OPENAI_BASE_URL=http://127.0.0.1:49723/p/"));
    }

    let report = envlink::unlink(&conn, "p1", "openai").unwrap();
    assert!(report.complete);
    assert_eq!(std::fs::read_to_string(&a).unwrap(), "A=1\n");
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "B=2\n");
}

#[test]
fn a_missing_default_env_is_created_and_a_missing_port_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();

    let req = LinkRequest {
        project_id: "p1".into(),
        project_name: "app".into(),
        route_prefix: "openai".into(),
        project_dir: Some(proj.clone()),
        files: vec![],
        var_override: None,
    };
    let plan = envlink::plan_link(&conn, &req).unwrap();
    assert!(!plan.files[0].exists);
    envlink::apply_link(&conn, &req, &plan).unwrap();
    assert!(proj.join(".env").exists());

    // Without a persisted port there is no stable URL to write.
    let dir2 = tempfile::tempdir().unwrap();
    let conn2 = migrated(&dir2.path().join("vault.db"));
    routes::add_manifest_route(&conn2, "openai", "openai").unwrap();
    let env2 = dir2.path().join(".env");
    std::fs::write(&env2, "").unwrap();
    let e = envlink::plan_link(&conn2, &request(&env2, None)).unwrap_err();
    assert!(e.to_string().contains("port"), "{e}");
}

#[test]
fn apply_refuses_when_the_file_changed_after_the_preview() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let env = dir.path().join(".env");
    std::fs::write(&env, "A=1\n").unwrap();

    let req = request(&env, None);
    let plan = envlink::plan_link(&conn, &req).unwrap();
    // The file changes between preview and apply.
    std::fs::write(&env, "A=1\nB=2\n").unwrap();
    let e = envlink::apply_link(&conn, &req, &plan).unwrap_err();
    assert!(e.to_string().contains("changed since the preview"), "{e}");
}

#[test]
fn unsupported_provider_requires_an_explicit_variable_name() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    // github declares no [gateway] section at all; a custom route for it
    // can exist, but linking needs an explicit variable.
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, custom_origin,
             custom_origin_port, custom_origin_mac, custom_origin_consent_at, created_at, updated_at)
         VALUES ('gh', 'github', 1, 'api.github.com', 443, x'00', '2026-01-01T00:00:00Z',
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    let mut config = store::load_config(&conn).unwrap();
    config.port = Some(49723);
    store::save_config(&conn, &config).unwrap();

    let env = dir.path().join(".env");
    std::fs::write(&env, "").unwrap();
    let mut req = request(&env, None);
    req.route_prefix = "gh".into();
    let e = envlink::plan_link(&conn, &req).unwrap_err();
    assert!(e.to_string().contains("variable"), "{e}");

    req.var_override = Some("GITHUB_API_URL".into());
    let plan = envlink::plan_link(&conn, &req).unwrap();
    assert_eq!(plan.vars, vec!["GITHUB_API_URL"]);
    // No base_path declared: the URL ends at the route prefix.
    assert!(plan.base_url.ends_with("/gh"), "{}", plan.base_url);
}

#[test]
fn supabase_declares_custom_only_env_metadata() {
    // The manifest change: origins empty (per-project hosts), env metadata
    // present, and manifest-route registration refused with a custom-origin
    // hint (KNOWN_CONFLICTS C11).
    let m = api_tracker_core::providers::find("supabase").unwrap();
    let gw = m.gateway.as_ref().expect("supabase [gateway] section");
    assert!(gw.origins.is_empty());
    assert_eq!(gw.env_vars, vec!["SUPABASE_URL"]);

    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    match routes::add_manifest_route(&conn, "supabase", "supabase") {
        Err(api_tracker_core::error::CoreError::Unsupported { hint, .. }) => {
            assert!(hint.contains("custom"), "{hint}");
        }
        other => panic!("custom-only providers must refuse manifest routes, got {other:?}"),
    }
}

#[test]
fn unlink_reports_missing_files_and_still_completes() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let env = dir.path().join(".env");
    std::fs::write(&env, "").unwrap();

    let req = request(&env, None);
    plan_and_apply(&conn, &req);
    std::fs::remove_file(&env).unwrap();

    let report = envlink::unlink(&conn, "p1", "openai").unwrap();
    assert!(report.complete, "a missing file is not a retryable failure");
    assert!(report
        .outcomes
        .iter()
        .any(|o| matches!(o, RestoreOutcome::FileMissing { .. })));
    assert!(routes::find_project_link(&conn, "p1", "openai")
        .unwrap()
        .is_none());
}
