//! `.env` link-writer tests (TEST_PLAN §10): lossless rewriting, marker
//! ownership, NO_PROXY handling, prior-state recording, exact restore,
//! user-edit preservation, idempotency, warnings, and scope policy.

use api_tracker_core::db;
use api_tracker_gateway::envlink::{self, LinkRequest, LinkWarning, RestoreOutcome};
use api_tracker_gateway::{routes, store};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// A deterministic restore-record key for tests.
///
/// Fixed rather than random so a single test can seal on `apply_link` and
/// open on `unlink` and get the same key both times — and unmistakably fake,
/// like every other credential in this suite.
fn restore_crypto() -> api_tracker_core::envrestore::RestoreCrypto {
    api_tracker_core::envrestore::RestoreCrypto::new(
        "vault-test-0001".to_string(),
        api_tracker_core::secret::SecretBytes::new(vec![0x2au8; 32]),
    )
}

/// The raw `prior_env_json` column, exactly as it sits in the database.
///
/// Every RA-006 assertion reads THIS rather than the in-memory plan: the
/// plan's `prior` is `#[serde(skip)]` and never persisted, so asserting on
/// it proves nothing about what a backup, a disk image, or another process
/// running as the user can see.
fn stored_prior(conn: &Connection) -> String {
    conn.query_row(
        "SELECT prior_env_json FROM gateway_project_links WHERE project_id = 'p1'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

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
    envlink::apply_link(conn, Some(&restore_crypto()), req, &plan).unwrap();
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
    envlink::apply_link(&conn, Some(&restore_crypto()), &req, &replan).unwrap();
    assert_eq!(std::fs::read_to_string(&env).unwrap(), first);

    // The recorded prior still holds the ORIGINAL pre-Tethra value.
    let link = routes::find_project_link(&conn, "p1", "openai")
        .unwrap()
        .unwrap();
    let recorded = link.prior_env_json.as_deref().unwrap();
    assert!(
        !recorded.contains("corp-proxy.example"),
        "the recorded prior must be sealed, not plaintext: {recorded}"
    );
    // Prove it is the ORIGINAL pre-Tethra value by restoring it: reading the
    // ciphertext proves only that something is there.
    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    assert!(
        std::fs::read_to_string(&env)
            .unwrap()
            .contains("OPENAI_BASE_URL=https://corp-proxy.example/v1"),
        "a re-link must not overwrite the original prior with Tethra's own write"
    );
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

    let report = envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
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

    let report = envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
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

    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
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
    envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap();

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

// Runs git and creates a symlink-free repo; the git-tracked/proxy warning
// wiring is platform-independent logic, exercised on macOS + Linux. Skipped
// on Windows, where git config/behavior differs and Windows is compile-only
// for this surface.
#[cfg(unix)]
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

#[cfg(unix)]
#[test]
fn symlinked_env_files_are_refused_outright() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let target = dir.path().join("real.env");
    std::fs::write(&target, "").unwrap();
    let link = dir.path().join(".env");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let e = envlink::plan_link(&conn, &request(&link, None)).unwrap_err();
    assert!(e.to_string().contains("symlink"), "{e}");
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

    let report = envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
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
    envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap();
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
    let e = envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap_err();
    assert!(e.to_string().contains("changed since the preview"), "{e}");
}

/// The digest has to bind the previewed INPUT, not just the planned output.
///
/// The rewrite is not injective: the writer sets the same gateway URL
/// whatever the variable held before, so a user who changed the value between
/// preview and apply produced a byte-identical planned output. Hashing only
/// that output made the documented refusal ("any file changed") silently
/// untrue for exactly the edit a user is most likely to make — the value was
/// overwritten without ever appearing in a diff (ZFT-023).
#[test]
fn apply_refuses_a_value_edit_the_rewrite_would_have_flattened() {
    let dir = tempfile::tempdir().unwrap();
    let conn = linkable(dir.path());
    let env = dir.path().join(".env");
    let previewed = "OPENAI_BASE_URL=https://old.internal-host.net/v1\n";
    std::fs::write(&env, previewed).unwrap();

    let req = request(&env, None);
    let plan = envlink::plan_link(&conn, &req).unwrap();

    // The user repoints the variable after seeing the preview.
    let edited = "OPENAI_BASE_URL=https://new.internal-host.net/v1\n";
    std::fs::write(&env, edited).unwrap();

    // Precondition, and the whole reason an output-only digest failed here:
    // both inputs plan to the SAME bytes.
    let after_edit = envlink::plan_link_with_slug(&conn, &req, &plan.link_slug).unwrap();
    assert_eq!(
        after_edit.files[0].new_content, plan.files[0].new_content,
        "precondition: the rewrite flattens both prior values to one output"
    );
    assert_ne!(
        after_edit.digest, plan.digest,
        "the digest must distinguish the two previews"
    );

    let e = envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap_err();
    assert!(e.to_string().contains("changed since the preview"), "{e}");
    assert_eq!(
        std::fs::read_to_string(&env).unwrap(),
        edited,
        "a refused apply must leave the user's edit exactly as it was"
    );
    assert!(
        routes::find_project_link(&conn, "p1", "openai")
            .unwrap()
            .is_none(),
        "and must not have recorded a link for a plan it never applied"
    );
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

    let report = envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    assert!(report.complete, "a missing file is not a retryable failure");
    assert!(report
        .outcomes
        .iter()
        .any(|o| matches!(o, RestoreOutcome::FileMissing { .. })));
    assert!(routes::find_project_link(&conn, "p1", "openai")
        .unwrap()
        .is_none());
}

/// A prior value that does not look like non-secret configuration is NOT
/// written into the plaintext `prior_env_json` column, and the user is told.
///
/// `--var` accepts any variable name, so the "base URLs and proxy lists are
/// non-secret configuration" assumption that makes exact restore safe does
/// not hold for an arbitrary override.
#[test]
fn a_secret_looking_prior_value_is_never_stored_in_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(&env, "OPENAI_API_KEY=sk-proj-CANARYSECRET000000000000\n").unwrap();
    let conn = linkable(dir.path());
    let mut req = request(&env, Some(dir.path().to_path_buf()));
    req.var_override = Some("OPENAI_API_KEY".into());

    let plan = envlink::plan_link(&conn, &req).unwrap();
    assert!(
        !plan.files[0].diff.contains("CANARYSECRET"),
        "the consent diff must not print the prior secret: {}",
        plan.files[0].diff
    );
    envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap();

    // The property that matters: what is DURABLE.
    let recorded = stored_prior(&conn);
    assert!(
        !recorded.contains("CANARYSECRET"),
        "the prior value must not reach the database in the clear: {recorded}"
    );
    assert!(
        recorded.contains("\"sealed\""),
        "it must be recorded, sealed - withholding it would cost the user their \
         undo for no security gain: {recorded}"
    );
    assert!(
        !recorded.contains("\"prior_withheld\":true"),
        "and it must NOT be withheld: encryption is what protects it now, not \
         a shape predicate: {recorded}"
    );

    // And undo still works, which is the capability the old design lost.
    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    assert!(
        std::fs::read_to_string(&env)
            .unwrap()
            .contains("OPENAI_API_KEY=sk-proj-CANARYSECRET000000000000"),
        "a sealed prior value must restore exactly"
    );
}

/// The same protection for a base URL that carries embedded credentials —
/// this one needs no `--var` at all.
#[test]
fn a_base_url_with_embedded_credentials_is_sealed_not_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    let original = "OPENAI_BASE_URL=https://user:CANARYPASSWORD@proxy.internal-host.net/v1\n";
    std::fs::write(&env, original).unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));
    let plan = envlink::plan_link(&conn, &req).unwrap();
    assert!(!plan.files[0].diff.contains("CANARYPASSWORD"));
    envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap();

    let recorded = stored_prior(&conn);
    assert!(
        !recorded.contains("CANARYPASSWORD"),
        "userinfo in a base URL must not reach the database in the clear: {recorded}"
    );
    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    assert!(
        std::fs::read_to_string(&env)
            .unwrap()
            .contains("CANARYPASSWORD"),
        "and it must still restore exactly"
    );
}

/// Rows an EARLIER build wrote still hold what the tightened rule now
/// refuses, and nothing else ever rewrites them — so the fix to the writer
/// alone leaves the recovered value sitting in `vault.db` (ZFT-016).
#[test]
fn a_legacy_plaintext_restore_record_is_resealed_not_left_in_the_clear() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(&env, "OPENAI_BASE_URL=https://api.openai.com/v1\n").unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));
    plan_and_apply(&conn, &req);

    // Exactly what a pre-fix build stored: a v1 document with the raw value.
    // `written` has to be the value actually in the file, or restore reads the
    // line as a user edit and correctly leaves it alone.
    const LEGACY: &str = "https://api.internal-host.net/v1?api_key=CANARYLEGACY0123456789";
    let written = std::fs::read_to_string(&env)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("OPENAI_BASE_URL=").map(str::to_string))
        .expect("the link wrote a base URL");
    let v1 = format!(
        r#"{{"v":1,"port":49723,"files":[{{"path":{:?},"existed":true,"vars":[{{"key":"OPENAI_BASE_URL","prior":{LEGACY:?},"prior_withheld":false,"written":{written:?}}}]}}]}}"#,
        env.display().to_string()
    );
    conn.execute(
        "UPDATE gateway_project_links SET prior_env_json = ?1 WHERE project_id = 'p1'",
        [&v1],
    )
    .unwrap();
    assert!(
        stored_prior(&conn).contains("CANARYLEGACY"),
        "precondition: the legacy value really is in the column"
    );

    assert_eq!(
        envlink::scrub_stored_prior_env(&conn, Some(&restore_crypto())).unwrap(),
        1,
        "the row must be rewritten"
    );
    let after = stored_prior(&conn);
    assert!(
        !after.contains("CANARYLEGACY"),
        "the legacy value must be gone from the plaintext column: {after}"
    );
    assert!(
        after.contains("\"sealed\""),
        "it must be RE-SEALED, not merely deleted - deleting it would silently \
         take away an upgrading user's undo: {after}"
    );
    assert!(
        after.contains("\"v\":2"),
        "and the record must be upgraded to the sealed version: {after}"
    );
    assert_eq!(
        envlink::scrub_stored_prior_env(&conn, Some(&restore_crypto())).unwrap(),
        0,
        "scrubbing is idempotent"
    );

    // The re-sealed value still restores.
    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    assert!(
        std::fs::read_to_string(&env)
            .unwrap()
            .contains("CANARYLEGACY"),
        "a re-sealed legacy value must still restore exactly"
    );
}

/// With no key, a legacy plaintext record is REDACTED rather than carried
/// forward — and the marker is not set, so the real re-seal still happens on
/// the next unlocked command.
#[test]
fn without_a_key_a_legacy_record_is_never_carried_forward_in_the_clear() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(&env, "OPENAI_BASE_URL=https://api.openai.com/v1\n").unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));
    plan_and_apply(&conn, &req);
    let written = std::fs::read_to_string(&env)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("OPENAI_BASE_URL=").map(str::to_string))
        .expect("the link wrote a base URL");
    let v1 = format!(
        r#"{{"v":1,"port":49723,"files":[{{"path":{:?},"existed":true,"vars":[{{"key":"OPENAI_BASE_URL","prior":"https://x/CANARYNOKEY","prior_withheld":false,"written":{written:?}}}]}}]}}"#,
        env.display().to_string()
    );
    conn.execute(
        "UPDATE gateway_project_links SET prior_env_json = ?1 WHERE project_id = 'p1'",
        [&v1],
    )
    .unwrap();

    // The keyless one-time scrub must be a NO-OP: redacting here would
    // destroy the undo a later, unlocked call can still preserve.
    assert_eq!(
        envlink::scrub_stored_prior_env_once(&conn, None).unwrap(),
        0,
        "a keyless scrub must not touch the record"
    );
    assert!(stored_prior(&conn).contains("CANARYNOKEY"));

    // A direct keyless scrub redacts rather than re-committing plaintext.
    assert_eq!(envlink::scrub_stored_prior_env(&conn, None).unwrap(), 1);
    let after = stored_prior(&conn);
    assert!(!after.contains("CANARYNOKEY"), "{after}");
    assert!(
        after.contains("\"prior_withheld\":true"),
        "and the loss of automatic restore must be recorded honestly: {after}"
    );
}

/// A base URL that carries its key in a QUERY STRING is never written to the
/// plaintext restore record, and the undo that this costs is degraded
/// HONESTLY rather than guessed at (ZFT-016).
///
/// The old allowlist inspected only the authority, so everything after the
/// host went into `vault.db` verbatim. There is no way to tell `?version=2`
/// from `?api_key=…`, so nothing with a query is recorded — which means unlink
/// must say so and leave the line alone, not delete it and not invent a value.
#[test]
fn a_query_bearing_base_url_is_sealed_and_restores_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    let original =
        "OPENAI_BASE_URL=https://api.internal-host.net/v1?api_key=CANARYQUERYKEY0123456789\n";
    std::fs::write(&env, original).unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));

    let plan = envlink::plan_link(&conn, &req).unwrap();
    assert!(
        plan.warnings.iter().any(
            |w| matches!(w, LinkWarning::ExistingValueRecorded { key, .. } if key == "OPENAI_BASE_URL")
        ),
        "the user must be told their existing value is being recorded: {:?}",
        plan.warnings
    );
    envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap();

    let recorded = stored_prior(&conn);
    assert!(
        !recorded.contains("CANARYQUERYKEY"),
        "a key carried in a query string must not reach the database in the \
         clear - the old allowlist inspected only the authority: {recorded}"
    );

    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    let after = std::fs::read_to_string(&env).unwrap();
    assert_eq!(
        after, original,
        "the file must come back byte-for-byte; the old design could only \
         leave the gateway line in place and apologise"
    );
}

/// An ordinary base URL still records and restores exactly — the withholding
/// rule must not break the normal path.
#[test]
fn an_ordinary_prior_base_url_is_still_recorded_and_restored() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(&env, "OPENAI_BASE_URL=https://api.openai.com/v1\n").unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));
    plan_and_apply(&conn, &req);
    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    assert!(std::fs::read_to_string(&env)
        .unwrap()
        .contains("OPENAI_BASE_URL=https://api.openai.com/v1"));
}

/// Duplicate definitions restore to their OWN prior values. `EnvDocument::get`
/// is last-wins but `set` rewrites every occurrence, so recording a single
/// value turned `KEY=a` … `KEY=b` into `KEY=b` … `KEY=b` on restore.
#[test]
fn duplicate_definitions_each_restore_to_their_own_prior_value() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(
        &env,
        "OPENAI_BASE_URL=https://first.example.com/v1\nOTHER=x\n\
         OPENAI_BASE_URL=https://second.example.com/v1\n",
    )
    .unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));
    plan_and_apply(&conn, &req);
    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();

    let restored = std::fs::read_to_string(&env).unwrap();
    assert!(
        restored.contains("OPENAI_BASE_URL=https://first.example.com/v1"),
        "the FIRST occurrence's own value must come back: {restored}"
    );
    assert!(
        restored.contains("OPENAI_BASE_URL=https://second.example.com/v1"),
        "and so must the second's: {restored}"
    );
}

/// A `.env` the link CREATED is removed on restore when nothing else was
/// added to it — `PriorFile.existed` promised that and nothing read it.
#[test]
fn a_created_env_file_is_removed_on_restore() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));
    plan_and_apply(&conn, &req);
    assert!(env.exists(), "precondition: the link created the file");

    let report = envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    assert!(
        !env.exists(),
        "a file the link created, with nothing else in it, must not be left behind"
    );
    assert!(report
        .outcomes
        .iter()
        .any(|o| matches!(o, RestoreOutcome::CreatedFileRemoved { .. })));
}

/// ...but a created file the USER later added to is kept.
#[test]
fn a_created_env_file_the_user_added_to_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));
    plan_and_apply(&conn, &req);
    let mut content = std::fs::read_to_string(&env).unwrap();
    content.push_str("MY_OWN_SETTING=1\n");
    std::fs::write(&env, content).unwrap();

    envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    assert!(env.exists(), "the user's own content must survive");
    assert!(std::fs::read_to_string(&env)
        .unwrap()
        .contains("MY_OWN_SETTING=1"));
}

/// A restore record from a NEWER build is refused rather than half-applied.
#[test]
fn a_future_version_restore_record_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(&env, "OPENAI_BASE_URL=https://api.openai.com/v1\n").unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));
    plan_and_apply(&conn, &req);
    conn.execute(
        "UPDATE gateway_project_links
         SET prior_env_json = replace(prior_env_json, \'\"v\":2\', \'\"v\":99\')",
        [],
    )
    .unwrap();

    let err = envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap_err();
    let text = format!("{err:?}");
    assert!(
        text.contains("99"),
        "must name the version it found: {text}"
    );
    assert!(
        std::fs::read_to_string(&env).unwrap().contains("127.0.0.1"),
        "the file must be left untouched for a newer build to restore"
    );
}

/// A file that became a SYMLINK after linking is not silently replaced. Link
/// time refuses a symlink because an atomic rename replaces the link rather
/// than its target; restore must hold the same line.
#[cfg(unix)]
#[test]
fn restore_refuses_to_replace_a_file_that_became_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    std::fs::write(&env, "OPENAI_BASE_URL=https://api.openai.com/v1\n").unwrap();
    let conn = linkable(dir.path());
    let req = request(&env, Some(dir.path().to_path_buf()));
    plan_and_apply(&conn, &req);

    // The user migrates to a shared dotfile setup after linking.
    let real = dir.path().join("shared.env");
    std::fs::rename(&env, &real).unwrap();
    std::os::unix::fs::symlink(&real, &env).unwrap();

    let report = envlink::unlink(&conn, Some(&restore_crypto()), "p1", "openai").unwrap();
    assert!(
        !report.complete,
        "a refused restore must keep the link row so it can be retried"
    );
    assert!(
        std::fs::symlink_metadata(&env)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the symlink must survive"
    );
    assert!(report.outcomes.iter().any(|o| matches!(
        o,
        RestoreOutcome::Failed { error, .. } if error.contains("symlink")
    )));
}
