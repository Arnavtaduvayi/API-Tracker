//! Detection fusion rules (AUTOMATIC_PROVIDER_DETECTION.md §3), pinned
//! per fixture. Values never appear in any serialized detection.

mod common;

use api_tracker_tracking::detect::{
    detect, Configurability, DetectionConfidence, DetectionInput, UnsupportedReason,
};
use common::*;
use tempfile::TempDir;

fn run(
    dir: &TempDir,
    conn: &rusqlite::Connection,
) -> api_tracker_tracking::detect::ProjectDetection {
    detect(
        conn,
        &DetectionInput {
            folder: dir.path(),
            project_id: None,
        },
    )
    .unwrap()
}

#[test]
fn key_plus_sdk_is_confirmed_and_automatic() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let detection = run(&dir, &conn);
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    assert_eq!(openai.confidence, DetectionConfidence::Confirmed);
    assert_eq!(openai.configurability, Configurability::Automatic);
    assert!(openai.target_env_files.contains(&".env".to_string()));
}

#[test]
fn key_alone_is_likely_and_sdk_alone_is_likely() {
    let (_db, conn) = test_conn();
    // Key alone (no SDK): anthropic key only.
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[(".env", &format!("ANTHROPIC_API_KEY={FAKE_ANTHROPIC_KEY}\n"))],
    );
    let detection = run(&dir, &conn);
    let anthropic = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "anthropic")
        .expect("anthropic detected");
    assert_eq!(anthropic.confidence, DetectionConfidence::Likely);

    // SDK alone (no key).
    let dir2 = TempDir::new().unwrap();
    write_project(
        dir2.path(),
        &[(
            "package.json",
            r#"{ "dependencies": { "openai": "^4.0.0" } }"#,
        )],
    );
    let detection2 = run(&dir2, &conn);
    let openai = detection2
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    assert_eq!(openai.confidence, DetectionConfidence::Likely);
}

#[test]
fn placeholder_values_do_not_count_as_keys() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[(
            ".env",
            "OPENAI_API_KEY=your-key-here\nANTHROPIC_API_KEY=changeme\n",
        )],
    );
    let detection = run(&dir, &conn);
    // No provider may reach Likely from a placeholder alone.
    for p in &detection.providers {
        assert!(
            p.confidence == DetectionConfidence::Possible,
            "{} got {:?} from a placeholder",
            p.provider_id,
            p.confidence
        );
    }
}

#[test]
fn assigned_credential_plus_env_key_is_confirmed() {
    let mut tv = test_vault();
    let project = tv
        .vault
        .create_project(api_tracker_core::vault::NewProject {
            name: "fixture-project".to_string(),
            ..Default::default()
        })
        .unwrap();
    tv.vault
        .add_credential(api_tracker_core::vault::AddCredential {
            project: project.id.clone(),
            provider: "openai".to_string(),
            name: "fixture-key".to_string(),
            environment: api_tracker_core::model::Environment::Development,
            value: api_tracker_core::secret::SecretString::new(FAKE_OPENAI_KEY.to_string()),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[(".env", &format!("OPENAI_API_KEY={FAKE_OPENAI_KEY}\n"))],
    );
    let detection = detect(
        tv.vault.connection(),
        &DetectionInput {
            folder: dir.path(),
            project_id: Some(&project.id),
        },
    )
    .unwrap();
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    // S1 (key in .env) + S4 (assigned credential) = Confirmed.
    assert_eq!(openai.confidence, DetectionConfidence::Confirmed);
    assert_eq!(
        openai.credential_candidates,
        vec!["fixture-key".to_string()]
    );
}

#[test]
fn supabase_origin_is_inferred_and_needs_confirmation() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[(
            ".env",
            "SUPABASE_URL=https://xyzcompany.supabase.co\nSUPABASE_SERVICE_ROLE_KEY=sb_secret_FAKE-TEST-NOT-REAL-0001\n",
        )],
    );
    let detection = run(&dir, &conn);
    let supabase = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "supabase")
        .expect("supabase detected");
    match &supabase.configurability {
        Configurability::NeedsOriginConfirm { inferred_origin } => {
            assert_eq!(inferred_origin, "https://xyzcompany.supabase.co:443");
        }
        other => panic!("expected NeedsOriginConfirm, got {other:?}"),
    }
}

#[test]
fn conflicting_supabase_origins_need_input() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[
            (".env", "SUPABASE_URL=https://one.supabase.co\n"),
            (".env.local", "SUPABASE_URL=https://two.supabase.co\n"),
        ],
    );
    let detection = run(&dir, &conn);
    let supabase = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "supabase")
        .expect("supabase detected");
    assert_eq!(supabase.configurability, Configurability::NeedsOriginInput);
    assert!(supabase
        .limitations
        .iter()
        .any(|l| l.contains("conflicting")));
}

#[test]
fn stripe_is_detected_but_unsupported_and_never_blocks_others() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[
            (
                ".env",
                &format!(
                    "STRIPE_SECRET_KEY=sk_live_FAKE0000000000000000000000000000\nOPENAI_API_KEY={FAKE_OPENAI_KEY}\n"
                ),
            ),
            (
                "package.json",
                r#"{ "dependencies": { "stripe": "^14.0.0", "openai": "^4.0.0" } }"#,
            ),
        ],
    );
    let detection = run(&dir, &conn);
    let stripe = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "stripe")
        .expect("stripe detected");
    assert_eq!(
        stripe.configurability,
        Configurability::Unsupported {
            reason: UnsupportedReason::NoConfigurableBaseUrl
        }
    );
    assert!(!stripe.limitations.is_empty(), "honest reason present");
    // The supported provider is untouched by the unsupported one.
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    assert_eq!(openai.confidence, DetectionConfidence::Confirmed);
}

#[test]
fn lockfile_only_is_possible() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[(
            "package-lock.json",
            r#"{ "packages": { "node_modules/openai": { "version": "4.0.0" } }, "dependencies": { "openai": {} } }"#,
        )],
    );
    let detection = run(&dir, &conn);
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected from lockfile");
    assert_eq!(openai.confidence, DetectionConfidence::Possible);
}

#[test]
fn empty_folder_detects_nothing() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    let detection = run(&dir, &conn);
    assert!(detection.providers.is_empty());
}

#[test]
fn prior_dismissal_steps_confidence_down_and_confirmation_up() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let canonical = dir.path().canonicalize().unwrap().display().to_string();
    conn.execute(
        "INSERT INTO stack_preferences (repo_path, template_id, decision, decided_at)
         VALUES (?1, 'openai-app', 'dismissed', '2026-01-01T00:00:00Z')",
        [&canonical],
    )
    .unwrap();
    let detection = run(&dir, &conn);
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .unwrap();
    // Confirmed stepped down one level by the dismissal.
    assert_eq!(openai.confidence, DetectionConfidence::Likely);

    // And a confirmation steps a lockfile-only Possible up to Likely.
    let dir2 = TempDir::new().unwrap();
    write_project(
        dir2.path(),
        &[(
            "package-lock.json",
            r#"{ "dependencies": { "openai": {} } }"#,
        )],
    );
    let canonical2 = dir2.path().canonicalize().unwrap().display().to_string();
    conn.execute(
        "INSERT INTO stack_preferences (repo_path, template_id, decision, decided_at)
         VALUES (?1, 'openai-app', 'confirmed', '2026-01-01T00:00:00Z')",
        [&canonical2],
    )
    .unwrap();
    let detection2 = run(&dir2, &conn);
    let openai2 = detection2
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .unwrap();
    assert_eq!(openai2.confidence, DetectionConfidence::Likely);
}

#[test]
fn serialized_detection_never_contains_a_value() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[
            (
                ".env",
                &format!("OPENAI_API_KEY={CANARY}abcdefgh\nSUPABASE_URL=https://xyzcompany.supabase.co\n"),
            ),
            (
                "package.json",
                r#"{ "dependencies": { "openai": "^4.0.0" } }"#,
            ),
        ],
    );
    let detection = run(&dir, &conn);
    let serialized = serde_json::to_string(&detection).unwrap();
    assert!(
        !serialized.contains(CANARY),
        "detection serialization leaked a secret value"
    );
    // The one permitted value-derived datum: the validated, confirmable
    // origin of a custom-origin provider.
    assert!(serialized.contains("xyzcompany.supabase.co"));
}

#[test]
fn dotenv_loader_and_docker_signals_are_reported() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[
            ("package.json", r#"{ "dependencies": { "express": "^4" } }"#),
            ("docker-compose.yml", "services: {}\n"),
        ],
    );
    let detection = run(&dir, &conn);
    assert_eq!(detection.project_signals.dotenv_loader, Some(false));
    assert!(detection.project_signals.docker_compose);
}
