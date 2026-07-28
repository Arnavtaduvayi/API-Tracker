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
fn a_key_whose_value_matches_the_published_format_is_confirmed() {
    // The manifests have always carried each provider's PUBLIC key-format
    // patterns (`sk-ant-…`, `sk-proj-…`), and detection never consulted
    // them: the placeholder filter was the only check a value ever got, so
    // `OPENAI_API_KEY=abcdefgh` reached the auto-select threshold
    // (ZFT-027). A value of the right shape is strong, independent
    // evidence — much stronger than a variable name anyone can type.
    let (_db, conn) = test_conn();
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
    assert_eq!(anthropic.confidence, DetectionConfidence::Confirmed);
}

#[test]
fn a_key_of_no_recognised_shape_stays_below_the_auto_select_threshold() {
    // The other half of the same rule, and the one that matters for
    // safety: a recognised variable NAME holding a value of no recognised
    // shape is real evidence, but not enough of it to configure without
    // asking. `Possible` is below the `Likely` threshold `Selections`
    // auto-includes at.
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    write_project(dir.path(), &[(".env", "OPENAI_API_KEY=abcdefgh12345678\n")]);
    let detection = run(&dir, &conn);
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai is still DETECTED — the name is real evidence");
    assert_eq!(
        openai.confidence,
        DetectionConfidence::Possible,
        "a value of no recognised shape must not reach the auto-select threshold"
    );
    assert!(
        !api_tracker_tracking::plan::Selections::defaults(&detection)
            .include
            .contains("openai"),
        "and it must not be auto-selected"
    );
}

#[test]
fn an_sdk_dependency_alone_is_likely() {
    // A declared SDK dependency with no key: the project plainly intends to
    // call the provider, so it is worth configuring, but nothing here
    // proves a credential exists.
    let (_db, conn) = test_conn();
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
fn a_prefix_named_package_is_not_the_package_it_prefixes() {
    // `openai-whisper` is an OFFLINE speech-to-text package that makes no
    // OpenAI API calls. `pyproject.toml` matched dependency names by PREFIX
    // while `requirements.txt` matched them exactly, so the same project
    // detected differently depending on which file it used (ZFT-026).
    let (_db, conn) = test_conn();
    for (file, content) in [
        (
            "pyproject.toml",
            "[project]\ndependencies = [\n  \"openai-whisper>=20231117\",\n]\n",
        ),
        ("requirements.txt", "openai-whisper==20231117\n"),
    ] {
        let dir = TempDir::new().unwrap();
        write_project(dir.path(), &[(file, content)]);
        let detection = run(&dir, &conn);
        assert!(
            !detection
                .providers
                .iter()
                .any(|p| p.provider_id == "openai"),
            "{file}: openai-whisper must not be read as the openai SDK: {:?}",
            detection
                .providers
                .iter()
                .map(|p| &p.provider_id)
                .collect::<Vec<_>>()
        );
    }

    // The control: the REAL package is still detected from both files.
    for (file, content) in [
        (
            "pyproject.toml",
            "[project]\ndependencies = [\n  \"openai>=1.40\",\n]\n",
        ),
        ("requirements.txt", "openai==1.40.0\n"),
    ] {
        let dir = TempDir::new().unwrap();
        write_project(dir.path(), &[(file, content)]);
        let detection = run(&dir, &conn);
        assert!(
            detection
                .providers
                .iter()
                .any(|p| p.provider_id == "openai"),
            "{file}: the real openai dependency must still be detected"
        );
    }
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

// ---------------------------------------------------------------------------
// RA-010: the ZFT-012 loopback guard must be anchored on the parsed host
// ---------------------------------------------------------------------------

/// A fixed-origin provider (OpenAI) whose base URL the project has set to
/// `value`, with enough other evidence to be `Confirmed`.
fn openai_with_base_url(dir: &std::path::Path, value: &str) {
    write_project(
        dir,
        &[
            (
                ".env",
                &format!("OPENAI_API_KEY={FAKE_OPENAI_KEY}\nOPENAI_BASE_URL={value}\n"),
            ),
            (
                "package.json",
                r#"{ "dependencies": { "openai": "^4.0.0" } }"#,
            ),
        ],
    );
}

#[test]
fn a_path_query_or_fragment_cannot_disguise_a_base_url_as_tethras_own_writing() {
    // The ZFT-012 guard asked `value.contains("127.0.0.1:")` over the WHOLE
    // base-URL value — path, query and fragment included — so a committed
    // `OPENAI_BASE_URL=https://attacker.example.com/#127.0.0.1:1` matched it.
    // Tethra then treated the attacker's host as its own previous writing:
    // the re-point warning and the origin-approval prompt both disappeared,
    // the provider fell back to `Automatic`, and repository content had
    // suppressed its own consent prompt (RA-010).
    let (_db, conn) = test_conn();
    for value in [
        "https://attacker.example.com/#127.0.0.1:1",
        "https://attacker.example.com/?redirect=127.0.0.1:1",
        "https://attacker.example.com/127.0.0.1:1/v1",
        "https://attacker.example.com/v1#127.0.0.1:8788",
        "https://127.0.0.1:1@attacker.example.com/v1",
        "https://127.0.0.1:443.attacker.example.com/v1",
    ] {
        let dir = TempDir::new().unwrap();
        openai_with_base_url(dir.path(), value);
        let detection = run(&dir, &conn);
        let openai = detection
            .providers
            .iter()
            .find(|p| p.provider_id == "openai")
            .expect("openai detected");
        assert_ne!(
            openai.configurability,
            Configurability::Automatic,
            "{value}: an already-customised base URL must not be silently re-pointed"
        );
        assert!(
            !openai.limitations.is_empty(),
            "{value}: the customisation must be stated on screen"
        );
        assert!(
            !api_tracker_tracking::plan::Selections::defaults(&detection)
                .include
                .contains("openai"),
            "{value}: and it must not be auto-selected"
        );
    }
}

#[test]
fn a_disguised_base_url_is_surfaced_for_approval_at_its_real_host() {
    // The same defect from the other side: the destination the user is asked
    // about must be the one the value actually names, not the loopback the
    // fragment spelled.
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    openai_with_base_url(dir.path(), "https://attacker.example.com/v1#127.0.0.1:1");
    let detection = run(&dir, &conn);
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    match &openai.configurability {
        Configurability::NeedsOriginConfirm { inferred_origin } => {
            assert_eq!(inferred_origin, "https://attacker.example.com:443");
        }
        other => panic!("expected NeedsOriginConfirm, got {other:?}"),
    }
    assert!(openai
        .limitations
        .iter()
        .any(|l| l.contains("attacker.example.com")));
}

#[test]
fn a_custom_origin_provider_reads_the_real_host_out_of_a_disguised_value() {
    // The second guard site (the custom-origin branch) had the same
    // unanchored test, and skipped the value entirely — so the origin the
    // user would be asked to approve never got built.
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[
            (
                ".env",
                "SUPABASE_URL=https://attacker.example.com/#127.0.0.1:1\nSUPABASE_SERVICE_ROLE_KEY=sb_secret_FAKE-TEST-NOT-REAL-0001\n",
            ),
        ],
    );
    let detection = run(&dir, &conn);
    let supabase = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "supabase")
        .expect("supabase detected");
    match &supabase.configurability {
        Configurability::NeedsOriginConfirm { inferred_origin } => {
            assert_eq!(inferred_origin, "https://attacker.example.com:443");
        }
        other => panic!("expected NeedsOriginConfirm, got {other:?}"),
    }
}

#[test]
fn tethras_own_written_base_url_is_still_recognised_as_its_own() {
    // The negative control for the anchoring above: `.env` linking writes
    // `http://127.0.0.1:<port>/p/<slug>/…`, and that value must keep being
    // read as a previous link rather than as a destination the project
    // chose. If it were not, every re-scan after a link would ask the user
    // to approve Tethra's own gateway.
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    openai_with_base_url(dir.path(), "http://127.0.0.1:49723/p/abc123/openai/v1");
    let detection = run(&dir, &conn);
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    assert_eq!(openai.configurability, Configurability::Automatic);
    assert!(
        openai.limitations.is_empty(),
        "Tethra's own writing is not a customisation: {:?}",
        openai.limitations
    );
    assert!(api_tracker_tracking::plan::Selections::defaults(&detection)
        .include
        .contains("openai"));
}

#[test]
fn tethras_own_writing_is_still_not_its_own_evidence_but_a_real_value_is() {
    // ZFT-025 must survive the anchoring: after the first link, Tethra's own
    // `OPENAI_BASE_URL` sat in the file and its mere presence counted as the
    // second independent signal class that promotes a detection to
    // `Confirmed`. The key here holds a value of no published shape, so the
    // S3 base-URL signal is exactly what decides Possible vs Confirmed.
    let (_db, conn) = test_conn();

    let ours = TempDir::new().unwrap();
    write_project(
        ours.path(),
        &[(
            ".env",
            "OPENAI_API_KEY=abcdefgh12345678\n\
             OPENAI_BASE_URL=http://127.0.0.1:49723/p/abc123/openai/v1\n",
        )],
    );
    let detection = run(&ours, &conn);
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    assert_eq!(
        openai.confidence,
        DetectionConfidence::Possible,
        "Tethra's own writing must not be Tethra's evidence"
    );

    // The control: a base URL the PROJECT chose is real, independent
    // evidence and still promotes the detection — the fragment must not
    // buy an attacker the suppression either.
    let theirs = TempDir::new().unwrap();
    write_project(
        theirs.path(),
        &[(
            ".env",
            "OPENAI_API_KEY=abcdefgh12345678\n\
             OPENAI_BASE_URL=https://litellm.corp.example/v1#127.0.0.1:1\n",
        )],
    );
    let detection = run(&theirs, &conn);
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    assert_eq!(openai.confidence, DetectionConfidence::Confirmed);
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
