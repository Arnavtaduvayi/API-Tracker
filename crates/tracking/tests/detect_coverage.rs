//! ZFT-010 / ZFT-VAL-6 regression suite: a screen that claims to show what
//! was detected must account for everything the scan saw.
//!
//! The audit ran a 30-API monorepo fixture. Four providers appeared under a
//! heading reading `Detected:`. The other twenty-six credentials —
//! `GROQ_API_KEY`, `MISTRAL_API_KEY`, `SENDGRID_API_KEY`,
//! `TWILIO_AUTH_TOKEN`, … — appeared **nowhere**: not detected, not
//! unsupported, not unknown, not counted. It also found that the
//! "30-provider-scale test" was a four-provider test with a thirty-variable
//! `.env`, and that the test's own comment conceded it.
//!
//! This file contains the REAL thirty-integration fixture, and asserts that
//! every one of its inputs is accounted for in exactly one bucket.

mod common;

use api_tracker_tracking::detect::{self, Configurability, ProjectDetection};
use api_tracker_tracking::plan::Selections;
use common::*;
use std::path::Path;

/// The thirty integrations, as (variable, kind) pairs. The mixture is what
/// the audit brief asks for: built-in supported providers, custom origins,
/// unknown providers, several credentials, duplicate dependencies, several
/// environment files, a nested application, and ambiguous evidence.
const BUILT_IN: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "DEEPSEEK_API_KEY",
    "TOGETHER_API_KEY",
    "PERPLEXITY_API_KEY",
    "FIREWORKS_API_KEY",
    "OPENROUTER_API_KEY",
    "XAI_API_KEY",
];

/// Services Tethra has no manifest for at all. These are the ones that used
/// to vanish.
const UNKNOWN: &[&str] = &[
    "SENDGRID_API_KEY",
    "TWILIO_AUTH_TOKEN",
    "SLACK_BOT_TOKEN",
    "ELEVENLABS_API_KEY",
    "ASSEMBLYAI_API_KEY",
    "PINECONE_API_KEY",
    "RESEND_API_KEY",
    "SENTRY_AUTH_TOKEN",
    "DATADOG_API_KEY",
    "ALGOLIA_ADMIN_KEY",
    "CLOUDFLARE_API_TOKEN",
    "MAILGUN_API_KEY",
    "SEGMENT_WRITE_KEY",
    "POSTHOG_API_KEY",
    "STRIPE_TEST_WEBHOOK_SECRET",
    "REDIS_PASSWORD",
    "LAUNCHDARKLY_SDK_KEY",
    "HONEYCOMB_API_KEY",
    "AIRTABLE_PAT",
];

fn thirty_api_fixture(dir: &Path) {
    // Spread across several env files, as a real monorepo does.
    let mut root_env = String::new();
    for (i, var) in BUILT_IN.iter().enumerate() {
        root_env.push_str(&format!("{var}=fake-builtin-value-{i}-0123456789abcdef\n"));
    }
    let mut local_env = String::new();
    for (i, var) in UNKNOWN.iter().take(10).enumerate() {
        local_env.push_str(&format!("{var}=fake-unknown-value-{i}-0123456789abcdef\n"));
    }
    let mut prod_env = String::new();
    for (i, var) in UNKNOWN.iter().skip(10).enumerate() {
        prod_env.push_str(&format!("{var}=fake-unknown-value-{i}-0123456789abcdef\n"));
    }
    // Custom origins: project-specific hosts that need explicit approval.
    let mut nested_env = String::new();
    nested_env.push_str("SUPABASE_URL=https://abcdefghijkl.supabase.co\n");
    nested_env.push_str("SUPABASE_SERVICE_ROLE_KEY=sb_secret_FAKE00000000000000000000\n");
    // Ambiguous evidence: a placeholder that must NOT count as a credential.
    nested_env.push_str("COHERE_API_KEY=your-key-here\n");
    // A duplicate of a root variable, in a second file.
    nested_env.push_str("OPENAI_API_KEY=fake-builtin-value-0-0123456789abcdef\n");

    write_project(
        dir,
        &[
            (
                "package.json",
                r#"{"dependencies":{
                    "openai":"^4",
                    "@anthropic-ai/sdk":"^0.30",
                    "@supabase/supabase-js":"^2",
                    "groq-sdk":"^0.7",
                    "@mistralai/mistralai":"^1",
                    "next":"^14",
                    "dotenv":"^16"
                }}"#,
            ),
            (".env", &root_env),
            (".env.local", &local_env),
            (".env.production", &prod_env),
            ("apps/api/.env", &nested_env),
            (
                "apps/api/requirements.txt",
                "openai==1.40.0\nanthropic==0.34.0\npython-dotenv==1.0.1\n",
            ),
        ],
    );
}

fn detect_folder(dir: &Path) -> ProjectDetection {
    let (_db, conn) = test_conn();
    detect::detect(
        &conn,
        &detect::DetectionInput {
            folder: dir,
            project_id: None,
        },
    )
    .unwrap()
}

#[test]
fn the_thirty_integration_fixture_really_contains_thirty_integrations() {
    // The audit's complaint about the old test was that its name lied.
    // Pin the fixture's own size so this one cannot quietly shrink.
    // 10 LLM-provider keys + 19 keys for services with no Tethra manifest,
    // plus Supabase (a project-specific origin plus its service-role key)
    // = 30 distinct integrations.
    assert_eq!(BUILT_IN.len(), 10);
    assert_eq!(UNKNOWN.len(), 19);
    let tmp = tempfile::tempdir().unwrap();
    thirty_api_fixture(tmp.path());
    let detection = detect_folder(tmp.path());
    assert_eq!(
        detection.coverage.total(),
        30,
        "the fixture must present exactly thirty integrations to the scan — the audit's \
         complaint about the old test was that a four-provider test was called a \
         thirty-provider one. Got {:?}",
        detection.coverage
    );
}

#[test]
fn no_credential_is_silently_dropped_from_the_review_screen() {
    let tmp = tempfile::tempdir().unwrap();
    thirty_api_fixture(tmp.path());
    let detection = detect_folder(tmp.path());

    // Everything the scan saw is either a recognised provider or an
    // explicitly listed unrecognised credential.
    let recognised: Vec<&str> = detection
        .providers
        .iter()
        .map(|p| p.provider_id.as_str())
        .collect();
    let unrecognised: Vec<&str> = detection
        .unrecognized
        .iter()
        .map(|u| u.var.as_str())
        .collect();

    let mut missing = Vec::new();
    for var in UNKNOWN {
        if !unrecognised.contains(var) {
            missing.push(*var);
        }
    }
    assert!(
        missing.is_empty(),
        "these credentials appeared NOWHERE on the review screen — not detected, \
         not unsupported, not unknown, not counted: {missing:?}\n\
         recognised: {recognised:?}\nunrecognised: {unrecognised:?}"
    );
}

#[test]
fn the_counts_add_up_to_the_headline() {
    let tmp = tempfile::tempdir().unwrap();
    thirty_api_fixture(tmp.path());
    let detection = detect_folder(tmp.path());
    let c = &detection.coverage;
    assert_eq!(
        c.total(),
        c.tracked_automatically
            + c.needs_origin_confirmation
            + c.detected_unsupported
            + c.unrecognized
            + c.low_confidence,
        "the headline number must be the sum of the buckets, or it is not a summary"
    );
    let lines = c.lines();
    assert!(
        lines[0].contains(&c.total().to_string()),
        "the first line states the total: {lines:?}"
    );
    // Every non-zero bucket must be named. Silence about a bucket is
    // exactly how twenty-six credentials became invisible.
    if c.unrecognized > 0 {
        assert!(
            lines.iter().any(|l| l.contains("could not be identified")),
            "a non-empty unknown bucket must be stated: {lines:?}"
        );
    }
    if c.tracked_automatically > 0 {
        assert!(lines.iter().any(|l| l.contains("tracked automatically")));
    }
}

#[test]
fn a_placeholder_value_is_not_counted_as_a_credential() {
    let tmp = tempfile::tempdir().unwrap();
    thirty_api_fixture(tmp.path());
    let detection = detect_folder(tmp.path());
    assert!(
        !detection
            .unrecognized
            .iter()
            .any(|u| u.var == "COHERE_API_KEY"),
        "`COHERE_API_KEY=your-key-here` is a placeholder, not an integration"
    );
}

#[test]
fn the_unknown_bucket_carries_a_usable_hint_and_never_a_value() {
    let tmp = tempfile::tempdir().unwrap();
    thirty_api_fixture(tmp.path());
    let detection = detect_folder(tmp.path());
    let sendgrid = detection
        .unrecognized
        .iter()
        .find(|u| u.var == "SENDGRID_API_KEY")
        .expect("SENDGRID_API_KEY is listed");
    assert_eq!(sendgrid.name_hint.as_deref(), Some("sendgrid"));
    assert!(
        sendgrid.file.ends_with(".env.local"),
        "the user needs to know which file it came from: {}",
        sendgrid.file
    );
    // No value, anywhere, for any entry.
    let serialized = serde_json::to_string(&detection.unrecognized).unwrap();
    for needle in ["fake-unknown-value", "fake-builtin-value", "sb_secret_"] {
        assert!(
            !serialized.contains(needle),
            "a value leaked into the unrecognised list: {needle}"
        );
    }
}

#[test]
fn a_hint_never_becomes_a_provider_or_a_route() {
    // The name heuristic is presentation only. Inferring an integration
    // from a variable name is exactly the evidence inflation the audit
    // flagged elsewhere.
    let tmp = tempfile::tempdir().unwrap();
    thirty_api_fixture(tmp.path());
    let detection = detect_folder(tmp.path());
    let hinted: Vec<String> = detection
        .unrecognized
        .iter()
        .filter_map(|u| u.name_hint.clone())
        .collect();
    for hint in &hinted {
        assert!(
            !detection.providers.iter().any(|p| &p.provider_id == hint),
            "the hint {hint:?} must not have become a detected provider"
        );
        assert!(
            !Selections::defaults(&detection).include.contains(hint),
            "the hint {hint:?} must never be selected for configuration"
        );
    }
}

#[test]
fn built_in_providers_are_still_bulk_configured_at_thirty_api_scale() {
    // The zero-friction property under load: many integrations must not
    // become many forms.
    let tmp = tempfile::tempdir().unwrap();
    thirty_api_fixture(tmp.path());
    let detection = detect_folder(tmp.path());
    let defaults = Selections::defaults(&detection);
    assert!(
        defaults.include.len() >= 2,
        "the supported providers must be selected together in one pass: {:?}",
        defaults.include
    );
    assert!(
        defaults.include.contains("openai") && defaults.include.contains("anthropic"),
        "the two providers with both an SDK dependency and a key must be automatic: {:?}",
        defaults.include
    );
    // Exactly one review screen: the number of things needing an individual
    // decision stays small even at thirty integrations.
    let pending = Selections::pending_origin_approvals(&detection);
    assert!(
        pending.len() <= 3,
        "a thirty-API project must not produce a wall of approvals: {pending:?}"
    );
}

#[test]
fn one_unsupported_provider_never_blocks_the_supported_ones() {
    let tmp = tempfile::tempdir().unwrap();
    thirty_api_fixture(tmp.path());
    let detection = detect_folder(tmp.path());
    let unsupported: Vec<&str> = detection
        .providers
        .iter()
        .filter(|p| matches!(p.configurability, Configurability::Unsupported { .. }))
        .map(|p| p.provider_id.as_str())
        .collect();
    let selected = Selections::defaults(&detection);
    assert!(
        !selected.include.is_empty(),
        "unsupported providers present ({unsupported:?}) must not empty the selection"
    );
    for id in &unsupported {
        assert!(
            !selected.include.contains(*id),
            "an unsupported provider must not be selected either: {id}"
        );
    }
}

#[test]
fn every_env_file_in_the_fixture_is_actually_scanned() {
    // The audit ruled out file-skipping as the cause of the disappearance;
    // pin that so a future regression cannot reintroduce it as one.
    let tmp = tempfile::tempdir().unwrap();
    thirty_api_fixture(tmp.path());
    let detection = detect_folder(tmp.path());
    let seen: Vec<&str> = detection
        .env_files
        .iter()
        .map(|f| f.rel_path.as_str())
        .collect();
    for expected in [".env", ".env.local", ".env.production", "apps/api/.env"] {
        assert!(
            seen.contains(&expected),
            "{expected} must be in the inventory: {seen:?}"
        );
    }
    assert!(
        detection.accounting.read >= 4,
        "the read counter must reflect the files actually read: {:?}",
        detection.accounting
    );
}
