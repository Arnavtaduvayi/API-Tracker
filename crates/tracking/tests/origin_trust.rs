//! ZFT-004 / ZFT-012 regression suite: repository content is evidence, not
//! authorization.
//!
//! The audit built a fixture containing **no secrets at all** — a committed
//! `package.json` naming `@supabase/supabase-js` and a committed
//! `SUPABASE_URL=https://attacker-controlled.example.com` — and Tethra
//! created a MAC'd, enabled route to that host and rewrote the project's
//! `.env` so its credential flowed through it. The security document
//! promised "an explicit checkbox (never part of Confirmed auto-config)";
//! the CLI had no checkbox and the desktop shipped it pre-checked.
//!
//! The rule these tests pin: an origin that comes from a compiled-in Tethra
//! manifest may be configured automatically; an origin read from project
//! content may not, ever, without a separate decision naming that exact
//! destination.

mod common;

use api_tracker_tracking::detect;
use api_tracker_tracking::detect::{Configurability, DetectionConfidence, ProjectDetection};
use api_tracker_tracking::origin;
use api_tracker_tracking::plan::Selections;
use common::*;
use std::path::Path;

/// A folder with a committed dependency and a project-chosen origin, and
/// nothing else. This is the audit's fixture.
fn attacker_origin_fixture(dir: &Path) {
    write_project(
        dir,
        &[
            (
                "package.json",
                r#"{"dependencies":{"@supabase/supabase-js":"^2.39.0"}}"#,
            ),
            (
                ".env.development",
                "SUPABASE_URL=https://attacker-controlled.example.com\n",
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

// ---------------------------------------------------------------------------
// The blocking property
// ---------------------------------------------------------------------------

#[test]
fn a_repository_chosen_origin_is_never_selected_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    attacker_origin_fixture(tmp.path());
    let detection = detect_folder(tmp.path());

    // Detection still WORKS — the point is not to stop noticing Supabase.
    let supabase = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "supabase")
        .expect("supabase is still detected");
    assert!(
        matches!(
            supabase.configurability,
            Configurability::NeedsOriginConfirm { .. }
        ),
        "a project-chosen origin must be classified as needing confirmation, got {:?}",
        supabase.configurability
    );
    assert!(
        supabase.confidence >= DetectionConfidence::Likely,
        "confidence is unchanged; only the authorization decision moved"
    );

    // …and it is NOT in the default selection.
    let defaults = Selections::defaults(&detection);
    assert!(
        !defaults.include.contains("supabase"),
        "a destination read from the project must never be auto-included"
    );
    assert!(
        defaults.confirmed_origins.is_empty(),
        "the confirmation must not be pre-filled by the code that should ask for it"
    );

    // It appears in the explicit approval list instead.
    let pending = Selections::pending_origin_approvals(&detection);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, "supabase");
    assert!(pending[0].1.contains("attacker-controlled.example.com"));
}

#[test]
fn a_built_in_manifest_origin_is_still_configured_automatically() {
    // The control that keeps the zero-friction promise honest: if this
    // regressed, every other test here would pass for the wrong reason.
    let tmp = tempfile::tempdir().unwrap();
    write_project(
        tmp.path(),
        &[
            ("package.json", r#"{"dependencies":{"openai":"^4"}}"#),
            (
                ".env",
                "OPENAI_API_KEY=sk-proj-FAKE000000000000000000000000000000\n",
            ),
        ],
    );
    let detection = detect_folder(tmp.path());
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    assert_eq!(openai.configurability, Configurability::Automatic);

    let defaults = Selections::defaults(&detection);
    assert!(
        defaults.include.contains("openai"),
        "a compiled-in manifest origin must still be automatic — the repository \
         cannot influence where api.openai.com points"
    );
}

#[test]
fn approving_one_origin_does_not_approve_another() {
    let mut sel = Selections::default();
    sel.approve_origin("supabase", "https://a.supabase.co");
    assert!(sel.include.contains("supabase"));
    assert_eq!(
        sel.confirmed_origins.get("supabase").map(String::as_str),
        Some("https://a.supabase.co")
    );
    // Nothing else was granted.
    assert_eq!(sel.include.len(), 1);
    assert_eq!(sel.confirmed_origins.len(), 1);
}

// ---------------------------------------------------------------------------
// ZFT-012 — an existing custom base URL must not be silently re-pointed
// ---------------------------------------------------------------------------

#[test]
fn an_existing_custom_base_url_downgrades_a_fixed_origin_provider() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(
        tmp.path(),
        &[
            ("package.json", r#"{"dependencies":{"openai":"^4"}}"#),
            (
                ".env",
                "OPENAI_API_KEY=sk-proj-FAKE000000000000000000000000000000\n\
                 OPENAI_BASE_URL=https://litellm.corp.example/v1\n",
            ),
        ],
    );
    let detection = detect_folder(tmp.path());
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");

    match &openai.configurability {
        Configurability::NeedsOriginConfirm { inferred_origin } => {
            assert!(
                inferred_origin.contains("litellm.corp.example"),
                "the EXISTING destination is what needs confirming, not the manifest one: \
                 {inferred_origin}"
            );
        }
        other => panic!(
            "a project already pointing OpenAI at a corporate gateway must not be silently \
             re-pointed at api.openai.com, got {other:?}"
        ),
    }
    assert!(
        openai
            .limitations
            .iter()
            .any(|l| l.contains("litellm.corp.example")),
        "the user must be told which destination is at stake: {:?}",
        openai.limitations
    );
    assert!(
        !Selections::defaults(&detection).include.contains("openai"),
        "a re-pointed provider must not be configured automatically"
    );
}

#[test]
fn a_base_url_already_equal_to_the_manifest_origin_stays_automatic() {
    // The converse control: setting `OPENAI_BASE_URL` to OpenAI's own
    // endpoint is not a customisation, and must not cost the user a prompt.
    let tmp = tempfile::tempdir().unwrap();
    write_project(
        tmp.path(),
        &[
            ("package.json", r#"{"dependencies":{"openai":"^4"}}"#),
            (
                ".env",
                "OPENAI_API_KEY=sk-proj-FAKE000000000000000000000000000000\n\
                 OPENAI_BASE_URL=https://api.openai.com/v1\n",
            ),
        ],
    );
    let detection = detect_folder(tmp.path());
    let openai = detection
        .providers
        .iter()
        .find(|p| p.provider_id == "openai")
        .expect("openai detected");
    assert_eq!(
        openai.configurability,
        Configurability::Automatic,
        "pointing at the manifest origin is not a customisation"
    );
}

// ---------------------------------------------------------------------------
// The approval store
// ---------------------------------------------------------------------------

#[test]
fn an_approval_is_reusable_for_the_exact_origin_and_nothing_else() {
    let mut tv = test_vault();
    let v = &mut tv.vault;
    let key = v.gateway_route_mac_key().unwrap();
    let vault_id = api_tracker_gateway::routes::vault_id(v.connection()).unwrap();

    assert!(
        origin::is_approved(
            v.connection(),
            &vault_id,
            &key,
            "https://abc.supabase.co",
            "supabase"
        )
        .unwrap()
        .is_none(),
        "nothing is approved before the user approves it"
    );

    origin::approve(
        v.connection(),
        &vault_id,
        &key,
        "https://abc.supabase.co",
        "supabase",
    )
    .unwrap();

    // Exact origin: reusable.
    assert!(origin::is_approved(
        v.connection(),
        &vault_id,
        &key,
        "https://abc.supabase.co",
        "supabase"
    )
    .unwrap()
    .is_some());
    // Same host, explicit default port: the same destination.
    assert!(origin::is_approved(
        v.connection(),
        &vault_id,
        &key,
        "https://abc.supabase.co:443",
        "supabase"
    )
    .unwrap()
    .is_some());

    // A DIFFERENT host is a different decision.
    assert!(
        origin::is_approved(
            v.connection(),
            &vault_id,
            &key,
            "https://evil.supabase.co",
            "supabase"
        )
        .unwrap()
        .is_none(),
        "approving one host must never approve another"
    );
    // A subdomain of the approved host is also a different host.
    assert!(origin::is_approved(
        v.connection(),
        &vault_id,
        &key,
        "https://x.abc.supabase.co",
        "supabase"
    )
    .unwrap()
    .is_none());
    // The same host for a DIFFERENT provider is a different decision too.
    assert!(origin::is_approved(
        v.connection(),
        &vault_id,
        &key,
        "https://abc.supabase.co",
        "openai"
    )
    .unwrap()
    .is_none());
}

#[test]
fn a_tampered_approval_row_is_rejected() {
    let mut tv = test_vault();
    let v = &mut tv.vault;
    let key = v.gateway_route_mac_key().unwrap();
    let vault_id = api_tracker_gateway::routes::vault_id(v.connection()).unwrap();
    origin::approve(
        v.connection(),
        &vault_id,
        &key,
        "https://abc.supabase.co",
        "supabase",
    )
    .unwrap();

    // Edit the row the way a process with write access to vault.db would:
    // repoint an existing approval at another host, keeping its MAC.
    v.connection()
        .execute(
            "UPDATE tracking_approved_origins SET origin = 'https://evil.example:443'",
            [],
        )
        .unwrap();

    assert!(
        origin::is_approved(
            v.connection(),
            &vault_id,
            &key,
            "https://evil.example",
            "supabase"
        )
        .unwrap()
        .is_none(),
        "a row whose MAC does not cover its contents must be treated as ABSENT"
    );
    let (valid, tampered) = origin::list(v.connection(), &vault_id, &key).unwrap();
    assert!(valid.is_empty());
    assert_eq!(tampered, 1, "tampering must be reported, not hidden");
}

#[test]
fn a_changed_origin_requires_reapproval() {
    let mut tv = test_vault();
    let v = &mut tv.vault;
    let key = v.gateway_route_mac_key().unwrap();
    let vault_id = api_tracker_gateway::routes::vault_id(v.connection()).unwrap();
    origin::approve(
        v.connection(),
        &vault_id,
        &key,
        "https://old.supabase.co",
        "supabase",
    )
    .unwrap();
    // The project's SUPABASE_URL changes — a new destination, a new decision.
    assert!(origin::is_approved(
        v.connection(),
        &vault_id,
        &key,
        "https://new.supabase.co",
        "supabase"
    )
    .unwrap()
    .is_none());
}

#[test]
fn revoking_an_approval_takes_effect() {
    let mut tv = test_vault();
    let v = &mut tv.vault;
    let key = v.gateway_route_mac_key().unwrap();
    let vault_id = api_tracker_gateway::routes::vault_id(v.connection()).unwrap();
    origin::approve(
        v.connection(),
        &vault_id,
        &key,
        "https://abc.supabase.co",
        "supabase",
    )
    .unwrap();
    assert!(origin::revoke(v.connection(), "https://abc.supabase.co", "supabase").unwrap());
    assert!(origin::is_approved(
        v.connection(),
        &vault_id,
        &key,
        "https://abc.supabase.co",
        "supabase"
    )
    .unwrap()
    .is_none());
}

// ---------------------------------------------------------------------------
// The disclosure surface
// ---------------------------------------------------------------------------

#[test]
fn the_approval_request_discloses_everything_the_brief_requires() {
    let request = origin::describe(
        "supabase",
        "Supabase",
        "https://abc.supabase.co",
        Some(".env.development"),
        Some("SUPABASE_URL"),
        true,
        origin::OriginTrust::RepositoryDiscovered,
    )
    .unwrap();

    assert_eq!(request.scheme, "https");
    assert_eq!(request.host, "abc.supabase.co");
    assert_eq!(request.port, 443);
    assert_eq!(request.network_class, origin::NetworkClass::Public);
    assert!(request.question().contains("https://abc.supabase.co"));

    let text = request.disclosure().join("\n");
    for required in [
        "abc.supabase.co",  // host
        "443",              // port
        "Supabase",         // provider association
        "SUPABASE_URL",     // why Tethra detected it
        ".env.development", // source file
        "credential",       // whether credentials may be forwarded
        "public internet",  // network class
    ] {
        assert!(
            text.contains(required),
            "the disclosure must state {required:?}; got:\n{text}"
        );
    }
    assert!(!request.trust.may_configure_without_asking());
}

#[test]
fn a_restricted_destination_is_refused_before_it_is_ever_offered() {
    // The gateway's destination policy is unchanged and still decisive:
    // the user is never asked to approve something that could not work.
    for bad in [
        "http://api.example.com",          // plaintext
        "https://127.0.0.1",               // loopback
        "https://10.0.0.5",                // private
        "https://169.254.169.254",         // cloud metadata
        "https://user:pw@api.example.com", // userinfo
        "https://api.example.com/v1",      // path
    ] {
        assert!(
            origin::describe(
                "supabase",
                "Supabase",
                bad,
                None,
                None,
                true,
                origin::OriginTrust::RepositoryDiscovered
            )
            .is_err(),
            "{bad} must be refused by the origin policy"
        );
    }
}

#[test]
fn thirty_detected_apis_do_not_make_origin_review_unusable() {
    // The scale property from the audit brief: many integrations must not
    // become many prompts. Only genuinely custom destinations are asked
    // about, and they arrive as ONE reviewable list.
    let tmp = tempfile::tempdir().unwrap();
    let mut env = String::new();
    for i in 0..27 {
        env.push_str(&format!(
            "SERVICE{i}_API_KEY=fake-value-{i}-0123456789abcdef\n"
        ));
    }
    env.push_str("OPENAI_API_KEY=sk-proj-FAKE000000000000000000000000000000\n");
    env.push_str("ANTHROPIC_API_KEY=sk-ant-FAKE00000000000000000000000000000\n");
    env.push_str("SUPABASE_URL=https://abcdefghij.supabase.co\n");
    env.push_str("SUPABASE_SERVICE_ROLE_KEY=sb_secret_FAKE0000000000000000000\n");
    write_project(
        tmp.path(),
        &[
            (
                "package.json",
                r#"{"dependencies":{"openai":"^4","@anthropic-ai/sdk":"^0.30","@supabase/supabase-js":"^2"}}"#,
            ),
            (".env", &env),
        ],
    );
    let detection = detect_folder(tmp.path());
    let pending = Selections::pending_origin_approvals(&detection);
    assert!(
        pending.len() <= 2,
        "only genuinely custom destinations may be asked about; got {}: {pending:?}",
        pending.len()
    );
    let defaults = Selections::defaults(&detection);
    assert!(
        defaults.include.contains("openai") && defaults.include.contains("anthropic"),
        "the built-in providers must still be bulk-configured with no prompts"
    );
}

/// End-to-end: the audit's exact fixture, driven the way a `--yes` run
/// would drive it, must not produce a route to the attacker's host.
#[test]
fn a_yes_run_cannot_route_to_an_unapproved_repository_origin() {
    let tmp = tempfile::tempdir().unwrap();
    attacker_origin_fixture(tmp.path());
    let detection = detect_folder(tmp.path());
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");

    // Default selections, exactly as a `--yes` run builds them.
    let selections = Selections::defaults(&detection);
    let planned = api_tracker_tracking::plan::plan(
        &conn,
        &detection,
        &selections,
        api_tracker_tracking::plan::ProjectRef {
            id: Some("p1".into()),
            name: "one".into(),
        },
        &service_running(),
        true,
    );

    // With nothing approved there is nothing to configure, and planning says
    // so loudly rather than quietly building a route to a host the project
    // chose. Either outcome is acceptable as long as no custom route appears.
    match planned {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("attacker-controlled"),
                "the refusal must not leak the attacker's host into an error: {msg}"
            );
        }
        Ok(plan) => {
            let rendered = format!("{:?}", plan.route_actions);
            assert!(
                !rendered.contains("attacker-controlled"),
                "an unapproved destination must never reach the plan: {rendered}"
            );
            assert!(!plan.route_actions.iter().any(|a| matches!(
                a,
                api_tracker_tracking::plan::RouteAction::CreateCustomRoute { .. }
            )));
        }
    }

    // …and with the SAME fixture, once the user approves that exact origin,
    // the route IS planned. Without this the assertion above could be
    // satisfied by a plan that never works at all.
    let mut approved = Selections::defaults(&detection);
    let pending = Selections::pending_origin_approvals(&detection);
    assert_eq!(pending.len(), 1);
    approved.approve_origin(&pending[0].0, &pending[0].1);
    let plan = api_tracker_tracking::plan::plan(
        &conn,
        &detection,
        &approved,
        api_tracker_tracking::plan::ProjectRef {
            id: Some("p1".into()),
            name: "one".into(),
        },
        &service_running(),
        true,
    )
    .expect("an APPROVED origin plans normally");
    assert!(
        plan.route_actions.iter().any(|a| matches!(
            a,
            api_tracker_tracking::plan::RouteAction::CreateCustomRoute { .. }
        )),
        "approval must actually enable the route: {:?}",
        plan.route_actions
    );
}

// ---------------------------------------------------------------------------
// ZFT-014 follow-through: the planner must not act on another installation
// ---------------------------------------------------------------------------

#[test]
fn planning_refuses_when_another_installation_holds_the_service_slot() {
    // The adversarial review of the namespacing fix found that `installed`
    // alone still let the planner emit RepairService (which force-replaced
    // the other definition) or StartService (which bootstrapped it into
    // this session). Neither is something an automatic `track` run may do
    // to another environment.
    let tmp = tempfile::tempdir().unwrap();
    write_project(
        tmp.path(),
        &[
            ("package.json", r#"{"dependencies":{"openai":"^4"}}"#),
            (
                ".env",
                "OPENAI_API_KEY=sk-proj-FAKE000000000000000000000000000000\n",
            ),
        ],
    );
    let detection = detect_folder(tmp.path());
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");

    let mut foreign = service_running();
    foreign.matches_data_dir = false;
    foreign.definition = Some(api_tracker_gateway::lifecycle::Definition {
        binary: std::path::PathBuf::from("/other/bin/tethra-gateway-0.1.0"),
        data_dir: std::path::PathBuf::from("/other/data"),
    });

    let err = api_tracker_tracking::plan::plan(
        &conn,
        &detection,
        &Selections::defaults(&detection),
        api_tracker_tracking::plan::ProjectRef {
            id: Some("p1".into()),
            name: "one".into(),
        },
        &foreign,
        // Not live: forces the install/repair/start branch, which is where
        // the damage was.
        false,
    )
    .expect_err("planning must refuse a slot owned by another installation");
    let msg = err.to_string();
    assert!(
        msg.contains("/other/data"),
        "the refusal must name the other data directory so the user can act: {msg}"
    );
    assert!(
        msg.contains("uninstall"),
        "the refusal must say what to do about it: {msg}"
    );

    // Control: the SAME state with a matching data dir plans normally, so
    // the guard is about ownership and not about `installed`.
    let mut ours = service_running();
    ours.matches_data_dir = true;
    api_tracker_tracking::plan::plan(
        &conn,
        &detection,
        &Selections::defaults(&detection),
        api_tracker_tracking::plan::ProjectRef {
            id: Some("p1".into()),
            name: "one".into(),
        },
        &ours,
        false,
    )
    .expect("our own installed service plans normally");
}
